"""Static-analysis replay tests for Temporal workflow determinism and correctness.

These tests validate workflow code properties without requiring the temporalio
runtime.  They use AST inspection and import checks to enforce:
  - determinism boundaries (no bare non-deterministic calls in workflow code)
  - signal handler presence
  - activity import validity
  - lifecycle-state consistency with the domain model
  - workflow file purity (no I/O package imports)
"""

from __future__ import annotations

import ast
import importlib
import os
import pathlib
import sys
import textwrap

import pytest

# ---------------------------------------------------------------------------
# temporalio availability flag -- static-analysis tests below work without
# the runtime, but actual replay tests (history-based) would call
# ``pytest.importorskip("temporalio")`` at the top of each such test.
# ---------------------------------------------------------------------------
_has_temporalio = importlib.util.find_spec("temporalio") is not None

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[2]

WORKFLOW_DIR = PROJECT_ROOT / "services" / "worker" / "workflows"
ACTIVITY_DIR = PROJECT_ROOT / "services" / "worker" / "activities"

ENGAGEMENT_WF = WORKFLOW_DIR / "engagement.py"
RECON_WF = WORKFLOW_DIR / "recon.py"
VALIDATION_WF = WORKFLOW_DIR / "validation.py"

ALL_WORKFLOW_FILES = [ENGAGEMENT_WF, RECON_WF, VALIDATION_WF]

# I/O-bearing packages that must never appear as top-level imports in a
# workflow file (inside ``with workflow.unsafe.imports_passed_through()`` is
# acceptable because those are type-only pass-throughs).
FORBIDDEN_IO_PACKAGES = frozenset({
    "httpx",
    "aiohttp",
    "requests",
    "urllib3",
    "sqlalchemy",
    "asyncpg",
    "psycopg",
    "psycopg2",
    "pymongo",
    "redis",
    "minio",
    "miniopy_async",
    "boto3",
    "botocore",
    "grpc",
    "grpcio",
    "paramiko",
    "fabric",
    "smtplib",
    "socket",
    "subprocess",
})

# Non-deterministic call patterns that must not appear in workflow method
# bodies.  Each entry is (module_or_attr, function_name).
NONDETERMINISTIC_CALLS: list[tuple[str, str]] = [
    ("datetime", "now"),
    ("datetime.datetime", "now"),
    ("datetime.datetime", "utcnow"),
    ("uuid", "uuid4"),
    ("uuid", "uuid1"),
    ("random", "random"),
    ("random", "randint"),
    ("random", "choice"),
    ("random", "shuffle"),
    ("random", "sample"),
    ("random", "uniform"),
    ("random", "randrange"),
    ("time", "time"),
    ("time", "sleep"),
    ("os", "urandom"),
]


# ===================================================================
# AST helpers
# ===================================================================

def _parse_file(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _top_level_import_names(tree: ast.Module) -> set[str]:
    """Return top-level imported module names (not inside ``with`` blocks)."""
    names: set[str] = set()
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def _imports_inside_with_blocks(tree: ast.Module) -> set[str]:
    """Return module names imported inside any ``with`` statement."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.With):
            for child in ast.walk(node):
                if isinstance(child, ast.Import):
                    for alias in child.names:
                        names.add(alias.name.split(".")[0])
                elif isinstance(child, ast.ImportFrom) and child.module:
                    names.add(child.module.split(".")[0])
    return names


def _all_import_names(tree: ast.Module) -> set[str]:
    """Return every imported module root across the entire file."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def _find_calls_in_functions(tree: ast.Module) -> list[tuple[str, int, str]]:
    """Return ``(dotted_name, lineno, filename)`` for every Call node inside
    function/method bodies (not at module level)."""
    results: list[tuple[str, int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = _call_name(child)
                if name:
                    results.append((name, child.lineno, node.name))
    return results


def _call_name(node: ast.Call) -> str | None:
    """Best-effort dotted name of a Call node's function."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts: list[str] = [node.func.attr]
        current = node.func.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        parts.reverse()
        return ".".join(parts)
    return None


def _class_nodes_with_decorator(tree: ast.Module, decorator_attr: str) -> list[ast.ClassDef]:
    """Return ClassDef nodes decorated with ``@workflow.defn`` (or similar)."""
    results: list[ast.ClassDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for dec in node.decorator_list:
            name = _call_name(ast.Call(func=dec, args=[], keywords=[])) if isinstance(dec, (ast.Attribute, ast.Name)) else None
            if name is None and isinstance(dec, ast.Attribute):
                name = f"{_attr_chain(dec)}"
            if name and name.endswith(decorator_attr):
                results.append(node)
    return results


def _attr_chain(node: ast.Attribute) -> str:
    parts = [node.attr]
    current = node.value
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return ".".join(parts)


def _method_names_with_decorator(cls_node: ast.ClassDef, decorator_suffix: str) -> list[str]:
    """Return method names inside *cls_node* that carry a decorator ending
    with *decorator_suffix* (e.g. ``workflow.signal``)."""
    results: list[str] = []
    for node in cls_node.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            dec_name: str | None = None
            if isinstance(dec, ast.Attribute):
                dec_name = _attr_chain(dec)
            elif isinstance(dec, ast.Name):
                dec_name = dec.id
            if dec_name and dec_name.endswith(decorator_suffix):
                results.append(node.name)
    return results


def _extract_lifecycle_strings_from_workflow(tree: ast.Module) -> set[str]:
    """Extract all string literals passed as the ``lifecycle`` keyword arg in
    ``_update(...)`` calls, direct assignments to ``self._state.lifecycle``,
    and default values in dataclass field definitions for ``lifecycle``."""
    states: set[str] = set()
    for node in ast.walk(tree):
        # self._update(lifecycle="RUNNING", ...)
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "lifecycle" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    states.add(kw.value.value)
        # self._state.lifecycle = "RUNNING"
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "lifecycle"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                states.add(node.value.value)
        # Dataclass field default: lifecycle: str = "DRAFT"
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "lifecycle" and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                states.add(node.value.value)
    return states


def _extract_activity_function_names_from_workflow(tree: ast.Module) -> set[str]:
    """Return bare function names passed to ``workflow.execute_activity()`` or
    ``workflow.start_activity()``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node)
        if call_name and ("execute_activity" in call_name or "start_activity" in call_name):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Name):
                    names.add(first_arg.id)
                elif isinstance(first_arg, ast.Attribute):
                    names.add(first_arg.attr)
    return names


def _extract_child_workflow_classes(tree: ast.Module) -> set[str]:
    """Return class names referenced in ``workflow.start_child_workflow()``."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node)
        if call_name and "start_child_workflow" in call_name:
            if node.args:
                first_arg = node.args[0]
                # e.g. ReconWorkflow.run
                if isinstance(first_arg, ast.Attribute) and isinstance(first_arg.value, ast.Name):
                    names.add(first_arg.value.id)
    return names


# ===================================================================
# 1. Determinism boundary tests
# ===================================================================

class TestDeterminismBoundary:
    """Workflow files must not call non-deterministic stdlib functions
    directly.  Only ``workflow.uuid4()`` etc. are allowed."""

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_datetime_now(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if name in ("datetime.now", "datetime.datetime.now", "datetime.datetime.utcnow")
        ]
        assert not violations, (
            f"{wf_path.name} calls datetime.now() directly: {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_bare_uuid4(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if name in ("uuid.uuid4", "uuid.uuid1", "uuid4")
            # workflow.uuid4() is fine -- only bare uuid.uuid4() is banned
        ]
        assert not violations, (
            f"{wf_path.name} calls uuid.uuid4() directly: {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_random_module_usage(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        random_funcs = {"random", "randint", "choice", "shuffle", "sample", "uniform", "randrange"}
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if any(name == f"random.{fn}" for fn in random_funcs)
        ]
        assert not violations, (
            f"{wf_path.name} uses random module: {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_time_sleep(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if name in ("time.sleep", "asyncio.sleep")
        ]
        assert not violations, (
            f"{wf_path.name} calls time.sleep()/asyncio.sleep(): {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_os_environ_reads(self, wf_path: pathlib.Path) -> None:
        """Workflows must not read environment variables -- that is
        non-deterministic across replays."""
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if name in ("os.environ.get", "os.getenv", "os.environ.__getitem__")
        ]
        assert not violations, (
            f"{wf_path.name} reads env vars: {violations}"
        )


# ===================================================================
# 2. Signal handler existence tests
# ===================================================================

class TestSignalHandlers:
    """The engagement workflow must expose the expected signal handlers."""

    @pytest.fixture()
    def engagement_tree(self) -> ast.Module:
        return _parse_file(ENGAGEMENT_WF)

    @pytest.fixture()
    def engagement_class(self, engagement_tree: ast.Module) -> ast.ClassDef:
        classes = _class_nodes_with_decorator(engagement_tree, "workflow.defn")
        assert classes, "No @workflow.defn class found in engagement.py"
        return classes[0]

    def _signal_methods(self, cls: ast.ClassDef) -> list[str]:
        return _method_names_with_decorator(cls, "workflow.signal")

    def test_has_pause_signal(self, engagement_class: ast.ClassDef) -> None:
        signals = self._signal_methods(engagement_class)
        assert "pause_engagement" in signals, (
            f"Missing PauseAssessment signal handler (pause_engagement). Found: {signals}"
        )

    def test_has_resume_signal(self, engagement_class: ast.ClassDef) -> None:
        signals = self._signal_methods(engagement_class)
        assert "resume_engagement" in signals, (
            f"Missing ResumeAssessment signal handler (resume_engagement). Found: {signals}"
        )

    def test_has_emergency_stop_signal(self, engagement_class: ast.ClassDef) -> None:
        signals = self._signal_methods(engagement_class)
        assert "emergency_stop" in signals, (
            f"Missing EmergencyStop signal handler. Found: {signals}"
        )

    def test_has_cancel_signal(self, engagement_class: ast.ClassDef) -> None:
        signals = self._signal_methods(engagement_class)
        assert "cancel_engagement" in signals, (
            f"Missing cancel_engagement signal handler. Found: {signals}"
        )

    def test_has_approval_signal(self, engagement_class: ast.ClassDef) -> None:
        signals = self._signal_methods(engagement_class)
        assert "provide_approval" in signals, (
            f"Missing provide_approval signal handler. Found: {signals}"
        )

    def test_signal_count(self, engagement_class: ast.ClassDef) -> None:
        """Engagement workflow should have at least 4 signal handlers."""
        signals = self._signal_methods(engagement_class)
        assert len(signals) >= 4, (
            f"Expected at least 4 signal handlers, found {len(signals)}: {signals}"
        )

    def test_validation_workflow_has_approval_signal(self) -> None:
        tree = _parse_file(VALIDATION_WF)
        classes = _class_nodes_with_decorator(tree, "workflow.defn")
        assert classes, "No @workflow.defn class in validation.py"
        signals = _method_names_with_decorator(classes[0], "workflow.signal")
        assert "provide_approval" in signals, (
            f"ValidationWorkflow missing provide_approval signal. Found: {signals}"
        )


# ===================================================================
# 3. Activity registration tests
# ===================================================================

class TestActivityRegistration:
    """Every activity function referenced in workflow code must be importable
    from the activities package."""

    def test_engagement_workflow_activities_importable(self) -> None:
        tree = _parse_file(ENGAGEMENT_WF)
        activity_names = _extract_activity_function_names_from_workflow(tree)
        assert activity_names, "No activity references found in engagement workflow"

        # All referenced activity functions should exist in the activities modules
        expected = {"establish_identities", "create_chain_step", "generate_reports", "run_cleanup"}
        assert expected.issubset(activity_names), (
            f"Missing activity references. Expected at least {expected}, found {activity_names}"
        )

    def test_recon_workflow_activities_importable(self) -> None:
        tree = _parse_file(RECON_WF)
        activity_names = _extract_activity_function_names_from_workflow(tree)
        assert "safe_http_recon" in activity_names, (
            f"ReconWorkflow should reference safe_http_recon. Found: {activity_names}"
        )

    def test_validation_workflow_activities_importable(self) -> None:
        tree = _parse_file(VALIDATION_WF)
        activity_names = _extract_activity_function_names_from_workflow(tree)
        assert "run_bola_validation" in activity_names, (
            f"ValidationWorkflow should reference run_bola_validation. Found: {activity_names}"
        )

    def test_all_referenced_activities_exist_as_files(self) -> None:
        """Every activity function referenced across all workflows should
        correspond to an importable function defined in the activities
        directory."""
        all_activities: set[str] = set()
        for wf_path in ALL_WORKFLOW_FILES:
            tree = _parse_file(wf_path)
            all_activities |= _extract_activity_function_names_from_workflow(tree)

        # Build a map of function names defined in activity files
        defined_functions: set[str] = set()
        for py_file in ACTIVITY_DIR.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            tree = _parse_file(py_file)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defined_functions.add(node.name)

        missing = all_activities - defined_functions
        assert not missing, (
            f"Activities referenced in workflows but not defined: {missing}"
        )

    def test_child_workflows_referenced_correctly(self) -> None:
        """Child workflow classes referenced in engagement.py should be
        importable from the workflows package."""
        tree = _parse_file(ENGAGEMENT_WF)
        child_classes = _extract_child_workflow_classes(tree)
        assert "ReconWorkflow" in child_classes
        assert "ValidationWorkflow" in child_classes

    def test_activities_init_exports_all_referenced(self) -> None:
        """The activities __init__.py should re-export every activity
        function that workflows reference."""
        init_tree = _parse_file(ACTIVITY_DIR / "__init__.py")
        exported: set[str] = set()
        for node in ast.walk(init_tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    exported.add(alias.asname or alias.name)

        all_activity_refs: set[str] = set()
        for wf_path in ALL_WORKFLOW_FILES:
            tree = _parse_file(wf_path)
            all_activity_refs |= _extract_activity_function_names_from_workflow(tree)

        missing = all_activity_refs - exported
        assert not missing, (
            f"Activity functions referenced in workflows but not exported from "
            f"activities/__init__.py: {missing}"
        )


# ===================================================================
# 4. State machine / lifecycle transition tests
# ===================================================================

class TestLifecycleTransitions:
    """Lifecycle states used in the workflow must be consistent with the
    domain model defined in packages/domain/governance/__init__.py."""

    @pytest.fixture()
    def domain_states(self) -> set[str]:
        """All valid lifecycle state names from the domain enum."""
        domain_path = PROJECT_ROOT / "packages" / "domain" / "governance" / "__init__.py"
        tree = _parse_file(domain_path)
        states: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "LifecycleState":
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                states.add(target.id)
        return states

    @pytest.fixture()
    def workflow_states(self) -> set[str]:
        tree = _parse_file(ENGAGEMENT_WF)
        return _extract_lifecycle_strings_from_workflow(tree)

    def test_all_workflow_states_defined_in_domain(
        self, workflow_states: set[str], domain_states: set[str]
    ) -> None:
        """Every lifecycle string the workflow uses must exist as a
        LifecycleState enum member."""
        missing = workflow_states - domain_states
        assert not missing, (
            f"Workflow uses lifecycle states not in domain model: {missing}. "
            f"Domain states: {sorted(domain_states)}"
        )

    def test_domain_main_sequence_present_in_workflow(
        self, workflow_states: set[str]
    ) -> None:
        """The domain's main sequence states should all appear in the
        engagement workflow."""
        main_seq = {"DRAFT", "AUTHORIZATION_PENDING", "SCOPE_COMPILED", "READY", "RUNNING"}
        missing = main_seq - workflow_states
        assert not missing, (
            f"Main sequence states missing from workflow: {missing}"
        )

    def test_terminal_states_present(self, workflow_states: set[str]) -> None:
        """The workflow should reference at least COMPLETED and FAILED."""
        assert "COMPLETED" in workflow_states
        assert "FAILED" in workflow_states

    def test_pause_resume_states_present(self, workflow_states: set[str]) -> None:
        """Pause/resume signals should set PAUSED and RUNNING."""
        assert "PAUSED" in workflow_states
        assert "RUNNING" in workflow_states

    def test_cleanup_state_present(self, workflow_states: set[str]) -> None:
        assert "CLEANUP_PENDING" in workflow_states

    def test_stopping_state_present(self, workflow_states: set[str]) -> None:
        assert "STOPPING" in workflow_states

    def test_reporting_state_present(self, workflow_states: set[str]) -> None:
        assert "REPORTING" in workflow_states

    def test_domain_lifecycle_transitions_complete(self) -> None:
        """Every LifecycleState should have an entry in
        LIFECYCLE_TRANSITIONS (even if the target set is empty)."""
        domain_path = PROJECT_ROOT / "packages" / "domain" / "governance" / "__init__.py"
        tree = _parse_file(domain_path)

        # Collect enum member names
        enum_members: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "LifecycleState":
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                enum_members.add(target.id)

        # Collect keys of LIFECYCLE_TRANSITIONS dict (annotated assignment)
        transition_keys: set[str] = set()
        for node in ast.walk(tree):
            target_name: str | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target_name = node.target.id
                value = node.value
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        target_name = tgt.id
                        value = node.value
            if target_name == "LIFECYCLE_TRANSITIONS" and isinstance(value, ast.Dict):
                for key in value.keys:
                    if isinstance(key, ast.Attribute):
                        transition_keys.add(key.attr)

        missing = enum_members - transition_keys
        assert not missing, (
            f"LifecycleState members missing from LIFECYCLE_TRANSITIONS: {missing}"
        )


# ===================================================================
# 5. Workflow file purity tests
# ===================================================================

class TestWorkflowPurity:
    """Workflow files must not import I/O-bearing packages at top level."""

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_io_packages_at_top_level(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        top_imports = _top_level_import_names(tree)
        violations = top_imports & FORBIDDEN_IO_PACKAGES
        assert not violations, (
            f"{wf_path.name} imports I/O packages at top level: {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_io_packages_anywhere(self, wf_path: pathlib.Path) -> None:
        """Even inside ``with`` blocks, workflow files should only import
        from the project's own activity/workflow modules -- not raw I/O
        packages."""
        tree = _parse_file(wf_path)
        all_imports = _all_import_names(tree)
        violations = all_imports & FORBIDDEN_IO_PACKAGES
        assert not violations, (
            f"{wf_path.name} imports I/O packages: {violations}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_subprocess_usage(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        all_imports = _all_import_names(tree)
        assert "subprocess" not in all_imports, (
            f"{wf_path.name} imports subprocess"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_no_open_calls(self, wf_path: pathlib.Path) -> None:
        """Workflows must not open files -- that is side-effecting and
        non-deterministic."""
        tree = _parse_file(wf_path)
        calls = _find_calls_in_functions(tree)
        violations = [
            (name, lineno, func)
            for name, lineno, func in calls
            if name == "open" or name == "builtins.open"
        ]
        assert not violations, (
            f"{wf_path.name} calls open(): {violations}"
        )

    def test_activities_are_io_boundary(self) -> None:
        """Activity files (not workflow files) are where I/O packages belong.
        At least one activity file should import an I/O package to confirm
        the boundary is correctly placed."""
        io_found = False
        for py_file in ACTIVITY_DIR.glob("*.py"):
            if py_file.name == "__init__.py":
                continue
            tree = _parse_file(py_file)
            all_imports = _all_import_names(tree)
            if all_imports & FORBIDDEN_IO_PACKAGES:
                io_found = True
                break
        assert io_found, (
            "No activity file imports I/O packages -- the I/O boundary may "
            "have shifted incorrectly."
        )


# ===================================================================
# 6. Structural / miscellaneous tests
# ===================================================================

class TestStructural:
    """Miscellaneous structural checks."""

    def test_histories_directory_exists(self) -> None:
        histories_dir = PROJECT_ROOT / "tests" / "histories"
        assert histories_dir.is_dir(), "tests/histories/ directory must exist"

    def test_histories_gitkeep_exists(self) -> None:
        gitkeep = PROJECT_ROOT / "tests" / "histories" / ".gitkeep"
        assert gitkeep.exists(), "tests/histories/.gitkeep must exist"

    def test_engagement_workflow_has_query_handler(self) -> None:
        tree = _parse_file(ENGAGEMENT_WF)
        classes = _class_nodes_with_decorator(tree, "workflow.defn")
        assert classes
        queries = _method_names_with_decorator(classes[0], "workflow.query")
        assert "get_state" in queries, (
            f"EngagementWorkflow missing get_state query. Found: {queries}"
        )

    def test_engagement_workflow_has_run_method(self) -> None:
        tree = _parse_file(ENGAGEMENT_WF)
        classes = _class_nodes_with_decorator(tree, "workflow.defn")
        assert classes
        runs = _method_names_with_decorator(classes[0], "workflow.run")
        assert "run" in runs, (
            f"EngagementWorkflow missing @workflow.run method. Found: {runs}"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_each_workflow_file_has_defn_class(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        classes = _class_nodes_with_decorator(tree, "workflow.defn")
        assert len(classes) >= 1, (
            f"{wf_path.name} has no @workflow.defn class"
        )

    @pytest.mark.parametrize("wf_path", ALL_WORKFLOW_FILES, ids=lambda p: p.name)
    def test_each_workflow_has_run_method(self, wf_path: pathlib.Path) -> None:
        tree = _parse_file(wf_path)
        classes = _class_nodes_with_decorator(tree, "workflow.defn")
        assert classes
        for cls in classes:
            runs = _method_names_with_decorator(cls, "workflow.run")
            assert runs, (
                f"{wf_path.name}::{cls.name} has no @workflow.run method"
            )

    def test_engagement_uses_workflow_uuid4_not_stdlib(self) -> None:
        """The engagement workflow should use ``workflow.uuid4()`` for ID
        generation, not ``uuid.uuid4()``."""
        tree = _parse_file(ENGAGEMENT_WF)
        calls = _find_calls_in_functions(tree)
        wf_uuid_calls = [
            (name, lineno)
            for name, lineno, func in calls
            if name == "workflow.uuid4"
        ]
        # The workflow calls workflow.uuid4() in multiple places
        assert len(wf_uuid_calls) >= 1, (
            "EngagementWorkflow should use workflow.uuid4() for deterministic UUIDs"
        )

    def test_workflow_retry_policy_defined(self) -> None:
        """The engagement workflow should define a retry policy constant."""
        tree = _parse_file(ENGAGEMENT_WF)
        module_level_names: set[str] = set()
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        module_level_names.add(target.id)
        assert "ACTIVITY_RETRY" in module_level_names, (
            "engagement.py should define an ACTIVITY_RETRY RetryPolicy"
        )
