"""Q-167. Does the binary we ship ACCEPT the command line we build for it?

THE DEFECT THIS EXISTS FOR. `_run_nuclei` passed `-json`. That flag was removed in nuclei v3, and
the binary exits 2 on an unknown flag -- before loading a single one of its 13,619 templates. So
every nuclei dispatch in this platform's history did nothing at all, and for most of that history
a non-zero exit did not cross the return edge (Q-092), so the mission record could not tell
"nuclei never started" from "the target is clean".

Nothing caught it because nothing could SEE it: the argv was built inline inside an async
dispatcher, so asserting on it needed a network, a target and a subprocess.

A test that pins the literal "-jsonl" would only catch the flag already fixed. These ask the
question generally -- does the installed binary accept every flag we emit -- so the NEXT rename
fails here instead of in six months of silent zero-finding scans.
"""
import shutil
import subprocess

import tools


def _argv():
    return tools.nuclei_argv("http://example.invalid", "tech,misconfig",
                             "low,medium,high,critical", "25", oob=False)


def test_the_v3_output_flag_is_used_and_the_removed_one_is_not():
    argv = _argv()
    assert "-jsonl" in argv, "nuclei v3 writes JSON lines with -jsonl (-j); -json no longer exists"
    assert "-json" not in argv, "-json was REMOVED in nuclei v3 and makes the binary exit 2"


def test_every_flag_we_emit_is_recognised_by_the_installed_binary():
    """The general guard. Not 'is it -jsonl', but 'does nuclei know what we are asking for'."""
    exe = shutil.which("nuclei")
    assert exe, "nuclei is not installed in this image -- the flag contract cannot be checked"
    help_text = subprocess.run([exe, "-h"], capture_output=True, text=True, timeout=120)
    blob = (help_text.stdout or "") + (help_text.stderr or "")
    assert len(blob) > 500, "nuclei -h produced no usage text to check flags against"
    unknown = [tok for tok in _argv()
               if tok.startswith("-") and tok not in blob]
    assert not unknown, "nuclei does not document these flags we pass: %s" % unknown


def test_the_command_line_does_not_make_nuclei_exit_on_usage():
    """THE reproduction. Exit 2 is nuclei's usage error -- the exact failure that was invisible.

    Aimed at a closed port on loopback so the run is offline and immediate: a target that answers
    nothing exits 0 with no findings, while a malformed command line exits 2 no matter what the
    target does. That is precisely the distinction the mission record could not make before Q-092,
    and it is the one this test pins.
    """
    exe = shutil.which("nuclei")
    assert exe, "nuclei is not installed in this image -- the flag contract cannot be checked"
    argv = tools.nuclei_argv("http://127.0.0.1:1", "tech", "low,medium,high,critical",
                             "5", oob=False)
    argv = [exe] + argv[1:]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    assert r.returncode != 2, (
        "nuclei rejected our command line (exit 2), so it never scanned: %s"
        % ((r.stderr or r.stdout).strip()[:300] or "(no output)"))
