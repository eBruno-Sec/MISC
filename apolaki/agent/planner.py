"""
Deterministic scan planner — the non-AI brain.

Sequences Apolaki's existing tools into the standard workflow

    passive recon → live-host discovery → fingerprint → enrich (openapi/graphql/js)
    → surface-driven probes → nuclei → playbook

WITHOUT an LLM. Pure and deterministic: given the mission state it returns the
NEXT batch of tool calls, or [] when the workflow is exhausted. Every step has a
stable dedup key; the executor re-plans after each batch, so a step never repeats
(loop guard) yet newly discovered in-scope assets are picked up on the next pass.

Tool-permission gating mirrors the assessment mode:
    passive → PASSIVE only
    active  → PASSIVE + ACTIVE
    full    → PASSIVE + ACTIVE + INTRUSIVE
The executor still runs every step through the scoped, HITL-gated tool pipeline,
so this module never bypasses scope or the approval gate — it only chooses order.
"""
from __future__ import annotations

from urllib.parse import urlparse

import surface as surface_mod
from scope import PermissionLevel
from tools import TOOL_PERMISSIONS

# per-mode allowed permission tiers
_ALLOWED = {
    "passive": {PermissionLevel.PASSIVE},
    "active": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE},
    "full": {PermissionLevel.PASSIVE, PermissionLevel.ACTIVE, PermissionLevel.INTRUSIVE},
}

# caps keep every run bounded + terminating
CAP_HOSTS = 30          # hosts we http_probe / fingerprint
CAP_ENDPOINTS = 25      # parameterized endpoints we actively probe
CAP_JS = 40             # js urls handed to js_review

_URLISH_PARAM = ("url", "uri", "link", "fetch", "redirect", "next", "return", "dest",
                 "target", "proxy", "image", "img", "callback", "webhook", "u", "r")
_FILE_PARAM = ("file", "path", "page", "doc", "document", "template", "include", "load", "read", "dir", "folder")
_CMD_PARAM = ("cmd", "command", "exec", "run", "ping", "host", "ip", "dns", "query", "shell", "code")


def _host(u: str) -> str:
    try:
        return (urlparse(u).netloc or "").split("@")[-1]
    except Exception:
        return ""


def _allowed(tool: str, mode: str) -> bool:
    tiers = _ALLOWED.get(mode, _ALLOWED["active"])
    return TOOL_PERMISSIONS.get(tool, PermissionLevel.ACTIVE) in tiers


def _step(tool: str, inp: dict, key: str) -> dict:
    return {"tool": tool, "input": inp, "key": key}


def estimate(mode: str, roots: list) -> dict:
    """A rough, pre-run estimate of the deterministic workload for the UI."""
    roots = [r for r in (roots or []) if r]
    n = max(1, len(roots))
    passive = 6 * n
    active = (4 * n) if mode in ("active", "full") else 0
    intrusive = 15 if mode == "full" else 0
    return {"passive_steps": passive, "active_steps": active,
            "intrusive_steps": intrusive, "ai_calls": 0}


def next_batch(state: dict) -> list:
    """Return the next batch of steps (earliest incomplete phase), or []."""
    mode = state.get("mode", "active")
    roots = sorted({r.lower().lstrip("*.") for r in (state.get("roots") or []) if r})
    done = state.get("done") or set()
    recon = state.get("recon") or {}
    urls = state.get("urls") or []

    def fresh(steps):
        # dedup against `done` AND within this freshly built batch (a step's key can
        # be generated twice in one phase, e.g. run_graphql from a URL hint and from
        # a host root) — so the same call never fires twice.
        out, seen = [], set()
        for s in steps:
            k = s["key"]
            if k in done or k in seen or not _allowed(s["tool"], mode):
                continue
            seen.add(k)
            out.append(s)
        return out

    # ── phase A: passive recon on each root ──
    a = []
    for root in roots:
        for tool in ("run_subfinder", "run_crtsh", "run_wayback", "run_dns", "run_asn", "run_github_recon"):
            a.append(_step(tool, {"domain": root}, f"{tool}:{root}"))
    a = fresh(a)
    if a:
        return a

    # discovered hosts (registrable + subdomains + live + url hosts), in scope by construction
    subs = [s for s in (recon.get("subdomains") or []) if s]
    live_hosts = [h.get("url") for h in (recon.get("live_hosts") or []) if h.get("url")]
    url_hosts = sorted({_host(u) for u in urls if _host(u)})

    # ── phase B: live-host discovery ──
    b = []
    targets = sorted(set(roots) | set(subs))
    if targets:
        # key on target count so a later recon cycle (more subdomains) re-runs httpx
        b.append(_step("run_httpx", {"targets": targets}, f"run_httpx:{len(targets)}"))
    b.append(_step("check_takeover", {}, "check_takeover"))
    # http_probe each in-scope host root once (extracts links + params → surface)
    host_roots = []
    for h in sorted(set(roots) | set(subs) | set(url_hosts)):
        host_roots.append(h)
    for h in host_roots[:CAP_HOSTS]:
        b.append(_step("http_probe", {"url": f"https://{h}"}, f"http_probe:{h}"))
    b = fresh(b)
    if b:
        return b

    # ── phase C: fingerprint live hosts ──
    c = [_step("run_fingerprint", {"url": u}, f"run_fingerprint:{u}") for u in live_hosts[:CAP_HOSTS]]
    c = fresh(c)
    if c:
        return c

    # ── phase D: enrich (openapi / graphql / js) ──
    d = []
    js_urls = [u for u in urls if u.split("?")[0].lower().endswith(".js")]
    for u in urls:
        low = u.lower()
        if any(k in low for k in ("swagger", "openapi", "api-docs", "/v2/api-docs", "openapi.json")):
            d.append(_step("fetch_openapi", {"url": u}, f"fetch_openapi:{u}"))
        if "graphql" in low:
            d.append(_step("run_graphql", {"url": u}, f"run_graphql:{_host(u)}"))
    # always try graphql discovery once per live host root
    for h in (set(roots) | set(subs)):
        d.append(_step("run_graphql", {"url": f"https://{h}/graphql"}, f"run_graphql:{h}"))
    if js_urls:
        d.append(_step("run_js_review", {"urls": js_urls[:CAP_JS]}, "run_js_review"))
    d = fresh(d)
    if d:
        return d

    # ── phase E: surface-driven probes ──
    inv = surface_mod.build_inventory(urls)
    param_eps = [e for e in inv if e.get("parameterized")][:CAP_ENDPOINTS]
    host_bases = sorted({e["host"] for e in inv})[:CAP_HOSTS]
    e_steps = []
    for ep in param_eps:
        u = ep.get("example") or f"https://{ep['host']}{ep['path']}"
        tag = f"{ep['host']}{ep['path']}"
        params_l = [str(p).lower() for p in (ep.get("params") or [])]
        e_steps.append(_step("run_xss", {"url": u}, f"run_xss:{tag}"))
        e_steps.append(_step("run_sqli", {"url": u}, f"run_sqli:{tag}"))
        e_steps.append(_step("run_injection_probes", {"url": u}, f"run_injection_probes:{tag}"))
        e_steps.append(_step("run_web_probes", {"url": u}, f"run_web_probes:{tag}"))   # LFI/traversal + IDOR
        if any(p in _URLISH_PARAM for p in params_l):
            e_steps.append(_step("run_ssrf", {"url": u}, f"run_ssrf:{tag}"))
        if any(p in _CMD_PARAM for p in params_l):
            e_steps.append(_step("run_cmdi", {"url": u}, f"run_cmdi:{tag}"))
    for h in host_bases:
        e_steps.append(_step("run_content_discovery", {"base_url": f"https://{h}"}, f"run_content_discovery:{h}"))
        e_steps.append(_step("run_exposure", {"base_url": f"https://{h}"}, f"run_exposure:{h}"))
    e_steps = fresh(e_steps)
    if e_steps:
        return e_steps

    # ── phase F: nuclei (safe tags) per live host ──
    f_steps = []
    for h in sorted(set(roots) | set(subs)):
        f_steps.append(_step("run_nuclei",
                             {"target": f"https://{h}", "tags": "tech,misconfig,exposed-panels,takeovers"},
                             f"run_nuclei:{h}"))
    f_steps = fresh(f_steps)
    if f_steps:
        return f_steps

    # ── phase G: deterministic playbook (always, even passive) ──
    if "generate_playbook" not in done:
        return [_step("generate_playbook", {}, "generate_playbook")]

    return []
