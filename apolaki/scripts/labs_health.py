#!/usr/bin/env python3
"""Is the LAB BENCH alive? Run this before believing any shakedown result.

    docker exec -i apolaki-agent-1 python - < scripts/labs_health.py          # check
    docker exec -i apolaki-agent-1 python - < scripts/labs_health.py -- --init  # check + set up

WHY. A dead lab and a broken engine produce the SAME observation: zero findings. Measured, in one
afternoon:

  * mutillidae answered "Database Offline" -- 3,339 bytes where a live instance serves 52,763.
  * bwapp answered "Connection failed: Unknown database 'bWAPP'" -- 43 bytes.

Both are the primary SQLi/XSS training targets. With their databases down, every injection engine
aimed at them returned zero CORRECTLY, and the cross-mission ledger reported those engines as
having never produced anything. dalfox in particular sat at 207 runs / 0 results across 64 missions
and looked structurally broken; pointed at a REVIVED mutillidae with the engine's exact argv it
immediately returned verified XSS. The tool was never the problem.

Neither lab is broken -- each needs a documented one-time setup call that nothing performs, so a
fresh `docker compose up` yields a bench that is quietly dead. `--init` performs those calls; they
are idempotent, so running it against a healthy bench costs one request and changes nothing.

Exits non-zero when any lab is dead, so a shakedown cannot be started against a dead bench and its
zeros mistaken for evidence about the engines.
"""
from __future__ import annotations

import sys

# name, url, minimum plausible body size, substrings that PROVE it is dead, one-time setup URL
LABS = [
    ("juice-shop",  "http://juice-shop:3000/",  3000, (), None),
    ("mutillidae",  "http://mutillidae/",      20000, ("Database Offline",),
     "http://mutillidae/set-up-database.php"),
    ("bwapp",       "http://bwapp/",            1000, ("Unknown database", "Connection failed"),
     "http://bwapp/install.php?install=yes"),
    ("dvwa",        "http://dvwa/",              800, (), None),
    ("webgoat",     "http://webgoat:8080/WebGoat", 800, (), None),
    ("vampi",       "http://vampi:5000/",        150, (), None),
    ("dvga",        "http://dvga:5013/",        2000, (), None),
    ("clientauthz", "http://clientauthz:8080/",   50, (), None),
    ("domsource",   "http://domsource:8080/",    200, (), None),
    ("wordpress",   "http://wordpress-wpreach-1/", 5000, (), None),
]


def _get(url, timeout=90):
    import httpx
    return httpx.get(url, timeout=timeout, follow_redirects=True)


def judge(status, body, floor, dead_sigs):
    """The verdict, as a PURE function of what came back. Separated from the fetch so the negative
    control can hand it a real dead body instead of asserting something about itself."""
    for sig in dead_sigs:
        if sig in body:
            return False, "serves %r (%d bytes) -- the app is up but its database is not" % (sig, len(body))
    if status >= 400:
        return False, "HTTP %d" % status
    if len(body) < floor:
        return False, "%d bytes, below the %d floor for a working instance" % (len(body), floor)
    return True, "HTTP %d, %d bytes" % (status, len(body))


def check(url, floor, dead_sigs):
    """Returns (ok, evidence). Evidence is what a reader needs, never a bare bool."""
    try:
        r = _get(url, timeout=20)
    except Exception as e:
        return False, "unreachable: %s" % str(e)[:90]
    return judge(r.status_code, r.text, floor, dead_sigs)


def selftest() -> int:
    """Can this check FAIL? A health check that cannot go red is decoration.

    Two negative controls, both offline: a closed port must read DEAD, and a body carrying a
    known dead-signature must read DEAD even though it is a 200 of respectable size. The second
    is the one that matters -- mutillidae served a perfectly good HTTP 200 while its database was
    down, and any check keyed only on status code would have called that bench healthy.
    """
    # The real body mutillidae served while its database was down: a 200, 3,339 bytes, padded
    # here past the 20,000-byte floor so the ONLY thing that can fail it is the signature. A
    # control that would also pass on size proves nothing about the signature.
    dead_body = ("<html><body>Database Offline The database server appears to be offline."
                 + ("<p>filler</p>" * 3000) + "</body></html>")
    must_be_dead = [
        ("closed port", check("http://127.0.0.1:1/", 10, ())),
        ("mutillidae's real db-offline body, padded ABOVE the size floor",
         judge(200, dead_body, 20000, ("Database Offline",))),
    ]
    must_be_alive = [
        ("a large healthy 200 with no dead signature",
         judge(200, "x" * 60000, 20000, ("Database Offline",))),
    ]
    ok = True
    for label, (passed, why) in must_be_dead:
        print("%-8s must read DEAD: %s -- %s" % ("ok" if not passed else "BROKEN", label, why))
        ok = ok and not passed
    for label, (passed, why) in must_be_alive:
        print("%-8s must read ALIVE: %s -- %s" % ("ok" if passed else "BROKEN", label, why))
        ok = ok and passed
    print("selftest: the check can go red AND green" if ok
          else "SELFTEST FAILED: this check does not discriminate")
    return 0 if ok else 1


def main(argv) -> int:
    if "--selftest" in argv:
        return selftest()
    do_init = "--init" in argv
    dead = []
    for name, url, floor, sigs, setup in LABS:
        ok, why = check(url, floor, sigs)
        if not ok and do_init and setup:
            try:
                _get(setup)
                ok, why = check(url, floor, sigs)
                why = ("set up, then " + why) if ok else ("setup ran but " + why)
            except Exception as e:
                why = "setup call failed: %s" % str(e)[:80]
        print("%-8s %-12s %s" % ("ALIVE" if ok else "DEAD", name, why))
        if not ok:
            dead.append(name)
    print()
    if dead:
        print("%d lab(s) DEAD: %s" % (len(dead), ", ".join(dead)))
        print("A dead lab returns zero for every engine. Do NOT read a shakedown against this bench")
        print("as evidence about the tools. Re-run with --init for the ones that have a setup call.")
        return 1
    print("bench healthy: %d labs" % len(LABS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
