"""Throughput diagnosis harness: where do the seconds actually go?

Run inside apolaki-agent-1 with `-w /app`. Times, on the SAME benchmark URL:
  A. raw transport cost (fresh client vs reused client, TLS vs plain)
  B. every sweep engine, individually, with an httpx request counter
No writes, no findings storage, read-only measurement.
"""
import asyncio
import os
import sys
import time
import json

sys.path.insert(0, "/app")

TARGET_BASE = os.environ.get("MEAS_BASE", "https://owaspbench:8443")
TARGET_URL = os.environ.get(
    "MEAS_URL",
    TARGET_BASE + "/benchmark/sqli-00/BenchmarkTest00008.html?BenchmarkTest00008=a")

# ---------------------------------------------------------------- request counter
import httpx

_COUNT = {"n": 0, "secs": 0.0, "conns": 0}
_orig_send = httpx.AsyncClient.send
_orig_init = httpx.AsyncClient.__init__


async def _counting_send(self, request, **kw):
    t0 = time.perf_counter()
    try:
        return await _orig_send(self, request, **kw)
    finally:
        _COUNT["n"] += 1
        _COUNT["secs"] += time.perf_counter() - t0


def _counting_init(self, *a, **kw):
    _COUNT["conns"] += 1
    return _orig_init(self, *a, **kw)


httpx.AsyncClient.send = _counting_send
httpx.AsyncClient.__init__ = _counting_init


def _reset():
    _COUNT["n"] = 0
    _COUNT["secs"] = 0.0
    _COUNT["conns"] = 0


def _snap():
    return dict(_COUNT)


# ---------------------------------------------------------------- A. transport cost
async def transport_costs():
    out = {}

    async def timeit(label, fn, reps=5):
        # one warm-up, then reps timed
        try:
            await fn()
        except Exception as e:
            out[label] = "ERR %s: %s" % (type(e).__name__, str(e)[:80])
            return
        t0 = time.perf_counter()
        for _ in range(reps):
            await fn()
        out[label] = round((time.perf_counter() - t0) / reps * 1000, 1)

    async def fresh_client_tls():
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
            await c.get(TARGET_URL)

    shared = httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15)

    async def reused_client_tls():
        await shared.get(TARGET_URL)

    async def client_ctor_only():
        async with httpx.AsyncClient(verify=False, timeout=15):
            pass

    await timeit("fresh_client_per_request_ms", fresh_client_tls)
    await timeit("reused_client_ms", reused_client_tls)
    await timeit("client_construct_teardown_only_ms", client_ctor_only)
    await shared.aclose()
    return out


# ---------------------------------------------------------------- B. engine cost
SWEEP_HTTP = ("run_sqli", "run_sqli_structural", "run_xpath", "run_ldap", "run_ssi",
              "run_css_injection", "run_waf_bypass", "run_injection_probes")
SWEEP_BROWSER = ("run_xss", "run_dom_trace")
HTML_PAGE = ("run_form_xss", "run_client_checks")


async def engine_costs(names):
    import scope as scope_mod
    import tools as tools_mod

    sc = scope_mod.ScopeEngine()
    sc.load_manual([TARGET_BASE], [], "measure")
    reg = tools_mod.ToolRegistry(sc, mission_id=None, lab_mode=True)

    rows = []
    for name in names:
        _reset()
        t0 = time.perf_counter()
        err = ""
        try:
            res = await reg.execute(name, {"url": TARGET_URL}, "meas")
            err = (res.error or "")[:60]
        except Exception as e:
            err = "EXC %s: %s" % (type(e).__name__, str(e)[:60])
        wall = time.perf_counter() - t0
        s = _snap()
        rows.append({"engine": name, "wall_s": round(wall, 2), "requests": s["n"],
                     "in_http_s": round(s["secs"], 2),
                     "clients_built": s["conns"],
                     "overhead_s": round(wall - s["secs"], 2),
                     "err": err})
    return rows


async def main():
    print("TARGET:", TARGET_URL)
    print()
    print("== A. transport cost (ms per request) ==")
    tc = await transport_costs()
    print(json.dumps(tc, indent=2))
    print()
    which = sys.argv[1:] or list(SWEEP_HTTP + SWEEP_BROWSER + HTML_PAGE)
    print("== B. per-engine cost ==")
    rows = await engine_costs(which)
    print("%-24s %9s %6s %10s %10s %8s  %s" %
          ("engine", "wall_s", "reqs", "in_http_s", "overhd_s", "clients", "err"))
    tot_w = tot_h = 0.0
    tot_r = 0
    for r in rows:
        print("%-24s %9.2f %6d %10.2f %10.2f %8d  %s" %
              (r["engine"], r["wall_s"], r["requests"], r["in_http_s"],
               r["overhead_s"], r["clients_built"], r["err"]))
        tot_w += r["wall_s"]
        tot_h += r["in_http_s"]
        tot_r += r["requests"]
    print("%-24s %9.2f %6d %10.2f %10.2f" % ("TOTAL", tot_w, tot_r, tot_h, tot_w - tot_h))


asyncio.run(main())
