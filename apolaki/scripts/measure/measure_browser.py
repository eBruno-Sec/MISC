"""Split run_xss's wall clock into: playwright start, chromium launch, context/page,
per-navigation goto, and the fixed 350 ms sleep. Read-only."""
import asyncio, os, sys, time, json
sys.path.insert(0, "/app")
import tools as T
import xss_tool as xt

URL = os.environ.get("MEAS_URL",
                     "https://owaspbench:8443/benchmark/sqli-00/BenchmarkTest00008.html?BenchmarkTest00008=a")


async def main():
    chrome = T._chrome_path()
    print("chrome:", chrome)
    from playwright.async_api import async_playwright
    os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")

    t = {}
    t0 = time.perf_counter()
    pw_cm = async_playwright()
    pw = await pw_cm.__aenter__()
    t["playwright_start_s"] = round(time.perf_counter() - t0, 3)

    t0 = time.perf_counter()
    browser = await pw.chromium.launch(headless=True, executable_path=chrome,
                                       args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
    t["chromium_launch_s"] = round(time.perf_counter() - t0, 3)

    t0 = time.perf_counter()
    ctx = await browser.new_context(ignore_https_errors=True)
    page = await ctx.new_page()
    t["context_and_page_s"] = round(time.perf_counter() - t0, 3)

    # per-navigation cost, same call shape as _xss_execute
    navs = []
    for pl in list(xt.EXEC_PAYLOADS)[:6]:
        tu = xt.set_param(URL, "BenchmarkTest00008", pl)
        t0 = time.perf_counter()
        try:
            await page.goto(tu, wait_until="load", timeout=8000)
        except Exception as e:
            navs.append(("TIMEOUT/" + type(e).__name__, round(time.perf_counter() - t0, 3)))
            continue
        navs.append(("ok", round(time.perf_counter() - t0, 3)))
    t["goto_samples_s"] = navs
    oks = [d for s, d in navs if s == "ok"]
    t["goto_mean_s"] = round(sum(oks) / max(len(oks), 1), 3)
    t["fixed_sleep_per_nav_s"] = 0.350

    # how many navigations does one _xss_execute actually do?
    sc_mod = __import__("scope")
    sc = sc_mod.ScopeEngine()
    sc.load_manual(["https://owaspbench:8443"], [], "meas")
    reg = T.ToolRegistry(sc, mission_id=None, lab_mode=True)
    t0 = time.perf_counter()
    disc = await reg._discover_params(URL)
    t["discover_params_s"] = round(time.perf_counter() - t0, 3)
    params = list(dict.fromkeys(list(xt.params_of(URL)) + disc))
    t["params"] = params
    t["nav_count_for_this_url"] = len(params) * len(xt.EXEC_PAYLOADS) + len(xt.EXEC_PAYLOADS)

    t0 = time.perf_counter()
    await browser.close()
    await pw_cm.__aexit__(None, None, None)
    t["teardown_s"] = round(time.perf_counter() - t0, 3)

    n = t["nav_count_for_this_url"]
    t["PROJECTED_run_xss_s"] = round(
        t["playwright_start_s"] + t["chromium_launch_s"] + t["context_and_page_s"]
        + n * (t["goto_mean_s"] + 0.350) + t["teardown_s"], 2)
    t["PROJECTED_fixed_sleep_total_s"] = round(n * 0.350, 2)
    t["PROJECTED_startup_total_s"] = round(
        t["playwright_start_s"] + t["chromium_launch_s"] + t["context_and_page_s"] + t["teardown_s"], 2)
    print(json.dumps(t, indent=2))


asyncio.run(main())
