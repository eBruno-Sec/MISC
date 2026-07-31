"""
Browser execution engine -- Apolaki's second first-class execution world (CHAD's "Playwright moment").

HTTP is fast but blind to JavaScript. This drives a real headless Chrome (via a browserless /function
endpoint) so the platform can faithfully exercise SPA routing, dynamic DOM, client-side validation,
storage, service workers, and JS-generated requests -- and, just as important, act as a SENSOR: one
navigation collects a rich structured observation set (forms, inputs, routes, JS bundles, runtime
API/WS endpoints, storage, cookies, framework) that feeds the SAME planner observations + attack graph
as HTTP recon. Deterministic, zero LLM.

Two entry points:
  observe(url)  -- browser-as-sensor: navigate + return structured observations.
  drive(url, js)-- browser-as-executor: run a browserless /function script (login, fill, click, assert).

With no browser configured (env CDP_BROWSER_URL / the headless-chrome sidecar) both degrade cleanly to a
clearly-labelled empty result -- nothing is faked, and the rest of the platform keeps working on HTTP.
"""
from __future__ import annotations

import json
import os

# browser-as-SENSOR: one navigation, a full structured observation set.
_OBSERVE_JS = r"""
export default async function ({ page }) {
  const target = %TARGET_JSON%;
  const api = new Set(), ws = new Set(), gql = new Set();
  page.on('request', r => { const u = r.url();
    if (/\/(api|rest|v1|v2|internal)\//i.test(u)) api.add(u.split('?')[0]);
    if (/graphql/i.test(u)) gql.add(u.split('?')[0]);
    if (u.startsWith('ws://') || u.startsWith('wss://')) ws.add(u); });
  let csp = '';
  page.on('response', res => { try { if (res.url() === target) {
    const h = res.headers(); csp = h['content-security-policy'] || csp; } } catch (e) {} });
  try { await page.goto(target, { waitUntil: 'networkidle2', timeout: 25000 }); } catch (e) {}
  try { await page.waitForTimeout(1500); } catch (e) {}
  const dom = await page.evaluate(() => {
    const forms = [...document.querySelectorAll('form')].map(f => ({
      action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(),
      inputs: [...f.querySelectorAll('input,textarea,select')].map(i => i.getAttribute('name') || i.getAttribute('id') || i.type).filter(Boolean) }));
    const inputs = [...document.querySelectorAll('input,textarea')].map(i => ({
      name: i.getAttribute('name') || i.id || '', type: i.type || 'text', placeholder: i.placeholder || '' }));
    const links = [...new Set([...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')).filter(h => h && !/^https?:/i.test(h)))];
    const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src);
    const framework = window.angular ? 'angular'
      : (window.React || document.querySelector('[data-reactroot],[data-reactid],#___gatsby')) ? 'react'
      : (window.Vue || document.querySelector('#app[data-v-app]')) ? 'vue' : '';
    return { title: document.title, forms, inputs, links, scripts, framework,
      buttons: [...document.querySelectorAll('button')].map(b => (b.innerText || '').trim()).filter(Boolean).slice(0, 40),
      storage: { local: Object.keys(localStorage || {}), session: Object.keys(sessionStorage || {}) },
      cookies: document.cookie ? document.cookie.split(';').map(c => c.split('=')[0].trim()) : [] };
  });
  return { ...dom, runtime_api: [...api], runtime_ws: [...ws], graphql: [...gql], csp };
}
"""


def _browser_url(browser_url=None):
    return (browser_url or os.environ.get("CDP_BROWSER_URL", "")).rstrip("/")


def _empty(target, note):
    return {"target": target, "browser": False, "note": note, "forms": [], "inputs": [], "links": [],
            "scripts": [], "runtime_api": [], "runtime_ws": [], "graphql": [], "framework": "",
            "storage": {"local": [], "session": []}, "cookies": [], "csp": ""}


def drive(target_url, js, browser_url=None, timeout=45):
    """Run a browserless /function script against the target. Returns the script's JSON result, or a
    labelled empty result when no browser is configured/reachable. Never raises."""
    browser = _browser_url(browser_url)
    if not browser:
        return _empty(target_url, "no headless browser configured (start the headless-chrome sidecar + set CDP_BROWSER_URL)")
    try:
        import httpx
    except Exception:
        return _empty(target_url, "httpx unavailable")
    code = js.replace("%TARGET_JSON%", json.dumps(target_url))
    try:
        r = httpx.post(browser + "/function", headers={"Content-Type": "application/javascript"},
                       content=code, timeout=timeout)
        if r.status_code != 200:
            return _empty(target_url, "headless browser returned %s" % r.status_code)
        data = r.json()
        return data.get("data", data) if isinstance(data, dict) else {}
    except Exception as e:
        return _empty(target_url, "headless browser unreachable: %s" % str(e)[:80])


def screenshot(target_url, browser_url=None, full=False, timeout=45):
    """Capture a PNG screenshot (base64) of the target via headless Chrome -- a PoC asset to attach to a
    finding. Labelled-empty dict when no browser is configured; never raises."""
    browser = _browser_url(browser_url)
    if not browser:
        return {"browser": False, "note": "no headless browser configured", "png_b64": ""}
    try:
        import base64
        import httpx
    except Exception:
        return {"browser": False, "note": "httpx unavailable", "png_b64": ""}
    try:
        r = httpx.post(browser + "/screenshot", json={"url": target_url, "options": {"fullPage": bool(full)}},
                       timeout=timeout)
        if r.status_code != 200:
            return {"browser": False, "note": "screenshot returned %s" % r.status_code, "png_b64": ""}
        return {"browser": True, "png_b64": base64.b64encode(r.content).decode(), "bytes": len(r.content),
                "target": target_url}
    except Exception as e:
        return {"browser": False, "note": "unreachable: %s" % str(e)[:60], "png_b64": ""}


def observe(target_url, browser_url=None):
    """Browser-as-sensor: navigate and return the structured observation set. Falls back to a labelled
    empty result when no browser is available."""
    res = drive(target_url, _OBSERVE_JS, browser_url=browser_url)
    if isinstance(res, dict) and res.get("browser") is False:
        return res
    res = res if isinstance(res, dict) else {}
    res.setdefault("target", target_url)
    res["browser"] = True
    return res


# ---------------------------------------------------------------------------- browser -> planner sensor
def to_observations(obs):
    """Map a browser observation set onto the deterministic planner vocabulary, so the browser sensor
    feeds the SAME technique planner as HTTP recon (one shared observation model). Pure."""
    out = set()
    if not obs or obs.get("browser") is False:
        return out
    inputs = obs.get("inputs") or []
    forms = obs.get("forms") or []
    names = " ".join((i.get("name", "") + " " + i.get("placeholder", "")).lower() for i in inputs)
    paths = " ".join(str(x).lower() for x in (obs.get("links") or []) + obs.get("runtime_api", []))
    ftext = " ".join(json.dumps(f).lower() for f in forms)
    if obs.get("scripts"):
        out.add("serves_js")
    if obs.get("runtime_api") or "/api" in paths or "/rest" in paths:
        out.add("has_api")
    if any(t in (names + ftext) for t in ("password", "login", "signin")):
        out.add("has_login")
    if "search" in (names + paths) or any("q" == (i.get("name") or "").lower() for i in inputs):
        out.add("has_search_param")
    if any(t in (names + ftext) for t in ("file", "upload")):
        out.add("has_file_upload")
    if any(t in (names + paths) for t in ("redirect", "url", "return", "next")):
        out.add("has_redirect_param")
    if obs.get("graphql"):
        out.add("has_api")
    if obs.get("runtime_ws"):
        out.add("has_api")
    return out
