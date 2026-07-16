"""
3-step iterative recon loop (Spec 3) — no MCP.

After the base active pass, this loop (max 3 iterations) expands recon on newly
discovered surface. A rule-based planner always runs (probe new web ports,
directory-bust undiscovered live hosts). If an AI key is configured, an LLM
planner additionally suggests the next concrete recon step, which is executed
ONLY when it targets an already-discovered, in-scope host with an enabled tool.
Recon-only by design — the loop never exploits.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

import galahad as GAL

from ..core import ai_client, runconfig
from ..core.scope import split_host_port

WEB_PORTS = {"80", "443", "8080", "8000", "8443", "8888", "3000", "3001", "5000", "9090", "4000", "8081"}


def _host_of(u: str) -> str:
    if "://" in u:
        return (urlparse(u).hostname or "").lower()
    return u.split(":")[0].lower()


def _known_hosts(recon: dict, target_host: str) -> set:
    hosts = {target_host.lower()}
    for h in recon.get("live_hosts", []) or []:
        hosts.add(_host_of(h.get("url", "")))
    for s in recon.get("all_subdomains", []) or []:
        hosts.add(s.lower())
    hosts.discard("")
    return hosts


def _new_web_urls_from_ports(recon: dict, target_host: str) -> list[str]:
    have = {(h.get("url") or "").rstrip("/") for h in recon.get("live_hosts", []) or []}
    out = []
    for line in (recon.get("nmap", {}).get("open_ports", []) or []):
        m = re.match(r"\s*(\d+)/tcp\s+open\s+(\S+)", line)
        if not m:
            continue
        port, svc = m.group(1), m.group(2).lower()
        if port in WEB_PORTS or "http" in svc:
            for scheme in ("http", "https"):
                u = f"{scheme}://{target_host}:{port}"
                if u.rstrip("/") not in have:
                    out.append(u)
    # de-dupe, cap
    seen, uniq = set(), []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq[:8]


def _merge_live(recon: dict, new_hosts: list[dict]) -> int:
    have = {(h.get("url") or "").rstrip("/") for h in recon.get("live_hosts", []) or []}
    added = 0
    for h in new_hosts:
        u = (h.get("url") or "").rstrip("/")
        if u and u not in have:
            recon.setdefault("live_hosts", []).append(h)
            have.add(u)
            added += 1
    return added


def _ai_plan(target: str, recon: dict, enabled: list[str]) -> dict:
    live = [h.get("url") for h in recon.get("live_hosts", [])[:15] if h.get("url")]
    ports = recon.get("nmap", {}).get("open_ports", [])[:15]
    paths = []
    for base, ps in (recon.get("dir_bust") or {}).items():
        for p in (ps or [])[:8]:
            paths.append(p.get("url") if isinstance(p, dict) else str(p))
    prompt = (
        "You are a recon planner for an AUTHORIZED assessment. Given the findings, decide if MORE "
        "RECON (enumeration only, never exploitation) is warranted, and propose up to 3 concrete next steps.\n"
        f"Enabled tools: {enabled}. Only use these. Targets must be hosts already listed below.\n"
        f"TARGET: {target}\nLIVE: {json.dumps(live)}\nOPEN PORTS: {json.dumps(ports)}\nPATHS: {json.dumps(paths[:20])}\n\n"
        "Reply ONLY with compact JSON: "
        '{"more_recon": true|false, "actions": [{"tool":"ffuf|httpx|nuclei","target":"http://host:port/optional-path","reason":"..."}]}'
    )
    try:
        import asyncio
        txt = asyncio.run(ai_client.complete(prompt, max_tokens=500,
                                             system="Return only valid JSON. Recon/enumeration only. No exploitation."))
    except Exception:
        return {}
    if not txt:
        return {}
    m = re.search(r"\{.*\}", txt, re.DOTALL)
    if not m:
        return {}
    try:
        return json.loads(m.group(0))
    except Exception:
        return {}


def run_recon_loop(target: str, run_dir: Path, recon: dict, log, cfg: dict, config: dict) -> None:
    config = runconfig.normalize(config)
    rc = config
    sp = runconfig.speed_profile(rc)
    en = lambda t: runconfig.tool_enabled(rc, t)
    threads = int(sp["threads"] or 10)
    timeout = int(cfg.get("timeout", 8))
    severity = cfg.get("nuclei_severity", "medium,high,critical")
    wordlist = str(Path(cfg.get("wordlist", "/app/wordlists/common.txt")))
    from .active import _wordlist
    wordlist = _wordlist()

    target_host, target_port = split_host_port(target)
    max_loops = int(config.get("max_loops", 3))
    loop_log = []
    run_dir = Path(run_dir)

    log(f"── 3-step recon loop (max {max_loops}) ──", "hdr", "loop")

    for i in range(1, max_loops + 1):
        added = 0
        actions = []

        # ── rule: probe newly discovered web ports ──
        # Only for bare-domain targets. If the operator pointed at a specific
        # host:port, don't wander to sibling ports (avoids self-scan + dupes).
        if en("httpx") and not target_port:
            cands = _new_web_urls_from_ports(recon, target_host)
            if cands:
                log(f"[loop {i}] probing {len(cands)} new web port(s)", "info", "loop")
                new = GAL.phase_live_hosts(cands, run_dir, threads, timeout, extra=sp["httpx_extra"])
                a = _merge_live(recon, new)
                added += a
                if a:
                    actions.append(f"httpx→{a} new live host(s)")

        # ── rule: directory-bust live hosts not yet covered ──
        if en("ffuf"):
            dusted = set((recon.get("dir_bust") or {}).keys())
            todo = [h for h in recon.get("live_hosts", []) if (h.get("url") or "").rstrip("/") not in dusted][:3]
            if todo:
                log(f"[loop {i}] directory-busting {len(todo)} new host(s)", "info", "loop")
                res = GAL.phase_dir_bust(todo, run_dir, wordlist, threads, extra=sp["ffuf_extra"])
                recon.setdefault("dir_bust", {}).update(res)
                gained = sum(len(v) for v in res.values())
                if gained:
                    added += gained
                    actions.append(f"ffuf→{gained} path(s)")

        # ── optional AI planner ──
        if ai_client.ai_enabled():
            plan = _ai_plan(target, recon, [t for t in runconfig.TOOLS if en(t)])
            for act in (plan.get("actions") or [])[:3]:
                tool = str(act.get("tool", "")).lower()
                tgt = str(act.get("target", "")).strip()
                if tool not in ("ffuf", "httpx", "nuclei") or not en(tool) or not tgt:
                    continue
                if _host_of(tgt) not in _known_hosts(recon, target_host):
                    log(f"[loop {i}] AI suggested out-of-scope target, skipped: {tgt}", "warn", "loop")
                    continue
                log(f"[loop {i}] AI: {tool} {tgt} — {act.get('reason','')[:70]}", "info", "loop")
                try:
                    if tool == "httpx":
                        new = GAL.phase_live_hosts([tgt], run_dir, threads, timeout, extra=sp["httpx_extra"])
                        added += _merge_live(recon, new)
                    elif tool == "ffuf":
                        res = GAL.phase_dir_bust([{"url": tgt}], run_dir, wordlist, threads, extra=sp["ffuf_extra"])
                        recon.setdefault("dir_bust", {}).update(res)
                        added += sum(len(v) for v in res.values())
                    elif tool == "nuclei":
                        nh, _ = split_host_port(_host_of(tgt))
                        nn = GAL.phase_nuclei(nh, [{"url": tgt}], run_dir, severity, extra=sp["nuclei_extra"])
                        exist = {json.dumps(x, sort_keys=True, default=str) for x in recon.get("nuclei", [])}
                        for x in nn:
                            if json.dumps(x, sort_keys=True, default=str) not in exist:
                                recon.setdefault("nuclei", []).append(x)
                                added += 1
                    actions.append(f"ai:{tool}")
                except Exception as e:
                    log(f"[loop {i}] AI action failed: {type(e).__name__}", "warn", "loop")
            if not plan.get("more_recon", True) and not actions:
                loop_log.append({"iteration": i, "actions": actions, "added": added})
                log(f"[loop {i}] planner says done.", "ok", "loop")
                break

        loop_log.append({"iteration": i, "actions": actions, "added": added})
        log(f"[loop {i}] added {added} new item(s): {', '.join(actions) or 'none'}", "ok", "loop")
        if added == 0:
            log("recon loop converged (no new surface).", "ok", "loop")
            break

    recon["loop_log"] = loop_log
