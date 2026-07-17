"""
Mission pipeline.

Runs on a worker thread (see hub.run_mission). Executes passive recon, optional
active enumeration, then builds the test-guidance playbook, a 2D topology graph,
stats, and (if configured) an AI executive summary. Everything is streamed to
the mission feed and persisted to SQLite.
"""
import asyncio
import io
import os
import re
import sys
from pathlib import Path

from ..core import ai_client, db, guidance as guidance_mod, runconfig
from . import active as active_mod
from . import passive as passive_mod

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEV_RANK = guidance_mod.SEVERITY_RANK


def _norm_url(u: str) -> str:
    """Canonicalize a URL so host and host:443 (or :80) collapse to one:
    drop the default port for the scheme and strip a trailing path slash.
    Used to de-duplicate live hosts and directory-busting results."""
    from urllib.parse import urlparse, urlunparse
    try:
        p = urlparse(u if "://" in u else "https://" + u)
        host = (p.hostname or "").lower()
        if not host:
            return u.rstrip("/")
        port = p.port
        default = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
        netloc = host if (port is None or default) else f"{host}:{port}"
        return urlunparse((p.scheme, netloc, (p.path or "").rstrip("/"), "", p.query, ""))
    except Exception:
        return u.rstrip("/")


class _Tee(io.TextIOBase):
    """Forward captured stdout to the real console and the mission feed, line by line."""

    def __init__(self, real, emit):
        self._real = real
        self._emit = emit
        self._buf = ""

    def write(self, s):
        try:
            self._real.write(s)
        except Exception:
            pass
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            clean = _ANSI.sub("", line).rstrip()
            if clean.strip():
                self._emit(clean)
        return len(s)

    def flush(self):
        try:
            self._real.flush()
        except Exception:
            pass


def _scope_allows_active(scope: dict) -> bool:
    return True  # operator chose the mode explicitly at launch; mode gates active


def _split_targets(target_field: str) -> list[str]:
    """One mission can cover several targets (e.g. an imported program scope).
    Split on commas/whitespace, dedupe, preserve order."""
    seen, out = set(), []
    for p in re.split(r"[,\s]+", (target_field or "").strip()):
        p = p.strip()
        if p and p.lower() not in seen:
            seen.add(p.lower())
            out.append(p)
    return out


def _safe_name(t: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", t.lower()) or "target"


def _scan_target(target, mode, scope, config, run_dir, log, hub, mission_id):
    """Full pipeline for ONE target: passive, optional active + confirm phases,
    then the per-target playbook. Returns (recon, guidance)."""
    recon: dict = {"target": target}

    log("── Percival // passive recon ──", "hdr", "passive")
    recon.update(passive_mod.run_passive(target, run_dir, log))

    if mode in ("active", "full") and _scope_allows_active(scope):
        en = [t for t, on in config["tools"].items() if on]
        log("── Galahad // active enumeration ──", "hdr", "active")
        log(f"Active packets to in-scope hosts · speed={config['speed']} · tools: {', '.join(en) or 'none'}", "warn", "active")
        if runconfig.is_authenticated(config):
            names = ", ".join(h.split(":", 1)[0] for h in runconfig.auth_headers(config))
            log(f"Authenticated scan: session passthrough active ({names}) on httpx/ffuf/nuclei + detectors", "ok", "active")
        tee = _Tee(sys.stdout, lambda ln: hub.emit(mission_id, "trace", "active", ln))
        old = sys.stdout
        sys.stdout = tee
        try:
            active_mod.run_active(target, run_dir, recon, log, cfg_from_env(), config, scope=scope)
            if config.get("recon_loop"):
                from . import loop as loop_mod
                loop_mod.run_recon_loop(target, run_dir, recon, log, cfg_from_env(), config)
        finally:
            sys.stdout = old

        # De-dupe live hosts by hostname (same app on :80/:443 -> one entry,
        # prefer https) so findings/topology aren't triplicated.
        if recon.get("live_hosts"):
            from urllib.parse import urlparse
            best: dict = {}
            for h in recon["live_hosts"]:
                u = h.get("url", "")
                host = urlparse(u).hostname or u
                cur = best.get(host)
                if cur is None or (u.startswith("https") and not (cur.get("url", "") or "").startswith("https")):
                    best[host] = h
            if len(best) < len(recon["live_hosts"]):
                log(f"deduped live hosts: {len(recon['live_hosts'])} -> {len(best)} (same app on multiple schemes/ports)", "info", "active")
            recon["live_hosts"] = list(best.values())
            for h in recon["live_hosts"]:
                if h.get("url"):
                    h["url"] = _norm_url(h["url"])

        # Collapse directory-busting results by canonical URL (host vs host:443)
        # and case-insensitive path, so paths aren't double-reported.
        if recon.get("dir_bust"):
            merged: dict = {}
            for base_u, paths in recon["dir_bust"].items():
                bucket = merged.setdefault(_norm_url(base_u), {})
                for p in paths or []:
                    u = p.get("url") if isinstance(p, dict) else str(p)
                    if not u:
                        continue
                    nu = _norm_url(u)
                    k = nu.lower()
                    cand = {**p, "url": nu} if isinstance(p, dict) else nu
                    prev = bucket.get(k)
                    if prev is None:
                        bucket[k] = cand
                    elif nu == k and (prev.get("url") if isinstance(prev, dict) else prev) != k:
                        bucket[k] = cand
            before = sum(len(v or []) for v in recon["dir_bust"].values())
            recon["dir_bust"] = {b: list(v.values()) for b, v in merged.items()}
            after = sum(len(v) for v in recon["dir_bust"].values())
            if after < before:
                log(f"deduped discovered paths: {before} -> {after} (port/case variants)", "info", "active")

        log("── Active detectors (confirm real vulns) ──", "hdr", "detect")
        from ..core import detectors
        auth_h = runconfig.auth_headers(config)
        confirmed = []
        for h in recon.get("live_hosts", [])[:3]:
            url = (h.get("url") or "").rstrip("/")
            if url:
                confirmed.extend(detectors.run_detectors(url, log, auth=auth_h))
        if config.get("headless_dast"):
            try:
                from . import dast as dast_mod
                dast_findings = dast_mod.run_dast(recon, config, log)
                if dast_findings:
                    confirmed.extend(dast_findings)
                    log(f"headless DAST added {len(dast_findings)} confirmed client-side issue(s)", "ok", "detect")
            except Exception as e:
                log(f"headless DAST skipped: {type(e).__name__}: {e}", "warn", "detect")
        try:
            from ..core import injection
            inj = injection.run_injection_tests(recon, config, log)
            if inj:
                confirmed.extend(inj)
        except Exception as e:
            log(f"injection testing skipped: {type(e).__name__}: {e}", "warn", "detect")

        recon["confirmed"] = confirmed
        log(f"detectors confirmed {len(confirmed)} issue(s)", "ok", "detect")
    else:
        log("Passive mode: skipping active enumeration.", "info", "mission")

    log("── Test-Guidance engine ──", "hdr", "guidance")
    pb = guidance_mod.build_guidance(recon)
    if recon.get("confirmed"):
        pb = guidance_mod.sort_guidance(recon["confirmed"] + pb)
    if config.get("ai_redteam"):
        from ..core import guidance_llm
        llm_pb = guidance_llm.build_llm_guidance(recon, config)
        log(f"AI RedTeam: {len(llm_pb)} LLM playbooks (OWASP LLM Top 10)", "ok", "guidance")
        pb = guidance_mod.sort_guidance(pb + llm_pb)
    from ..core import intuition
    hunches = intuition.build_intuition(recon, config)
    if hunches:
        log(f"Intuition: {len(hunches)} hunch(es) from endpoints/JS/signals", "info", "guidance")
        pb = guidance_mod.sort_guidance(pb + hunches)
    recon["_intuition_count"] = len(hunches)
    return recon, pb


def execute(mission_id: str, hub) -> None:
    m = db.get_mission(mission_id)
    if not m:
        return
    target = m["target"]
    mode = m["mode"]
    scope = m["scope"] or {}
    config = runconfig.normalize(m.get("config"))

    def log(message, level="info", phase="mission"):
        hub.emit(mission_id, level, phase, message)

    run_dir = db.DATA_DIR / "runs" / mission_id
    run_dir.mkdir(parents=True, exist_ok=True)

    db.update_mission(mission_id, status="running")
    hub.push(mission_id, {"type": "status", "status": "running"})
    log(f"Mission started · target={target} · mode={mode}", "ok", "mission")

    targets = _split_targets(target) or [target]
    multi = len(targets) > 1
    recon: dict = {"target": target, "targets": targets, "live_hosts": [],
                   "all_subdomains": [], "nmap": {"open_ports": []}, "nuclei": [],
                   "confirmed": [], "dir_bust": {}, "_intuition_count": 0}
    all_pb: list = []
    try:
        if multi:
            log(f"Batch mission: scanning {len(targets)} targets into one report", "ok", "mission")
        for i, t in enumerate(targets, 1):
            if multi:
                log(f"══════ Target {i}/{len(targets)} · {t} ══════", "hdr", "mission")
            t_dir = (run_dir / _safe_name(t)) if multi else run_dir
            t_dir.mkdir(parents=True, exist_ok=True)
            recon_t, pb_t = _scan_target(t, mode, scope, config, t_dir, log, hub, mission_id)
            all_pb.extend(pb_t)
            recon["live_hosts"].extend(recon_t.get("live_hosts", []))
            recon["all_subdomains"].extend(recon_t.get("all_subdomains") or recon_t.get("subdomains", []))
            recon["nmap"]["open_ports"].extend((recon_t.get("nmap") or {}).get("open_ports", []))
            recon["nuclei"].extend(recon_t.get("nuclei", []))
            recon["confirmed"].extend(recon_t.get("confirmed", []))
            recon["dir_bust"].update(recon_t.get("dir_bust", {}))
            recon["_intuition_count"] += recon_t.get("_intuition_count", 0)
            # carry first-seen per-domain passive data for reference
            for k in ("http", "email", "caa_records", "domain", "sub_cats", "takeover_candidates", "js_endpoints"):
                if k not in recon and recon_t.get(k) is not None:
                    recon[k] = recon_t.get(k)
        hub.push(mission_id, {"type": "phase_done", "phase": "active"})

        # ── merge every target's playbook into ONE report ───────────────────
        playbook = guidance_mod.sort_guidance(all_pb)
        gstats = guidance_mod.guidance_stats(playbook)
        log(f"generated {gstats['total']} test playbooks across {len(targets)} target(s): {gstats['by_severity']}", "ok", "guidance")

        # ── topology ────────────────────────────────────────────────────────
        topology = build_topology(recon, playbook)

        # ── stats ───────────────────────────────────────────────────────────
        stats = {
            "subdomains": len(set(recon.get("all_subdomains", []))),
            "live_hosts": len(recon.get("live_hosts", [])),
            "open_ports": len(recon.get("nmap", {}).get("open_ports", [])),
            "nuclei": len(recon.get("nuclei", [])),
            "confirmed": len(recon.get("confirmed", [])),
            "hunches": recon.get("_intuition_count", 0),
            "targets": len(targets),
            "guidance": gstats,
            "mode": mode,
            "speed": config["speed"],
            "recon_loop": config["recon_loop"],
            "ai_redteam": config["ai_redteam"],
            "headless_dast": config.get("headless_dast", False),
        }

        # ── optional AI executive summary ───────────────────────────────────
        ai_block = {}
        if ai_client.ai_enabled():
            log("AI triage (optional) …", "info", "ai")
            ai_block = _ai_summary(target, recon, playbook)
            if ai_block.get("triage"):
                log("AI executive summary attached.", "ok", "ai")
            else:
                log("AI enabled but returned nothing (key/model/quota?). Continuing.", "warn", "ai")
        else:
            log("AI disabled (no AI_API_KEY). Rule-based guidance is complete on its own.", "info", "ai")

        result = {
            "recon": recon,
            "guidance": playbook,
            "topology": topology,
            "stats": stats,
            "ai": ai_block,
            "ai_info": ai_client.ai_info(),
            "config": config,
        }
        db.update_mission(mission_id, status="completed", result=result, error=None)
        hub.push(mission_id, {"type": "done", "status": "completed", "stats": stats})
        log(f"Mission complete · {gstats['total']} playbooks · {stats['live_hosts']} live hosts", "ok", "mission")

    except Exception as e:  # noqa: BLE001
        import traceback

        tb = traceback.format_exc()
        db.update_mission(mission_id, status="failed", error=f"{type(e).__name__}: {e}",
                          result={"recon": recon, "traceback": tb})
        log(f"Mission failed: {type(e).__name__}: {e}", "err", "mission")
        hub.push(mission_id, {"type": "done", "status": "failed", "error": str(e)})


def cfg_from_env() -> dict:
    return {
        "threads": int(os.getenv("ROUNDTABLE_THREADS", "10")),
        "timeout": int(os.getenv("ROUNDTABLE_HTTP_TIMEOUT", "8")),
        "nuclei_severity": os.getenv("ROUNDTABLE_NUCLEI_SEVERITY", "medium,high,critical"),
        "ports": os.getenv("ROUNDTABLE_PORTS", "80,443,8080,8443,8888,3000,5000,9090,9200,27017,6379,5432,3306,2375,5601"),
    }


# ── topology ────────────────────────────────────────────────────────────────
def _max_sev_for(surface_matchers: list[str], guidance: list[dict]) -> str:
    best, best_rank = "INFO", 0
    for g in guidance:
        surf = (g.get("surface") or "").lower()
        if any(mm and mm in surf for mm in surface_matchers):
            r = SEV_RANK.get(g["severity"], 0)
            if r > best_rank:
                best_rank, best = r, g["severity"]
    return best


def build_topology(recon: dict, guidance: list[dict]) -> dict:
    from urllib.parse import urlparse

    target = recon.get("target", "target")
    nodes: list[dict] = []
    links: list[dict] = []
    seen: set[str] = set()

    def add_node(nid, label, ntype, severity="INFO", meta=None):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "type": ntype, "severity": severity, "meta": meta or {}})

    overall = _max_sev_for([target.lower()], guidance) if guidance else "INFO"
    add_node("root", target, "domain", overall, {"apex": target})

    live = recon.get("live_hosts", []) or []
    host_added = 0
    if live:
        for h in live[:40]:
            url = (h.get("url") or "").rstrip("/")
            if not url:
                continue
            host = urlparse(url).hostname or url
            sev = _max_sev_for([host.lower(), url.lower()], guidance)
            add_node(url, host, "host", sev, {
                "status": h.get("status-code"),
                "tech": h.get("tech", []),
                "title": (h.get("title") or "")[:60],
                "webserver": h.get("webserver", ""),
            })
            links.append({"source": "root", "target": url})
            host_added += 1
    else:
        # No active scan: show categorized subdomains from passive recon.
        for cat, subs in (recon.get("sub_cats") or {}).items():
            for s in subs[:8]:
                name = s["name"]
                add_node(name, name, "subdomain", s.get("severity", "INFO"), {"category": cat})
                links.append({"source": "root", "target": name})
                host_added += 1
            if host_added > 40:
                break

    # Open ports hang off the root.
    for line in (recon.get("nmap", {}).get("open_ports", []) or [])[:15]:
        mm = re.match(r"\s*(\d+)/tcp\s+\S+\s+(\S+)", line)
        if not mm:
            continue
        port, svc = mm.group(1), mm.group(2)
        nid = f"port:{port}"
        sev = _max_sev_for([f"{target}:{port}".lower(), f":{port}"], guidance)
        add_node(nid, f"{port}/{svc}", "port", sev, {"line": line.strip()})
        links.append({"source": "root", "target": nid})

    # High-value endpoints (guidance surfaces that are full URLs with a path).
    important = {"secrets", "vcs", "graphql", "swagger", "actuator", "admin", "backup", "idor"}
    ep = 0
    for g in guidance:
        if ep >= 20:
            break
        surf = g.get("surface", "")
        if not surf.startswith("http") or "/" not in surf.split("://", 1)[-1]:
            continue
        tags = set(g.get("tags", [])) | {g.get("key", "").split("-")[-1]}
        if not (tags & important):
            continue
        host = urlparse(surf).hostname or ""
        parent = next((n["id"] for n in nodes if n["type"] == "host" and host and host in n["id"]), "root")
        nid = f"ep:{g['id']}"
        add_node(nid, _short_path(surf), "endpoint", g["severity"], {"title": g["title"], "gid": g["id"]})
        links.append({"source": parent, "target": nid})
        ep += 1

    return {"nodes": nodes, "links": links}


def _short_path(url: str) -> str:
    from urllib.parse import urlparse

    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query[:20]
    return path[:32]


# ── optional AI ──────────────────────────────────────────────────────────────
def _ai_summary(target: str, recon: dict, guidance: list[dict]) -> dict:
    top = guidance[:15]
    lines = [f"TARGET: {target}", f"Live hosts: {len(recon.get('live_hosts', []))}", "TOP TEST PLAYBOOKS:"]
    for g in top:
        lines.append(f"- [{g['severity']}/{g['confidence_label']}] {g['title']} @ {g['surface']}")
    prompt = (
        "You are a senior bug-bounty triage lead. Below are the machine-generated test "
        "playbooks Round Table produced for an AUTHORIZED target. Do NOT exploit anything. "
        "Write, in plain text (no markdown headers, no emojis):\n"
        "1) A 4-6 sentence executive summary of the most promising surfaces.\n"
        "2) The 3 strongest attack chains (connect multiple playbooks; Step -> Step -> Impact).\n"
        "3) A prioritized 'test these first' list of 5 items with a one-line reason each.\n\n"
        + "\n".join(lines)
    )
    system = "You are an expert web-app pentest lead. Be specific, concise, and reference the provided data."
    try:
        text = asyncio.run(ai_client.complete(prompt, max_tokens=1600, system=system))
    except RuntimeError:
        # Rare: a loop is already running in this thread. Fall back to a fresh loop.
        loop = asyncio.new_event_loop()
        try:
            text = loop.run_until_complete(ai_client.complete(prompt, max_tokens=1600, system=system))
        finally:
            loop.close()
    return {"triage": text, "model": ai_client.ai_info().get("model")}
