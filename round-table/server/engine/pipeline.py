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

    recon: dict = {"target": target}
    try:
        # ── passive (always) ────────────────────────────────────────────────
        log("── Percival // passive recon ──", "hdr", "passive")
        recon.update(passive_mod.run_passive(target, run_dir, log))
        hub.push(mission_id, {"type": "phase_done", "phase": "passive"})

        # ── active (active/full only) ───────────────────────────────────────
        if mode in ("active", "full") and _scope_allows_active(scope):
            en = [t for t, on in config["tools"].items() if on]
            log("── Galahad // active enumeration ──", "hdr", "active")
            log(f"Active packets to in-scope hosts · speed={config['speed']} · tools: {', '.join(en) or 'none'}", "warn", "active")
            tee = _Tee(sys.stdout, lambda ln: hub.emit(mission_id, "trace", "active", ln))
            old = sys.stdout
            sys.stdout = tee
            try:
                active_mod.run_active(target, run_dir, recon, log, cfg_from_env(), config)
                # ── 3-step iterative recon loop (opt-in) ──
                if config.get("recon_loop"):
                    from . import loop as loop_mod
                    loop_mod.run_recon_loop(target, run_dir, recon, log, cfg_from_env(), config)
            finally:
                sys.stdout = old

            # ── active detectors: CONFIRM real vulns on live hosts ──
            log("── Active detectors (confirm real vulns) ──", "hdr", "detect")
            from ..core import detectors
            confirmed = []
            for h in recon.get("live_hosts", [])[:3]:
                url = (h.get("url") or "").rstrip("/")
                if url:
                    confirmed.extend(detectors.run_detectors(url, log))
            recon["confirmed"] = confirmed
            log(f"detectors confirmed {len(confirmed)} issue(s)", "ok", "detect")
            hub.push(mission_id, {"type": "phase_done", "phase": "active"})
        else:
            log("Passive mode: skipping active enumeration.", "info", "mission")

        # ── guidance (the buff) ─────────────────────────────────────────────
        log("── Test-Guidance engine ──", "hdr", "guidance")
        playbook = guidance_mod.build_guidance(recon)
        if recon.get("confirmed"):
            playbook = guidance_mod.sort_guidance(recon["confirmed"] + playbook)
        # ── AI RedTeam: OWASP-LLM-Top-10 advisory playbooks (opt-in) ──
        if config.get("ai_redteam"):
            from ..core import guidance_llm
            llm_pb = guidance_llm.build_llm_guidance(recon, config)
            log(f"AI RedTeam: {len(llm_pb)} LLM playbooks (OWASP LLM Top 10)", "ok", "guidance")
            playbook = guidance_mod.sort_guidance(playbook + llm_pb)
        gstats = guidance_mod.guidance_stats(playbook)
        log(f"generated {gstats['total']} test playbooks: {gstats['by_severity']}", "ok", "guidance")

        # ── topology ────────────────────────────────────────────────────────
        topology = build_topology(recon, playbook)

        # ── stats ───────────────────────────────────────────────────────────
        stats = {
            "subdomains": len(recon.get("all_subdomains") or recon.get("subdomains", [])),
            "live_hosts": len(recon.get("live_hosts", [])),
            "open_ports": len(recon.get("nmap", {}).get("open_ports", [])),
            "nuclei": len(recon.get("nuclei", [])),
            "confirmed": len(recon.get("confirmed", [])),
            "guidance": gstats,
            "mode": mode,
            "speed": config["speed"],
            "recon_loop": config["recon_loop"],
            "ai_redteam": config["ai_redteam"],
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
