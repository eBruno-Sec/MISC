"""
LANCELOT  //  Phase 3 — AI Triage
Feeds all recon data into OpenRouter (Claude, GPT-4o, Llama, etc.)
and gets back ranked findings, attack chains, and PoC guidance.
"""

import json
import requests
from pathlib import Path

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; M="\033[95m"; BOLD="\033[1m"; RST="\033[0m"

def ok(m):  print(f"  {G}[+]{RST} {m}")
def info(m):print(f"  {C}[*]{RST} {m}")
def warn(m):print(f"  {Y}[!]{RST} {m}")
def err(m): print(f"  {R}[-]{RST} {m}")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

SYSTEM_PROMPT = """You are an elite bug bounty hunter and penetration tester with 15+ years of experience.
You have been given raw intelligence data from a passive and active reconnaissance scan of a target domain.
Your job is to act as a senior hunter reviewing this data and providing triage output in three sections:

1. RANKED FINDINGS — List the top 10 most impactful findings from the data, ranked by bounty potential and exploitability. For each finding:
   - Severity (CRITICAL/HIGH/MEDIUM/LOW)
   - Finding name
   - Why it matters for bug bounty
   - Exploitability score (1-10)
   - Estimated bounty range if applicable

2. ATTACK CHAINS — Identify 3-5 realistic attack chains by connecting multiple findings together. Format:
   Chain name -> Step 1 -> Step 2 -> Step 3 -> Impact. Think like an attacker chaining weaknesses.

3. MANUAL INVESTIGATION PRIORITIES — List the top 5 things a hunter should manually verify RIGHT NOW, in priority order.
   For each: what to test, how to test it (specific tool commands or Burp steps), and what a valid PoC looks like.

Be specific, technical, and direct. No generic advice. Reference the actual data provided.
Output in plain text with clear section headers. No markdown. No emojis."""

def build_prompt(target, percival_data, galahad_data):
    """Build a focused, token-efficient prompt from recon data."""

    sections = []
    sections.append(f"TARGET: {target}\n")

    # WHOIS
    w = percival_data.get("whois", {})
    if w:
        sections.append(f"WHOIS: Registrar={w.get('registrar','?')} Created={w.get('created','?')} Expires={w.get('expires','?')} Privacy={w.get('privacy_redacted','?')}")

    # DNS
    sections.append(f"DNS: A={percival_data.get('a_records',[])} MX={percival_data.get('mx_records',[])} NS={percival_data.get('ns_records',[])}")
    if percival_data.get("caa_records"):
        sections.append(f"CAA: {percival_data['caa_records']}")
    else:
        sections.append("CAA: NONE (any CA can issue certs)")

    # Email security
    em = percival_data.get("email", {})
    sections.append(f"SPF: {em.get('spf','MISSING')}")
    sections.append(f"DMARC: {em.get('dmarc','MISSING')}")
    sections.append(f"DKIM selectors found: {[d['selector'] for d in em.get('dkim',[])]}")
    sections.append(f"BIMI: {em.get('bimi','not configured')}")

    # HTTP headers
    http = percival_data.get("http", {})
    if http.get("ok"):
        h = http.get("headers", {})
        missing_hdrs = []
        for name in ["strict-transport-security","content-security-policy","x-frame-options",
                     "x-content-type-options","referrer-policy","permissions-policy"]:
            if name not in h:
                missing_hdrs.append(name)
        sections.append(f"HTTP STATUS: {http.get('status')} HTTPS: {http.get('is_https')}")
        sections.append(f"MISSING SECURITY HEADERS: {missing_hdrs}")
        if h.get("server"):
            sections.append(f"SERVER HEADER: {h['server']}")
        if h.get("x-powered-by"):
            sections.append(f"X-POWERED-BY: {h['x-powered-by']}")
        if h.get("set-cookie"):
            cookie = h["set-cookie"]
            flags = []
            if "httponly" not in cookie.lower(): flags.append("missing HttpOnly")
            if "secure" not in cookie.lower():   flags.append("missing Secure")
            if "samesite" not in cookie.lower():  flags.append("missing SameSite")
            if flags:
                sections.append(f"COOKIE ISSUES: {', '.join(flags)}")

    # SSL
    ssl = percival_data.get("ssl", {})
    if "error" not in ssl:
        sections.append(f"SSL: issued_by={ssl.get('issued_by','?')} days_left={ssl.get('days_left','?')} SANs={ssl.get('san',[])[:5]}")
    else:
        sections.append(f"SSL ERROR: {ssl.get('error')}")

    # Tech stack
    vendors = percival_data.get("vendors", [])
    if vendors:
        critical_high = [v for v in vendors if v.get("rv") in ("CRITICAL","HIGH")]
        sections.append(f"TECH STACK (critical/high recon value): {[(v['name'],v['cat']) for v in critical_high]}")
        all_vendors = [(v['name'],v['rv']) for v in vendors]
        sections.append(f"FULL VENDOR LIST: {all_vendors}")

    # Subdomains
    sub_cats = percival_data.get("sub_cats", {})
    high_value_cats = ["CI/CD & DevOps","Security Infrastructure","Admin & Management","Payment & Financial"]
    for cat in high_value_cats:
        if cat in sub_cats:
            subs = [s["name"] for s in sub_cats[cat]][:10]
            sections.append(f"HIGH-VALUE SUBDOMAINS [{cat}]: {subs}")

    # Galahad data
    if galahad_data:
        # Live hosts
        live = galahad_data.get("live_hosts", [])
        if live:
            live_summary = [{"url": h.get("url"), "status": h.get("status-code"), "tech": h.get("tech",[])} for h in live[:15]]
            sections.append(f"LIVE HOSTS ({len(live)} total, showing 15): {json.dumps(live_summary)}")

        # Nmap
        nmap = galahad_data.get("nmap", {})
        if nmap.get("open_ports"):
            sections.append(f"OPEN PORTS: {nmap['open_ports'][:20]}")

        # Nuclei
        nuclei = galahad_data.get("nuclei", [])
        if nuclei:
            nuclei_summary = []
            for n in nuclei[:20]:
                info_block = n.get("info", {})
                nuclei_summary.append({
                    "name": info_block.get("name","") or n.get("raw","")[:60],
                    "severity": info_block.get("severity","?"),
                    "host": n.get("host",""),
                })
            sections.append(f"NUCLEI FINDINGS ({len(nuclei)} total): {json.dumps(nuclei_summary)}")

        # CORS and VCS
        misc = galahad_data.get("misc", [])
        if misc:
            sections.append(f"CORS/VCS FINDINGS: {json.dumps(misc[:10])}")

        # Dir bust
        dir_bust = galahad_data.get("dir_bust", {})
        if dir_bust:
            for url, paths in list(dir_bust.items())[:3]:
                if paths:
                    sections.append(f"PATHS FOUND ON {url}: {[p.get('url','') for p in paths[:10]]}")

        # Takeover candidates
        takeovers = galahad_data.get("takeover_candidates", [])
        if takeovers:
            crit = [t for t in takeovers if t.get("severity") == "CRITICAL"]
            if crit:
                sections.append(f"TAKEOVER CANDIDATES (CRITICAL): {crit[:5]}")

        # Total subdomains
        all_subs = galahad_data.get("all_subdomains", [])
        sections.append(f"TOTAL SUBDOMAINS DISCOVERED: {len(all_subs)}")

    return "\n".join(sections)

def call_openrouter(api_key, model, system_prompt, user_prompt, timeout=60):
    """Call OpenRouter API. Compatible with any OpenRouter model."""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/eBruno-Sec/round-table",
        "X-Title": "Round Table Bug Bounty Suite",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "max_tokens": 4000,
        "temperature": 0.3,
    }

    # Enable extended thinking for supported models (Claude 3.5+ via OpenRouter)
    thinking_models = ["anthropic/claude", "claude-"]
    if any(m in model.lower() for m in thinking_models):
        payload["thinking"] = {"type": "enabled", "budget_tokens": 2000}

    response = requests.post(
        OPENROUTER_URL,
        headers=headers,
        data=json.dumps(payload),
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    # Extract content from response
    choices = data.get("choices", [])
    if not choices:
        raise ValueError(f"No choices in response: {data}")

    message = choices[0].get("message", {})
    content = message.get("content", "")

    # Some models return content as list of blocks
    if isinstance(content, list):
        text_blocks = [b.get("text","") for b in content if b.get("type") == "text"]
        content = "\n".join(text_blocks)

    usage = data.get("usage", {})
    model_used = data.get("model", model)

    return content, usage, model_used

def run_lancelot(target, results, cfg):
    ai_cfg  = cfg.get("ai", {})
    api_key = ai_cfg.get("api_key","")
    model   = ai_cfg.get("model","meta-llama/llama-3.3-70b-instruct:free")
    timeout = ai_cfg.get("timeout", 60)

    if not api_key or api_key == "YOUR_KEY_HERE":
        warn("No OpenRouter API key configured. Skipping AI triage.")
        warn("Set your key in config.yaml under ai.api_key")
        warn("Get a free key at: https://openrouter.ai/keys")
        return {"skipped": True, "reason": "No API key"}

    percival_data = results.get("percival", {})
    galahad_data  = results.get("galahad",  {})

    info(f"Building intelligence prompt for {target}...")
    user_prompt = build_prompt(target, percival_data, galahad_data)

    info(f"Calling OpenRouter API (model: {model})...")
    info("This may take 15-60 seconds depending on the model...")

    try:
        content, usage, model_used = call_openrouter(
            api_key, model, SYSTEM_PROMPT, user_prompt, timeout
        )
    except requests.exceptions.HTTPError as e:
        err(f"OpenRouter API error: {e}")
        if e.response is not None:
            err(f"Response: {e.response.text[:300]}")
        return {"error": str(e)}
    except requests.exceptions.Timeout:
        err("OpenRouter request timed out. Try increasing ai.timeout in config.yaml")
        return {"error": "timeout"}
    except Exception as e:
        err(f"Lancelot error: {e}")
        return {"error": str(e)}

    ok(f"AI triage complete. Model: {model_used}")
    ok(f"Tokens used: prompt={usage.get('prompt_tokens','?')} completion={usage.get('completion_tokens','?')}")

    # Print triage output
    print(f"\n{M}{BOLD}{'═'*60}{RST}")
    print(f"{M}{BOLD}  LANCELOT  //  AI TRIAGE OUTPUT{RST}")
    print(f"{M}{BOLD}{'═'*60}{RST}\n")
    print(content)
    print(f"\n{M}{BOLD}{'═'*60}{RST}\n")

    return {
        "model": model_used,
        "triage": content,
        "usage": usage,
        "prompt_length": len(user_prompt),
    }
