"""Stealth / IDS-evasion nmap profiles (#113): named levels map to evasion flags (slower timing /
fragmentation / decoys — never DoS), and the widened run_nmap allowlist keeps those flags while still
refusing script selection, output files, input lists, and shell injection. Pure + deterministic."""
import stealth
from security import safe_flags

# the exact allowlist run_nmap uses (default port-scan prefixes + the evasion flags)
_ALLOW = ("-s", "-p", "-T", "--top-ports", "-Pn", "-n", "--open") + stealth.EVASION_FLAGS


def test_profiles_map_levels_to_flags():
    assert stealth.stealth_profile("off").startswith("-sT") and "-T3" in stealth.stealth_profile("off")
    assert "-T1" in stealth.stealth_profile("sneaky") and "-f" in stealth.stealth_profile("sneaky")
    p = stealth.stealth_profile("paranoid")
    assert "-T0" in p and "-f" in p and "-D RND:5" in p and "--data-length" in p
    assert stealth.stealth_profile("bogus") == stealth.stealth_profile("off")   # unknown -> off
    assert stealth.stealth_profile(None) == stealth.PROFILES["off"]
    assert set(stealth.LEVELS) == {"off", "polite", "sneaky", "paranoid"}


def test_evasion_flags_survive_the_gate_but_dangerous_ones_do_not():
    toks = safe_flags(stealth.stealth_profile("paranoid"), _ALLOW)
    for expect in ("-sS", "-T0", "-f", "-D", "RND:5", "--data-length", "24", "-sV", "--top-ports"):
        assert expect in toks, expect
    # the gate still refuses script selection / output files / input lists, and drops shell-meta tokens
    bad = safe_flags("--script vuln -oN /etc/cron.d/x -iL hosts.txt; rm -rf /", _ALLOW)
    assert "--script" not in bad and "-oN" not in bad and "-iL" not in bad and "-rf" not in bad
    assert not any(";" in t for t in bad)          # the injection token is dropped


def test_describe_non_empty_and_defaults():
    assert stealth.describe("paranoid") and stealth.describe("sneaky")
    assert stealth.describe("bogus") == stealth.describe("off")


def test_mission_stealth_reaches_the_nmap_flags(monkeypatch):
    """#113's real gap was reachability: the profiles existed but no operator could pick one. A stealth
    level set on the mission must reach the nmap command line without the caller passing it per-call."""
    import asyncio
    import stealth
    from scope import ScopeEngine
    from tools import ToolRegistry

    scope = ScopeEngine()
    scope.load_manual(["example.com"], [], "t")
    reg = ToolRegistry(scope, mission_id="m", stealth="paranoid")
    seen = {}

    async def fake_cmd(cmd, timeout=180):
        seen["cmd"] = list(cmd)
        return "<nmaprun></nmaprun>", ""

    monkeypatch.setattr(reg, "_cmd", fake_cmd)
    asyncio.run(reg.execute("run_nmap", {"target": "example.com"}, "s"))
    cmd = " ".join(seen["cmd"])
    assert "-T0" in cmd and "-f" in cmd and "-D" in cmd, cmd      # the paranoid profile's evasion flags
    # and the default mission stays exactly as it was
    reg2 = ToolRegistry(scope, mission_id="m")
    monkeypatch.setattr(reg2, "_cmd", fake_cmd)
    asyncio.run(reg2.execute("run_nmap", {"target": "example.com"}, "s"))
    assert "-T3" in " ".join(seen["cmd"]) and "-D" not in " ".join(seen["cmd"])


def test_no_stealth_profile_is_a_denial_of_service():
    """Evasion, never DoS: no profile may use nmap's most aggressive timing or any flood technique."""
    import stealth
    for level, flags in stealth.PROFILES.items():
        assert "-T5" not in flags and "-T4" not in flags, level
        for banned in ("--min-rate", "--max-retries 0", "-Pn --script dos", "dos"):
            assert banned not in flags, (level, banned)
