"""Stealth / IDS-evasion profiles for Apolaki's OWN nmap scan (#113).

Named quiet-to-loud profiles mapping to nmap flag strings that the `run_nmap` tool passes through its
safe_flags allowlist. This is EVASION, not denial-of-service: slower timing, fragmentation, decoys,
packet padding, source-port games — techniques that make an AUTHORIZED scan harder for an IDS to
attribute, never techniques that flood or crash the target (no -T5 storm, no packet floods). Pure +
deterministic; the tool wrapper runs nmap. Fragmentation / decoy / SYN scan need raw-socket privileges
(present when nmap runs as root, as it does in the agent container).
"""
from __future__ import annotations

_BASE = "-sV --top-ports 1000"

# level -> nmap flags, ascending quietness (and ascending evasion). Every flag is within the run_nmap
# safe_flags allowlist below; none is a DoS technique.
PROFILES = {
    "off":      "-sT %s -T3" % _BASE,                               # default: connect scan, normal speed
    "polite":   "-sT %s -T2" % _BASE,                               # slower connect scan (unprivileged-safe)
    "sneaky":   "-sS %s -T1 -f" % _BASE,                            # half-open SYN, slow, fragmented
    "paranoid": "-sS %s -T0 -f -D RND:5 --data-length 24" % _BASE,  # slowest, fragmented, 5 decoys, padded
}
LEVELS = tuple(PROFILES)

# the extra flag prefixes these profiles need beyond the default port-scan allowlist. The run_nmap gate
# must permit EXACTLY these (evasion) and nothing that selects scripts, output files, or input lists.
EVASION_FLAGS = ("-f", "-D", "--data-length", "-g", "--source-port", "--mtu")

_DESC = {
    "off": "normal-speed TCP connect scan, no evasion",
    "polite": "slower connect scan to stay under rate-based alerts",
    "sneaky": "half-open SYN scan, slow timing, fragmented packets",
    "paranoid": "slowest timing, fragmented, 5 random decoys, padded packets",
}


def _norm(level) -> str:
    lv = str(level or "off").lower().strip()
    return lv if lv in PROFILES else "off"


def stealth_profile(level: str = None) -> str:
    """nmap flag string for a named stealth level (default/unknown -> 'off' = today's behaviour)."""
    return PROFILES[_norm(level)]


def describe(level: str = None) -> str:
    return _DESC[_norm(level)]
