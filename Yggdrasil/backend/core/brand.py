"""Shared Yggdrasil stage labels.

The internal agent keys remain the original Olympus-compatible names so old
mission context and API clients keep working. User-facing labels are Norse to
match the Yggdrasil UI and README.
"""

# Release codename for this revision of the platform. Bumped per named
# milestone; shown in the startup banner and the report footer.
RELEASE = "Aang"

AGENTS = {
    "zeus": {"name": "ODIN", "symbol": "OD", "role": "Orchestration"},
    "athena": {"name": "FRIGG", "symbol": "FR", "role": "Strategy"},
    "hermes": {"name": "HEIMDALL", "symbol": "HE", "role": "Recon"},
    "ares": {"name": "TYR", "symbol": "TY", "role": "Active Assessment"},
    "hephaestus": {"name": "BROKKR", "symbol": "BR", "role": "Payload Forge"},
    "hades": {"name": "SKULD", "symbol": "SK", "role": "Impact Review"},
    "metis": {"name": "MIMIR", "symbol": "MI", "role": "Triage"},
    "apollo": {"name": "SAGA", "symbol": "SA", "role": "Reporting"},
}


def agent_meta(key: str | None) -> dict:
    if key and key in AGENTS:
        return AGENTS[key]
    label = (key or "agent").upper()
    return {"name": label, "symbol": label[:2], "role": "Assessment Stage"}


def agent_display_name(key: str | None) -> str:
    return agent_meta(key)["name"]


def agent_symbol(key: str | None) -> str:
    return agent_meta(key)["symbol"]
