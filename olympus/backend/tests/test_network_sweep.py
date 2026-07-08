"""Unit tests for the CIDR network-sweep nmap parser (agents/hermes.py)."""
from agents.hermes import parse_nmap_greppable, NETWORK_SERVICE_RISK, NETWORK_SWEEP_PORTS


GREPPABLE = "\n".join([
    "# Nmap 7.94 scan initiated",
    "Host: 10.0.0.5 ()\tStatus: Up",
    "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.2p1 Ubuntu/, "
    "3389/open/tcp//ms-wbt-server///, 80/filtered/tcp//http///\tIgnored State: closed (29)",
    "Host: 10.0.0.9 ()\tStatus: Up",  # up, no open service ports
    "Host: 10.0.0.20 ()\tStatus: Down",
    "Host: 10.0.0.30 ()\tPorts: 6379/open/tcp//redis///\tIgnored State: closed (31)",
    "# Nmap done",
])


def test_parses_open_ports_with_versions():
    parsed = parse_nmap_greppable(GREPPABLE)
    host = parsed["10.0.0.5"]
    assert host["status"] == "up"
    ports = {p["port"]: p for p in host["ports"]}
    assert set(ports) == {22, 3389}                      # filtered/80 excluded
    assert ports[22]["service"] == "ssh"
    assert ports[22]["version"] == "OpenSSH 8.2p1 Ubuntu"
    assert ports[3389]["service"] == "ms-wbt-server"
    assert ports[22]["proto"] == "tcp"


def test_up_host_with_no_open_ports_is_kept():
    parsed = parse_nmap_greppable(GREPPABLE)
    assert parsed["10.0.0.9"]["status"] == "up"
    assert parsed["10.0.0.9"]["ports"] == []


def test_down_host_marked_down():
    parsed = parse_nmap_greppable(GREPPABLE)
    assert parsed["10.0.0.20"]["status"] == "down"


def test_open_port_without_status_line_still_up():
    # 10.0.0.30 only ever appears on a Ports line — an open port implies Up.
    parsed = parse_nmap_greppable(GREPPABLE)
    assert parsed["10.0.0.30"]["status"] == "up"
    assert parsed["10.0.0.30"]["ports"][0]["port"] == 6379


def test_empty_and_junk_input():
    assert parse_nmap_greppable("") == {}
    assert parse_nmap_greppable(None) == {}
    assert parse_nmap_greppable("not an nmap line\nHost:\n") == {}


def test_risk_table_ports_are_scanned():
    # Every service we flag must actually be in the port set we scan, or we'd never
    # see it. (Web ports live in the sweep set but not the risk table by design.)
    swept = {int(p) for p in NETWORK_SWEEP_PORTS.split(",")}
    assert set(NETWORK_SERVICE_RISK).issubset(swept)


def test_risk_table_severities_valid():
    valid = {"info", "low", "medium", "high", "critical"}
    for port, (name, sev, cvss, desc) in NETWORK_SERVICE_RISK.items():
        assert sev in valid, f"{name} has bad severity {sev}"
        assert isinstance(cvss, (int, float))
        assert name and desc
