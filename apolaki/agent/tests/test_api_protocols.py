"""SOAP/WSDL/gRPC API protocol inventory (Codex Tier-2 #8): WSDL parse seeds endpoints/operations, SOAP
endpoints seed XML-body candidates (routing to XXE, never a finding), gRPC is inventory-only, off-scope
WSDL service URLs are rejected."""
import api_protocols as P

_WSDL = """<?xml version="1.0"?>
<definitions name="Calc" xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/">
  <portType name="CalcPort">
    <operation name="Add"/><operation name="Subtract"/>
  </portType>
  <service name="CalculatorService">
    <port name="CalcSoap"><soap:address location="http://app.local/calc.asmx"/></port>
  </service>
</definitions>"""


def test_wsdl_parse_extracts_service_endpoint_and_operations():
    p = P.parse_wsdl(_WSDL)
    assert p["protocol"] == "soap" and p["service"] == "CalculatorService"
    assert p["endpoints"] == ["http://app.local/calc.asmx"]
    assert set(p["operations"]) == {"Add", "Subtract"}
    assert P.parse_wsdl("not xml") == {}


def test_detect_wsdl_links_in_html():
    html = '<a href="/svc?wsdl">svc</a> <a href="http://x/y.wsdl">y</a> <a href="/normal">n</a>'
    links = P.detect_wsdl_links(html, base_url="http://app.local/")
    assert "http://app.local/svc?wsdl" in links and "http://x/y.wsdl" in links
    assert all("wsdl" in l.lower() for l in links)


def test_soap_endpoint_seeds_xml_body_candidate_routing_to_xxe():
    cands = P.soap_body_candidates(P.parse_wsdl(_WSDL))
    assert len(cands) == 1
    c = cands[0]
    assert c["api_protocol"] == "soap" and c["candidate"] is True
    assert c["suggested_check"] == "xxe" and c["requires_runtime_validation"] is True
    assert "operations" in c and c["target"] == "http://app.local/calc.asmx"


def test_off_scope_wsdl_service_url_is_rejected():
    in_scope = lambda u: "app.local" in u
    ok = P.parse_wsdl(_WSDL)
    assert P.soap_body_candidates(ok, in_scope=in_scope)                 # app.local is in scope
    evil = {"protocol": "soap", "service": "X", "endpoints": ["http://evil.example/attack"], "operations": []}
    assert P.soap_body_candidates(evil, in_scope=in_scope) == []          # off-scope rejected


def test_grpc_is_inventory_observation_only():
    obs = P.grpc_observation(headers={"content-type": "application/grpc"}, url="http://app.local/svc")
    assert obs["api_protocol"] == "grpc" and obs["kind"] == "inventory_observation"
    assert "vulnerabilit" in obs["note"].lower()          # explicitly no vuln claim
    assert P.grpc_observation(headers={"content-type": "application/json"}) is None


def test_protocol_detection():
    assert P.detect_protocol(headers={"content-type": "application/grpc"}) == "grpc"
    assert P.detect_protocol(headers={"SOAPAction": '"urn:Add"'}, content_type="text/xml") == "soap"
    assert P.detect_protocol(path="/api/graphql") == "graphql"
    assert P.detect_protocol(path="/api/users", content_type="application/json") == "rest"


def test_inventory_is_descriptive_not_a_finding():
    inv = P.inventory([{"api_protocol": "soap", "target": "http://a/x"},
                       {"api_protocol": "grpc", "target": "http://a/y"}])
    assert set(inv["protocols"]) == {"soap", "grpc"} and inv["count"] == 2
    assert "no vulnerabilit" in inv["note"].lower()
