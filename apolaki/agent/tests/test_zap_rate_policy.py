from __future__ import annotations

import asyncio

import browser_engine
import pytest
import zap_client


def _run(awaitable):
    return asyncio.run(awaitable)


class _SafetyApi(zap_client.ZapClient):
    def __init__(self, expose_rule=True):
        super().__init__(addr="http://zap:8090", api_key="test")
        self.calls = []
        self.rule = None
        self.expose_rule = expose_rule

    async def _call(self, component, kind, action, **params):
        self.calls.append((component, kind, action, params))
        if action == "removeRateLimitRule":
            self.rule = None
            return {"Result": "OK"}
        if action == "addRateLimitRule":
            self.rule = {
                "description": params["description"],
                "matchString": params["matchString"],
                "requestsPerSecond": float(params["requestsPerSecond"]),
                "groupBy": params["groupBy"].upper(),
                "matchRegex": False,
                "enabled": params["enabled"] == "true",
            }
            return {"Result": "OK"}
        if action == "getRateLimitRules":
            return {"getRateLimitRules": [self.rule] if self.rule and self.expose_rule else []}
        return {"Result": "OK"}


def test_target_safety_is_read_back_from_zap_not_assumed_from_action_success():
    client = _SafetyApi()
    state = _run(client.configure_target_safety(
        "https://zap-target.example:8443/", hosts=["api.zap-target.example", "*.other.example"]))

    assert state["hosts"] == ["api.zap-target.example", "other.example", "zap-target.example"]
    assert state["requests_per_second"] == 1.0
    adds = [call for call in client.calls if call[2] == "addRateLimitRule"]
    assert {call[3]["matchString"] for call in adds} == set(state["hosts"])
    assert all(call[3]["requestsPerSecond"] == "1" for call in adds)
    assert any(call[2] == "getRateLimitRules" for call in client.calls)


def test_action_success_without_an_active_rule_fails_closed():
    client = _SafetyApi(expose_rule=False)
    with pytest.raises(RuntimeError, match="was not active"):
        _run(client.configure_target_safety("https://zap-target.example/"))


def test_seed_uses_one_observable_request_without_redirect_following():
    class Seed(zap_client.ZapClient):
        async def _call(self, component, kind, action, **params):
            assert (component, kind, action) == ("core", "action", "sendRequest")
            assert params["followRedirects"] == "false"
            assert params["request"].startswith(
                "GET https://zap-target.example:8443/a?b=1 HTTP/1.1\r\n")
            assert "\r\nHost: zap-target.example:8443\r\n" in params["request"]
            assert "\r\nX-Apolaki-ZAP-Seed: seed-1\r\n" in params["request"]
            return {"sendRequest": [{"responseHeader": "HTTP/1.1 200 OK"}]}

    result = _run(Seed(addr="http://zap:8090").access_url(
        "https://zap-target.example:8443/a?b=1", request_id="seed-1"))

    assert "sendRequest" in result


def test_stop_all_has_no_silently_invalid_ajax_actions():
    class StopApi(zap_client.ZapClient):
        def __init__(self):
            super().__init__(addr="http://zap:8090")
            self.calls = []

        async def _call(self, component, kind, action, **params):
            self.calls.append((component, kind, action))
            return {"Result": "OK"}

    client = StopApi()
    _run(client.stop_all())

    assert ("ajaxSpider", "action", "stop") in client.calls
    assert not any(component == "ajaxSpider" and action in {
        "stopAllScans", "removeAllScans"} for component, _kind, action in client.calls)


def test_zap_history_retry_after_updates_the_shared_policy():
    class History(zap_client.ZapClient):
        async def history_cursor(self):
            return 1

        async def _call(self, component, kind, action, **params):
            assert (component, kind, action) == ("core", "view", "messages")
            return {"messages": [{
                "id": "1",
                "requestHeader": "GET https://zap-target.example/a HTTP/1.1\r\nHost: zap-target.example\r\n\r\n",
                "responseHeader": "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\r\n",
            }]}

    clock = [0.0]
    policy = browser_engine.TargetRatePolicy(max_wait=5, clock=lambda: clock[0])
    cursor, event = _run(History(addr="http://zap:8090").observe_rate_limits(
        0, "https://zap-target.example/", policy, allowed_hosts=["api.zap-target.example"]))

    assert cursor == 1
    assert event["status"] == 429 and event["retry_after_seconds"] == 2
    assert policy.remaining("https://zap-target.example/next") == 2


def test_incomplete_zap_history_row_is_retried_not_consumed():
    class CommittingHistory(zap_client.ZapClient):
        def __init__(self):
            super().__init__(addr="http://zap:8090")
            self.reads = 0

        async def history_cursor(self):
            return 1

        async def _call(self, component, kind, action, **params):
            assert (component, kind, action) == ("core", "view", "messages")
            self.reads += 1
            response = "" if self.reads == 1 else (
                "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\r\n")
            return {"messages": [{
                "id": "1",
                "requestHeader": (
                    "GET https://zap-target.example/a HTTP/1.1\r\n"
                    "Host: zap-target.example\r\n\r\n"),
                "responseHeader": response,
            }]}

    clock = [0.0]
    policy = browser_engine.TargetRatePolicy(max_wait=5, clock=lambda: clock[0])
    client = CommittingHistory()

    first_cursor, first_event = _run(client.observe_rate_limits(
        0, "https://zap-target.example/", policy))
    second_cursor, second_event = _run(client.observe_rate_limits(
        first_cursor, "https://zap-target.example/", policy))

    assert first_cursor == 0 and first_event is None
    assert second_cursor == 1 and second_event["status"] == 429
    assert client.reads == 2


def test_message_observation_rejects_non_http_and_malformed_rows():
    assert zap_client.message_observation({}) is None
    assert zap_client.message_observation({
        "requestHeader": "CONNECT zap-target.example:443 HTTP/1.1\r\n\r\n",
        "responseHeader": "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 2\r\n\r\n",
    }) is None


def test_alerts_are_attributed_only_to_messages_created_after_the_pass_cursor():
    class History(zap_client.ZapClient):
        async def history_cursor(self):
            return 12

        async def _call(self, component, kind, action, **params):
            assert (component, kind, action) == ("core", "view", "messages")
            assert params == {"start": 10, "count": 2}
            return {"messages": [{"id": "11"}, {"id": "12"}]}

        async def alerts(self, baseurl=None, count=1000):
            assert baseurl == "https://zap-target.example"
            return [
                {"alert": "old", "messageId": "7"},
                {"alert": "current", "messageId": "11"},
                {"alert": "current-source", "sourceMessageId": 12},
                {"alert": "unattributed"},
            ]

    alerts, retained = _run(History(addr="http://zap:8090").alerts_since(
        10, baseurl="https://zap-target.example"))

    assert [alert["alert"] for alert in alerts] == ["current", "current-source"]
    assert retained == 4
