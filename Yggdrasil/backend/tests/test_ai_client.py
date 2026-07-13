"""Items 1+2: core.ai_client.complete() must never swallow a real failure into
a blank string. No key -> AIUnavailable. A call attempted but failing for any
reason (SDK error, network error, HTTP error, empty response) -> AICompletionError
carrying provider/model/status/detail. This is the root-cause fix for MIMIR's
old "Expecting value: line 1 column 1 (char 0)" crash: that error only existed
because complete() used to return "" on every failure path.
"""
import importlib.util
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

HAS_HTTPX = importlib.util.find_spec("httpx") is not None
HAS_ANTHROPIC = importlib.util.find_spec("anthropic") is not None


class _EnvGuard(unittest.IsolatedAsyncioTestCase):
    """Snapshots and restores every AI_*/ANTHROPIC_API_KEY env var so tests
    never leak config into each other or depend on the real environment."""
    KEYS = ("AI_PROVIDER", "AI_API_KEY", "AI_MODEL", "AI_BASE_URL", "ANTHROPIC_API_KEY")

    async def asyncSetUp(self):
        self._saved = {k: os.environ.get(k) for k in self.KEYS}
        for k in self.KEYS:
            os.environ.pop(k, None)

    async def asyncTearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class AIUnavailableTests(_EnvGuard):
    async def test_no_key_raises_ai_unavailable_not_blank_string(self):
        from core.ai_client import complete, AIUnavailable
        with self.assertRaises(AIUnavailable) as ctx:
            await complete("hello")
        self.assertEqual(ctx.exception.provider, "anthropic")
        self.assertIn("anthropic", str(ctx.exception))

    async def test_no_key_respects_configured_provider(self):
        from core.ai_client import complete, AIUnavailable
        os.environ["AI_PROVIDER"] = "openrouter"
        with self.assertRaises(AIUnavailable) as ctx:
            await complete("hello")
        self.assertEqual(ctx.exception.provider, "openrouter")

    async def test_blank_key_treated_as_no_key(self):
        from core.ai_client import complete, AIUnavailable
        os.environ["AI_API_KEY"] = ""
        with self.assertRaises(AIUnavailable):
            await complete("hello")


class AICompletionErrorShapeTests(unittest.TestCase):
    """AICompletionError must carry the real provider/model/status, and must
    truncate detail so a giant error body can't blow out a log line."""

    def test_carries_provider_model_status_detail(self):
        from core.ai_client import AICompletionError
        err = AICompletionError("anthropic", "claude-sonnet-4-6", "HTTP 401", "invalid x-api-key")
        self.assertEqual(err.provider, "anthropic")
        self.assertEqual(err.model, "claude-sonnet-4-6")
        self.assertEqual(err.status, "HTTP 401")
        self.assertEqual(err.detail, "invalid x-api-key")
        self.assertIn("anthropic/claude-sonnet-4-6", str(err))
        self.assertIn("HTTP 401", str(err))

    def test_detail_truncated_to_300_chars(self):
        from core.ai_client import AICompletionError
        err = AICompletionError("anthropic", "m", "status", "x" * 5000)
        self.assertEqual(len(err.detail), 300)

    def test_none_detail_becomes_empty_string_not_none(self):
        from core.ai_client import AICompletionError
        err = AICompletionError("anthropic", "m", "status")
        self.assertEqual(err.detail, "")


class AnthropicDispatchTests(_EnvGuard):
    """Drives the real complete() -> _anthropic() path with the SDK mocked out,
    proving the actual shipped error-extraction logic (not a hand reimplementation)
    turns an SDK exception into a structured AICompletionError."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        os.environ["AI_PROVIDER"] = "anthropic"
        os.environ["AI_API_KEY"] = "sk-ant-test-key"

    def _fake_anthropic_module(self, create_side_effect=None, create_return=None):
        fake_module = MagicMock()
        client = MagicMock()
        client.messages.create = AsyncMock(side_effect=create_side_effect, return_value=create_return)
        fake_module.AsyncAnthropic.return_value = client
        return fake_module

    async def test_sdk_error_becomes_ai_completion_error_with_status_and_detail(self):
        from core.ai_client import complete, AICompletionError

        class FakeAPIError(Exception):
            def __init__(self):
                self.status_code = 401
                self.message = "invalid x-api-key"
                super().__init__("invalid x-api-key")

        fake_module = self._fake_anthropic_module(create_side_effect=FakeAPIError())
        with patch.dict("sys.modules", {"anthropic": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.provider, "anthropic")
        self.assertEqual(ctx.exception.status, "HTTP 401")
        self.assertIn("invalid x-api-key", ctx.exception.detail)

    async def test_sdk_error_without_status_code_falls_back_to_exception_type(self):
        from core.ai_client import complete, AICompletionError

        class FakeConnectionError(Exception):
            pass

        fake_module = self._fake_anthropic_module(create_side_effect=FakeConnectionError("boom"))
        with patch.dict("sys.modules", {"anthropic": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.status, "FakeConnectionError")
        self.assertIn("boom", ctx.exception.detail)

    async def test_empty_content_becomes_ai_completion_error_not_blank_string(self):
        from core.ai_client import complete, AICompletionError
        resp = MagicMock()
        resp.content = []
        fake_module = self._fake_anthropic_module(create_return=resp)
        with patch.dict("sys.modules", {"anthropic": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.status, "empty_response")

    async def test_whitespace_only_content_becomes_ai_completion_error(self):
        from core.ai_client import complete, AICompletionError
        block = MagicMock()
        block.text = "   \n  "
        resp = MagicMock()
        resp.content = [block]
        fake_module = self._fake_anthropic_module(create_return=resp)
        with patch.dict("sys.modules", {"anthropic": fake_module}):
            with self.assertRaises(AICompletionError):
                await complete("hello")

    async def test_successful_reply_returns_stripped_text(self):
        from core.ai_client import complete
        block = MagicMock()
        block.text = "  {\"ok\": true}  "
        resp = MagicMock()
        resp.content = [block]
        fake_module = self._fake_anthropic_module(create_return=resp)
        with patch.dict("sys.modules", {"anthropic": fake_module}):
            text = await complete("hello")
        self.assertEqual(text, '{"ok": true}')


class OpenRouterDispatchTests(_EnvGuard):
    """Same coverage for the OpenRouter path: HTTP-status errors, in-body error
    envelopes, missing-choices, and network exceptions all become AICompletionError."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        os.environ["AI_PROVIDER"] = "openrouter"
        os.environ["AI_API_KEY"] = "sk-or-test-key"

    def _fake_httpx_module(self, post_side_effect=None, post_return=None):
        fake_module = MagicMock()

        class _FakeAsyncClient:
            def __init__(self, *a, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **kw):
                if post_side_effect:
                    raise post_side_effect
                return post_return

        fake_module.AsyncClient = _FakeAsyncClient
        return fake_module

    def _resp(self, status_code=200, json_data=None, text=""):
        r = MagicMock()
        r.status_code = status_code
        r.text = text
        r.json.return_value = json_data
        return r

    async def test_http_error_status_becomes_ai_completion_error(self):
        from core.ai_client import complete, AICompletionError
        resp = self._resp(status_code=401, text="Unauthorized")
        fake_module = self._fake_httpx_module(post_return=resp)
        with patch.dict("sys.modules", {"httpx": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.status, "HTTP 401")
        self.assertIn("Unauthorized", ctx.exception.detail)

    async def test_200_with_error_envelope_becomes_ai_completion_error(self):
        from core.ai_client import complete, AICompletionError
        resp = self._resp(status_code=200, json_data={"error": {"message": "rate limited"}})
        fake_module = self._fake_httpx_module(post_return=resp)
        with patch.dict("sys.modules", {"httpx": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.status, "provider_error")
        self.assertIn("rate limited", ctx.exception.detail)

    async def test_missing_choices_becomes_ai_completion_error(self):
        from core.ai_client import complete, AICompletionError
        resp = self._resp(status_code=200, json_data={"id": "x"})
        fake_module = self._fake_httpx_module(post_return=resp)
        with patch.dict("sys.modules", {"httpx": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertEqual(ctx.exception.status, "no_choices")

    async def test_network_exception_becomes_ai_completion_error(self):
        from core.ai_client import complete, AICompletionError
        fake_module = self._fake_httpx_module(post_side_effect=ConnectionError("dns failure"))
        with patch.dict("sys.modules", {"httpx": fake_module}):
            with self.assertRaises(AICompletionError) as ctx:
                await complete("hello")
        self.assertIn("dns failure", ctx.exception.detail)

    async def test_successful_reply_returns_stripped_text(self):
        from core.ai_client import complete
        resp = self._resp(status_code=200, json_data={
            "choices": [{"message": {"content": "  hello back  "}}]
        })
        fake_module = self._fake_httpx_module(post_return=resp)
        with patch.dict("sys.modules", {"httpx": fake_module}):
            text = await complete("hello")
        self.assertEqual(text, "hello back")


if __name__ == "__main__":
    unittest.main()
