"""Unit tests for the AI/LLM attack-surface classifier (core/ai_surface.py)."""
from core.ai_surface import classify_endpoint, build_ai_surface


def test_chat_completions_path():
    tags = classify_endpoint("/v1/chat/completions", [])
    assert "llm-chat" in tags
    assert "llm-completion" in tags


def test_completion_by_param():
    # No path signal ("/talk"), but strong LLM params → still classified.
    assert classify_endpoint("/api/v2/talk", ["messages", "model"]) == ["llm-chat"]
    assert classify_endpoint("/api/run", ["prompt", "max_tokens"]) == ["llm-completion"]


def test_embedding_and_mcp_and_vectordb():
    assert classify_endpoint("/v1/embeddings", []) == ["llm-embedding"]
    assert classify_endpoint("/mcp", []) == ["mcp"]
    assert classify_endpoint("/collections/docs/points/search", []) == ["vector-db"]


def test_tool_call_and_agent():
    assert classify_endpoint("/api/agent/run", []) == ["llm-tool-call"]
    assert classify_endpoint("/function-call", []) == ["llm-tool-call"]


def test_sse_only_when_ai_signal_present():
    # Bare streaming endpoints must NOT be flagged (avoid false positives).
    assert classify_endpoint("/stream", []) == []
    assert classify_endpoint("/events", []) == []
    # …but chat + stream is a streaming chat endpoint.
    assert classify_endpoint("/chat/stream", []) == ["llm-chat", "sse-stream"]


def test_non_ai_endpoints_are_empty():
    assert classify_endpoint("/api/users", ["id", "page"]) == []
    assert classify_endpoint("/login", ["username", "password"]) == []
    assert classify_endpoint("/user-agent", []) == []      # not an /agent endpoint
    assert classify_endpoint("", None) == []


def test_build_ai_surface_filters_and_shapes():
    inv = [
        {"host": "t.example", "path": "/v1/chat/completions", "params": ["model"], "example": "https://t.example/v1/chat/completions"},
        {"host": "t.example", "path": "/api/users", "params": ["id"], "example": "https://t.example/api/users"},
        "junk", None, 123,
        {"host": "t.example", "path": "/embed", "params": []},
    ]
    out = build_ai_surface(inv)
    paths = {e["path"] for e in out}
    assert paths == {"/v1/chat/completions", "/embed"}   # non-AI + junk dropped
    chat = next(e for e in out if e["path"] == "/v1/chat/completions")
    assert "llm-chat" in chat["tags"]
    assert chat["host"] == "t.example"
    assert chat["params"] == ["model"]


def test_empty_input():
    assert build_ai_surface([]) == []
    assert build_ai_surface(None) == []


# ── Item 8 regression: root + noisy mined-param list must not false-positive ──
def test_root_with_noisy_generic_mined_params_not_flagged():
    # Exact shape of the reported bug: crawl root "/" carries a huge auto-mined
    # candidate parameter list (PARAM_MINE_CANDIDATES-style) that happens to
    # include the generic word "message" — that alone must never tag the root
    # as an LLM chat endpoint.
    noisy_params = [
        "account_id", "action", "admin", "body", "callback", "cmd", "comment",
        "content", "data", "debug", "dest", "dir", "doc", "download", "email",
        "exec", "export", "field", "file", "filter", "format", "id", "import",
        "include", "key", "lang", "limit", "message", "mode", "name", "next",
        "offset", "order", "orderId", "page", "path", "preview", "print",
        "productId", "q", "query", "redirect", "ref", "report", "return", "s",
        "search", "searchTerm", "sort", "source", "start", "step", "stockApi",
        "target", "template", "test", "title", "token", "trk", "type", "url",
        "user", "userId", "username", "value", "view", "xml",
    ]
    assert classify_endpoint("/", noisy_params) == []


def test_root_with_two_weak_llm_params_together_is_flagged():
    # A real second signal alongside "message" (not just generic mining noise)
    # should still be caught — the fix requires corroboration, not silence.
    assert classify_endpoint("/", ["message", "prompt"]) == ["llm-chat"]


def test_single_generic_weak_param_never_tags_any_path():
    assert classify_endpoint("/contact", ["message"]) == []
    assert classify_endpoint("/support/widget", ["prompt"]) == []


def test_distinctive_param_alone_still_tags():
    assert classify_endpoint("/api/v9/unusual-name", ["system_prompt"]) == ["llm-completion"]
    assert classify_endpoint("/api/v9/unusual-name", ["max_tokens"]) == ["llm-completion"]
