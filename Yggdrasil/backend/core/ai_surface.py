"""AI / LLM attack-surface classifier.

Passively tags discovered endpoints by their likely AI role (chat, completion,
embedding, tool-call, MCP, vector-DB) so an operator knows where to aim manual
LLM red-teaming: prompt injection, jailbreak, system-prompt extraction, context/
training-data exfiltration.

Concept borrowed from RedAmon's "AI Gauntlet", but this layer is deterministic —
it reads URLs/paths/param names only. It sends NO requests and calls NO LLM. It is
the map; the active LLM-attack module (garak/PyRIT-style probing) is a later step.
"""
import re

# (category, [path regexes]). Matched against the lowercased path.
AI_PATH_SIGNATURES = [
    ("llm-chat", [r"/chat(?:/|\b)", r"/chat[-_/]?completions?\b", r"/conversations?\b",
                  r"/assistant\b", r"/copilot\b", r"/v1/chat", r"/ask\b"]),
    ("llm-completion", [r"/completions?\b", r"/v1/completions", r"/generate\b",
                        r"/text[-_/]?generat"]),
    ("llm-embedding", [r"/embeddings?\b", r"/embed\b", r"/v1/embeddings"]),
    ("llm-tool-call", [r"/tool[-_]?calls?\b", r"/function[-_]?calls?\b", r"/agents?\b"]),
    ("mcp", [r"/mcp(?:/|\b)", r"/\.well-known/mcp"]),
    ("vector-db", [r"/collections\b", r"/points/search", r"/qdrant\b", r"/chroma\b",
                   r"/weaviate\b", r"/milvus\b", r"/vectors?\b"]),
]

# Query/body param names that strongly imply an LLM endpoint.
LLM_STRONG_PARAMS = {
    "prompt", "messages", "message", "completion", "temperature", "max_tokens",
    "top_p", "system_prompt", "presence_penalty", "frequency_penalty",
}


def classify_endpoint(path: str, params=None) -> list:
    """Return the sorted AI category tags for one endpoint (empty if not AI-ish).

    Path signatures give the category; strong LLM param names both add a signal and
    disambiguate chat vs completion. sse-stream is only tagged when there is already
    another AI signal, to avoid flagging generic /stream or /events endpoints."""
    p = (path or "").lower()
    tags = set()
    for cat, patterns in AI_PATH_SIGNATURES:
        if any(re.search(rx, p) for rx in patterns):
            tags.add(cat)

    lp = {str(x).lower() for x in (params or [])}
    if lp & LLM_STRONG_PARAMS:
        if "messages" in lp or "message" in lp or "/chat" in p:
            tags.add("llm-chat")
        else:
            tags.add("llm-completion")

    if re.search(r"/(?:sse|stream)\b", p) and tags:
        tags.add("sse-stream")

    return sorted(tags)


def build_ai_surface(inventory) -> list:
    """Classify a surface inventory (list of {host, path, params, example}) into the
    AI-endpoint subset. Returns [{host, path, example, params, tags}], only for
    endpoints that matched at least one AI category."""
    out = []
    for e in inventory or []:
        if not isinstance(e, dict):
            continue
        tags = classify_endpoint(e.get("path", ""), e.get("params"))
        if tags:
            out.append({
                "host": e.get("host", ""),
                "path": e.get("path", ""),
                "example": e.get("example", ""),
                "params": list(e.get("params", []) or []),
                "tags": tags,
            })
    return out
