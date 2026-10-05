"""
Thin OpenAI layer — one stateless call per agentic turn.

The engine (loop.py) owns the loop; this is just the HTTP call that returns the
raw ChatCompletion so the engine can read finish_reason and tool_calls.

OpenAI chat-completions tool-calling: the system prompt is the first message
(role=system), tools are function schemas, and the model answers either with
text (finish) or with `tool_calls` (the engine runs them and feeds results back
as role=tool messages).
"""
from __future__ import annotations

import logging
from typing import Any

from openai import AsyncOpenAI

logger = logging.getLogger(__name__)


def build_client(api_key: str, *, timeout: float = 45.0) -> AsyncOpenAI:
    return AsyncOpenAI(api_key=api_key, timeout=timeout)


async def call(
    *,
    client: AsyncOpenAI,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    max_tokens: int = 1024,
) -> Any:
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"
    logger.debug("OpenAI req: model=%s tools=%d msgs=%d", model, len(tools or []), len(messages))
    resp = await client.chat.completions.create(**kwargs)
    logger.debug("OpenAI resp: finish=%s usage=%s", resp.choices[0].finish_reason, resp.usage)
    return resp
