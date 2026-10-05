"""
Thin Anthropic layer — one stateless call per agentic turn.

Mirrors BeingAI's providers/llm/claude.py: the engine (loop.py) owns the loop;
this file is just the HTTP call that returns the raw Message so the engine can
read stop_reason and content blocks.
"""
from __future__ import annotations

import logging
from typing import Any

import anthropic

logger = logging.getLogger(__name__)


def build_client(api_key: str, *, timeout: float = 45.0) -> anthropic.AsyncAnthropic:
    return anthropic.AsyncAnthropic(api_key=api_key, timeout=timeout)


async def call(
    *,
    client: anthropic.AsyncAnthropic,
    model: str,
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
    max_tokens: int = 1024,
) -> anthropic.types.Message:
    kwargs: dict[str, Any] = {
        "model": model,
        "system": system,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if tools:
        kwargs["tools"] = tools
    logger.debug("Claude req: model=%s tools=%d msgs=%d", model, len(tools or []), len(messages))
    resp = await client.messages.create(**kwargs)
    logger.debug("Claude resp: stop=%s usage=%s", resp.stop_reason, resp.usage)
    return resp
