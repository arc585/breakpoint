"""
A general tool-using agent loop (Anthropic), reused by both sides of Breakpoint:
  * attacker agents (tools reach into the Target / PayPal to try an exploit)
  * (the Barista assistant has its own loop in target/barista.py)

Design, carried over from BeingAI's ad_agent engine:
  * the loop lives here, not in the model — up to MAX_TOOL_ITERATIONS turns;
  * a Tool maps name -> async handler; a handler returns (result, is_error);
  * retry/backoff on transient Anthropic errors, hard-fail on auth;
  * thinking blocks (if any) are serialized back verbatim.

Kept short to bound token spend (Haiku by default).
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import anthropic

from . import llm

logger = logging.getLogger(__name__)

MAX_TOOL_ITERATIONS = 5
MAX_TOKENS = 512
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0
_RETRYABLE = (anthropic.RateLimitError, anthropic.APITimeoutError, anthropic.InternalServerError)

ToolHandler = Callable[[dict[str, Any]], Awaitable[tuple[Any, bool]]]


class AgentError(RuntimeError):
    """The conversation could not be advanced (Claude unreachable or rejected)."""


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


@dataclass
class RunResult:
    final_text: str
    transcript: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    stopped: str = "end_turn"


def _serialize(content: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in content:
        kind = getattr(b, "type", None)
        if kind == "text":
            out.append({"type": "text", "text": b.text})
        elif kind == "tool_use":
            out.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})
        elif kind == "thinking":
            out.append({"type": "thinking", "thinking": b.thinking, "signature": b.signature})
        elif kind == "redacted_thinking":
            out.append({"type": "redacted_thinking", "data": b.data})
    return out


def _text_of(content: list[dict[str, Any]]) -> str:
    return "\n".join(b["text"] for b in content if b.get("type") == "text").strip()


async def _call_with_retry(client, *, model, system, messages, tools):
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            return await llm.call(client=client, model=model, system=system, messages=messages,
                                  tools=tools, max_tokens=MAX_TOKENS)
        except anthropic.AuthenticationError as exc:
            raise AgentError("ANTHROPIC_API_KEY was rejected by Anthropic.") from exc
        except _RETRYABLE as exc:
            last = exc
            if attempt == MAX_ATTEMPTS - 1:
                break
            delay = BACKOFF_BASE_S * (2 ** attempt)
            logger.warning("[redteam] %s; retry in %.1fs", type(exc).__name__, delay)
            await asyncio.sleep(delay)
        except anthropic.APIError as exc:
            raise AgentError(f"Could not reach Claude: {exc}") from exc
    raise AgentError(f"Claude unavailable after {MAX_ATTEMPTS} attempts: {last}")


async def run_agent(
    *,
    api_key: str,
    model: str,
    system: str,
    tools: list[Tool],
    first_message: str,
    max_iterations: int = MAX_TOOL_ITERATIONS,
) -> RunResult:
    client = llm.build_client(api_key)
    by_name = {t.name: t for t in tools}
    schemas = [t.schema() for t in tools]
    messages: list[dict[str, Any]] = [{"role": "user", "content": first_message}]
    transcript: list[dict[str, Any]] = [{"role": "user", "content": first_message}]
    tool_calls: list[dict[str, Any]] = []

    try:
        resp = None
        for _ in range(max_iterations):
            resp = await _call_with_retry(client, model=model, system=system, messages=messages, tools=schemas)
            blocks = _serialize(resp.content)
            messages.append({"role": "assistant", "content": blocks})
            transcript.append({"role": "assistant", "content": _text_of(blocks)})

            if resp.stop_reason != "tool_use":
                return RunResult(final_text=_text_of(blocks), transcript=transcript, tool_calls=tool_calls)

            results = []
            for b in blocks:
                if b.get("type") != "tool_use":
                    continue
                tool = by_name.get(b["name"])
                if tool is None:
                    result, is_err = (f"No such tool: {b['name']}", True)
                else:
                    try:
                        result, is_err = await tool.handler(b["input"])
                    except Exception as exc:
                        logger.exception("[redteam] tool %s raised", b["name"])
                        result, is_err = (f"Tool error: {exc}", True)
                tool_calls.append({"name": b["name"], "input": b["input"], "result": result, "is_error": is_err})
                results.append({"type": "tool_result", "tool_use_id": b["id"],
                                "content": result if isinstance(result, str) else _as_text(result),
                                "is_error": is_err})
            messages.append({"role": "user", "content": results})

        final = _text_of(_serialize(resp.content)) if resp else ""
        return RunResult(final_text=final, transcript=transcript, tool_calls=tool_calls, stopped="max_iterations")
    finally:
        await client.close()


def _as_text(result: Any) -> str:
    try:
        return json.dumps(result, default=str)
    except TypeError:
        return str(result)
