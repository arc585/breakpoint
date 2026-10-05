"""
A general tool-using agent loop, reused by both sides of Breakpoint:
  * attacker agents (tools reach into the Target / PayPal to try an exploit)
  * the Barista shop assistant (tools apply discounts, create orders, refund)

Design, lifted from BeingAI's ad_agent engine:
  * the loop lives here, not in the model — up to MAX_TOOL_ITERATIONS turns;
  * a ToolBox maps tool name -> async handler; a handler returns (result, is_error);
  * retry/backoff on transient Anthropic errors, hard-fail on auth;
  * thinking blocks are serialized back verbatim so a thinking model stays happy;
  * the transcript is captured in full for the findings report.

The loop itself is neutral. What makes an agent "unsafe" or "hardened" is which
tools it is given and what those tools allow — the state machine is the tools.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import anthropic

from . import llm

logger = logging.getLogger(__name__)

MAX_TOOL_ITERATIONS = 10
MAX_TOKENS = 1024
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0
_RETRYABLE = (anthropic.RateLimitError, anthropic.InternalServerError, anthropic.APITimeoutError)

# A handler takes the tool input dict, returns (result_for_model, is_error).
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
    stopped: str = "end_turn"   # end_turn | max_iterations


def _serialize(resp: anthropic.types.Message) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for b in resp.content:
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


def _text_of(resp: anthropic.types.Message) -> str:
    return "\n".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()


async def _call_with_retry(client, *, model, system, messages, tools) -> anthropic.types.Message:
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            return await llm.call(
                client=client, model=model, system=system, messages=messages,
                tools=tools, max_tokens=MAX_TOKENS,
            )
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
    """Drive one agent to completion: it may call tools repeatedly until it
    stops with a text answer or hits the iteration cap."""
    client = llm.build_client(api_key)
    by_name = {t.name: t for t in tools}
    schemas = [t.schema() for t in tools]
    messages: list[dict[str, Any]] = [{"role": "user", "content": first_message}]
    transcript: list[dict[str, Any]] = [{"role": "user", "content": first_message}]
    tool_calls: list[dict[str, Any]] = []

    try:
        for _ in range(max_iterations):
            resp = await _call_with_retry(
                client, model=model, system=system, messages=messages, tools=schemas
            )
            content = _serialize(resp)
            messages.append({"role": "assistant", "content": content})
            transcript.append({"role": "assistant", "content": content})

            if resp.stop_reason != "tool_use":
                return RunResult(final_text=_text_of(resp), transcript=transcript, tool_calls=tool_calls)

            results = []
            for block in content:
                if block.get("type") != "tool_use":
                    continue
                tool = by_name.get(block["name"])
                if tool is None:
                    result, is_err = (f"No such tool: {block['name']}", True)
                else:
                    try:
                        result, is_err = await tool.handler(block["input"])
                    except Exception as exc:  # a tool bug must not crash the run
                        logger.exception("[redteam] tool %s raised", block["name"])
                        result, is_err = (f"Tool error: {exc}", True)
                tool_calls.append(
                    {"name": block["name"], "input": block["input"], "result": result, "is_error": is_err}
                )
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": result if isinstance(result, str) else _as_text(result),
                        "is_error": is_err,
                    }
                )
            messages.append({"role": "user", "content": results})
            transcript.append({"role": "user", "content": results})

        return RunResult(
            final_text=_text_of(resp), transcript=transcript, tool_calls=tool_calls, stopped="max_iterations"
        )
    finally:
        await client.close()


def _as_text(result: Any) -> str:
    import json

    try:
        return json.dumps(result, default=str)
    except TypeError:
        return str(result)
