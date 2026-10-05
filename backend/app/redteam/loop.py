"""
A general tool-using agent loop (OpenAI), reused by both sides of Breakpoint:
  * attacker agents (tools reach into the Target / PayPal to try an exploit)
  * the Barista shop assistant (tools apply discounts, create orders, refund)

Design, carried over from BeingAI's ad_agent engine:
  * the loop lives here, not in the model — up to MAX_TOOL_ITERATIONS turns;
  * a Tool maps name -> async handler; a handler returns (result, is_error);
  * retry/backoff on transient OpenAI errors, hard-fail on auth;
  * the full transcript is captured for the findings report.

The loop itself is neutral. What makes an agent "unsafe" or "hardened" is which
tools it is given and what those tools allow — the state machine is the tools.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import openai

from . import llm

logger = logging.getLogger(__name__)

MAX_TOOL_ITERATIONS = 10
MAX_TOKENS = 1024
MAX_ATTEMPTS = 3
BACKOFF_BASE_S = 1.0
_RETRYABLE = (openai.RateLimitError, openai.APITimeoutError, openai.InternalServerError)

# A handler takes the parsed tool-input dict, returns (result_for_model, is_error).
ToolHandler = Callable[[dict[str, Any]], Awaitable[tuple[Any, bool]]]


class AgentError(RuntimeError):
    """The conversation could not be advanced (OpenAI unreachable or rejected)."""


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler

    def schema(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.input_schema,
            },
        }


@dataclass
class RunResult:
    final_text: str
    transcript: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    stopped: str = "stop"  # stop | max_iterations


async def _call_with_retry(client, *, model, messages, tools) -> Any:
    last: Exception | None = None
    for attempt in range(MAX_ATTEMPTS):
        try:
            return await llm.call(
                client=client, model=model, messages=messages, tools=tools, max_tokens=MAX_TOKENS
            )
        except openai.AuthenticationError as exc:
            raise AgentError("OPENAI_API_KEY was rejected by OpenAI.") from exc
        except _RETRYABLE as exc:
            last = exc
            if attempt == MAX_ATTEMPTS - 1:
                break
            delay = BACKOFF_BASE_S * (2 ** attempt)
            logger.warning("[redteam] %s; retry in %.1fs", type(exc).__name__, delay)
            await asyncio.sleep(delay)
        except openai.APIError as exc:
            raise AgentError(f"Could not reach OpenAI: {exc}") from exc
    raise AgentError(f"OpenAI unavailable after {MAX_ATTEMPTS} attempts: {last}")


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
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": first_message},
    ]
    transcript: list[dict[str, Any]] = [{"role": "user", "content": first_message}]
    tool_calls: list[dict[str, Any]] = []

    try:
        resp = None
        for _ in range(max_iterations):
            resp = await _call_with_retry(client, model=model, messages=messages, tools=schemas)
            msg = resp.choices[0].message
            # Record the assistant turn verbatim so OpenAI keeps tool_call linkage.
            messages.append(msg.model_dump(exclude_none=True))
            transcript.append(
                {"role": "assistant", "content": msg.content or "",
                 "tool_calls": [tc.model_dump() for tc in (msg.tool_calls or [])]}
            )

            if not msg.tool_calls:
                return RunResult(final_text=msg.content or "", transcript=transcript, tool_calls=tool_calls)

            for tc in msg.tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                tool = by_name.get(name)
                if tool is None:
                    result, is_err = (f"No such tool: {name}", True)
                else:
                    try:
                        result, is_err = await tool.handler(args)
                    except Exception as exc:  # a tool bug must not crash the run
                        logger.exception("[redteam] tool %s raised", name)
                        result, is_err = (f"Tool error: {exc}", True)
                tool_calls.append({"name": name, "input": args, "result": result, "is_error": is_err})
                messages.append(
                    {"role": "tool", "tool_call_id": tc.id,
                     "content": result if isinstance(result, str) else _as_text(result)}
                )
                transcript.append(
                    {"role": "tool", "name": name, "is_error": is_err,
                     "content": result if isinstance(result, str) else _as_text(result)}
                )

        final = resp.choices[0].message.content or "" if resp else ""
        return RunResult(final_text=final, transcript=transcript, tool_calls=tool_calls, stopped="max_iterations")
    finally:
        await client.close()


def _as_text(result: Any) -> str:
    try:
        return json.dumps(result, default=str)
    except TypeError:
        return str(result)
