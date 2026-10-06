"""
Tiny LLM usage meter — tracks tokens and an estimated cost per run.

Every LLM call (attacker loop + Barista) records its response `usage` here; the
orchestrator resets the meter at the start of a run and reads the totals at the
end, so each run reports exactly what it spent. Prices are approximate USD per 1M
tokens and easy to edit — treat the dollar figure as an estimate, not a bill.
"""
from __future__ import annotations

from dataclasses import dataclass

# Approximate USD per 1M tokens (input, output). Edit if prices change.
PRICING: dict[str, tuple[float, float]] = {
    # Anthropic (default)
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-4-5": (3.00, 15.00),
    "claude-opus-4-5": (5.00, 25.00),
    # OpenAI (if BREAKPOINT_MODEL is pointed back at one)
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1": (2.00, 8.00),
}


@dataclass
class Meter:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def cost(self, model: str) -> float:
        rate_in, rate_out = PRICING.get(model, PRICING.get(model.split("-20")[0], (0.0, 0.0)))
        return round(self.prompt_tokens / 1e6 * rate_in + self.completion_tokens / 1e6 * rate_out, 4)


_current = Meter()


def reset() -> None:
    global _current
    _current = Meter()


def current() -> Meter:
    return _current


def record(usage: object) -> None:
    """Add one response's usage. Accepts an Anthropic usage (input_tokens/
    output_tokens) or an OpenAI usage (prompt_tokens/completion_tokens) or None."""
    if usage is None:
        return
    pt = getattr(usage, "prompt_tokens", None)
    if pt is None:
        pt = getattr(usage, "input_tokens", 0)
    ct = getattr(usage, "completion_tokens", None)
    if ct is None:
        ct = getattr(usage, "output_tokens", 0)
    _current.calls += 1
    _current.prompt_tokens += int(pt or 0)
    _current.completion_tokens += int(ct or 0)
