"""
Tiny OpenAI usage meter — tracks tokens and an estimated cost per run.

Every LLM call (attacker loop + Barista) records its response `usage` here; the
orchestrator resets the meter at the start of a run and reads the totals at the
end, so each run reports exactly what it spent. Prices are approximate USD per 1M
tokens and easy to edit — treat the dollar figure as an estimate, not a bill.
"""
from __future__ import annotations

from dataclasses import dataclass

# Approximate USD per 1M tokens (input, output). Edit if OpenAI prices change.
PRICING: dict[str, tuple[float, float]] = {
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
    """Add one response's usage. Accepts an OpenAI usage object or None."""
    if usage is None:
        return
    _current.calls += 1
    _current.prompt_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
    _current.completion_tokens += int(getattr(usage, "completion_tokens", 0) or 0)
