"""
Run the attack suite against one posture and persist the findings.

Picks the real PayPal sandbox client (--live) or the deterministic mock, builds
one Dusk Coffee target, runs each attack, and writes a finding per attack to the
store. LLM attacks are skipped (recorded as ERROR) when no OpenAI key is set.
"""
from __future__ import annotations

import logging
from typing import Any

from ..config import Settings
from ..paypal.client import PayPalClient
from ..paypal.mock import MockPayPalClient
from ..store.models import Store
from ..target.ledger import Ledger
from ..target.service import DuskCoffee
from .attacks import ALL_ATTACKS

logger = logging.getLogger(__name__)


async def run_suite(
    *, settings: Settings, store: Store, use_live: bool, only: list[str] | None = None, label: str = ""
) -> str:
    client: Any = (
        PayPalClient(base_url=settings.paypal_base_url, client_id=settings.paypal_client_id,
                     secret=settings.paypal_secret)
        if use_live else MockPayPalClient()
    )
    dusk = DuskCoffee(settings=settings, client=client, ledger=Ledger())
    posture_label = label or ("hardened" if settings.is_hardened() else "vulnerable") + (" (live)" if use_live else " (mock)")
    run_id = store.create_run(posture=settings.posture(), is_hardened=settings.is_hardened(), label=posture_label)

    try:
        for name, (fn, needs_llm) in ALL_ATTACKS.items():
            if only and name not in only:
                continue
            if needs_llm and not settings.openai_api_key:
                store.add_finding(run_id, _error_finding(name, "no OPENAI_API_KEY set — LLM attack skipped"))
                continue
            try:
                finding = await fn(dusk, settings, api_key=settings.openai_api_key,
                                   model=settings.breakpoint_model, live=use_live)
            except Exception as exc:  # one broken attack must not sink the run
                logger.exception("[orchestrator] attack %s failed", name)
                finding = _error_finding(name, f"{type(exc).__name__}: {exc}")
            store.add_finding(run_id, finding)
    finally:
        await client.aclose()

    return run_id


def _error_finding(attack: str, reason: str) -> dict[str, Any]:
    return {
        "attack": attack, "title": attack.replace("_", " ").title(), "status": "ERROR",
        "severity": "low", "amount_at_risk": 0.0, "summary": reason, "fix": "",
        "transcript": [{"step": "error", "detail": reason}], "api_calls": [], "evidence": {},
    }
