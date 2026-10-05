"""
Dusk Coffee's webhook listener — the forged-webhook surface.

A merchant marks an order paid/fulfilled when PayPal tells it a capture
completed. The question is whether it CHECKS that the message really came from
PayPal:

  * TRUST_WEBHOOK on  (vulnerable): fulfil on the event body as-is. An attacker
    who POSTs a fake PAYMENT.CAPTURE.COMPLETED gets goods with no real payment.
  * TRUST_WEBHOOK off (hardened):   call verify-webhook-signature first and
    fulfil only when PayPal returns SUCCESS. A forged event fails verification.

`handle_webhook` returns (fulfilled, reason) and updates the ledger record.
"""
from __future__ import annotations

from typing import Any

from ..config import Settings
from ..paypal.client import PayPalClient, PayPalError
from .ledger import Ledger


def _order_id_from_event(event: dict[str, Any]) -> str | None:
    """PAYPAL custom_id / supplementary data carries our order id in a real event.
    For the demo the attacker references the Dusk order_id directly."""
    res = event.get("resource", {})
    return (
        res.get("custom_id")
        or res.get("supplementary_data", {}).get("related_ids", {}).get("order_id")
        or event.get("dusk_order_id")
    )


async def handle_webhook(
    *,
    event: dict[str, Any],
    headers: dict[str, str],
    settings: Settings,
    ledger: Ledger,
    client: PayPalClient | None = None,
) -> tuple[bool, str]:
    event_type = event.get("event_type", "")
    order_id = _order_id_from_event(event)
    rec = ledger.get(order_id) if order_id else None

    if event_type != "PAYMENT.CAPTURE.COMPLETED":
        return False, f"ignored event_type={event_type!r}"
    if rec is None:
        return False, f"no such order {order_id!r}"

    if settings.trust_webhook:
        # VULNERABLE: no signature check — trust the body.
        rec.fulfilled = True
        rec.fulfilled_reason = "fulfilled on unverified webhook (vulnerable)"
        ledger.put(rec)
        return True, rec.fulfilled_reason

    # HARDENED: verify with PayPal before trusting anything.
    if client is None:
        return False, "no PayPal client to verify signature (hardened: refused)"
    try:
        genuine = await client.verify_webhook_signature(
            headers=headers, webhook_id=settings.paypal_webhook_id, event_body=event
        )
    except PayPalError as exc:
        return False, f"verify-webhook-signature errored, refused to fulfil: {exc}"
    if not genuine:
        return False, "signature verification FAILED — forged webhook rejected (hardened)"

    rec.fulfilled = True
    rec.fulfilled_reason = "fulfilled after signature verification (hardened)"
    ledger.put(rec)
    return True, rec.fulfilled_reason
