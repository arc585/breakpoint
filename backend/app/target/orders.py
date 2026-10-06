"""
Turn a priced cart into a real PayPal sandbox order and capture it.

We pay with a sandbox TEST CARD in the create-order call (Expanded Checkout /
`payment_source.card`) so the whole create→capture happens server-side with no
browser approval step — which is what lets the red team run unattended. The
captured amount is read straight back from PayPal so the judge compares the
TRUE captured value against the honest list price.

If card processing isn't enabled on the sandbox app, place_order raises
PayPalError; the Day-1 smoke test catches that and the fallback is the
approval-redirect flow. See README / plan.
"""
from __future__ import annotations

import uuid
from typing import Any

from ..paypal.client import PayPalClient, PayPalError

# PayPal's documented sandbox test card (Visa). No 3DS → captures server-side.
# From developer.paypal.com card-testing; any future expiry + 3-digit CVV.
SANDBOX_TEST_CARD = {
    "number": "4005519200000004",
    "expiry": "2030-01",
    "security_code": "123",
    "name": "Dusk Coffee Buyer",
}


def build_order_body(
    *,
    charged_total: float,
    currency: str = "USD",
    description: str = "Dusk Coffee order",
    with_card: bool = True,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "intent": "CAPTURE",
        "purchase_units": [
            {
                "amount": {"currency_code": currency, "value": f"{charged_total:.2f}"},
                "description": description,
            }
        ],
    }
    if with_card:
        body["payment_source"] = {"card": dict(SANDBOX_TEST_CARD)}
    return body


def _capture_value(capture_resp: dict[str, Any]) -> tuple[str | None, float | None]:
    """Pull (capture_id, captured_amount) out of a capture response."""
    try:
        cap = capture_resp["purchase_units"][0]["payments"]["captures"][0]
        return cap["id"], float(cap["amount"]["value"])
    except (KeyError, IndexError, TypeError, ValueError):
        return None, None


async def place_order(
    client: PayPalClient,
    *,
    charged_total: float,
    currency: str = "USD",
    description: str = "Dusk Coffee order",
) -> dict[str, Any]:
    """Create + capture an order; return ids and the TRUE captured amount."""
    request_id = uuid.uuid4().hex
    body = build_order_body(charged_total=charged_total, currency=currency, description=description)
    created = await client.create_order(body, request_id=request_id)
    order_id = created.get("id")

    status = created.get("status")
    capture_resp: dict[str, Any]
    if status == "COMPLETED":
        # Card orders can capture inline on create.
        capture_resp = created
    else:
        capture_resp = await client.capture_order(order_id, request_id=uuid.uuid4().hex)

    capture_id, captured_value = _capture_value(capture_resp)
    return {
        "order_id": order_id,
        "capture_id": capture_id,
        "captured_value": captured_value,
        "currency": currency,
        "create_status": status,
        "raw_create": created,
        "raw_capture": capture_resp,
    }
