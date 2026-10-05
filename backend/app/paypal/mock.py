"""
A deterministic stand-in for PayPalClient.

Lets the full attack suite + judge run with no network — for development, CI, and
pre-seeding the demo before live sandbox card-capture is confirmed. It mimics the
*shape* of real responses and the one security-relevant behavior that matters:
verify_webhook_signature returns False for a forged event, True otherwise. Swap
in the real client with run_suite --live.
"""
from __future__ import annotations

import uuid
from typing import Any


class MockPayPalClient:
    def __init__(self) -> None:
        self._captures: dict[str, float] = {}

    async def aclose(self) -> None:  # parity with PayPalClient
        return None

    async def create_order(self, order: dict[str, Any], *, request_id: str | None = None) -> dict[str, Any]:
        value = float(order["purchase_units"][0]["amount"]["value"])
        oid = "MOCK-O-" + uuid.uuid4().hex[:10]
        cap_id = "MOCK-C-" + uuid.uuid4().hex[:10]
        self._captures[cap_id] = value
        # Card orders complete inline, like PayPal's sandbox card flow.
        return {
            "id": oid,
            "status": "COMPLETED",
            "purchase_units": [{"payments": {"captures": [
                {"id": cap_id, "amount": {"currency_code": "USD", "value": f"{value:.2f}"}, "status": "COMPLETED"}
            ]}}],
        }

    async def capture_order(self, order_id: str, *, request_id: str | None = None) -> dict[str, Any]:
        cap_id = "MOCK-C-" + uuid.uuid4().hex[:10]
        self._captures[cap_id] = 0.0
        return {"id": order_id, "status": "COMPLETED",
                "purchase_units": [{"payments": {"captures": [
                    {"id": cap_id, "amount": {"currency_code": "USD", "value": "0.00"}, "status": "COMPLETED"}]}}]}

    async def refund_capture(self, capture_id: str, amount=None, *, request_id: str | None = None) -> dict[str, Any]:
        val = amount["value"] if amount else f"{self._captures.get(capture_id, 0.0):.2f}"
        return {"id": "MOCK-R-" + uuid.uuid4().hex[:10], "status": "COMPLETED",
                "amount": {"currency_code": "USD", "value": val}}

    async def get_capture(self, capture_id: str) -> dict[str, Any]:
        return {"id": capture_id, "amount": {"value": f"{self._captures.get(capture_id, 0.0):.2f}"}}

    async def verify_webhook_signature(self, *, headers, webhook_id, event_body) -> bool:
        # The one security-relevant behavior: a forged event never verifies.
        eid = str(event_body.get("id", ""))
        return not eid.startswith("WH-FORGED")

    async def create_dispute_sandbox(self, *, buyer_transaction_id, reason, amount, auth_jwt) -> dict[str, Any]:
        did = "PP-D-MOCK-" + uuid.uuid4().hex[:6]
        return {"links": [{"href": f"https://api-m.sandbox.paypal.com/v1/customer/disputes/{did}", "rel": "self"}]}

    async def provide_evidence(self, dispute_id: str, *, notes: str, document=None) -> dict[str, Any]:
        return {"status": "OK", "dispute_id": dispute_id}
