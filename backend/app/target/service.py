"""
DuskCoffee — the facade the red team drives.

Composes catalog + checkout (pricing/refund rules) + orders (real PayPal
sandbox create→capture) + webhook (fulfilment trust) + ledger (store truth).
Every method honours the vulnerability toggles via Settings, and records to the
ledger so the judge can read the true outcome afterwards.
"""
from __future__ import annotations

import uuid
from typing import Any

from ..config import Settings
from ..paypal.client import PayPalClient
from . import catalog, checkout, orders, webhook
from .ledger import Ledger, OrderRecord


class DuskCoffee:
    def __init__(self, *, settings: Settings, client: PayPalClient, ledger: Ledger | None = None):
        self.settings = settings
        self.client = client
        self.ledger = ledger or Ledger()

    # ── pricing (amount tampering + coupon stacking surface) ──
    def quote(
        self, cart: list[dict[str, Any]], *, client_total: float | None = None, coupons: list[str] | None = None
    ) -> checkout.Quote:
        return checkout.price_quote(
            cart, settings=self.settings, client_total=client_total, coupons=coupons
        )

    # ── buy: price then really create+capture in the PayPal sandbox ──
    async def buy(
        self,
        cart: list[dict[str, Any]],
        *,
        client_total: float | None = None,
        coupons: list[str] | None = None,
        description: str = "Dusk Coffee order",
    ) -> OrderRecord:
        q = self.quote(cart, client_total=client_total, coupons=coupons)
        placed = await orders.place_order(
            self.client, charged_total=q.charged_total, currency=q.currency, description=description
        )
        rec = OrderRecord(
            order_id=placed["order_id"] or uuid.uuid4().hex,
            items=cart,
            list_total=q.list_total,
            charged_total=q.charged_total,
            currency=q.currency,
            capture_id=placed["capture_id"],
            captured_value=placed["captured_value"],
            notes=list(q.notes),
        )
        return self.ledger.put(rec)

    # ── refunds (unbounded-refund surface) ──
    async def refund(self, order_id: str, amount: float) -> tuple[bool, str, dict | None]:
        rec = self.ledger.get(order_id)
        if rec is None or not rec.capture_id:
            return False, f"no captured order {order_id!r}", None
        ok, reason = checkout.refund_is_allowed(
            capture_amount=rec.captured_value or 0.0,
            already_refunded=rec.refunded_total,
            requested=amount,
            settings=self.settings,
        )
        if not ok:
            return False, reason, None
        resp = await self.client.refund_capture(
            rec.capture_id, {"currency_code": rec.currency, "value": f"{amount:.2f}"}
        )
        rec.refunded_total = round(rec.refunded_total + amount, 2)
        rec.notes.append(reason)
        self.ledger.put(rec)
        return True, reason, resp

    # ── webhook fulfilment (forged-webhook surface) ──
    async def receive_webhook(self, event: dict[str, Any], headers: dict[str, str]) -> tuple[bool, str]:
        return await webhook.handle_webhook(
            event=event, headers=headers, settings=self.settings, ledger=self.ledger, client=self.client
        )

    # ── sandbox dispute (refund double-dip second leg) ──
    async def open_dispute_as_buyer(
        self, order_id: str, *, reason: str = "MERCHANDISE_OR_SERVICE_NOT_RECEIVED", amount: float | None = None
    ) -> dict:
        """Open a dispute on a captured order using the sandbox-only endpoint.
        Requires buyer creds; raises PayPalError if unavailable (attack degrades
        gracefully to the refund-only exploit)."""
        from ..paypal.client import auth_assertion

        rec = self.ledger.get(order_id)
        if rec is None or not rec.capture_id:
            raise ValueError(f"no captured order {order_id!r}")
        jwt = auth_assertion(self.settings.paypal_client_id, email=self.settings.paypal_buyer_email or None)
        resp = await self.client.create_dispute_sandbox(
            buyer_transaction_id=rec.capture_id,
            reason=reason,
            amount={"currency_code": rec.currency, "value": f"{amount or rec.captured_value or 0:.2f}"},
            auth_jwt=jwt,
        )
        # pull the dispute id out of the HATEOAS self link
        try:
            href = resp["links"][0]["href"]
            rec.dispute_id = href.rstrip("/").split("/")[-1]
            self.ledger.put(rec)
        except (KeyError, IndexError, TypeError):
            pass
        return resp

    def forged_capture_event(self, order_id: str, amount: float | None = None) -> dict[str, Any]:
        """A fake PAYMENT.CAPTURE.COMPLETED an attacker would POST to the webhook."""
        rec = self.ledger.get(order_id)
        value = amount if amount is not None else (rec.list_total if rec else 0.0)
        return {
            "id": f"WH-FORGED-{uuid.uuid4().hex[:8]}",
            "event_type": "PAYMENT.CAPTURE.COMPLETED",
            "resource": {
                "custom_id": order_id,
                "amount": {"currency_code": "USD", "value": f"{value:.2f}"},
                "status": "COMPLETED",
            },
            "dusk_order_id": order_id,
        }

    def products(self) -> list[dict[str, Any]]:
        return catalog.list_products()
