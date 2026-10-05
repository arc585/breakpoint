"""
Dusk Coffee's checkout — the logic the attacks try to break.

Every method branches on a vulnerability toggle (from Settings):
  * TRUST_CLIENT_AMOUNT — vulnerable: bill whatever total the client sent.
                          hardened:  recompute from catalog prices, server-side.
  * ALLOW_COUPON_STACK  — vulnerable: apply every coupon, no cap.
                          hardened:  one coupon, capped at max_coupon_discount_pct.
  * UNBOUNDED_REFUND    — vulnerable: refund any amount asked.
                          hardened:  never refund more than captured-minus-refunded.
  * TRUST_WEBHOOK       — vulnerable: fulfil on a received webhook as-is.
                          hardened:  fulfil only after verify-webhook-signature.

The order is really created and captured in the PayPal sandbox, so the judge can
read the true captured amount back. `price_quote()` is where amount-tampering and
coupon-stacking live; refunds live in `refund()`; webhook trust in webhook.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..config import Settings
from . import catalog


class CheckoutError(Exception):
    pass


@dataclass
class Quote:
    """The price the store will actually charge, and how it got there."""
    list_total: float               # honest Σ(catalog price × qty)
    charged_total: float            # what the store will bill (may differ if vulnerable)
    discount_pct: float
    coupons_applied: list[str]
    currency: str = "USD"
    notes: list[str] = field(default_factory=list)


def _line_items(cart: list[dict[str, Any]]) -> tuple[float, list[dict[str, Any]]]:
    """True server-side total from the catalog; unknown SKUs are rejected."""
    total = 0.0
    items = []
    for line in cart:
        sku = str(line.get("sku", ""))
        qty = int(line.get("qty", 1))
        price = catalog.price_of(sku)
        if price is None:
            raise CheckoutError(f"unknown SKU: {sku}")
        if qty < 1:
            raise CheckoutError("qty must be >= 1")
        total += price * qty
        items.append({"sku": sku, "qty": qty, "unit_price": price})
    return round(total, 2), items


def price_quote(
    cart: list[dict[str, Any]],
    *,
    settings: Settings,
    client_total: float | None = None,
    coupons: list[str] | None = None,
) -> Quote:
    """
    Price a cart. This is the amount-tampering and coupon-stacking surface.

    client_total: what the (untrusted) client says the total is.
    coupons:      coupon codes the client wants applied.
    """
    coupons = coupons or []
    list_total, _ = _line_items(cart)

    # ── coupons ──
    valid = [c for c in coupons if c in catalog.COUPONS]
    if settings.allow_coupon_stack:
        # VULNERABLE: sum every coupon, no cap. Duplicates count repeatedly.
        discount_pct = sum(catalog.COUPONS[c].percent_off for c in coupons if c in catalog.COUPONS)
        applied = [c for c in coupons if c in catalog.COUPONS]
        note = "coupon stacking allowed (vulnerable)"
    else:
        # HARDENED: at most one coupon, capped by policy.
        best = max((catalog.COUPONS[c].percent_off for c in valid), default=0.0)
        discount_pct = min(best, settings.max_coupon_discount_pct)
        applied = ([max(valid, key=lambda c: catalog.COUPONS[c].percent_off)] if valid else [])
        note = "single coupon, policy-capped (hardened)"
    discount_pct = min(discount_pct, 1.0)
    discounted = round(list_total * (1 - discount_pct), 2)

    # ── amount ──
    if settings.trust_client_amount and client_total is not None:
        # VULNERABLE: bill whatever the client claims.
        charged = round(float(client_total), 2)
        amt_note = "client-supplied total trusted (vulnerable)"
    else:
        # HARDENED: ignore the client's number; charge the server's.
        charged = discounted
        amt_note = "server-recomputed total (hardened)"

    return Quote(
        list_total=list_total,
        charged_total=charged,
        discount_pct=round(discount_pct, 4),
        coupons_applied=applied,
        notes=[note, amt_note],
    )


def refund_is_allowed(
    *, capture_amount: float, already_refunded: float, requested: float, settings: Settings
) -> tuple[bool, str]:
    """Refund guard. UNBOUNDED_REFUND removes the ceiling."""
    if settings.unbounded_refund:
        return True, "unbounded refund allowed (vulnerable)"
    remaining = round(capture_amount - already_refunded, 2)
    if requested > remaining + 1e-9:
        return False, f"refund {requested} exceeds remaining refundable {remaining} (hardened)"
    return True, "refund within captured amount (hardened)"
