"""
Proves the hardened store enforces a RULE, not a rejection of one demo payload.

Each rule is exercised across many products, values, coupon combinations and
repeated amounts. The vulnerable store is shown to fail across the same range, so
the before/after isn't a test written to pass a single input. Pure pricing/refund
logic — no PayPal, no LLM.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app.config import Settings
from app.target import checkout

PRODUCTS = ["DC-ESP-250", "DC-ETH-250", "DC-SUB-BOX", "DC-GIFT-100", "DC-EQP-GRND", "DC-WHL-5KG"]
LIST = {"DC-ESP-250": 18.0, "DC-ETH-250": 22.0, "DC-SUB-BOX": 45.0, "DC-GIFT-100": 100.0,
        "DC-EQP-GRND": 400.0, "DC-WHL-5KG": 320.0}


def _s(vulnerable: bool) -> Settings:
    return Settings(_env_file=None, trust_client_amount=vulnerable, allow_coupon_stack=vulnerable,
                    unbounded_refund=vulnerable, trust_webhook=vulnerable, unsafe_barista=vulnerable,
                    min_price_floor_pct=0.50, max_coupon_discount_pct=0.30)


# ── Rule: order.amount == server_price(cart) — across products and claimed totals
@pytest.mark.parametrize("sku", PRODUCTS)
@pytest.mark.parametrize("client_total", [0.01, 1.0, 4.0, 9.99, 50.0])
def test_hardened_always_recomputes_price(sku, client_total):
    q = checkout.price_quote([{"sku": sku, "qty": 1}], settings=_s(False), client_total=client_total)
    assert q.charged_total == LIST[sku]            # client's number never used


@pytest.mark.parametrize("sku", PRODUCTS)
@pytest.mark.parametrize("client_total", [0.01, 1.0, 4.0])
def test_vulnerable_trusts_client_total(sku, client_total):
    q = checkout.price_quote([{"sku": sku, "qty": 1}], settings=_s(True), client_total=client_total)
    assert q.charged_total == round(client_total, 2)


# ── Rule: effective_discount ≤ cap AND ≤ 1 coupon — across many combinations
COMBOS = [
    ["FRIEND25", "LOYAL20"],
    ["FRIEND25", "LOYAL20", "SUMMER15", "WELCOME10"],
    ["FRIEND25", "FRIEND25"],              # duplicate
    ["WELCOME10", "WELCOME10", "WELCOME10"],
    ["SUMMER15", "LOYAL20"],
]


@pytest.mark.parametrize("sku", ["DC-EQP-GRND", "DC-WHL-5KG", "DC-SUB-BOX"])
@pytest.mark.parametrize("coupons", COMBOS)
def test_hardened_caps_discount(sku, coupons):
    cap = 0.30
    q = checkout.price_quote([{"sku": sku, "qty": 1}], settings=_s(False), coupons=coupons)
    assert q.discount_pct <= cap + 1e-9
    assert len(q.coupons_applied) <= 1
    assert q.charged_total >= round(LIST[sku] * (1 - cap), 2) - 1e-9


# 3×WELCOME10 sums to exactly 30% (the cap), not past it — exclude it here.
@pytest.mark.parametrize("coupons", [c for c in COMBOS if c != ["WELCOME10", "WELCOME10", "WELCOME10"]])
def test_vulnerable_stacks_past_cap(coupons):
    # These combos all exceed 30% once stacked (incl. duplicates counted repeatedly).
    q = checkout.price_quote([{"sku": "DC-EQP-GRND", "qty": 1}], settings=_s(True), coupons=coupons)
    assert q.discount_pct > 0.30


# ── Rule: Σ refunds ≤ captured − already_refunded — across amounts
@pytest.mark.parametrize("captured", [18.0, 45.0, 100.0, 320.0, 400.0])
@pytest.mark.parametrize("extra", [0.01, 50.0, 500.0])   # always at least one cent over
def test_hardened_bounds_refund(captured, extra):
    requested = round(captured + extra, 2)
    ok, _ = checkout.refund_is_allowed(capture_amount=captured, already_refunded=0.0,
                                       requested=requested, settings=_s(False))
    assert ok is False


@pytest.mark.parametrize("captured", [18.0, 100.0, 400.0])
def test_hardened_allows_legit_refund(captured):
    ok, _ = checkout.refund_is_allowed(capture_amount=captured, already_refunded=0.0,
                                       requested=captured, settings=_s(False))
    assert ok is True


@pytest.mark.parametrize("captured", [18.0, 100.0, 400.0])
def test_vulnerable_allows_over_refund(captured):
    ok, _ = checkout.refund_is_allowed(capture_amount=captured, already_refunded=0.0,
                                       requested=captured + 50, settings=_s(True))
    assert ok is True
