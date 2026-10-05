"""
The vulnerability toggles must actually change behavior. These tests pin the
before/after that the whole demo depends on — no PayPal or LLM needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # backend/ on path

from app.config import Settings
from app.target import checkout


def _settings(**toggles) -> Settings:
    base = dict(
        trust_client_amount=False,
        allow_coupon_stack=False,
        unbounded_refund=False,
        min_price_floor_pct=0.50,
        max_coupon_discount_pct=0.30,
    )
    base.update(toggles)
    return Settings(_env_file=None, **base)


GRINDER = [{"sku": "DC-EQP-GRND", "qty": 1}]  # $400 hero item


def test_amount_tampering_vulnerable_bills_client_total():
    s = _settings(trust_client_amount=True)
    q = checkout.price_quote(GRINDER, settings=s, client_total=4.00)
    assert q.list_total == 400.00
    assert q.charged_total == 4.00          # $400 grinder billed as $4 — the exploit


def test_amount_tampering_hardened_recomputes():
    s = _settings(trust_client_amount=False)
    q = checkout.price_quote(GRINDER, settings=s, client_total=4.00)
    assert q.charged_total == 400.00        # client's number ignored


def test_coupon_stacking_vulnerable_blows_past_cap():
    s = _settings(allow_coupon_stack=True)
    q = checkout.price_quote(GRINDER, settings=s, coupons=["FRIEND25", "LOYAL20", "SUMMER15"])
    assert q.discount_pct == 0.60           # 25+20+15 stacked
    assert q.charged_total == 160.00


def test_coupon_stacking_hardened_caps_at_policy():
    s = _settings(allow_coupon_stack=False)
    # Best single coupon is FRIEND25 (25%), already under the 30% cap → 25%, not stacked.
    q = checkout.price_quote(GRINDER, settings=s, coupons=["FRIEND25", "LOYAL20", "SUMMER15"])
    assert q.coupons_applied == ["FRIEND25"]
    assert q.discount_pct == 0.25
    assert q.charged_total == 300.00


def test_coupon_over_cap_is_capped():
    # A single coupon above the policy cap is clamped to it.
    s = _settings(allow_coupon_stack=False, max_coupon_discount_pct=0.20)
    q = checkout.price_quote(GRINDER, settings=s, coupons=["FRIEND25"])
    assert q.discount_pct == 0.20           # 25% clamped to the 20% policy cap
    assert q.charged_total == 320.00


def test_refund_unbounded_vulnerable():
    s = _settings(unbounded_refund=True)
    ok, _ = checkout.refund_is_allowed(
        capture_amount=4.00, already_refunded=0.0, requested=400.00, settings=s
    )
    assert ok is True                       # refund $400 on a $4 capture


def test_refund_bounded_hardened():
    s = _settings(unbounded_refund=False)
    ok, _ = checkout.refund_is_allowed(
        capture_amount=4.00, already_refunded=0.0, requested=400.00, settings=s
    )
    assert ok is False


def test_unknown_sku_rejected():
    s = _settings()
    try:
        checkout.price_quote([{"sku": "NOPE", "qty": 1}], settings=s)
        assert False, "should reject unknown SKU"
    except checkout.CheckoutError:
        pass
