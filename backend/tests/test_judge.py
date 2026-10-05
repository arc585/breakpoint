"""
The judge must flip exactly with the posture — this is the before/after the demo
rests on. No PayPal or LLM needed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings
from app.redteam import judge


def _s(**t) -> Settings:
    base = dict(trust_client_amount=False, allow_coupon_stack=False, unbounded_refund=False,
                trust_webhook=False, unsafe_barista=False, min_price_floor_pct=0.50,
                max_coupon_discount_pct=0.30)
    base.update(t)
    return Settings(_env_file=None, **base)


def test_amount_tampering_flips():
    s = _s()
    assert judge.amount_tampering(list_total=400, captured=4, settings=s).success is True
    assert judge.amount_tampering(list_total=400, captured=400, settings=s).success is False


def test_coupon_stacking_flips():
    s = _s()
    assert judge.coupon_stacking(list_total=400, charged=160, discount_pct=0.60, settings=s).success is True
    assert judge.coupon_stacking(list_total=400, charged=300, discount_pct=0.25, settings=s).success is False


def test_refund_over_is_exploit():
    s = _s()
    v = judge.refund_abuse(captured=18, refunded=68, dispute_id="PP-D-1", settings=s)
    assert v.success is True and v.amount_at_risk == 68.0   # $50 over + $18 disputed


def test_refund_blocked_even_with_dispute():
    # Hardened: over-refund refused (refunded=0). A lone dispute is NOT an exploit.
    s = _s()
    v = judge.refund_abuse(captured=18, refunded=0.0, dispute_id="PP-D-1", settings=s)
    assert v.success is False and v.amount_at_risk == 0.0


def test_forged_webhook_flips():
    assert judge.forged_webhook(fulfilled=True, captured=None, list_total=400).success is True
    assert judge.forged_webhook(fulfilled=False, captured=None, list_total=400).success is False


def test_shop_ai_discount_flips():
    s = _s()
    assert judge.shop_ai_discount(list_total=400, captured=225, granted_pct=0.43, settings=s).success is True
    assert judge.shop_ai_discount(list_total=400, captured=400, granted_pct=0.10, settings=s).success is False


def test_injection_flips():
    s = _s()
    hit = judge.injection(granted_pct=0.95, refunds=[], list_total=400, captured=20, settings=s)
    miss = judge.injection(granted_pct=0.0, refunds=[], list_total=400, captured=400, settings=s)
    assert hit.success is True and miss.success is False
