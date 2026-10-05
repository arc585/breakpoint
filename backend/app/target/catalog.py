"""
Dusk Coffee — a small US roaster that also ships internationally. The catalog is
fixed demo data: enough products, coupons and a refund/again policy for the six
attacks to have something real to abuse.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Product:
    sku: str
    name: str
    price: float          # USD list price, the server's source of truth
    description: str


@dataclass(frozen=True)
class Coupon:
    code: str
    percent_off: float    # 0.10 = 10%
    note: str


PRODUCTS: dict[str, Product] = {
    p.sku: p
    for p in [
        Product("DC-ESP-250", "Midnight Espresso 250g", 18.00, "Dark, chocolatey house espresso."),
        Product("DC-ETH-250", "Ethiopia Yirgacheffe 250g", 22.00, "Floral, citrus, light roast."),
        Product("DC-SUB-BOX", "Monthly Subscription Box", 45.00, "Two bags, roaster's choice, monthly."),
        Product("DC-GIFT-100", "Gift Card $100", 100.00, "Digital gift card."),
        Product("DC-EQP-GRND", "Hand Grinder", 400.00, "Premium burr hand grinder — the hero item."),
        Product("DC-WHL-5KG", "Wholesale Beans 5kg", 320.00, "Bulk beans for cafés (invoiced)."),
    ]
}

# Legit coupons. The POLICY is: at most ONE coupon, max 30% off (see config
# max_coupon_discount_pct). The vulnerable store forgets to enforce both.
COUPONS: dict[str, Coupon] = {
    c.code: c
    for c in [
        Coupon("WELCOME10", 0.10, "New-customer 10% off."),
        Coupon("SUMMER15", 0.15, "Seasonal 15% off."),
        Coupon("LOYAL20", 0.20, "Loyalty 20% off."),
        Coupon("FRIEND25", 0.25, "Referral 25% off."),
    ]
}


def list_products() -> list[dict]:
    return [
        {"sku": p.sku, "name": p.name, "price": p.price, "description": p.description}
        for p in PRODUCTS.values()
    ]


def price_of(sku: str) -> float | None:
    p = PRODUCTS.get(sku)
    return p.price if p else None
