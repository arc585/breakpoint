#!/usr/bin/env python3
"""Print Dusk Coffee's catalogue and coupons, and confirm config loads.
The catalogue is static demo data in code, so there's nothing to write — this
just lets a judge see what the store sells before running the suite."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.target import catalog  # noqa: E402


def main() -> None:
    print("Dusk Coffee — products:")
    for p in catalog.list_products():
        print(f"  {p['sku']:<12} ${p['price']:>7.2f}  {p['name']}")
    print("\nCoupons (policy: one per order, max 30%):")
    for code, c in catalog.COUPONS.items():
        print(f"  {code:<10} {int(c.percent_off*100)}%  {c.note}")


if __name__ == "__main__":
    main()
