#!/usr/bin/env python3
"""
Run the Breakpoint attack suite against one posture and store the findings.

  python scripts/run_suite.py --target vulnerable        # mock PayPal (default)
  python scripts/run_suite.py --target hardened
  python scripts/run_suite.py --target vulnerable --live  # real PayPal sandbox
  python scripts/run_suite.py --only amount_tampering,forged_webhook

'vulnerable' turns every toggle ON; 'hardened' turns them all OFF. Keys/model are
read from .env. Prints a one-line summary and the run id.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.config import Settings          # noqa: E402
from app.store.models import Store        # noqa: E402
from app.redteam.orchestrator import run_suite  # noqa: E402

VULN = ("trust_client_amount", "allow_coupon_stack", "unbounded_refund", "trust_webhook", "unsafe_barista")


def build_settings(target: str) -> Settings:
    s = Settings()  # reads .env for keys/model/policy
    on = target == "vulnerable"
    for flag in VULN:
        setattr(s, flag, on)
    return s


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", choices=["vulnerable", "hardened"], default="vulnerable")
    ap.add_argument("--live", action="store_true", help="use the real PayPal sandbox (default: mock)")
    ap.add_argument("--only", default="", help="comma-separated attack names")
    args = ap.parse_args()

    settings = build_settings(args.target)
    db_path = str(ROOT / settings.breakpoint_db) if not Path(settings.breakpoint_db).is_absolute() else settings.breakpoint_db
    store = Store(db_path)
    only = [x.strip() for x in args.only.split(",") if x.strip()] or None

    run_id = await run_suite(settings=settings, store=store, use_live=args.live, only=only)
    stats = store.run_stats(run_id)
    run = store.get_run(run_id)
    print(f"run {run_id}  [{args.target}{' live' if args.live else ' mock'}]")
    print(f"  {stats['succeeded']}/{stats['total']} scenarios exploited · "
          f"exposure by basis: " +
          (", ".join(f"{k}=${v:.2f}" for k, v in stats['exposure_by_basis'].items()) or "none"))
    print(f"  LLM usage: {run['tokens_total']} tokens ({run['model']}) · est ${run['est_cost_usd']:.4f}")
    for f in store.list_findings(run_id):
        mark = {"SUCCEEDED": "✗", "BLOCKED": "✓", "ERROR": "!"}.get(f["status"], "?")
        print(f"   {mark} {f['attack']:<18} {f['status']:<10} ${f['amount_at_risk']:.2f}  {f['summary'][:70]}")
    store.close()


if __name__ == "__main__":
    asyncio.run(main())
