"""
Read/trigger API for the dashboard.

  GET  /api/runs                 → runs (newest first) with stats
  GET  /api/runs/{run_id}        → run + its findings
  GET  /api/summary              → latest vulnerable vs hardened, for the headline
  POST /api/runs                 → run the suite now {target, live, only?}

Findings carry the full transcript, API calls, $ at risk and the fix — the grid
reads straight from here.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import Settings, get_settings
from ..redteam.orchestrator import run_suite
from ..store.models import Store

router = APIRouter(prefix="/api")
_ROOT = Path(__file__).resolve().parents[3]  # repo root (…/backend/app/api/routes.py)
VULN = ("trust_client_amount", "allow_coupon_stack", "unbounded_refund", "trust_webhook", "unsafe_barista")


def _db_path() -> str:
    db = get_settings().breakpoint_db
    return db if Path(db).is_absolute() else str(_ROOT / db)


def _store() -> Store:
    return Store(_db_path())


def _run_payload(store: Store, run_id: str) -> dict[str, Any]:
    run = store.get_run(run_id)
    if not run:
        raise HTTPException(404, "run not found")
    return {**run, "stats": store.run_stats(run_id), "findings": store.list_findings(run_id)}


@router.get("/runs")
def list_runs() -> list[dict[str, Any]]:
    store = _store()
    try:
        return [{**r, "stats": store.run_stats(r["id"])} for r in store.list_runs()]
    finally:
        store.close()


@router.get("/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    store = _store()
    try:
        return _run_payload(store, run_id)
    finally:
        store.close()


@router.get("/summary")
def summary() -> dict[str, Any]:
    """Latest vulnerable and latest hardened run, for the before/after headline."""
    store = _store()
    try:
        runs = store.list_runs()
        latest_vuln = next((r for r in runs if not r["is_hardened"]), None)
        latest_hard = next((r for r in runs if r["is_hardened"]), None)
        return {
            "vulnerable": _run_payload(store, latest_vuln["id"]) if latest_vuln else None,
            "hardened": _run_payload(store, latest_hard["id"]) if latest_hard else None,
        }
    finally:
        store.close()


class RunRequest(BaseModel):
    target: str = "vulnerable"       # vulnerable | hardened
    live: bool = False
    only: list[str] | None = None


@router.post("/runs")
async def create_run(req: RunRequest) -> dict[str, Any]:
    s = Settings()
    on = req.target == "vulnerable"
    for flag in VULN:
        setattr(s, flag, on)
    store = _store()
    try:
        run_id = await run_suite(settings=s, store=store, use_live=req.live, only=req.only)
        return _run_payload(store, run_id)
    finally:
        store.close()
