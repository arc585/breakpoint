"""
Zero-setup persistence: plain sqlite3 with JSON columns. No ORM, so a judge
can `python scripts/run_suite.py` and get a populated DB with no migrations.

Two tables:
  runs      — one red-team run against one posture (vulnerable or hardened)
  findings  — one attack attempt: status, dollars at risk, the full transcript,
              the real PayPal API calls, the success-check evidence, and the fix.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    posture     TEXT NOT NULL,          -- json: which toggles were on
    is_hardened INTEGER NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    model             TEXT NOT NULL DEFAULT '',
    tokens_prompt     INTEGER NOT NULL DEFAULT 0,
    tokens_completion INTEGER NOT NULL DEFAULT 0,
    est_cost_usd      REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id             TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL REFERENCES runs(id),
    attack         TEXT NOT NULL,
    title          TEXT NOT NULL,
    status         TEXT NOT NULL,        -- SUCCEEDED | BLOCKED | ERROR
    severity       TEXT NOT NULL,        -- critical | high | medium | low
    amount_at_risk REAL NOT NULL DEFAULT 0,
    loss_kind      TEXT NOT NULL DEFAULT 'none',
    amount_basis   TEXT NOT NULL DEFAULT 'none',
    currency       TEXT NOT NULL DEFAULT 'USD',
    summary        TEXT NOT NULL DEFAULT '',
    fix            TEXT NOT NULL DEFAULT '',
    invariant      TEXT NOT NULL DEFAULT '',
    transaction_ids TEXT NOT NULL DEFAULT '{}',
    transcript     TEXT NOT NULL DEFAULT '[]',   -- json
    api_calls      TEXT NOT NULL DEFAULT '[]',   -- json
    evidence       TEXT NOT NULL DEFAULT '{}',   -- json: what proved success
    created_at     REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ── runs ──
    def create_run(self, *, posture: dict[str, bool], is_hardened: bool, label: str = "") -> str:
        rid = uuid.uuid4().hex
        self._conn.execute(
            "INSERT INTO runs (id, created_at, posture, is_hardened, label) VALUES (?,?,?,?,?)",
            (rid, time.time(), json.dumps(posture), int(is_hardened), label),
        )
        self._conn.commit()
        return rid

    def set_run_usage(self, run_id: str, *, model: str, prompt: int, completion: int, cost: float) -> None:
        self._conn.execute(
            "UPDATE runs SET model=?, tokens_prompt=?, tokens_completion=?, est_cost_usd=? WHERE id=?",
            (model, int(prompt), int(completion), float(cost), run_id),
        )
        self._conn.commit()

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self._conn.execute("SELECT * FROM runs ORDER BY created_at DESC").fetchall()
        return [self._run_row(r) for r in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        r = self._conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run_row(r) if r else None

    # ── findings ──
    def add_finding(self, run_id: str, finding: dict[str, Any]) -> str:
        fid = uuid.uuid4().hex
        self._conn.execute(
            """INSERT INTO findings
               (id, run_id, attack, title, status, severity, amount_at_risk, loss_kind, amount_basis,
                currency, summary, fix, invariant, transaction_ids, transcript, api_calls, evidence, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fid, run_id,
                finding["attack"], finding.get("title", finding["attack"]),
                finding["status"], finding.get("severity", "medium"),
                float(finding.get("amount_at_risk", 0)), finding.get("loss_kind", "none"),
                finding.get("amount_basis", "none"),
                finding.get("currency", "USD"),
                finding.get("summary", ""), finding.get("fix", ""), finding.get("invariant", ""),
                json.dumps(finding.get("transaction_ids", {})),
                json.dumps(finding.get("transcript", [])),
                json.dumps(finding.get("api_calls", [])),
                json.dumps(finding.get("evidence", {})),
                time.time(),
            ),
        )
        self._conn.commit()
        return fid

    def list_findings(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE run_id=? ORDER BY created_at ASC", (run_id,)
        ).fetchall()
        return [self._finding_row(r) for r in rows]

    def run_stats(self, run_id: str) -> dict[str, Any]:
        rows = self.list_findings(run_id)
        succeeded = [f for f in rows if f["status"] == "SUCCEEDED"]
        # Break exposure down by kind — an underpaid order, goods shipped unpaid,
        # and a duplicate refund are different dollars; don't present one blended total.
        by_kind: dict[str, float] = {}
        by_basis: dict[str, float] = {}
        for f in succeeded:
            by_kind[f["loss_kind"]] = round(by_kind.get(f["loss_kind"], 0.0) + f["amount_at_risk"], 2)
            by_basis[f["amount_basis"]] = round(by_basis.get(f["amount_basis"], 0.0) + f["amount_at_risk"], 2)
        return {
            "total": len(rows),
            "succeeded": len(succeeded),
            "blocked": len([f for f in rows if f["status"] == "BLOCKED"]),
            "exposure_by_kind": by_kind,
            "exposure_by_basis": by_basis,
            "amount_at_risk": round(sum(f["amount_at_risk"] for f in succeeded), 2),
        }

    # ── row mappers ──
    @staticmethod
    def _run_row(r: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": r["id"], "created_at": r["created_at"],
            "posture": json.loads(r["posture"]), "is_hardened": bool(r["is_hardened"]),
            "label": r["label"], "model": r["model"],
            "tokens_prompt": r["tokens_prompt"], "tokens_completion": r["tokens_completion"],
            "tokens_total": r["tokens_prompt"] + r["tokens_completion"],
            "est_cost_usd": r["est_cost_usd"],
        }

    @staticmethod
    def _finding_row(r: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": r["id"], "run_id": r["run_id"], "attack": r["attack"], "title": r["title"],
            "status": r["status"], "severity": r["severity"],
            "amount_at_risk": r["amount_at_risk"], "loss_kind": r["loss_kind"],
            "amount_basis": r["amount_basis"], "currency": r["currency"],
            "summary": r["summary"], "fix": r["fix"], "invariant": r["invariant"],
            "transaction_ids": json.loads(r["transaction_ids"]),
            "transcript": json.loads(r["transcript"]), "api_calls": json.loads(r["api_calls"]),
            "evidence": json.loads(r["evidence"]), "created_at": r["created_at"],
        }
