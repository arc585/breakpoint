"""
In-memory order ledger — Dusk Coffee's store-side truth.

PayPal knows what it captured; the ledger knows what Dusk *charged*, whether it
*fulfilled*, and what it *refunded*. The judge reads both and flags a finding
when they disagree (e.g. fulfilled with no capture, refunded more than paid,
captured far below list price). State is per-run and lives only in memory.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OrderRecord:
    order_id: str
    items: list[dict[str, Any]]
    list_total: float                 # honest Σ(catalog price × qty)
    charged_total: float              # what Dusk billed
    currency: str = "USD"
    capture_id: str | None = None
    captured_value: float | None = None   # what PayPal actually captured
    refunded_total: float = 0.0
    fulfilled: bool = False
    fulfilled_reason: str = ""
    dispute_id: str | None = None
    notes: list[str] = field(default_factory=list)

    def net_paid_to_merchant(self) -> float:
        """Captured minus refunded — what Dusk actually keeps."""
        return round((self.captured_value or 0.0) - self.refunded_total, 2)


class Ledger:
    def __init__(self) -> None:
        self._orders: dict[str, OrderRecord] = {}

    def put(self, rec: OrderRecord) -> OrderRecord:
        self._orders[rec.order_id] = rec
        return rec

    def get(self, order_id: str) -> OrderRecord | None:
        return self._orders.get(order_id)

    def all(self) -> list[OrderRecord]:
        return list(self._orders.values())
