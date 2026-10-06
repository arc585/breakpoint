"""
Settings for Breakpoint.

Two groups matter:
  * PayPal sandbox credentials + the LLM key — real integration.
  * The vulnerability toggles — the whole point of the demo. With every toggle
    ON, the Dusk Coffee target is exploitable; flip them OFF and the same attack
    suite is run against the HARDENED store, which is the before/after the judges
    see. The toggles live in config (not scattered `if`s) so a run records
    exactly which posture it attacked.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── PayPal ──
    paypal_env: str = "sandbox"
    paypal_client_id: str = ""
    paypal_secret: str = ""
    paypal_merchant_email: str = ""
    paypal_merchant_payer_id: str = ""
    paypal_buyer_email: str = ""
    paypal_webhook_id: str = ""

    # ── LLM (OpenAI drives the attacker agents + the Barista) ──
    # Default to the cheapest reliable tool-caller; bump via BREAKPOINT_MODEL.
    openai_api_key: str = ""
    breakpoint_model: str = "gpt-4o-mini"

    # ── Vulnerability toggles (ON = exploitable) ──
    trust_client_amount: bool = True
    allow_coupon_stack: bool = True
    unbounded_refund: bool = True
    trust_webhook: bool = True
    unsafe_barista: bool = True

    # ── Policy the hardened store enforces / the judge measures against ──
    min_price_floor_pct: float = 0.50
    max_coupon_discount_pct: float = 0.30

    # ── App ──
    breakpoint_db: str = "backend/breakpoint.db"
    attacker_concurrency: int = 3

    @property
    def paypal_base_url(self) -> str:
        return (
            "https://api-m.paypal.com"
            if self.paypal_env == "live"
            else "https://api-m.sandbox.paypal.com"
        )

    def posture(self) -> dict[str, bool]:
        """The toggle state a run attacked, recorded with every finding."""
        return {
            "trust_client_amount": self.trust_client_amount,
            "allow_coupon_stack": self.allow_coupon_stack,
            "unbounded_refund": self.unbounded_refund,
            "trust_webhook": self.trust_webhook,
            "unsafe_barista": self.unsafe_barista,
        }

    def is_hardened(self) -> bool:
        return not any(self.posture().values())


@lru_cache
def get_settings() -> Settings:
    return Settings()
