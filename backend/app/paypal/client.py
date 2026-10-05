"""
Thin async PayPal REST client for the sandbox.

Only what Breakpoint's target and attackers need, nothing more:
  * OAuth2 client-credentials token (cached until shortly before expiry)
  * Orders v2: create / get / authorize / capture
  * Payments v2: refund a capture
  * Disputes v1: list / get / provide-evidence, plus the SANDBOX-ONLY create
    endpoint (needs a PayPal-Auth-Assertion JWT) used to simulate a buyer
    opening a dispute
  * Webhooks: verify-webhook-signature  (the check the TRUST_WEBHOOK=off store
    performs and the forged-webhook attack tries to beat)

Every call returns parsed JSON; non-2xx raises PayPalError carrying status +
body so the red-team judge can inspect exactly what PayPal said.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx


class PayPalError(RuntimeError):
    def __init__(self, status: int, body: Any, *, where: str = ""):
        self.status = status
        self.body = body
        super().__init__(f"PayPal {status} at {where}: {body}")


def auth_assertion(client_id: str, payer_id: str | None = None, email: str | None = None) -> str:
    """
    Unsigned PayPal-Auth-Assertion JWT ({"alg":"none"}) identifying the account
    the call acts on behalf of. Required by the sandbox dispute-create endpoint
    and by multiparty calls. Header.Payload. with a trailing dot, no signature.
    """
    def b64(obj: dict[str, Any]) -> str:
        return base64.b64encode(json.dumps(obj).encode()).decode().rstrip("=")

    payload: dict[str, Any] = {"iss": client_id}
    if payer_id:
        payload["payer_id"] = payer_id
    elif email:
        payload["email"] = email
    return f"{b64({'alg': 'none'})}.{b64(payload)}."


class PayPalClient:
    def __init__(self, *, base_url: str, client_id: str, secret: str, timeout: float = 30.0):
        self._base = base_url.rstrip("/")
        self._id = client_id
        self._secret = secret
        self._http = httpx.AsyncClient(base_url=self._base, timeout=timeout)
        self._token: str | None = None
        self._token_exp: float = 0.0

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "PayPalClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ── auth ──
    async def _access_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        resp = await self._http.post(
            "/v1/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(self._id, self._secret),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 200:
            raise PayPalError(resp.status_code, _body(resp), where="oauth2/token")
        data = resp.json()
        self._token = data["access_token"]
        self._token_exp = time.time() + float(data.get("expires_in", 3000))
        return self._token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        data: Any | None = None,
        files: Any | None = None,
        extra_headers: dict[str, str] | None = None,
        ok: tuple[int, ...] = (200, 201, 202, 204),
    ) -> Any:
        headers = {"Authorization": f"Bearer {await self._access_token()}"}
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        resp = await self._http.request(
            method, path, json=json_body, data=data, files=files, headers=headers
        )
        if resp.status_code not in ok:
            raise PayPalError(resp.status_code, _body(resp), where=f"{method} {path}")
        return _body(resp)

    # ── Orders v2 ──
    async def create_order(self, order: dict[str, Any], *, request_id: str | None = None) -> Any:
        headers = {"PayPal-Request-Id": request_id} if request_id else None
        return await self._request("POST", "/v2/checkout/orders", json_body=order, extra_headers=headers)

    async def get_order(self, order_id: str) -> Any:
        return await self._request("GET", f"/v2/checkout/orders/{order_id}")

    async def capture_order(self, order_id: str, *, request_id: str | None = None) -> Any:
        headers = {"PayPal-Request-Id": request_id} if request_id else None
        return await self._request(
            "POST", f"/v2/checkout/orders/{order_id}/capture", json_body={}, extra_headers=headers
        )

    async def authorize_order(self, order_id: str) -> Any:
        return await self._request("POST", f"/v2/checkout/orders/{order_id}/authorize", json_body={})

    # ── Payments v2: refunds ──
    async def refund_capture(
        self, capture_id: str, amount: dict[str, str] | None = None, *, request_id: str | None = None
    ) -> Any:
        body = {"amount": amount} if amount else {}
        headers = {"PayPal-Request-Id": request_id} if request_id else None
        return await self._request(
            "POST", f"/v2/payments/captures/{capture_id}/refund", json_body=body, extra_headers=headers
        )

    async def get_capture(self, capture_id: str) -> Any:
        return await self._request("GET", f"/v2/payments/captures/{capture_id}")

    # ── Disputes v1 ──
    async def list_disputes(self) -> Any:
        return await self._request("GET", "/v1/customer/disputes")

    async def get_dispute(self, dispute_id: str) -> Any:
        return await self._request("GET", f"/v1/customer/disputes/{dispute_id}")

    async def create_dispute_sandbox(
        self, *, buyer_transaction_id: str, reason: str, amount: dict[str, str], auth_jwt: str
    ) -> Any:
        """
        SANDBOX ONLY. Opens a dispute as the buyer. `auth_jwt` is a
        PayPal-Auth-Assertion for the buyer account (see auth_assertion()).
        Sent as multipart/form-data per PayPal's sample.
        """
        payload = {
            "disputed_transactions": [{"buyer_transaction_id": buyer_transaction_id}],
            "reason": reason,
            "dispute_amount": amount,
        }
        files = {"input": (None, json.dumps(payload), "application/json")}
        return await self._request(
            "POST", "/v1/customer/disputes", files=files,
            extra_headers={"PayPal-Auth-Assertion": auth_jwt},
        )

    async def provide_evidence(self, dispute_id: str, *, notes: str, document: tuple | None = None) -> Any:
        files: dict[str, Any] = {"input": (None, json.dumps({"notes": notes}), "application/json")}
        if document:
            files["file1"] = document
        return await self._request(
            "POST", f"/v1/customer/disputes/{dispute_id}/provide-evidence", files=files
        )

    # ── Webhooks ──
    async def verify_webhook_signature(
        self, *, headers: dict[str, str], webhook_id: str, event_body: dict[str, Any]
    ) -> bool:
        """Returns True only if PayPal confirms the webhook signature is genuine."""
        payload = {
            "auth_algo": headers.get("paypal-auth-algo"),
            "cert_url": headers.get("paypal-cert-url"),
            "transmission_id": headers.get("paypal-transmission-id"),
            "transmission_sig": headers.get("paypal-transmission-sig"),
            "transmission_time": headers.get("paypal-transmission-time"),
            "webhook_id": webhook_id,
            "webhook_event": event_body,
        }
        result = await self._request(
            "POST", "/v1/notifications/verify-webhook-signature", json_body=payload
        )
        return isinstance(result, dict) and result.get("verification_status") == "SUCCESS"


def _body(resp: httpx.Response) -> Any:
    if resp.status_code == 204 or not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError:
        return resp.text
