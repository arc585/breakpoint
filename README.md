# Breakpoint

**A sandbox security test bench for AI-enabled checkout.** Breakpoint runs a set
of **attack scenarios** — four scripted business-logic checks and two that drive
a live LLM against the shop's AI assistant — against **Dusk Coffee**, a
purpose-built, intentionally-vulnerable demo app, entirely in the **PayPal
sandbox**. For each scenario it shows the order/payment state it caused, whether
it succeeded, the exposure it created, and the **security rule (invariant)** that
fixes it. Then it re-runs every scenario against the hardened build and shows
them blocked — and a generality test suite proves each rule holds across many
products, values, and coupon combinations, not just the demo payload.

Built for the **PayPal AI Hackathon** (2026).

### Scope & honesty
- It tests **only the bundled Dusk Coffee app**, which is built to be vulnerable.
  It is **not** a tool for testing arbitrary live stores.
- Four scenarios (amount tampering, coupon stacking, refund double-dip, forged
  webhook) are **scripted** checks. Two (**haggle**, **prompt injection**) are
  **AI-driven**: an LLM attacker adapts across turns to the assistant's replies
  and chooses its own tactics; the harness then verifies the result independently
  from sandbox state (never the model's claim).
- In the AI cases **PayPal (sandbox) captures exactly what the order says**; the
  flaw is the shop's pricing/discount policy, not PayPal. Every "capture" in this
  project is a **sandbox** capture.
- Each finding has **transaction ids** (order/capture/refund/dispute) so you can
  check it against the PayPal sandbox ledger.
- Exposure is reported **by category and by basis**, never blended:
  - *uncollected order value* — goods/commitment worth more than was collected
    (amount tampering, coupon excess, goods shipped unpaid);
  - *captured loss* — cash actually moved out, confirmed in the ledger;
  - *estimated exposure* — what the merchant's code would allow but the rail does
    not execute. The refund over-charge is **estimated exposure**: PayPal's live
    sandbox rail rejects it (`REFUND_AMOUNT_EXCEEDED`), so it is not a real loss —
    it's a merchant-logic flaw the mock surfaces.

---

## ⚠️ Safety & scope

Breakpoint is a **defensive, authorized** security tool. It attacks **only the
Dusk Coffee demo store that ships inside this repo**, and **only in the PayPal
sandbox** — no real money, no live accounts, no third-party systems, ever. The
target is intentionally vulnerable so the attacks have something to find; the
same code ships a hardened version that blocks them. Do not point this at any
system you do not own and have explicit permission to test.

---

## How it works

```
  ┌──────────────┐     attacks      ┌───────────────────────────┐
  │  Red team    │ ───────────────► │  Target: "Dusk Coffee"    │
  │  (AI agents) │                  │  checkout API + Barista   │
  │  6 attacks   │ ◄─────────────── │  (PayPal sandbox)         │
  └──────┬───────┘   real PayPal    └───────────────────────────┘
         │           state decides
         ▼
  ┌──────────────┐
  │  Judge       │  success is read from PayPal/order state, never the model's claim
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │  Dashboard   │  findings grid · transcript · API calls · $ drained · the fix
  │  (AG Grid)   │  before (vulnerable) vs after (hardened)
  └──────────────┘
```

- **Target — Dusk Coffee:** a small coffee roaster with a PayPal Orders v2
  checkout and an AI assistant ("Barista"). Vulnerability toggles (see
  `.env.example`) flip it between **exploitable** and **hardened**.
- **Red team:** six attacker agents, each a Claude agent that drives tools
  against the target. A judge confirms each exploit from real PayPal state.
- **Report:** a React + AG Grid dashboard of runs and findings.

## Attack scenarios (v1)

| Scenario | Kind | What it abuses | Invariant the fix enforces |
|----------|------|----------------|----------------------------|
| Amount tampering | scripted | client-supplied cart total trusted | `order.amount == server_price(cart)` |
| Coupon stacking | scripted | coupons stack past the policy cap | `discount ≤ cap AND ≤ 1 coupon` |
| Refund double-dip | scripted | over-refund / refund + dispute same charge | `Σ refunds ≤ captured; one payout per charge` |
| Forged webhook | scripted | fake `PAYMENT.CAPTURE.COMPLETED`, no sig check | `fulfil ⟹ verify_webhook_signature == SUCCESS` |
| Haggle | **AI** | LLM talks the shop assistant below cost | `assistant_discount ≤ cap; server sets final price` |
| Prompt injection | **AI** | hidden instruction in a review hijacks the assistant | `tool-returned text is data, never instructions` |

## Run it (local)

Keys needed depend on how much you want to exercise:
- **Four scripted scenarios on the mock PayPal** — no keys at all (self-contained).
- **The two AI scenarios** (haggle, prompt injection) — need an `OPENAI_API_KEY`.
- **`--live`** against the real PayPal sandbox — needs a **US** sandbox business
  account + app (India accounts can't do Advanced card processing).

```bash
cp .env.example .env                 # OPENAI_API_KEY for the AI scenarios; PayPal keys only for --live
cd backend && pip install -r requirements.txt
pytest                               # unit + generality suite, no keys/network
python ../scripts/run_suite.py --target vulnerable   # mock; add --live for real sandbox
python ../scripts/run_suite.py --target hardened     # same scenarios, now blocked
uvicorn app.main:app --port 8008                     # API + dashboard data
# dashboard:
cd ../frontend && npm install && npm run dev          # http://localhost:5173
```

"Self-contained mock" means no PayPal and no network for the scripted scenarios;
the AI scenarios still call the LLM. Judge instructions and sandbox test
credentials are in the Devpost submission's private field (kept out of this repo).

## Stack
Python 3.12 · FastAPI · OpenAI SDK · SQLite · React 19 + Vite + AG Grid ·
deployable on Render.

## License
MIT © 2026 Arnuv Chaubey
