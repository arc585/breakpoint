# Breakpoint

**An AI red team for your PayPal checkout.** Breakpoint unleashes a swarm of AI
attacker agents on a store's checkout *and* its AI shopping assistant, finds the
**business-logic** holes that normal scanners miss — haggling the shop bot into a
99% discount, slipping instructions into a product review, tampering with the
cart total, stacking coupons, double-dipping a refund with a dispute, forging a
"paid" webhook — and hands back a ranked report with the exact attack transcript,
the real PayPal API calls, the money it drained, and a one-line fix. Then it
re-runs the same attacks against the hardened store and shows them blocked.

Built for the **PayPal AI Hackathon** (2026).

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

## Attack catalog (v1)

| Attack | What it abuses | PayPal surface |
|--------|----------------|----------------|
| Haggle | talks the shop AI into an oversized discount | Orders + the AI agent |
| Prompt injection | hidden instructions in a review/support message | the AI agent's tools |
| Amount tampering | client-supplied cart total trusted | Orders v2 create/capture |
| Coupon stacking | coupons stack past the policy cap | Orders + discount logic |
| Refund double-dip | refund, then open a sandbox dispute for the same txn | Refunds + Disputes |
| Forged webhook | fake `PAYMENT.CAPTURE.COMPLETED`, no signature check | Webhooks + verify-signature |

## Run it (local)

> Requires a free PayPal **sandbox** app and an Anthropic API key.

```bash
cp .env.example .env     # fill in PayPal sandbox + Anthropic keys
cd backend && pip install -r requirements.txt
python ../scripts/seed_catalog.py
python ../scripts/run_suite.py --target vulnerable   # then: --target hardened
uvicorn app.main:app --reload                        # API + dashboard data
# frontend:
cd ../frontend && npm install && npm run dev
```

Full judge instructions and sandbox test credentials are in the Devpost
submission (kept out of this public repo).

## Stack
Python 3.12 · FastAPI · Anthropic SDK · SQLite · React 19 + Vite + AG Grid ·
deployable on Render.

## License
MIT © 2026 Arnuv Chaubey
