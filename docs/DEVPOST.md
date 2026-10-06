# Breakpoint — an AI red team for your PayPal checkout

> Paste this into the Devpost project description (it's already Markdown).
> Repo: https://github.com/arc585/breakpoint

## Inspiration

Every store is racing to bolt an AI shopping assistant onto its checkout and let
agents pay through PayPal. Almost nobody is asking the opposite question: **can
those agents be talked into losing money?** In 2026 they already are — Unit 42
documented live agentic retail-fraud, AI-faked refund evidence is the fastest-
growing return scam, and Anthropic's Project Vend showed an AI shopkeeper
cheerfully handing out discounts until it went broke. We wanted the firewall for
that world: something that attacks a checkout the way a real adversary would,
*before* it ships.

## What it does

Breakpoint unleashes a swarm of AI attacker agents on a demo store's PayPal
checkout **and** its AI shop assistant — all in the PayPal sandbox, no real
money. Four scenarios are scripted business-logic checks; two are genuinely
AI-driven (an LLM attacker converses with the assistant). It confirms each one
from real PayPal state (never the model's claim) and reports the **invariant**
that fixes it. Then it re-runs every scenario against a hardened build and shows
them blocked — and a generality suite proves each rule holds across many
products, values and coupon combinations, not just the demo payload.

| Scenario | Kind | What it abuses |
|---|---|---|
| Amount tampering | scripted | client-supplied cart total trusted at create-order |
| Coupon stacking | scripted | coupons stacked past the policy cap |
| Refund double-dip | scripted | over-refund, or refund + a dispute on the same charge |
| Forged webhook | scripted | a fake `PAYMENT.CAPTURE.COMPLETED` with no signature check |
| Haggle | **AI** | an LLM talks the shop assistant into selling below cost |
| Prompt injection | **AI** | a hidden instruction in a review hijacks the assistant |

**The money shot — two distinct flaws:** (1) *Amount tampering* — the shop puts
the client's $4 into a $400 order and PayPal captures $4 as asked; the bug is
trusting the client's number. (2) *Haggle* — the LLM assistant grants a big
discount, the shop creates a low-price order, and PayPal charges it **correctly**;
the bug is the assistant's discount authority, **not PayPal**. Both are blocked on
the hardened store. Every "capture" here is a **sandbox** capture.

Exposure is reported by category and by **basis**, never blended: *uncollected
order value* (goods worth more than was collected), *captured loss* (cash moved
out, confirmed), and *estimated exposure* (what the shop's code would allow but
the rail doesn't execute). The refund over-charge is estimated exposure — PayPal's
live sandbox rail rejects it (`REFUND_AMOUNT_EXCEEDED`), so we don't call it a
real loss. Each finding carries its transaction ids for ledger verification.

## How we built it

- **Target "Dusk Coffee"** — a real PayPal **Orders v2** checkout (sandbox card
  capture), an order ledger, a webhook handler (`verify-webhook-signature`), and
  **Barista**, an LLM shop assistant in unsafe and hardened forms. Vulnerability
  toggles flip the whole store between exploitable and hardened.
- **Red team** — four scripted scenarios drive the checkout directly; two are
  LLM agents that adapt across turns to Barista's replies (OpenAI tool-calling
  loop, a `talk_to_barista` tool) and choose their own tactics.
- **Judge** — decides success independently from real PayPal/ledger state, never
  the model's claim. Pure functions, unit-tested; a generality suite proves each
  hardening rule holds across many inputs, not just the demo payload.
- **Dashboard** — React + **AG Grid**: before/after tiles, findings grid, and a
  detail panel with transcript, API calls and the fix.
- Python/FastAPI · OpenAI · SQLite · React 19/Vite · deployable on **Render**.

## Challenges we ran into

- PayPal **India** sandbox accounts can't do Advanced card processing
  (`PAYEE_NOT_ENABLED_FOR_CARD_PROCESSING`) — solved by creating a US sandbox
  business account + app.
- Real PayPal **bounds refunds at the rail**, so the "unbounded refund" exploit
  is caught live — a useful finding: that class is a merchant-logic flaw the mock
  exposes, while PayPal's own guard stops the naive version in production.
- Making success **verifiable, not claimed** — the judge reads captured amounts
  and ledger state, so every finding is reproducible.

## Accomplishments

- A working before/after: **vulnerable 6/6 exploited vs hardened 0/6**, with live
  PayPal sandbox captures (including an LLM agent haggled to 95% off → a real $20
  capture on a $400 item).
- The hardened fixes are real code (server-side price recompute, discount caps,
  signature verification, quarantining untrusted text) — the report's "fix" is
  something you can actually ship.

## What we learned

Agentic commerce's weak point isn't the crypto or the rails — it's **business
logic and the AI in the loop**. The same model that sells can be sold.

## What's next

More attack classes (idempotency replay, AI-faked refund photos), a GitHub
Action that runs Breakpoint on every PR, and a hardening library teams can adopt.

## How to run / test it

Public repo with full instructions: https://github.com/arc585/breakpoint
Runs fully on a mock PayPal client (no keys needed) for the before/after demo;
`--live` exercises the real PayPal sandbox. Judge test credentials are in the
private "Testing Instructions" field of this submission.
