# Breakpoint — <3-minute demo video script

Goal: show the problem, the attack, and the fix — with a real number on screen.
Record the dashboard (http://localhost:5173) with the backend running.

---

**0:00–0:20 — The hook**
> "Every store is adding an AI shopping assistant and letting agents pay through
> PayPal. Nobody's checking whether those agents can be *tricked*. Breakpoint is
> the red team that finds out — before real fraudsters do."

Show the dashboard landing: the two tiles — **Vulnerable 6/6 exploited, $1,624
drained** vs **Hardened 6/6 blocked, $0**.

**0:20–0:50 — What it is**
> "It attacks a demo store's PayPal checkout *and* its AI shop assistant, in the
> PayPal sandbox. Six business-logic attacks. It doesn't guess — it confirms each
> one from real PayPal state."

Scroll the findings grid; hover the red SUCCEEDED rows.

**0:50–1:30 — The money shot (amount tampering)**
Click the **"Buy a $400 grinder for $4"** finding.
> "Here an agent submits its own cart total. The store trusts it. PayPal captures
> four dollars on a four-hundred-dollar order." 

Point at the transcript (cart → tamper → capture) and the API calls. If live:
show the real capture amount.

**1:30–2:10 — The AI gets played (prompt injection + haggle)**
Click **"Hidden instruction in a review hijacks the shop AI."**
> "A customer hid an instruction in a product review. When the shop's AI reads
> reviews, it obeys — and gives a 95% discount. And over here, an attacker just
> *argues* the AI down below cost."

Show the Barista transcript lines.

**2:10–2:45 — The fix (before/after)**
Switch the run selector to the **hardened** run (or click "Run hardened").
> "Now the same six attacks against the hardened store — server recomputes the
> price, caps discounts, verifies webhook signatures, and treats review text as
> data, not instructions. Six for six: blocked."

Show the green tile / all BLOCKED rows. Click one → read the one-line fix.

**2:45–3:00 — Close**
> "Breakpoint: the firewall for agentic commerce. Real attacks, real PayPal,
> real fixes — and it's open source."

Show the GitHub URL: github.com/arc585/breakpoint

---

Tips: keep the mock run as the on-screen demo (instant, clean 6/6). Pre-run both
`python scripts/run_suite.py --target vulnerable` and `--target hardened` before
recording so the grid is populated. Mention "PayPal sandbox — no real money" once.
