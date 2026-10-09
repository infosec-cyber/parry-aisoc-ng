# Parry — Presentation Walkthrough

**Deck:** open `slides/parry-deck.html` in a browser. Arrow keys / space to move.
Press `P` then `Ctrl/Cmd-P` → "Save as PDF" for a handout. 12 slides, ~6 minutes + demo.

**Golden path:** open the deck on one screen and the live dashboard
(`http://localhost:8050`) on another. Talk the deck, cut to the dashboard for the demo.

---

## Timing (8-minute slot)
| Section | Slides | Time |
|---|---|---|
| Hook + problem | 1–2 | 1:00 |
| What we built + architecture | 3–5 | 2:00 |
| **Live demo** | (dashboard) | 2:30 |
| Sponsor deep-dives | 7–10 | 1:30 |
| Results + close | 11–12 | 1:00 |

---

## Per-slide talking points

**1 · Title.** "Everyone can *detect* attacks. Parry *responds* to them — autonomously, in under a second. Here's how, and how we used five sponsor platforms to do it."

**2 · Problem.** One line each: alerts aren't actions; the response gap is hours vs an attack that takes seconds; the context to decide lives in people. Land the question at the bottom.

**3 · What we built.** Name the four-phase loop — DETECT, TRIAGE, GROUND, ACT. Point at the dashboard thumbnail: "this is live, reading ClickHouse Cloud." Drop the three numbers.

**4 · Architecture (the money slide).** Trace the arrows with your cursor:
"Attacker hits our reverse proxy. Every request is mirrored into ClickHouse and synced to **ClickHouse Cloud** — the brain. The **blue agent** reads the Cloud, runs its loop, and fans out to the four ACT lanes. When it decides to block, it pushes a row back and the **proxy returns 403** — that red arrow is the kill."

**5 · Architecture detail.** Ingest path on the left, decision path on the right. Emphasize: "detection is just SQL," and "every conclusion is grounded in rows — flow ids, model, cited docs, latency."

**6 · Demo setup → CUT TO LIVE.** Read the kill-chain list, then switch to the dashboard and run it (see below).

**7–10 · Sponsors.** For each, one sentence on the *optimal* angle:
- **ClickHouse:** "Detection *is* a SQL query. Materialized views pre-aggregate at ingest. Same store feeds a native ClickHouse dashboard."
- **Akash:** "We deploy a GPU LLM through the new **Console API** — managed wallet, automatic funding, a runtime cap so we can't overspend. OpenAI-compatible endpoint."
- **Semgrep:** "A detection becomes the exact vulnerable line — custom rules plus the p/flask Pro set, wired to Guardian."
- **Senso + Guild:** "Senso grounds every call with cited docs. Guild's hosted agent adjudicates every critical as a tamper-evident audit trail."

**11 · Results.** The measured numbers from the live run. "Fully evidenced, graceful degradation."

**12 · Close.** Stack + what's next. End on the one-liner: "It sees the attack, understands it, stops it, and shows you why."

---

## Live demo script (2.5 min)
1. Have the dashboard open at `http://localhost:8050`, already showing a clean/low state.
2. Say: "I'm launching an autonomous attacker against our app now."
3. Run the kill chain (one command — see `demo/RUN.md`).
4. Narrate as tiles light up: "recon… brute force… SQL injection… now it's walking *other users'* private notes… **there** — a Stripe key and DB creds just left the app, flagged critical… and command injection — **blocked.**"
5. Point at **Autonomous Response**: "Parry blocked the IP. Watch the attacker's next requests."
6. Point at **Live traffic**: the attacker's rows are now `403`. "Game over, no human touched it."
7. Optional: open the **ClickHouse Cloud SQL console** and run a tile from `clickhouse/dashboard.sql` to show the same data is queryable BI.

## If the demo misbehaves
- Screenshots in `demo/screenshots/` (`03-final.png`, `02-midattack.png`) are a full fallback — talk over them.
- Each sponsor lane is optional; if one is down the loop still runs. Say so — it's a feature.

## Likely questions
- *"Is the LLM in the hot path?"* No — detection is pure SQL (ms). The LLM enriches/triages; if it's slow or down, rules-only still detects and blocks.
- *"False positives?"* Rules set a severity floor; the model can raise but never silently lower. Blocks are gated to a small set of high-confidence critical techniques.
- *"Why ClickHouse not a SIEM?"* Detection as SQL over columnar storage = add a rule in one line, sub-second over millions of rows, and the same store powers the dashboard.
- *"Does it scale multi-app?"* One ClickHouse, per-app partitioning; the proxy/agent are stateless.
