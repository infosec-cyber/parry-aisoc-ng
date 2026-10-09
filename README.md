# Parry — an AI AppSec SOC

**Autonomous application-security operations.** Parry sits inline in front of a web app, turns every
HTTP request into a row in ClickHouse, and runs a continuous AI blue-team loop that **detects, triages,
grounds, responds — and writes its own rules**, with no human in the loop.

> It sees the attack, stops it, kicks off the fix, and guards the gap until the code is patched — and it
> never denies service, because every auto-generated rule is correlated against real traffic first.

## The loop
1. **Parse** — a mitmproxy reverse-proxy addon parses every request/response into a structured row (incl. real client IP via `X-Forwarded-For`) and can enforce `403`s.
2. **Store at scale** — ClickHouse Cloud holds millions of events; materialized views pre-aggregate at ingest (~10x compression, sub-20ms queries).
3. **Detect → trigger** — 8 detection rules are plain SQL with thresholds, run every 2s. A crossed threshold is what wakes the SOC — so the LLM only ever sees events that already look like an attack.
4. **Triage** — an OpenAI-compatible `qwen2.5` on a rented **Akash** A100 scores severity, writes the patch, and the incident report.
5. **Ground** — **Senso** supplies the cited response playbook (`grounded_by` doc ids).
6. **Respond + fix** — block the IP; **Semgrep** pins the vulnerable line; the Akash LLM writes a secure patch; **Guild**'s commander agent adjudicates criticals.
7. **Learn, correlate & hold** — distill the exploit into a new ClickHouse rule, **correlate it against real legitimate traffic (0 false positives ⇒ safe to enforce)**, and hold it as a **virtual patch until the code fix is deployed**. Secrets touched during exfiltration are **rotated for real**.

## Sponsors (how we leverage each)
| Partner | Role |
|---|---|
| **ClickHouse Cloud** | the brain — detection is SQL, MVs pre-aggregate, one store feeds the UI + a native CH dashboard |
| **Akash** | rented A100 GPU via the new Console API; one model does triage, patch, and incident report |
| **Semgrep** | turns a detection into the exact `file:line` + CWE; Guardian deployment |
| **Senso** | grounds every decision in cited, verified playbooks |
| **Guild** | hosted commander agent adjudicates criticals — tamper-evident audit trail |

## Run it
See `demo/RUN.md`. Dashboard at `http://localhost:8050` (Live SOC · Battle · How it works · Sponsors · Deck).
Copy `.env.example` → `.env.runtime` and fill in keys. Launch attacks from the **Battle** page.

## Materials
- Slide deck: `slides/parry-deck.html` (+ `.pdf`)
- 3-min explainer video: `demo/parry-podcast.mp4` (transcript in `demo/podcast-transcript.md`)
- Submission copy: `submission/SUBMISSION.md`
- Screenshots: `demo/screenshots/`

*Built for a hackathon. The target app (`target-app/`) is intentionally vulnerable — do not reuse it.*
