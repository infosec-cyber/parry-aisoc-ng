# Parry — Hackathon submission package

Fill the form with the fields below. Copy-paste verbatim; bold the marked phrases in the editor.

---

## What does it do, and for whom?  (≤300 chars)
Parry is an autonomous AI AppSec SOC for web apps. It watches every HTTP request, detects live attacks as SQL over ClickHouse, triages and patches them with an LLM on Akash GPUs, blocks the attacker, rotates exposed secrets, and writes its own detection rules — no human in the loop.

*(276 characters)*

---

## Project description  (≤1,500 chars)
> Bold these phrases in the editor: **DETECT, TRIAGE, GROUND, RESPOND**, **ClickHouse Cloud**, **Akash**, **Semgrep**, **Senso**, **Guild**, **Detection IS SQL**, **writes a secure patch**, **rotates every touched secret**, **returns 403**.

The problem: detection is solved, response isn't. Alerts pile up, a human triages, and the attacker is gone. Dwell time is hours; an automated attack finishes in seconds.

Parry closes the loop. It sits inline as a reverse proxy; every request becomes a row in ClickHouse, and an AI blue-team agent runs a continuous loop: DETECT, TRIAGE, GROUND, RESPOND.

How we use each partner:
ClickHouse Cloud — the brain. Detection IS SQL: 8 rules over live telemetry every 2s, with materialized views pre-aggregating at ingest. Add a detector in one SELECT.
Akash — triage runs on a rented NVIDIA A100 via the new Console API (managed wallet, auto-funding, runtime cap). One model scores alerts, writes the code patch, and the incident report.
Semgrep — pins the exact vulnerable line on every high-severity alert; the Akash LLM then writes a secure patch.
Senso — grounds every call in verified playbooks, citing the doc ids used.
Guild — a hosted commander agent adjudicates critical detections as a tamper-evident audit trail.

What makes it smart: when an exploit succeeds once, Parry distills it into a brand-new, validated ClickHouse rule and arms it instantly. And the moment exfiltration is seen, it rotates every touched secret for real — the stolen key is already dead.

The result: launch an attacker from the dashboard, watch it caught, blocked, and patched live; run it again and the whole attack returns 403. Autonomous defense, with receipts.

*(1,449 characters)*

---

## Team
1 — Just me (the submitter).

## Event tech partners — SELECT these 5
- [x] ClickHouse
- [x] Akash
- [x] Semgrep
- [x] Senso.ai
- [x] Guild.ai
- [ ] Pi  (not used)

## Links
- GitHub repository: https://github.com/infosec-cyber/parry-aisoc-ng
- Project website: https://github.com/infosec-cyber/parry-aisoc-ng  (or your deployed dashboard URL)
- Demo video (~3 min): upload demo/parry-podcast.mp4 to YouTube/Drive/Loom and paste the link here.

## Screenshot (gallery cover, ≤5 MB)
Upload one of:
- demo/screenshots/01-live.png  (recommended — richest single view)
- demo/screenshots/page-attack.png  (the live 3-column Battle view)

## Additional project details (optional)
Four sponsor lanes run live in the demo (ClickHouse Cloud, Akash GPU, Semgrep, Senso); Guild is wired as the critical-escalation commander. The dashboard has five pages — Live SOC, Battle (launch attacks + watch attacker/ClickHouse/blue-team side by side), How it works, Sponsors (live per-partner proof + metrics), and the slide deck embedded. All detection, triage, grounding, patching, rule-learning and secret-rotation is autonomous and evidenced in ClickHouse.
