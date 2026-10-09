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

---

## Technical architecture
**Data plane (capture → store):**
- A **mitmproxy** reverse proxy sits inline in front of the target app. A Python addon (`pipeline/ch_sink.py`) parses every request + response into one structured row — method, path, query, headers, body snippet, status, latency, cookie-derived session, and the real client IP (from `X-Forwarded-For`) — and streams it to ClickHouse. The same addon enforces blocks by returning `403`.
- Capture writes to a **local ClickHouse** buffer; a host-side mirror (`pipeline/mirror.py`) syncs flows to **ClickHouse Cloud** on port 443 (this host's egress only permits 443). Two `AggregatingMergeTree` materialized views pre-aggregate request/error rate and auth-failure pressure at ingest.

**Control plane (detect → respond), `agents/blue/blue_agent.py`, every 2s:**
1. **DETECT** — 8 detection rules are plain SQL with `HAVING` thresholds over the live Cloud tables. A returned row is the trigger.
2. **TRIAGE** — an OpenAI-compatible `qwen2.5` on a rented **Akash A100** (deployed via the Console API) returns `{severity, confidence, summary}`; it also writes the code patch and the incident report.
3. **GROUND** — **Senso** search returns the cited response playbook; doc ids are stored on the detection (`grounded_by`).
4. **RESPOND** — write a blocklist row (local for proxy enforcement + Cloud for the UI); **Semgrep** pins the vulnerable `file:line`; the Akash LLM writes a secure patch; **Guild**'s commander agent adjudicates criticals (agent_test session + events flow).
5. **ADAPT** — distill the exploit into a new ClickHouse rule, **correlate it against a baseline of real legitimate traffic** (0 false positives ⇒ `enforce=1`, else alert-only) so it never denies service, and hold it as a **virtual patch** (`status=holding`) until the code fix is deployed. Secrets touched during exfiltration are rotated for real via `docker exec` into the target.

**Tables:** `http_events`, `detections`, `blocklist`, `fixes`, `learned_rules`, `rotations`, plus `mv_src_rates` / `mv_auth`.
**Presentation:** a Flask dashboard (`dashboard/`) with 5 pages reads Cloud directly and launches attacks via `/api/attack/*`.
**Attacker/benign:** `agents/red/red_agent.py` (8-stage kill chain, scenario + pace + custom stages, distinct attacker IP) and `agents/red/normal_user.py` (legitimate-traffic generator for the correlation baseline).

## Setup instructions
```bash
# 1. Bring up the local data plane (target app, proxy, local ClickHouse)
cd parry && docker compose up -d        # target:5000, proxy:8080, clickhouse:8123

# 2. Configure keys
cp .env.example .env.runtime            # fill in ClickHouse Cloud URL + sponsor keys
#    CLICKHOUSE_URL, AKASH_OPENAI_URL/MODEL, SEMGREP_APP_TOKEN,
#    SENSO_API_KEY, GUILD_WS/AGENT_ID/AGENT_VERSION/KEY_ID/KEY_SECRET

# 3. Load the schema into ClickHouse Cloud (statements are split; HTTP runs one at a time)
#    see clickhouse/schema.sql

# 4. Run the host-side brain (uses a venv with flask + requests)
set -a; source .env.runtime; set +a
python3 -u pipeline/mirror.py            &   # local -> Cloud sync
python3 -u agents/blue/blue_agent.py     &   # the SOC loop
python3 -u dashboard/app.py              &   # dashboard on :8050
python3 -u agents/red/normal_user.py http://localhost:8080 &   # baseline traffic

# 5. Open http://localhost:8050 → Battle page → Launch attack
```
Notes: Semgrep's scanner needs `EIO_BACKEND=posix` on hosts where io_uring/memlock is restricted. GCP/Senso/Akash APIs reject the default `Python-urllib` user-agent (Cloudflare), so all calls send a browser `User-Agent`.

## Lessons learned
- **LLMs don't scale to every request — SQL does.** The winning move was making detection a ClickHouse query and spending the GPU only on events that already matched a rule. Materialized views made it sub-20ms over millions of rows.
- **Auto-generated rules are dangerous.** An unchecked learned rule can block real users and DoS your own app. Correlating each new rule against live legitimate traffic (and only enforcing at 0 false positives) was essential, not optional.
- **A detection should own the fix until it's closed.** Treating each learned rule as a *virtual patch that holds until the code is fixed* turned detection+response into real remediation.
- **CPU LLM inference was unusable (~7s/token); GPU on Akash was ~0.5s.** The Console API's managed wallet + `runtimeLimitHours` kept a GPU affordable and safe to leave running.
- **Egress is a real constraint.** Only port 443 was allowed outbound, so ClickHouse Cloud is reached on 443 (not 8443) and containers that can't egress write locally and are mirrored up.
- **Every sponsor API had a quirk** (Cloudflare UA blocks on Akash/Senso/GCP; Guild account keys can only open `agent_test`/`chat` sessions, not `api_trigger`; Semgrep rule YAML + io_uring). Budgeting time for integration edge-cases mattered as much as the core logic.
