# Running the Parry demo

## Services (already running on the host)
- `pipeline/mirror.py` — local ClickHouse → ClickHouse Cloud sync
- `agents/blue/blue_agent.py` — the SOC loop (reads/writes ClickHouse Cloud)
- `dashboard/app.py` — dashboard at **http://localhost:8050**
- Docker stack: `parry-proxy` (:8080), `parry-target` (:5000), `parry-clickhouse` (:8123)

Config lives in `.env.runtime` (cloud URL on port 443, sponsor keys).

## One-shot clean demo
```bash
cd /shared/cybergames/hackathon/parry
PY=/shared/env/py/.venv/bin/python3

# 1) reset tables (local + cloud) for a clean board
for t in http_events detections blocklist fixes; do
  curl -s --data-binary "TRUNCATE TABLE parry.$t" http://localhost:8123/ -H 'X-ClickHouse-User: parry' -H 'X-ClickHouse-Key: parry-local'
  curl -s --user 'default:<CLICKHOUSE_CLOUD_PASSWORD>' --data-binary "TRUNCATE TABLE parry.$t" https://<YOUR-INSTANCE>.clickhouse.cloud:443/
done

# 2) (re)start the blue agent fresh so its dedup state is clear
#    kill the old one first (find pid: ps -eo pid,args | grep blue_agent)
set -a; source .env.runtime; set +a
$PY -u agents/blue/blue_agent.py > .state/blue.log 2>&1 &

# 3) launch the attacker (normal pace ≈ 90s; add --fast for ~30s)
$PY -u agents/red/red_agent.py http://localhost:8080
```
Open **http://localhost:8080** is the attack surface; watch **http://localhost:8050**.

## Capture fresh screenshots
```bash
$PY -I demo/shoot.py http://localhost:8050/ demo/screenshots/dashboard.png
```

## ClickHouse-native dashboard
Paste tiles from `clickhouse/dashboard.sql` into the ClickHouse Cloud SQL console
(console.clickhouse.cloud → service "Red Team" → SQL console) and add each to a dashboard.

## Multi-page UI (dashboard at http://localhost:8050)
- **Live SOC** — real-time console (KPIs, kill chain, AI incident report, detections w/ MITRE+confidence, traffic, rate, AI patches).
- **Battle** — side-by-side attacker / ClickHouse telemetry / blue team, with in-UI buttons to Launch / Fast-run / Reset the attack. Best page to demo live.
- **How it works** — the 6-stage pipeline, each annotated with sponsor + what/how/when.
- **Sponsors** — per-sponsor card: how Parry uses it, when it fires, live status + metrics (pulled from /api/sponsors).
- **Deck** — the slide deck embedded in the UI.

Attack control endpoints (used by the Battle page):
`POST /api/attack/start[?fast=1]`, `GET /api/attack/status`, `POST /api/attack/reset`.
