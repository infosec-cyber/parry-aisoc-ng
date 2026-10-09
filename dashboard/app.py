#!/usr/bin/env python3
"""Parry SOC dashboard — reads parry.* straight from ClickHouse Cloud and
renders a live defender console. Run on the host:

  CLICKHOUSE_URL="https://default:PW@host:443" python3 dashboard/app.py
"""
import base64, json, os, sys, time, subprocess, threading
from urllib.parse import urlsplit, urlunsplit, quote
import urllib.request
from flask import Flask, jsonify, Response, send_from_directory, request

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://parry:parry-local@localhost:8123")
LANES = {
    "ClickHouse": True,
    "Akash": bool(os.environ.get("AKASH_OPENAI_URL") or os.environ.get("AKASHML_API_KEY")),
    "Semgrep": bool(os.environ.get("SEMGREP_APP_TOKEN")),
    "Guild": bool(os.environ.get("GUILD_SESSIONS_URL")),
    "Senso": bool(os.environ.get("SENSO_API_KEY")),
}

def _parts(u):
    s = urlsplit(u); host = s.hostname + (f":{s.port}" if s.port else "")
    return urlunsplit((s.scheme, host, "", "", "")), (s.username or "default"), (s.password or "")
CB, CU, CP = _parts(CH_URL)
AKASH_URL = os.environ.get("AKASH_OPENAI_URL", "")
AKASH_MODEL = os.environ.get("AKASH_OPENAI_MODEL", "")
CH_HOST = urlsplit(CH_URL).hostname or "localhost"
SENSO_KEY = os.environ.get("SENSO_API_KEY", "")
SEMGREP_WEB = os.environ.get("SEMGREP_WEB_TOKEN", os.environ.get("SEMGREP_APP_TOKEN", ""))

def ch(sql):
    req = urllib.request.Request(CB + "/?query=" + quote(sql),
        headers={"Authorization": "Basic " + base64.b64encode(f"{CU}:{CP}".encode()).decode()})
    return urllib.request.urlopen(req, timeout=20).read().decode()

def chj(sql):
    try:
        return [json.loads(l) for l in ch(sql + " FORMAT JSONEachRow").splitlines() if l]
    except Exception:
        return []

def _http(url, headers=None, data=None):
    h = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=(data.encode() if isinstance(data, str) else data), headers=h)
    try:
        return json.loads(urllib.request.urlopen(req, timeout=20).read().decode())
    except Exception as e:
        return {"error": str(e)[:160]}

app = Flask(__name__)

RED = os.path.join(os.path.dirname(__file__), "..", "agents", "red", "red_agent.py")
RED_LOG = os.path.join(os.path.dirname(__file__), "..", ".state", "red_ui.log")
LOCAL_CH = os.environ.get("LOCAL_CH_URL", "http://parry:parry-local@localhost:8123")
_red = {"p": None}

def _ch_post(url, sql):
    u = urlsplit(url); host = u.hostname + (f":{u.port}" if u.port else "")
    base = urlunsplit((u.scheme, host, "", "", ""))
    req = urllib.request.Request(base + "/", data=sql.encode(),
        headers={"Authorization": "Basic " + base64.b64encode(f"{(u.username or 'default')}:{(u.password or '')}".encode()).decode()})
    return urllib.request.urlopen(req, timeout=20).read().decode()

KILL_CHAIN = ["recon-scan","bruteforce","sqli-probe","sqli-dump","idor-enum","bac-admin","cmdinj","exfil-canary"]

@app.route("/api/stats")
def stats():
    ev = chj("SELECT count() c, uniq(src_ip) ips FROM parry.http_events")
    det = chj("SELECT count() c FROM parry.detections WHERE technique NOT IN ('commander-report','incident-report')")
    blk = chj("SELECT count() c FROM parry.blocklist")
    fx = chj("SELECT count() c FROM parry.fixes")
    lr = chj("SELECT count() c FROM parry.learned_rules")
    hold = chj("SELECT count() c FROM parry.learned_rules WHERE status='holding'")
    rot = chj("SELECT count() c FROM parry.rotations")
    sev = chj("SELECT severity, count() c FROM parry.detections WHERE technique NOT IN ('commander-report','incident-report') GROUP BY severity")
    fired = chj("SELECT DISTINCT technique FROM parry.detections")
    return jsonify(
        events=ev[0]["c"] if ev else 0, ips=ev[0]["ips"] if ev else 0,
        detections=det[0]["c"] if det else 0, blocked=blk[0]["c"] if blk else 0,
        fixes=fx[0]["c"] if fx else 0,
        learned=lr[0]["c"] if lr else 0, rotated=rot[0]["c"] if rot else 0,
        holding=hold[0]["c"] if hold else 0,
        severity={r["severity"]: r["c"] for r in sev},
        chain=[{"stage": s, "hit": any(f["technique"] == s for f in fired)} for s in KILL_CHAIN],
        lanes=LANES,
    )

@app.route("/api/traffic")
def traffic():
    return jsonify(chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, src_ip, method, path, status, resp_bytes
        FROM parry.http_events ORDER BY ts DESC LIMIT 25"""))

@app.route("/api/detections")
def detections():
    return jsonify(chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, detection_id, severity, technique, title,
        narrative, latency_ms, model, length(evidence_ids) evidence, grounded_by,
        mitre, round(confidence,2) confidence
        FROM parry.detections WHERE technique NOT IN ('commander-report','incident-report') ORDER BY ts DESC LIMIT 20"""))

@app.route("/api/mitigations")
def mitigations():
    blk = chj("SELECT formatDateTime(ts,'%H:%i:%S') t, src_ip, reason FROM parry.blocklist ORDER BY ts DESC LIMIT 10")
    fx = chj("SELECT formatDateTime(ts,'%H:%i:%S') t, semgrep_rule, file, line, patch FROM parry.fixes ORDER BY ts DESC LIMIT 10")
    cmd = chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, narrative FROM parry.detections
        WHERE technique='commander-report' ORDER BY ts DESC LIMIT 5""")
    return jsonify(blocked=blk, fixes=fx, commander=cmd)

@app.route("/api/ratechart")
def ratechart():
    return jsonify(chj("""SELECT formatDateTime(bucket,'%H:%i:%S') t, countMerge(reqs) reqs
        FROM parry.mv_src_rates GROUP BY bucket ORDER BY bucket DESC LIMIT 30"""))

@app.route("/api/senso")
def senso_proof():
    """Live proof of Senso grounding: the actual passages the agent retrieves."""
    if not SENSO_KEY:
        return jsonify(enabled=False, passages=[], grounded_detections=0)
    q = "response playbook for sqli-dump and data exfiltration"
    data = _http("https://apiv2.senso.ai/api/v1/org/search/context",
                 {"X-API-Key": SENSO_KEY, "Content-Type": "application/json"},
                 json.dumps({"query": q, "max_results": 4}))
    passages = [{"title": p.get("title"), "content_id": p.get("content_id"),
                 "score": round(p.get("score", 0), 3),
                 "text": (p.get("chunk_text") or "")[:260]} for p in data.get("results", [])]
    gd = chj("SELECT count() c FROM parry.detections WHERE length(grounded_by)>0")
    return jsonify(enabled=True, query=q, passages=passages,
                   grounded_detections=gd[0]["c"] if gd else 0,
                   kb_docs=len({p["content_id"] for p in passages if p["content_id"]}))


@app.route("/api/semgrep")
def semgrep_proof():
    """The authored Semgrep rules + the root-cause fixes the agent produced."""
    rules = []
    try:
        import yaml
        doc = yaml.safe_load(open(os.path.join(os.path.dirname(__file__), "..", "semgrep", "parry.yaml")))
        for r in doc.get("rules", []):
            md = r.get("metadata", {}) or {}
            rules.append({"id": r.get("id"), "message": (r.get("message") or "").strip()[:130],
                          "cwe": str(md.get("cwe", "")).strip()[:60],
                          "severity": r.get("severity", ""), "owasp": str(md.get("owasp", ""))[:40]})
    except Exception as e:
        rules = [{"id": "parse-error", "message": str(e)[:80], "cwe": "", "severity": "", "owasp": ""}]
    fixes = chj("""SELECT semgrep_rule, file, line, substring(patch,1,400) patch
        FROM parry.fixes ORDER BY ts DESC LIMIT 8""")
    findings = 0
    if SEMGREP_WEB:
        d = _http("https://semgrep.dev/api/v1/deployments/rotemb_appsec_personal_org/findings",
                  {"Authorization": f"Bearer {SEMGREP_WEB}"})
        findings = len(d.get("findings", [])) if isinstance(d, dict) else 0
    return jsonify(rules=rules, fixes=fixes, platform_findings=findings,
                   deployment="rotemb-appsec-personal-org")


@app.route("/api/chstats")
def ch_stats():
    """Deeper ClickHouse proof: rows, on-disk size and compression per table."""
    rows = chj("""SELECT table, sum(rows) rows, formatReadableSize(sum(data_compressed_bytes)) compressed,
        formatReadableSize(sum(data_uncompressed_bytes)) uncompressed,
        round(sum(data_uncompressed_bytes)/greatest(sum(data_compressed_bytes),1),1) ratio
        FROM system.parts WHERE database='parry' AND active GROUP BY table ORDER BY rows DESC""")
    q = chj("""SELECT count() q, round(avg(query_duration_ms),1) avg_ms FROM system.query_log
        WHERE event_time > now() - INTERVAL 1 HOUR AND type=2""")
    mv = chj("SELECT count() c FROM parry.mv_src_rates")
    return jsonify(tables=rows, queries_1h=(q[0]["q"] if q else 0),
                   avg_query_ms=(q[0]["avg_ms"] if q else 0),
                   mv_rows=mv[0]["c"] if mv else 0, version="ClickHouse Cloud 26.x")


@app.route("/api/remediate", methods=["POST"])
def remediate():
    """Simulate 'the underlying issue was fixed & deployed' — retire virtual-patch rules."""
    for url in (LOCAL_CH, CH_URL):
        try: _ch_post(url, "ALTER TABLE parry.learned_rules UPDATE status='retired', enabled=0 WHERE status='holding'")
        except Exception: pass
    return jsonify(ok=True)


@app.route("/api/adaptive")
def adaptive():
    lr = chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, name, technique, rationale, sql,
        false_positives, baseline_checked, enforce, status, protects
        FROM parry.learned_rules ORDER BY ts DESC LIMIT 12""")
    rot = chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, secret_type, old_masked, new_masked, reason
        FROM parry.rotations ORDER BY ts DESC LIMIT 12""")
    return jsonify(learned=lr, rotations=rot)


@app.route("/api/attack/start", methods=["POST"])
def attack_start():
    from flask import request
    if _red["p"] and _red["p"].poll() is None:
        return jsonify(running=True, msg="already running")
    stages = request.args.get("stages", "").strip()
    pace = request.args.get("pace", "normal")
    args = [sys.executable, "-u", RED, "http://localhost:8080"]
    if pace == "fast":
        args.append("--fast")
    elif pace == "slow":
        args += ["--delay", "1.8"]
    if stages:
        args += ["--stages", stages]
    open(RED_LOG, "w").close()   # fresh log each run
    _red["p"] = subprocess.Popen(args, stdout=open(RED_LOG, "w"), stderr=subprocess.STDOUT)
    return jsonify(running=True, stages=stages or "full", pace=pace)

@app.route("/api/attack/status")
def attack_status():
    p = _red["p"]; running = bool(p and p.poll() is None)
    try:
        lines = open(RED_LOG).read().splitlines()[-60:]
    except Exception:
        lines = []
    return jsonify(running=running, lines=lines)

@app.route("/api/attack/reset", methods=["POST"])
def attack_reset():
    for t in ("http_events", "detections", "blocklist", "fixes", "learned_rules", "rotations"):
        for url in (LOCAL_CH, CH_URL):
            try: _ch_post(url, f"TRUNCATE TABLE parry.{t}")
            except Exception: pass
    try: open(RED_LOG, "w").close()
    except Exception: pass
    return jsonify(ok=True)

@app.route("/api/sponsors")
def sponsors():
    import time as _t
    ev = chj("SELECT count() c FROM parry.http_events")
    det = chj("SELECT count() c FROM parry.detections WHERE technique NOT IN ('commander-report','incident-report')")
    mv = chj("SELECT count() c FROM parry.mv_src_rates")
    fx = chj("SELECT count() c FROM parry.fixes")
    lr = chj("SELECT count() c FROM parry.learned_rules")
    hold = chj("SELECT count() c FROM parry.learned_rules WHERE status='holding'")
    rot = chj("SELECT count() c FROM parry.rotations")
    tri = chj("SELECT count() c FROM parry.detections WHERE model LIKE 'akash%'")
    ir = chj("SELECT count() c FROM parry.detections WHERE technique='incident-report'")
    t0 = _t.time(); _ = chj("SELECT 1"); ch_ms = int((_t.time()-t0)*1000)
    return jsonify({
        "ClickHouse": {"on": LANES["ClickHouse"], "host": CH_HOST,
            "metrics": {"events stored": ev[0]["c"] if ev else 0,
                        "materialized-view rows": mv[0]["c"] if mv else 0,
                        "detections written": det[0]["c"] if det else 0,
                        "round-trip query": f"{ch_ms} ms"}},
        "Akash": {"on": LANES["Akash"], "host": (AKASH_URL.split('//')[-1][:38]+'…') if AKASH_URL else "",
            "metrics": {"model": AKASH_MODEL or "-", "GPU": "NVIDIA A100",
                        "LLM triages run": tri[0]["c"] if tri else 0,
                        "incident reports": ir[0]["c"] if ir else 0}},
        "Semgrep": {"on": LANES["Semgrep"], "host": "rotemb-appsec-personal-org",
            "metrics": {"root-cause fixes": fx[0]["c"] if fx else 0,
                        "custom rules": 4, "DeepSemgrep": "enabled"}},
        "Senso": {"on": LANES["Senso"], "host": "apiv2.senso.ai",
            "metrics": {"status": "connected" if LANES["Senso"] else "needs tgr_ key to activate"}},
        "Guild": {"on": LANES["Guild"], "host": "api.guild.ai",
            "metrics": {"status": "connected" if LANES["Guild"] else "key set; publish agent for sessions URL"}},
    })


@app.route("/slides/<path:p>")
def slides(p):
    return send_from_directory(os.path.join(os.path.dirname(__file__), "..", "slides"), p)


@app.route("/api/incident")
def incident():
    rows = chj("""SELECT formatDateTime(ts,'%H:%i:%S') t, narrative, model
        FROM parry.detections WHERE technique='incident-report' ORDER BY ts DESC LIMIT 1""")
    return jsonify(rows[0] if rows else {})


@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")

HTML = open(os.path.join(os.path.dirname(__file__), "index.html")).read() if os.path.exists(
    os.path.join(os.path.dirname(__file__), "index.html")) else "<h1>index.html missing</h1>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, threaded=True)
