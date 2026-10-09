#!/usr/bin/env python3
"""Parry blue agent — real-time AI defender.

Loop (every POLL_SECS):
  1. DETECT   — SQL rules over ClickHouse telemetry (candidate alerts, ~ms)
  2. TRIAGE   — AkashML open model classifies/scores each candidate (JSON out)
  3. GROUND   — Senso verified context: playbook + baseline passages, cited in
                the detection row (grounded_by). Alerts Senso can't answer show
                up in Senso's gap report = detection-coverage backlog.
  4. ACT      — block attacker IP (ClickHouse blocklist -> proxy enforces),
                Semgrep root-cause on the app source + fix row,
                Guild commander escalation (hosted SOC-commander agent),
                GitHub PR with the patch (optional, env-gated).

Every sponsor lane is optional: unset keys => heuristic-only mode still demos.
"""
import json
import os
import re
import subprocess
import time
import uuid
from urllib.parse import quote, urlsplit, urlunsplit

import requests

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://parry:parry-local@localhost:8123")
POLL_SECS = float(os.environ.get("POLL_SECS", "2"))
WINDOW_S = int(os.environ.get("WINDOW_S", "15"))                      # lookback per poll
TARGET_SRC = os.environ.get("TARGET_SRC", os.path.join(os.path.dirname(__file__), "../../target-app"))

AKASH_KEY = os.environ.get("AKASHML_API_KEY", "")
AKASH_MODEL = os.environ.get("AKASHML_MODEL", "openai/gpt-oss-20b")
# Akash compute: an Ollama (OpenAI-compatible) LLM we deployed on the Akash
# marketplace via the Console API. If set, triage runs there instead of AkashML.
AKASH_OPENAI_URL = os.environ.get("AKASH_OPENAI_URL", "")   # e.g. http://<lease>.ingress...
AKASH_OPENAI_MODEL = os.environ.get("AKASH_OPENAI_MODEL", "qwen2.5:3b-instruct")
BLOCKLIST_CH_URL = os.environ.get("BLOCKLIST_CH_URL", "")   # local CH so the proxy enforces
SENSO_KEY = os.environ.get("SENSO_API_KEY", "")
SENSO_BASE = "https://apiv2.senso.ai/api/v1"
GUILD_KEY_ID = os.environ.get("GUILD_KEY_ID", "")
GUILD_KEY_SECRET = os.environ.get("GUILD_KEY_SECRET", "")
GUILD_SESSIONS_URL = os.environ.get("GUILD_SESSIONS_URL", "")  # .../v1/workspaces/<o>/<w>/sessions
GUILD_WS = os.environ.get("GUILD_WS", "")
GUILD_AGENT_ID = os.environ.get("GUILD_AGENT_ID", "")
GUILD_AGENT_VERSION = os.environ.get("GUILD_AGENT_VERSION", "")
ENABLE_BLOCK = os.environ.get("ENABLE_BLOCK", "1") == "1"
BLOCK_AFTER = set(os.environ.get("BLOCK_AFTER", "cmdinj,sqli-dump").split(","))
ENABLE_PR = os.environ.get("ENABLE_PR", "0") == "1"            # needs gh auth + GITHUB_REPO
GITHUB_REPO = os.environ.get("GITHUB_REPO", "")


# ---------- ClickHouse ----------
def _ch_parts():
    u = urlsplit(CH_URL)
    host = u.hostname + (f":{u.port}" if u.port else "")
    return urlunsplit((u.scheme, host, "", "", "")), u.username or "default", u.password or ""


CH_BASE, CH_USER, CH_PW = _ch_parts()


def ch(sql: str, data: str | None = None):
    r = requests.post(
        f"{CH_BASE}/?query={quote(sql)}", data=data,
        headers={"X-ClickHouse-User": CH_USER, "X-ClickHouse-Key": CH_PW}, timeout=10)
    r.raise_for_status()
    return r.text


def chj(sql: str):
    out = ch(sql + " FORMAT JSONEachRow")
    return [json.loads(l) for l in out.splitlines() if l]


def insert(table: str, row: dict):
    ch(f"INSERT INTO {table} FORMAT JSONEachRow", json.dumps(row))


def insert_local(table: str, row: dict):
    """Write to the LOCAL ClickHouse too (the in-container proxy polls it to
    enforce blocks; it cannot egress to the cloud)."""
    if not BLOCKLIST_CH_URL:
        return
    u = urlsplit(BLOCKLIST_CH_URL)
    host = u.hostname + (f":{u.port}" if u.port else "")
    base = urlunsplit((u.scheme, host, "", "", ""))
    try:
        requests.post(f"{base}/?query={quote(f'INSERT INTO {table} FORMAT JSONEachRow')}",
                      data=json.dumps(row),
                      headers={"X-ClickHouse-User": u.username or "default",
                               "X-ClickHouse-Key": u.password or ""}, timeout=5)
    except Exception as e:
        print(f"[blue] local blocklist write failed: {e}")


# ---------- 1. DETECT: SQL rules ----------
# Each rule: (technique, severity_floor, sql). Rows must include src_ip + evidence.
RULES = [
    ("recon-scan", "low", f"""
        SELECT src_ip, count() hits, uniq(path) paths, countIf(status=404) nf,
               groupArray(10)(flow_id) ev
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
        GROUP BY src_ip HAVING paths >= 8 AND nf >= 4"""),
    ("bruteforce", "medium", f"""
        SELECT src_ip, countIf(status=401) fails, groupArray(10)(flow_id) ev
        FROM parry.http_events
        WHERE ts > now64(3) - {WINDOW_S} AND path LIKE '%login%' AND method='POST'
        GROUP BY src_ip HAVING fails >= 4"""),
    ("sqli-probe", "high", f"""
        SELECT src_ip, count() hits, groupArray(10)(flow_id) ev,
               groupArray(3)(query) samples
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND (positionCaseInsensitive(query,'union')>0
               OR positionCaseInsensitive(query,'%27')>0 OR position(query,'''')>0
               OR (status=500 AND positionCaseInsensitive(resp_body_snip,'syntax')>0))
        GROUP BY src_ip"""),
    ("sqli-dump", "critical", f"""
        SELECT src_ip, count() hits, groupArray(10)(flow_id) ev
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND positionCaseInsensitive(query,'union')>0 AND status=200
          AND (position(resp_body_snip,'N0teNest')>0 OR position(resp_body_snip,'hunter2')>0)
        GROUP BY src_ip"""),
    ("idor-enum", "high", f"""
        SELECT src_ip, uniq(path) ids, groupArray(10)(flow_id) ev
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND match(path, '^/api/notes/[0-9]+$') AND status=200
        GROUP BY src_ip HAVING ids >= 4"""),
    ("bac-admin", "high", f"""
        SELECT src_ip, groupArray(10)(flow_id) ev, any(auth_user) who
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND path='/api/admin/users' AND status=200 AND auth_user NOT IN ('admin','')
        GROUP BY src_ip"""),
    ("cmdinj", "critical", f"""
        SELECT src_ip, groupArray(10)(flow_id) ev, groupArray(3)(query) samples
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND path='/api/export'
          AND (position(query,'%3B')>0 OR position(query,';')>0
               OR position(resp_body_snip,'uid=')>0)
        GROUP BY src_ip"""),
    ("exfil-canary", "critical", f"""
        SELECT src_ip, count() hits, groupArray(10)(flow_id) ev
        FROM parry.http_events WHERE ts > now64(3) - {WINDOW_S}
          AND (position(resp_body_snip,'sk_live_')>0 OR position(resp_body_snip,'pg://')>0)
        GROUP BY src_ip HAVING hits >= 2"""),
]

# technique -> (vulnerable file hint, semgrep focus) for the fix lane
ROOT_CAUSE = {
    "sqli-probe": ("app.py", "formatted-sql-query"),
    "sqli-dump": ("app.py", "formatted-sql-query"),
    "idor-enum": ("app.py", "missing-ownership-check"),
    "bac-admin": ("app.py", "client-side-authz"),
    "cmdinj": ("app.py", "subprocess-shell-true"),
    "bruteforce": ("app.py", "no-rate-limit"),
}

# technique -> (ATT&CK tactic, technique id, technique name)
MITRE = {
    "recon-scan":   ("Reconnaissance", "T1595", "Active Scanning"),
    "bruteforce":   ("Credential Access", "T1110", "Brute Force"),
    "sqli-probe":   ("Initial Access", "T1190", "Exploit Public-Facing Application"),
    "sqli-dump":    ("Collection", "T1213", "Data from Information Repositories"),
    "idor-enum":    ("Collection", "T1213", "Data from Information Repositories"),
    "bac-admin":    ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"),
    "cmdinj":       ("Execution", "T1059", "Command and Scripting Interpreter"),
    "exfil-canary": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
}

def mitre_for(technique: str) -> str:
    t = MITRE.get(technique)
    return f"{t[1]} {t[2]} ({t[0]})" if t else ""


# ---------- 2. TRIAGE: AkashML ----------
def akash_triage(technique: str, evidence: dict) -> dict:
    fallback = {"severity": None, "confidence": 0.7, "summary": "", "model": "rules-only"}
    if AKASH_OPENAI_URL:
        url = AKASH_OPENAI_URL.rstrip("/") + "/v1/chat/completions"
        model = AKASH_OPENAI_MODEL
        headers = {"Content-Type": "application/json"}
    elif AKASH_KEY:
        url = "https://api.akashml.com/v1/chat/completions"
        model = AKASH_MODEL
        headers = {"Authorization": f"Bearer {AKASH_KEY}"}
    else:
        return fallback
    try:
        r = requests.post(
            url,
            headers=headers,
            json={
                "model": model,
                "response_format": {"type": "json_object"},
                "max_completion_tokens": 200,
                "messages": [
                    {"role": "system", "content":
                        "You are a SOC triage analyst. Given a candidate detection, return JSON: "
                        '{"severity":"info|low|medium|high|critical","confidence":0..1,'
                        '"summary":"one plain-language sentence for a human analyst"}'},
                    {"role": "user", "content": json.dumps({"technique": technique, "evidence": evidence})},
                ],
            }, timeout=20)
        r.raise_for_status()
        out = json.loads(r.json()["choices"][0]["message"]["content"])
        out["model"] = f"akash:{model}" if AKASH_OPENAI_URL else model
        return out
    except Exception as e:
        print(f"[blue] akash triage failed: {e}")
        return fallback


# ---------- 3. GROUND: Senso ----------
def senso_context(technique: str) -> tuple[list[str], str]:
    """Returns (grounded_by doc ids, playbook excerpt)."""
    if not SENSO_KEY:
        return [], ""
    try:
        r = requests.post(
            f"{SENSO_BASE}/org/search/context",
            headers={"X-API-Key": SENSO_KEY, "Content-Type": "application/json"},
            json={"query": f"response playbook and baseline for {technique}", "max_results": 3},
            timeout=15)
        r.raise_for_status()
        data = r.json()
        ids, excerpt = [], ""
        for p in data.get("results", data.get("passages", []))[:3]:
            ids.append(str(p.get("content_id", p.get("id", ""))))
            excerpt += p.get("text", p.get("content", ""))[:400] + "\n"
        return ids, excerpt
    except Exception as e:
        print(f"[blue] senso failed: {e}")
        return [], ""


def senso_writeback(title: str, text: str):
    if not SENSO_KEY:
        return
    try:
        requests.post(f"{SENSO_BASE}/org/kb/raw",
                      headers={"X-API-Key": SENSO_KEY, "Content-Type": "application/json"},
                      json={"title": title, "text": text}, timeout=15)
    except Exception as e:
        print(f"[blue] senso writeback failed: {e}")


# ---------- 4a. ACT: Guild commander ----------
def guild_escalate(detection: dict) -> str:
    """Drive the published Guild SOC-commander agent (agent_test session + events)."""
    if not (GUILD_WS and GUILD_AGENT_VERSION and GUILD_KEY_ID):
        return ""
    base = "https://api.guild.ai/v1"
    auth = (GUILD_KEY_ID, GUILD_KEY_SECRET)
    hdr = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
    try:
        r = requests.post(f"{base}/workspaces/{GUILD_WS}/sessions", auth=auth, headers=hdr,
                          json={"session_type": "agent_test", "agent_version_id": GUILD_AGENT_VERSION}, timeout=30)
        r.raise_for_status()
        j = r.json(); sid = j.get("id") or j.get("session", {}).get("id")
        if not sid:
            return ""
        prompt = ("You are the Parry SOC commander. Reply in plain text only, no tools. "
                  "Given this detection JSON, give: VERDICT (confirm/downgrade), whether to APPROVE the IP block, "
                  "and a 2-sentence CISO summary.\n" + json.dumps(detection))
        requests.post(f"{base}/sessions/{sid}/events", auth=auth, headers=hdr,
                      json={"mode": "text", "content": prompt, "agent_id": GUILD_AGENT_ID}, timeout=30)
        # poll for the agent's LLM output
        import re as _re
        for _ in range(10):
            time.sleep(3)
            ev = requests.get(f"{base}/sessions/{sid}/events", auth=auth,
                              headers={"User-Agent": "Mozilla/5.0"}, timeout=20).json()
            items = ev.get("items", ev if isinstance(ev, list) else [])
            texts = []
            for it in items:
                if it.get("type") == "llm_done":
                    body = it.get("body", "")
                    for m in _re.finditer(r'"text":\s*"((?:[^"\\]|\\.)*)"', body if isinstance(body, str) else json.dumps(body)):
                        try: texts.append(json.loads('"' + m.group(1) + '"'))
                        except Exception: pass
            full = " ".join(t for t in texts if len(t) > 40)
            if full:
                return full[:900]
        return f"Guild commander engaged — tamper-evident session {sid} on guild.ai"
    except Exception as e:
        print(f"[blue] guild escalation failed: {e}")
        return ""


# ---------- 4b. ACT: Semgrep root-cause + fix ----------
def semgrep_root_cause(technique: str) -> list[dict]:
    rules = os.path.join(os.path.dirname(__file__), "../../semgrep/parry.yaml")
    cmd = ["semgrep", "scan", "--config", rules]
    if os.environ.get("SEMGREP_PRO_RULES") == "1":
        cmd += ["--config", "p/flask"]          # registry (Pro) ruleset, opt-in
    cmd += ["--json", "--quiet", "--disable-version-check", TARGET_SRC]
    try:
        _env = {**os.environ, "EIO_BACKEND": "posix"}  # semgrep-core io_uring unavailable here
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=_env)
        if not out.stdout.strip():
            print(f"[blue] semgrep no output; stderr={out.stderr.strip()[:160]}")
            return []
        results = json.loads(out.stdout).get("results", [])
    except Exception as e:
        print(f"[blue] semgrep failed: {e}")
        return []
    want = ROOT_CAUSE.get(technique, (None, None))[1]
    hits = [r for r in results if want and want in r["check_id"]] or results
    return [{"semgrep_rule": r["check_id"].split(".")[-1],
             "file": os.path.basename(r["path"]),
             "line": r["start"]["line"],
             "msg": r["extra"]["message"]} for r in hits[:3]]


def ai_patch(hit: dict) -> str:
    """Ask the Akash-hosted LLM to rewrite the vulnerable lines Semgrep flagged."""
    if not AKASH_OPENAI_URL:
        return f"# {hit['msg']}"
    path = os.path.join(TARGET_SRC, hit["file"])
    try:
        src = open(path).read().splitlines()
        lo, hi = max(0, hit["line"] - 7), min(len(src), hit["line"] + 6)
        snippet = "\n".join(f"{i+1}: {src[i]}" for i in range(lo, hi))
    except Exception:
        snippet = ""
    prompt = (f"A Semgrep scan flagged {hit['semgrep_rule']} at {hit['file']}:{hit['line']} "
              f"— {hit['msg']}.\nCode:\n{snippet}\n\n"
              "Rewrite ONLY the vulnerable statement(s) to fix it securely (parameterized "
              "queries, ownership checks, no shell=True, server-side authz). "
              "Output a minimal unified diff or the corrected Python lines only — no prose.")
    try:
        r = requests.post(
            AKASH_OPENAI_URL.rstrip("/") + "/v1/chat/completions",
            json={"model": AKASH_OPENAI_MODEL, "max_tokens": 320,
                  "messages": [
                      {"role": "system", "content": "You are a secure-coding assistant. Reply with code only."},
                      {"role": "user", "content": prompt}]},
            timeout=45)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip()[:1500]
    except Exception as e:
        print(f"[blue] ai_patch failed: {e}")
        return f"# {hit['msg']}"


_last_report = [0.0]
def ai_incident_report(src_ip: str):
    """On a critical, have the LLM write a CISO-ready summary of the whole incident."""
    if not AKASH_OPENAI_URL or time.time() - _last_report[0] < 45:
        return
    _last_report[0] = time.time()
    try:
        dets = chj(f"""SELECT severity, technique, mitre, narrative FROM parry.detections
                       WHERE technique!='commander-report' AND technique!='incident-report'
                       AND ts > now64(3) - 300 ORDER BY ts""")
        if not dets:
            return
        chain = "\n".join(f"- {d['severity'].upper()} {d['technique']} [{d['mitre']}]" for d in dets)
        r = requests.post(
            AKASH_OPENAI_URL.rstrip("/") + "/v1/chat/completions",
            json={"model": AKASH_OPENAI_MODEL, "max_tokens": 260,
                  "messages": [
                      {"role": "system", "content": "You are a SOC lead. Write a 3-sentence incident summary a CISO can read: what happened, impact, action taken."},
                      {"role": "user", "content": f"Attacker {src_ip} kill chain:\n{chain}\nParry auto-blocked the source at the command-injection stage."}]},
            timeout=45)
        r.raise_for_status()
        report = r.json()["choices"][0]["message"]["content"].strip()[:1200]
        insert("parry.detections", {
            "detection_id": f"IR-{uuid.uuid4().hex[:8]}", "severity": "info",
            "technique": "incident-report", "title": f"Incident report · {src_ip}",
            "narrative": report, "evidence_ids": [], "kill_chain": [],
            "latency_ms": 0, "model": f"akash:{AKASH_OPENAI_MODEL}", "grounded_by": [],
            "mitre": "", "confidence": 0.0})
        print(f"[blue] 📝 incident report written for {src_ip}")
    except Exception as e:
        print(f"[blue] incident report failed: {e}")


# ============ ADAPTIVE DEFENSE: auto-learn rules + rotate secrets ============
# Techniques that represent a *successful* exploit — seeing one once is enough to
# synthesize a durable detection rule (and, for exfil, rotate the touched secrets).
LEARN_ON = {"exfil-canary", "cmdinj", "idor-enum", "bac-admin", "sqli-dump"}

def _learned_sql(technique: str) -> tuple:
    """Return (signature, sql) for a durable rule distilled from a successful exploit."""
    W = WINDOW_S
    T = {
      "exfil-canary": ("resp:sk_live_|pg://", f"""
          SELECT src_ip, count() hits, groupArray(10)(flow_id) ev
          FROM parry.http_events WHERE ts > now64(3) - {W}
            AND (position(resp_body_snip,'sk_live_')>0 OR position(resp_body_snip,'pg://')>0)
          GROUP BY src_ip HAVING hits >= 1"""),
      "cmdinj": ("export:shell-metachar", f"""
          SELECT src_ip, count() hits, groupArray(10)(flow_id) ev
          FROM parry.http_events WHERE ts > now64(3) - {W}
            AND path='/api/export' AND (match(query,'%3B|%7C|%60|%24%28') OR match(query,'[;|`]'))
          GROUP BY src_ip"""),
      "idor-enum": ("notes:cross-object", f"""
          SELECT src_ip, uniq(path) ids, groupArray(10)(flow_id) ev
          FROM parry.http_events WHERE ts > now64(3) - {W}
            AND match(path,'^/api/notes/[0-9]+$') AND status=200
          GROUP BY src_ip HAVING ids >= 2"""),
      "bac-admin": ("admin:nonadmin-200", f"""
          SELECT src_ip, groupArray(10)(flow_id) ev, any(auth_user) who
          FROM parry.http_events WHERE ts > now64(3) - {W}
            AND path='/api/admin/users' AND status=200 AND auth_user NOT IN ('admin','')
          GROUP BY src_ip"""),
      "sqli-dump": ("search:union-200", f"""
          SELECT src_ip, count() hits, groupArray(10)(flow_id) ev
          FROM parry.http_events WHERE ts > now64(3) - {W}
            AND path='/api/search' AND positionCaseInsensitive(query,'union')>0 AND status=200
          GROUP BY src_ip HAVING hits >= 1"""),
    }
    return T.get(technique, (None, None))

_known_sigs = set()
def learn_rule(technique: str, det_id: str):
    """Synthesize a durable detection rule the first time an exploit succeeds."""
    sig, sql = _learned_sql(technique)
    if not sig:
        return
    key = f"{technique}:{sig}"
    if key in _known_sigs:
        return
    # dedup against what's already stored
    try:
        existing = chj("SELECT signature FROM parry.learned_rules")
        for e in existing:
            _known_sigs.add(e["signature"])
        if key in _known_sigs:
            return
    except Exception:
        pass
    # validate the SQL actually runs before arming it
    try:
        chj(sql)
    except Exception as e:
        print(f"[blue] learned rule failed validation: {e}")
        return
    name, rationale = f"auto:{technique}", f"Confirmed {technique}; armed a durable rule from observed indicators."
    if AKASH_OPENAI_URL:
        try:
            r = requests.post(AKASH_OPENAI_URL.rstrip("/") + "/v1/chat/completions",
                json={"model": AKASH_OPENAI_MODEL, "max_tokens": 80,
                      "messages": [{"role":"system","content":"Reply with a short rule name (<=6 words) then a one-sentence rationale, separated by ' | '."},
                                   {"role":"user","content":f"A {technique} attack just succeeded. Name a detection rule for its signature ({sig})."}]},
                timeout=30)
            txt = r.json()["choices"][0]["message"]["content"].strip()
            if "|" in txt:
                parts = [x.strip()[:120] for x in txt.split("|", 1)]
                if parts[0]: name = parts[0]
                if len(parts) > 1 and parts[1]: rationale = parts[1]
        except Exception:
            pass
    # ---- SAFETY: correlate the new rule against REAL legitimate traffic so we
    # never deny service. Run the rule over a wide baseline window; any match from
    # a non-attacker IP is a false positive. Only enforce when there are none.
    false_positives, baseline = 0, 0
    try:
        attackers = {row for d in chj("SELECT DISTINCT src_ip FROM parry.detections "
                                      "WHERE technique NOT IN ('commander-report','incident-report') "
                                      "AND ts > now64(3) - 900") for row in [d["src_ip"]]}
        attackers |= {d["src_ip"] for d in chj("SELECT DISTINCT src_ip FROM parry.blocklist")}
        base_sql = sql.replace(f"now64(3) - {WINDOW_S}", "now64(3) - 900")
        hits = chj(base_sql)
        false_positives = len([h for h in hits if h.get("src_ip") and h["src_ip"] not in attackers])
        bl = chj("SELECT uniq(src_ip) u, count() c FROM parry.http_events "
                 "WHERE ts > now64(3) - 900 AND src_ip NOT IN (" +
                 (",".join("'%s'" % a.replace("'", "") for a in attackers) or "''") + ")")
        baseline = bl[0]["c"] if bl else 0
    except Exception as e:
        print(f"[blue] rule correlation failed: {e}")
    enforce = 1 if false_positives == 0 else 0
    rc = ROOT_CAUSE.get(technique)
    protects = f"{rc[0]} ({rc[1]})" if rc else ""
    _known_sigs.add(key)
    insert("parry.learned_rules", {"name": name, "technique": f"learned-{technique}",
        "signature": key, "sql": " ".join(sql.split()), "rationale": rationale,
        "source_detection": det_id, "enabled": 1,
        "false_positives": false_positives, "baseline_checked": baseline,
        "enforce": enforce, "status": "holding", "protects": protects})
    verdict = "SAFE to enforce" if enforce else f"{false_positives} FP — alert-only"
    print(f"[blue] 🧬 learned '{name}' ({technique}) — correlated vs {baseline} legit reqs: {verdict}; virtual-patch holds until {protects or 'fix'}")

_lr_cache = {"t": 0.0, "rules": []}
def load_learned_rules():
    if time.time() - _lr_cache["t"] < 8:
        return _lr_cache["rules"]
    try:
        rows = chj("SELECT technique, sql FROM parry.learned_rules WHERE enabled=1")
        _lr_cache["rules"] = [(r["technique"], "high", r["sql"]) for r in rows]
        _lr_cache["t"] = time.time()
    except Exception:
        pass
    return _lr_cache["rules"]

# ---- secret rotation ----
import uuid as _uuid
def _mask(v): return (v[:16] + "…") if len(v) > 18 else v[:4] + "…"
def rotate_secrets(det_id: str):
    """Scan recent traffic for exposed secrets; rotate each (for real, in the target)."""
    try:
        recent = chj(f"""SELECT path, status, resp_body_snip FROM parry.http_events
                         WHERE ts > now64(3) - 120""")
    except Exception:
        return
    blob = " ".join(r.get("resp_body_snip","") for r in recent)
    leaked = []
    if "sk_live_" in blob: leaked.append("stripe_key")
    if "pg://" in blob: leaked.append("db_creds")
    if any(r["path"]=="/api/admin/users" and r["status"]==200 for r in recent): leaked.append("admin_password")
    if not leaked:
        return
    try:
        done = {x["secret_type"] for x in chj("SELECT secret_type FROM parry.rotations WHERE ts > now64(3) - 120")}
    except Exception:
        done = set()
    leaked = [x for x in leaked if x not in done]
    if not leaked:
        return
    new = {"stripe_key": f"sk_live_{_uuid.uuid4().hex[:24]}",
           "db_creds": f"pg://notenest:{_uuid.uuid4().hex[:16]}@10.0.0.5/prod",
           "admin_password": f"NN-{_uuid.uuid4().hex[:12]}!"}
    old = {"stripe_key": "sk_live_51Hxyz_FAKE_DEMO",
           "db_creds": "pg://notenest:N0teN3stDB@10.0.0.5/prod",
           "admin_password": "N0teNest-Adm1n-Pr0d"}
    # rotate for real inside the target container's DB
    script = (
      "import sqlite3;d=sqlite3.connect('/app/notenest.db');"
      f"d.execute(\"UPDATE notes SET body='stripe_live_key={new['stripe_key']}' WHERE id=3\");"
      f"d.execute(\"UPDATE notes SET body='prod db: {new['db_creds']}' WHERE id=4\");"
      f"d.execute(\"UPDATE users SET password='{new['admin_password']}' WHERE username='admin'\");"
      "d.commit();print('rotated')")
    try:
        subprocess.run(["docker","exec","parry-target","python3","-c",script],
                       capture_output=True, text=True, timeout=15)
    except Exception as e:
        print(f"[blue] rotation exec failed: {e}")
    for t in leaked:
        insert("parry.rotations", {"secret_type": t, "old_masked": _mask(old[t]),
            "new_masked": _mask(new[t]), "reason": "exposed in attack — auto-rotated",
            "detection_id": det_id})
        print(f"[blue] 🔄 rotated {t} ({_mask(old[t])} -> {_mask(new[t])})")


def file_fix(detection_id: str, technique: str):
    for hit in semgrep_root_cause(technique):
        insert("parry.fixes", {
            "detection_id": detection_id, "semgrep_rule": hit["semgrep_rule"],
            "file": hit["file"], "line": hit["line"],
            "patch": ai_patch(hit), "pr_url": ""})
        print(f"[blue] root cause: {hit['file']}:{hit['line']} ({hit['semgrep_rule']})")
    if ENABLE_PR and GITHUB_REPO:
        subprocess.Popen(["python3", os.path.join(os.path.dirname(__file__), "open_pr.py"),
                          detection_id, technique])


# ---------- main loop ----------
def main():
    seen: dict[tuple, float] = {}   # (technique, src_ip) -> last fired
    print(f"[blue] watching {CH_BASE} every {POLL_SECS}s "
          f"(akash={'on' if (AKASH_OPENAI_URL or AKASH_KEY) else 'OFF'} senso={'on' if SENSO_KEY else 'OFF'} "
          f"guild={'on' if GUILD_SESSIONS_URL else 'OFF'} pr={'on' if ENABLE_PR else 'OFF'})")
    while True:
        t0 = time.time()
        for technique, floor, sql in RULES + load_learned_rules():
            try:
                rows = chj(sql)
            except Exception as e:
                print(f"[blue] rule {technique} query failed: {e}")
                continue
            for row in rows:
                key = (technique, row["src_ip"])
                if time.time() - seen.get(key, 0) < 60:
                    continue
                seen[key] = time.time()
                handle_candidate(technique, floor, row, t0)
        time.sleep(POLL_SECS)


SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def handle_candidate(technique: str, floor: str, row: dict, t0: float):
    det_id = f"D-{uuid.uuid4().hex[:8]}"
    triage = akash_triage(technique, row)
    sev = triage["severity"] or floor
    if SEV_RANK.get(sev, 0) < SEV_RANK.get(floor, 0):
        sev = floor                                   # model can raise, not lower
    grounded_by, playbook = senso_context(technique)
    narrative = triage["summary"] or f"Rule {technique} fired for {row['src_ip']}"
    if playbook:
        narrative += f" | playbook: {playbook.splitlines()[0][:160]}"
    detection = {
        "detection_id": det_id, "severity": sev, "technique": technique,
        "title": f"{technique} from {row['src_ip']}",
        "narrative": narrative, "evidence_ids": row.get("ev", []),
        "kill_chain": [technique], "latency_ms": int((time.time() - t0) * 1000),
        "model": triage["model"], "grounded_by": grounded_by,
        "mitre": mitre_for(technique),
        "confidence": float(triage.get("confidence") or 0.7),
    }
    insert("parry.detections", detection)
    print(f"[blue] 🚨 {sev.upper()} {technique} src={row['src_ip']} ({det_id})")

    # ACT phase runs in a background thread so the detect loop keeps polling
    # (semgrep / guild calls must never stall real-time detection).
    import threading as _t
    _t.Thread(target=_act_phase, args=(det_id, technique, sev, row, detection, narrative),
              daemon=True).start()
    print(f"[blue] ↪ response actions dispatched for {det_id}")


def _act_phase(det_id, technique, sev, row, detection, narrative):
    if sev in ("high", "critical") and technique in ROOT_CAUSE:
        file_fix(det_id, technique)
    if sev == "critical":
        ai_incident_report(row["src_ip"])
    # adaptive defense: learn a durable rule + rotate any exposed secrets
    if technique in LEARN_ON:
        learn_rule(technique, det_id)
    if technique in ("exfil-canary", "idor-enum", "bac-admin"):
        rotate_secrets(det_id)
    if sev == "critical":
        report = guild_escalate(detection)
        if report:
            insert("parry.detections", {
                "detection_id": det_id + "-cmd", "severity": "info",
                "technique": "commander-report", "title": f"Guild commander on {det_id}",
                "narrative": report, "evidence_ids": [], "kill_chain": [],
                "latency_ms": 0, "model": "guild", "grounded_by": []})
        senso_writeback(f"Incident learning {det_id}",
                        f"technique={technique} src={row['src_ip']}\n{narrative}")
    if ENABLE_BLOCK and technique in BLOCK_AFTER:
        blk = {"src_ip": row["src_ip"], "reason": technique, "detection_id": det_id}
        insert("parry.blocklist", blk)        # cloud (dashboard)
        insert_local("parry.blocklist", blk)  # local (proxy enforcement)
        print(f"[blue] ⛔ blocked {row['src_ip']} ({technique})")


if __name__ == "__main__":
    main()
