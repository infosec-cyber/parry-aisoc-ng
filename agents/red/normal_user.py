#!/usr/bin/env python3
"""Benign traffic generator — legitimate users of NoteNest. Gives Parry a REAL
baseline so auto-generated rules can be correlated against normal traffic and
never deny service. Each user gets a distinct source IP via X-Forwarded-For.
Usage: normal_user.py [http://localhost:8080] [--rate 1.5]
"""
import random, sys, time, requests
BASE = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("--") else "http://localhost:8080"
RATE = 1.5
for i,a in enumerate(sys.argv):
    if a == "--rate" and i+1 < len(sys.argv): RATE = float(sys.argv[i+1])
USERS = [("alice","alice2026!",1),("bob","hunter2",2),("carol","Carol#1pass",3)]
LEGIT_SEARCHES = ["milk","notes","demo","standup","todo","meeting"]
def ip(): return f"10.0.{random.randint(1,4)}.{random.randint(2,250)}"
def one():
    u,pw,uid = random.choice(USERS)
    s = requests.Session(); s.headers["X-Forwarded-For"] = ip()
    s.headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1"
    try:
        s.get(BASE+"/", timeout=8); s.get(BASE+"/api/health", timeout=8)
        s.post(BASE+"/login", data={"username":u,"password":pw}, timeout=8)
        s.get(BASE+"/api/search", params={"q":random.choice(LEGIT_SEARCHES)}, timeout=8)
        s.get(f"{BASE}/api/notes/{uid}", timeout=8)          # own note only
        s.get(BASE+"/api/export", params={"fmt":"txt"}, timeout=8)  # clean export
    except requests.RequestException:
        pass
if __name__ == "__main__":
    print(f"[normal] generating legit traffic against {BASE}", flush=True)
    while True:
        one(); time.sleep(random.uniform(RATE*0.6, RATE*1.6))
