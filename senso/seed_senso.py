#!/usr/bin/env python3
"""Seed Senso with Parry's verified ground truth (run once after getting a key).

  SENSO_API_KEY=tgr_... python3 seed_senso.py
"""
import os
import pathlib
import sys

import requests

KEY = os.environ.get("SENSO_API_KEY")
if not KEY:
    sys.exit("set SENSO_API_KEY")
BASE = "https://apiv2.senso.ai/api/v1"
H = {"X-API-Key": KEY, "Content-Type": "application/json"}

here = pathlib.Path(__file__).parent / "ground-truth"
for f in sorted(here.glob("*.md")):
    r = requests.post(f"{BASE}/org/kb/raw", headers=H,
                      json={"title": f.stem, "text": f.read_text()}, timeout=30)
    print(f.stem, r.status_code, r.text[:120])

# sanity: retrieval round-trip
r = requests.post(f"{BASE}/org/search/context", headers=H,
                  json={"query": "response playbook for sqli-dump", "max_results": 2}, timeout=30)
print("retrieval check:", r.status_code, str(r.json())[:300])
