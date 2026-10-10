import time, glob, os
from playwright.sync_api import sync_playwright
URL="http://localhost:8050/"
def cap(pg, text):
    pg.evaluate("""(t)=>{let c=document.getElementById('__cap');if(!c){c=document.createElement('div');c.id='__cap';
      c.style.cssText='position:fixed;left:50%;bottom:28px;transform:translateX(-50%);z-index:99999;'+
      'background:rgba(10,14,20,.92);border:1px solid #2a4a86;color:#e6edf3;font:600 20px -apple-system,Segoe UI,sans-serif;'+
      'padding:12px 22px;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.6);max-width:80%;text-align:center';
      document.body.appendChild(c);} c.textContent=t;}""", text)
def scroll_to(pg, y, steps=14, dt=0.12):
    for i in range(1,steps+1):
        pg.evaluate(f"window.scrollTo(0,{int(y*i/steps)})"); time.sleep(dt)
with sync_playwright() as p:
    b=p.chromium.launch(args=["--no-sandbox"])
    ctx=b.new_context(viewport={"width":1600,"height":900},
                      record_video_dir="/tmp/screencast-out", record_video_size={"width":1600,"height":900})
    pg=ctx.new_page()
    pg.goto(URL, wait_until="domcontentloaded"); time.sleep(3)
    cap(pg,"Parry — an AI AppSec SOC. Autonomous detection & response."); time.sleep(3)

    # --- Battle: launch a live attack ---
    pg.click('.tab[data-p="attack"]'); time.sleep(2)
    cap(pg,"Battle view: attacker · ClickHouse telemetry · blue team — side by side"); time.sleep(3)
    cap(pg,"Launching the full 8-stage kill chain from the dashboard…")
    try: pg.click('#pace div[data-v="fast"]')
    except Exception: pass
    time.sleep(1)
    try: pg.click('#atk')
    except Exception: pass
    time.sleep(3)
    cap(pg,"Left: the attacker's kill chain, streaming live"); time.sleep(12)
    cap(pg,"Middle: every request parsed into ClickHouse in real time"); time.sleep(12)
    cap(pg,"Right: blue team detects, maps to MITRE ATT&CK, triages & responds"); time.sleep(14)
    cap(pg,"Command injection → attacker auto-blocked; secrets rotated; rules learned"); time.sleep(16)

    # --- Live SOC: results ---
    pg.click('.tab[data-p="live"]'); time.sleep(2); pg.evaluate("window.scrollTo(0,0)")
    cap(pg,"Live SOC: detections, AI triage, and autonomous response"); time.sleep(5)
    scroll_to(pg, 500); cap(pg,"AI incident report, written by an LLM on Akash GPUs"); time.sleep(5)
    scroll_to(pg, 1050); cap(pg,"Adaptive defense: auto-learned rules + real secret rotation"); time.sleep(6)
    scroll_to(pg, 1550); cap(pg,"Each new rule correlated vs real traffic — 0 false positives to enforce"); time.sleep(7)
    scroll_to(pg, 2100); cap(pg,"Semgrep root-cause + an AI-written patch for every bug"); time.sleep(6)

    # --- Sponsors proof ---
    pg.click('.tab[data-p="sponsors"]'); time.sleep(2); pg.evaluate("window.scrollTo(0,0)")
    cap(pg,"Sponsors: why each fits, how we use it — with live proof data"); time.sleep(5)
    scroll_to(pg, 900); cap(pg,"ClickHouse query stats · Akash GPU · Semgrep rules"); time.sleep(6)
    scroll_to(pg, 1700); cap(pg,"Senso: the exact grounded playbook passages, with scores"); time.sleep(6)

    # --- How it works ---
    pg.click('.tab[data-p="pipeline"]'); time.sleep(2); pg.evaluate("window.scrollTo(0,0)")
    cap(pg,"How it works: parse → store at scale → detect → triage → respond → learn"); time.sleep(8)

    pg.click('.tab[data-p="live"]'); time.sleep(2); pg.evaluate("window.scrollTo(0,0)")
    cap(pg,"Parry — it sees the attack, stops it, fixes it, and shows you why."); time.sleep(5)

    ctx.close(); b.close()
vid=sorted(glob.glob("/tmp/screencast-out/*.webm"), key=os.path.getmtime)[-1]
print("RAW", vid, os.path.getsize(vid))
