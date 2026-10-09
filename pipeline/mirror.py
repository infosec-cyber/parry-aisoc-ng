#!/usr/bin/env python3
"""Host-side mirror: stream parry.http_events from LOCAL ClickHouse up to
ClickHouse CLOUD. The mitmproxy sink (in a container that cannot egress to the
cloud on :443) writes locally; this process keeps the cloud copy ~1s fresh so
the blue agent + dashboard run against ClickHouse Cloud.
"""
import base64, json, os, time, urllib.request
from urllib.parse import urlsplit, urlunsplit, quote

LOCAL = os.environ.get("LOCAL_CH_URL", "http://parry:parry-local@localhost:8123")
CLOUD = os.environ.get("CLOUD_CH_URL", "")

def parts(u):
    s = urlsplit(u); host = s.hostname + (f":{s.port}" if s.port else "")
    return urlunsplit((s.scheme, host, "", "", "")), (s.username or "default"), (s.password or "")

LB, LU, LP = parts(LOCAL)
CB, CU, CP = parts(CLOUD)

def q(base, user, pw, sql, data=None):
    url = base + "/?query=" + quote(sql)
    req = urllib.request.Request(url, data=(data.encode() if data else None),
        headers={"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()})
    return urllib.request.urlopen(req, timeout=30).read().decode()

COLS = ("ts,flow_id,src_ip,method,host,path,query,status,req_headers,req_body,"
        "resp_headers,resp_body_snip,resp_bytes,duration_ms,user_agent,session_id,auth_user")

def main():
    seen = set()
    # prime cursor from cloud max ts
    try:
        cur = q(CB, CU, CP, "SELECT max(ts) FROM parry.http_events").strip() or "1970-01-01 00:00:00"
    except Exception:
        cur = "1970-01-01 00:00:00"
    print(f"[mirror] local={LB} -> cloud={CB} cursor={cur}", flush=True)
    while True:
        try:
            sql = (f"SELECT {COLS} FROM parry.http_events WHERE ts >= toDateTime64('{cur}',3) "
                   f"ORDER BY ts FORMAT JSONEachRow")
            rows = [json.loads(l) for l in q(LB, LU, LP, sql).splitlines() if l]
            fresh = [r for r in rows if r["flow_id"] not in seen]
            if fresh:
                body = "\n".join(json.dumps(r) for r in fresh)
                q(CB, CU, CP, "INSERT INTO parry.http_events FORMAT JSONEachRow", body)
                for r in fresh:
                    seen.add(r["flow_id"]); cur = max(cur, r["ts"])
                print(f"[mirror] +{len(fresh)} -> cloud (cursor={cur})", flush=True)
                if len(seen) > 20000:
                    seen = set(list(seen)[-10000:])
        except Exception as e:
            print(f"[mirror] {e}", flush=True)
        time.sleep(1.0)

if __name__ == "__main__":
    main()
