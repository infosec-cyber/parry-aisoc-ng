"""mitmproxy addon: stream every HTTP flow into ClickHouse (parry.http_events).

Runs inside the mitmproxy container (see docker-compose). Batches rows and
flushes every FLUSH_SECS or BATCH_MAX rows, whichever first — keeps insert
latency low enough that the blue agent sees attacks within ~1-2s.
"""
import json
import os
import threading
import time
import urllib.parse
import urllib.request

from mitmproxy import http

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://parry:parry-local@localhost:8123")
FLUSH_SECS = 1.0
BATCH_MAX = 200
SNIP = 4096


def _split_auth(url: str):
    # http://user:pass@host:port -> (http://host:port, user, pass)
    from urllib.parse import urlsplit, urlunsplit
    u = urlsplit(url)
    host = u.hostname + (f":{u.port}" if u.port else "")
    return urlunsplit((u.scheme, host, u.path, u.query, u.fragment)), u.username, u.password


class ClickHouseSink:
    def __init__(self):
        self.buf = []
        self.lock = threading.Lock()
        self.base, self.user, self.pw = _split_auth(CH_URL)
        self.blocked = set()
        t = threading.Thread(target=self._flusher, daemon=True)
        t.start()

    def _flusher(self):
        while True:
            time.sleep(FLUSH_SECS)
            self.flush()
            self._refresh_blocklist()

    def _query(self, sql: str) -> str:
        req = urllib.request.Request(
            f"{self.base}/?query=" + urllib.parse.quote(sql),
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.pw},
        )
        return urllib.request.urlopen(req, timeout=5).read().decode()

    def _refresh_blocklist(self):
        try:
            out = self._query("SELECT DISTINCT src_ip FROM parry.blocklist")
            self.blocked = {l for l in out.splitlines() if l}
        except Exception:
            pass

    @staticmethod
    def _client_ip(flow):
        xff = flow.request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return flow.client_conn.peername[0] if flow.client_conn.peername else ""

    def request(self, flow: http.HTTPFlow):
        ip = self._client_ip(flow)
        if ip in self.blocked:
            flow.response = http.Response.make(
                403, b'{"error":"blocked by parry"}', {"Content-Type": "application/json"}
            )

    def flush(self):
        with self.lock:
            rows, self.buf = self.buf, []
        if not rows:
            return
        body = "\n".join(json.dumps(r) for r in rows).encode()
        req = urllib.request.Request(
            f"{self.base}/?query=INSERT%20INTO%20parry.http_events%20FORMAT%20JSONEachRow",
            data=body, method="POST",
            headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": self.pw},
        )
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:  # never break the proxy path
            print(f"[ch_sink] insert failed ({len(rows)} rows): {e}")

    def response(self, flow: http.HTTPFlow):
        req, resp = flow.request, flow.response
        row = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                  + f".{int((time.time() % 1) * 1000):03d}",
            "flow_id": flow.id,
            "src_ip": self._client_ip(flow),
            "method": req.method,
            "host": req.host,
            "path": req.path.split("?", 1)[0],
            "query": req.path.split("?", 1)[1] if "?" in req.path else "",
            "status": resp.status_code,
            "req_headers": dict(req.headers),
            "req_body": req.get_text(strict=False)[:SNIP] if req.content else "",
            "resp_headers": dict(resp.headers),
            "resp_body_snip": resp.get_text(strict=False)[:SNIP] if resp.content else "",
            "resp_bytes": len(resp.content or b""),
            "duration_ms": (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
                           if flow.response.timestamp_end else 0.0,
            "user_agent": req.headers.get("user-agent", ""),
            "session_id": req.cookies.get("session", ""),
            "auth_user": resp.headers.get("x-auth-user", ""),  # target app echoes identity
        }
        with self.lock:
            self.buf.append(row)
            if len(self.buf) >= BATCH_MAX:
                rows, self.buf = self.buf, []
                threading.Thread(target=self._send, args=(rows,), daemon=True).start()

    def _send(self, rows):
        with self.lock:
            self.buf = rows + self.buf
        self.flush()


addons = [ClickHouseSink()]
