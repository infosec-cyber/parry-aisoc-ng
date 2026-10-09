-- Parry telemetry schema — ClickHouse
-- One row per HTTP flow captured at the proxy, plus app/auth events.

CREATE DATABASE IF NOT EXISTS parry;

CREATE TABLE IF NOT EXISTS parry.http_events
(
    ts              DateTime64(3) DEFAULT now64(3),
    flow_id         String,
    src_ip          String,
    method          LowCardinality(String),
    host            LowCardinality(String),
    path            String,
    query           String,
    status          UInt16,
    req_headers     Map(String, String),
    req_body        String CODEC(ZSTD(3)),
    resp_headers    Map(String, String),
    resp_body_snip  String CODEC(ZSTD(3)),   -- first 4KB only
    resp_bytes      UInt32,
    duration_ms     Float32,
    user_agent      String,
    session_id      String,                   -- cookie-derived
    auth_user       String                    -- app-reported identity, '' if anon
)
ENGINE = MergeTree
ORDER BY (ts, host, path);

CREATE TABLE IF NOT EXISTS parry.app_events
(
    ts        DateTime64(3) DEFAULT now64(3),
    source    LowCardinality(String),   -- app | authlog | syslog
    level     LowCardinality(String),
    event     String,                   -- login_fail, login_ok, sqlerror, ...
    user      String,
    detail    String
)
ENGINE = MergeTree
ORDER BY (ts, source, event);

-- Blue agent writes its conclusions here; dashboard reads both.
CREATE TABLE IF NOT EXISTS parry.detections
(
    ts            DateTime64(3) DEFAULT now64(3),
    detection_id  String,
    severity      LowCardinality(String),      -- info|low|medium|high|critical
    technique     String,                      -- e.g. T1190, sqli, idor, bruteforce
    title         String,
    narrative     String,                      -- blue agent's plain-language story
    evidence_ids  Array(String),               -- flow_ids backing the claim
    kill_chain    Array(String),               -- ordered steps
    latency_ms    UInt32,                      -- attack-seen -> detection written
    model         LowCardinality(String),      -- which LLM lane produced it
    grounded_by   Array(String)                -- senso context doc ids used
)
ENGINE = MergeTree
ORDER BY (ts, severity);

CREATE TABLE IF NOT EXISTS parry.fixes
(
    ts            DateTime64(3) DEFAULT now64(3),
    detection_id  String,
    semgrep_rule  String,
    file          String,
    line          UInt32,
    patch         String CODEC(ZSTD(3)),
    pr_url        String
)
ENGINE = MergeTree
ORDER BY ts;

-- Blue agent inserts here; the proxy polls it and enforces 403s.
CREATE TABLE IF NOT EXISTS parry.blocklist
(
    ts       DateTime64(3) DEFAULT now64(3),
    src_ip   String,
    reason   String,
    detection_id String
)
ENGINE = MergeTree
ORDER BY ts;

-- ===== Real-time analytics the blue agent + dashboard poll =====

-- Per-5s request rate / error rate / distinct-path fanout per source.
CREATE MATERIALIZED VIEW IF NOT EXISTS parry.mv_src_rates
ENGINE = AggregatingMergeTree ORDER BY (bucket, src_ip)
AS SELECT
    toStartOfInterval(ts, INTERVAL 5 second) AS bucket,
    src_ip,
    countState()                              AS reqs,
    countIfState(status >= 400)               AS errs,
    uniqState(path)                           AS paths,
    uniqState(user_agent)                     AS uas
FROM parry.http_events
GROUP BY bucket, src_ip;

-- Auth outcome stream for brute-force / credstuff detection.
CREATE MATERIALIZED VIEW IF NOT EXISTS parry.mv_auth
ENGINE = AggregatingMergeTree ORDER BY (bucket, src_ip)
AS SELECT
    toStartOfInterval(ts, INTERVAL 5 second) AS bucket,
    src_ip,
    countIfState(status = 401 OR status = 403) AS denies,
    uniqState(auth_user)                       AS users_tried
FROM parry.http_events
WHERE path LIKE '%login%' OR path LIKE '%auth%'
GROUP BY bucket, src_ip;
