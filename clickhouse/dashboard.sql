-- ============================================================================
-- Parry — ClickHouse Cloud native dashboard tiles
-- ----------------------------------------------------------------------------
-- Paste each query into the ClickHouse Cloud SQL console (console.clickhouse.cloud
-- -> SQL console), run it, click "Add to dashboard", and pick the chart type noted.
-- Every tile reads the same live tables the blue agent writes to, so the
-- ClickHouse-native dashboard and Parry's own dashboard stay in lock-step.
-- ============================================================================

-- TILE 1 — Live request rate & error rate  [chart: line / area, x=bucket]
-- Reads the AggregatingMergeTree materialized view (pre-aggregated at ingest).
SELECT bucket,
       countMerge(reqs)           AS requests,
       countMerge(errs)           AS errors,
       uniqMerge(paths)           AS distinct_paths
FROM parry.mv_src_rates
WHERE bucket > now() - INTERVAL 10 MINUTE
GROUP BY bucket
ORDER BY bucket;

-- TILE 2 — Detections by severity  [chart: bar, x=severity]
SELECT severity, count() AS detections
FROM parry.detections
WHERE technique != 'commander-report'
GROUP BY severity
ORDER BY multiIf(severity='critical',4,severity='high',3,severity='medium',2,severity='low',1,0) DESC;

-- TILE 3 — Detection latency p50/p95 (attack-seen -> written)  [chart: stat/number]
SELECT round(quantile(0.50)(latency_ms)) AS p50_ms,
       round(quantile(0.95)(latency_ms)) AS p95_ms,
       round(avg(latency_ms))            AS avg_ms
FROM parry.detections
WHERE technique != 'commander-report';

-- TILE 4 — Attack kill-chain coverage  [chart: bar / table]
SELECT technique, count() AS times_fired, max(ts) AS last_seen
FROM parry.detections
WHERE technique != 'commander-report'
GROUP BY technique
ORDER BY last_seen DESC;

-- TILE 5 — Top attacker IPs  [chart: table]
SELECT src_ip,
       count()                                  AS requests,
       countIf(status >= 400)                   AS errors,
       uniq(path)                               AS paths_touched,
       any(user_agent)                          AS ua
FROM parry.http_events
GROUP BY src_ip
ORDER BY requests DESC
LIMIT 20;

-- TILE 6 — Autonomous responses (IP blocks)  [chart: table]
SELECT ts, src_ip, reason, detection_id
FROM parry.blocklist
ORDER BY ts DESC
LIMIT 50;

-- TILE 7 — Brute-force pressure per source (login denials)  [chart: line]
-- Second materialized view, scoped to auth endpoints.
SELECT bucket, src_ip,
       countMerge(denies)      AS denied_logins,
       uniqMerge(users_tried)  AS usernames_tried
FROM parry.mv_auth
WHERE bucket > now() - INTERVAL 10 MINUTE
GROUP BY bucket, src_ip
ORDER BY bucket;

-- TILE 8 — Sensitive-data exposure (canary hits in responses)  [chart: table]
SELECT ts, src_ip, path,
       extract(resp_body_snip, '(sk_live_[A-Za-z0-9_]+|pg://[^"]+)') AS leaked_secret
FROM parry.http_events
WHERE resp_body_snip LIKE '%sk_live_%' OR resp_body_snip LIKE '%pg://%'
ORDER BY ts DESC
LIMIT 50;
