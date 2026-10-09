# Parry — ~3-minute podcast transcript (AI AppSec SOC)
Two hosts: **Maya** (woman) and **Dan** (man). Voices: Google Chirp 3 HD.

**[01 · Maya]** Welcome to Build Logs. Today: Parry — an AI AppSec SOC. A security operations center for your applications that doesn't just detect attacks, it responds to them, and even writes its own rules, automatically.

**[02 · Dan]** The hard part isn't spotting one attack — it's the data. A busy app emits millions of HTTP events a day. You cannot run every request through a language model; it's too slow and too expensive. So the first problem Parry solves is scale.

**[03 · Maya]** Here's how. Parry sits inline as a reverse proxy. Its sensor parses every request and response into one structured row — method, path, query, body, status, session, and the real client IP — and streams it into ClickHouse.

**[04 · Dan]** ClickHouse Cloud is the brain, and it's what makes scale affordable. Detection is literally SQL: eight rules over live telemetry every two seconds, with materialized views pre-aggregating at ingest. We see about ten-to-one compression and sub-twenty-millisecond queries over the full stream.

**[05 · Maya]** And that's how we detect in the first place: when a SQL rule crosses its threshold — say, a UNION injection that returns data, or a canary secret leaving the app — that row IS the trigger that wakes the SOC loop. Only then does an AI get involved.

**[06 · Dan]** Triage runs on Akash. We rented an NVIDIA A100 through Akash's Console API — managed wallet, auto-funding, a runtime cap. One model scores the alert, writes the patch, and the incident report — but only for the handful of events that already matched a rule.

**[07 · Maya]** Every call is grounded in Senso. Our response playbooks live there, and the agent cites the exact documents it used — no hallucinated response steps. Semgrep then pins the vulnerable line, and the Akash model writes the secure patch.

**[08 · Dan]** Now the part we're most excited about: rule generation. The first time an exploit succeeds, Parry distills its indicators into a brand-new ClickHouse detection rule, and the model names it.

**[09 · Maya]** But a new auto-generated rule is dangerous — a bad one could block legitimate users and take down your own app. So before Parry ever enforces a rule, it correlates it against real, live traffic. We run it over a baseline of genuine user requests, and only arm it to block when it produces zero false positives. We will not deny service to ourselves.

**[10 · Dan]** And that rule is a virtual patch. It holds the line — blocking the exploit — and it stays in place until the underlying code is actually fixed and deployed. The moment the fix lands, the rule retires. Detection kicks off the fix, and guards the gap until it's closed.

**[11 · Maya]** Oh, and when a secret is touched during exfiltration — an API key, database credentials, the admin password — Parry rotates it for real, immediately. The stolen secret is already dead. Guild runs a commander agent that adjudicates every critical as a tamper-evident audit trail.

**[12 · Dan]** In the demo you launch an attacker from the dashboard and watch three columns: the attacker on the left, ClickHouse telemetry in the middle, and the blue team detecting, correlating, blocking, and patching on the right. Run it again and the whole attack comes back 403 — caught by the rules it learned the first time.

**[13 · Maya]** Parry: an AI AppSec SOC. Detection as SQL at scale, AI on decentralized GPU, grounded, self-improving, and safe by correlation. It sees the attack, stops it, fixes it, and shows you exactly why. Thanks for listening to Build Logs.
