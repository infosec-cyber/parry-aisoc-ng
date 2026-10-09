# Detection & Response Playbooks (verified)

## recon-scan
Signal: ≥8 distinct paths with ≥4 404s inside 15s from one IP.
Response: observe only. Tag the IP. Do not block (loses attribution).

## bruteforce
Signal: ≥4 failed POST /login in 15s from one IP.
Response: severity medium; if later followed by a 200 login from the same IP,
escalate to high (successful credential attack) and require session review.

## sqli-probe / sqli-dump
Signal: quote/UNION patterns in query strings; 500s containing "syntax".
sqli-dump = UNION query returning user-table contents (usernames/passwords in
a notes response). Response: CRITICAL. Block the source IP immediately,
rotate all user passwords, open root-cause fix on the search handler.

## idor-enum
Signal: one session reading ≥4 distinct /api/notes/<id> that it does not own.
Response: high. Verify ownership column against inventory; fix = ownership
check in the note handler.

## bac-admin
Signal: /api/admin/users returns 200 to any identity other than `admin`.
Response: high. The role check must be server-side; client-side checks are
not a control.

## cmdinj
Signal: shell metacharacters in /api/export fmt, or `uid=` in a response.
Response: CRITICAL. Block source IP immediately. Fix = remove shell=True,
allowlist fmt.

## exfil-canary
Signal: canary strings (sk_live_, pg://) in any response body.
Response: CRITICAL. Confirmed exfiltration — block, escalate to commander,
file incident report.
