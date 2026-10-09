# NoteNest — Verified Asset Inventory (ground truth)

Service: NoteNest v1.4.2, Flask, single container, exposed via Parry proxy :8080.

## Endpoints and intended access policy
| Endpoint | Method | Intended access |
|---|---|---|
| / | GET | public |
| /api/health | GET | public |
| /login | GET/POST | public (5 attempts/min/IP intended) |
| /api/search | GET | authenticated, OWN notes only |
| /api/notes/<id> | GET | authenticated, OWNER of the note only |
| /api/export | GET | authenticated; fmt must be one of txt,md,json |
| /api/admin/users | GET | role=admin ONLY |

## Verified baselines
- Only users alice, bob, carol, admin exist. Only `admin` has role=admin.
- Notes 3 and 4 are CANARY documents (fake stripe key `sk_live_…`, fake db DSN
  `pg://…`). Any response containing these strings leaving the service is a
  confirmed data-exfiltration event — no legitimate flow returns them.
- Normal traffic baseline: < 10 req/min per client IP, < 5 distinct paths/min,
  zero requests to /.env, /.git, /backup.zip.
- /api/export legitimate values: fmt=txt|md|json. Any `;`, `|`, `&` in fmt is
  command-injection attempt by definition.
