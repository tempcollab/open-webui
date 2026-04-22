#!/usr/bin/env bash
# setup.sh — Stand up the Open WebUI Docker test environment for security audit.
#
# Wraps test_environment.py --no-teardown.
# Container: openwebui-security-test
# Modes:
#   forced-default-secret  -> explicitly sets WEBUI_SECRET_KEY=t0p-s3cr3t for F1/F10/F12 chain testing
#   default-docker         -> stock startup behavior with generated/random secret
#
# Usage:
#   ./setup.sh [port] [mode]     defaults: 8080 forced-default-secret

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8080}"
MODE="${2:-forced-default-secret}"

echo "========================================"
echo "  Open WebUI Security Audit — Setup"
echo "  Container : openwebui-security-test"
echo "  Port      : ${PORT}"
echo "  Mode      : ${MODE}"
if [[ "${MODE}" == "forced-default-secret" ]]; then
    echo "  Secret    : t0p-s3cr3t (explicit lab mode)"
else
    echo "  Secret    : stock startup behavior"
fi
echo "========================================"
echo

if ! command -v docker &>/dev/null; then
    echo "[-] Docker is not installed or not in PATH"
    exit 1
fi

if ! docker info &>/dev/null; then
    echo "[-] Docker daemon is not running (or no permission)"
    exit 1
fi

echo "[*] Launching test environment via test_environment.py..."
python3 "${SCRIPT_DIR}/test_environment.py" \
    --port "${PORT}" \
    --mode "${MODE}" \
    --no-teardown

echo
echo "[*] To run the exploit scripts:"
if [[ "${MODE}" == "forced-default-secret" ]]; then
    echo "    JWT-dependent chain scripts are expected to work in this lab mode."
else
    echo "    JWT-dependent chain scripts will fail here unless the deployment actually uses the public default secret."
fi
echo "    After the first admin is created, public signup is disabled by current startup."
echo "    Prefer --token / --user-token / --admin-id on scripts that support them."
echo "    python3 autofyn_audit/exploit_cors_origin_reflection.py    --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_token_revocation_bypass.py   --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_oauth_cookie_httponly.py     --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_cors_chain.py                --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_mermaid_xss.py               --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_pip_injection.py             --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_full_rce_chain.py            --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_ssrf_rag.py                  --target http://localhost:${PORT} --token <verified_user_token>"
echo "    python3 autofyn_audit/exploit_tool_exec_rce.py             --target http://localhost:${PORT}"
echo
echo "[*] To tear down: ./autofyn_audit/teardown.sh"
