#!/usr/bin/env bash
# setup.sh — Stand up the Open WebUI Docker test environment for security audit.
#
# Wraps test_environment.py --no-teardown.
# Container: openwebui-security-test
# Secret:    WEBUI_SECRET_KEY=t0p-s3cr3t (for compatibility with all exploit scripts)
#
# Usage:
#   ./setup.sh [port]     default port: 8080

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${1:-8080}"

echo "========================================"
echo "  Open WebUI Security Audit — Setup"
echo "  Container : openwebui-security-test"
echo "  Port      : ${PORT}"
echo "  Secret    : t0p-s3cr3t"
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
    --no-teardown

echo
echo "[*] To run the new exploit scripts:"
echo "    python3 autofyn_audit/exploit_cors_origin_reflection.py    --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_token_revocation_bypass.py   --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_oauth_cookie_httponly.py     --target http://localhost:${PORT}"
echo "    python3 autofyn_audit/exploit_cors_chain.py                --target http://localhost:${PORT}"
echo
echo "[*] To tear down: ./autofyn_audit/teardown.sh"
