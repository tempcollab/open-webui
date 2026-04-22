#!/usr/bin/env bash
# teardown.sh — Remove the Open WebUI Docker test container.
#
# Usage:
#   ./teardown.sh

set -euo pipefail

CONTAINER_NAME="openwebui-security-test"

echo "[*] Removing container: ${CONTAINER_NAME}"

if docker rm -f "${CONTAINER_NAME}" 2>/dev/null; then
    echo "[+] Container '${CONTAINER_NAME}' removed successfully"
else
    echo "[-] Container '${CONTAINER_NAME}' not found or already removed"
    exit 1
fi
