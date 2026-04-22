#!/usr/bin/env python3
"""
test_environment.py — Stand up a local Open WebUI instance with default (vulnerable) config.

Uses Docker to run ghcr.io/open-webui/open-webui:main without WEBUI_SECRET_KEY set,
so the default hardcoded secret 't0p-s3cr3t' is used.
"""

import argparse
import subprocess
import sys
import time

import requests

CONTAINER_NAME = 'openwebui-security-test'
DOCKER_IMAGE = 'ghcr.io/open-webui/open-webui:main'
DEFAULT_PORT = 8080
WAIT_TIMEOUT = 180
ADMIN_EMAIL = 'admin@test.local'
ADMIN_PASSWORD = 'TestAdmin123!'
ADMIN_NAME = 'Admin'


def check_docker_available() -> bool:
    try:
        result = subprocess.run(
            ['docker', 'info'],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def setup_environment(port: int = DEFAULT_PORT, timeout: int = WAIT_TIMEOUT) -> str:
    print(f'[*] Starting Open WebUI container on port {port}...')

    # Remove any existing container with the same name
    subprocess.run(
        ['docker', 'rm', '-f', CONTAINER_NAME],
        capture_output=True,
    )

    result = subprocess.run(
        [
            'docker', 'run', '-d',
            '--name', CONTAINER_NAME,
            '-p', f'{port}:8080',
            '-e', 'WEBUI_SECRET_KEY=t0p-s3cr3t',
            '-e', 'ENABLE_SIGNUP=true',
            '-e', 'ENABLE_ADMIN_EXPORT=true',
            '-e', 'WEBUI_AUTH=true',
            DOCKER_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )

    if result.returncode != 0:
        print(f'[-] Failed to start container: {result.stderr.strip()}')
        sys.exit(1)

    container_id = result.stdout.strip()
    print(f'[+] Container started: {container_id[:12]}')
    return container_id


def wait_for_ready(base_url: str, timeout: int = WAIT_TIMEOUT) -> bool:
    print(f'[*] Waiting for Open WebUI to be ready at {base_url} (timeout: {timeout}s)...')
    deadline = time.time() + timeout
    interval = 3

    while time.time() < deadline:
        try:
            resp = requests.get(f'{base_url}/api/version', timeout=5)
            if resp.status_code == 200:
                version = resp.json().get('version', 'unknown')
                print(f'[+] Open WebUI is ready (version: {version})')
                return True
        except requests.RequestException:
            pass
        time.sleep(interval)

    print(f'[-] Timed out waiting for Open WebUI to be ready after {timeout}s')
    return False


def teardown_environment(container_id: str) -> None:
    print(f'[*] Tearing down container {container_id[:12]}...')
    result = subprocess.run(
        ['docker', 'rm', '-f', container_id],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode == 0:
        print('[+] Container removed successfully')
    else:
        print(f'[!] Warning: failed to remove container: {result.stderr.strip()}')


def setup_initial_admin(base_url: str) -> dict:
    print(f'[*] Creating initial admin account ({ADMIN_EMAIL})...')
    resp = requests.post(
        f'{base_url}/api/v1/auths/signup',
        json={
            'name': ADMIN_NAME,
            'email': ADMIN_EMAIL,
            'password': ADMIN_PASSWORD,
        },
        timeout=30,
    )

    if resp.status_code == 200:
        data = resp.json()
        role = data.get('role', 'unknown')
        user_id = data.get('id', 'unknown')
        token = data.get('token', '')
        print(f'[+] Admin account created — id: {user_id}, role: {role}')
        return {'user_id': user_id, 'token': token, 'role': role, 'email': ADMIN_EMAIL}
    else:
        print(f'[-] Failed to create admin account: {resp.status_code} {resp.text}')
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Stand up a vulnerable Open WebUI test environment'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=DEFAULT_PORT,
        help=f'Host port to bind (default: {DEFAULT_PORT})',
    )
    parser.add_argument(
        '--no-teardown',
        action='store_true',
        help='Leave the container running after setup',
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=WAIT_TIMEOUT,
        help=f'Seconds to wait for container readiness (default: {WAIT_TIMEOUT})',
    )
    args = parser.parse_args()

    if not check_docker_available():
        print('[-] Docker is not available or not running')
        print('[!] Ensure Docker is installed and the socket is accessible')
        sys.exit(1)

    print('[*] Docker is available')
    base_url = f'http://localhost:{args.port}'

    container_id = setup_environment(port=args.port, timeout=args.timeout)

    ready = wait_for_ready(base_url, timeout=args.timeout)
    if not ready:
        teardown_environment(container_id)
        sys.exit(1)

    admin_info = setup_initial_admin(base_url)

    print()
    print('=' * 60)
    print('[+] Test environment ready')
    print(f'    Target URL : {base_url}')
    print(f"    Admin email: {admin_info['email']}")
    print(f"    Admin ID   : {admin_info['user_id']}")
    print(f"    Admin token: {admin_info['token'][:40]}...")
    print('    Secret key : t0p-s3cr3t (default — NOT set in env)')
    print('=' * 60)

    if not args.no_teardown:
        input('\nPress Enter to tear down the test environment...')
        teardown_environment(container_id)
    else:
        print(f"\n[*] Container '{CONTAINER_NAME}' left running (--no-teardown)")
        print(f'[*] To stop: docker rm -f {CONTAINER_NAME}')


if __name__ == '__main__':
    main()
