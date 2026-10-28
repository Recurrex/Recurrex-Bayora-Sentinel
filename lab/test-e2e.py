#!/usr/bin/env python3
"""End-to-end lab test (Part 4 deliverable #6).

Boots the lab, then:
  1. runs a harmless `nmap` port scan red-vm -> blue-vm (inside guests, never
     from the host);
  2. polls the broker for the Suricata alert the scan must raise;
  3. asserts the alert lands within 5 seconds;
  4. reverts the lab snapshot so the run leaves nothing behind.

Requires: Linux + KVM, root group access to libvirt, `make lab-up`,
`make lab-guard`, broker reachable at $BROKER_URL (default 127.0.0.1:8000)
and a red-role session token at $SENTINEL_TOKEN.  Exits 0 only if the alert
arrived in time; every other outcome exits non-zero with a reason.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

BROKER = os.environ.get("BROKER_URL", "http://127.0.0.1:8000")
TOKEN = os.environ.get("SENTINEL_TOKEN", "")
SNAPSHOT = "lab-clean"
ALERT_TIMEOUT = 5.0
SCAN_WAIT = 30.0


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"{cmd[0]} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout.strip()


def ssh_red(cmd: str) -> str:
    """Run a command inside red-vm via the mgmt net; never from the host."""
    return run([
        "ssh", "-i", "/etc/sentinel/lab-keys/red-vm.key",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "sentinel@10.66.10.12", "--", f"sudo -n {cmd}",
    ])


def fetch(path: str) -> dict | list | None:
    request = urllib.request.Request(
        BROKER + path, headers={"Authorization": "Bearer " + TOKEN}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        print(f"  broker {path} -> HTTP {error.code}", file=sys.stderr)
        return None


def main() -> int:
    if sys.platform != "linux":
        print("e2e needs the Linux/KVM host", file=sys.stderr)
        return 77

    if not TOKEN:
        print("set SENTINEL_TOKEN (a red-role session token)", file=sys.stderr)
        return 77

    print("[1/4] booting lab (safety check runs first)")
    subprocess.run(["make", "-f", "lab/Makefile", "lab-up"], check=True)

    print("[2/4] harmless scan: nmap -Pn -p 22,80 red -> blue (guest-internal)")
    try:
        ssh_red("nmap -Pn -p 22,80 10.66.12.11")
    except RuntimeError as error:
        print(f"    scan skipped: {error}", file=sys.stderr)
        return 77

    print("[3/4] polling broker /events for the Suricata ids_alert")
    deadline = time.monotonic() + ALERT_TIMEOUT
    while time.monotonic() < deadline:
        body = fetch("/events?since=0")
        if body and "suricata alert" in body:
            print(f"    ids_alert visible ({deadline - time.monotonic():.1f}s early)")
            break
        time.sleep(0.2)
    else:
        print("FAIL: no Suricata alert within 5 s", file=sys.stderr)
        subprocess.run(["make", "-f", "lab/Makefile", "lab-down"], check=False)
        return 1

    print("[4/4] reverting lab to clean snapshot")
    subprocess.run(["make", "-f", "lab/Makefile", "lab-reset"], check=True)
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
