"""PTY bridge: real shell windows over WebSocket (Part 2: terminal app).

The browser Terminal/Toolbox windows open

    /ws/pty?vm=red-vm&token=<session token>

and the broker connects into the matching guest over SSH (paramiko) with the
role's lab key.  The guest never receives more credentials than required:

- red token    -> red-vm only
- blue token   -> blue-vm only
- observer     -> either guest, joined to its matching host account

One SSH session per WebSocket; the session dies with the socket, so there is
nothing to manage for a closed browser.  Every byte flowing through here is
untrusted guest output, the desktop renders it as text only.
"""

from __future__ import annotations

import asyncio
import logging
import os

import paramiko

import auditlog

log = logging.getLogger("sentinel.pty")

# Role -> guest allowlist.  Red users must never shell into blue-vm, which
# holds the detection stack and defense material.
ROLE_VM_ALLOW: dict[str, set[str]] = {
    "red": {"red-vm"},
    "blue": {"blue-vm"},
    "observer": {"red-vm", "blue-vm"},
}

# Default lab host accounts were provisioned through cloud-init (no personal
# data; generated keys under /etc/sentinel/lab-keys).
KEY_DIR = os.environ.get("LAB_KEY_DIR", "/etc/sentinel/lab-keys")
SSH_USER = os.environ.get("LAB_SSH_USER", "sentinel")
SSH_PORT = 22

# Guest IPs: fixed in the libvirt networks (lab/net/*.xml).
VM_HOSTS = {
    "red-vm": os.environ.get("LAB_RED_HOST", "10.66.11.11"),
    "blue-vm": os.environ.get("LAB_BLUE_HOST", "10.66.12.11"),
}

CHUNK_BYTES = 8192


def role_may_use(role: str, vm: str) -> bool:
    return vm in ROLE_VM_ALLOW.get(role, set())


async def _handoff(websocket, channel) -> None:
    """Pump one SSH PTY into the WebSocket and vice-versa."""

    async def to_browser():
        loop = asyncio.get_running_loop()
        while not channel.closed:
            data = await loop.run_in_executor(None, channel.recv, CHUNK_BYTES)
            if not data:
                break
            await websocket.send_text(data.decode("utf-8", "replace"))

    async def to_guest():
        while True:
            try:
                text = await websocket.receive_text()
            except Exception:
                break
            await asyncio.get_running_loop().run_in_executor(
                None, channel.sendall, text.encode("utf-8")
            )
            if not channel.active:
                break

    try:
        await asyncio.gather(to_browser(), to_guest())
    finally:
        try:
            channel.close()
        except Exception:
            pass


class _SSHSession:
    """Blocking SSH setup, run once in a worker thread."""

    def __init__(self, vm: str) -> None:
        self.vm = vm
        self.client: paramiko.SSHClient | None = None

    def open(self):
        host = VM_HOSTS.get(self.vm)
        if not host:
            raise RuntimeError(f"unknown guest {self.vm!r}")
        key_path = os.path.join(KEY_DIR, f"{self.vm}.key")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        # Identity is the lab CA-signed key; fingerprint pinning uses the
        # per-guest known-guests file shipped under lab/keys/guests/.
        try:
            client.load_system_host_keys(
                os.path.join(KEY_DIR, "guests", f"{self.vm}.known_hosts")
            )
        except FileNotFoundError:
            pass
        client.connect(
            hostname=host,
            port=SSH_PORT,
            username=SSH_USER,
            key_filename=key_path,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            banner_timeout=10,
        )
        self.client = client
        channel = client.invoke_shell(
            term="xterm-256color", width=120, height=32
        )
        channel.settimeout(0.0)
        return channel

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass


async def open_pty_session(websocket, principal: dict, vm: str) -> None:
    """Accept the WebSocket and attach it to the guest's shell."""
    role = principal["r"]
    if not role_may_use(role, vm):
        auditlog.append(
            "lab", "vm_action",
            f"pty denied: role {role} may not open {vm}",
        )
        await websocket.close(code=4403)
        return

    session = _SSHSession(vm)
    loop = asyncio.get_running_loop()
    try:
        channel = await loop.run_in_executor(None, session.open)
    except Exception as error:
        # Keep the detail in the log only; the client gets an opaque close.
        log.warning("SSH into %s failed: %s", vm, error)
        await websocket.close(code=4502)
        return

    await websocket.accept()
    await websocket.send_text(f"-- connected to {vm} --\r\n")
    try:
        await _handoff(websocket, channel)
    finally:
        await loop.run_in_executor(None, session.close)
