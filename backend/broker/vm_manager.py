"""VM lifecycle control for the isolated lab (Part 2 / Part 3 of the plan).

The lab runs on KVM/QEMU via libvirt on the host.  The broker never talks to
libvirt's daemon bindings directly; it shells out to `virsh` so the module
stays dependency-free and behaves identically in Docker with the socket
mounted in.

Network isolation rules enforced here (never bridged, never internet-routed):

- Every lab VM interface must belong to one of the isolated libvirt networks
  (`sentinel-mgmt`, `sentinel-red`, `sentinel-blue`) which are defined with
  `<forward mode="none"/>` -- no NAT, no bridge, no internet.
- A host nftables table (`inet sentinel-guard`) must exist and drop all
  forwarded/lab-sourced traffic (lab/egress-guard.sh installs it).  Start
  actions abort if it is missing, because that is the only thing standing
  between the lab subnets and the internet uplink.

Every successful or failed action is written to the hash-chained audit log,
type vm_action, source lab.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import auditlog

# The three lab guests and the only subnets they may ever use.
LAB_VMS = ("router-vm", "blue-vm", "red-vm")
LAB_NETWORKS = ("sentinel-mgmt", "sentinel-red", "sentinel-blue")
LAB_SUBNETS = ("10.66.10.0/24", "10.66.11.0/24", "10.66.12.0/24")

# libvirt connection; override for a system session or testing.
LIBVIRT_URI = os.environ.get("LIBVIRT_URI", "qemu:///system")

# Snapshot created once by `make lab-reset-init` (lab/Makefile) after
# provisioning; "Reset lab" reverts every guest to it.
CLEAN_SNAPSHOT = "lab-clean"

# Set to "0" in tests / offline brokers where libvirt cannot exist.
VM_MANAGER_ENABLED = os.environ.get("VM_MANAGER_ENABLED", "1") != "0"


class VMError(Exception):
    """Raised for unexpected virsh output or refused lab operations."""


def _virsh(*args: str, check: bool = True) -> str:
    if shutil.which("virsh") is None:
        raise VMError("virsh is not installed")
    result = subprocess.run(
        ["virsh", "--connect", LIBVIRT_URI, *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        raise VMError(f"virsh {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


# ---------------------------------------------------------------- state


def _is_up(state: str) -> bool:
    return state.lower() == "running"


def vm_state() -> dict:
    """One snapshot for the tray / UI: guest states + guard + snapshot flag."""

    if not VM_MANAGER_ENABLED:
        return {"vms": {}, "guard": "off", "snapshot": None, "unsupported": True}

    vms: dict[str, dict] = {}
    for name in LAB_VMS:
        try:
            raw = _virsh("domstate", name, check=False)
        except VMError:
            raw = "shut off"
        running = _is_up(raw.splitlines()[0] if raw else "")
        vms[name] = {"up": running, "state": raw}

    guard = _guard_status()
    snapshot = CLEAN_SNAPSHOT in _virsh(
        "snapshot-list", "red-vm", check=False
    ) if VM_MANAGER_ENABLED else False

    return {"vms": vms, "guard": guard, "snapshot": snapshot, "unsupported": False}


def _guard_status() -> str:
    """'up' when the nftables egress guard is loaded, 'down' otherwise."""

    if shutil.which("nft") is None:
        return "down"
    result = subprocess.run(
        ["nft", "list", "table", "inet", "sentinel-guard"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    return "up" if result.returncode == 0 else "down"


# ---------------------------------------------------------------- safety


def safety_check() -> list[str]:
    """Return a list of isolation violations; empty list means safe to run.

    Checked before every start/reset action:
      1. No lab VM interface may be attached to a bridge (brX / physical
         device) -- only the three isolated networks are allowed.
      2. The host must hold no default route pointing into a lab subnet
         (a misconfigured router VM must not become the lab uplink).
      3. The nftables egress guard must be loaded.
    """

    violations: list[str] = []
    if not VM_MANAGER_ENABLED:
        return violations
    if _guard_status() != "up":
        violations.append("nftables egress guard (inet sentinel-guard) is not loaded")

    for name in LAB_VMS:
        out = _virsh("domiflist", name, check=False)
        for line in out.splitlines()[2:]:
            fields = line.split()
            if len(fields) < 5:
                continue
            iface_type, source = fields[2], fields[3]
            if iface_type == "bridge" or (
                iface_type == "direct" and source not in LAB_NETWORKS
            ):
                violations.append(
                    f"{name}: interface {fields[0]} is attached to {iface_type} "
                    f"{source} (bridged/physical) -- lab must stay internal"
                )
            elif iface_type == "network" and source not in LAB_NETWORKS:
                violations.append(
                    f"{name}: interface {fields[0]} uses unexpected network {source}"
                )

    route_out = subprocess.run(
        ["ip", "-4", "route", "show"], capture_output=True, text=True, timeout=15
    ).stdout
    for line in route_out.splitlines():
        for subnet in LAB_SUBNETS:
            if line.startswith("default") and subnet in line:
                violations.append(f"default route points into lab subnet {subnet}")

    return violations


# ------------------------------------------------------------- lifecycle


def _audit(user: str, message: str) -> None:
    auditlog.append("lab", "vm_action", f"{user} {message}")


def start_vm(name: str, user: str) -> dict:
    _verify_vm(name)
    violations = safety_check()
    if violations:
        _audit(user, f"start {name} REFUSED: " + "; ".join(violations))
        raise VMError("labor isolation check failed: " + "; ".join(violations))
    _audit(user, f"starting {name}")
    _virsh("start", name)
    return {"ok": True, "vm": name, "action": "start"}


def stop_vm(name: str, user: str) -> dict:
    _verify_vm(name)
    _virsh("shutdown", name, check=False)
    _audit(user, f"stop {name}")
    return {"ok": True, "vm": name, "action": "stop"}


def reset_lab(user: str) -> dict:
    """Revert every guest to the clean provisioning snapshot."""
    violations = safety_check()
    if violations:
        _audit(user, "reset REFUSED: " + "; ".join(violations))
        raise VMError("labor isolation check failed: " + "; ".join(violations))
    results = {}
    for name in LAB_VMS:
        _virsh("snapshot-revert", name, CLEAN_SNAPSHOT, check=False)
        _virsh("start", name, check=False)
        results[name] = "reverted"
    _audit(user, "reset lab: all guests reverted to snapshot " + CLEAN_SNAPSHOT)
    return {"ok": True, "results": results}


def _verify_vm(name: str) -> None:
    if name not in LAB_VMS:
        raise VMError(f"unknown lab vm: {name!r}")
