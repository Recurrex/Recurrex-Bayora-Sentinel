#!/usr/bin/env bash
# Boot safety gate for the Bayora Sentinel lab (Part 3).
# Aborts (exit 1) unless the lab is provably isolated:
#   * no lab VM interface on a bridge or physical NIC
#   * nftables egress guard table `inet sentinel-guard` is loaded
#   * no default route resolves into a lab subnet
# Run before lab-up / snapshot actions.  Requires root.

set -euo pipefail

LAB_NETWORKS="sentinel-mgmt sentinel-red sentinel-blue"
LAB_SUBNETS="10.66.10.0/24 10.66.11.0/24 10.66.12.0/24"
VIOLATIONS=0
fail() { echo "ABORT: $*" >&2; VIOLATIONS=$((VIOLATIONS+1)); }

for net in $LAB_NETWORKS; do
  out=$(virsh -q net-info "$net" 2>/dev/null || true)
  if [ -z "$out" ]; then
    fail "libvirt network $net is not defined"
    continue
  fi
  if ! virsh net-dumpxml "$net" | grep -q '<forward mode=.none.'; then
    fail "network $net is not isolated (forward mode is not 'none')"
  fi
done

# Any lab VM attached to a bridge or physical device -> refuse.
for vm in $(virsh list --all --name | grep -E '^(red-vm|blue-vm|router-vm)$'); do
  virsh domiflist "$vm" | awk 'NR>2 {print $3, $4}' | while read -r t s; do
    case "$t" in
      network)
        case "$s" in
          sentinel-mgmt|sentinel-red|sentinel-blue) ;;
          *) echo "ABORT: $vm uses unexpected network $s" >&2; exit 1 ;;
        esac ;;
      *) echo "ABORT: $vm interface type $t ($s) is not isolated" >&2; exit 1 ;;
    esac
  done || VIOLATIONS=$((VIOLATIONS+1))
done

# Egress guard must be loaded; without it lab traffic could reach the WAN.
if ! nft list table inet sentinel-guard >/dev/null 2>&1; then
  fail "nftables guard table inet sentinel-guard is missing (run egress-guard.sh)"
fi

# Default route must never pick a lab subnet as its gateway.
if ip -4 route show | grep -E '^default .*(10\.66\.(10|11|12))'; then
  fail "default route resolves into a lab subnet"
fi

if [ "$VIOLATIONS" -ne 0 ]; then
  echo "lab start refused: $VIOLATIONS violation(s)" >&2
  exit 1
fi

echo "safety check ok: lab firewall grid isolated"
