#!/usr/bin/env bash
# Egress lock for the Bayora Sentinel lab: nothing inside the guest lab
# reaches the internet or the host LAN.  Installed by setup-kvm.sh and
# verified by safety-check.sh before every lab start.
#
# Idempotent: re-running deletes and rebuilds the table.  Requires root+nft.

set -euo pipefail

if ! command -v nft >/dev/null 2>&1; then
  echo "nft not installed" >&2
  exit 1
fi

nft list table inet sentinel-guard >/dev/null 2>&1 && nft delete table inet sentinel-guard

nft --file -- <<'NFT'
table inet sentinel-guard {
  chain lab_egress {
    type filter hook forward priority 300; policy accept;
    ip daddr 10.66.0.0/16 accept
    ip saddr 10.66.0.0/16 counter drop
  }
  chain lab_input {
    type filter hook input priority 300; policy accept;
    ip saddr 10.66.0.0/16 ip daddr != 10.66.10.1 drop
  }
}
NFT

echo "sentinel-guard loaded: lab egress dropped (10.66.0.0/16 -> WAN)"
