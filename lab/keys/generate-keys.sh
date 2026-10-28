#!/usr/bin/env bash
# Generate the lab key material once, on the Linux host (as root):
#   * broker Ed25519 key per guest  -> /etc/sentinel/lab-keys/<vm>.key
#     (the only key allowed to SSH into that guest; pinned host key below)
#   * guest SSH host pubkey         -> guests/<vm>.known_hosts
#   * collector shared token        -> /etc/sentinel/collector-ingest-token
# Nothing here is personal or real credentials; everything is lab-generated.

set -euo pipefail

BASE=/etc/sentinel/lab-keys
mkdir -p "$BASE/guests"
chmod 700 "$BASE" "$BASE/guests"

for vm in red-vm blue-vm; do
  key="$BASE/$vm.key"
  if [ ! -f "$key" ]; then
    ssh-keygen -q -N "" -t ed25519 -f "$key" -C "sentinel-$vm"
  fi
  chmod 600 "$key"
  echo "broker key: $key"
done

# Collector token: random hex, shared with blue-vm's collector.env only.
token="$BASE/../collector-ingest-token"
if [ ! -s "$token" ]; then
  openssl rand -hex 24 > "$token"
  chmod 600 "$token"
fi
echo "collector token: $token"
echo
echo "wire these into Packer (http/*-user-data.tpl) and render the guests:"
echo "  sed -e 's|__BROKER_KEY__|'$(cat $BASE/red-vm.key.pub)'|' lab/packer/http/red-user-data.tpl"
