#!/usr/bin/env bash
# Packer build step, run inside the guest: emit this machine's SSH host key
# so the broker's pty_bridge can pin the guest fingerprint (host key
# checking uses /etc/sentinel/lab-keys/guests/<vm>.known_hosts on the host,
# written by lab/keys/generate-keys.sh -- never playwright-style blanket
# accept policies).

set -euo pipefail
ssh-keygen -A >/dev/null
cat /etc/ssh/ssh_host_ed25519_key.pub
