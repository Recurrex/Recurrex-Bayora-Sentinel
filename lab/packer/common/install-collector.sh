#!/usr/bin/env bash
# Installed once by Packer on blue-vm:
#   * collector.service -> systemd start on lab boot
#   * canary mount seeds: fake secrets planted for leak detection.
# No personal data, no real credentials: values are generated at provision.

set -euo pipefail

# --- canary tokens: unique random strings, planted in + referenced by -------
CANARIES_FILE=/etc/sentinel/canaries.json
mkdir -p /etc/sentinel
{
  echo '{'
  echo ' "canaries": ['
  for _ in 1 2 3; do
    # openssl rand hex; token prefix marks it as a sentinel canary
    echo -n '  "SNTL-'$(openssl rand -hex 12)'",'
    echo
  done | sed '$ s/,$//'
  echo ' ]'
  echo '}'
} > "$CANARIES_FILE"
chmod 600 "$CANARIES_FILE"

# Plant one canary in a decoy file; leak of that file is detectable.
echo "SNTL-DOCS-$(openssl rand -hex 12)" > /home/sentinel/.secret-notes
chown sentinel:sentinel /home/sentinel/.secret-notes

# --- collector service -------------------------------------------------------
cat > /lib/systemd/system/collector.service <<EOF
[Unit]
Description=Sentinel lab collector (tails suricata + auditd -> broker)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/collector.py
Restart=always
User=root
EOF

python3 - <<'PY'
import shutil
shutil.copy("/usr/local/lib/packer-collector.py", "/usr/local/bin/collector.py")
PY

systemctl daemon-reload
