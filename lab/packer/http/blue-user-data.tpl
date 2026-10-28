#cloud-config
# First boot for blue-vm (defender / target).  Same rules as the red guest:
# throwaway credentials only, key-based SSH, no personal data.
users:
  - name: sentinel
    groups: [adm, sudo, staff]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: true

ssh_pwauth: false
chpasswd: { expire: false }

ssh_authorized_keys:
  - __BROKER_KEY__

write_files:
  - path: /etc/motd
    content: |
      Bayora Sentinel blue-vm: defender practice box. Isolated 10.66.0.0/16.
      Suricata (ids) + auditd (host) fact feed; collector posts to broker.
  - path: /etc/sentinel/collector.env
    permissions: "0600"
    content: |
      BROKER_URL=http://10.66.10.1:8000
      COLLECTOR_TOKEN=__COLLECTOR_TOKEN__

runcmd:
  # auditd keeps its rules where the collector+broker can verify the chain.
  - [ systemctl, enable, --now, ssh ]
  - [ systemctl, enable, --now, auditd ]
