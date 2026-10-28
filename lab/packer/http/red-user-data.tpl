#cloud-config
# First boot for red-vm (attacker).  Throwaway credentials only; the guest
# holds generated lab material and no personal data.
users:
  - name: sentinel
    groups: [adm, sudo]
    shell: /bin/bash
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    lock_passwd: true
    shell_setup: []

ssh_pwauth: false
chpasswd: { expire: false }

# Only the lab broker key may log in; passwords are locked.
ssh_authorized_keys:
  - __BROKER_KEY__

write_files:
  - path: /etc/motd
    content: |
      Bayora Sentinel red-vm: attack practice box. Isolated 10.66.0.0/16.
      Egress is dropped at the host; this box has no internet.
  - path: /etc/sentinel/canaries.json
    permissions: "0600"
    content: |
      {"canaries": ["SNTL-RECOVERED-0000000000000000"]}

bootcmd:
  - [ systemctl, mask, cloud-init.service ]   # static guest; nothing first-booty
