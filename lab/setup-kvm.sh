#!/usr/bin/env bash
# One-command host setup for the Bayora Sentinel lab (Debian/Ubuntu).
# Installs KVM + libvirt + nftables, defines the three isolated networks,
# installs the egress guard.  Run as root (or with sudo via lab-setup).

set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo" >&2
  exit 1
fi

if [ ! -e /dev/kvm ]; then
  echo "no /dev/kvm: enable virtualization (VT-x/AMD-V) first" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  qemu-kvm libvirt-daemon-system libvirt-clients \
  virtinst cloud-image-utils nftables openssh-client curl jq

systemctl enable --now libvirtd

# Define (not start) the three isolated networks.
for net in sentinel-mgmt sentinel-red sentinel-blue; do
  virsh net-undefine "$net" >/dev/null 2>&1 || true
  virsh net-define "$LAB_DIR/net/$net.xml"
done

# Egress guard: lab subnets may never leave the host.
bash "$LAB_DIR/egress-guard.sh"

echo
echo "host ready. Next:"
echo "  cd lab/packer && packer build red.pkr.hcl blue.pkr.hcl"
echo "  make -f lab/Makefile lab-up lab-reset-init"
