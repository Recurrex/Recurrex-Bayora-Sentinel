# Bayora Sentinel lab — real isolated VM range

KVM/QEMU guests managed through libvirt. NEVER bridged, never
internet-routed: three internal LANs joined by a router guest, egress dropped
on the host with nftables.

## Prerequisites (Linux host)

- KVM support (`/dev/kvm`), `qemu-kvm`, `libvirt-daemon-system`
- `virt-install`, `virsh` (libvirt-clients), `virt-manager` optional
- [Packer](https://developer.hashicorp.com/packer/downloads) >= 1.9
- `cloud-image-utils` (`cloud-localds`)
- `nft` (nftables), `openssh-client`
- Debian 12 cloud image URL reachable once for Packer builds

One command (Debian/Ubuntu) does the host setup:

```
make -f lab/Makefile setup
```

## Network map

```
        host (linux, libvirt + nftables guard)
                     |
   +-----------------+------------------+
   | mgmt 10.66.10.0/24  (broker bridge only; forward=none)
   |     10.66.10.1   host mgmt address
   |     10.66.10.11  blue-vm eth0  (collector -> broker)
   |     10.66.10.12  red-vm  eth0  (terminal/PTY sessions)
   |
   | red net 10.66.11.0/24  (forward=none, NO dhcp-to-internet)
   |     10.66.11.1   router-vm eth1
   |     10.66.11.11  red-vm  eth1  (attack origin)
   |
   | blue net 10.66.12.0/24  (forward=none)
   |     10.66.12.1   router-vm eth2
   |     10.66.12.11  blue-vm eth1  (Suricata + auditd sensor)
   |     10.66.12.99  optional target services
```

`red-net` and `blue-net` are defined with `<forward mode="none"/>`.
The router guest (Debian netinstall, 3 NICs) carries the only cross-subnet
path so red traffic passes a monitored point; Suricata mirrors/watches the
blue leg via iptables NFLOG or an inline toffy ring.

## Isolation rules

| Rule                       | Enforcement                                        |
|----------------------------|----------------------------------------------------|
| never bridged              | `<forward mode="none"/>` networks; `lab/safety-check.sh` aborts if a lab VM interface is attached to a bridge |
| never internet-routed      | nftables table `inet sentinel-guard` drops forward+input for 10.66.10/11/12; checked before every lab start |
| no personal credentials    | guests hold generated keys only; cloud-init sets throwaway passwords |
| attack tools off the host  | nmap/hydra/etc. pre-installed inside guests only    |
| tamper-evident audit trail | broker writes every VM action to the hash-chained log |

## Build the guests once

```
cd lab/packer && packer build red.pkr.hcl blue.pkr.hcl
make -f lab/Makefile lab-up
make -f lab/Makefile lab-reset-init   # clean snapshot "lab-clean"
```

`lab-reset` reverts every guest to that snapshot; the desktop's
"Reset lab" tray action posts `/vm/reset` to the broker, which reverts via
libvirt after re-running `lab/safety-check.sh`.
