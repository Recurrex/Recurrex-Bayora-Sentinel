# Red guest (attacker lab box): Debian 12 + XFCE + attack tooling.
# Built once on the host; the qcow2 is later attached to the three isolated
# libvirt networks by lab/Makefile + virsh commands (see README network map).

packer {
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "deb_url" {
  type    = string
  default = "https://cdimage.debian.org/cdimage/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
}

variable "deb_checksum" {
  type    = string
  default = "file:https://cdimage.debian.org/cdimage/cloud/bookworm/latest/SHA256SUMS"
}

source "qemu" "red-vm" {
  iso_url      = var.deb_url
  iso_checksum = var.deb_checksum

  # Debian cloud images boot straight from the qcow2; cloud-init reads
  # the seed ISO built from lab/packer/http/red-user-data.tpl.
  disk_size          = "8G"
  format             = "qcow2"
  accelerator        = "kvm"
  cpus               = 2
  memory             = 2048
  output_directory   = "../../build/red-vm"
  vm_name            = "red-vm.qcow2"
  headless           = true

  ssh_username       = "root"
  ssh_password       = "sentinel-pack"
  ssh_timeout        = "25m"

  # Provisioner seed: cloud-init + generated lab key for first boot.
  cd_files           = ["http/red-user-data.tpl"]
  cd_label           = "CIDATA"

  qemu_binary        = "qemu-system-x86_64"
  qemu_args = [
    ["-device", "virtio-net-pci,netdev=net0"],
    ["-netdev", "user,id=net0,hostfwd=tcp::2222-:22"]
  ]
}

build {
  sources = ["source.qemu.red-vm"]

  # Base: XFCE desktop the streamed session serves, plus attack tooling.
  provisioner "shell" {
    inline = [
      "apt-get update -qq",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends",
      "  xfce4 xfce4-terminal xauth dbus-x11 openssh-server ca-certificates curl jq",
      "  nmap nikto hydra dirb sqlmap tcpdump",
      "apt-get clean",
      "useradd -m -s /bin/bash sentinel || true",
      "mkdir -p /home/sentinel/.ssh && chmod 700 /home/sentinel/.ssh",
      "passwd -l root",   # no root login; only the lab key
      "passwd -l sentinel",
    ]
  }

  # Grab this build's SSH host pubkey so pty_bridge can pin the guest
  # (lab/keys/generate-keys.sh writes it under /etc/sentinel/lab-keys/guests/).
  provisioner "shell" {
    execute_command = "chmod +x {{.Path}}; {{.Vars}} bash {{.Path}}"
    script          = "common/collect-host-key.sh"
  }
}
