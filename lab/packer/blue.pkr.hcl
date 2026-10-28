# Blue guest (defender / target): Debian 12 + XFCE + detection stack.
# Suricata watches the blue leg; the collector tails eve.json + auth.log
# and posts to the broker across the mgmt net.

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

source "qemu" "blue-vm" {
  iso_url      = var.deb_url
  iso_checksum = var.deb_checksum

  disk_size          = "10G"   # blue holds the detection stack + logs
  format             = "qcow2"
  accelerator        = "kvm"
  cpus               = 2
  memory             = 4096    # suricata wants headroom
  output_directory   = "../../build/blue-vm"
  vm_name            = "blue-vm.qcow2"
  headless           = true

  ssh_username       = "root"
  ssh_password       = "sentinel-pack"
  ssh_timeout        = "25m"

  cd_files           = ["http/blue-user-data.tpl", "common/"]
  cd_label           = "CIDATA"

  qemu_binary        = "qemu-system-x86_64"
  qemu_args = [
    ["-device", "virtio-net-pci,netdev=net0"],
    ["-netdev", "user,id=net0,hostfwd=tcp::2223-:22"]
  ]
}

build {
  sources = ["source.qemu.blue-vm"]

  provisioner "shell" {
    inline = [
      "apt-get update -qq",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends",
      "  xfce4 xfce4-terminal xauth dbus-x11 openssh-server ca-certificates curl jq",
      "  suricata auditd python3 python3-urllib3",
      "apt-get clean",
      "useradd -m -s /bin/bash sentinel || true",
      "mkdir -p /home/sentinel/.ssh && chmod 700 /home/sentinel/.ssh",
      "passwd -l root",
      "passwd -l sentinel",
    ]
  }

  # Sensor baseline: local-only alerts on the blue leg, eve.json in NDJSON.
  provisioner "file" {
    source      = "common/suricata-lab.yaml"
    destination = "/etc/suricata/suricata-lab.yaml"
  }

  provisioner "shell" {
    inline = [
      "suricata -T -c /etc/suricata/suricata-lab.yaml",   # config self-test
      "systemctl disable suricata || true",                # started by lab-up
    ]
  }

  provisioner "file" {
    source      = "common/collector.env.tpl"
    destination = "/etc/sentinel/collector.env"
  }

  provisioner "shell" {
    script = "common/install-collector.sh"
  }

  provisioner "shell" {
    execute_command = "chmod +x {{.Path}}; {{.Vars}} bash {{.Path}}"
    script          = "common/collect-host-key.sh"
  }
}
