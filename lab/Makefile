# Bayora Sentinel lab orchestration.
#
#   make lab-setup        install host deps, define isolated networks
#   make lab-up           boot the three guests (safety check first)
#   make lab-reset-init   take the clean snapshot once, after provisioning
#   make lab-reset        revert all guests to the clean snapshot
#   make lab-down         power every guest off
#   make lab-guard        install/reset the nftables egress guard
#   make lab-e2e          boot lab, nmap red->blue, assert alert <= 5 s
#   make lab-clean        lab-down + guard table removal

LAB_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT    := $(abspath $(LAB_DIR)..)
NETWORKS = sentinel-mgmt sentinel-red sentinel-blue
VMS      = router-vm blue-vm red-vm
SNAPSHOT = lab-clean

.PHONY: lab-setup lab-up lab-reset-init lab-reset lab-down lab-guard lab-e2e lab-clean

lab-setup:
	sudo bash $(LAB_DIR)setup-kvm.sh
	sudo bash $(LAB_DIR)egress-guard.sh

lab-guard:
	sudo bash $(LAB_DIR)egress-guard.sh

lab-up:
	sudo bash $(LAB_DIR)safety-check.sh
	@for net in $(NETWORKS); do \
	  sudo virsh net-start $$net >/dev/null 2>&1 || true; done
	@for vm in $(VMS); do \
	  echo "starting $$vm"; \
	  sudo virsh start $$vm >/dev/null 2>&1 || true; done
	@echo "lab up (suricata needs ~10 s on blue-vm)"

lab-reset-init:
	sudo bash $(LAB_DIR)safety-check.sh
	@for vm in $(VMS); do \
	  sudo virsh snapshot-create-as $$vm $(SNAPSHOT) >/dev/null; \
	  echo "snapshot $(SNAPSHOT) taken on $$vm"; done

lab-reset:
	sudo bash $(LAB_DIR)safety-check.sh
	@for vm in $(VMS); do \
	  sudo virsh snapshot-revert $$vm $(SNAPSHOT) >/dev/null 2>&1 || \
	  sudo virsh start $$vm >/dev/null 2>&1 || true; done
	@echo "lab reset to $(SNAPSHOT)"

lab-down:
	@for vm in $(VMS); do \
	  sudo virsh shutdown $$vm >/dev/null 2>&1 || true; done
	@sudo pkill -f "sshuttle" 2>/dev/null || true
	@echo "lab down"

lab-clean: lab-down
	sudo nft delete table inet sentinel-guard 2>/dev/null || true

lab-e2e:
	python3 $(LAB_DIR)test-e2e.py
