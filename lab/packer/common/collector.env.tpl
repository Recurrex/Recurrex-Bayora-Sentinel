# /etc/sentinel/collector.env on blue-vm (rendered at Packer build time).
# One shared collector token; no user credentials ever live in guests.
BROKER_URL=http://10.66.10.1:8000
COLLECTOR_TOKEN=__COLLECTOR_TOKEN__
