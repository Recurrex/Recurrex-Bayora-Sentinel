"""Lab event collector -- runs inside blue-vm (installed by cloud-in).

Tails two real guest log sources and forwards each new detection to the
broker over HTTP:

  - /var/log/suricata/eve.json      (Suricata network IDS alerts)
  - /var/log/auth.log               (auditd/SSH host events)

Configured with the collector bearer token (COLLECTOR_TOKEN) reading
/etc/sentinel/collector.env.  Messages sent to the broker are counts and
signatures only -- never the raw payload bytes of any guest traffic.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import urllib.request

BROKER = os.environ.get("BROKER_URL", "http://10.66.10.1:8000")
EVE_LOG = os.environ.get("EVE_LOG", "/var/log/suricata/eve.json")
AUTH_LOG = os.environ.get("AUTH_LOG", "/var/log/auth.log")

# Max per POST payload; a burst is batched but never silently dropped.
BATCH_MAX = 50
POLL_S = 0.5


_offsets: dict[str, int] = {}


def load_token() -> str | None:
    path = Path("/etc/sentinel/collector.env")
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("COLLECTOR_TOKEN="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def tail_from_start(path: str) -> tuple[int, list[str]]:
    """Return (new_offset, line_batch) for file content since the last call."""
    handle = Path(path)
    if not handle.exists():
        return _offsets.get(path, 0), []
    size = handle.stat().st_size
    offset = _offsets.get(path, 0)
    if size <= offset:
        if size < offset:
            _offsets[path] = 0  # rotated / truncated: start over
        return size, []
    with handle.open("rb") as f:
        f.seek(offset)
        new_bytes = f.read()
    _offsets[path] = size
    text = new_bytes.decode("utf-8", "replace")
    lines = [line for line in text.splitlines() if line.strip()]
    return size, lines




def send_events(events: list[dict], token: str) -> None:
    request = urllib.request.Request(
        BROKER + "/ingest",
        data=json.dumps({"events": events}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"broker rejected ingest: HTTP {response.status}")


def suricata_event(raw: str) -> dict | None:
    try:
        record = json.loads(raw)
    except ValueError:
        return None
    if record.get("event_type") != "alert":
        return None
    alert = record.get("alert") or {}
    signature = alert.get("signature") or "unknown"
    src = record.get("src_ip") or "?"
    dst = record.get("dest_ip") or "?"
    return {
        "source": "blue",
        "type": "ids_alert",
        "message": f"suricata alert {signature} {src} -> {dst}",
    }


def host_event(raw: str) -> dict | None:
    # auditd / sshd lines: forward type + first 160 chars only.
    if "sshd" not in raw and "audit" not in raw:
        return None
    detail = raw.strip()[:160]
    return {
        "source": "blue",
        "type": "host_event",
        "message": "host event: " + detail,
    }


def main() -> None:
    token = load_token()
    if not token:
        raise SystemExit("collector token missing at /etc/sentinel/collector.env")
    batch: list[dict] = []
    last_send = 0.0
    print("collector up: tailing", EVE_LOG, "and", AUTH_LOG, flush=True)
    while True:
        for path, mapper in ((EVE_LOG, suricata_event), (AUTH_LOG, host_event)):
            _, lines = tail_from_start(path)
            for line in lines:
                event = mapper(line)
                if event is not None:
                    batch.append(event)
        now = time.time()
        if batch and (len(batch) >= BATCH_MAX or now - last_send > 2.0):
            try:
                send_events(batch[:BATCH_MAX], token)
                batch = batch[BATCH_MAX:]
                last_send = now
            except OSError as error:
                print("ingest failed:", error, flush=True)
                time.sleep(2)
        time.sleep(POLL_S)


if __name__ == "__main__":
    main()
