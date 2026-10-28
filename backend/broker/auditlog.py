"""Hash-chained SQLite audit log (SPEC.md event schema and hash rule).

DB at LOG_DB (default /var/lib/sentinel/audit.db), table `events` with columns
exactly as the event schema.  One process-wide writer lock; every append runs
in a BEGIN IMMEDIATE transaction.  Application code never UPDATEs or DELETEs
rows -- tampering can only happen from outside, and verify() detects it.

Hash rule (exact, from SPEC.md):
    hash = SHA256("|".join([str(id), time, source, type, message,
                            "1" if canary_hit else "0", prev_hash]).encode("utf-8")).hexdigest()
The first entry uses prev_hash = "0" * 64.
"""

import hashlib
import os
import sqlite3
import threading
from datetime import datetime

DEFAULT_LOG_DB = "/var/lib/sentinel/audit.db"

FIRST_PREV_HASH = "0" * 64

SOURCES = ("red", "blue", "ai", "sentinel", "lab")
# "ids_alert"/"host_event" come from the real lab (Suricata / auditd facts
# forwarded by the collector); "vm_action" records lifecycle changes.
TYPES = (
    "attack", "response", "defense", "leak_alert", "selftest", "tamper_alert",
    "ids_alert", "host_event", "vm_action",
)

# Single writer lock: SQLite would serialize us anyway, but the lock lets us
# read the tail (id, prev_hash) and insert in one atomic step.
_WRITE_LOCK = threading.Lock()


def db_path() -> str:
    return os.environ.get("LOG_DB", DEFAULT_LOG_DB)


def _connect() -> sqlite3.Connection:
    path = db_path()
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY,
            time       TEXT NOT NULL,
            source     TEXT NOT NULL,
            type       TEXT NOT NULL,
            message    TEXT NOT NULL,
            canary_hit INTEGER NOT NULL DEFAULT 0,
            prev_hash  TEXT NOT NULL,
            hash       TEXT NOT NULL
        )
        """
    )
    return conn


def compute_hash(event_id, time_str, source, event_type, message, canary_hit, prev_hash) -> str:
    """SPEC.md hash rule, verbatim."""
    payload = "|".join(
        [str(event_id), time_str, source, event_type, message,
         "1" if canary_hit else "0", prev_hash]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _row_to_event(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "time": row["time"],
        "source": row["source"],
        "type": row["type"],
        "message": row["message"],
        "canary_hit": bool(row["canary_hit"]),
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }


def append(source: str, event_type: str, message: str, canary_hit: bool = False) -> dict:
    """Append one event; returns the stored event (with id and hashes)."""
    if source not in SOURCES:
        raise ValueError(f"invalid source: {source!r}")
    if event_type not in TYPES:
        raise ValueError(f"invalid type: {event_type!r}")
    with _WRITE_LOCK:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            tail = conn.execute(
                "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            next_id = tail["id"] + 1 if tail else 1
            prev_hash = tail["hash"] if tail else FIRST_PREV_HASH
            time_str = datetime.now().astimezone().isoformat(timespec="seconds")
            event_hash = compute_hash(
                next_id, time_str, source, event_type, message, canary_hit, prev_hash
            )
            conn.execute(
                "INSERT INTO events (id, time, source, type, message, canary_hit, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (next_id, time_str, source, event_type, message,
                 1 if canary_hit else 0, prev_hash, event_hash),
            )
            conn.commit()
            return {
                "id": next_id,
                "time": time_str,
                "source": source,
                "type": event_type,
                "message": message,
                "canary_hit": bool(canary_hit),
                "prev_hash": prev_hash,
                "hash": event_hash,
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def list_events(since: int = 0) -> list[dict]:
    """All events with id > since, in id order."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id ASC", (since,)
        ).fetchall()
        return [_row_to_event(r) for r in rows]
    finally:
        conn.close()


def count_canary_hits() -> int:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE canary_hit = 1"
        ).fetchone()
        return row["n"]
    finally:
        conn.close()


def has_tamper_alert() -> bool:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM events WHERE type = 'tamper_alert' LIMIT 1"
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def tamper_alert_exists(message: str) -> bool:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM events WHERE type = 'tamper_alert' AND message = ? LIMIT 1",
            (message,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def verify() -> tuple[bool, int | None]:
    """Recompute the whole chain.

    Returns (True, None) if intact, else (False, id of the first bad entry).
    An entry is bad if its id breaks the contiguous 1,2,3... sequence
    (a row was deleted), its prev_hash is not the previous entry's hash, or
    its stored hash does not match the recomputed one.
    """
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
    finally:
        conn.close()
    prev_hash = FIRST_PREV_HASH
    expected_id = 1
    for row in rows:
        if row["id"] != expected_id:
            return False, row["id"]
        if row["prev_hash"] != prev_hash:
            return False, row["id"]
        recomputed = compute_hash(
            row["id"], row["time"], row["source"], row["type"],
            row["message"], bool(row["canary_hit"]), row["prev_hash"],
        )
        if recomputed != row["hash"]:
            return False, row["id"]
        prev_hash = row["hash"]
        expected_id += 1
    return True, None
