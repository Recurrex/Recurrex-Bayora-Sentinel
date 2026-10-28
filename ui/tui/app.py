#!/usr/bin/env python3
"""Bayora Sentinel terminal dashboard.

Reads ``BROKER_URL`` and ``BROKER_TOKEN`` from the environment (the sentinel
CLI sets both for ``sentinel tui``), then polls the broker's read API.

The token is only sent in the Authorization header. It is never printed,
logged, or included in an error message.

Network calls run in Textual worker threads so the UI never blocks. Event
messages are attacker-controlled: every value from the broker is rendered
through ``rich.text.Text`` (or ``str`` values passed to Text.append), never
through Rich markup or f-strings with markup enabled.

Keys: r refresh report, v verify log now, f cycle type filter, q quit.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import DataTable, Footer, Static

# ---------------------------------------------------------------------------
# Constants shared with the web dashboard
# ---------------------------------------------------------------------------

KNOWN_TYPES = (
    "attack",
    "response",
    "defense",
    "leak_alert",
    "selftest",
    "tamper_alert",
)

FILTER_CYCLE = ("all",) + KNOWN_TYPES
ALERT_TYPES = frozenset({"leak_alert", "tamper_alert"})
MAX_EVENTS = 500
MAX_STORED_EVENTS = 2000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024

INK = "#e3eff0"
INK_SOFT = "#c3d4d6"
MUTED = "#8ba2a8"
FAINT = "#6f878d"
ACCENT = "#69ddcc"
GOOD = "#79d995"
WARN = "#e6be73"
BAD = "#ff7b7b"
BAD_SOFT = "#ff9e9e"
BLUE = "#8cc7ff"
VIOLET = "#c3a7ff"


# ---------------------------------------------------------------------------
# Small pure helpers (also covered by tests)
# ---------------------------------------------------------------------------


class BrokerError(Exception):
    """A safe, user-facing network error. Never contains the token."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def normalize_broker_url(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    # Strip query, fragment and trailing slashes before appending API paths.
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


def broker_label(url: str | None) -> str:
    if not url:
        return "no broker"
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return "broker"
    host = parsed.hostname or "broker"
    port = parsed.port
    return f"{host}:{port}" if port else host


def decode_claims(token: str | None) -> dict[str, Any] | None:
    """Decode the display payload only. No signature check; broker is authority."""
    if not isinstance(token, str) or not token or "." not in token:
        return None
    try:
        body = token.split(".", 1)[0]
        padding = "=" * (-len(body) % 4)
        raw = base64.urlsafe_b64decode(body + padding)
        payload = json.loads(raw.decode("utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def identity_text(url: str | None, token: str | None, error: str | None = None) -> Text:
    text = Text()
    text.append("BAYORA ", style=f"bold {INK}")
    text.append("SENTINEL", style=f"bold {ACCENT}")
    text.append("   read-only console", style=FAINT)
    text.append("\n")
    claims = decode_claims(token)
    user = ""
    role = ""
    if claims:
        if isinstance(claims.get("u"), str):
            user = claims["u"][:120]
        if isinstance(claims.get("r"), str):
            role = claims["r"][:40]
    if error:
        text.append("not signed in", style=f"bold {BAD}")
    else:
        text.append(user or "unknown", style=f"bold {INK_SOFT}")
        text.append(" · team ", style=MUTED)
        text.append(role or "unknown", style=ACCENT)
        text.append("   ", style=MUTED)
        text.append(broker_label(url), style=FAINT)
    return text


def format_event_time(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "—"
    raw = value.strip()
    normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    try:
        parsed = datetime.fromisoformat(normalized)
        return parsed.strftime("%H:%M:%S")
    except ValueError:
        return raw[:24]


def normalize_event(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, Mapping):
        return None
    event_id = raw.get("id")
    if isinstance(event_id, bool) or not isinstance(event_id, int) or event_id <= 0:
        return None

    def string_field(name: str, fallback: str = "") -> str:
        value = raw.get(name)
        return value if isinstance(value, str) else fallback

    message = string_field("message")
    # A message is the only large attacker-controlled field. Cap what we keep
    # in the table so a single hostile entry cannot exhaust the terminal.
    if len(message) > 8000:
        message = message[:8000] + "…"

    return {
        "id": event_id,
        "time": string_field("time"),
        "source": string_field("source", "unknown"),
        "type": string_field("type", "unknown"),
        "message": message,
        "canary_hit": raw.get("canary_hit") is True,
    }


def merge_events(
    existing: Mapping[int, dict[str, Any]],
    incoming: Any,
    limit: int = MAX_STORED_EVENTS,
) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    """Merge a broker page into the cache, returning (events, newly added)."""
    merged = dict(existing)
    added: list[dict[str, Any]] = []
    if not isinstance(incoming, list):
        return merged, added
    for raw in incoming:
        event = normalize_event(raw)
        if event is None:
            continue
        if event["id"] not in merged:
            added.append(event)
        merged[event["id"]] = event
    if limit > 0 and len(merged) > limit:
        for event_id in sorted(merged, reverse=True)[limit:]:
            del merged[event_id]
    return merged, added


def filter_events(events: Iterable[dict[str, Any]], type_filter: str) -> list[dict[str, Any]]:
    ordered = sorted(events, key=lambda event: int(event["id"]))
    if type_filter == "all":
        return ordered
    return [event for event in ordered if event.get("type") == type_filter]


def next_filter(current: str) -> str:
    try:
        index = FILTER_CYCLE.index(current)
    except ValueError:
        return "all"
    return FILTER_CYCLE[(index + 1) % len(FILTER_CYCLE)]


def event_cells(event: Mapping[str, Any]) -> tuple[Text, Text, Text, Text, Text]:
    """Build DataTable cells. Text never interprets markup."""
    event_type = str(event.get("type", "unknown"))
    canary = event.get("canary_hit") is True
    alert = event_type in ALERT_TYPES

    base = f"bold {BAD_SOFT}" if alert else INK_SOFT
    id_cell = Text(str(event.get("id", "")), style=f"{MUTED}")
    time_cell = Text(format_event_time(event.get("time")), style=FAINT)
    source_cell = Text(str(event.get("source", "unknown")), style=base)

    type_style = f"bold {BAD_SOFT}" if alert else INK_SOFT
    if event_type == "attack":
        type_style = BAD_SOFT
    elif event_type == "response":
        type_style = BLUE
    elif event_type == "defense":
        type_style = ACCENT
    elif event_type == "selftest":
        type_style = VIOLET
    type_cell = Text(event_type, style=type_style)

    message_cell = Text(style=base)
    if canary:
        message_cell.append("CANARY  ", style=f"bold {WARN}")
    message_cell.append(str(event.get("message", "")))
    if alert:
        message_cell.stylize(f"bold {BAD_SOFT}")

    return id_cell, time_cell, source_cell, type_cell, message_cell


def status_line(status: Mapping[str, Any] | None, error: str | None = None) -> Text:
    """A colour-plus-text status line: never colour alone."""
    text = Text()
    if not isinstance(status, Mapping):
        values: dict[str, str] = {}
    else:
        values = {key: status.get(key) for key in ("broker", "red", "blue", "ai", "test", "log_ok")}

    labels = {
        "broker": "broker",
        "red": "red",
        "blue": "blue",
        "ai": "ai",
        "test": "test",
        "log_ok": "audit",
    }

    for key in ("broker", "red", "blue", "ai", "test", "log_ok"):
        raw = values.get(key)
        if key == "log_ok" and isinstance(raw, bool):
            value = "ok" if raw else "BROKEN"
            style = GOOD if raw else BAD
        elif key == "test":
            value = raw if isinstance(raw, str) and raw.strip() else "unknown"
            style = WARN if value == "running" else FAINT
        else:
            value = raw if isinstance(raw, str) and raw.strip() else "unknown"
            if value == "up":
                style = GOOD
            elif value == "down":
                style = BAD
            else:
                style = FAINT
        text.append("● ", style=style)
        text.append(labels[key] + " ", style=FAINT)
        text.append(value, style=f"bold {style}" if style != FAINT else style)
        if key != "log_ok":
            text.append("   ", style=FAINT)

    if error:
        text.append("  ·  ", style=FAINT)
        text.append(error, style=f"bold {BAD}")
    return text


def integrity_badge(result: Mapping[str, Any] | None, error: str | None = None) -> Text:
    if error:
        return Text("● integrity unavailable", style=f"bold {WARN}")
    if not isinstance(result, Mapping) or not isinstance(result.get("ok"), bool):
        return Text("● not checked", style=FAINT)
    if result["ok"]:
        return Text("● chain OK", style=f"bold {GOOD}")
    broken = result.get("broken_at")
    label = str(broken) if isinstance(broken, int) and not isinstance(broken, bool) else "?"
    return Text(f"● chain BROKEN at entry {label}", style=f"bold {BAD}")


def integrity_meta(result: Mapping[str, Any] | None, error: str | None = None) -> Text:
    if error:
        return Text(error, style=MUTED)
    if not isinstance(result, Mapping) or not isinstance(result.get("ok"), bool):
        return Text("Waiting for /verify-log.", style=FAINT)
    checked = datetime.now().strftime("%H:%M:%S")
    if result["ok"]:
        return Text(f"checked {checked} · SHA-256 chain recomputed", style=FAINT)
    return Text(f"checked {checked} · an audit entry no longer matches its hash", style=MUTED)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def report_text(report: Mapping[str, Any] | None, error: str | None = None) -> Text:
    if error:
        text = Text()
        text.append("Report unavailable\n", style=f"bold {BAD}")
        text.append(error, style=MUTED)
        return text
    if not isinstance(report, Mapping):
        return Text("Waiting for /report…", style=FAINT)

    text = Text()
    leaks = report.get("leaks")
    tampered = report.get("tamper_detected") is True

    text.append("LEAKS  ", style=f"bold {FAINT}")
    text.append(
        str(leaks) if isinstance(leaks, int) and not isinstance(leaks, bool) else "—",
        style=f"bold {INK}",
    )
    text.append("     TAMPER  ", style=f"bold {FAINT}")
    if tampered:
        text.append("detected", style=f"bold {BAD}")
    else:
        text.append("none", style=f"bold {GOOD}")
    text.append("\n\n")

    text.append("SECURE\n", style=f"bold {ACCENT}")
    secure = _string_list(report.get("secure"))
    if secure:
        for item in secure:
            text.append("  ▸ ", style=GOOD)
            text.append(item + "\n", style=INK_SOFT)
    else:
        text.append("  None reported.\n", style=FAINT)

    text.append("\nRESIDUAL RISK\n", style=f"bold {WARN}")
    risks = _string_list(report.get("residual_risk"))
    if risks:
        for item in risks:
            text.append("  ▸ ", style=WARN)
            text.append(item + "\n", style=INK_SOFT)
    else:
        text.append("  None reported.\n", style=FAINT)
    return text


# ---------------------------------------------------------------------------
# Broker client (stdlib only; called from worker threads)
# ---------------------------------------------------------------------------


@dataclass
class BrokerClient:
    base_url: str
    token: str
    timeout: float = 4.0

    def _get_json(self, path: str) -> Any:
        request = urllib.request.Request(
            self.base_url + path,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/json",
                "User-Agent": "bayora-sentinel-tui/1.0",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                raise BrokerError("Session expired. Run sentinel again.", 401) from None
            raise BrokerError(f"Broker returned HTTP {exc.code}.", exc.code) from None
        except urllib.error.URLError:
            raise BrokerError("Broker unreachable. Retrying.") from None
        except (TimeoutError, OSError):
            raise BrokerError("Broker did not answer. Retrying.") from None

        if len(payload) > MAX_RESPONSE_BYTES:
            raise BrokerError("Broker response was too large.")
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BrokerError("Broker returned invalid JSON.") from None

    def get_events(self, since: int) -> Any:
        query = urllib.parse.urlencode({"since": max(0, int(since))})
        return self._get_json(f"/events?{query}")

    def get_status(self) -> Any:
        return self._get_json("/status")

    def get_report(self) -> Any:
        return self._get_json("/report")

    def verify_log(self) -> Any:
        return self._get_json("/verify-log")


# ---------------------------------------------------------------------------
# Events table
# ---------------------------------------------------------------------------


class EventsTable(DataTable):
    """DataTable that appends safely and keeps the newest event visible."""

    def on_mount(self) -> None:
        self.cursor_type = "row"
        self.zebra_stripes = True
        self.add_column("ID", width=5, key="id")
        self.add_column("TIME", width=9, key="time")
        self.add_column("SOURCE", width=8, key="source")
        self.add_column("TYPE", width=13, key="type")
        self.add_column("MESSAGE", key="message")
        self._row_ids: list[str] = []
        self._row_id_set: set[str] = set()
        self._filter = "all"

    def sync_events(
        self,
        events: Iterable[dict[str, Any]],
        type_filter: str,
        *,
        follow: bool = True,
    ) -> int:
        desired = filter_events(events, type_filter)[-MAX_EVENTS:]
        desired_ids = [str(event["id"]) for event in desired]
        desired_set = set(desired_ids)

        needs_rebuild = (
            self._filter != type_filter
            or not self._row_id_set.issubset(desired_set)
            or self._row_ids != desired_ids[: len(self._row_ids)]
        )
        if needs_rebuild:
            self.clear(columns=False)
            self._row_ids = []
            self._row_id_set = set()

        added = 0
        for event, key in zip(desired, desired_ids):
            if key in self._row_id_set:
                continue
            self.add_row(*event_cells(event), key=key, height=None)
            self._row_ids.append(key)
            self._row_id_set.add(key)
            added += 1

        self._filter = type_filter
        if added and follow:
            self.call_after_refresh(
                self.scroll_end,
                animate=False,
                immediate=True,
                x_axis=False,
            )
        return added

    def plain_row(self, event_id: int) -> list[Text] | None:
        """Test helper: return the cells for a row, if it is present."""
        try:
            row = self.get_row(str(event_id))
        except Exception:
            return None
        return [cell if isinstance(cell, Text) else Text(str(cell)) for cell in row]


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class SentinelApp(App[None]):
    TITLE = "Bayora Sentinel"
    SUB_TITLE = "security console"

    CSS = """
    Screen {
        background: #071013;
        color: #e3eff0;
    }

    #topbar {
        height: 3;
        padding: 0 1;
        background: #0b171c;
        border-bottom: solid #1d3037;
        content-align: left middle;
    }

    #status-line {
        height: 2;
        padding: 0 1;
        background: #0a1418;
        border-bottom: solid #14252b;
        content-align: left middle;
    }

    #body {
        height: 1fr;
        padding: 0 0 0 0;
    }

    #events-panel {
        width: 2fr;
        height: 100%;
        margin: 1 1 0 1;
        border: round #2a454e;
        border-title-color: #69ddcc;
        border-subtitle-color: #6f878d;
        background: #0d181d;
    }

    EventsTable {
        height: 1fr;
        width: 100%;
        background: #0d181d;
        color: #c3d4d6;
        scrollbar-color: #2a454e;
        scrollbar-color-hover: #3b616c;
        scrollbar-color-active: #69ddcc;
    }

    EventsTable > .datatable--header {
        background: #101e24;
        color: #6f878d;
        text-style: bold;
    }

    EventsTable > .datatable--cursor {
        background: #15312f;
        color: #e3eff0;
    }

    EventsTable > .datatable--hover {
        background: #10242a;
    }

    #side {
        width: 1fr;
        height: 100%;
        margin: 1 1 0 0;
        layout: vertical;
    }

    #integrity-panel {
        height: 8;
        border: round #2a454e;
        border-title-color: #69ddcc;
        background: #0d181d;
        padding: 0 1;
    }

    #integrity-badge {
        height: 1;
        margin-top: 1;
    }

    #integrity-meta {
        height: 2;
        color: #8ba2a8;
    }

    #report-panel {
        height: 1fr;
        margin-top: 1;
        border: round #2a454e;
        border-title-color: #69ddcc;
        background: #0d181d;
        scrollbar-color: #2a454e;
        scrollbar-color-hover: #3b616c;
    }

    #report-body {
        width: 100%;
        padding: 0 1;
    }

    #error-line {
        height: 2;
        padding: 0 1;
        background: #0a1418;
        border-top: solid #14252b;
        content-align: left middle;
    }

    Footer {
        background: #0b171c;
        color: #8ba2a8;
    }

    Footer > .footer--key {
        background: #14252b;
        color: #69ddcc;
    }

    Footer > .footer--description {
        color: #6f878d;
    }

    .narrow #body {
        layout: vertical;
    }

    .narrow #events-panel {
        width: 100%;
        height: 1fr;
        margin: 1 1 0 1;
    }

    .narrow #side {
        width: 100%;
        height: 9;
        margin: 0 1 0 1;
        layout: horizontal;
    }

    .narrow #integrity-panel {
        width: 42%;
        height: 100%;
        margin-right: 1;
    }

    .narrow #report-panel {
        width: 58%;
        height: 100%;
        margin-top: 0;
    }
    """

    BINDINGS = [
        Binding("r", "refresh_report", "refresh report", show=True),
        Binding("v", "verify_now", "verify log", show=True),
        Binding("f", "cycle_filter", "filter", show=True),
        Binding("q", "quit", "quit", show=True),
    ]

    def __init__(
        self,
        broker_url: str | None = None,
        broker_token: str | None = None,
    ) -> None:
        super().__init__()
        raw_url = broker_url if broker_url is not None else os.environ.get("BROKER_URL")
        raw_token = broker_token if broker_token is not None else os.environ.get("BROKER_TOKEN")

        self.broker_url = normalize_broker_url(raw_url)
        self._token = raw_token.strip() if isinstance(raw_token, str) else ""
        self.client: BrokerClient | None = None

        self.events: dict[int, dict[str, Any]] = {}
        self.cursor = 0
        self.type_filter = "all"
        self.status: dict[str, Any] | None = None
        self.verify_result: dict[str, Any] | None = None
        self.report: dict[str, Any] | None = None
        self.report_checked = False

        self._busy = {"events": False, "status": False, "verify": False, "report": False}
        self._errors: dict[str, str] = {}
        self._poll_timers: list[Any] = []
        self._fatal = False
        self._config_error: str | None = None

        if not self._token:
            self._config_error = "BROKER_TOKEN is not set. Launch with sentinel tui."
        elif not self.broker_url:
            self._config_error = "BROKER_URL is missing or invalid. Launch with sentinel tui."
        else:
            self.client = BrokerClient(self.broker_url, self._token)

    # -- layout ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(identity_text(self.broker_url, self._token, self._config_error), id="topbar")
        yield Static(status_line(None), id="status-line")
        with Horizontal(id="body"):
            with Vertical(id="events-panel"):
                yield EventsTable(id="events-table")
            with Vertical(id="side"):
                with Vertical(id="integrity-panel"):
                    yield Static(integrity_badge(None), id="integrity-badge")
                    yield Static(integrity_meta(None), id="integrity-meta")
                with VerticalScroll(id="report-panel"):
                    yield Static(report_text(None), id="report-body")
        yield Static(id="error-line")
        yield Footer()

    def on_resize(self, event) -> None:
        self.screen.set_class(event.size.width < 95, "narrow")

    def on_mount(self) -> None:
        events_panel = self.query_one("#events-panel")
        events_panel.border_title = "LIVE EVENTS"
        self.query_one("#integrity-panel").border_title = "INTEGRITY"
        self.query_one("#report-panel").border_title = "REPORT"
        self._update_filter_subtitle()
        self._render_error_line()

        if self._config_error:
            self._fatal = True
            self._render_status()
            self._render_integrity()
            self._render_report()
            self._set_error("config", self._config_error)
            return

        self._poll_timers = [
            self.set_interval(1.0, self._tick_events),
            self.set_interval(3.0, self._tick_status),
            self.set_interval(10.0, self._tick_verify),
        ]

        self._tick_events()
        self._tick_status()
        self._tick_verify()
        self._tick_report()
        self.query_one(EventsTable).focus()

    # -- rendering ---------------------------------------------------------

    def _update_filter_subtitle(self) -> None:
        panel = self.query_one("#events-panel")
        count = len(filter_events(self.events.values(), self.type_filter))
        smooth = "event" if count == 1 else "events"
        panel.border_subtitle = f"filter: {self.type_filter} · {count} {smooth}"

    def _fatal_error(self) -> str | None:
        return self._config_error if self._fatal else None

    def _render_status(self) -> None:
        error = self._errors.get("status") or self._fatal_error()
        self.query_one("#status-line", Static).update(status_line(self.status, error))

    def _render_integrity(self) -> None:
        error = self._errors.get("verify") or self._fatal_error()
        self.query_one("#integrity-badge", Static).update(
            integrity_badge(self.verify_result, error)
        )
        self.query_one("#integrity-meta", Static).update(
            integrity_meta(self.verify_result, error)
        )

    def _render_report(self) -> None:
        error = self._errors.get("report") or self._fatal_error()
        self.query_one("#report-body", Static).update(report_text(self.report, error))

    def _render_error_line(self) -> None:
        line = self.query_one("#error-line", Static)
        if self._fatal and self._config_error:
            line.update(Text("! " + self._config_error, style=f"bold {BAD}"))
            return
        if self._errors:
            group, message = next(reversed(self._errors.items()))
            prefix = "! "
            line.update(Text(prefix + message, style=f"bold {BAD}"))
            return
        line.update(
            Text(
                "Ready · polling the broker · token stays in memory",
                style=FAINT,
            )
        )

    def _set_error(self, group: str, message: str) -> None:
        self._errors[group] = message
        self._render_error_line()

    def _clear_error(self, group: str) -> None:
        if group in self._errors:
            del self._errors[group]
            self._render_error_line()

    # -- timers ------------------------------------------------------------

    def _tick_events(self) -> None:
        if self._fatal or self.client is None or self._busy["events"]:
            return
        self._busy["events"] = True
        self._fetch_events(self.cursor)

    def _tick_status(self) -> None:
        if self._fatal or self.client is None or self._busy["status"]:
            return
        self._busy["status"] = True
        self._fetch_status()

    def _tick_verify(self) -> None:
        if self._fatal or self.client is None or self._busy["verify"]:
            return
        self._busy["verify"] = True
        self._fetch_verify()

    def _tick_report(self) -> None:
        if self._fatal or self.client is None or self._busy["report"]:
            return
        self._busy["report"] = True
        self._fetch_report()

    # -- workers -----------------------------------------------------------

    @work(thread=True, group="events")
    def _fetch_events(self, since: int) -> None:
        try:
            payload = self.client.get_events(since) if self.client else []
        except BrokerError as exc:
            self._from_thread(self._on_network_error, "events", exc)
            return
        except Exception:
            self._from_thread(
                self._on_network_error, "events", BrokerError("Unexpected network error.")
            )
            return
        self._from_thread(self._on_events, payload)

    @work(thread=True, group="status")
    def _fetch_status(self) -> None:
        try:
            payload = self.client.get_status() if self.client else None
        except BrokerError as exc:
            self._from_thread(self._on_network_error, "status", exc)
            return
        except Exception:
            self._from_thread(
                self._on_network_error, "status", BrokerError("Unexpected network error.")
            )
            return
        self._from_thread(self._on_status, payload)

    @work(thread=True, group="verify")
    def _fetch_verify(self) -> None:
        try:
            payload = self.client.verify_log() if self.client else None
        except BrokerError as exc:
            self._from_thread(self._on_network_error, "verify", exc)
            return
        except Exception:
            self._from_thread(
                self._on_network_error, "verify", BrokerError("Unexpected network error.")
            )
            return
        self._from_thread(self._on_verify, payload)

    @work(thread=True, group="report")
    def _fetch_report(self) -> None:
        try:
            payload = self.client.get_report() if self.client else None
        except BrokerError as exc:
            self._from_thread(self._on_network_error, "report", exc)
            return
        except Exception:
            self._from_thread(
                self._on_network_error, "report", BrokerError("Unexpected network error.")
            )
            return
        self._from_thread(self._on_report, payload)

    def _from_thread(self, callback: Any, *args: Any) -> None:
        try:
            self.call_from_thread(callback, *args)
        except Exception:
            # The app is shutting down; there is nothing to update.
            pass

    # -- worker results ----------------------------------------------------

    def _on_network_error(self, group: str, error: BrokerError) -> None:
        self._busy[group] = False
        if self._fatal:
            return
        if error.status == 401:
            self._fail("Session expired. Run sentinel again.")
            return
        self._set_error(group, error.message)
        if group == "status":
            self._render_status()
        elif group == "verify":
            self._render_integrity()
        elif group == "report":
            self._render_report()

    def _fail(self, message: str) -> None:
        if self._fatal:
            return
        self._fatal = True
        self._config_error = message
        for timer in self._poll_timers:
            timer.stop()
        self._poll_timers.clear()
        self._errors["session"] = message
        self.query_one("#topbar", Static).update(
            identity_text(self.broker_url, self._token, message)
        )
        self._render_error_line()
        self._render_status()
        self._render_integrity()
        self._render_report()

    def _on_events(self, payload: Any) -> None:
        self._busy["events"] = False
        if self._fatal:
            return
        if not isinstance(payload, list):
            self._set_error("events", "Unexpected /events response from the broker.")
            return

        self.events, added = merge_events(self.events, payload)
        if self.events:
            self.cursor = max(self.cursor, max(self.events))
        if added:
            self.query_one(EventsTable).sync_events(self.events.values(), self.type_filter)
            self._update_filter_subtitle()
            if any(event["type"] == "tamper_alert" for event in added):
                self._tick_verify()
            if any(event["type"] in ALERT_TYPES for event in added):
                self._tick_report()
        self._clear_error("events")

    def _on_status(self, payload: Any) -> None:
        self._busy["status"] = False
        if self._fatal:
            return
        if not isinstance(payload, dict):
            self._set_error("status", "Unexpected /status response from the broker.")
            self._render_status()
            return
        self.status = payload
        self._clear_error("status")
        self._render_status()

    def _on_verify(self, payload: Any) -> None:
        self._busy["verify"] = False
        if self._fatal:
            return
        if not isinstance(payload, dict):
            self._set_error("verify", "Unexpected /verify-log response from the broker.")
            self._render_integrity()
            return
        self.verify_result = payload
        self._clear_error("verify")
        self._render_integrity()

    def _on_report(self, payload: Any) -> None:
        self._busy["report"] = False
        if self._fatal:
            return
        if not isinstance(payload, dict):
            self._set_error("report", "Unexpected /report response from the broker.")
            self._render_report()
            return
        self.report = payload
        self.report_checked = True
        self._clear_error("report")
        self._render_report()

    # -- actions -----------------------------------------------------------

    def action_refresh_report(self) -> None:
        if self._fatal:
            self._set_error("session", self._config_error or "Session unavailable.")
            return
        self._tick_report()

    def action_verify_now(self) -> None:
        if self._fatal:
            self._set_error("session", self._config_error or "Session unavailable.")
            return
        self._tick_verify()

    def action_cycle_filter(self) -> None:
        self.type_filter = next_filter(self.type_filter)
        self._update_filter_subtitle()
        self.query_one(EventsTable).sync_events(self.events.values(), self.type_filter)


def main() -> None:
    SentinelApp().run()


if __name__ == "__main__":
    main()
