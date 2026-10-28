from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.app import App, ComposeResult
from textual.widgets import Static

import app as tui
from mock_server import create_app

PAYLOAD = "<img src=x onerror=alert(1)>"


def run(coro):
    return asyncio.run(coro)


class TableHarness(App):
    def compose(self) -> ComposeResult:
        yield tui.EventsTable(id="events")


def test_event_message_is_rendered_as_literal_text_in_data_table():
    event = {
        "id": 42,
        "time": "2026-10-21T08:57:00+05:30",
        "source": "red",
        "type": "attack",
        "message": PAYLOAD,
        "canary_hit": False,
    }

    async def scenario():
        harness = TableHarness()
        async with harness.run_test(size=(120, 32)) as pilot:
            table = harness.query_one(tui.EventsTable)
            table.sync_events([event], "all", follow=False)
            await pilot.pause()

            cells = table.plain_row(42)
            assert cells is not None
            message = cells[4]
            assert message.plain == PAYLOAD
            assert "".join(span.style for span in message.spans) == ""

            buffer = io.StringIO()
            Console(
                file=buffer,
                width=200,
                force_terminal=False,
                color_system=None,
                markup=False,
            ).print(message, end="")
            assert PAYLOAD in buffer.getvalue()

    run(scenario())


def test_leak_and_tamper_cells_are_red_and_canary_is_marked():
    base = {
        "id": 1,
        "time": "2026-10-21T08:57:00+05:30",
        "source": "sentinel",
        "message": "leak",
        "canary_hit": True,
    }
    for event_type in ("leak_alert", "tamper_alert"):
        cells = tui.event_cells({**base, "type": event_type})
        assert "ff9e9e" in str(cells[4].style)
        assert "ff9e9e" in str(cells[3].style)
        assert "CANARY" in cells[4].plain

    canary_response = tui.event_cells(
        {**base, "type": "response", "message": "The file contains: SNTL-CANARY-X"}
    )
    assert "CANARY" in canary_response[4].plain
    assert "SNTL-CANARY-X" in canary_response[4].plain


def test_merge_filter_and_cycle_helpers():
    first = {
        "id": 1,
        "time": "2026-10-21T08:57:00+05:30",
        "source": "red",
        "type": "attack",
        "message": "one",
        "canary_hit": False,
    }
    second = {
        **first,
        "id": 2,
        "type": "defense",
        "source": "blue",
        "message": "two",
    }
    merged, added = tui.merge_events({}, [first, second, {"id": "bad"}, None])
    assert list(merged) == [1, 2]
    assert [event["id"] for event in added] == [1, 2]
    assert tui.filter_events(merged.values(), "attack")[0]["message"] == "one"
    assert tui.filter_events(merged.values(), "defense")[-1]["message"] == "two"
    assert len(tui.filter_events(merged.values(), "all")) == 2
    assert tui.next_filter("all") == "attack"
    assert tui.next_filter("tamper_alert") == "all"
    assert (
        tui.normalize_broker_url("HTTP://127.0.0.1:8099/api/?x=1#frag")
        == "http://127.0.0.1:8099/api"
    )
    assert tui.normalize_broker_url("file:///tmp/broker") is None


def test_status_integrity_and_report_text_are_safe_and_explicit():
    status = tui.status_line(
        {
            "broker": "up",
            "red": "up",
            "blue": "up",
            "ai": "up",
            "test": "running",
            "log_ok": False,
        }
    )
    for piece in ("broker", "up", "test", "running", "audit", "BROKEN"):
        assert piece in status.plain

    assert "chain OK" in tui.integrity_badge({"ok": True, "broken_at": None}).plain
    broken = tui.integrity_badge({"ok": False, "broken_at": 4})
    assert "chain BROKEN at entry 4" in broken.plain

    report = tui.report_text(
        {
            "secure": [PAYLOAD],
            "residual_risk": ["[bold red]not markup[/bold red]"],
            "leaks": 2,
            "tamper_detected": True,
        }
    )
    assert PAYLOAD in report.plain
    assert "[bold red]not markup[/bold red]" in report.plain
    assert "LEAKS" in report.plain
    assert "detected" in report.plain

    buffer = io.StringIO()
    Console(
        file=buffer,
        width=200,
        force_terminal=False,
        color_system=None,
        markup=False,
    ).print(report, end="")
    rendered = buffer.getvalue()
    assert PAYLOAD in rendered
    assert "<img" in rendered


def test_identity_text_never_contains_the_raw_token():
    # A structurally valid token whose payload is displayable but whose signature
    # is opaque. The full string must not appear in the header.
    token = (
        "eyJ1IjoiYWxpY2UiLCJyIjoicmVkIiwiZXhwIjo5OTk5OTk5OTk5fQ."
        + "a" * 64
    )
    rendered = tui.identity_text("http://127.0.0.1:8099", token)
    assert "alice" in rendered.plain
    assert "red" in rendered.plain
    assert token not in rendered.plain
    assert "a" * 64 not in rendered.plain


def test_missing_environment_shows_instructions_without_crashing(monkeypatch):
    monkeypatch.delenv("BROKER_URL", raising=False)
    monkeypatch.delenv("BROKER_TOKEN", raising=False)
    application = tui.SentinelApp()

    async def scenario():
        async with application.run_test(size=(110, 32)) as pilot:
            await pilot.pause()
            content = application.query_one("#error-line", Static).content
            text = content.plain if hasattr(content, "plain") else str(content)
            assert "BROKER_TOKEN" in text
            assert "sentinel tui" in text
            assert application.query_one("#events-panel").border_title == "LIVE EVENTS"

    run(scenario())


def test_tui_polls_mock_broker_and_renders_hostile_event(live_server):
    server = live_server(
        create_app(event_interval=60.0, leak_after=999.0)
    )
    response = server.request("POST", "/attack", json={"prompt": PAYLOAD})
    assert response.status_code == 200

    application = tui.SentinelApp(server.url, "tui-test-token")

    async def scenario():
        async with application.run_test(size=(130, 40)) as pilot:
            async def wait_for_event():
                for _ in range(80):
                    if any(event["message"] == PAYLOAD for event in application.events.values()):
                        return True
                    await pilot.pause()
                    await asyncio.sleep(0.05)
                return False

            assert await wait_for_event()
            event = next(
                event for event in application.events.values() if event["message"] == PAYLOAD
            )
            table = application.query_one(tui.EventsTable)
            cells = table.plain_row(event["id"])
            assert cells is not None
            assert cells[4].plain == PAYLOAD
            assert application.status is not None
            assert application.status.get("broker") == "up"

    run(scenario())
