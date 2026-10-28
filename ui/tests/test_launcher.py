from __future__ import annotations

import io

import httpx
import pytest

import launcher
from helpers import free_port



def reader_for(values):
    iterator = iter(values)

    def read(_prompt: str) -> str:
        return next(iterator)

    return read


def test_banner_has_small_welcome_large_wordmark_and_pink_violet_colour():
    plain = launcher.render_banner(color=False, width=80)
    assert "W E L C O M E   T O   T H E" in plain
    assert "SENTINEL" in plain
    assert "BAYORA SENTINEL" in plain
    assert "██████" in plain
    assert all(len(line) <= 62 for line in plain.splitlines())

    coloured = launcher.render_banner(color=True, width=80)
    assert "\x1b[38;2;" in coloured
    assert "232;121;249" in coloured  # pinkish-violet wordmark line
    assert "\x1b[0m" in coloured

    compact = launcher.render_banner(color=False, width=50)
    assert "W E L C O M E   T O   T H E" in compact
    assert "SENTINEL" in compact
    assert all(len(line) <= 50 for line in compact.splitlines())


def test_authorize_and_team_choice_are_clear_and_retry():
    messages: list[str] = []
    assert launcher.authorize(
        reader=reader_for(["maybe", "y"]), writer=messages.append
    )
    assert any("Please answer" in message for message in messages)

    assert launcher.authorize(reader=reader_for([""]), writer=messages.append)
    assert not launcher.authorize(reader=reader_for(["n"]), writer=messages.append)

    def closed(_prompt: str) -> str:
        raise EOFError

    assert not launcher.authorize(reader=closed, writer=messages.append)

    assert (
        launcher.choose_team(
            reader=reader_for(["nope", "2"]), writer=messages.append
        )
        == "blue"
    )
    assert (
        launcher.choose_team(reader=reader_for(["red"]), writer=messages.append)
        == "red"
    )
    assert launcher.choose_team(reader=closed, writer=messages.append) is None


def test_main_opens_the_role_handoff_url(monkeypatch):
    class FakeServer:
        base_url = "http://127.0.0.1:9999"
        process = None
        owned = False

        def __init__(self):
            self.stopped = False

        def stop(self):
            self.stopped = True

    fake = FakeServer()
    monkeypatch.setattr(launcher, "start_mock", lambda port: fake)
    monkeypatch.setattr(
        launcher.time, "sleep", lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt)
    )

    opened: list[str] = []
    out = io.StringIO()
    code = launcher.main(
        ["--port", "9999", "--no-color"],
        stream=out,
        reader=reader_for(["", "1"]),
        opener=lambda url, new=0: opened.append(url) or True,
    )

    assert code == 0
    assert fake.stopped
    assert opened == ["http://127.0.0.1:9999/_mock/launch/red"]
    text = out.getvalue()
    assert "W E L C O M E" in text
    assert "Red team selected" in text
    assert "Opened the sandbox desktop in your browser." in text
    assert "eyJ" not in text  # no token payload is printed


def test_start_mock_owns_and_stops_a_working_broker():
    port = free_port()
    server = launcher.start_mock(port, event_interval=60.0, leak_after=999.0)
    try:
        assert server.owned
        assert launcher.mock_ready(server.base_url)
        status = httpx.get(
            server.base_url + "/status",
            headers={"Authorization": "Bearer test"},
            timeout=2,
        )
        assert status.status_code == 200
        assert status.json()["broker"] == "up"

        handoff = httpx.get(
            server.base_url + "/_mock/launch/blue", follow_redirects=False, timeout=2
        )
        assert handoff.status_code == 303
        assert "sentinel_mock_role=blue" in handoff.headers["set-cookie"]
    finally:
        process = server.process
        server.stop()

    assert process is not None
    assert process.poll() is not None
