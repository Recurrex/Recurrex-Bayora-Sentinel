from __future__ import annotations

import base64
import hashlib
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from mock_server import create_app


EVENT_KEYS = {
    "id",
    "time",
    "source",
    "type",
    "message",
    "canary_hit",
    "prev_hash",
    "hash",
}
HEADERS = {"Authorization": "Bearer test-token"}


def make_client(**kwargs) -> TestClient:
    kwargs.setdefault("event_interval", 60.0)
    kwargs.setdefault("leak_after", 999.0)
    return TestClient(create_app(**kwargs))


def spec_hash(entry: dict) -> str:
    payload = "|".join(
        [
            str(entry["id"]),
            entry["time"],
            entry["source"],
            entry["type"],
            entry["message"],
            "1" if entry["canary_hit"] else "0",
            entry["prev_hash"],
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def assert_valid_chain(events: list[dict]) -> None:
    previous = "0" * 64
    for index, entry in enumerate(events, start=1):
        assert set(entry) == EVENT_KEYS
        assert entry["id"] == index
        assert entry["prev_hash"] == previous
        assert entry["hash"] == spec_hash(entry)
        previous = entry["hash"]


def test_get_endpoints_have_spec_shapes():
    with make_client() as client:
        status = client.get("/status", headers=HEADERS)
        assert status.status_code == 200
        assert set(status.json()) == {"red", "blue", "ai", "broker", "test", "log_ok"}
        assert status.json()["test"] in {"idle", "running"}
        assert isinstance(status.json()["log_ok"], bool)

        events = client.get("/events", headers=HEADERS)
        assert events.status_code == 200
        assert isinstance(events.json(), list)
        assert events.json()
        assert all(set(event) == EVENT_KEYS for event in events.json())
        assert all(
            event["source"] in {"red", "blue", "ai", "sentinel"}
            for event in events.json()
        )
        assert all(
            event["type"]
            in {"attack", "response", "defense", "leak_alert", "selftest", "tamper_alert"}
            for event in events.json()
        )
        assert_valid_chain(events.json())

        report = client.get("/report", headers=HEADERS)
        assert report.status_code == 200
        assert set(report.json()) == {
            "secure",
            "residual_risk",
            "leaks",
            "tamper_detected",
        }
        assert all(isinstance(item, str) for item in report.json()["secure"])
        assert all(isinstance(item, str) for item in report.json()["residual_risk"])
        assert isinstance(report.json()["leaks"], int)
        assert isinstance(report.json()["tamper_detected"], bool)

        verify = client.get("/verify-log", headers=HEADERS)
        assert verify.status_code == 200
        assert set(verify.json()) == {"ok", "broken_at"}
        assert verify.json() == {"ok": True, "broken_at": None}


def test_auth_is_required_for_every_read_endpoint():
    with make_client() as client:
        for path in ("/events", "/status", "/report", "/verify-log"):
            response = client.get(path)
            assert response.status_code == 401, path
            response = client.get(path, headers={"Authorization": "Basic nope"})
            assert response.status_code == 401, path


def test_since_is_exclusive_and_polling_returns_new_events():
    with make_client(event_interval=0.05) as client:
        first = client.get("/events", headers=HEADERS).json()
        assert first
        last_id = first[-1]["id"]

        deadline = time.monotonic() + 3
        new_events: list[dict] = []
        while time.monotonic() < deadline and not new_events:
            new_events = client.get(
                f"/events?since={last_id}", headers=HEADERS
            ).json()
            if not new_events:
                time.sleep(0.05)
        assert new_events
        assert all(event["id"] > last_id for event in new_events)
        assert new_events == sorted(new_events, key=lambda event: event["id"])


def test_websocket_delivers_events():
    with make_client(event_interval=0.05) as client:
        with client.websocket_connect("/ws/events?token=anything") as socket:
            event = socket.receive_json()
            assert set(event) == EVENT_KEYS
            assert event["hash"] == spec_hash(event)
            assert event["id"] >= 1


def test_websocket_requires_token():
    from starlette.websockets import WebSocketDisconnect

    with make_client(event_interval=0.05) as client:
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect("/ws/events") as socket:
                socket.receive_json()
        assert excinfo.value.code == 4401


def test_write_endpoints_for_development():
    with make_client() as client:
        bad = client.post("/attack", headers=HEADERS, json={})
        assert bad.status_code == 422

        attack = client.post(
            "/attack",
            headers=HEADERS,
            json={"prompt": "<img src=x onerror=alert(1)>"},
        )
        assert attack.status_code == 200
        body = attack.json()
        assert set(body) == {"reply", "verdict", "blocked", "egress"}
        assert isinstance(body["reply"], str)
        # The sandbox judge rules on every turn, and the stub refuses.
        assert body["verdict"]["status"] in {"saved", "penetrated"}
        assert isinstance(body["blocked"], bool)
        assert body["egress"].count(".") == 3

        defense = client.post(
            "/defense", headers=HEADERS, json={"rule": "reject canary prompts"}
        )
        assert defense.status_code == 200
        assert defense.json() == {"ok": True}

        selftest = client.post(
            "/selftest",
            headers=HEADERS,
            json={
                "name": "red_cannot_read_blue_home",
                "passed": True,
                "detail": "PermissionError as expected",
            },
        )
        assert selftest.status_code == 200
        assert selftest.json() == {"ok": True}

        events = client.get("/events?since=0", headers=HEADERS).json()
        assert any(
            event["type"] == "attack"
            and event["message"] == "<img src=x onerror=alert(1)>"
            for event in events
        )
        assert any(
            event["type"] == "selftest"
            and event["message"]
            == "PASS red_cannot_read_blue_home: PermissionError as expected"
            for event in events
        )


def test_tamper_breaks_chain_and_reset_restores_it():
    with make_client() as client:
        before = client.get("/events", headers=HEADERS).json()
        assert_valid_chain(before)

        tampered = client.post("/_mock/tamper", headers=HEADERS)
        assert tampered.status_code == 200
        body = tampered.json()
        assert body["tampered"] is True
        assert isinstance(body["broken_at"], int)

        verify = client.get("/verify-log", headers=HEADERS).json()
        assert verify == {"ok": False, "broken_at": body["broken_at"]}

        events = client.get("/events", headers=HEADERS).json()
        assert any(event["type"] == "tamper_alert" for event in events)
        assert any(
            event["id"] == body["broken_at"]
            and "[edited after the fact]" in event["message"]
            for event in events
        )
        # The tamper alert itself is a validly appended entry.
        alert = next(event for event in events if event["type"] == "tamper_alert")
        assert alert["hash"] == spec_hash(alert)

        report = client.get("/report", headers=HEADERS).json()
        assert report["tamper_detected"] is True
        assert client.get("/status", headers=HEADERS).json()["log_ok"] is False

        reset = client.post("/_mock/reset", headers=HEADERS)
        assert reset.status_code == 200
        assert reset.json() == {"ok": True}
        assert client.get("/verify-log", headers=HEADERS).json() == {
            "ok": True,
            "broken_at": None,
        }
        assert_valid_chain(client.get("/events?since=0", headers=HEADERS).json())


def test_leak_alert_arrives_after_configured_delay():
    with make_client(event_interval=60.0, leak_after=0.15) as client:
        deadline = time.monotonic() + 4
        events: list[dict] = []
        while time.monotonic() < deadline:
            events = client.get("/events?since=0", headers=HEADERS).json()
            if any(event["type"] == "leak_alert" for event in events):
                break
            time.sleep(0.05)

        leak = next(event for event in events if event["type"] == "leak_alert")
        assert leak["canary_hit"] is True
        assert leak["source"] in {"red", "blue", "ai", "sentinel"}
        response = next(
            event
            for event in events
            if event["type"] == "response" and event["canary_hit"] is True
        )
        assert "CANARY" in response["message"]
        assert client.get("/report", headers=HEADERS).json()["leaks"] == 1


def config_from(client: TestClient) -> dict:
    response = client.get("/config.js")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/javascript")
    match = re.search(r"window\.SENTINEL\s*=\s*(\{.*\});", response.text)
    assert match
    return json.loads(match.group(1))


def token_claims(token: str) -> dict:
    body = token.split(".")[0]
    body += "=" * (-len(body) % 4)
    return json.loads(base64.urlsafe_b64decode(body).decode("utf-8"))


def test_config_js_is_generated_and_decodes_for_display():
    with make_client() as client:
        config = config_from(client)
        assert config["broker"].startswith("http://testserver")
        claims = token_claims(config["token"])
        assert claims["r"] == "observer"
        assert claims["u"] == "mock.observer"

        index = client.get("/")
        assert index.status_code == 200
        assert "Bayora Sentinel" in index.text
        assert "app.js" in index.text
        assert client.get("/app.js").status_code == 200
        assert client.get("/style.css").status_code == 200


def test_desktop_is_served_offline_and_referenced_by_no_external_assets():
    with make_client() as client:
        for path in ("/desktop", "/desktop.html"):
            page = client.get(path)
            assert page.status_code == 200
            assert page.headers["content-type"].startswith("text/html")
            assert "desktop.js" in page.text
            assert "desktop.css" in page.text
            # The desktop is a self-contained offline page: no CDN, no web
            # fonts, no external images.
            assert "http://" not in page.text.replace("http://testserver", "")
            assert "https://" not in page.text

        script = client.get("/desktop.js")
        assert script.status_code == 200
        assert script.headers["content-type"].startswith("application/javascript")
        styles = client.get("/desktop.css")
        assert styles.status_code == 200
        assert styles.headers["content-type"].startswith("text/css")
        for asset in (script.text, styles.text):
            assert "googleapis" not in asset
            assert "cdn." not in asset


def test_role_launch_selects_the_display_role_for_config_js():
    with make_client() as client:
        red = client.get("/_mock/launch/red", follow_redirects=False)
        assert red.status_code == 303
        assert "sentinel_mock_role=red" in red.headers.get("set-cookie", "")
        assert red.headers["location"] == "/desktop"
        assert token_claims(config_from(client)["token"])["r"] == "red"

        blue = client.get("/_mock/launch/blue", follow_redirects=False)
        assert blue.status_code == 303
        assert token_claims(config_from(client)["token"])["r"] == "blue"

        missing = client.get("/_mock/launch/green", follow_redirects=False)
        assert missing.status_code == 404

        # The mock's data remains the observer view; only the display token
        # changes. The real broker is still the authority on visibility.
        assert client.get("/events", headers=HEADERS).status_code == 200
