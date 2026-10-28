from __future__ import annotations

import json
import re

import pytest

from browser_harness import ChromePage, find_browser
from mock_server import create_app


def test_web_renders_hostile_message_as_text_and_updates_live_state(live_server):
    if find_browser() is None:
        pytest.skip("Chrome/Chromium/Edge is not installed; browser DOM test skipped")
    try:
        import websockets.sync.client  # noqa: F401
    except ImportError:
        pytest.skip("websockets is required for the browser acceptance test")

    app = create_app(event_interval=999.0, leak_after=999.0)
    server = live_server(app)
    payload = "<img src=x onerror=alert(1)>"

    # Enter through the launcher's role handoff, exactly as b-sentinel does.
    # The handoff lands on the sandbox desktop; the read-only console is the
    # "console" link in its top bar.
    with ChromePage(server.url + "/_mock/launch/red") as page:
        assert page.wait_for(
            "document.getElementById('session-role').dataset.role === 'red'",
            timeout=8,
        )
        page.eval("window.location.href = '/'")
        assert page.wait_for(
            "document.readyState === 'complete' && "
            "document.getElementById('events-table') !== null",
            timeout=10,
        )

        # Session identity is decoded from the generated config token for display.
        session = page.eval(
            "document.getElementById('session-user').textContent + '|' + "
            "document.getElementById('session-role').textContent"
        )
        assert session == "mock.observer|red"

        assert page.wait_for(
            "document.querySelector('[data-key=\"broker\"] .status-value')"
            ".textContent === 'up'",
            timeout=8,
        )
        assert page.wait_for(
            "document.getElementById('live-state').dataset.mode === 'live'",
            timeout=8,
        )

        # The report is two columns by design, not one list.
        assert page.eval("document.querySelectorAll('.report-columns .report-col').length") == 2
        assert page.wait_for(
            "document.querySelectorAll('#report-secure li').length > 0",
            timeout=5,
        )

        # An attacker-controlled event must become a text node, not an element.
        response = server.request("POST", "/attack", json={"prompt": payload})
        assert response.status_code == 200

        found = page.wait_for(
            "(() => {"
            "  const wanted = " + json.dumps(payload) + ";"
            "  return Array.from(document.querySelectorAll('#events-body td.event-message'))"
            "    .some((cell) => cell.textContent.indexOf(wanted) !== -1);"
            "})()",
            timeout=8,
        )
        assert found

        rendered = page.eval(
            "(() => {"
            "  const wanted = " + json.dumps(payload) + ";"
            "  const cell = Array.from(document.querySelectorAll('#events-body td.event-message'))"
            "    .find((node) => node.textContent.indexOf(wanted) !== -1);"
            "  return {"
            "    images: document.querySelectorAll('#events-body img').length,"
            "    allImages: document.querySelectorAll('img').length,"
            "    text: cell ? cell.textContent : null,"
            "    html: cell ? cell.innerHTML : null"
            "  };"
            "})()"
        )
        assert rendered["images"] == 0
        assert rendered["allImages"] == 0
        assert payload in rendered["text"]
        assert "&lt;img" in rendered["html"]
        assert "<img" not in rendered["html"]

        # A leak is emitted on demand and must reach the banner in under a second.
        start = page.eval("performance.now()")
        leak = server.request("POST", "/_mock/leak")
        assert leak.status_code == 200

        assert page.wait_for(
            "!document.getElementById('alert-banner').hidden && "
            "document.getElementById('alert-title').textContent.indexOf('Canary') !== -1",
            timeout=3,
        )
        elapsed_ms = page.eval("performance.now()") - start
        assert elapsed_ms < 1000, f"leak banner took {elapsed_ms:.0f} ms"

        # The banner stays until dismissed, then a newer alert re-opens it.
        page.eval("document.getElementById('alert-dismiss').click()")
        assert page.eval("document.getElementById('alert-banner').hidden") is True

        tamper = server.request("POST", "/_mock/tamper")
        assert tamper.status_code == 200
        assert page.wait_for(
            "!document.getElementById('alert-banner').hidden && "
            "document.getElementById('alert-title').textContent.indexOf('tamper') !== -1",
            timeout=3,
        )

        # The integrity button flips the badge immediately; polling covers the
        # same path every 10 seconds without interaction.
        page.eval("document.getElementById('verify-button').click()")
        assert page.wait_for(
            "document.getElementById('integrity-text').textContent.includes('chain BROKEN at entry')",
            timeout=4,
        )
        assert page.eval("document.getElementById('integrity-badge').dataset.tone") == "bad"

        # Status poll (3 s) also reflects the broken audit log.
        assert page.wait_for(
            "document.querySelector('[data-key=\"log_ok\"] .status-value')"
            ".textContent === 'BROKEN'",
            timeout=6,
        )

        assert page.eval("document.getElementById('events-count').textContent.length > 0")

        # Phone width: the page itself must not overflow; the table scrolls in
        # its own container.
        page.cdp.call(
            "Emulation.setDeviceMetricsOverride",
            {"width": 375, "height": 800, "deviceScaleFactor": 1, "mobile": False},
        )
        assert page.wait_for("window.innerWidth === 375", timeout=3)
        overflow = page.eval(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth"
        )
        assert overflow <= 1, f"phone layout overflows by {overflow}px"


def test_web_source_uses_no_html_sinks_or_persistent_token_storage():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "web" / "app.js").read_text(
        encoding="utf-8"
    )
    assert re.search(r"\.innerHTML\s*=", source) is None
    assert re.search(r"insertAdjacentHTML", source) is None
    assert re.search(r"localStorage\s*\.\s*setItem", source) is None
    assert re.search(r"sessionStorage\s*\.\s*setItem", source) is None
    assert re.search(r"console\s*\.\s*log", source) is None
