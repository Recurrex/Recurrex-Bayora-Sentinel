from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from browser_harness import ChromePage, find_browser
from mock_server import create_app


def _require_browser_and_sockets() -> None:
    if find_browser() is None:
        pytest.skip("Chrome/Chromium/Edge is not installed; browser DOM test skipped")
    try:
        import websockets.sync.client  # noqa: F401
    except ImportError:
        pytest.skip("websockets is required for the browser acceptance test")


DOCK = ".dock-button[data-tool='{tool}']"
WINDOW = ".window[data-tool='{tool}']"


def test_desktop_red_offers_attack_not_defense_and_renders_events_safely(live_server):
    _require_browser_and_sockets()

    app = create_app(event_interval=999.0, leak_after=999.0)
    server = live_server(app)
    payload = "<img src=x onerror=alert(1)>"

    with ChromePage(server.url + "/_mock/launch/red") as page:
        # The launcher handoff lands on the sandbox desktop with the red role.
        assert page.wait_for(
            "document.getElementById('desktop').hidden === false && "
            "document.getElementById('session-role').dataset.role === 'red'",
            timeout=10,
        )

        # Red's dock has the attack console and no defense console.
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % DOCK.format(tool="attack"),
            timeout=5,
        )
        assert page.eval(
            "document.querySelector(\"%s\") === null" % DOCK.format(tool="defense")
        ) is True
        assert page.eval(
            "document.querySelector(\"%s\") === null" % DOCK.format(tool="detector")
        ) is True

        # The attack console opens automatically for red.
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % WINDOW.format(tool="attack"),
            timeout=5,
        )

        # Launch an attack through the console UI; the mock replies.
        page.eval(
            "(() => {"
            "  const box = document.querySelector(\"%s .tool-textarea\");"
            "  box.value = %s;"
            "  const button = Array.from(document.querySelectorAll(\"%s button\"))"
            "    .find((node) => node.textContent === 'Launch attack');"
            "  button.click();"
            "  return true;"
            "})()" % (WINDOW.format(tool="attack"), json.dumps(payload),
                      WINDOW.format(tool="attack"))
        )
        assert page.wait_for(
            "(() => {"
            "  const term = document.querySelector(\"%s .term\");"
            "  return term.textContent.indexOf(%s) !== -1;"
            "})()" % (WINDOW.format(tool="attack"), json.dumps(payload)),
            timeout=8,
        )

        # The hostile string in the live wire is a text node, never an element.
        page.eval(
            "document.querySelector(\"%s\").click()" % DOCK.format(tool="wire")
        )
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % WINDOW.format(tool="wire"),
            timeout=5,
        )
        response = server.request("POST", "/attack", json={"prompt": payload})
        assert response.status_code == 200
        assert page.wait_for(
            "(() => {"
            "  const wanted = %s;"
            "  return Array.from(document.querySelectorAll('.window .tool-table td'))"
            "    .some((node) => node.textContent.indexOf(wanted) !== -1);"
            "})()" % json.dumps(payload),
            timeout=8,
        )
        assert page.eval("document.querySelectorAll('.window img').length") == 0
        assert page.eval("document.querySelectorAll('img').length") == 0

        # A leak raises the desktop toast (role-independent alerting).
        leak = server.request("POST", "/_mock/leak")
        assert leak.status_code == 200
        assert page.wait_for(
            "!document.getElementById('alert-toast').hidden && "
            "document.getElementById('toast-message').textContent.length > 0",
            timeout=3,
        )
        page.eval("document.getElementById('toast-dismiss').click()")
        assert page.eval("document.getElementById('alert-toast').hidden") is True

        # The scanner reports the broker reachable and the chain OK.
        page.eval(
            "document.querySelector(\"%s\").click()" % DOCK.format(tool="scanner")
        )
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % WINDOW.format(tool="scanner"),
            timeout=5,
        )
        page.eval(
            "(() => {"
            "  const button = Array.from(document.querySelectorAll(\"%s button\"))"
            "    .find((node) => node.textContent === 'Run scan');"
            "  button.click();"
            "  return true;"
            "})()" % WINDOW.format(tool="scanner")
        )
        assert page.wait_for(
            "(() => {"
            "  const term = document.querySelector(\"%s .term\");"
            "  return term.textContent.indexOf('chain OK') !== -1;"
            "})()" % WINDOW.format(tool="scanner"),
            timeout=8,
        )


def test_desktop_blue_gets_detector_and_defense_but_not_attack(live_server):
    _require_browser_and_sockets()

    app = create_app(event_interval=999.0, leak_after=999.0)
    server = live_server(app)

    with ChromePage(server.url + "/_mock/launch/blue") as page:
        assert page.wait_for(
            "document.getElementById('desktop').hidden === false && "
            "document.getElementById('session-role').dataset.role === 'blue'",
            timeout=10,
        )

        for tool in ("detector", "defense", "scanner", "wire"):
            assert page.wait_for(
                "document.querySelector(\"%s\") !== null" % DOCK.format(tool=tool),
                timeout=5,
            ), tool
        assert page.eval(
            "document.querySelector(\"%s\") === null" % DOCK.format(tool="attack")
        ) is True

        # The detector opens automatically for blue and sees seeded attacks as
        # metadata only — the body is hidden by policy in its threat list.
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % WINDOW.format(tool="detector"),
            timeout=5,
        )
        assert page.wait_for(
            "(() => {"
            "  const table = document.querySelector(\"%s .tool-table\");"
            "  return table.textContent.indexOf('hidden by policy') !== -1;"
            "})()" % WINDOW.format(tool="detector"),
            timeout=8,
        )

        # A defense rule submitted in the console appears in the live wire.
        page.eval(
            "document.querySelector(\"%s\").click()" % DOCK.format(tool="wire")
        )
        assert page.wait_for(
            "document.querySelector(\"%s\") !== null" % WINDOW.format(tool="wire"),
            timeout=5,
        )
        response = server.request(
            "POST", "/defense", json={"rule": "Reject prompts mentioning canaries."}
        )
        assert response.status_code == 200
        assert page.wait_for(
            "(() => {"
            "  const wanted = 'Reject prompts mentioning canaries.';"
            "  return Array.from(document.querySelectorAll('.window .tool-table td'))"
            "    .some((node) => node.textContent.indexOf(wanted) !== -1);"
            "})()",
            timeout=8,
        )


def test_desktop_source_has_no_html_sinks_or_persistent_token_storage():
    source = (
        Path(__file__).resolve().parents[1] / "web" / "desktop.js"
    ).read_text(encoding="utf-8")
    assert re.search(r"\.innerHTML\s*=", source) is None
    assert re.search(r"insertAdjacentHTML", source) is None
    # The desktop persists exactly two settings: the theme choice and window
    # geometry (the window manager). Any other key — especially anything
    # carrying the broker URL or the session token — is forbidden.
    for write in re.finditer(r"localStorage\s*\.\s*setItem\(([^\n]*)", source):
        assert re.search(r"THEME_KEY|WM_KEY", write.group(1)) is not None, (
            "unexpected localStorage persistence: " + write.group(1)
        )
    assert re.search(r"sessionStorage\s*\.\s*setItem", source) is None
    assert re.search(r"console\s*\.\s*log", source) is None
    assert re.search(r"eval\s*\(", source) is None


def test_vm_desktop_ships_a_terminal_browser_and_wallpaper(live_server):
    _require_browser_and_sockets()

    app = create_app(event_interval=999.0, leak_after=999.0)
    server = live_server(app)

    with ChromePage(server.url + "/_mock/launch/red") as page:
        assert page.wait_for(
            "document.getElementById('desktop').hidden === false && "
            "document.querySelector(\".window[data-tool='terminal']\") !== null",
            timeout=12,
        )

        # The wallpaper is the dark scheme: flat background plus the faint
        # grid texture, no image asset, and only the low-contrast mark.
        assert page.eval(
            "document.querySelector('.wallpaper-mark') !== null"
        ) is True
        assert page.eval(
            "getComputedStyle(document.querySelector('.wallpaper'))"
            ".backgroundSize.indexOf('32px') !== -1"
        ) is True

        # The dock carries a full practice VM, not just consoles.
        for tool in ("terminal", "browser", "mail", "files", "proxy", "tools"):
            assert page.eval(
                "document.querySelector(\".dock-button[data-tool='%s']\") !== null" % tool
            ) is True, tool

        # Every dock button has a real SVG icon, not a text glyph.
        assert page.eval(
            "document.querySelectorAll('.dock-button svg.dock-glyph').length"
            " === document.querySelectorAll('.dock-button').length"
        ) is True

        # The Toolbox lists the Kali-style tools and can run one.
        page.eval("document.querySelector(\".dock-button[data-tool='tools']\").click()")
        assert page.wait_for(
            "document.querySelector(\".window[data-tool='tools'] .toolbox-item\") !== null",
            timeout=8,
        )
        assert page.eval(
            "document.querySelector(\".window[data-tool='tools']\").textContent"
            ".indexOf('Nmap') !== -1"
        ) is True

        # Run a real command through the terminal: recon against the portal.
        page.eval(
            "(() => {"
            "  const input = document.querySelector("
            "    \".window[data-tool='terminal'] .vm-input\");"
            "  input.value = 'nmap -sV portal';"
            "  input.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', bubbles: true}));"
            "  return true;"
            "})()"
        )
        assert page.wait_for(
            "document.querySelector(\".window[data-tool='terminal'] .vm-term\")"
            ".textContent.indexOf('Nmap scan report for portal') !== -1",
            timeout=8,
        )

        # The browser opens the in-range target and offers the sandbox chat.
        page.eval("document.querySelector(\".dock-button[data-tool='browser']\").click()")
        assert page.wait_for(
            "document.querySelector(\".window[data-tool='browser'] .browser-title\")"
            " !== null",
            timeout=6,
        )
        assert page.wait_for(
            "document.querySelector(\".window[data-tool='browser']\")"
            ".textContent.indexOf('AI Sandbox') !== -1",
            timeout=6,
        )

        # The sandbox window reports the live verdict badge.
        page.eval("document.querySelector(\".dock-button[data-tool='sandbox']\").click()")
        assert page.wait_for(
            "(() => {"
            "  const word = document.querySelector("
            "    \".window[data-tool='sandbox'] .verdict-word\");"
            "  return word !== null && word.textContent.trim().length > 0;"
            "})()",
            timeout=8,
        )
