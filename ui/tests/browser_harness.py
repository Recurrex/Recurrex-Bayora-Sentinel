"""Minimal headless Chrome driver over the DevTools protocol.

The project has no build step and no Node dependency, so the browser test uses
the Chrome/Edge that is already installed and the small ``websockets`` client.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from helpers import wait_until

CHROME_CANDIDATES = (
    os.environ.get("CHROME_BIN", ""),
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
)


def find_browser() -> str | None:
    for candidate in CHROME_CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    return None


class CDP:
    """One DevTools page connection."""

    def __init__(self, websocket) -> None:
        self.ws = websocket
        self._next_id = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self.ws.send(
            json.dumps({"id": request_id, "method": method, "params": params or {}})
        )
        deadline = time.monotonic() + 15
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"CDP call timed out: {method}")
            raw = self.ws.recv(timeout=remaining)
            message = json.loads(raw)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"CDP error for {method}: {message['error']}")
            return message.get("result", {})

    def eval(self, expression: str) -> Any:
        result = self.call(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True,
            },
        )
        if "exceptionDetails" in result:
            details = result["exceptionDetails"]
            description = details.get("exception", {}).get("description", str(details))
            raise RuntimeError(f"JavaScript error: {description}")
        return result.get("result", {}).get("value")

    def wait_for(self, expression: str, timeout: float = 5.0) -> Any:
        return wait_until(lambda: self.eval(expression), timeout=timeout, interval=0.02)


class ChromePage:
    """Launch a temporary headless browser, open a page, and expose CDP."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._process: subprocess.Popen | None = None
        self._profile: str | None = None
        self._cdp: CDP | None = None
        self._ws = None
        self._log_path: Path | None = None
        self._log_file = None

    def __enter__(self) -> "ChromePage":
        browser = find_browser()
        if not browser:
            raise RuntimeError("no Chrome/Chromium/Edge binary found")

        self._profile = tempfile.mkdtemp(prefix="sentinel-chrome-")
        self._log_path = Path(self._profile) / "chrome.log"
        self._log_file = open(self._log_path, "wb")
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        self._process = subprocess.Popen(
            [
                browser,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--metrics-recording-only",
                "--remote-allow-origins=*",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                f"--user-data-dir={self._profile}",
                "--no-sandbox",
                "about:blank",
            ],
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
        )

        devtools_file = Path(self._profile) / "DevToolsActivePort"
        if not wait_until(devtools_file.is_file, timeout=15.0, interval=0.05):
            self._raise_start_failure("Chrome did not open its DevTools port")
        try:
            port = int(devtools_file.read_text(encoding="utf-8").splitlines()[0])
        except (IndexError, ValueError):
            self._raise_start_failure("Chrome wrote an invalid DevToolsActivePort")

        target_url = f"http://127.0.0.1:{port}/json/new?" + urllib.parse.quote(
            self.url, safe=""
        )
        request = urllib.request.Request(target_url, method="PUT")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                target = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            self._raise_start_failure(f"could not create a browser target: {exc}")

        ws_url = target.get("webSocketDebuggerUrl")
        if not ws_url:
            self._raise_start_failure("browser target had no webSocketDebuggerUrl")

        try:
            from websockets.sync.client import connect
        except ImportError as exc:  # pragma: no cover - dependency guard
            self._raise_start_failure(f"websockets is not installed: {exc}")

        self._ws = connect(
            ws_url,
            proxy=None,
            open_timeout=10,
            max_size=None,
            max_queue=None,
        )
        self._cdp = CDP(self._ws)
        self._cdp.call("Runtime.enable")
        self._cdp.wait_for(
            "document.readyState === 'complete' && document.getElementById('session-user') !== null",
            timeout=15.0,
        )
        return self

    def _raise_start_failure(self, message: str) -> None:
        log_tail = ""
        if self._log_path and self._log_path.is_file():
            try:
                log_tail = self._log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
            except OSError:
                log_tail = ""
        raise RuntimeError(message + (f"\nChrome log:\n{log_tail}" if log_tail else ""))

    @property
    def cdp(self) -> CDP:
        if self._cdp is None:
            raise RuntimeError("browser page is not open")
        return self._cdp

    def eval(self, expression: str) -> Any:
        return self.cdp.eval(expression)

    def wait_for(self, expression: str, timeout: float = 5.0) -> Any:
        return self.cdp.wait_for(expression, timeout=timeout)

    def close(self) -> None:
        try:
            if self._ws is not None:
                self._ws.close()
        except Exception:
            pass
        self._ws = None
        if self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=5)
        self._process = None
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
        self._log_file = None
        if self._profile:
            shutil.rmtree(self._profile, ignore_errors=True)
        self._profile = None

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
