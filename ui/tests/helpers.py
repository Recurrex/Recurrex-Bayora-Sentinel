from __future__ import annotations

import socket
import threading
import time
from typing import Any, Callable

import httpx
import uvicorn


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_until(
    predicate: Callable[[], Any],
    timeout: float = 5.0,
    interval: float = 0.02,
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
        except Exception:
            value = None
        if value:
            return value
        time.sleep(interval)
    try:
        return predicate()
    except Exception:
        return None


class LiveServer:
    """Run a FastAPI app on a real loopback port for HTTP/WebSocket/browser tests."""

    def __init__(self, app) -> None:
        self.app = app
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "LiveServer":
        config = uvicorn.Config(
            self.app,
            host="127.0.0.1",
            port=self.port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
        self._server = uvicorn.Server(config)
        # Signal handlers may only be installed on the main thread.
        self._server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        self._thread = threading.Thread(
            target=self._server.run,
            name=f"mock-broker-{self.port}",
            daemon=True,
        )
        self._thread.start()
        ready = wait_until(self._ready, timeout=10.0, interval=0.05)
        if not ready:
            self.stop()
            raise RuntimeError("mock broker did not start")
        return self

    def _ready(self) -> bool:
        try:
            response = httpx.get(
                self.url + "/status",
                headers={"Authorization": "Bearer readiness"},
                timeout=0.5,
            )
        except Exception:
            return False
        return response.status_code == 200

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=10)
        self._thread = None
        self._server = None

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = "test-token",
        **kwargs: Any,
    ) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if token is not None:
            headers.setdefault("Authorization", f"Bearer {token}")
        return httpx.request(
            method,
            self.url + path,
            headers=headers,
            timeout=5.0,
            **kwargs,
        )
