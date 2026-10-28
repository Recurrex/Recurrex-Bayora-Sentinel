from __future__ import annotations

import sys
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
UI_DIR = TESTS_DIR.parent
PROJECT_ROOT = UI_DIR.parent

for path in (str(UI_DIR), str(UI_DIR / "tui"), str(TESTS_DIR)):
    if path not in sys.path:
        sys.path.insert(0, path)

from helpers import LiveServer  # noqa: E402  (path is set above)


@pytest.fixture
def live_server():
    """Factory that starts the mock broker in a background uvicorn thread."""
    servers: list[LiveServer] = []

    def start(app) -> LiveServer:
        server = LiveServer(app)
        server.start()
        servers.append(server)
        return server

    yield start

    for server in servers:
        server.stop()
