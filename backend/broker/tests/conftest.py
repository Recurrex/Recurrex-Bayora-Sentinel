"""Shared fixtures for broker tests.

Each test gets a fresh temp world: its own secret, canary file and audit DB,
FAKE_AI=1 so no Ollama is needed, and cleared in-process state.
"""

import base64
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SECRET = b"unit-test-secret-bytes-0123456789"
CANARIES = ["SNTL-CANARY-UNIT-ALPHA", "SNTL-CANARY-UNIT-BETA"]


def make_token(role="red", user="tester", exp=None, secret=SECRET):
    """Mint a token exactly the way the CLI does (SPEC.md format)."""
    if exp is None:
        exp = int(time.time()) + 3600
    payload = json.dumps({"u": user, "r": role, "exp": exp}).encode("utf-8")
    body = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def auth_header(role="red"):
    return {"Authorization": f"Bearer {make_token(role=role)}"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    secret_path = tmp_path / "secret"
    secret_path.write_bytes(SECRET)
    canaries_path = tmp_path / "canaries.json"
    canaries_path.write_text(json.dumps({"canaries": CANARIES}))
    db_path = tmp_path / "audit.db"

    monkeypatch.setenv("SECRET_PATH", str(secret_path))
    monkeypatch.setenv("CANARIES_PATH", str(canaries_path))
    monkeypatch.setenv("LOG_DB", str(db_path))
    monkeypatch.setenv("FAKE_AI", "1")

    import app as app_module
    import auth
    import policy

    app_module._RULES.clear()
    app_module._STATE["last_attack"] = 0.0
    auth.LAST_SEEN.clear()
    policy.reload_policy()

    yield {
        "secret": SECRET,
        "canaries": CANARIES,
        "db": db_path,
        "app_module": app_module,
    }


@pytest.fixture()
def client(env):
    from fastapi.testclient import TestClient

    from app import app

    # Context manager so FastAPI's lifespan runs (startup event logged).
    with TestClient(app) as c:
        yield c
