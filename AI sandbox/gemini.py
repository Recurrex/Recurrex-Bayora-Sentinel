"""Google AI Studio (Gemini) client.

This is the only place that talks to Google. It is shared by the AI sandbox
(reply generation and the saved/penetrated judge) and by the broker's
``ai_client`` so both paths use the same model.

Credentials come from the environment, never from a file in the repo:

    GEMINI_API_KEY   your AI Studio key  (https://aistudio.google.com/apikey)
    GEMINI_MODEL     model id            (default: gemini-2.5-flash)

With no key every caller falls back to its deterministic offline stub, so the
demo runs with no network and no credentials. The key is sent in the
``x-goog-api-key`` header, never in a URL, and is never logged.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger("sentinel.gemini")

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


def _load_env_file() -> None:
    """Pick up GEMINI_* from the project .env without overriding real env vars.

    The file is optional and must never be committed. Values are not logged.
    """
    try:
        lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file()

API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_MODEL = "gemini-2.5-flash"
TIMEOUT_S = 25.0


def api_key() -> str:
    return os.environ.get("GEMINI_API_KEY", "").strip()


def model() -> str:
    return os.environ.get("GEMINI_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def is_configured() -> bool:
    """True when a key is present. It does not probe the network."""
    return bool(api_key())


def engine() -> str:
    """Short label for the UI: which model answers in this process."""
    return "google-ai-studio" if is_configured() else "offline-stub"


def generate(prompt: str, *, system: str | None = None, timeout: float = TIMEOUT_S) -> str | None:
    """One stateless text completion. Returns None if Google is unavailable.

    Never raises: a missing key, a timeout or an unexpected payload all mean
    "no model answer", and the caller uses its stub instead.
    """
    key = api_key()
    if not key:
        return None

    payload: dict = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 512},
    }
    if system:
        payload["systemInstruction"] = {"parts": [{"text": system}]}

    request = urllib.request.Request(
        "{}/{}:generateContent".format(API_ROOT, model()),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": key,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Status only: the body can echo the prompt and must not be logged.
        log.info("AI Studio HTTP %s", exc.code)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        log.info("AI Studio request failed: %s", type(exc).__name__)
        return None

    try:
        parts = data["candidates"][0]["content"]["parts"]
        text = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
    except (KeyError, IndexError, TypeError):
        log.info("AI Studio returned an unexpected payload")
        return None
    text = text.strip()
    return text or None
