"""Authentication for the Bayora Sentinel broker.

Token format (SPEC.md): base64url(json).hex(hmac_sha256(secret, base64url(json)))
where the JSON is {"u": "alice", "r": "red", "exp": 1760000000}.

The broker takes the role from the token, never from anything the client claims.
Missing, forged or expired token -> 401.  Role not allowed for an action -> 403.
"""

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Callable

from fastapi import HTTPException, Request, WebSocket

import policy as policy_mod

# Roles that may ever hold a token.
ROLES = ("red", "blue", "observer")

# Last-request timestamp per role, used by GET /status ("up"/"down").
LAST_SEEN: dict[str, float] = {}


def verify_token(token: str, secret: bytes):
    """Returns {"u","r","exp"} if the token is genuine and not expired, else None.

    Verbatim from SPEC.md.
    """
    try:
        body, sig = token.split(".")
        good = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        p = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return p if p["exp"] > time.time() else None
    except Exception:
        return None


def load_secret() -> bytes:
    """Read the signing secret from SECRET_PATH (default /etc/sentinel/secret).

    A single trailing newline is tolerated (the CLI may write the file with
    print()).  Any read problem raises OSError; callers map that to 401.
    """
    path = os.environ.get("SECRET_PATH", "/etc/sentinel/secret")
    with open(path, "rb") as f:
        data = f.read()
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    return data


def _record_activity(role: str) -> None:
    LAST_SEEN[role] = time.time()


def authenticate_token(token: str) -> dict:
    """Verify a bearer token; return the payload or raise 401/403."""
    if not token:
        raise HTTPException(status_code=401, detail="missing token")
    try:
        secret = load_secret()
    except OSError:
        # Without the secret no token can be verified.
        raise HTTPException(status_code=401, detail="cannot verify token")
    payload = verify_token(token, secret)
    if payload is None:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    role = payload.get("r")
    user = payload.get("u")
    if role not in ROLES or not isinstance(user, str) or not user:
        raise HTTPException(status_code=403, detail="role not allowed")
    _record_activity(role)
    return payload


def get_principal(request: Request) -> dict:
    """FastAPI dependency: authenticate `Authorization: Bearer <token>`."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing token")
    return authenticate_token(header[len("Bearer "):].strip())


def require_action(action: str) -> Callable:
    """Dependency factory: any authenticated role that policy.json permits
    for `action` (attack -> red, defense -> blue, everything else -> any)."""

    def dependency_wrapper(request: Request) -> dict:
        payload = get_principal(request)
        if not policy_mod.role_allowed(action, payload["r"]):
            raise HTTPException(status_code=403, detail="role not allowed")
        return payload

    return dependency_wrapper


def authenticate_websocket(websocket: WebSocket) -> dict | None:
    """Authenticate a WebSocket from `?token=`; return payload or None."""
    token = websocket.query_params.get("token") or ""
    if not token:
        return None
    try:
        secret = load_secret()
    except OSError:
        return None
    payload = verify_token(token, secret)
    if payload is None:
        return None
    role = payload.get("r")
    user = payload.get("u")
    if role not in ROLES or not isinstance(user, str) or not user:
        return None
    _record_activity(role)
    return payload
