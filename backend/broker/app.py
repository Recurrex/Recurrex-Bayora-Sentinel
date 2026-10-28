"""Bayora Sentinel broker API (SPEC.md "Broker API").

Every endpoint requires a valid signed token; the role comes only from the
token.  Red and Blue never talk directly: all traffic goes through here, every
message is canary-scanned, and everything is written to the hash-chained audit
log.  All request bodies, headers and AI replies are untrusted input.

Endpoints (exactly as SPEC.md):
  POST /attack            red    send an attack prompt to the AI via broker
  POST /defense           blue   submit a defense rule (regex)
  GET  /events?since=<id> any    list log entries, filtered by role
  WS   /ws/events?token=  any    live stream of new entries, filtered by role
  GET  /status            any    environments up/down, test running/idle
  GET  /report            any    secure vs. remaining risk summary
  GET  /verify-log        any    recompute the chain; {ok, broken_at}
  POST /selftest          any    record a boundary self-test result
"""

import asyncio
import logging
import re
import threading
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

import ai_client
import auditlog
import auth
import canaries
import policy
import pty_bridge
import vm_manager

log = logging.getLogger("sentinel.broker")

# Limits for untrusted defense regexes (rule body text <= 200 chars is
# enforced by the pydantic model below).
MAX_RULES = 100
MAX_PROMPT_MATCH_CHARS = 4000  # rules match only the first 4000 chars

# Heuristic: a quantified group whose body itself contains a quantifier,
# e.g. (a+)+, (a*)*, (\\d+)+, ((a)*)+ -- classic ReDoS shapes.
_NESTED_QUANTIFIER = re.compile(
    r"\((?:[^()]|\([^()]*\))*[+*{](?:[^()]|\([^()]*\))*\)\s*[*+?{]"
)

# In-memory active defense rules: (rule_number, compiled regex).
_RULES: list[tuple[int, re.Pattern]] = []
_RULES_LOCK = threading.Lock()

# Connected /ws/events clients, discarded on disconnect.
_WS_CLIENTS: set[WebSocket] = set()

# When the last /attack was handled (for GET /status "test": running/idle).
_STATE = {"last_attack": 0.0}

# Known limits from SPEC.md -- always stated in the report, never hidden.
KNOWN_LIMITS = [
    "Login is a gate on one machine: the red and blue SSH keys sit under the "
    "same host account, so someone with full control of that account can pick "
    "either team. Real enforcement is the broker, which trusts only the signed token.",
    "Docker and the VM are not a perfect security boundary.",
    "Canaries catch only leaks of secrets we plant.",
    "A hash chain shows tampering, it does not prevent it.",
    "Defense rules are regexes matched against the first 4000 characters only; "
    "Python's re has no timeout, so a pathological pattern carries residual ReDoS risk.",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    auditlog.append("sentinel", "selftest", "broker started")
    yield


app = FastAPI(title="Bayora Sentinel Broker", version="1.0", lifespan=lifespan)


# --------------------------------------------------------------------- models

class AttackBody(BaseModel):
    prompt: str = Field(..., min_length=1)


class DefenseBody(BaseModel):
    # max 200 chars, enforced as 422 by FastAPI's validation.
    rule: str = Field(..., min_length=1, max_length=200)


class SelftestBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    passed: bool
    detail: str = Field(..., max_length=1000)


class IngestBody(BaseModel):
    # One POST per small batch from the guest collector; no user input here.
    events: list[dict] = Field(..., min_length=1, max_length=100)


class VmActionBody(BaseModel):
    vm: str = Field(..., pattern="^(red-vm|blue-vm|router-vm)$")
    action: str = Field(..., pattern="^(start|stop)$")


# -------------------------------------------------------------------- /attack

@app.post("/attack")
def attack(body: AttackBody, principal: dict = Depends(auth.require_action("attack"))):
    prompt = body.prompt
    _STATE["last_attack"] = time.time()

    # a) Canary in the prompt: Red is trying to inject a planted secret.
    prompt_hits = canaries.scan(prompt)
    if prompt_hits:
        auditlog.append(
            "red", "attack",
            "Attack request blocked: canary in prompt; not forwarded",
            canary_hit=True,
        )
        auditlog.append(
            "red", "leak_alert",
            "Canary detected in attack prompt; attack not forwarded",
            canary_hit=True,
        )
        return {"reply": "[blocked: canary in prompt]"}

    # b) Blue's active defense rules.
    with _RULES_LOCK:
        rules = list(_RULES)
    for rule_no, pattern in rules:
        if pattern.search(prompt[:MAX_PROMPT_MATCH_CHARS]):
            auditlog.append(
                "red", "attack",
                f"Attack request matched defense rule {rule_no}",
            )
            auditlog.append(
                "blue", "defense",
                f"rule {rule_no} blocked an attack",
            )
            return {"reply": "[blocked by defense]"}

    # c) Forward to the AI statelessly (no history, no context field).
    auditlog.append("red", "attack", "Attack forwarded to AI")
    try:
        reply = ai_client.ask(prompt)
    except ai_client.AIUnavailable:
        raise HTTPException(status_code=504, detail="AI did not answer")

    # d) Canary in the AI reply: mask before Red sees it, raise leak_alert.
    reply_hits = canaries.scan(reply)
    if reply_hits:
        auditlog.append(
            "ai", "response",
            "AI reply contained a canary; masked before delivery",
            canary_hit=True,
        )
        auditlog.append(
            "ai", "leak_alert",
            "Canary detected in AI reply; masked as [CANARY]",
            canary_hit=True,
        )
        return {"reply": canaries.mask(reply, reply_hits)}

    auditlog.append("ai", "response", "AI reply delivered to Red")
    return {"reply": reply}


# ------------------------------------------------------------------- /defense

def _has_nested_quantifier(pattern: str) -> bool:
    return _NESTED_QUANTIFIER.search(pattern) is not None


@app.post("/defense")
def defense(body: DefenseBody, principal: dict = Depends(auth.require_action("defense"))):
    rule_text = body.rule
    try:
        compiled = re.compile(rule_text, re.IGNORECASE)
    except re.error:
        raise HTTPException(status_code=422, detail="invalid regex")
    if _has_nested_quantifier(rule_text):
        raise HTTPException(
            status_code=422, detail="nested quantifiers are not allowed"
        )
    with _RULES_LOCK:
        if len(_RULES) >= MAX_RULES:
            raise HTTPException(
                status_code=422, detail=f"maximum {MAX_RULES} active rules"
            )
        rule_no = (max(n for n, _ in _RULES) + 1) if _RULES else 1
        _RULES.append((rule_no, compiled))
    auditlog.append("blue", "defense", f"Rule {rule_no} added: {rule_text}")
    return {"ok": True}


# -------------------------------------------------------------------- /events

@app.get("/events")
def events(
    since: int = Query(0, ge=0),
    principal: dict = Depends(auth.require_action("events")),
):
    rows = auditlog.list_events(since=since)
    return policy.filter_events(rows, principal["r"])


# --------------------------------------------------------------- /ws/events

@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    principal = auth.authenticate_websocket(websocket)
    if principal is None or not policy.role_allowed("ws_events", principal["r"]):
        # Browsers cannot send headers on a WebSocket; reject by close code.
        await websocket.close(code=4401)
        return
    role = principal["r"]
    await websocket.accept()
    cursor = 0
    last_ping = time.time()
    _WS_CLIENTS.add(websocket)
    try:
        while True:
            rows = auditlog.list_events(since=cursor)
            if rows:
                cursor = rows[-1]["id"]
                for event in policy.filter_events(rows, role):
                    await websocket.send_json(event)
                last_ping = time.time()
            elif time.time() - last_ping >= 20.0:
                await websocket.send_json({"ping": True})
                last_ping = time.time()
            await asyncio.sleep(0.2)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _WS_CLIENTS.discard(websocket)


# -------------------------------------------------------------------- /status

@app.get("/status")
def status(principal: dict = Depends(auth.require_action("status"))):
    now = time.time()
    red_up = now - auth.LAST_SEEN.get("red", 0.0) <= 600
    blue_up = now - auth.LAST_SEEN.get("blue", 0.0) <= 600
    test_state = "running" if now - _STATE["last_attack"] <= 60 else "idle"
    chain_ok, _ = auditlog.verify()
    return {
        "red": "up" if red_up else "down",
        "blue": "up" if blue_up else "down",
        "ai": "up" if ai_client.is_up() else "down",
        "broker": "up",
        "test": test_state,
        "log_ok": chain_ok,
    }


# -------------------------------------------------------------------- /report

@app.get("/report")
def report(principal: dict = Depends(auth.require_action("report"))):
    rows = auditlog.list_events(since=0)
    secure: list[str] = []
    failed: list[str] = []
    for event in rows:
        if event["type"] != "selftest":
            continue
        message = event["message"]
        if message.startswith("PASS "):
            name = message[len("PASS "):].split(":", 1)[0].strip()
            if name and name not in secure:
                secure.append(name)
        elif message.startswith("FAIL "):
            name = message[len("FAIL "):].split(":", 1)[0].strip()
            if name and name not in failed:
                failed.append(name)
    residual = list(KNOWN_LIMITS)
    residual.extend(f"Self-test failed: {name}" for name in failed)
    return {
        "secure": secure,
        "residual_risk": residual,
        "leaks": auditlog.count_canary_hits(),
        "tamper_detected": auditlog.has_tamper_alert(),
    }


# ---------------------------------------------------------------- /verify-log

@app.get("/verify-log")
def verify_log(principal: dict = Depends(auth.require_action("verify_log"))):
    ok, broken_at = auditlog.verify()
    if ok:
        return {"ok": True, "broken_at": None}
    message = f"Chain verification failed at entry {broken_at}"
    if not auditlog.tamper_alert_exists(message):
        auditlog.append("sentinel", "tamper_alert", message)
    return {"ok": False, "broken_at": broken_at}


# ------------------------------------------------------------------ /selftest

@app.post("/selftest")
def selftest(body: SelftestBody, principal: dict = Depends(auth.require_action("selftest"))):
    verdict = "PASS" if body.passed else "FAIL"
    auditlog.append(
        "sentinel", "selftest", f"{verdict} {body.name}: {body.detail}"
    )
    return {"ok": True}


# ------------------------------------------------------------- lab endpoints

@app.get("/vm/state")
def vm_state(principal: dict = Depends(auth.require_action("vm_state"))):
    """Guest up/down, snapshot availability, egress-guard state for the tray."""
    try:
        return vm_manager.vm_state()
    except vm_manager.VMError as error:
        raise HTTPException(status_code=503, detail=str(error))


@app.post("/vm/action")
def vm_action(
    body: VmActionBody,
    principal: dict = Depends(auth.require_action("vm_action")),
):
    """Start or stop one lab guest. The isolation check runs first and the
    action is refused (403-style VMError -> 503) when any rule trips."""
    user = f"{principal['u']}({principal['r']})"
    try:
        if body.action == "start":
            result = vm_manager.start_vm(body.vm, user)
        else:
            result = vm_manager.stop_vm(body.vm, user)
    except vm_manager.VMError as error:
        raise HTTPException(status_code=503, detail=str(error))
    return dict(result, by=principal["r"])


@app.post("/vm/reset")
def vm_reset(principal: dict = Depends(auth.require_action("vm_action"))):
    """Revert the whole lab to the clean snapshot (Reset lab in the UI)."""
    user = f"{principal['u']}({principal['r']})"
    try:
        result = vm_manager.reset_lab(user)
    except vm_manager.VMError as error:
        raise HTTPException(status_code=503, detail=str(error))
    return dict(result, by=principal["r"])


@app.post("/ingest")
def ingest(body: IngestBody, request: Request):
    """Collector entry point (blue-vm only). Authenticated by a dedicated
    shared token (COLLECTOR_INGEST_TOKEN), not a user token: no role may
    push guest events by hand."""
    import hmac as hmac_mod
    import os as os_mod

    header = request.headers.get("Authorization", "")
    token = header[len("Bearer "):].strip() if header.startswith("Bearer ") else ""
    expected = os_mod.environ.get("COLLECTOR_INGEST_TOKEN", "")
    if not expected or not hmac_mod.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="collector token required")
    stored = []
    for event in body.events:
        try:
            stored.append(
                auditlog.append(
                    "blue",
                    str(event.get("type", "host_event")),
                    str(event.get("message", ""))[:1000],
                )
            )
        except ValueError:
            continue  # unknown type from a misbehaving collector: drop it
    return {"ok": True, "stored": len(stored)}


@app.websocket("/ws/pty")
async def ws_pty(websocket: WebSocket, vm: str = Query("red-vm")):
    """Real shell into a lab guest over SSH; role decides which guest."""
    principal = auth.authenticate_websocket(websocket)
    if principal is None:
        await websocket.close(code=4401)
        return
    if not policy.role_allowed("pty", principal["r"]):
        await websocket.close(code=4403)
        return
    try:
        await pty_bridge.open_pty_session(websocket, principal, vm)
    except Exception:
        log.exception("pty session failed")
        try:
            await websocket.close(code=4500)
        except RuntimeError:
            pass
