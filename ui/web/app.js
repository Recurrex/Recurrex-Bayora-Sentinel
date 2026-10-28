/* Bayora Sentinel — web dashboard
 *
 * Read-only client for the broker. No frameworks, no build step, no storage.
 * The session token lives in this closure only: it is never written to
 * localStorage/sessionStorage, never inserted into the page, and never logged.
 *
 * Event messages are attacker-controlled. Every piece of broker data is put
 * into the DOM with textContent or DOM nodes; innerHTML is not used.
 */

(() => {
  "use strict";

  const KNOWN_TYPES = [
    "attack",
    "response",
    "defense",
    "leak_alert",
    "selftest",
    "tamper_alert",
  ];

  const STATUS_MS = 3000;
  const VERIFY_MS = 10000;
  const POLL_MS = 1000;
  const RECONNECT_BASE_MS = 1000;
  const RECONNECT_MAX_MS = 15000;
  const FRESH_MS = 2600;
  const MAX_ROWS = 500;

  const timeFormatter = new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const els = {};
  let state = null;

  class AuthError extends Error {
    constructor() {
      super("unauthorized");
      this.name = "AuthError";
    }
  }

  class ApiError extends Error {
    constructor(status) {
      super("broker request failed");
      this.name = "ApiError";
      this.status = status;
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }

  function boot() {
    cacheElements();
    state = {
      config: null,
      stopped: false,
      events: new Map(),
      signatures: new Map(),
      cursor: 0,
      filter: "all",
      fresh: new Map(),
      latestAlertId: 0,
      dismissedAlertId: 0,
      initialLoaded: false,
      unreachable: false,

      pollTimer: null,
      pollBootTimer: null,
      pollInFlight: false,
      statusTimer: null,
      verifyTimer: null,
      verifyInFlight: false,
      reportInFlight: false,
      reconnectTimer: null,
      reconnectDelay: RECONNECT_BASE_MS,

      ws: null,
      wsUp: false,

      renderQueued: false,
      connectionKey: null,
    };

    bindEvents();

    const config = readConfig();
    if (!config) {
      showSetup();
      return;
    }

    state.config = config;
    setSession(decodeTokenPayload(config.token));
    els.setupNotice.hidden = true;
    enableControls();
    start();
  }

  function cacheElements() {
    els.setupNotice = document.getElementById("setup-notice");
    els.connectionNotice = document.getElementById("connection-notice");
    els.connectionText = document.getElementById("connection-text");
    els.alertBanner = document.getElementById("alert-banner");
    els.alertKicker = document.getElementById("alert-kicker");
    els.alertTitle = document.getElementById("alert-title");
    els.alertMessage = document.getElementById("alert-message");
    els.alertMeta = document.getElementById("alert-meta");
    els.alertDismiss = document.getElementById("alert-dismiss");

    els.sessionUser = document.getElementById("session-user");
    els.sessionRole = document.getElementById("session-role");
    els.statusBar = document.getElementById("status-bar");
    els.statusUpdated = document.getElementById("status-updated");

    els.eventsHeading = document.getElementById("events-heading");
    els.eventsTable = document.getElementById("events-table");
    els.eventsBody = document.getElementById("events-body");
    els.eventsEmpty = document.getElementById("events-empty");
    els.eventsCount = document.getElementById("events-count");
    els.typeFilter = document.getElementById("type-filter");
    els.liveState = document.getElementById("live-state");
    els.liveText = document.getElementById("live-text");

    els.verifyButton = document.getElementById("verify-button");
    els.integrityBadge = document.getElementById("integrity-badge");
    els.integrityText = document.getElementById("integrity-text");
    els.integrityMeta = document.getElementById("integrity-meta");

    els.reportRefresh = document.getElementById("report-refresh");
    els.reportLeaks = document.getElementById("report-leaks");
    els.reportTamper = document.getElementById("report-tamper");
    els.reportSecure = document.getElementById("report-secure");
    els.reportRisk = document.getElementById("report-risk");
    els.reportState = document.getElementById("report-state");
  }

  function bindEvents() {
    els.typeFilter.addEventListener("change", () => {
      const value = els.typeFilter.value;
      state.filter = value || "all";
      requestRender();
    });

    els.alertDismiss.addEventListener("click", dismissAlert);
    els.verifyButton.addEventListener("click", () => {
      refreshIntegrity();
    });
    els.reportRefresh.addEventListener("click", () => {
      refreshReport();
    });

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState !== "visible" || !state || state.stopped) {
        return;
      }
      refreshStatus();
      refreshIntegrity();
      refreshReport();
      if (!state.wsUp) {
        pollEvents();
      }
    });
  }

  /* -----------------------------------------------------------------------
     Configuration and identity
     --------------------------------------------------------------------- */

  function readConfig() {
    const raw = window.SENTINEL;
    if (!raw || typeof raw !== "object") {
      return null;
    }
    const brokerValue = typeof raw.broker === "string" ? raw.broker.trim() : "";
    const token = typeof raw.token === "string" ? raw.token.trim() : "";
    if (!brokerValue || !token) {
      return null;
    }

    let brokerUrl;
    try {
      brokerUrl = new URL(brokerValue);
    } catch {
      return null;
    }
    if (brokerUrl.protocol !== "http:" && brokerUrl.protocol !== "https:") {
      return null;
    }
    brokerUrl.hash = "";
    brokerUrl.search = "";
    const broker = brokerUrl.toString().replace(/\/+$/, "");
    return { broker, token };
  }

  function decodeTokenPayload(token) {
    try {
      const body = token.split(".")[0];
      if (!body) {
        return null;
      }
      let base64 = body.replace(/-/g, "+").replace(/_/g, "/");
      base64 += "=".repeat((4 - (base64.length % 4)) % 4);
      const binary = atob(base64);
      const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      const payload = JSON.parse(text);
      return payload && typeof payload === "object" ? payload : null;
    } catch {
      return null;
    }
  }

  function setSession(payload) {
    const user =
      payload && typeof payload.u === "string" && payload.u.trim()
        ? payload.u.trim().slice(0, 120)
        : "unknown";
    const role =
      payload && typeof payload.r === "string" && payload.r.trim()
        ? payload.r.trim().slice(0, 40)
        : "unknown";
    els.sessionUser.textContent = user;
    els.sessionRole.textContent = role;
  }

  function showSetup() {
    els.setupNotice.hidden = false;
    els.alertBanner.hidden = true;
    els.connectionNotice.hidden = true;
    els.sessionUser.textContent = "unknown";
    els.sessionRole.textContent = "unknown";
    els.statusUpdated.textContent = "not connected";
    els.eventsEmpty.textContent = "Not connected. Launch with sentinel web.";
    els.eventsEmpty.hidden = false;
    els.eventsTable.hidden = true;
    els.eventsCount.textContent = "";
    els.liveState.dataset.mode = "offline";
    els.liveText.textContent = "Offline";
    els.integrityBadge.dataset.tone = "unknown";
    els.integrityText.textContent = "Not checked";
    els.integrityMeta.textContent = "Waiting for a configured dashboard.";
    els.reportState.textContent = "Not connected.";
    disableControls();
    renderStatusUnavailable("not connected");
  }

  function start() {
    setLive("connecting");
    els.eventsEmpty.textContent = "Loading events…";
    enableControls();

    refreshStatus();
    refreshReport();
    refreshIntegrity();
    scheduleVerify();
    loadInitialEvents();
    connectSocket();

    // If the socket is slow to open, start the HTTP fallback immediately.
    state.pollBootTimer = window.setTimeout(() => {
      if (!state.stopped && !state.wsUp) {
        startPolling();
      }
    }, 1200);
  }

  function enableControls() {
    els.typeFilter.disabled = false;
    els.verifyButton.disabled = false;
    els.reportRefresh.disabled = false;
  }

  function disableControls() {
    els.typeFilter.disabled = true;
    els.verifyButton.disabled = true;
    els.reportRefresh.disabled = true;
  }

  /* -----------------------------------------------------------------------
     HTTP
     --------------------------------------------------------------------- */

  async function api(path) {
    if (!state.config || state.stopped) {
      throw new AuthError();
    }
    let response;
    try {
      response = await fetch(state.config.broker + path, {
        method: "GET",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          Authorization: "Bearer " + state.config.token,
        },
      });
    } catch {
      throw new ApiError(0);
    }

    if (response.status === 401) {
      onUnauthorized();
      throw new AuthError();
    }
    if (!response.ok) {
      throw new ApiError(response.status);
    }

    try {
      return await response.json();
    } catch {
      throw new ApiError(response.status);
    }
  }

  function brokerHost() {
    try {
      return new URL(state.config.broker).host;
    } catch {
      return "the broker";
    }
  }

  function markUnreachable() {
    if (state.stopped) {
      return;
    }
    state.unreachable = true;
    setConnection(
      "unreachable",
      "warn",
      "Broker unreachable at " + brokerHost() + ". Retrying automatically."
    );
    renderStatusUnavailable("retrying");
    requestRender();
  }

  function markReachable() {
    state.unreachable = false;
    clearConnection("unreachable");
  }

  function setConnection(key, tone, text) {
    if (state.connectionKey === "session") {
      return;
    }
    state.connectionKey = key;
    els.connectionNotice.dataset.kind = tone;
    els.connectionText.textContent = text;
    els.connectionNotice.hidden = false;
  }

  function clearConnection(key) {
    if (state.connectionKey === key) {
      state.connectionKey = null;
      els.connectionNotice.hidden = true;
      els.connectionText.textContent = "";
    }
  }

  function onUnauthorized() {
    if (state.stopped) {
      return;
    }
    state.stopped = true;
    clearTimers();
    closeSocket();
    disableControls();
    setLive("offline");
    state.connectionKey = "session";
    els.connectionNotice.dataset.kind = "error";
    els.connectionText.textContent =
      "Session expired. Run sentinel again to sign in with a fresh session.";
    els.connectionNotice.hidden = false;
    els.statusUpdated.textContent = "session expired";
    els.eventsEmpty.hidden = false;
    els.eventsEmpty.textContent = "Session expired. Run sentinel again.";
    els.integrityBadge.dataset.tone = "unknown";
    els.integrityText.textContent = "Not available";
    els.integrityMeta.textContent = "The broker rejected this session.";
    els.reportState.textContent = "Session expired. Run sentinel again.";
    renderStatusUnavailable("session expired");
  }

  function clearTimers() {
    window.clearTimeout(state.statusTimer);
    window.clearTimeout(state.verifyTimer);
    window.clearTimeout(state.pollTimer);
    window.clearTimeout(state.pollBootTimer);
    window.clearTimeout(state.reconnectTimer);
    state.statusTimer = null;
    state.verifyTimer = null;
    state.pollTimer = null;
    state.pollBootTimer = null;
    state.reconnectTimer = null;
  }

  /* -----------------------------------------------------------------------
     Status
     --------------------------------------------------------------------- */

  async function refreshStatus() {
    if (state.stopped) {
      return;
    }
    window.clearTimeout(state.statusTimer);
    try {
      const status = await api("/status");
      if (!status || typeof status !== "object") {
        throw new ApiError(200);
      }
      renderStatus(status);
      markReachable();
    } catch (error) {
      if (!(error instanceof AuthError)) {
        markUnreachable();
      }
    } finally {
      if (!state.stopped) {
        state.statusTimer = window.setTimeout(refreshStatus, STATUS_MS);
      }
    }
  }

  function renderStatus(status) {
    setStatusItem("broker", valueText(status.broker), toneForUp(status.broker));
    setStatusItem("red", valueText(status.red), toneForUp(status.red));
    setStatusItem("blue", valueText(status.blue), toneForUp(status.blue));
    setStatusItem("ai", valueText(status.ai), toneForUp(status.ai));

    const testValue = valueText(status.test);
    setStatusItem(
      "test",
      testValue,
      status.test === "running" ? "warn" : status.test === "idle" ? "idle" : "unknown"
    );

    if (typeof status.log_ok === "boolean") {
      setStatusItem("log_ok", status.log_ok ? "ok" : "BROKEN", status.log_ok ? "good" : "bad");
    } else {
      setStatusItem("log_ok", "unknown", "unknown");
    }

    els.statusUpdated.textContent = "updated " + clockTime(new Date());
  }

  function renderStatusUnavailable(reason) {
    const keys = ["broker", "red", "blue", "ai", "test", "log_ok"];
    for (const key of keys) {
      const value = key === "broker" ? reason : "unknown";
      const tone = key === "broker" ? (reason === "retrying" ? "warn" : "bad") : "unknown";
      setStatusItem(key, value, tone);
    }
    els.statusUpdated.textContent =
      reason === "retrying" ? "broker unreachable · retrying" : reason;
  }

  function setStatusItem(key, value, tone) {
    const item = els.statusBar.querySelector('[data-key="' + key + '"]');
    if (!item) {
      return;
    }
    const dot = item.querySelector(".status-dot");
    const valueNode = item.querySelector(".status-value");
    if (dot) {
      dot.dataset.tone = tone;
    }
    if (valueNode) {
      valueNode.textContent = value;
    }
    item.dataset.tone = tone;
  }

  function toneForUp(value) {
    if (value === "up") {
      return "good";
    }
    if (value === "down") {
      return "bad";
    }
    return "unknown";
  }

  function valueText(value) {
    if (typeof value === "string" && value.trim()) {
      return value.trim().slice(0, 40);
    }
    return "unknown";
  }

  /* -----------------------------------------------------------------------
     Events: initial load, polling, socket
     --------------------------------------------------------------------- */

  async function loadInitialEvents() {
    if (state.stopped) {
      return;
    }
    try {
      const events = await api("/events?since=0");
      ingest(events, { highlight: false });
      markReachable();
    } catch (error) {
      if (!(error instanceof AuthError)) {
        markUnreachable();
      }
    } finally {
      state.initialLoaded = true;
      requestRender();
    }
  }

  async function pollEvents() {
    if (state.stopped || state.wsUp) {
      return;
    }
    if (state.pollInFlight) {
      return;
    }
    state.pollInFlight = true;
    window.clearTimeout(state.pollTimer);
    try {
      const events = await api("/events?since=" + encodeURIComponent(state.cursor));
      ingest(events, { highlight: true });
      markReachable();
    } catch (error) {
      if (!(error instanceof AuthError)) {
        markUnreachable();
      }
    } finally {
      state.pollInFlight = false;
      if (!state.stopped && !state.wsUp) {
        state.pollTimer = window.setTimeout(pollEvents, POLL_MS);
      }
    }
  }

  function startPolling() {
    if (state.stopped || state.wsUp || state.pollTimer || state.pollInFlight) {
      return;
    }
    setLive("polling");
    pollEvents();
  }

  function stopPolling() {
    window.clearTimeout(state.pollTimer);
    state.pollTimer = null;
  }

  async function catchUp() {
    if (state.stopped) {
      return;
    }
    try {
      const events = await api("/events?since=" + encodeURIComponent(state.cursor));
      ingest(events, { highlight: true });
      markReachable();
    } catch (error) {
      if (!(error instanceof AuthError)) {
        markUnreachable();
      }
    }
  }

  function connectSocket() {
    if (state.stopped) {
      return;
    }
    let url;
    try {
      const socketUrl = new URL(state.config.broker);
      socketUrl.protocol = socketUrl.protocol === "https:" ? "wss:" : "ws:";
      socketUrl.pathname = socketUrl.pathname.replace(/\/+$/, "") + "/ws/events";
      socketUrl.searchParams.set("token", state.config.token);
      socketUrl.hash = "";
      url = socketUrl.toString();
    } catch {
      scheduleReconnect();
      return;
    }

    let socket;
    try {
      socket = new WebSocket(url);
    } catch {
      setLive("polling");
      startPolling();
      scheduleReconnect();
      return;
    }

    state.ws = socket;
    setLive("connecting");

    socket.onopen = () => {
      if (state.ws !== socket || state.stopped) {
        return;
      }
      state.wsUp = true;
      state.reconnectDelay = RECONNECT_BASE_MS;
      window.clearTimeout(state.reconnectTimer);
      state.reconnectTimer = null;
      stopPolling();
      setLive("live");
      catchUp();
    };

    socket.onmessage = (message) => {
      if (state.ws !== socket || state.stopped) {
        return;
      }
      handleSocketMessage(message.data);
    };

    socket.onerror = () => {
      try {
        socket.close();
      } catch {
        /* The close handler below owns reconnection. */
      }
    };

    socket.onclose = (event) => {
      if (state.ws !== socket) {
        return;
      }
      state.ws = null;
      state.wsUp = false;
      if (state.stopped) {
        return;
      }
      if (event.code === 4401) {
        onUnauthorized();
        return;
      }
      setLive("polling");
      startPolling();
      scheduleReconnect();
    };
  }

  function scheduleReconnect() {
    if (state.stopped || state.reconnectTimer) {
      return;
    }
    const delay = state.reconnectDelay;
    state.reconnectTimer = window.setTimeout(() => {
      state.reconnectTimer = null;
      connectSocket();
    }, delay);
    state.reconnectDelay = Math.min(state.reconnectDelay * 2, RECONNECT_MAX_MS);
  }

  function closeSocket() {
    if (!state.ws) {
      return;
    }
    const socket = state.ws;
    state.ws = null;
    state.wsUp = false;
    socket.onopen = null;
    socket.onmessage = null;
    socket.onerror = null;
    socket.onclose = null;
    try {
      socket.close();
    } catch {
      /* Nothing to clean up. */
    }
  }

  function handleSocketMessage(raw) {
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      return;
    }
    if (Array.isArray(data)) {
      ingest(data, { highlight: true });
      return;
    }
    if (data && typeof data === "object") {
      ingest([data], { highlight: true });
    }
  }

  function ingest(rawEvents, options) {
    if (state.stopped) {
      return;
    }
    const highlight = Boolean(options && options.highlight);
    const incoming = Array.isArray(rawEvents) ? rawEvents : [];
    const addedIds = [];
    const changedIds = [];
    let alertArrived = false;
    let tamperArrived = false;

    for (const raw of incoming) {
      const event = normalizeEvent(raw);
      if (!event) {
        continue;
      }
      const key = String(event.id);
      const previous = state.events.get(key);
      const signature =
        event.time +
        "\u0000" +
        event.source +
        "\u0000" +
        event.type +
        "\u0000" +
        event.message +
        "\u0000" +
        (event.canary_hit ? "1" : "0");

      if (!previous) {
        addedIds.push(key);
      } else if (state.signatures.get(key) !== signature) {
        changedIds.push(key);
      }

      state.events.set(key, event);
      state.signatures.set(key, signature);
      if (event.id > state.cursor) {
        state.cursor = event.id;
      }
      if (event.type === "leak_alert" || event.type === "tamper_alert") {
        alertArrived = true;
        if (event.type === "tamper_alert") {
          tamperArrived = true;
        }
      }
    }

    if (addedIds.length || changedIds.length) {
      syncTypeOptions();
      if (highlight && addedIds.length) {
        markFresh(addedIds);
      }
      updateAlertFromEvents();
      requestRender();
    }

    if (alertArrived) {
      // A tamper alert means the chain is already known to be broken; do not
      // make the viewer wait for the next 10-second verification tick.
      refreshReport();
      if (tamperArrived) {
        refreshIntegrity();
        refreshStatus();
      }
    }
  }

  function normalizeEvent(raw) {
    if (!raw || typeof raw !== "object") {
      return null;
    }
    const id = Number(raw.id);
    if (!Number.isSafeInteger(id) || id <= 0) {
      return null;
    }
    return {
      id,
      time: typeof raw.time === "string" ? raw.time : "",
      source: typeof raw.source === "string" ? raw.source : "unknown",
      type: typeof raw.type === "string" ? raw.type : "unknown",
      message: typeof raw.message === "string" ? raw.message : "",
      canary_hit: raw.canary_hit === true,
    };
  }

  function markFresh(ids) {
    const until = Date.now() + FRESH_MS;
    for (const id of ids) {
      state.fresh.set(String(id), until);
    }
    window.setTimeout(() => {
      const now = Date.now();
      for (const [id, expiry] of state.fresh) {
        if (expiry <= now) {
          state.fresh.delete(id);
        }
      }
      requestRender();
    }, FRESH_MS + 80);
  }

  function requestRender() {
    if (state.renderQueued) {
      return;
    }
    state.renderQueued = true;
    window.requestAnimationFrame(() => {
      state.renderQueued = false;
      renderEvents();
    });
  }

  function renderEvents() {
    if (!state) {
      return;
    }
    const all = Array.from(state.events.values()).sort((a, b) => b.id - a.id);
    const filtered =
      state.filter === "all" ? all : all.filter((event) => event.type === state.filter);
    const rows = filtered.slice(0, MAX_ROWS);
    const fragment = document.createDocumentFragment();

    for (const event of rows) {
      fragment.appendChild(createRow(event));
    }
    els.eventsBody.replaceChildren(fragment);

    const hasRows = rows.length > 0;
    els.eventsTable.hidden = !hasRows;
    els.eventsEmpty.hidden = hasRows;

    if (!hasRows) {
      if (!state.initialLoaded && all.length === 0) {
        els.eventsEmpty.textContent = "Loading events…";
      } else if (all.length === 0 && state.unreachable) {
        els.eventsEmpty.textContent = "Broker unreachable. Retrying automatically.";
      } else if (all.length === 0) {
        els.eventsEmpty.textContent =
          "No events yet. New broker entries will appear here as they are logged.";
      } else if (state.filter !== "all") {
        els.eventsEmpty.textContent =
          "No " + state.filter + " events yet. Choose another type to see the rest.";
      } else {
        els.eventsEmpty.textContent = "No events to display.";
      }
    }

    if (all.length === 0) {
      els.eventsCount.textContent = "";
    } else {
      const filterLabel = state.filter === "all" ? "" : " " + state.filter;
      const truncated =
        filtered.length > rows.length
          ? " · showing the latest " + rows.length
          : "";
      els.eventsCount.textContent =
        filtered.length +
        filterLabel +
        (filtered.length === 1 ? " event" : " events") +
        truncated +
        " · newest first";
    }
  }

  function createRow(event) {
    const key = String(event.id);
    const row = document.createElement("tr");
    row.dataset.id = key;

    if (event.type === "leak_alert" || event.type === "tamper_alert") {
      row.classList.add("event-critical");
    }
    if (event.canary_hit) {
      row.classList.add("event-canary");
    }
    if (state.fresh.has(key)) {
      row.classList.add("is-new");
    }

    const idCell = document.createElement("td");
    idCell.className = "cell-id";
    idCell.textContent = String(event.id);
    row.appendChild(idCell);

    const timeCell = document.createElement("td");
    timeCell.className = "cell-time";
    const timeNode = document.createElement("time");
    timeNode.dateTime = event.time;
    timeNode.title = event.time;
    timeNode.textContent = formatEventTime(event.time);
    timeCell.appendChild(timeNode);
    row.appendChild(timeCell);

    const sourceCell = document.createElement("td");
    sourceCell.className = "cell-source";
    const sourceChip = document.createElement("span");
    sourceChip.className = "chip chip-source";
    sourceChip.dataset.source = event.source;
    sourceChip.textContent = event.source;
    sourceCell.appendChild(sourceChip);
    row.appendChild(sourceCell);

    const typeCell = document.createElement("td");
    typeCell.className = "cell-type";
    const typeChip = document.createElement("span");
    typeChip.className = "chip chip-type";
    typeChip.dataset.type = event.type;
    typeChip.textContent = event.type;
    typeCell.appendChild(typeChip);
    row.appendChild(typeCell);

    const messageCell = document.createElement("td");
    messageCell.className = "cell-message event-message";
    if (event.canary_hit) {
      const canary = document.createElement("span");
      canary.className = "canary-mark";
      canary.textContent = "CANARY";
      messageCell.appendChild(canary);
    }
    messageCell.appendChild(document.createTextNode(event.message));
    row.appendChild(messageCell);

    return row;
  }

  function syncTypeOptions() {
    const types = new Set(KNOWN_TYPES);
    for (const event of state.events.values()) {
      if (event.type) {
        types.add(event.type);
      }
    }
    const existing = new Set(
      Array.from(els.typeFilter.options).map((option) => option.value)
    );
    const extras = Array.from(types)
      .filter((type) => !existing.has(type) && type !== "all")
      .sort();

    for (const type of extras) {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      els.typeFilter.appendChild(option);
    }
  }

  function formatEventTime(value) {
    if (!value) {
      return "—";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value.slice(0, 24);
    }
    return timeFormatter.format(date);
  }

  function clockTime(date) {
    return timeFormatter.format(date);
  }

  /* -----------------------------------------------------------------------
     Alerts
     --------------------------------------------------------------------- */

  function updateAlertFromEvents() {
    const alerts = Array.from(state.events.values()).filter(
      (event) => event.type === "leak_alert" || event.type === "tamper_alert"
    );
    if (!alerts.length) {
      return;
    }
    alerts.sort((a, b) => b.id - a.id);
    const latest = alerts[0];
    state.latestAlertId = latest.id;

    if (latest.id <= state.dismissedAlertId) {
      return;
    }


    const unread = alerts.filter((event) => event.id > state.dismissedAlertId).length;
    const tamper = latest.type === "tamper_alert";
    els.alertKicker.textContent = tamper ? "Integrity alert" : "Policy alert";
    els.alertTitle.textContent = tamper
      ? "Audit log tamper detected"
      : "Canary leak detected";
    els.alertMessage.textContent = latest.message || "See the event feed for details.";
    els.alertMeta.textContent =
      "event #" +
      latest.id +
      " · " +
      formatEventTime(latest.time) +
      " · source " +
      latest.source +
      (unread > 1 ? " · " + unread + " unread alerts" : "");
    els.alertBanner.dataset.type = latest.type;
    els.alertBanner.hidden = false;
  }

  function dismissAlert() {
    state.dismissedAlertId = Math.max(state.dismissedAlertId, state.latestAlertId);
    els.alertBanner.hidden = true;
    els.eventsHeading.focus({ preventScroll: true });
  }

  /* -----------------------------------------------------------------------
     Integrity
     --------------------------------------------------------------------- */

  function scheduleVerify() {
    window.clearTimeout(state.verifyTimer);
    if (state.stopped) {
      return;
    }
    state.verifyTimer = window.setTimeout(async () => {
      await refreshIntegrity();
      scheduleVerify();
    }, VERIFY_MS);
  }

  async function refreshIntegrity() {
    if (!state || state.stopped || state.verifyInFlight) {
      return;
    }
    state.verifyInFlight = true;
    if (els.verifyButton) {
      els.verifyButton.disabled = true;
    }
    try {
      const result = await api("/verify-log");
      renderIntegrity(result);
    } catch (error) {
      if (!(error instanceof AuthError)) {
        setIntegrity(
          "unknown",
          "Integrity unavailable",
          "The broker did not answer the verification check."
        );
      }
    } finally {
      state.verifyInFlight = false;
      if (els.verifyButton) {
        els.verifyButton.disabled = state.stopped;
      }
    }
  }

  function renderIntegrity(result) {
    if (!result || typeof result.ok !== "boolean") {
      setIntegrity("unknown", "Integrity unknown", "Unexpected response from /verify-log.");
      return;
    }
    if (result.ok) {
      setIntegrity("good", "chain OK", "Checked " + clockTime(new Date()) + " · SHA-256 chain intact.");
      return;
    }
    const brokenAt = result.broken_at;
    const label =
      Number.isSafeInteger(brokenAt) && brokenAt >= 0 ? String(brokenAt) : "?";
    setIntegrity(
      "bad",
      "chain BROKEN at entry " + label,
      "Checked " + clockTime(new Date()) + " · an audit entry no longer matches its hash."
    );
  }

  function setIntegrity(tone, text, meta) {
    els.integrityBadge.dataset.tone = tone;
    els.integrityText.textContent = text;
    els.integrityMeta.textContent = meta;
  }

  /* -----------------------------------------------------------------------
     Report
     --------------------------------------------------------------------- */

  async function refreshReport() {
    if (!state || state.stopped || state.reportInFlight) {
      return;
    }
    state.reportInFlight = true;
    els.reportRefresh.disabled = true;
    els.reportState.textContent = "Loading report…";
    const panel = els.reportSecure.closest(".report-panel");
    if (panel) {
      panel.setAttribute("aria-busy", "true");
    }
    try {
      const report = await api("/report");
      renderReport(report);
      els.reportState.textContent =
        "Updated " + clockTime(new Date()) + " · broker assessment, read-only.";
    } catch (error) {
      if (!(error instanceof AuthError)) {
        els.reportState.textContent = "Report unavailable — the broker did not answer.";
      }
    } finally {
      state.reportInFlight = false;
      els.reportRefresh.disabled = state.stopped;
      if (panel) {
        panel.removeAttribute("aria-busy");
      }
    }
  }

  function renderReport(report) {
    if (!report || typeof report !== "object") {
      els.reportState.textContent = "Report unavailable — unexpected response.";
      return;
    }

    const leaks = Number(report.leaks);
    els.reportLeaks.textContent = Number.isFinite(leaks) && leaks >= 0 ? String(leaks) : "—";

    const tampered = report.tamper_detected === true;
    els.reportTamper.textContent = tampered ? "detected" : "none";
    els.reportTamper.dataset.tone = tampered ? "bad" : "good";

    renderReportList(els.reportSecure, report.secure);
    renderReportList(els.reportRisk, report.residual_risk);
  }

  function renderReportList(list, items) {
    const fragment = document.createDocumentFragment();
    const values = Array.isArray(items)
      ? items.filter((item) => typeof item === "string" && item.trim())
      : [];

    if (!values.length) {
      const item = document.createElement("li");
      item.className = "list-empty";
      item.textContent = "None reported.";
      fragment.appendChild(item);
    } else {
      for (const value of values) {
        const item = document.createElement("li");
        item.textContent = value;
        fragment.appendChild(item);
      }
    }
    list.replaceChildren(fragment);
  }

  /* -----------------------------------------------------------------------
     Live-state indicator
     --------------------------------------------------------------------- */

  function setLive(mode) {
    const labels = {
      live: "Live · socket",
      polling: "Polling · 1 s",
      connecting: "Connecting",
      offline: "Offline",
    };
    if (!els.liveState) {
      return;
    }
    els.liveState.dataset.mode = mode;
    els.liveText.textContent = labels[mode] || "Unknown";
  }
})();
