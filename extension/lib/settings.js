/* Shared settings (chrome.storage.sync). Holds configuration only — never detected values. */
(function (root) {
  "use strict";
  const DEFAULTS = {
    serverUrl: "http://localhost:8765",
    token: "",
    aiSites: ["chat.openai.com", "chatgpt.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com", "perplexity.ai"],
    customRules: [],          // [{kind, pattern}]
    siteMode: "deny",         // "deny": run everywhere except siteList; "allow": only on siteList
    siteList: [],
    highlight: true,          // outline sensitive elements
    guard: true,              // paste/submit guard on AI sites
    maskByDefault: false,
  };
  const ALLOWED_SERVERS = ["http://localhost:8765", "http://127.0.0.1:8765"];

  async function load() {
    try {
      const got = await chrome.storage.sync.get(DEFAULTS);
      return { ...DEFAULTS, ...got };
    } catch (_) { return { ...DEFAULTS }; }
  }
  async function save(patch) { await chrome.storage.sync.set(patch); }

  /** host matches pattern "example.com" (also subdomains) */
  function hostMatches(host, pattern) {
    host = String(host || "").toLowerCase(); pattern = String(pattern || "").trim().toLowerCase().replace(/^\*\./, "");
    return !!pattern && (host === pattern || host.endsWith("." + pattern));
  }
  function siteEnabled(settings, host) {
    const listed = (settings.siteList || []).some((p) => hostMatches(host, p));
    return settings.siteMode === "allow" ? listed : !listed;
  }
  function isAiSite(settings, host) { return (settings.aiSites || []).some((p) => hostMatches(host, p)); }
  function serverBase(settings) {
    const u = String(settings.serverUrl || "").replace(/\/+$/, "");
    return ALLOWED_SERVERS.includes(u) ? u : DEFAULTS.serverUrl;
  }
  function serverHeaders(settings, extra) {
    const h = { ...(extra || {}) };
    if (settings.token) h["X-Zen-Token"] = settings.token;
    return h;
  }
  /** Health check with timeout. Resolves {ok:false} offline — never throws. */
  async function health(settings, ms = 1500) {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), ms);
    try {
      const r = await fetch(serverBase(settings) + "/api/health", { signal: ctl.signal, headers: serverHeaders(settings), cache: "no-store" });
      if (!r.ok) return { ok: false, status: r.status };
      const j = await r.json();
      return { ok: !!j.ok, version: j.version, features: j.features || {} };
    } catch (_) { return { ok: false }; } finally { clearTimeout(t); }
  }

  const KIND_INFO = {
    CARD: "Payment card number (passes Luhn checksum)",
    CVV: "Card security code",
    CARD_EXP: "Card expiry date",
    AADHAAR: "Aadhaar number (passes Verhoeff checksum)",
    PAN: "Indian PAN (tax ID) format",
    EMAIL: "Email address",
    PHONE: "Indian mobile number",
    IP: "IPv4 / IPv6 address",
    API_KEY: "API key / cloud credential",
    TOKEN: "Auth token (JWT / bearer / session)",
    SECRET: "Secret value (field marked secret)",
    PASSWORD: "Password (field type or 'password:' text)",
    OTP: "One-time code",
    PIN: "PIN field",
    NAME: "Personal name (name/cardholder field)",
    ADDRESS: "Postal address field",
    FACE: "Camera / face media",
  };
  const KIND_COLORS = {
    CARD: "#d9480f", CVV: "#d9480f", CARD_EXP: "#e8590c", AADHAAR: "#9c36b5", PAN: "#862e9c", EMAIL: "#1971c2",
    PHONE: "#0c8599", IP: "#5c940d", API_KEY: "#c92a2a", TOKEN: "#c2255c", SECRET: "#c92a2a", PASSWORD: "#e03131",
    OTP: "#f08c00", PIN: "#f08c00", NAME: "#495057", ADDRESS: "#2b8a3e", FACE: "#364fc7",
  };
  const kindColor = (k) => KIND_COLORS[k] || "#7048e8";

  const api = { DEFAULTS, ALLOWED_SERVERS, load, save, hostMatches, siteEnabled, isAiSite, serverBase, serverHeaders, health, KIND_INFO, kindColor };
  root.ZenSettings = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
