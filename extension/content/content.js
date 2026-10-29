/*
 * Zen content script: scans visible text + form fields LOCALLY, outlines sensitive items with a
 * per-kind badge, optional on-screen mask. Never mutates page text or input values (all visuals live
 * in a closed shadow-root overlay), never sends anything over the network, never stores values.
 */
(function () {
  "use strict";
  if (globalThis.__ZenContent) return; // idempotent (scripting.executeScript re-injection)
  const Z = globalThis.ZenDetect, ST = globalThis.ZenStructural, CFG = globalThis.ZenSettings;

  const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "TEXTAREA", "INPUT", "SELECT", "OPTION", "IFRAME", "OBJECT", "HEAD", "TITLE"]);
  const MAX_NODES = 20000, MAX_FINDINGS = 800, MAX_ELEMS = 6000;
  const FIELD_SEL = "input, textarea, select";
  const HINT_SEL = "[id],[class],[name],[aria-label],[title],[data-testid],img,video,canvas";

  const state = {
    settings: { ...CFG.DEFAULTS }, customRules: [], enabled: false, mask: false,
    findings: [],   // {kind, reason, el?:Element, range?:Range, field?:bool}  — no values kept
    host: null, layer: null, rescanTimer: 0, rafPending: false, lastScan: 0,
    agent: false, probeTimer: 0, armSheet: null, domRedacted: [], masked: new Map(),  // Agent Shield
  };
  const SHIELD_MIN_GAP = 40; // ms between rescans while the shield is up (normal mode: 600)
  /** Agent Shield is up when forced on, or in auto mode when an automation signal is present. */
  function shieldOn() {
    const m = state.settings.shieldMode;
    return m === "on" || (m !== "off" && (navigator.webdriver === true || state.agent));
  }
  const ZL = (globalThis.__ZenContent = { state, scheduleScan, render, ui: {} });

  // ---------- overlay ----------
  /** Constructable stylesheet (not subject to page style-src CSP); <style> fallback. */
  function adoptCss(sr, css) {
    try { const sh = new CSSStyleSheet(); sh.replaceSync(css); sr.adoptedStyleSheets = [sh]; }
    catch (_) { const st = document.createElement("style"); st.textContent = css; sr.appendChild(st); }
  }
  ZL.adoptCss = adoptCss;
  function ensureOverlay() {
    if (state.host && state.host.isConnected && state.host2 && state.host2.isConnected) return;
    if (state.host) { state.host.remove(); if (state.host2) state.host2.remove(); }
    const host = document.createElement("zenlens-overlay");
    host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483646;";
    // Second host anchored to the DOCUMENT (absolute, 0x0): boxes in it scroll with the page on the compositor, so they
    // cannot lag or drift behind the content. Fixed/sticky content goes in the viewport-anchored host above.
    const host2 = document.createElement("zenlens-overlay-doc");
    host2.style.cssText = "all:initial;position:absolute;left:0;top:0;width:0;height:0;overflow:visible;pointer-events:none;z-index:2147483646;";
    const css = `
      .b{position:fixed;box-sizing:border-box;border:2px solid var(--c);border-radius:3px;pointer-events:none}
      .b.m{background:color-mix(in srgb,var(--c) 18%,#111);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      .b.m.f{background:transparent;backdrop-filter:none;border-style:dashed}
      .b.s{border:0;border-radius:2px;background:#1b1c1a;color:#fbf9f5;display:flex;align-items:center;justify-content:center;
           overflow:hidden;font:600 10px/1 ui-monospace,Menlo,monospace;letter-spacing:.06em;white-space:nowrap}
      .t{position:absolute;right:-2px;top:-15px;font:600 9px/13px system-ui,sans-serif;color:#fff;background:var(--c);
         padding:0 4px;border-radius:3px 3px 0 3px;white-space:nowrap;letter-spacing:.02em}
      .b.low .t{top:auto;bottom:-15px}
      .d .b{position:absolute}`;
    const sr = host.attachShadow({ mode: "closed" }), sr2 = host2.attachShadow({ mode: "closed" });
    adoptCss(sr, css); adoptCss(sr2, css);
    state.layer = document.createElement("div");
    state.docLayer = document.createElement("div"); state.docLayer.className = "d";
    sr.appendChild(state.layer); sr2.appendChild(state.docLayer);
    state.host = host; state.host2 = host2;
    ZL.ui.shadow = sr;
    document.documentElement.append(host2, host);
  }
  /** Fixed/sticky content stays put while the document scrolls, so its covers must be viewport-anchored. */
  function pinned(el) {
    if (!state.pin) state.pin = new WeakMap();
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      let v = state.pin.get(e);
      if (v === undefined) { const p = getComputedStyle(e).position; v = p === "fixed" || p === "sticky"; state.pin.set(e, v); }
      if (v) return true;
    }
    return false;
  }
  const isOurs = (n) => !!(state.host && (n === state.host || state.host.contains(n))) ||
    (n && n.nodeType === 1 && n.tagName && n.tagName.startsWith("ZENLENS-"));

  function visible(el) {
    if (!el || !el.isConnected) return false;
    if (el.checkVisibility) return el.checkVisibility({ visibilityProperty: true });
    return el.getClientRects().length > 0;
  }

  // ---------- agent shield: arm, DOM redaction ----------
  /** Until the first scan finishes, hide the page entirely so a screenshot taken during load shows nothing. */
  function arm() {
    if (state.armSheet) return;
    try {
      const sh = new CSSStyleSheet(); sh.replaceSync("html{visibility:hidden!important}");
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sh]; state.armSheet = sh;
      setTimeout(disarm, 1500); // never leave a page blank if a scan stalls
    } catch (_) { /* old engine: overlay only */ }
  }
  function disarm() {
    if (!state.armSheet) return;
    try { document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== state.armSheet); } catch (_) { /* ignore */ }
    state.armSheet = null;
  }
  const MAX_DOM_EDITS = 5000;
  /** Replace sensitive text in the DOM by [REDACTED:KIND] so get_page_text / accessibility-tree reads are redacted too.
   *  Originals live only in this array (page memory) and are restored when the shield drops. */
  function applyDom() {
    if (!state.settings.domRedact || state.domRedacted.length >= MAX_DOM_EDITS) return;
    const byNode = new Map(), leaves = [];
    for (const f of state.findings) {
      if (f.range) {
        const n = f.range.startContainer;
        if (n.nodeType === 3 && n === f.range.endContainer && !(n.parentElement && n.parentElement.isContentEditable)) {
          if (!byNode.has(n)) byNode.set(n, []);
          byNode.get(n).push({ s: f.range.startOffset, e: f.range.endOffset, k: f.kind }); f.done = true;
        }
      } else if (f.el && !f.field && f.el.childElementCount === 0 && !f.el.isContentEditable &&
                 !["IMG", "VIDEO", "CANVAS", "A"].includes(f.el.tagName) && /\S{3}/.test(f.el.textContent || "")) leaves.push(f);
    }
    for (const [node, spans] of byNode) {
      const orig = node.data; let out = orig;
      for (const sp of spans.sort((a, b) => b.s - a.s)) out = out.slice(0, sp.s) + `[REDACTED:${sp.k}]` + out.slice(sp.e);
      node.data = out; state.domRedacted.push({ node, orig, kinds: spans.map((x) => x.k) });
    }
    for (const f of leaves) {
      const orig = f.el.textContent; f.el.textContent = `[REDACTED:${f.kind}]`; f.done = true;
      state.domRedacted.push({ el: f.el, orig, kinds: [f.kind] });
    }
    state.findings = state.findings.filter((f) => !f.done);
    mo.takeRecords(); // our own writes must not trigger a rescan
  }
  /** Pre-filled / autofilled sensitive field values are replaced in the DOM (el.value is what DOM-reading agents get).
   *  Originals stay in `state.masked`. A field the user or agent types into starts empty; real values are restored for the
   *  instant of a submit/click/Enter so the page still works, then masked again. */
  function maskFields() {
    if (!state.settings.domRedact) return;
    for (const f of state.findings) {
      const el = f.el; if (!f.field || !el || f.empty || state.masked.has(el)) continue;
      if (el.tagName === "SELECT" || /^(checkbox|radio|button|submit|reset|file|image)$/.test(el.type) || !(el.value || "").trim()) continue;
      const ph = `[REDACTED:${f.kind}]`;
      if (el.value === ph) continue;
      state.masked.set(el, { orig: el.value, ph });
      setValue(el, ph);
    }
    mo.takeRecords();
  }
  function setValue(el, v) {
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    try { Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v); } catch (_) { el.value = v; }
  }
  function unmaskFields(remask) {
    for (const [el, m] of state.masked) if (el.isConnected && el.value === m.ph) setValue(el, m.orig);
    if (!remask) state.masked.clear();
    else setTimeout(() => { state.masked.clear(); if (shieldOn()) scan(); }, 400);
    mo.takeRecords();
  }
  function restoreDom() {
    unmaskFields(false);
    for (const r of state.domRedacted) {
      try {
        if (r.node && r.node.isConnected && r.node.data.includes("[REDACTED:")) r.node.data = r.orig;
        else if (r.el && r.el.isConnected && r.el.textContent.startsWith("[REDACTED:")) r.el.textContent = r.orig;
      } catch (_) { /* node gone */ }
    }
    state.domRedacted = []; mo.takeRecords();
  }

  // ---------- scanning ----------
  function scanFields(out, covered) {
    for (const el of document.querySelectorAll(FIELD_SEL)) {
      // hidden inputs (csrf tokens, session ids) draw nothing but DOM-reading agents get their value: scan them too
      if (isOurs(el) || (el.type !== "hidden" && !visible(el))) continue;
      let r = null;
      try { r = ST.classifyDomElement(el); } catch (_) { /* ignore */ }
      const value = el.tagName === "SELECT" ? (el.selectedOptions[0] || {}).text || "" : el.value || "";
      if (r && value.trim()) { out.push({ kind: r[0], reason: r[1], el, field: true }); covered.add(el); continue; }
      if (!value.trim()) {
        if (r) { out.push({ kind: r[0], reason: r[1] + " (empty)", el, field: true, empty: true }); covered.add(el); }
        continue;
      }
      const hits = Z.detectAll(value, state.customRules);
      if (hits.length) { out.push({ kind: hits[0].kind, reason: `value:${hits.map((h) => h.kind).join("+")}`, el, field: true, kinds: hits.map((h) => h.kind) }); covered.add(el); }
    }
  }
  function scanStructuralLeaves(out, covered) {
    let n = 0;
    for (const el of document.body.querySelectorAll(HINT_SEL)) {
      if (++n > MAX_ELEMS) break;
      if (el.matches(FIELD_SEL) || isOurs(el) || SKIP_TAGS.has(el.tagName)) continue;
      let r = null;
      try { r = ST.classifyDomElement(el); } catch (_) { /* ignore */ }
      if (r && visible(el)) {
        // like structural.sanitize_html `whole()`: a full-match text detection names the kind
        const t = (el.textContent || "").trim(), sp = t ? Z.detectAll(t, state.customRules) : [];
        const kind = sp.length === 1 && sp[0].start === 0 && sp[0].end === t.length ? sp[0].kind : r[0];
        out.push({ kind, reason: r[1], el }); covered.add(el);
      }
    }
    // Links whose href carries PII/secrets (tel:, mailto:, ?token=...) even though the label looks harmless.
    for (const a of document.body.querySelectorAll("a[href]")) {
      if (covered.has(a) || isOurs(a)) continue;
      let href = a.getAttribute("href") || "";
      try { href = decodeURIComponent(href); } catch (_) { /* keep raw */ }
      const hits = Z.detectAll(href, state.customRules);
      if (hits.length && visible(a)) { out.push({ kind: hits[0].kind, reason: `attr:href:${hits[0].kind}`, el: a }); covered.add(a); }
    }
  }
  function insideCovered(node, covered) {
    for (let e = node.parentElement; e; e = e.parentElement) if (covered.has(e)) return true;
    return false;
  }
  function scanText(out, covered) {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        const p = n.parentElement;
        if (!p || SKIP_TAGS.has(p.tagName) || isOurs(p)) return NodeFilter.FILTER_REJECT;
        return n.data.trim().length >= 3 ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      },
    });
    let n = 0, node;
    const seenParents = new Map();
    while ((node = walker.nextNode()) && n++ < MAX_NODES) {
      const p = node.parentElement;
      let vis = seenParents.get(p);
      if (vis === undefined) { vis = visible(p); seenParents.set(p, vis); }
      if (!vis || insideCovered(node, covered)) continue;
      for (const h of Z.detectAll(node.data, state.customRules)) {
        const range = document.createRange();
        range.setStart(node, h.start); range.setEnd(node, h.end);
        out.push({ kind: h.kind, reason: `text:${h.kind}`, range });
        if (out.length >= MAX_FINDINGS) return;
      }
    }
  }
  function scan() {
    state.rescanTimer = 0; state.lastScan = Date.now(); state.pin = new WeakMap();
    if (!state.enabled || !document.body) { state.findings = []; render(); report(); return; }
    if (!shieldOn() && state.domRedacted.length) restoreDom();
    const out = [], covered = new Set();
    try {
      scanFields(out, covered);
      scanStructuralLeaves(out, covered);
      scanText(out, covered);
    } catch (e) { console.debug("[Zen] scan error", e && e.message); }
    state.findings = out.slice(0, MAX_FINDINGS);
    if (shieldOn()) { try { maskFields(); applyDom(); } catch (e) { console.debug("[Zen] dom redact error", e && e.message); } }
    render(); report();
  }
  /** Throttled rescan: at most once per 600ms, trailing. */
  function scheduleScan(delay = 300) {
    if (state.rescanTimer) return;
    const wait = shieldOn() ? Math.max(0, SHIELD_MIN_GAP - (Date.now() - state.lastScan))
      : Math.max(delay, 600 - (Date.now() - state.lastScan));
    state.rescanTimer = setTimeout(scan, wait);
  }

  // ---------- rendering ----------
  function rectsOf(f) {
    if (f.el) { if (!f.el.isConnected) return []; const r = f.el.getBoundingClientRect(); return r.width || r.height ? [r] : []; }
    if (f.range) { if (!f.range.startContainer.isConnected) return []; return Array.from(f.range.getClientRects()).filter((r) => r.width && r.height); }
    return [];
  }
  function render() {
    // Shield mode paints synchronously (a scroll or layout shift must never expose a frame); normal mode uses rAF.
    if (shieldOn()) return paint();
    if (state.rafPending) return;
    state.rafPending = true;
    requestAnimationFrame(() => { state.rafPending = false; paint(); });
  }
  function paint() {
    {
      const sh = shieldOn();
      const show = state.enabled && (sh || state.settings.highlight || state.mask) && state.findings.length;
      if (!show) { if (state.layer) state.layer.textContent = ""; if (state.docLayer) state.docLayer.textContent = ""; return; }
      ensureOverlay();
      const frag = document.createDocumentFragment(), docFrag = document.createDocumentFragment();
      const vw = innerWidth, vh = innerHeight, active = document.activeElement, sx = scrollX, sy = scrollY;
      for (const f of state.findings) {
        const rs = rectsOf(f);
        if (!rs.length) continue;
        const host = f.el || (f.range && f.range.startContainer.parentElement);
        const pin = pinned(host);
        rs.forEach((r, i) => {
          // doc layer keeps a 2-viewport margin: a native scroll can reveal boxes before the next paint
          if (pin ? (r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw)
                  : (r.bottom < -2 * vh || r.top > 3 * vh || r.right < -2 * vw || r.left > 3 * vw)) return;
          const d = document.createElement("div");
          d.className = "b" + (sh ? " s" : state.mask ? " m" : "") + (!sh && state.mask && f.el && f.el === active ? " f" : "") + (r.top < 16 ? " low" : "");
          const out = pin ? frag : docFrag, ox = pin ? 0 : sx, oy = pin ? 0 : sy;
          d.style.cssText = `--c:${CFG.kindColor(f.kind)};left:${r.left + ox - 2}px;top:${r.top + oy - 2}px;width:${r.width + 4}px;height:${r.height + 4}px`;
          if (sh) { if (r.width >= 44 && r.height >= 12) d.textContent = f.kind; out.appendChild(d); return; }
          if (!state.settings.highlight) d.style.borderColor = "transparent";
          if (i === 0 && state.settings.highlight) {
            const t = document.createElement("span"); t.className = "t"; t.textContent = f.kind; d.appendChild(t);
          }
          out.appendChild(d);
        });
      }
      state.layer.replaceChildren(frag); state.docLayer.replaceChildren(docFrag);
    }
  }

  // ---------- reporting / messages ----------
  function counts() {
    const c = {};
    for (const f of state.findings) c[f.kind] = (c[f.kind] || 0) + 1;
    for (const r of state.domRedacted) for (const k of r.kinds) c[k] = (c[k] || 0) + 1;
    return c;
  }
  function report() {
    try { chrome.runtime.sendMessage({ type: "zl:count", total: Object.values(counts()).reduce((a, b) => a + b, 0), shield: shieldOn() }).catch(() => {}); } catch (_) { /* context gone */ }
  }
  function pageText() { return document.body ? document.body.innerText || "" : ""; }
  /** Page text spans: structurally flagged leaf text (e.g. .shipping-address) first, then text rules. */
  function sanitizePage() {
    const text = pageText(), spans = [];
    for (const f of state.findings) {
      if (!f.el || f.field) continue;
      const v = (f.el.innerText || "").trim();
      if (v.length < 3) continue;
      for (let i = text.indexOf(v); i !== -1; i = text.indexOf(v, i + v.length)) {
        if (!spans.some((b) => i < b.end && b.start < i + v.length)) spans.push({ start: i, end: i + v.length, kind: f.kind });
      }
    }
    for (const h of Z.detectAll(text, state.customRules)) if (!spans.some((b) => h.start < b.end && b.start < h.end)) spans.push(h);
    spans.sort((a, b) => a.start - b.start);
    return { before: text, spans, after: Z.redactSpans(text, spans) };
  }
  function fieldRows() {
    return state.findings.filter((f) => f.field).map((f) => {
      const el = f.el, label = ST.labelText(el) || el.getAttribute("aria-label") || el.name || el.id || el.tagName.toLowerCase();
      const value = el.tagName === "SELECT" ? (el.selectedOptions[0] || {}).text || "" : el.value || "";
      return { label: label.slice(0, 80), kind: f.kind, reason: f.reason, before: value, after: value ? `[REDACTED:${f.kind}]` : "" };
    });
  }
  function boxes() {
    const out = [];
    for (const f of state.findings) for (const r of rectsOf(f)) {
      if (r.bottom < 0 || r.top > innerHeight || r.right < 0 || r.left > innerWidth) continue;
      out.push({ x: r.left, y: r.top, w: r.width, h: r.height, kind: f.kind });
    }
    return { rects: out, vw: innerWidth, vh: innerHeight, dpr: devicePixelRatio };
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch (_) { /* fall through */ }
    const ta = document.createElement("textarea");
    ta.value = text; ta.style.cssText = "position:fixed;left:-9999px;top:0;opacity:0";
    document.documentElement.appendChild(ta); ta.select();
    let ok = false; try { ok = document.execCommand("copy"); } catch (_) { ok = false; }
    ta.remove();
    return ok;
  }
  function toast(msg) {
    ensureOverlay();
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.cssText = "position:fixed;right:16px;bottom:16px;max-width:360px;background:#1f1d2b;color:#fff;font:13px/1.4 system-ui,sans-serif;padding:10px 14px;border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.3);border-left:4px solid #7048e8";
    ZL.ui.shadow.appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }
  ZL.ui.toast = toast;
  ZL.copyText = copyText;

  chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
    if (!msg || typeof msg.type !== "string" || !msg.type.startsWith("zl:")) return;
    const h = location.hostname;
    switch (msg.type) {
      case "zl:summary":
        reply({ enabled: state.enabled, host: h, counts: counts(), total: Object.values(counts()).reduce((a, b) => a + b, 0), mask: state.mask,
          shield: { mode: state.settings.shieldMode, active: shieldOn(), agent: navigator.webdriver === true || state.agent },
          aiSite: CFG.isAiSite(state.settings, h), guard: !!(ZL.guardActive && ZL.guardActive()) });
        return;
      case "zl:setMask":
        state.mask = !!msg.on; render(); reply({ mask: state.mask }); return;
      case "zl:rescan":
        scan(); reply({ total: state.findings.length }); return;
      case "zl:sanitizedText": {
        const r = sanitizePage();
        reply({ text: r.after, count: r.spans.length }); return;
      }
      case "zl:preview": {
        const r = sanitizePage();
        reply({ title: document.title, host: h, before: r.before, spans: r.spans.map(({ start, end, kind }) => ({ start, end, kind })),
          after: r.after, fields: fieldRows(), counts: counts() });
        return;
      }
      case "zl:boxes": reply(boxes()); return;
      case "zl:redactSelection": {
        const sel = String(getSelection() || "") || msg.fallback || "";
        const r = Z.redactAll(sel, state.customRules);
        copyText(r.text).then((ok) => {
          toast(ok ? `Zen: copied sanitized selection (${r.spans.length} item${r.spans.length === 1 ? "" : "s"} redacted)` : "Zen: clipboard blocked by page");
          reply({ ok, count: r.spans.length });
        });
        return true;
      }
    }
  });

  // ---------- lifecycle ----------
  async function init() {
    const s = await CFG.load();
    state.settings = s;
    state.customRules = Z.compileCustomRules(s.customRules).rules;
    state.enabled = CFG.siteEnabled(s, location.hostname);
    state.mask = !!s.maskByDefault; // the popup toggle is saved in settings, so it survives reloads and applies to every tab
    if (shieldOn()) arm(); else { disarm(); restoreDom(); }
    scan();
    disarm(); // first scan is done: covers are up
    if (ZL.onSettings) ZL.onSettings(s);
    startProbe();
  }
  /** Auto mode: ask the service worker once a second whether a debugger client (an AI agent) is attached to this tab. */
  function startProbe() {
    if (state.probeTimer || navigator.webdriver === true) return;
    state.probeTimer = setInterval(async () => {
      if (state.settings.shieldMode !== "auto") return;
      let r = null;
      try { r = await chrome.runtime.sendMessage({ type: "zl:probe" }); } catch (_) { return; }
      const a = !!(r && r.agent);
      if (a === state.agent) return;
      state.agent = a;
      if (a) arm();
      scan(); disarm();
    }, 1000);
  }
  chrome.storage.onChanged.addListener((_c, area) => { if (area === "sync") init(); });

  const mo = new MutationObserver((muts) => {
    if (!state.enabled) return;
    for (const m of muts) if (!isOurs(m.target)) { if (shieldOn()) render(); scheduleScan(); return; }
  });
  function start() {
    mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["value", "type", "autocomplete", "class", "hidden", "style"] });
    addEventListener("input", (e) => { if (!isOurs(e.target)) scheduleScan(400); }, true); // shield: 40 ms
    addEventListener("change", () => scheduleScan(200), true);
    addEventListener("scroll", render, { capture: true, passive: true });
    addEventListener("resize", render, { passive: true });
    addEventListener("focusin", render, true);
    addEventListener("focusout", render, true);
    // document_start: settings load async, so mutations before `enabled` was set were ignored. Rescan once the DOM exists.
    document.addEventListener("beforeinput", (e) => {  // typing into a masked field starts from empty, never appends to the placeholder
      const m = state.masked.get(e.target);
      if (m && e.target.value === m.ph) { setValue(e.target, ""); state.masked.delete(e.target); }
    }, true);
    const real = () => { if (state.masked.size && shieldOn()) unmaskFields(true); };  // page code must see real values on submit
    document.addEventListener("submit", real, true);
    document.addEventListener("click", (e) => { if (e.target && e.target.closest && e.target.closest("button,[type=submit],input[type=submit],a")) real(); }, true);
    document.addEventListener("keydown", (e) => { if (e.key === "Enter") real(); }, true);
    document.addEventListener("DOMContentLoaded", () => scheduleScan(0), { once: true });
    addEventListener("load", () => scheduleScan(0), { once: true });
    init();
  }
  if (navigator.webdriver === true) arm(); // automation present: blank until the first scan has put covers up
  start();   // document_start: the observer is armed before the page paints
})();
