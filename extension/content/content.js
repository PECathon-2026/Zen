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
  };
  const ZL = (globalThis.__ZenContent = { state, scheduleScan, render, ui: {} });

  // ---------- overlay ----------
  /** Constructable stylesheet (not subject to page style-src CSP); <style> fallback. */
  function adoptCss(sr, css) {
    try { const sh = new CSSStyleSheet(); sh.replaceSync(css); sr.adoptedStyleSheets = [sh]; }
    catch (_) { const st = document.createElement("style"); st.textContent = css; sr.appendChild(st); }
  }
  ZL.adoptCss = adoptCss;
  function ensureOverlay() {
    if (state.host && state.host.isConnected) return;
    const host = document.createElement("zenlens-overlay");
    host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483646;";
    const sr = host.attachShadow({ mode: "closed" });
    adoptCss(sr, `
      .b{position:fixed;box-sizing:border-box;border:2px solid var(--c);border-radius:3px;pointer-events:none}
      .b.m{background:color-mix(in srgb,var(--c) 18%,#111);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
      .b.m.f{background:transparent;backdrop-filter:none;border-style:dashed}
      .t{position:absolute;right:-2px;top:-15px;font:600 9px/13px system-ui,sans-serif;color:#fff;background:var(--c);
         padding:0 4px;border-radius:3px 3px 0 3px;white-space:nowrap;letter-spacing:.02em}
      .b.low .t{top:auto;bottom:-15px}`);
    state.layer = document.createElement("div");
    sr.appendChild(state.layer);
    state.host = host;
    ZL.ui.shadow = sr;
    document.documentElement.appendChild(host);
  }
  const isOurs = (n) => !!(state.host && (n === state.host || state.host.contains(n))) ||
    (n && n.nodeType === 1 && n.tagName && n.tagName.startsWith("ZENLENS-"));

  function visible(el) {
    if (!el || !el.isConnected) return false;
    if (el.checkVisibility) return el.checkVisibility({ visibilityProperty: true });
    return el.getClientRects().length > 0;
  }

  // ---------- scanning ----------
  function scanFields(out, covered) {
    for (const el of document.querySelectorAll(FIELD_SEL)) {
      if (isOurs(el) || el.type === "hidden" || !visible(el)) continue;
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
    state.rescanTimer = 0; state.lastScan = Date.now();
    if (!state.enabled || !document.body) { state.findings = []; render(); report(); return; }
    const out = [], covered = new Set();
    try {
      scanFields(out, covered);
      scanStructuralLeaves(out, covered);
      scanText(out, covered);
    } catch (e) { console.debug("[Zen] scan error", e && e.message); }
    state.findings = out.slice(0, MAX_FINDINGS);
    render(); report();
  }
  /** Throttled rescan: at most once per 600ms, trailing. */
  function scheduleScan(delay = 300) {
    if (state.rescanTimer) return;
    const wait = Math.max(delay, 600 - (Date.now() - state.lastScan));
    state.rescanTimer = setTimeout(scan, wait);
  }

  // ---------- rendering ----------
  function rectsOf(f) {
    if (f.el) { if (!f.el.isConnected) return []; const r = f.el.getBoundingClientRect(); return r.width || r.height ? [r] : []; }
    if (f.range) { if (!f.range.startContainer.isConnected) return []; return Array.from(f.range.getClientRects()).filter((r) => r.width && r.height); }
    return [];
  }
  function render() {
    if (state.rafPending) return;
    state.rafPending = true;
    requestAnimationFrame(() => {
      state.rafPending = false;
      const show = state.enabled && (state.settings.highlight || state.mask) && state.findings.length;
      if (!show) { if (state.layer) state.layer.textContent = ""; return; }
      ensureOverlay();
      const frag = document.createDocumentFragment();
      const vw = innerWidth, vh = innerHeight, active = document.activeElement;
      for (const f of state.findings) {
        const rs = rectsOf(f);
        rs.forEach((r, i) => {
          if (r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw) return;
          const d = document.createElement("div");
          d.className = "b" + (state.mask ? " m" : "") + (state.mask && f.el && f.el === active ? " f" : "") + (r.top < 16 ? " low" : "");
          d.style.cssText = `--c:${CFG.kindColor(f.kind)};left:${r.left - 2}px;top:${r.top - 2}px;width:${r.width + 4}px;height:${r.height + 4}px`;
          if (!state.settings.highlight) d.style.borderColor = "transparent";
          if (i === 0 && state.settings.highlight) {
            const t = document.createElement("span"); t.className = "t"; t.textContent = f.kind; d.appendChild(t);
          }
          frag.appendChild(d);
        });
      }
      state.layer.replaceChildren(frag);
    });
  }

  // ---------- reporting / messages ----------
  function counts() {
    const c = {};
    for (const f of state.findings) c[f.kind] = (c[f.kind] || 0) + 1;
    return c;
  }
  function report() {
    try { chrome.runtime.sendMessage({ type: "zl:count", total: state.findings.length }).catch(() => {}); } catch (_) { /* context gone */ }
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
        reply({ enabled: state.enabled, host: h, counts: counts(), total: state.findings.length, mask: state.mask,
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
    if (state.mask === false && s.maskByDefault) state.mask = true;
    scan();
    if (ZL.onSettings) ZL.onSettings(s);
  }
  chrome.storage.onChanged.addListener((_c, area) => { if (area === "sync") init(); });

  const mo = new MutationObserver((muts) => {
    if (!state.enabled) return;
    for (const m of muts) if (!isOurs(m.target)) { scheduleScan(); return; }
  });
  function start() {
    mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["value", "type", "autocomplete", "class", "hidden", "style"] });
    addEventListener("input", (e) => { if (!isOurs(e.target)) scheduleScan(400); }, true);
    addEventListener("change", () => scheduleScan(200), true);
    addEventListener("scroll", render, { capture: true, passive: true });
    addEventListener("resize", render, { passive: true });
    addEventListener("focusin", render, true);
    addEventListener("focusout", render, true);
    init();
  }
  if (document.body) start(); else addEventListener("DOMContentLoaded", start, { once: true });
})();
