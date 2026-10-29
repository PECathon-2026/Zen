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
    agent: false, probeTimer: 0, armSheet: null, domRedacted: [], masked: new Map(), attrMasked: [], img: new Map(), analyzing: 0, roots: [], observed: new WeakSet(), watching: false, sig: "",  // Agent Shield
  };
  const STICKY_MS = 10 * 60 * 1000;
  const SHIELD_MIN_GAP = 40; // ms between rescans while the shield is up (normal mode: 600)
  /** Agent Shield is up when forced on, or in auto mode when an automation signal is present. */
  function shieldOn() {
    const m = state.settings.shieldMode;
    return m === "on" || (m !== "off" && (navigator.webdriver === true || state.agent));
  }
  const ZL = (globalThis.__ZenContent = { state, scheduleScan, render, scan: () => scan(), ui: {} });

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
      /* shield: opaque per-kind colour (nothing shows through), kind label inside; .p = soft highlight on text already replaced */
      .b.s{border:2px solid var(--c);border-radius:3px;background:color-mix(in srgb,var(--c) 72%,#14110f);color:#fff;display:flex;
           align-items:center;justify-content:center;overflow:hidden;font:700 10px/1 ui-monospace,Menlo,monospace;letter-spacing:.06em;white-space:nowrap}
      .b.x{pointer-events:auto;user-select:none;-webkit-user-select:none;cursor:not-allowed}
      .b.p{border:1.5px solid var(--c);border-radius:3px;background:color-mix(in srgb,var(--c) 16%,transparent)}
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
      } else if (f.el && !f.field && !f.media && !f.el.isContentEditable && (f.split || f.el.childElementCount === 0) &&
                 !["IMG", "VIDEO", "CANVAS", "A"].includes(f.el.tagName) && /\S{3}/.test(f.el.textContent || "")) leaves.push(f);
    }
    for (const [node, spans] of byNode) {
      const orig = node.data; spans.sort((x, y) => x.s - y.s);
      let out = "", pos = 0; const marks = [];
      for (const sp of spans) {
        out += orig.slice(pos, sp.s);
        const ph = `[REDACTED:${sp.k}]`; marks.push({ s: out.length, e: out.length + ph.length, k: sp.k });
        out += ph; pos = sp.e;
      }
      node.data = out + orig.slice(pos);
      state.domRedacted.push({ node, orig, kinds: marks.map((m) => m.k), marks: marks.map((m) => {
        const range = document.createRange(); range.setStart(node, m.s); range.setEnd(node, m.e); return { kind: m.k, range };
      }) });
    }
    for (const f of leaves) {
      const orig = f.split ? f.el.innerHTML : f.el.textContent;
      f.el.textContent = `[REDACTED:${f.kind}]`; f.done = true;
      state.domRedacted.push({ el: f.el, orig, html: f.split ? orig : null, kinds: [f.kind], marks: [{ kind: f.kind, el: f.el }] });
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
      // the value ATTRIBUTE (outerHTML, getAttribute) holds the original too: mask it as well
      const isTa = el.tagName === "TEXTAREA";
      state.masked.set(el, { orig: el.value, ph, attr: isTa ? el.defaultValue : el.getAttribute("value") });
      setValue(el, ph);
      try { if (isTa) el.defaultValue = ph; else if (el.hasAttribute("value")) el.setAttribute("value", ph); } catch (_) { /* ignore */ }
    }
    mo.takeRecords();
  }
  function setValue(el, v) {
    const proto = el.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    try { Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v); } catch (_) { el.value = v; }
  }
  function unmaskFields(remask) {
    for (const [el, m] of state.masked) {
      if (!el.isConnected) continue;
      if (el.value === m.ph) setValue(el, m.orig);
      try { if (el.tagName === "TEXTAREA") el.defaultValue = m.attr; else if (m.attr != null) el.setAttribute("value", m.attr); } catch (_) { /* ignore */ }
    }
    if (!remask) state.masked.clear();
    else setTimeout(() => { state.masked.clear(); if (shieldOn()) scan(); }, 400);
    mo.takeRecords();
  }
  function restoreDom() {
    unmaskFields(false);
    for (const r of state.domRedacted) {
      try {
        if (r.node && r.node.isConnected && r.node.data.includes("[REDACTED:")) r.node.data = r.orig;
        else if (r.el && r.el.isConnected && r.el.textContent.startsWith("[REDACTED:")) { if (r.html != null) r.el.innerHTML = r.html; else r.el.textContent = r.orig; }
      } catch (_) { /* node gone */ }
    }
    state.domRedacted = [];
    for (const m of state.attrMasked) { try { if (m.el.isConnected) m.el.setAttribute(m.a, m.orig); } catch (_) { /* ignore */ } }
    state.attrMasked = []; mo.takeRecords();
  }
  /** alt / title / aria-label / placeholder / href are read by DOM and accessibility-tree tools: mask PII in them too. */
  const ATTRS = ["alt", "title", "aria-label", "placeholder", "href"];
  function maskAttrs() {
    if (!state.settings.domRedact || state.attrMasked.length > MAX_DOM_EDITS) return;
    const faces = new Set(state.findings.filter((f) => f.media || f.kind === "FACE").map((f) => f.el));
    for (const el of qsa("[alt],[title],[aria-label],[placeholder],a[href]")) {
      if (isOurs(el)) continue;
      for (const a of ATTRS) {
        const v = el.getAttribute(a);
        if (!v || v.startsWith("[REDACTED") || v.includes("[REDACTED:")) continue;
        let probe = v, nv = null;
        if (a === "href") { if (!/^(mailto:|tel:|https?:)/i.test(v)) continue; try { probe = decodeURIComponent(v); } catch (_) { /* raw */ } }
        if (faces.has(el) && (a === "alt" || a === "title" || a === "aria-label")) nv = "[REDACTED:FACE]";
        else { const hits = Z.detectAll(probe, state.customRules); if (hits.length) nv = Z.redactSpans(probe, hits); }
        if (nv != null && nv !== v) { state.attrMasked.push({ el, a, orig: v }); el.setAttribute(a, nv); }
      }
    }
    mo.takeRecords();
  }
  // ---------- keep covers glued to animated / transitioning content ----------
  const allDrawn = () => state.findings.concat(state.domRedacted.flatMap((r) => (r.marks || []).map((m) => ({ ...m, placeholder: true }))));
  function sigOf() {
    let sg = scrollX + "," + scrollY + ";";
    for (const f of allDrawn()) for (const r of rectsOf(f)) sg += (r.left | 0) + "," + (r.top | 0) + "," + (r.width | 0) + "," + (r.height | 0) + ";";
    return sg;
  }
  function watch() {
    if (!state.enabled || !shieldOn()) { state.watching = false; return; }
    const sg = sigOf();
    if (sg !== state.sig) { state.sig = sg; paint(); }
    requestAnimationFrame(watch);
  }
  function ensureWatch() { if (!state.watching && shieldOn()) { state.watching = true; requestAnimationFrame(watch); } }

  // ---------- open shadow roots ----------
  /** The document plus every open shadow root (web components hide text and fields from document.querySelectorAll). */
  function collectRoots() {
    const rs = [document], q = [document]; let n = 0;
    while (q.length && n < 8000) {
      const r = q.shift();
      for (const el of r.querySelectorAll("*")) {
        n++;
        // chrome.dom.openOrClosedShadowRoot also returns CLOSED shadow roots (extensions only)
        const sr = el.shadowRoot || (chrome.dom && chrome.dom.openOrClosedShadowRoot ? chrome.dom.openOrClosedShadowRoot(el) : null);
        if (sr && !isOurs(el)) { rs.push(sr); q.push(sr); observeRoot(sr); }
      }
    }
    return rs;
  }
  const qsa = (sel) => state.roots.flatMap((r) => Array.from(r.querySelectorAll(sel)));

  // ---------- scanning ----------
  function scanFields(out, covered) {
    for (const el of qsa(FIELD_SEL)) {
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
    for (const el of qsa(HINT_SEL)) {
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
    for (const a of qsa("a[href]")) {
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
    for (const root of state.roots) { if (scanTextIn(root === document ? document.body : root, out, covered)) return; }
  }
  function scanTextIn(top, out, covered) {
    const walker = document.createTreeWalker(top, NodeFilter.SHOW_TEXT, {
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
        if (out.length >= MAX_FINDINGS) return true;
      }
    }
  }
  // ---------- faces / media ----------
  const FACE_HINT = /avatar|profile|face|selfie|portrait|headshot|participant|speaker|attendee|member|gravatar|pfp|user[-_ ]?(photo|pic|img|image)|webcam|camera|self[-_ ]?view|video[-_ ]?tile|people|person/i;
  const hintText = (el) => [el.getAttribute("alt"), el.getAttribute("title"), el.id, typeof el.className === "string" ? el.className : "",
    el.getAttribute("aria-label"), (el.getAttribute("src") || "").slice(0, 200), el.parentElement && el.parentElement.id,
    el.parentElement && typeof el.parentElement.className === "string" ? el.parentElement.className : ""].filter(Boolean).join(" ");
  // ---------- image / canvas analysis (faces via the bundled detector, text via the optional local server) ----------
  const canvasIds = new WeakMap(); let canvasSeq = 0;
  const canvasId = (c) => { if (!canvasIds.has(c)) canvasIds.set(c, ++canvasSeq); return canvasIds.get(c); };
  const imgKey = (el) => el.currentSrc || el.src || "";
  function elementDataUrl(el) { // same-origin / data / blob pixels, read in the page (tainted canvases throw)
    try {
      const nw = el.naturalWidth || el.width, nh = el.naturalHeight || el.height;
      if (!nw || !nh) return null;
      const s = Math.min(1, 1024 / Math.max(nw, nh)), c = document.createElement("canvas");
      c.width = Math.max(1, Math.round(nw * s)); c.height = Math.max(1, Math.round(nh * s));
      c.getContext("2d").drawImage(el, 0, 0, c.width, c.height);
      return c.toDataURL("image/jpeg", 0.85);
    } catch (_) { return null; }
  }
  function imgMessage(el) {
    const src = imgKey(el);
    if (/^https?:/i.test(src)) return { type: "zl:analyze", src };
    const dataUrl = el.complete ? elementDataUrl(el) : null;       // data:, blob:, or not decodable by the worker
    return dataUrl ? { type: "zl:analyze", dataUrl } : null;
  }
  function canvasMessage(el) {
    try { return { type: "zl:analyze", dataUrl: el.toDataURL("image/jpeg", 0.8), ttl: 1500 }; } catch (_) { return null; }
  }
  /** Ask the service worker about an image once (cached); until the answer is in, or if it fails, cover the whole element. */
  function requestAnalysis(key, make, ttl) {
    let ent = state.img.get(key);
    if (ent && (ent.status === "pending" || Date.now() - ent.ts < ttl)) return ent;
    if (ent && ent.status === "fail" && Date.now() - ent.ts < 30000) return ent;
    if (state.analyzing >= 4) return ent || { status: "pending" };   // retried on a later scan
    const fresh = { status: "pending", ts: Date.now(), boxes: ent ? ent.boxes : [], nw: ent && ent.nw, nh: ent && ent.nh, ocrUp: ent && ent.ocrUp };
    state.img.set(key, fresh); state.analyzing++;
    Promise.resolve().then(make).then((msg) => (msg ? chrome.runtime.sendMessage(msg) : { ok: false }))
      .then((r) => { if (r && r.ok) Object.assign(fresh, r.res, { status: "done" }); else fresh.status = "fail"; })
      .catch(() => { fresh.status = "fail"; })
      .finally(() => { fresh.ts = Date.now(); state.analyzing--; scheduleScan(0); });
    return fresh;
  }
  function imageFindings(el, key, make, ttl, needOcr, out, covered) {
    const ent = key ? requestAnalysis(key, make, ttl) : { status: "fail" };
    covered.add(el);
    if (ent.status === "done" && !(needOcr && !ent.ocrUp)) {
      for (const b of ent.boxes) out.push({ kind: b.kind, reason: "image:" + b.kind, el, media: true, box: { ...b, nw: ent.nw, nh: ent.nh } });
      return;
    }
    // pending, failed, or a canvas without OCR: fail closed
    out.push({ kind: "IMAGE", reason: ent.status === "done" ? "no-ocr" : ent.status, el, media: true });
  }
  /** Map a box (fractions of the image) to viewport pixels, honouring object-fit. */
  function boxRect(f) {
    const el = f.el, b = f.box;
    if (!el.isConnected) return [];
    const r = el.getBoundingClientRect(), cs = getComputedStyle(el), fit = el.tagName === "CANVAS" ? "fill" : cs.objectFit;
    let sx = r.width / b.nw, sy = r.height / b.nh;
    if (fit === "contain" || fit === "scale-down") sx = sy = Math.min(sx, sy);
    else if (fit === "cover") sx = sy = Math.max(sx, sy);
    else if (fit === "none") sx = sy = 1;
    const ox = (r.width - b.nw * sx) / 2, oy = (r.height - b.nh * sy) / 2;
    const left = Math.max(r.left, r.left + ox + b.x * b.nw * sx - 2), top = Math.max(r.top, r.top + oy + b.y * b.nh * sy - 2);
    const right = Math.min(r.right, r.left + ox + (b.x + b.w) * b.nw * sx + 2), bottom = Math.min(r.bottom, r.top + oy + (b.y + b.h) * b.nh * sy + 2);
    return right > left && bottom > top ? [{ left, top, right, bottom, width: right - left, height: bottom - top }] : [];
  }
  /** Video-call tiles, webcam previews, avatars and profile photos: covered whole (a screenshot shows faces, not text). */
  function scanMedia(out, covered) {
    for (const el of qsa("video,img,canvas")) {
      if (isOurs(el) || covered.has(el)) continue;
      const r = el.getBoundingClientRect();
      if (r.width < 24 || r.height < 24 || !visible(el)) continue;
      let face = false;
      if (el.tagName === "VIDEO") face = (typeof MediaStream !== "undefined" && el.srcObject instanceof MediaStream) || FACE_HINT.test(hintText(el));
      else if (el.tagName === "CANVAS") face = FACE_HINT.test(hintText(el));
      else {
        face = FACE_HINT.test(hintText(el));
        if (!face) { // round, roughly square, avatar-sized picture
          const cs = getComputedStyle(el), rad = cs.borderTopLeftRadius || "0", br = parseFloat(rad) || 0;
          const round = rad.includes("%") ? br >= 40 : br >= Math.min(r.width, r.height) * 0.4;
          face = round && r.width <= 640 && Math.abs(r.width - r.height) <= 0.25 * Math.max(r.width, r.height);
        }
      }
      if (face) { out.push({ kind: "FACE", reason: "media:" + el.tagName.toLowerCase(), el, media: true }); covered.add(el); continue; }
      // Stock Chrome has no face detector and canvas text cannot be read: in shield mode cover what we cannot scan (fail closed).
      if (shieldOn()) {
        const mode = state.settings.shieldImages;
        if (el.tagName === "IMG" && r.width >= 64 && r.height >= 64 && mode !== "hinted") {
          if (mode === "all") { out.push({ kind: "IMAGE", reason: "unscannable:img", el, media: true }); covered.add(el); }
          else imageFindings(el, imgKey(el), () => imgMessage(el), 10 * 60 * 1000, false, out, covered);
        } else if (el.tagName === "CANVAS" && r.width >= 64 && r.height >= 32 && state.settings.shieldCanvas !== "off") {
          // canvas content changes: re-analyse every 2 s; without OCR we cannot know it holds no text, so cover it whole
          imageFindings(el, "canvas:" + canvasId(el), () => canvasMessage(el), 2000, true, out, covered);
        }
      }
    }
    for (const el of qsa("[class*=avatar i],[class*=profile-pic i],[class*=participant i],[class*=userpic i],[id*=avatar i]")) {
      if (isOurs(el) || covered.has(el) || !visible(el)) continue;
      const r = el.getBoundingClientRect();
      if (r.width < 24 || r.height < 24 || insideCovered(el.firstChild || el, covered)) continue;
      if (/url\(/.test(getComputedStyle(el).backgroundImage || "")) { out.push({ kind: "FACE", reason: "media:bg", el, media: true }); covered.add(el); }
    }
  }
  // ---------- text split over several elements ----------
  const INLINE_TAGS = new Set(["SPAN", "B", "I", "EM", "STRONG", "A", "CODE", "SMALL", "MARK", "U", "SUB", "SUP", "FONT", "BR", "WBR"]);
  function spansNodes(el, h) {
    const w = document.createTreeWalker(el, NodeFilter.SHOW_TEXT); let pos = 0, n, one = false;
    while ((n = w.nextNode())) { if (h.start >= pos && h.end <= pos + n.data.length) one = true; pos += n.data.length; }
    return !one;
  }
  /** "4111 <b>1111</b> 1111 1111": no single text node holds the value, but the element's text does. */
  function scanSplit(out, covered) {
    for (const el of qsa("p,div,li,td,th,dd,dt,label,h1,h2,h3,h4,h5,h6,span,a,pre")) {
      if (isOurs(el) || covered.has(el) || SKIP_TAGS.has(el.tagName)) continue;
      const kids = el.children.length;
      if (kids < 1 || kids > 14) continue;
      const t = el.textContent || "";
      if (t.length < 8 || t.length > 400 || ![...el.children].every((c) => INLINE_TAGS.has(c.tagName))) continue;
      const hits = Z.detectAll(t, state.customRules);
      if (!hits.length || !hits.some((h) => spansNodes(el, h)) || !visible(el) || insideCovered(el.firstChild || el, covered)) continue;
      out.push({ kind: hits[0].kind, reason: `split:${hits[0].kind}`, el, split: true }); covered.add(el);
    }
  }
  function scan() {
    state.rescanTimer = 0; state.lastScan = Date.now(); state.pin = new WeakMap();
    if (!state.enabled || !document.body) { state.findings = []; render(); report(); return; }
    if (!shieldOn() && state.domRedacted.length) restoreDom();
    const out = [], covered = new Set();
    try {
      state.roots = collectRoots();
      scanFields(out, covered);
      scanStructuralLeaves(out, covered);
      scanMedia(out, covered);
      scanText(out, covered);
      scanSplit(out, covered);
    } catch (e) { console.debug("[Zen] scan error", e && e.message); }
    state.findings = out.slice(0, MAX_FINDINGS);
    if (shieldOn()) { try { maskFields(); maskAttrs(); applyDom(); ensureWatch(); } catch (e) { console.debug("[Zen] dom redact error", e && e.message); } }
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
    if (f.box) return boxRect(f);
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
      const drawn = sh ? allDrawn() : state.findings;
      const show = state.enabled && (sh || state.settings.highlight || state.mask) && drawn.length;
      if (!show) { if (state.layer) state.layer.textContent = ""; if (state.docLayer) state.docLayer.textContent = ""; return; }
      ensureOverlay();
      const frag = document.createDocumentFragment(), docFrag = document.createDocumentFragment();
      const vw = innerWidth, vh = innerHeight, active = document.activeElement, sx = scrollX, sy = scrollY;
      for (const f of drawn) {
        const rs = rectsOf(f);
        if (!rs.length) continue;
        const host = f.el || (f.range && f.range.startContainer.parentElement);
        const pin = pinned(host);
        rs.forEach((r, i) => {
          // doc layer keeps a 2-viewport margin: a native scroll can reveal boxes before the next paint
          if (pin ? (r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw)
                  : (r.bottom < -2 * vh || r.top > 3 * vh || r.right < -2 * vw || r.left > 3 * vw)) return;
          const d = document.createElement("div");
          d.className = "b" + (sh ? (f.placeholder ? " p" : " s") : state.mask ? " m" : "") + (!sh && state.mask && f.el && f.el === active ? " f" : "") + (r.top < 16 ? " low" : "");
          const out = pin ? frag : docFrag, ox = pin ? 0 : sx, oy = pin ? 0 : sy;
          // Covers over text/media swallow clicks, drags and selection starts. Fields stay click-through (an agent must be
          // able to focus and type); their value is masked and copy is intercepted below.
          if ((sh || state.mask) && !f.field && !f.placeholder) d.classList.add("x");
          d.style.cssText = `--c:${CFG.kindColor(f.kind)};left:${r.left + ox - 2}px;top:${r.top + oy - 2}px;width:${r.width + 4}px;height:${r.height + 4}px`;
          if (sh) { if (!f.placeholder && r.width >= 44 && r.height >= 12) d.textContent = f.kind; out.appendChild(d); return; }
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
  function sanitizePage() { return sanitizeText(pageText()); }
  /** Spans for structurally flagged leaf text (e.g. .shipping-address) first, then the text rules, over any string. */
  function sanitizeText(text) {
    const spans = [];
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

  // ---------- copy / cut / drag protection ----------
  /** Text the user or an agent is trying to copy: selection, or the selected part of a focused field. */
  function selectedText() {
    const a = document.activeElement;
    if (a && /^(INPUT|TEXTAREA)$/.test(a.tagName) && typeof a.selectionStart === "number" && a.selectionEnd > a.selectionStart) return { text: a.value.slice(a.selectionStart, a.selectionEnd), field: a };
    return { text: String(getSelection() || ""), field: null };
  }
  const protectedNow = () => state.enabled && (shieldOn() || state.mask);
  function touchesProtected(field) {
    if (field) return state.findings.some((f) => f.el === field) || state.masked.has(field);
    const sel = getSelection();
    if (!sel || sel.isCollapsed) return false;
    for (const f of allDrawn()) {
      const node = f.el || (f.range && f.range.startContainer);
      try { if (node && sel.containsNode(node, true)) return true; } catch (_) { /* detached */ }
    }
    return false;
  }
  /** Copying covered content yields [REDACTED:KIND] instead of the real value, whoever (or whatever) presses Ctrl+C. */
  function guardCopy(e) {
    if (!protectedNow()) return;
    const { text, field } = selectedText();
    if (!text || !touchesProtected(field)) return;
    let out;
    if (field) { const fnd = state.findings.find((f) => f.el === field); out = fnd ? `[REDACTED:${fnd.kind}]` : sanitizeText(text).after; }
    else out = sanitizeText(text).after;
    // a covered element with no detectable text (image, field label) still must not leak: placeholder for the whole selection
    if (out === text) out = "[REDACTED]";
    e.preventDefault(); e.stopImmediatePropagation();
    try { e.clipboardData.setData("text/plain", out); } catch (_) { /* ignore */ }
    if (e.type === "cut" && field) return; // never cut a protected value out of the page
  }
  for (const t of ["copy", "cut"]) document.addEventListener(t, guardCopy, true);
  document.addEventListener("dragstart", (e) => { if (protectedNow() && touchesProtected(selectedText().field)) e.preventDefault(); }, true);

  // ---------- lifecycle ----------
  async function init() {
    const s = await CFG.load();
    state.settings = s;
    try { // agent seen recently anywhere in this browser: start shielded, before the first scan
      const g = await chrome.storage.session.get({ agentAt: 0 });
      if (Date.now() - g.agentAt < STICKY_MS) state.agent = true;
    } catch (_) { /* session storage not exposed to content scripts: the probe below still catches it */ }
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
    const tick = async () => {
      if (state.settings.shieldMode !== "auto") return;
      let r = null;
      try { r = await chrome.runtime.sendMessage({ type: "zl:probe" }); } catch (_) { return; }
      const a = !!(r && r.agent);
      if (a === state.agent) return;
      state.agent = a;
      if (a) arm();
      scan(); disarm();
    };
    tick();                                  // ask right away: a page that loads between two agent actions is still covered
    state.probeTimer = setInterval(tick, 1000);
  }
  chrome.storage.onChanged.addListener((_c, area) => { if (area === "sync") init(); });

  const mo = new MutationObserver((muts) => {
    if (!state.enabled) return;
    for (const m of muts) if (!isOurs(m.target)) { if (shieldOn()) render(); scheduleScan(); return; }
  });
  const MO_OPTS = { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["value", "type", "autocomplete", "class", "hidden", "style", "src"] };
  function observeRoot(sr) { if (!state.observed.has(sr)) { state.observed.add(sr); try { mo.observe(sr, MO_OPTS); } catch (_) { /* ignore */ } } }
  function start() {
    mo.observe(document.documentElement, MO_OPTS);
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
