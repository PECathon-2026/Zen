/*
 * ZenLens paste/submit guard for AI chat sites. Intercepts paste and Enter/send in the prompt box,
 * detects PII locally, and asks: Send sanitized (default) / Send anyway / Cancel.
 * It only edits the prompt box the user is typing in, at the user's choice. It never transmits
 * anything itself — the site's own UI sends whatever ends up in the box.
 */
(function () {
  "use strict";
  const ZL = globalThis.__ZenLensContent;
  if (!ZL || ZL.guardInstalled) return;
  ZL.guardInstalled = true;
  const Z = globalThis.ZenLensDetect, CFG = globalThis.ZenLensSettings;

  const SEND_SEL = [
    'button[data-testid="send-button"]', 'button[data-testid*="send" i]', 'button[aria-label*="send" i]',
    'button[aria-label*="submit" i]', 'button[type="submit"]',
  ].join(",");
  const EDITABLE_SEL = 'textarea, input[type="text"], input:not([type]), [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]';

  let bypass = null;       // {text, until} one-shot allowance after the user chose
  let dialogOpen = false;
  let lastBox = null;

  const active = () => {
    const s = ZL.state.settings;
    return ZL.state.enabled && s.guard && CFG.isAiSite(s, location.hostname);
  };
  ZL.guardActive = active;

  function boxOf(target) {
    if (!target || target.nodeType !== 1) target = target && target.parentElement;
    if (!target || !target.closest) return null;
    let el = target.closest(EDITABLE_SEL);
    if (!el) return null;
    // climb to the outermost contenteditable host (ProseMirror / Lexical roots)
    while (el.parentElement && el.parentElement.isContentEditable) el = el.parentElement;
    return el;
  }
  const isField = (el) => el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT");
  const boxText = (el) => (isField(el) ? el.value : el.innerText || el.textContent || "");
  const findBox = () => (lastBox && lastBox.isConnected ? lastBox : null) ||
    boxOf(document.querySelector('#prompt-textarea, [contenteditable="true"][role="textbox"], div.ProseMirror[contenteditable="true"], textarea'));

  function saveSelection(box) {
    if (isField(box)) return { s: box.selectionStart, e: box.selectionEnd };
    const sel = getSelection();
    return sel && sel.rangeCount ? sel.getRangeAt(0).cloneRange() : null;
  }
  function restoreSelection(box, saved) {
    box.focus();
    if (!saved) return;
    if (isField(box)) { try { box.setSelectionRange(saved.s, saved.e); } catch (_) { /* ignore */ } return; }
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(saved);
  }
  function selectAll(box) {
    box.focus();
    if (isField(box)) { box.select(); return; }
    const r = document.createRange(); r.selectNodeContents(box);
    const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
  }
  /** Insert text at the current selection the way a user would (keeps editor state consistent). */
  function insertText(box, text) {
    let ok = false;
    try { ok = document.execCommand("insertText", false, text); } catch (_) { ok = false; }
    if (ok) return true;
    if (isField(box)) {
      box.setRangeText(text, box.selectionStart, box.selectionEnd, "end");
      box.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: text }));
      return true;
    }
    // Rich editors: synthetic paste with our (already chosen) text; flagged so we don't re-intercept.
    const dt = new DataTransfer(); dt.setData("text/plain", text);
    bypass = { text, until: Date.now() + 1000, paste: true };
    box.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
    return true;
  }

  function submit(box) {
    const btn = document.querySelector(SEND_SEL);
    bypass = { text: boxText(box), until: Date.now() + 2000 };
    setTimeout(() => {
      const b = document.querySelector(SEND_SEL) || btn;
      if (b && !b.disabled) { b.click(); return; }
      box.focus();
      box.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
    }, 60);
  }
  function bypassed(text, paste = false) {
    if (bypass && Date.now() < bypass.until && !!bypass.paste === paste && (paste ? bypass.text === text : true)) {
      bypass = null; return true;
    }
    return false;
  }

  // ---------- dialog ----------
  function summarise(hits) {
    const c = {};
    hits.forEach((h) => { c[h.kind] = (c[h.kind] || 0) + 1; });
    return Object.entries(c).map(([k, n]) => `${n} × ${k}`).join(", ");
  }
  function dialog(mode, text, hits) {
    return new Promise((resolve) => {
      dialogOpen = true;
      const host = document.createElement("zenlens-guard");
      host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;";
      const sr = host.attachShadow({ mode: "closed" });
      const verb = mode === "paste" ? "Paste" : "Send";
      const sanitized = Z.redactSpans(text, hits);
      ZL.adoptCss(sr, `
        .bg{position:fixed;inset:0;background:rgba(10,8,20,.45);display:flex;align-items:center;justify-content:center;padding:16px;font:14px/1.45 system-ui,-apple-system,sans-serif}
        .d{background:#fff;color:#1f1d2b;max-width:560px;width:100%;border-radius:14px;box-shadow:0 18px 60px rgba(0,0,0,.35);padding:18px 18px 14px;max-height:calc(100vh - 32px);overflow:auto}
        h2{margin:0 0 4px;font-size:16px;display:flex;gap:8px;align-items:center}
        .dot{width:10px;height:10px;border-radius:50%;background:#7048e8}
        .k{color:#5f5b70;margin:0 0 10px}
        pre{white-space:pre-wrap;word-break:break-word;background:#f4f2fb;border-radius:8px;padding:10px;max-height:180px;overflow:auto;font:12px/1.5 ui-monospace,Menlo,monospace;margin:0 0 12px}
        .r{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap}
        button{font:600 13px system-ui,sans-serif;border-radius:8px;padding:8px 14px;cursor:pointer;border:1px solid #d6d2e8;background:#fff;color:#1f1d2b}
        button.p{background:#7048e8;border-color:#7048e8;color:#fff}
        button:focus-visible{outline:3px solid #b197fc;outline-offset:1px}
        .n{font-size:11px;color:#7a768c;margin-top:8px}
        @media (prefers-color-scheme:dark){.d{background:#1f1d2b;color:#eee}.k{color:#aaa}pre{background:#2b2840;color:#eee}button{background:#2b2840;color:#eee;border-color:#45405e}}
      `);
      // Built with DOM APIs (no innerHTML) so Trusted-Types pages (e.g. Gemini) cannot break it.
      const h = (tag, attrs = {}, ...kids) => { const e = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); e.append(...kids); return e; };
      const btn = (a, label, cls) => h("button", cls ? { "data-a": a, class: cls } : { "data-a": a }, label);
      sr.appendChild(h("div", { class: "bg", role: "dialog", "aria-modal": "true", "aria-labelledby": "t" },
        h("div", { class: "d" },
          h("h2", { id: "t" }, h("span", { class: "dot" }), "ZenLens found sensitive data"),
          h("p", { class: "k" }), h("pre"),
          h("div", { class: "r" }, btn("cancel", "Cancel"), btn("anyway", `${verb} anyway`), btn("sanitized", `${verb} sanitized`, "p")),
          h("div", { class: "n" }, "Detected locally. ZenLens never sends anything; the site sends what is in the box."))));
      sr.querySelector(".k").textContent = `${summarise(hits)} in your ${mode === "paste" ? "paste" : "message"}. Preview of the sanitized version:`;
      sr.querySelector("pre").textContent = sanitized.length > 1200 ? sanitized.slice(0, 1200) + "…" : sanitized;
      const done = (a) => { dialogOpen = false; host.remove(); removeEventListener("keydown", onKey, true); resolve(a); };
      const onKey = (e) => {
        if (e.key === "Escape") { e.preventDefault(); e.stopImmediatePropagation(); done("cancel"); }
      };
      addEventListener("keydown", onKey, true);
      sr.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => done(b.dataset.a)));
      sr.querySelector(".bg").addEventListener("click", (e) => { if (e.target.classList.contains("bg")) done("cancel"); });
      for (const t of ["keydown", "keyup", "keypress", "input", "paste"]) host.addEventListener(t, (ev) => ev.stopPropagation());
      document.documentElement.appendChild(host);
      setTimeout(() => sr.querySelector("button.p").focus(), 0);
    });
  }

  // ---------- interceptors ----------
  addEventListener("focusin", (e) => { const b = boxOf(e.target); if (b) lastBox = b; }, true);

  addEventListener("paste", async (e) => {
    if (!active() || dialogOpen) return;
    const box = boxOf(e.target);
    if (!box) return;
    const text = e.clipboardData ? e.clipboardData.getData("text/plain") : "";
    if (!text || bypassed(text, true)) return;
    const hits = Z.detectAll(text, ZL.state.customRules);
    if (!hits.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const saved = saveSelection(box);
    const choice = await dialog("paste", text, hits);
    if (choice === "cancel") { restoreSelection(box, saved); return; }
    restoreSelection(box, saved);
    insertText(box, choice === "sanitized" ? Z.redactSpans(text, hits) : text);
  }, true);

  async function guardSend(e, box) {
    const text = boxText(box);
    if (!text.trim() || bypassed(text)) return;
    const hits = Z.detectAll(text, ZL.state.customRules);
    if (!hits.length) return;
    e.preventDefault(); e.stopImmediatePropagation();
    const choice = await dialog("send", text, hits);
    if (choice === "cancel") { box.focus(); return; }
    if (choice === "sanitized") {
      selectAll(box);
      insertText(box, Z.redactSpans(text, hits));
      await new Promise((r) => setTimeout(r, 30));
      const left = Z.detectAll(boxText(box), ZL.state.customRules);
      if (left.length) { // editor did not take the replacement: fail closed, do not send
        ZL.ui.toast && ZL.ui.toast("ZenLens: could not sanitize this editor; message NOT sent. Please edit it manually.");
        return;
      }
    }
    submit(box);
  }

  addEventListener("keydown", (e) => {
    if (!active() || dialogOpen || e.key !== "Enter" || e.shiftKey || e.isComposing || e.keyCode === 229) return;
    const box = boxOf(e.target);
    if (!box) return;
    guardSend(e, box);
  }, true);

  addEventListener("click", (e) => {
    if (!active() || dialogOpen) return;
    const btn = e.target && e.target.closest && e.target.closest(SEND_SEL);
    if (!btn) return;
    const box = findBox();
    if (box) guardSend(e, box);
  }, true);

  addEventListener("submit", (e) => {
    if (!active() || dialogOpen) return;
    const box = e.target && e.target.querySelector && boxOf(e.target.querySelector(EDITABLE_SEL));
    if (box) guardSend(e, box);
  }, true);
})();
