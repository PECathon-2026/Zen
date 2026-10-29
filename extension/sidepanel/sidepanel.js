/* Side panel: before/after privacy preview + screenshot redaction (local DOM boxes, optional local OCR). */
const CFG = globalThis.ZenSettings;
const $ = (id) => document.getElementById(id);
const MAX_TEXT = 200000;
let current = null;

async function activeTab() { const [t] = await chrome.tabs.query({ active: true, currentWindow: true }); return t; }
async function ask(tab, msg) { try { return await chrome.tabs.sendMessage(tab.id, msg); } catch (_) { return null; } }

function showErr(t) { $("err").hidden = !t; $("err").textContent = t || ""; }

function renderBefore(text, spans) {
  const box = $("before"); box.replaceChildren();
  let pos = 0; const frag = document.createDocumentFragment();
  for (const s of spans) {
    if (s.start >= MAX_TEXT) break;
    frag.append(text.slice(pos, s.start));
    const m = document.createElement("mark"); m.textContent = text.slice(s.start, s.end);
    m.style.background = CFG.kindColor(s.kind); m.title = s.kind; frag.append(m); pos = s.end;
  }
  frag.append(text.slice(pos, MAX_TEXT));
  box.append(frag);
}
function renderAfter(text) {
  const box = $("after"); box.replaceChildren();
  const frag = document.createDocumentFragment();
  text.slice(0, MAX_TEXT).split(/(\[REDACTED:[A-Z0-9_]+\])/).forEach((part, i) => {
    if (i % 2) { const s = document.createElement("span"); s.className = "red"; s.textContent = part; frag.append(s); } else frag.append(part);
  });
  box.append(frag);
}

async function refresh() {
  const tab = await activeTab();
  current = tab;
  $("page").textContent = tab ? (tab.title || tab.url || "") : "";
  const p = tab && await ask(tab, { type: "zl:preview" });
  if (!p) {
    showErr("Zen is not running on this tab (browser page, or opened before install). Click the Zen toolbar icon once, then Refresh.");
    $("before").textContent = ""; $("after").textContent = ""; $("fields").tBodies[0].replaceChildren(); return;
  }
  showErr("");
  renderBefore(p.before, p.spans);
  renderAfter(p.after);
  const tb = $("fields").tBodies[0]; tb.replaceChildren();
  for (const f of p.fields) {
    const tr = document.createElement("tr");
    const a = document.createElement("td"); a.textContent = f.label;
    const k = document.createElement("td"); const kk = document.createElement("span"); kk.className = "kind"; kk.textContent = f.kind; kk.style.background = CFG.kindColor(f.kind); kk.title = f.reason; k.append(kk);
    const v = document.createElement("td"); const c = document.createElement("code"); c.textContent = f.after || "(empty)"; v.append(c);
    tr.append(a, k, v); tb.append(tr);
  }
  $("nofields").hidden = p.fields.length > 0;
  const total = Object.values(p.counts).reduce((a, b) => a + b, 0);
  $("counts").textContent = `${p.spans.length} text redaction(s); ${total} item(s) on page`;
}

function selectTab(after) {
  $("t-before").setAttribute("aria-selected", String(!after));
  $("t-after").setAttribute("aria-selected", String(after));
  $("before").hidden = after; $("after").hidden = !after;
}
$("t-before").addEventListener("click", () => selectTab(false));
$("t-after").addEventListener("click", () => selectTab(true));
$("refresh").addEventListener("click", async () => { const t = await activeTab(); if (t) await ask(t, { type: "zl:rescan" }); refresh(); });
$("copyafter").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("after").textContent);
  $("counts").textContent = "Copied sanitized text.";
});

// ---------- screenshot redaction ----------
const loadImage = (src) => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = src; });

async function captureAndRedact() {
  const info = $("shotinfo"); info.textContent = "Capturing…"; $("dl").hidden = true;
  const tab = await activeTab();
  const boxes = tab && await ask(tab, { type: "zl:boxes" });
  if (!boxes) { info.textContent = "Zen is not running on this tab, so a safe redaction is not possible. Nothing captured."; return; }
  let dataUrl;
  try { dataUrl = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }); }
  catch (e) { info.textContent = "Capture needs permission: click the Zen toolbar icon on this tab first, then retry. (" + (e && e.message) + ")"; return; }
  const img = await loadImage(dataUrl);
  const cv = document.createElement("canvas"); cv.width = img.width; cv.height = img.height;
  const g = cv.getContext("2d"); g.drawImage(img, 0, 0);
  const sx = img.width / boxes.vw, sy = img.height / boxes.vh, pad = 2;
  g.fillStyle = "#000";
  for (const r of boxes.rects) g.fillRect((r.x - pad) * sx, (r.y - pad) * sy, (r.w + 2 * pad) * sx, (r.h + 2 * pad) * sy);
  let method = `${boxes.rects.length} DOM box(es) blacked out locally`;

  // Optional second pass: local OCR server (only ever receives the already-redacted image).
  const settings = await CFG.load();
  const h = await CFG.health(settings);
  let out = cv;
  if (h.ok && h.features && h.features.ocr) {
    try {
      const blob = await new Promise((r) => cv.toBlob(r, "image/png"));
      const fd = new FormData(); fd.append("image", blob, "screenshot.png");
      const r = await fetch(CFG.serverBase(settings) + "/api/redact_image", { method: "POST", body: fd, headers: CFG.serverHeaders(settings) });
      if (r.ok) {
        const ocrImg = await loadImage(URL.createObjectURL(await r.blob()));
        const c2 = document.createElement("canvas"); c2.width = ocrImg.width; c2.height = ocrImg.height; c2.getContext("2d").drawImage(ocrImg, 0, 0);
        out = c2;
        method += ` + local OCR server (${r.headers.get("X-Zen-Redactions") || "?"} OCR redaction(s))`;
      } else method += ` (OCR server returned ${r.status}; DOM boxes only)`;
    } catch (_) { method += " (OCR server unreachable; DOM boxes only)"; }
  } else method += " (no OCR server: text inside images/canvas is NOT redacted)";

  const url = out.toDataURL("image/png");
  $("shotimg").src = url; $("shotimg").hidden = false;
  $("dl").dataset.url = url; $("dl").hidden = false;
  info.textContent = method + ".";
}
$("dl").addEventListener("click", () => {
  const a = document.createElement("a"); a.href = $("dl").dataset.url; a.download = "zenlens-redacted.png"; a.click();
});
$("shot").addEventListener("click", () => captureAndRedact().catch((e) => ($("shotinfo").textContent = "Failed: " + (e && e.message))));

chrome.tabs.onActivated.addListener(refresh);
chrome.tabs.onUpdated.addListener((id, ch) => { if (current && id === current.id && ch.status === "complete") refresh(); });
refresh();
