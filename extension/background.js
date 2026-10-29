/* Zen service worker: context menu, toolbar badge, agent probe, image analysis. No storage of values. */

// tracking.js (BSD, bundled in lib/vendor) expects a window; its Viola-Jones detector is pure JS and runs fine in a worker.
self.window = self.window || self; self.document = self.document || {};
try { importScripts("lib/vendor/tracking-min.js", "lib/vendor/face-min.js", "lib/settings.js"); } catch (e) { console.warn("Zen: face detector not loaded", e && e.message); }

const MENU_ID = "zenlens-redact-copy";
const STICKY_MS = 10 * 60 * 1000;
// Content scripts read the "agent seen" timestamp straight from session storage at document_start (no service-worker wake-up
// needed), so a page that loads between two agent actions is covered from its first scan.
chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" }).catch(() => {});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: MENU_ID, title: "Redact selection & copy", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_ID || !tab || tab.id == null) return;
  const msg = { type: "zl:redactSelection", fallback: info.selectionText || "" };
  try {
    await chrome.tabs.sendMessage(tab.id, msg);
  } catch (_) {
    // No content script (e.g. page loaded before install): inject via activeTab grant from the menu click.
    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id },
        files: ["lib/detect.js", "lib/structural.js", "lib/settings.js", "content/content.js", "content/guard.js"] });
      await chrome.tabs.sendMessage(tab.id, msg);
    } catch (e) { console.warn("Zen: cannot redact on this page", e && e.message); }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg && msg.type === "zl:count" && sender.tab && sender.tab.id != null) {
    const n = msg.total | 0;
    chrome.action.setBadgeText({ tabId: sender.tab.id, text: msg.shield && !n ? "ON" : n ? String(n > 999 ? "999+" : n) : "" });
    chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: msg.shield ? "#b8431e" : "#7048e8" });
  }
  // Agent detection: is any debugger client (another extension's agent, DevTools, a CDP script) attached to this tab?
  // We never attach ourselves, so this shows no infobar. Only a boolean leaves this function.
  // Real agents (Claude in Chrome) attach the debugger per action and detach in between, so "attached right now" is
  // racy: a page load or read between two actions would be unprotected. Once a tab has seen an agent, keep the shield up for
  // STICKY_MS (kept in storage.session so it survives service-worker restarts).
  if (msg && msg.type === "zl:probe" && sender.tab && sender.tab.id != null) {
    const id = sender.tab.id, now = Date.now();
    Promise.all([chrome.debugger.getTargets(), chrome.storage.session.get({ agentSeen: {}, agentAt: 0 })]).then(async ([ts, got]) => {
      const seen = got.agentSeen || {};
      let at = got.agentAt || 0;
      if (ts.some((t) => t.tabId === id && t.attached)) { seen[id] = now; at = now; await chrome.storage.session.set({ agentSeen: seen, agentAt: now }); }
      reply({ agent: now - Math.max(seen[id] || 0, at) < STICKY_MS });
    }).catch(() => reply({ agent: false }));
    return true;
  }
});

// Side panel opens from the popup's "Privacy preview" button; clicking the toolbar icon shows the popup.
chrome.sidePanel && chrome.sidePanel.setPanelBehavior && chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});


// ---------- image analysis: faces (bundled detector) + text/faces via the optional local Zen server ----------
// Content scripts cannot read cross-origin pixels (tainted canvas); the worker can fetch them with host permissions.
const analysisCache = new Map(); // key -> {t, res}
const FACE_PAD = 0.22;           // grow detected boxes: cascades box the inner face, hair/ears/chin are identifying too
const clamp01 = (v) => Math.max(0, Math.min(1, v));

function detectFaces(bmp) {
  const nw = bmp.width, nh = bmp.height, scale = Math.min(1, 480 / Math.max(nw, nh));
  const w = Math.max(1, Math.round(nw * scale)), h = Math.max(1, Math.round(nh * scale));
  const oc = new OffscreenCanvas(w, h), g = oc.getContext("2d", { willReadFrequently: true });
  g.drawImage(bmp, 0, 0, w, h);
  const v = self.tracking && self.tracking.ViolaJones;
  if (!v || !v.classifiers || !v.classifiers.face) throw new Error("face detector missing");
  const px = g.getImageData(0, 0, w, h).data;
  return v.detect(px, w, h, 1.2, 1.25, 1.5, 0.2, v.classifiers.face).map((f) => {
    const px0 = f.width * FACE_PAD, py0 = f.height * FACE_PAD;
    const x0 = clamp01((f.x - px0) / w), y0 = clamp01((f.y - py0) / h), x1 = clamp01((f.x + f.width + px0) / w), y1 = clamp01((f.y + f.height + py0) / h);
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0, kind: "FACE" };
  });
}

/** Text/face boxes from the local server (Apple Vision / Tesseract OCR + OpenCV). Resolves null when it is not running. */
async function serverBoxes(blob, nw, nh) {
  try {
    const settings = await ZenSettings.load(), ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 6000);
    const fd = new FormData(); fd.append("image", blob, "image"); fd.append("faces", "true");
    const r = await fetch(ZenSettings.serverBase(settings) + "/api/redact_image", { method: "POST", body: fd, headers: ZenSettings.serverHeaders(settings), signal: ctl.signal });
    clearTimeout(t);
    if (!r.ok) return null;
    const list = JSON.parse(r.headers.get("X-Zen-Redactions") || "[]");
    return list.map((b) => ({ x: clamp01(b.box[0] / nw), y: clamp01(b.box[1] / nh), w: clamp01((b.box[2] - b.box[0]) / nw), h: clamp01((b.box[3] - b.box[1]) / nh), kind: b.kind === "EXTRA" ? "TEXT" : b.kind }));
  } catch (_) { return null; }
}

async function analyzeImage(msg) {
  const key = msg.src || "d:" + msg.dataUrl.length + ":" + msg.dataUrl.slice(-48);
  const hit = analysisCache.get(key);
  if (hit && Date.now() - hit.t < (msg.ttl || 10 * 60 * 1000)) return hit.res;
  let blob;
  if (msg.dataUrl) blob = await (await fetch(msg.dataUrl)).blob();
  else {
    const r = await fetch(msg.src, { credentials: "omit", cache: "force-cache" });
    if (!r.ok) throw new Error("fetch " + r.status);
    blob = await r.blob();
  }
  if (blob.size > 12e6 || !/^image\//.test(blob.type || "image/")) throw new Error("not analysable");
  const bmp = await createImageBitmap(blob), nw = bmp.width, nh = bmp.height;
  const boxes = detectFaces(bmp);
  const srv = await serverBoxes(blob, nw, nh);
  if (srv) boxes.push(...srv);
  const res = { nw, nh, boxes, ocrUp: !!srv };
  analysisCache.set(key, { t: Date.now(), res });
  if (analysisCache.size > 300) analysisCache.delete(analysisCache.keys().next().value);
  return res;
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (!msg || msg.type !== "zl:analyze") return;
  analyzeImage(msg).then((res) => reply({ ok: true, res })).catch((e) => reply({ ok: false, error: String((e && e.message) || e).slice(0, 80) }));
  return true;
});
