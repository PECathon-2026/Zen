/* Popup: per-tab summary, mask toggle, sanitized copy, side panel launcher, server status. */
const CFG = globalThis.ZenSettings;
const $ = (id) => document.getElementById(id);
let tab = null;

function setStatus(t) { $("status").textContent = t; }

async function send(msg) {
  try { return await chrome.tabs.sendMessage(tab.id, msg); } catch (_) { return null; }
}

/** Content script may be missing (tab opened before install): inject using the activeTab grant. */
async function ensureContent() {
  let s = await send({ type: "zl:summary" });
  if (s) return s;
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id },
      files: ["lib/detect.js", "lib/structural.js", "lib/settings.js", "content/content.js", "content/guard.js"] });
    await new Promise((r) => setTimeout(r, 250));
    s = await send({ type: "zl:summary" });
  } catch (_) { s = null; }
  return s;
}

function renderSummary(s) {
  $("host").textContent = s.host || "";
  $("disabled").hidden = s.enabled;
  $("summary").hidden = !s.enabled;
  $("total").textContent = s.total;
  $("totlabel").textContent = s.total === 1 ? "sensitive item on this page" : "sensitive items on this page";
  const ul = $("kinds"); ul.replaceChildren();
  Object.entries(s.counts).sort((a, b) => b[1] - a[1]).forEach(([k, n]) => {
    const li = document.createElement("li");
    const tag = document.createElement("span"); tag.className = "kind"; tag.textContent = k; tag.style.background = CFG.kindColor(k);
    const x = document.createElement("span"); x.className = "x"; x.textContent = CFG.KIND_INFO[k] || "Custom rule";
    const c = document.createElement("span"); c.className = "n"; c.textContent = n;
    li.append(tag, x, c); ul.append(li);
  });
  $("mask").checked = !!s.mask;
  const sh = s.shield || { mode: "auto", active: false, agent: false };
  $("shield-mode").value = sh.mode || "auto";
  $("shield-state").textContent = sh.active ? (sh.agent ? "active: agent detected" : "active") : "standing by";
  $("shield-state").className = "pill" + (sh.active ? " on" : "");
  $("guard").hidden = !(s.aiSite && s.guard);
}

async function init() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const settings = await CFG.load();
  CFG.health(settings).then((h) => {
    $("srvdot").className = "dot " + (h.ok ? "on" : "off");
    $("srvtxt").textContent = h.ok ? `server${h.features && h.features.ocr ? " · OCR" : ""}` : "server offline";
    $("server").title = h.ok ? `Zen server ${h.version || ""} at ${CFG.serverBase(settings)}` : "Local server not running — everything still works offline (no OCR).";
  });
  const s = tab && /^(https?|file):/.test(tab.url || "") ? await ensureContent() : null;
  if (!s) {
    $("unavailable").hidden = false; $("summary").hidden = true;
    ["mask", "copy"].forEach((id) => ($(id).disabled = true));
    return;
  }
  renderSummary(s);
}

$("shield-mode").addEventListener("change", async (e) => {
  await CFG.save({ shieldMode: e.target.value });
  setStatus(e.target.value === "off" ? "Agent Shield off." : e.target.value === "on" ? "Agent Shield always on." : "Agent Shield will switch on when an agent is detected.");
  setTimeout(async () => { const s = await send({ type: "zl:summary" }); if (s) renderSummary(s); }, 300);
});
$("mask").addEventListener("change", async (e) => {
  await send({ type: "zl:setMask", on: e.target.checked });
  await CFG.save({ maskByDefault: e.target.checked }); // survives reloads and new tabs
  setStatus(e.target.checked ? "Sensitive items are masked on screen." : "Mask off.");
});
$("copy").addEventListener("click", async () => {
  const r = await send({ type: "zl:sanitizedText" });
  if (!r) return setStatus("Could not read this page.");
  await navigator.clipboard.writeText(r.text);
  setStatus(`Copied sanitized text (${r.count} item${r.count === 1 ? "" : "s"} redacted).`);
});
$("preview").addEventListener("click", async () => {
  try {
    await chrome.sidePanel.open({ tabId: tab.id });
    window.close();
  } catch (e) { setStatus("Side panel unavailable: " + (e && e.message)); }
});
$("theme").addEventListener("click", async () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  ZenTheme.apply(next); await CFG.save({ theme: next });
});
$("options").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });

init();
