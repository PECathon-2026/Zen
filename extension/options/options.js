/* Options: server URL + token, AI site list, custom rules (validated), site allow/deny list. */
const CFG = globalThis.ZenSettings, Z = globalThis.ZenDetect;
const $ = (id) => document.getElementById(id);
const lines = (t) => t.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean)
  .map((s) => s.replace(/^https?:\/\//, "").replace(/\/.*$/, ""));
const HOST_RE = /^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)*(:\d+)?$/;

function ruleRow(r = { kind: "", pattern: "" }) {
  const tr = document.createElement("tr");
  tr.innerHTML = `<td><input class="k" placeholder="EMP_ID" aria-label="Kind"></td><td><input class="p" placeholder="EMP-\\d{6}" aria-label="Pattern" spellcheck="false"></td><td><button class="del" title="Remove rule" aria-label="Remove rule">✕</button></td>`;
  tr.querySelector(".k").value = r.kind; tr.querySelector(".p").value = r.pattern;
  tr.querySelector(".del").addEventListener("click", () => { tr.remove(); trySample(); });
  tr.querySelectorAll("input").forEach((i) => i.addEventListener("input", trySample));
  $("rules").tBodies[0].append(tr);
}
function readRules() {
  return [...$("rules").tBodies[0].rows].map((tr) => ({ kind: tr.querySelector(".k").value.trim().toUpperCase(), pattern: tr.querySelector(".p").value }))
    .filter((r) => r.kind || r.pattern);
}
function trySample() {
  const { rules, errors } = Z.compileCustomRules(readRules());
  const t = $("sample").value;
  $("sampleout").textContent = (errors.length ? "Errors:\n  " + errors.join("\n  ") + "\n" : "") + (t ? "→ " + Z.redactAll(t, rules).text : "");
}

function fill(s) {
  $("serverUrl").value = CFG.ALLOWED_SERVERS.includes(s.serverUrl) ? s.serverUrl : CFG.DEFAULTS.serverUrl;
  $("token").value = s.token || "";
  $("highlight").checked = !!s.highlight; $("guard").checked = !!s.guard; $("maskByDefault").checked = !!s.maskByDefault;
  $("aiSites").value = (s.aiSites || []).join("\n");
  $("siteList").value = (s.siteList || []).join("\n");
  document.querySelector(`input[name=siteMode][value=${s.siteMode === "allow" ? "allow" : "deny"}]`).checked = true;
  $("rules").tBodies[0].replaceChildren();
  (s.customRules || []).forEach(ruleRow);
  trySample();
}
function msg(t, err) { $("msg").textContent = t; $("msg").className = err ? "err" : ""; }

async function save() {
  const customRules = readRules();
  const { errors } = Z.compileCustomRules(customRules);
  if (errors.length) return msg("Fix custom rules first: " + errors[0], true);
  const aiSites = lines($("aiSites").value), siteList = lines($("siteList").value);
  const badHost = [...aiSites, ...siteList].find((h) => !HOST_RE.test(h));
  if (badHost) return msg(`Not a host name: ${badHost}`, true);
  const siteMode = document.querySelector("input[name=siteMode]:checked").value;
  if (siteMode === "allow" && !siteList.length) return msg("Allow-list mode with an empty list would disable Zen everywhere.", true);
  await CFG.save({
    serverUrl: $("serverUrl").value, token: $("token").value.trim(), aiSites, siteList, siteMode, customRules,
    highlight: $("highlight").checked, guard: $("guard").checked, maskByDefault: $("maskByDefault").checked,
  });
  msg("Saved.");
}

$("addrule").addEventListener("click", () => ruleRow());
$("sample").addEventListener("input", trySample);
$("save").addEventListener("click", save);
$("reset").addEventListener("click", () => { fill(CFG.DEFAULTS); msg("Defaults restored — click Save to keep them."); });
$("test").addEventListener("click", async () => {
  $("srv").textContent = "Checking…";
  const h = await CFG.health({ serverUrl: $("serverUrl").value, token: $("token").value.trim() });
  $("srv").textContent = h.ok ? `Connected · v${h.version || "?"} · OCR ${h.features.ocr ? "yes" : "no"}` : `Not reachable${h.status ? " (HTTP " + h.status + ")" : ""} — offline mode`;
});
CFG.load().then(fill);
