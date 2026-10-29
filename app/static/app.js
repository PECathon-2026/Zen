/* ZenLens PWA. Talks only to its own origin (CSP connect-src 'self'). No third-party code. */
'use strict';

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const store = {
  get(k, d) { try { const v = localStorage.getItem('zl.' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('zl.' + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

/* ---------- why-redacted explanations (kind -> rule) ---------- */
const KIND = {
  CARD: ['Payment card number', 'Luhn-valid 13–19 digit card number'],
  CVV: ['Card security code', 'Field marked as CVV/CVC (autocomplete=cc-csc or label)'],
  CARD_EXP: ['Card expiry', 'Field marked as card expiry (autocomplete=cc-exp or label)'],
  AADHAAR: ['Aadhaar number', '12 digits, first digit 2–9, Verhoeff checksum valid'],
  PAN: ['PAN (tax ID)', 'Format AAAPA9999A: 5 letters (4th = holder type), 4 digits, 1 letter'],
  EMAIL: ['Email address', 'name@domain.tld pattern'],
  PHONE: ['Phone number', 'Indian mobile: 10 digits starting 6–9, optional +91/0 prefix'],
  API_KEY: ['API key', 'Known key prefix (sk-, AKIA, ghp_, AIza, xox*) or AWS secret assignment'],
  TOKEN: ['Access token', 'JWT (eyJ… with three segments) or bearer token'],
  OTP: ['One-time code', '4–8 digits next to “OTP”, “verification code”, “code is”…'],
  PASSWORD: ['Password', 'Value after “password:”, “pwd=”, “passwd is”… or a password field'],
  PIN: ['PIN', 'Field labelled PIN / UPI PIN'],
  SECRET: ['Secret', 'Field labelled secret'],
  IP: ['IP address', 'Valid IPv4/IPv6 address (version numbers excluded)'],
  NAME: ['Person name', 'Field marked as a name (cardholder, participant, autocomplete=name)'],
  ADDRESS: ['Postal address', 'Field marked as address / postal code'],
  FACE: ['Face', 'Face detected locally (OpenCV) or a camera/avatar element'],
  EXTRA: ['Sensitive field', 'Screen area of a field the DOM detector flagged'],
  CANARY: ['Vault secret', 'Exact match of a secret stored in your local vault'],
  TEXT: ['Sensitive text', 'Text containing a redacted value'],
};
function explain(kind) {
  const custom = rules().find(r => r.kind === kind);
  if (custom && !KIND[kind]) return [kind.replace(/_/g, ' ').toLowerCase().replace(/^./, c => c.toUpperCase()), `Your rule: /${custom.pattern}/`, true];
  return [...(KIND[kind] || [kind, 'Flagged by a local detector']), false];
}
function kindAttrs(el, kind) {
  el.dataset.k = kind;
  if (explain(kind)[2]) el.dataset.custom = '';
  return el;
}

/* ---------- API ---------- */
async function api(path, { json, form, raw } = {}) {
  const headers = {};
  const tok = store.get('token', '');
  if (tok) headers['X-ZenLens-Token'] = tok;
  let body;
  if (json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  if (form) body = form;
  const res = await fetch(path, { method: body ? 'POST' : 'GET', headers, body, cache: 'no-store' });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); msg = j.error || j.detail || msg; if (j.fields) msg += ': ' + j.fields.map(f => f.loc.slice(1).join('.') + ' ' + f.msg).join('; '); } catch { /* not json */ }
    if (res.status === 401) msg = 'Pairing token missing or wrong. Open Settings and paste the token printed by the server.';
    const e = new Error(msg); e.status = res.status; throw e;
  }
  return raw ? res : res.json();
}

function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => { t.hidden = true; }, err ? 7000 : 3000);
}
async function busy(btn, fn) {
  if (btn.getAttribute('aria-busy') === 'true') return;
  const label = btn.innerHTML;
  btn.setAttribute('aria-busy', 'true'); btn.disabled = true;
  btn.innerHTML = '<span class="spinner" aria-hidden="true"></span> Working…';
  try { await fn(); } catch (e) { toast(e.message || String(e), true); } finally {
    btn.innerHTML = label; btn.disabled = false; btn.removeAttribute('aria-busy');
  }
}
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v;
    else if (k.startsWith('data-')) n.setAttribute(k, v); else if (v !== null && v !== undefined) n.setAttribute(k, v);
  }
  for (const c of kids) if (c !== null && c !== undefined) n.append(c);
  return n;
}

/* ---------- state: info, pairing, local-only ---------- */
let INFO = null;
const localOnly = () => store.get('localOnly', false) || (INFO && INFO.local_only);
function rules() { return store.get('rules', []); }

function pairFromHash() {
  const m = location.hash.match(/token=([A-Za-z0-9_-]{8,128})/);
  if (m) {
    store.set('token', m[1]);
    history.replaceState(null, '', location.pathname + location.search);  // token never lingers in the URL bar
    toast('Paired with this ZenLens server.');
  }
}

async function loadInfo() {
  const dot = $('#status-dot'), txt = $('#status-text');
  try {
    INFO = await api('/api/info');
    dot.className = 'dot ok';
    txt.textContent = INFO.lan ? 'Connected (LAN)' : 'Connected (this device)';
  } catch (e) {
    dot.className = 'dot bad'; txt.textContent = 'Server offline';
    INFO = null;
  }
  applyLocalOnly(); renderSettings(); renderTestChips();
}

function applyLocalOnly() {
  const lo = localOnly();
  $('#local-pill').hidden = !lo;
  const claudeOk = INFO && INFO.features.claude && !lo;
  const r = $('#mode-claude');
  r.disabled = !claudeOk;
  if (!claudeOk && r.checked) $('input[name=mode][value=scripted]').checked = true;
  $('#agent-claude-hint').textContent = lo ? 'Local-only mode is on: Claude mode is disabled, nothing leaves this device.'
    : (INFO && !INFO.features.claude ? 'Claude mode needs the anthropic package and ANTHROPIC_API_KEY on the server.' : '');
  syncScriptBox();
}

/* ---------- tabs ---------- */
function showTab(name) {
  $$('.tab').forEach(t => t.toggleAttribute('aria-current', false));
  const tab = $(`.tab[data-tab="${name}"]`) || $('.tab');
  tab.setAttribute('aria-current', 'page');
  $$('.screen').forEach(s => { s.hidden = s.id !== 'screen-' + tab.dataset.tab; });
  store.set('tab', tab.dataset.tab);
  hideTip();
}
$$('.tab').forEach(t => t.addEventListener('click', () => { showTab(t.dataset.tab); $('#main').focus({ preventScroll: true }); window.scrollTo(0, 0); }));

/* ---------- tooltip for marks ---------- */
const tip = el('div', { class: 'tip', role: 'tooltip', id: 'tip', hidden: '' });
document.body.append(tip);
function showTip(target) {
  const k = target.dataset.k; if (!k) return;
  const [title, rule] = explain(k);
  tip.replaceChildren(el('b', { text: `${title} (${k})` }), document.createTextNode(rule));
  tip.hidden = false;
  const r = target.getBoundingClientRect(), tw = tip.offsetWidth, th = tip.offsetHeight;
  let x = Math.min(Math.max(8, r.left + r.width / 2 - tw / 2), innerWidth - tw - 8);
  let y = r.top - th - 8; if (y < 8) y = r.bottom + 8;
  tip.style.left = x + 'px'; tip.style.top = y + 'px';
}
function hideTip() { tip.hidden = true; }
document.addEventListener('mouseover', e => { const t = e.target.closest('[data-tip]'); if (t) showTip(t); });
document.addEventListener('mouseout', e => { if (e.target.closest('[data-tip]')) hideTip(); });
document.addEventListener('focusin', e => { const t = e.target.closest('[data-tip]'); if (t) showTip(t); else hideTip(); });
document.addEventListener('click', e => { const t = e.target.closest('[data-tip]'); if (t) showTip(t); else hideTip(); });
addEventListener('scroll', hideTip, { passive: true });

function redactedSpan(kind) {
  return kindAttrs(el('span', { class: 'redacted', 'data-tip': '', tabindex: '0', text: `[REDACTED:${kind}]` }), kind);
}
/* Render a sanitized string with [REDACTED:KIND] tokens styled. */
function renderSanitized(node, s) {
  node.replaceChildren();
  const re = /\[REDACTED:([A-Z0-9_]+)\]/g; let pos = 0, m;
  while ((m = re.exec(s))) { node.append(s.slice(pos, m.index), redactedSpan(m[1])); pos = m.index + m[0].length; }
  node.append(s.slice(pos));
}
function renderCounts(node, counts, extraLabel) {
  node.replaceChildren();
  const entries = Object.entries(counts || {});
  const total = entries.reduce((a, [, n]) => a + n, 0);
  if (!total) { node.append(el('span', { class: 'chip-count none', text: '✓ Nothing sensitive found' })); return; }
  node.append(el('span', { class: 'chip-count total' }, el('b', { text: String(total) }), ' ' + (extraLabel || 'redacted')));
  for (const [k, n] of entries.sort((a, b) => b[1] - a[1])) {
    const c = kindAttrs(el('span', { class: 'chip-count', 'data-tip': '', tabindex: '0' }, el('i'), explain(k)[0], ' ', el('b', { text: String(n) })), k);
    node.append(c);
  }
}

/* ---------- TEXT ---------- */
const SAMPLE = `Hi team, please refund order #4412 for Meera.
Card: 4111 1111 1111 1111 (exp 08/29). Her Aadhaar is 2345 6789 0124 and PAN ABCPD1234K.
Reach her at meera.synthetic@example.org or +91 98765 43210.
Staging DB is at 10.20.30.40, api key sk-test_51HxSyntheticKeyAbc123XYZ.
Login code is 482913. password: Synth3tic!Pass
Version 2.4.1.0 shipped on 12 March; call back within 30 minutes.`;
$('#text-sample').onclick = () => { $('#text-in').value = SAMPLE; $('#text-in').focus(); };
$('#text-clear').onclick = () => { $('#text-in').value = ''; $('#text-out').hidden = true; };
$('#text-go').onclick = e => busy(e.currentTarget, async () => {
  const text = $('#text-in').value;
  if (!text.trim()) { toast('Paste some text first.'); return; }
  const extra = rules();
  const res = await api('/api/sanitize', { json: extra.length ? { text, extra_rules: extra } : { text } });
  // Server offsets are Unicode code points; JS strings are UTF-16, so slice by code points.
  const cps = Array.from(text), before = $('#text-before');
  before.replaceChildren();
  let pos = 0;
  for (const f of res.findings) {
    before.append(cps.slice(pos, f.start).join(''));
    before.append(kindAttrs(el('mark', { class: 'pii', 'data-tip': '', tabindex: '0', text: cps.slice(f.start, f.end).join('') }), f.kind));
    pos = f.end;
  }
  before.append(cps.slice(pos).join(''));
  renderSanitized($('#text-after'), res.sanitized);
  $('#text-after').dataset.raw = res.sanitized;
  renderCounts($('#text-counts'), res.counts);
  const why = $('#text-why'); why.replaceChildren();
  for (const k of Object.keys(res.counts)) {
    const [t, rule, custom] = explain(k);
    why.append(el('li', {}, kindAttrs(el('span', { class: 'sw' }), k), el('span', {}, el('strong', { text: `${t} ` }), el('code', { text: k }), ` × ${res.counts[k]}`), el('small', { text: rule + (custom ? ' (custom)' : '') })));
  }
  if (!why.children.length) why.append(el('li', { text: 'No sensitive values were detected. The text can be shared as is.' }));
  $('#text-out').hidden = false;
});
$('#text-copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('#text-after').dataset.raw || ''); toast('Sanitized text copied.'); }
  catch { toast('Copy failed: select the text manually.', true); }
};
function updateRulesHint() {
  const n = rules().length;
  $('#text-rules-hint').textContent = n ? `+ ${n} custom rule${n > 1 ? 's' : ''}` : '';
}

/* ---------- SCREENSHOT ---------- */
let beforeURL = null, afterURL = null;
async function redactFile(file) {
  if (!file) return;
  if (!/^image\/(png|jpeg)$/.test(file.type) && !/\.(png|jpe?g)$/i.test(file.name)) { toast('Use a PNG or JPEG image (on iPhone set Camera > Formats > Most Compatible).', true); return; }
  if (INFO && !INFO.features.ocr) toast('No local OCR backend on the server: redaction will fail closed.', true);
  const btn = $('#img-pick-label');
  btn.setAttribute('aria-busy', 'true');
  $('#img-ocr-hint').textContent = 'Reading text on your computer…';
  try {
    const fd = new FormData(); fd.append('image', file, file.name || 'image');
    if ($('#img-faces').checked) fd.append('faces', 'true');
    const res = await api('/api/redact_image', { form: fd, raw: true });
    let boxes = [];
    try { boxes = JSON.parse(res.headers.get('X-ZenLens-Redactions') || '[]'); } catch { /* ignore */ }
    const blob = await res.blob();
    if (beforeURL) URL.revokeObjectURL(beforeURL); if (afterURL) URL.revokeObjectURL(afterURL);
    beforeURL = URL.createObjectURL(file);   // original stays in this browser; never re-uploaded or stored
    afterURL = URL.createObjectURL(blob);
    $('#img-before').src = beforeURL; $('#img-after').src = afterURL;
    $('#img-download').href = afterURL;
    const counts = {}; boxes.forEach(b => { counts[b.kind] = (counts[b.kind] || 0) + 1; });
    renderCounts($('#img-counts'), counts, 'areas blacked out');
    $('#img-out').hidden = false; setSlider(50); $('#img-range').value = 50;
    $('#img-ocr-hint').textContent = '';
  } catch (e) {
    $('#img-out').hidden = true;
    $('#img-ocr-hint').textContent = '';
    toast(e.message, true);
  } finally { btn.removeAttribute('aria-busy'); }
}
function setSlider(p) {
  $('#img-before-wrap').style.clipPath = `inset(0 ${100 - p}% 0 0)`;
  $('#img-handle').style.left = p + '%';
}
$('#img-range').addEventListener('input', e => setSlider(+e.target.value));
(function dragSlider() {
  const s = $('#img-slider'); let on = false;
  const move = e => { const r = s.getBoundingClientRect(); const p = Math.round(Math.min(100, Math.max(0, (e.clientX - r.left) / r.width * 100))); setSlider(p); $('#img-range').value = p; };
  s.addEventListener('pointerdown', e => { on = true; s.setPointerCapture(e.pointerId); move(e); });
  s.addEventListener('pointermove', e => { if (on) move(e); });
  s.addEventListener('pointerup', () => { on = false; });
})();
['#img-camera', '#img-pick'].forEach(id => $(id).addEventListener('change', e => { redactFile(e.target.files[0]); e.target.value = ''; }));
(function drop() {
  const d = $('#img-drop');
  d.addEventListener('dragover', e => { e.preventDefault(); d.classList.add('over'); });
  d.addEventListener('dragleave', () => d.classList.remove('over'));
  d.addEventListener('drop', e => { e.preventDefault(); d.classList.remove('over'); redactFile(e.dataTransfer.files[0]); });
})();

/* ---------- WEB PAGE ---------- */
function renderTestChips() {
  const pages = (INFO && INFO.testpages) || [];
  for (const [box, input] of [['#page-tests', '#page-url'], ['#agent-tests', '#agent-url']]) {
    const c = $(box); c.replaceChildren();
    for (const p of pages) {
      const b = el('button', { class: 'chip', type: 'button', 'aria-pressed': 'false', text: p.replace(/_/g, ' ') });
      b.onclick = () => {
        $(input).value = p;
        $$('.chip', c).forEach(x => x.setAttribute('aria-pressed', String(x === b)));
        if (box === '#agent-tests') applyPreset(p);
      };
      c.append(b);
    }
  }
}
function elementRow(e) {
  const kind = e.sensitive || (/\[REDACTED:([A-Z0-9_]+)\]/.exec(`${e.text || ''}${e.value || ''}`) || [])[1];
  const row = el('div', { class: 'el' + (kind ? ' sens' : '') },
    el('span', { class: 'eid', text: e.id }),
    el('span', { class: 'erole', text: `${e.role}${e.type ? ' · ' + e.type : ''}${e.name ? ' · “' + e.name + '”' : ''}` }));
  if (kind) kindAttrs(row, kind);
  const t = el('span', { class: 'etext mono' });
  const shown = [e.text, e.value !== null && e.value !== undefined && e.value !== '' ? `value: ${e.value}` : null].filter(Boolean).join('  ·  ');
  if (shown) { renderSanitized(t, shown); row.append(t); }
  return row;
}
$('#page-go').onclick = e => busy(e.currentTarget, async () => {
  const url = $('#page-url').value.trim();
  if (!url) { toast('Enter a URL or pick a test page.'); return; }
  const p = await api('/api/preview', { json: { url } });
  const shot = $('#page-shot'); shot.replaceChildren();
  if (p.screenshot) shot.append(el('img', { src: 'data:image/png;base64,' + p.screenshot, alt: `Redacted screenshot of ${p.title || 'the page'}` }));
  else shot.append(el('p', { class: 'hint err', text: `Screenshot withheld (fail closed): ${p.screenshot_reason || 'unavailable'}` }));
  const counts = { ...(p.redactions || {}) };
  renderCounts($('#page-counts'), counts, 'values hidden from the model');
  const list = $('#page-els'); list.replaceChildren();
  const els = (p.view && p.view.elements) || [];
  if (!els.length) list.append(el('p', { class: 'hint', text: p.screenshot_reason || 'No elements captured.' }));
  els.forEach(x => list.append(elementRow(x)));
  $('#page-out').hidden = false;
});

/* ---------- AGENT ---------- */
let PRESETS = {};
async function loadPresets() {
  try { PRESETS = (await api('/api/demo_scripts')).presets || {}; } catch { PRESETS = {}; }
  if (!$('#agent-url').value) { $('#agent-url').value = 'auth'; applyPreset('auth'); }
}
function applyPreset(name) {
  const p = PRESETS[name]; if (!p) return;
  $('#agent-goal').value = p.goal;
  $('#agent-script').value = JSON.stringify(p.script, null, 1).replace(/\n\s*/g, ' ').replace(/\}, \{/g, '},\n {');
}
function syncScriptBox() {
  const scripted = $('input[name=mode]:checked').value === 'scripted';
  $('#agent-script-box').hidden = !scripted;
}
$$('input[name=mode]').forEach(r => r.addEventListener('change', syncScriptBox));

function verdictBadge(s) {
  const v = s.verdict;
  if (v === 'ok') return el('span', { class: 'badge ok', text: s.needs_approval ? 'approved' : 'allowed' });
  if (v === 'rejected') return el('span', { class: 'badge bad', text: s.needs_approval && s.approved === false ? 'needs approval' : 'rejected' });
  if (v === 'done') return el('span', { class: 'badge ok', text: 'done' });
  if (v === 'ask_user') return el('span', { class: 'badge warn', text: 'asks you' });
  return el('span', { class: 'badge warn', text: v || '—' });
}
function jsonBlock(obj) {
  const pre = el('pre', { class: 'json mono' });
  renderSanitized(pre, JSON.stringify(obj, null, 2));
  return pre;
}
$('#agent-go').onclick = e => busy(e.currentTarget, async () => {
  const mode = $('input[name=mode]:checked').value;
  if (mode === 'claude' && localOnly()) { toast('Local-only mode is on.', true); return; }
  const body = { goal: $('#agent-goal').value.trim(), url: $('#agent-url').value.trim(), mode, auto_approve: $('#agent-approve').checked };
  if (!body.goal || !body.url) { toast('Enter a goal and a start URL.'); return; }
  if (mode === 'scripted') {
    try { body.script = JSON.parse($('#agent-script').value || '[]'); if (!Array.isArray(body.script)) throw 0; }
    catch { toast('Demo script must be a JSON array of actions.', true); return; }
  }
  $('#agent-out').hidden = false;
  const steps = $('#agent-steps'); steps.replaceChildren(el('li', { class: 'hint', text: 'Running in a local headless browser…' }));
  $('#agent-summary').replaceChildren(el('span', { class: 'spinner' }), ' Running…');
  $('#agent-egress').replaceChildren(); $('#agent-egress-note').textContent = '';
  const r = await api('/api/agent/run', { json: body });
  renderReport(r);
});
async function renderReport(r) {
  const eg = r.egress || { payloads: [], sent_to_third_party: false };
  const sum = $('#agent-summary'); sum.replaceChildren(
    el('span', { class: 'big', text: `Status: ${r.status}` }),
    el('span', { text: `${r.steps.length} steps · ${r.rejected} rejected` }),
    el('span', { text: `planner: ${r.llm}` }),
    r.reason ? el('span', { class: 'hint', text: r.reason }) : null);
  const steps = $('#agent-steps'); steps.replaceChildren();
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  for (const [i, s] of r.steps.entries()) {
    const li = el('li', { class: 'step' },
      el('div', { class: 'step-head' }, el('span', { class: 'step-n', text: `${s.step}.` }), el('code', { text: s.action }), verdictBadge(s)),
      s.reason ? el('div', { class: 'hint', text: `Model’s reason: ${s.reason}` }) : null,
      s.result && s.result !== 'ok' ? el('div', { class: 'hint', text: s.result }) : null,
      s.needs_approval ? el('div', { class: 'hint', text: `Approval: ${s.approval_reason} → ${s.approved ? 'approved' : 'denied'}` }) : null,
      s.privacy ? el('div', { class: 'hint', text: `View had ${s.privacy.total} redacted values, ${s.privacy.sensitive_fields} sensitive fields` }) : null);
    if (eg.payloads[i]) li.append(el('details', {}, el('summary', { text: 'What the model saw at this step' }), jsonBlock(eg.payloads[i])));
    steps.append(li);
    if (!reduced) { await new Promise(res => setTimeout(res, 220)); }
    requestAnimationFrame(() => li.classList.add('in'));
  }
  if (!r.steps.length) steps.append(el('li', { class: 'hint', text: r.reason || 'No steps.' }));
  const bytes = eg.payloads.reduce((a, p) => a + new Blob([JSON.stringify(p)]).size, 0);
  $('#agent-egress-note').textContent = eg.sent_to_third_party
    ? `${eg.payloads.length} request${eg.payloads.length === 1 ? '' : 's'} (${(bytes / 1024).toFixed(1)} KB) sent to ${eg.destination}. Every one passed the egress gate; this is exactly what was sent.`
    : `Nothing left this device: the scripted planner runs locally. Below is exactly what Claude would have received (${eg.payloads.length} request${eg.payloads.length === 1 ? '' : 's'}, ${(bytes / 1024).toFixed(1)} KB), already sanitized and egress-checked.`;
  const box = $('#agent-egress'); box.replaceChildren();
  if (r.secrets_available && r.secrets_available.length) box.append(el('p', { class: 'hint', text: `Vault placeholders the model may use (values stay local): ${r.secrets_available.join(', ')}` }));
  eg.payloads.forEach((p, i) => box.append(el('details', i === eg.payloads.length - 1 ? { open: '' } : {}, el('summary', { text: `Request ${i + 1}` }), jsonBlock(p))));
  if (!eg.payloads.length) box.append(el('p', { class: 'hint', text: 'No payloads were produced.' }));
}

/* ---------- SETTINGS ---------- */
function renderSettings() {
  $('#set-local').checked = !!store.get('localOnly', false) || !!(INFO && INFO.local_only);
  $('#set-local').disabled = !!(INFO && INFO.local_only);
  $('#set-server').textContent = location.origin;
  $('#set-lan').textContent = INFO ? (INFO.lan ? 'LAN (token required)' : 'This computer only') + (INFO.local_only ? ' · server local-only' : '') : 'offline';
  const f = INFO ? INFO.features : {};
  $('#set-features').textContent = INFO ? `OCR ${f.ocr ? '✓' : '✗'} · Browser ${f.playwright ? '✓' : '✗'} · Claude ${f.claude ? '✓' : '✗'} · Agent ${INFO.runner ? '✓' : '✗'}` : '—';
  $('#set-token').value = store.get('token', '');
  const theme = store.get('theme', 'system');
  $$('input[name=theme]').forEach(r => { r.checked = r.value === theme; });
  renderRules();
}
$('#set-local').addEventListener('change', e => { store.set('localOnly', e.target.checked); applyLocalOnly(); toast(e.target.checked ? 'Local-only mode on.' : 'Local-only mode off.'); });
$('#set-token-save').onclick = () => { store.set('token', $('#set-token').value.trim()); toast('Token saved in this browser.'); loadInfo(); };
function applyTheme(t) { if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.dataset.theme = t; }
$$('input[name=theme]').forEach(r => r.addEventListener('change', () => { store.set('theme', r.value); applyTheme(r.value); }));

function renderRules() {
  const ul = $('#rules'); ul.replaceChildren();
  const rs = rules();
  if (!rs.length) ul.append(el('li', { class: 'empty', text: 'No custom rules yet.' }));
  rs.forEach((r, i) => {
    const del = el('button', { class: 'btn small ghost', type: 'button', 'aria-label': `Delete rule ${r.kind}`, text: 'Remove' });
    del.onclick = () => { const n = rules(); n.splice(i, 1); store.set('rules', n); renderRules(); };
    ul.append(el('li', {}, kindAttrs(el('span', { class: 'chip-count', text: r.kind }), r.kind), el('code', { text: r.pattern, title: r.pattern }), del));
  });
  updateRulesHint();
}
$('#rule-form').addEventListener('submit', async e => {
  e.preventDefault();
  const err = $('#rule-err'); err.textContent = '';
  const kind = $('#rule-kind').value.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  const pattern = $('#rule-pattern').value;
  if (!/^[A-Z][A-Z0-9_]{0,23}$/.test(kind)) { err.textContent = 'Kind: letters, digits and _ (start with a letter).'; return; }
  if (!pattern) { err.textContent = 'Pattern is empty.'; return; }
  const list = rules();
  if (list.length >= 20) { err.textContent = 'At most 20 rules.'; return; }
  try { // the server is the authority (Python regex + safety checks)
    await api('/api/sanitize', { json: { text: 'x', extra_rules: [...list, { kind, pattern }] } });
  } catch (x) { err.textContent = x.message; return; }
  store.set('rules', [...list, { kind, pattern }]);
  $('#rule-kind').value = ''; $('#rule-pattern').value = '';
  renderRules(); toast(`Rule ${kind} added.`);
});

/* ---------- boot ---------- */
applyTheme(store.get('theme', 'system'));
pairFromHash();
showTab(store.get('tab', 'text'));
renderRules();
loadInfo().then(loadPresets);
addEventListener('hashchange', () => { pairFromHash(); loadInfo(); });
if ('serviceWorker' in navigator && window.isSecureContext) {
  navigator.serviceWorker.register('/sw.js').catch(() => { /* optional */ });
}
