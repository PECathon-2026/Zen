/* ZenLens "Redact before you share".
 * Input: an image shared via the Web Share Target (parked by sw.js in the 'zenlens-share-inbox' cache,
 * ?id=...) or picked with the file input. The original lives only in memory on this page: the inbox entry
 * is deleted as soon as it is read, and the only network request carrying it is POST /api/redact_image
 * on this same origin (CSP connect-src 'self' enforces that too). Output: a redacted PNG for the share sheet.
 */
'use strict';

const INBOX = 'zenlens-share-inbox';
const MAX_UPLOAD = 14 * 1024 * 1024;  // server caps at 15 MB; re-encode bigger images
const $ = s => document.querySelector(s);

const store = {
  get(k, d) { try { const v = localStorage.getItem('zl.' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('zl.' + k, JSON.stringify(v)); } catch { /* private mode */ } },
};

let original = null;   // Blob (memory only)
let redacted = null;   // Blob
let urls = { orig: null, out: null };
let runId = 0;

/* ---------- states ---------- */
function show(state) {
  for (const s of ['pick', 'work', 'done', 'err']) $('#st-' + s).hidden = s !== state;
}
function notice(msg) { const n = $('#notice'); n.textContent = msg || ''; n.hidden = !msg; }
function fail(msg) { $('#err-msg').textContent = msg; show('err'); }

function forget() {
  runId++;
  for (const k of Object.keys(urls)) if (urls[k]) { URL.revokeObjectURL(urls[k]); urls[k] = null; }
  original = redacted = null;
  $('#out').removeAttribute('src');
  $('#pick').value = '';
}
/* Delete parked shares. keepFresh: leave entries younger than 60 s alone (a share that is being handed
 * over to another share.html right now); anything older is an orphan and goes. */
async function clearInbox(keepFresh = false) {
  if (!('caches' in self)) return;
  try {
    const inbox = await caches.open(INBOX);
    for (const req of await inbox.keys()) {
      const res = keepFresh ? await inbox.match(req) : null;
      const age = res ? Date.now() - Number(res.headers.get('X-Stashed-At') || 0) : Infinity;
      if (age > 60000) await inbox.delete(req);
    }
  } catch { /* nothing to clear */ }
}

/* ---------- input ---------- */
async function takeShared(id) {
  if (!('caches' in self) || !/^[A-Za-z0-9-]{8,64}$/.test(id)) return null;
  try {
    const inbox = await caches.open(INBOX);
    const res = await inbox.match('/__share-inbox/' + id);
    const blob = res ? await res.blob() : null;
    const count = res ? Number(res.headers.get('X-Share-Count') || '1') : 0;
    await inbox.delete('/__share-inbox/' + id);  // deleted before redaction even starts: only in memory now
    await clearInbox(true);
    if (blob && count > 1) notice(`You shared ${count} images; ZenLens redacts one at a time (the first one).`);
    return blob;
  } catch {
    await clearInbox(true);
    return null;
  }
}

async function sniff(blob) {
  const b = new Uint8Array(await blob.slice(0, 8).arrayBuffer());
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  return null;
}

/* The server takes PNG/JPEG only. WebP/HEIC/GIF (or a huge file) are re-encoded locally with a canvas. */
async function uploadable(blob) {
  const type = await sniff(blob);
  if (type && blob.size <= MAX_UPLOAD) return blob;
  let bmp;
  try { bmp = await createImageBitmap(blob); } catch {
    throw new Error('This image format cannot be opened in this browser. Try a PNG or JPEG screenshot.');
  }
  const scale = Math.min(1, 4000 / Math.max(bmp.width, bmp.height));
  const c = document.createElement('canvas');
  c.width = Math.round(bmp.width * scale); c.height = Math.round(bmp.height * scale);
  c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
  bmp.close && bmp.close();
  const out = await new Promise(r => c.toBlob(r, 'image/jpeg', 0.92));
  if (!out) throw new Error('Could not convert the image.');
  return out;
}

/* ---------- redaction (the only network call with the image) ---------- */
async function redact() {
  const my = ++runId;
  show('work');
  $('#work-msg').textContent = 'Finding sensitive text…';
  try {
    const img = await uploadable(original);
    const fd = new FormData();
    fd.append('image', img, (await sniff(img)) === 'image/png' ? 'shared.png' : 'shared.jpg');
    fd.append('faces', $('#faces').checked ? 'true' : 'false');
    const headers = {};
    const tok = store.get('token', '');
    if (tok) headers['X-ZenLens-Token'] = tok;
    const res = await fetch('/api/redact_image', { method: 'POST', body: fd, headers, cache: 'no-store',
      credentials: 'same-origin', referrerPolicy: 'no-referrer' });
    if (my !== runId) return;
    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      try { const j = await res.json(); msg = j.error || msg; } catch { /* not json */ }
      if (res.status === 401) msg = 'This phone is not paired with ZenLens yet. Open the pairing link (QR code) printed by the server once, then try again.';
      throw new Error(msg);
    }
    let boxes = [];
    try { boxes = JSON.parse(res.headers.get('X-ZenLens-Redactions') || '[]'); } catch { /* ignore */ }
    const out = await res.blob();
    if (my !== runId) return;
    if (out.type !== 'image/png' || (await sniff(out)) !== 'image/png') throw new Error('Unexpected response from the server.');
    redacted = out;
    if (urls.out) URL.revokeObjectURL(urls.out);
    urls.out = URL.createObjectURL(out);
    $('#out').src = urls.out;
    render(boxes);
    show('done');
  } catch (e) {
    if (my !== runId) return;
    fail(e && e.name === 'TypeError' ? 'Could not reach the ZenLens server. Is it running on your computer, and is this phone on the same Wi-Fi?' : (e.message || String(e)));
  }
}

function render(boxes) {
  const counts = {};
  for (const b of boxes) counts[b.kind] = (counts[b.kind] || 0) + 1;
  const total = boxes.length;
  $('#summary').textContent = total
    ? `${total} item${total === 1 ? '' : 's'} blacked out. Check the image, then share.`
    : 'Nothing sensitive was found. Check the image yourself before sharing.';
  const ul = $('#chips');
  ul.replaceChildren();
  for (const [k, n] of Object.entries(counts).sort((a, b) => b[1] - a[1])) {
    const li = document.createElement('li');
    li.dataset.k = k;
    li.textContent = `${k.toLowerCase()} × ${n}`;
    ul.append(li);
  }
  const f = shareFile();
  const canShare = !!(navigator.canShare && navigator.share && navigator.canShare({ files: [f] }));
  $('#share').textContent = canShare ? 'Share redacted' : 'Download redacted';
  $('#share-hint').textContent = canShare
    ? 'Opens your share sheet (WhatsApp, Telegram, Mail…) with the redacted copy only.'
    : 'This browser cannot share files directly, so the redacted copy is downloaded instead.';
}

/* ---------- output ---------- */
function shareFile() {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[-:T]/g, '');
  return new File([redacted || new Blob()], `zenlens-redacted-${stamp}.png`, { type: 'image/png' });
}

function download(file) {
  const a = document.createElement('a');
  const u = URL.createObjectURL(file);
  a.href = u; a.download = file.name; a.rel = 'noopener';
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(u), 10000);
}

async function shareOut() {
  if (!redacted) return;
  const file = shareFile();
  if (navigator.canShare && navigator.share && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file] }); return; } catch (e) {
      if (e && e.name === 'AbortError') return;  // user closed the sheet
    }
  }
  download(file);
}

/* ---------- hold-to-peek at the original ---------- */
function peek(on) {
  if (!original || !redacted) return;
  if (on && !urls.orig) urls.orig = URL.createObjectURL(original);
  $('#out').src = on ? urls.orig : urls.out;
  $('#out').alt = on ? 'Original image (only on this device)' : 'Redacted image';
  $('#frame').classList.toggle('peeking', on);
  $('#peek-label').hidden = !on;
  $('#peek').setAttribute('aria-pressed', String(on));
}
for (const el of [$('#frame'), $('#peek')]) {
  el.addEventListener('pointerdown', e => { e.preventDefault(); peek(true); });
  for (const ev of ['pointerup', 'pointercancel', 'pointerleave']) el.addEventListener(ev, () => peek(false));
  el.addEventListener('contextmenu', e => e.preventDefault());  // long-press menu would offer "save original"
}
$('#peek').addEventListener('keydown', e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); peek(true); } });
$('#peek').addEventListener('keyup', () => peek(false));
$('#peek').addEventListener('blur', () => peek(false));

/* ---------- wiring ---------- */
function start(blob) {
  forget();
  original = blob;
  redact();
}
function again() {
  forget();
  notice('');
  history.replaceState(null, '', '/share.html');
  show('pick');
  $('#pick-label').focus();
}

$('#pick').addEventListener('change', e => { const f = e.target.files && e.target.files[0]; if (f) start(f); });
$('#share').addEventListener('click', shareOut);
$('#again').addEventListener('click', again);
$('#err-again').addEventListener('click', again);
$('#faces').addEventListener('change', () => { if (original) redact(); });
window.addEventListener('pagehide', () => forget());  // drop the in-memory original and object URLs

const ERRORS = {
  nosw: 'ZenLens was not ready to receive that share. Open ZenLens once from your home screen, then share again, or pick the image below.',
  nofile: 'No image arrived with that share. Pick the image below.',
  read: 'The shared image could not be read. Pick it below instead.',
};

(async function init() {
  const m = location.hash.match(/token=([A-Za-z0-9_-]{8,128})/);
  if (m) store.set('token', m[1]);
  const q = new URLSearchParams(location.search);
  const id = q.get('id'), err = q.get('error');
  history.replaceState(null, '', '/share.html');  // no id/token left in the URL bar or history
  if ('serviceWorker' in navigator && window.isSecureContext) navigator.serviceWorker.register('/sw.js').catch(() => {});
  if (err) notice(ERRORS[err] || ERRORS.read);
  if (id) {
    const blob = await takeShared(id);
    if (blob) return start(blob);
    notice('That shared image is gone (originals are deleted right after use). Share it again or pick it below.');
  } else {
    await clearInbox(true);  // sweep orphaned shares (e.g. the app was closed mid-hand-over)
  }
  show('pick');
})();
