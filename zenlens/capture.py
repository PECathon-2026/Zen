"""Playwright capture: page -> element list + DOM + screenshot (all local). Only `sanitized_view` may leave."""
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .gate import egress_check
from .sanitize import redact

try:  # optional structural (DOM-attribute) detector; capture still works without it
    from . import structural as _structural
except Exception:  # missing or broken -> text redaction only
    _structural = None

_INSTALL = "playwright not available: run `.venv/bin/pip install playwright && .venv/bin/python -m playwright install chromium`"
ATTR = "data-zl-id"

# Walks the DOM in document order; tags each kept element with data-zl-id so ids are stable for the same DOM.
_EXTRACT_JS = r"""
(attr) => {
  const INTERACTIVE = 'a[href],button,input,select,textarea,summary,[role],[contenteditable=""],[contenteditable="true"],[tabindex]';
  const own = el => Array.from(el.childNodes).filter(n => n.nodeType === 3).map(n => n.textContent).join(' ').replace(/\s+/g, ' ').trim();
  const visible = el => {
    if (el.type === 'hidden') return false;
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    return s.visibility !== 'hidden' && s.display !== 'none' && r.width > 0 && r.height > 0;
  };
  const labelOf = el => {
    const t = s => (s || '').replace(/\s+/g, ' ').trim();
    if (el.getAttribute('aria-label')) return t(el.getAttribute('aria-label'));
    const lb = el.getAttribute('aria-labelledby');
    if (lb) return t(lb.split(/\s+/).map(i => (document.getElementById(i) || {}).textContent || '').join(' '));
    if (el.labels && el.labels.length) return t(Array.from(el.labels).map(l => l.textContent).join(' '));
    return t(el.getAttribute('alt') || el.getAttribute('title') || '');
  };
  const ROLE = {A: 'link', BUTTON: 'button', SELECT: 'combobox', TEXTAREA: 'textbox', H1: 'heading', H2: 'heading',
    H3: 'heading', H4: 'heading', H5: 'heading', H6: 'heading', IMG: 'img', LABEL: 'label', LI: 'listitem'};
  const inputRole = t => ({checkbox: 'checkbox', radio: 'radio', submit: 'button', button: 'button', reset: 'button',
    range: 'slider', search: 'searchbox'})[t] || 'textbox';
  document.querySelectorAll('[' + attr + ']').forEach(e => e.removeAttribute(attr));
  const out = []; let n = 0;
  for (const el of document.body ? document.body.querySelectorAll('*') : []) {
    if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'OPTION'].includes(el.tagName)) continue;
    const inter = el.matches(INTERACTIVE), text = own(el);
    if (!(inter || text) || !visible(el)) continue;
    const id = 'e' + (++n); el.setAttribute(attr, id);
    const r = el.getBoundingClientRect(), tag = el.tagName.toLowerCase();
    let value = null;
    if (tag === 'input') value = ['checkbox', 'radio'].includes(el.type) ? String(el.checked) : el.value;
    else if (tag === 'textarea') value = el.value;
    else if (tag === 'select') value = el.selectedOptions.length ? el.selectedOptions[0].textContent.trim() : '';
    out.push({id, tag,
      role: el.getAttribute('role') || (tag === 'input' ? inputRole(el.type) : ROLE[el.tagName] || 'text'),
      name: labelOf(el), text: inter && tag !== 'select' ? (el.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 300) : text.slice(0, 300),
      type: tag === 'input' || tag === 'button' ? el.type : null, autocomplete: el.getAttribute('autocomplete'),
      field_name: el.getAttribute('name'), dom_id: el.id || null, cls: el.getAttribute('class'), placeholder: el.getAttribute('placeholder'), value,
      bbox: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]});
  }
  return out;
}
"""


@dataclass
class Element:
    id: str
    tag: str
    role: str
    name: str = ""
    text: str = ""
    type: str | None = None
    autocomplete: str | None = None
    field_name: str | None = None
    placeholder: str | None = None
    dom_id: str | None = None  # local-only hints for structural detection; never put in the view
    cls: str | None = None
    value: str | None = field(default=None, repr=False)
    bbox: list[int] = field(default_factory=list)


@dataclass
class PageSnapshot:
    """Raw local capture. Contains real values: never log, never send. Use `sanitized_view` for egress."""
    url: str
    title: str = field(repr=False)
    elements: list[Element] = field(repr=False)
    html: str = field(repr=False)
    screenshot: bytes = field(repr=False)
    page: object = field(default=None, repr=False)  # live Playwright Page when captured in a Session

    def selector_for(self, eid: str) -> str:
        if not any(e.id == eid for e in self.elements):
            raise KeyError(f"unknown element id: {eid}")
        return f'[{ATTR}="{eid}"]'

    def locator_for(self, eid: str):
        """Local-only: element id -> Playwright Locator on the live page."""
        sel = self.selector_for(eid)
        if self.page is None:
            raise RuntimeError("snapshot has no live page; capture inside a Session to act on elements")
        return self.page.locator(sel)


def _sync_playwright():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise ImportError(_INSTALL) from e
    return sync_playwright


def to_url(target: str) -> str:
    if re.match(r"^[a-z][a-z0-9+.-]*://", target, re.I) or target.startswith(("about:", "data:")):
        return target
    p = Path(target).expanduser()
    if not p.exists():
        raise FileNotFoundError(target)
    return p.resolve().as_uri()


def snapshot_page(page) -> PageSnapshot:
    """Capture the current state of a live Playwright page (ids re-assigned in document order)."""
    raw = page.evaluate(_EXTRACT_JS, ATTR)
    return PageSnapshot(url=page.url, title=page.title(), elements=[Element(**r) for r in raw],
                        html=page.content(), screenshot=page.screenshot(full_page=True), page=page)


class Session:
    """Keeps a headless Chromium page open so ids from a snapshot can be acted on later."""

    def __init__(self, headless: bool = True):
        self.headless = headless

    def __enter__(self):
        self._pw = _sync_playwright()().start()
        self.browser = self._pw.chromium.launch(headless=self.headless)
        self.page = self.browser.new_page(viewport={"width": 1280, "height": 900})
        return self

    def __exit__(self, *exc):
        self.browser.close()
        self._pw.stop()

    def goto(self, target: str) -> PageSnapshot:
        self.page.goto(to_url(target), wait_until="load")
        return snapshot_page(self.page)

    def capture(self) -> PageSnapshot:
        return snapshot_page(self.page)


def capture(target: str) -> PageSnapshot:
    """One-shot: open target (URL or local path), snapshot, close. Returned snapshot has no live page."""
    with Session() as s:
        snap = s.goto(target)
    snap.page = None
    return snap


# Inputs whose value is always redacted, whatever it looks like.
_SENSITIVE_AC = {"current-password": "PASSWORD", "new-password": "PASSWORD", "one-time-code": "OTP",
                 "cc-number": "CARD", "cc-csc": "CARD", "cc-exp": "CARD", "cc-exp-month": "CARD", "cc-exp-year": "CARD"}
_SENSITIVE_HINT = [("PASSWORD", r"pass(word|code)|\bpwd\b|\bpin\b"), ("OTP", r"\botp\b|one[- ]time|verification code"),
                   ("CARD", r"\bcvv\b|\bcvc\b|\bcsc\b|card ?(number|no)|security code|expiry|\bexp\b"),
                   ("API_KEY", r"api[ _-]?key|secret|token")]


def sensitive_kind(e: Element) -> str | None:
    if e.type == "password":
        return "PASSWORD"
    if (e.autocomplete or "").split()[-1:] and (k := _SENSITIVE_AC.get(e.autocomplete.split()[-1])):
        return k
    hint = " ".join(filter(None, [e.name, e.field_name, e.placeholder])).lower()
    for kind, pat in _SENSITIVE_HINT:
        if re.search(pat, hint):
            return kind
    return None


def _clean(s: str | None) -> str | None:
    if s is None:
        return None
    # trailing ':' dropped so "Password:" next to JSON punctuation cannot look like "password: <value>"
    return redact(s.rstrip().rstrip(":").rstrip())[0]


def _clean_url(url: str) -> str:
    u = urlsplit(url)
    if u.scheme == "file":
        return "file:///" + _clean(Path(u.path).name)  # local paths may contain usernames
    return _clean(urlunsplit((u.scheme, u.netloc, u.path, "", "")))  # query/fragment often carry tokens


def _structural_kinds(snap: PageSnapshot) -> dict[str, str]:
    """id -> kind from zenlens.structural.element_kind if available; else {} (text redaction still applies)."""
    fn = getattr(_structural, "element_kind", None) if _structural else None
    out = {}
    for e in snap.elements if fn else ():
        try:
            k = fn({"id": e.dom_id, "class": e.cls, "tag": e.tag, "type": e.type, "autocomplete": e.autocomplete,
                    "field_name": e.field_name, "placeholder": e.placeholder, "name": e.name, "text": e.text})
        except Exception:
            k = None
        if k:
            out[e.id] = str(k)
    return out


def sanitized_view(snap: PageSnapshot, canaries: tuple[str, ...] = ()) -> dict:
    """The ONLY capture output meant to leave the machine. No HTML, no screenshot. Raises gate.Blocked on residue."""
    forced = _structural_kinds(snap)
    els = []
    for e in snap.elements:
        kind = forced.get(e.id) or sensitive_kind(e)
        if e.value in (None, ""):
            value = e.value
        elif kind:
            value = f"[REDACTED:{kind}]"
        else:
            value = _clean(e.value)
        text = _clean(e.text)
        if kind and (e.tag in ("input", "textarea", "select") or e.id in forced):  # structural flags only value-like leaves
            text = f"[REDACTED:{kind}]" if e.text else e.text
        els.append({"id": e.id, "tag": e.tag, "role": e.role, "type": e.type, "autocomplete": e.autocomplete,
                    "bbox": e.bbox, "sensitive": kind, "field_name": _clean(e.field_name),
                    "placeholder": _clean(e.placeholder), "name": _clean(e.name), "text": text, "value": value})
    view = {"url": _clean_url(snap.url), "title": _clean(snap.title), "elements": els}
    egress_check(json.dumps(view, ensure_ascii=False), canaries)
    return view
