"""Structural PII detection on raw DOM HTML (stdlib html.parser, no browser, no network).

Flags elements by what they *are* (type=password, autocomplete=cc-csc, label "OTP", ...) even when
their value would slip past text regexes, then merges text detect() hits from text nodes and attributes.
API for a later Playwright capture step: scan_html(html) -> findings; sanitize_html(html) -> (html, findings).
"""
import re
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser

from .detect import detect

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
RAW = {"script", "style"}
INLINE = {"b", "i", "em", "strong", "span", "code", "small", "mark", "br", "sup", "sub", "u", "kbd", "samp"}
NO_STRUCT = {"label", "button", "h1", "h2", "h3", "h4", "h5", "h6", "title", "option", "legend", "th"}
SKIP_INPUT = {"submit", "button", "reset", "checkbox", "radio", "image", "file", "range", "color"}
TEXT_ATTRS = {"value", "placeholder", "alt", "title", "aria-label", "content", "href", "src", "data-value"}

AUTOCOMPLETE = {
    "cc-number": "CARD", "cc-csc": "CVV", "cc-exp": "CARD_EXP", "cc-exp-month": "CARD_EXP", "cc-exp-year": "CARD_EXP",
    "cc-name": "NAME", "name": "NAME", "given-name": "NAME", "family-name": "NAME",
    "one-time-code": "OTP", "current-password": "PASSWORD", "new-password": "PASSWORD",
    "email": "EMAIL", "tel": "PHONE", "tel-national": "PHONE", "street-address": "ADDRESS",
    "address-line1": "ADDRESS", "address-line2": "ADDRESS", "postal-code": "ADDRESS",
}
TYPES = {"password": "PASSWORD", "email": "EMAIL", "tel": "PHONE"}
# Keyword rules over normalised hint text (name/id/class/aria-label/placeholder/label). Order = priority.
KEYWORDS = [
    ("OTP", r"\b(?:otp|one ?time (?:code|password|pin)|verification code|2fa|totp|mfa code)\b"),
    ("CVV", r"\b(?:cvv2?|cvc2?|csc|card security|security code)\b"),
    ("PASSWORD", r"\b(?:password|passwd|passcode|pwd)\b"),
    ("PIN", r"\b(?:upi |atm )?pin\b(?! ?code)"),
    ("API_KEY", r"\b(?:api ?key|access ?key|secret ?key|private ?key)\b"),
    ("TOKEN", r"\b(?:token|bearer|session ?id|csrf|authorization)\b"),
    ("SECRET", r"\bsecret\b"),
    ("AADHAAR", r"\b(?:aadhaa?r|uidai)\b"),
    ("PAN", r"\bpan(?: number| card| no)?\b"),
    ("CARD", r"\b(?:card ?number|cc ?number|credit card|debit card)\b"),
    ("CARD_EXP", r"\b(?:expiry|expiration|exp date|cc exp|valid thru)\b"),
    ("EMAIL", r"\be ?mail\b"),
    ("PHONE", r"\b(?:phone|mobile|telephone)\b"),
    ("IP", r"\b(?:ip|ipv4|ipv6|ip address|host ip)\b"),
    ("FACE", r"\b(?:face|webcam|camera|selfie|avatar|participant|self view|video tile)\b"),
    ("NAME", r"\b(?:participant|display|full|speaker|caller|card ?holder) name\b|\bcardholder\b"),
    ("ADDRESS", r"\b(?:address|street|postal code|zip|pincode|pin code)\b"),
]
FACE_TAGS = {"img", "video", "canvas"}
# Text-only extras for values detect() has no rule for (bearer tokens, JWTs).
EXTRA = [("TOKEN", r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 1),
         ("TOKEN", r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}", 0)]
_GATE = {"NAME": r"[A-Z][\w.'-]*(?: [A-Z][\w.'-]*){0,3}", "ADDRESS": r"(?=.*\d)[^<>]{5,200}"}


@dataclass
class Finding:
    elem_id: str | None  # id of the element, or nearest ancestor with an id
    tag: str
    kind: str
    reason: str          # e.g. "autocomplete=cc-csc", "label:CVV", "text:EMAIL", "attr:value:CARD"
    value: str | None    # sensitive value if present (None for empty sensitive fields)


def _norm(s: str) -> str:
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    return " ".join(re.sub(r"[^a-z0-9]+", " ", s.lower()).split())


def _keyword(hint: str, face: bool = False):
    h = _norm(hint)
    for kind, pat in KEYWORDS:
        if (kind == "FACE") == face and (m := re.search(pat, h)):
            return kind, m.group(0)
    return None


def _spans(text: str):
    """detect() spans plus EXTRA rules, non-overlapping, as (start, end, kind)."""
    out = [(s.start, s.end, s.kind) for s in detect(text)]
    for kind, pat, g in EXTRA:
        for m in re.finditer(pat, text):
            s, e = m.span(g)
            if not any(s < b and a < e for a, b, _ in out):
                out.append((s, e, kind))
    return sorted(out)


def _redact(text: str):
    spans, out, pos = _spans(text), [], 0
    for s, e, k in spans:
        out += [text[pos:s], f"[REDACTED:{k}]"]
        pos = e
    out.append(text[pos:])
    return "".join(out), [(text[s:e], k) for s, e, k in spans]


class _El:
    __slots__ = ("tag", "attrs", "parent", "text", "block_child", "kind", "why")

    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.text, self.block_child, self.kind, self.why = [], False, None, ""

    def id(self):
        e = self
        while e and not e.attrs.get("id"):
            e = e.parent
        return e.attrs["id"] if e else None


class _Tok(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.toks, self.els, self.stack = [], [], []

    def _open(self, tag, attrs, closed):
        parent = self.stack[-1] if self.stack else None
        el = _El(tag, [(k, v or "") for k, v in attrs], parent)
        if parent and tag not in INLINE:
            parent.block_child = True
        self.els.append(el)
        self.toks.append(("start", el, self.get_starttag_text(), closed))
        if not closed and tag not in VOID:
            self.stack.append(el)

    def handle_starttag(self, tag, attrs): self._open(tag, attrs, False)
    def handle_startendtag(self, tag, attrs): self._open(tag, attrs, True)

    def handle_endtag(self, tag):
        if any(e.tag == tag for e in self.stack):
            while self.stack.pop().tag != tag:
                pass
        self.toks.append(("raw", f"</{tag}>"))

    def handle_data(self, data):
        for e in self.stack:
            e.text.append(data)
        self.toks.append(("data", self.stack[-1] if self.stack else None, data))

    def handle_comment(self, data): self.toks.append(("comment", data))
    def handle_decl(self, decl): self.toks.append(("raw", f"<!{decl}>"))
    def handle_pi(self, data): self.toks.append(("raw", f"<?{data}>"))
    def unknown_decl(self, data): self.toks.append(("raw", f"<![{data}]>"))


def _text(el): return " ".join("".join(el.text).split())


def _rule(el, lab=""):
    """(kind, reason) for one element by structure: type, autocomplete, attribute hints, label text."""
    a, tag = el.attrs, el.tag
    if tag in NO_STRUCT or tag in RAW:
        return None
    form = tag in ("input", "textarea", "select")
    typ = (a.get("type") or "text").lower()
    if tag == "input" and typ in SKIP_INPUT:
        return None
    ac = next((t for t in (a.get("autocomplete") or "").lower().split() if t in AUTOCOMPLETE), None)
    hint = " ".join(a.get(k) or "" for k in ("name", "id", "class", "aria-label", "placeholder", "data-testid", "title"))
    face = tag in FACE_TAGS
    if tag == "input" and typ == "password":
        kind, why = "PASSWORD", "type=password"
    elif ac:
        kind, why = AUTOCOMPLETE[ac], f"autocomplete={ac}"
    elif (k := _keyword(hint, face)):
        kind, why = k[0], f"attr:{k[1]}"
    elif lab and (k := _keyword(lab, face)):
        kind, why = k[0], f"label:{k[1]}"
    elif tag == "input" and typ in TYPES:
        kind, why = TYPES[typ], f"type={typ}"
    else:
        return None
    if not form and not face:
        # Plain element: only a leaf whose text looks like a single value, not a heading/container.
        t = _text(el)
        if el.block_child or not t:
            return None
        gate = _GATE.get(kind)
        if gate and not re.fullmatch(gate, t):
            return None
        if not gate and not (re.fullmatch(r"(?i)(?:bearer\s+)?\S{3,200}", t)
                             and (re.search(r"[\d\W_]", t) or len(t) >= 16)):
            return None
    return kind, why


def _classify(els):
    labels = {el.attrs["for"]: _text(el) for el in els if el.tag == "label" and el.attrs.get("for")}
    for el in els:
        lab, p = labels.get(el.attrs.get("id", ""), ""), el.parent
        while p and not lab:
            lab = _text(p) if p.tag == "label" else ""
            p = p.parent
        if (r := _rule(el, lab)):
            el.kind, el.why = r


def element_kind(e: dict) -> str | None:
    """Per-element hook for capture.py (not auto-wired; kinds differ, e.g. CVV not CARD): e has tag/type/autocomplete/field_name/placeholder/name/text/id.
    `name` is the accessible name (label text), used as the label hint."""
    attrs = {"id": e.get("id"), "type": e.get("type"), "autocomplete": e.get("autocomplete"),
             "name": e.get("field_name"), "placeholder": e.get("placeholder"), "class": e.get("class")}
    el = _El((e.get("tag") or "").lower(), [(k, v or "") for k, v in attrs.items()], None)
    el.text = [e.get("text") or ""]
    r = _rule(el, e.get("name") or "")
    return r[0] if r else None


def _flagged(el):
    while el:
        if el.kind and el.tag not in ("input", "select") and el.tag not in FACE_TAGS:
            return el
        el = el.parent
    return None


def sanitize_html(html: str) -> tuple[str, list[Finding]]:
    """Return HTML with sensitive text/attribute values replaced by [REDACTED:KIND], plus findings."""
    p = _Tok()
    p.feed(html)
    p.close()
    _classify(p.els)
    found: dict = {}

    def add(el, kind, reason, value):
        key = (el.id() if el else None, value)
        f = found.get(key)
        if f is None:
            found[key] = Finding(key[0], el.tag if el else "", kind, reason, value)
        elif reason not in f.reason:
            f.reason += f"; {reason}"

    def whole(el, text):
        """Redact a structurally sensitive value; a full-match text detection names the kind."""
        sp = _spans(text.strip())
        kind = sp[0][2] if len(sp) == 1 and sp[0][1] - sp[0][0] == len(text.strip()) else el.kind
        if sp and kind != el.kind:
            add(el, kind, f"text:{kind}", text.strip())
        add(el, kind, el.why, text.strip())
        lead, trail = text[: len(text) - len(text.lstrip())], text[len(text.rstrip()):]
        return f"{lead}[REDACTED:{kind}]{trail}"

    out = []
    for tok in p.toks:
        typ = tok[0]
        if typ == "start":
            _, el, raw, closed = tok
            attrs, changed = [], False
            if el.kind and el.tag in ("input", "select", "textarea") and not el.attrs.get("value", "").strip() \
                    and not _text(el):
                add(el, el.kind, el.why, None)
            for k, v in el.attrs.items():
                nv = v
                if v.strip() and el.kind and ((k == "value" and el.tag == "input")
                                              or (k in ("alt", "title", "aria-label") and el.tag in FACE_TAGS)):
                    nv = whole(el, v)
                elif v.strip() and (k in TEXT_ATTRS or k.startswith("data-")):
                    nv, hits = _redact(v)
                    for val, kind in hits:
                        add(el, kind, f"attr:{k}:{kind}", val)
                changed |= nv != v
                attrs.append((k, nv))
            if el.kind and el.tag in FACE_TAGS and not any(el.attrs.get(k) for k in ("alt", "title", "aria-label")):
                add(el, el.kind, el.why, None)
            if changed:
                body = "".join(f' {k}="{escape(v)}"' for k, v in attrs)
                raw = f"<{el.tag}{body}{' /' if closed else ''}>"
            out.append(raw)
        elif typ == "data":
            _, el, data = tok
            raw_ctx = el is not None and el.tag in RAW
            fl = None if raw_ctx else _flagged(el)
            if fl and data.strip():  # text inside a structurally sensitive element: redact whole
                new = whole(fl, data)
            else:
                new, hits = _redact(data)
                for val, kind in hits:
                    add(el, kind, f"text:{kind}", val)
            out.append(new if raw_ctx else escape(new, quote=False))
        elif typ == "comment":
            new, hits = _redact(tok[1])
            for val, kind in hits:
                add(None, kind, f"comment:{kind}", val)
            out.append(f"<!--{new}-->")
        else:
            out.append(tok[1])
    return "".join(out), list(found.values())


def scan_html(html: str) -> list[Finding]:
    """Findings only (element id, kind, reason, value). Never sends anything anywhere."""
    return sanitize_html(html)[1]
