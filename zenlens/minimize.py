"""Data minimisation AFTER detection/redaction: remove context that lets a model infer a redacted value.

Redaction hides the value; minimisation hides the clues around it. Opt-in, local, deterministic.
  minimize(text)       -> (text, notes)
  minimize_view(view)  -> (view, notes)   view = dict from capture.sanitized_view (not mutated)
Rules (each change adds a note {rule, reason[, where]}; notes never contain values):
  hint          password hints / memorable words / security answers removed
  masked_email  a***@example.com -> ***@example.com (domain kept: it is usually the site itself)
  masked_number 98XXXXX210, XXXX XXXX 1234, 4532 01•• •••• 0766 -> [MASKED]
  partial_value "ending 4242", "last 4 digits 1234" -> "ending [MASKED]"
  dob           labelled date of birth -> birth year
  age           exact age (Age: 34, 34-year-old) -> 10-year band (30-39)
  pin_code      labelled / city-anchored 6-digit PIN -> first 3 digits (sorting district) + xxx
  ifsc          IFSC (with IFSC/branch/bank context) -> bank code only (branch codes can prefix accounts)
  echo          numbers shaped like a redacted value on the same page (OTP 4-8, phone 10, card 13-19 Luhn,
                Aadhaar 12 Verhoeff) in titles/URLs/alt/aria/filenames/identifiers; checksum-valid card/Aadhaar
                runs glued into identifiers (statement_<card>.pdf) are masked even without a redaction
  name          name after an explicit label (Signed in as / Welcome / Account holder ...) -> [NAME]
  username_slug when an email is redacted: user.name-shaped tokens in URL paths, titles, alt/aria -> [MASKED]
Redaction markers ([REDACTED:KIND]) and pseudonym tokens ([EMAIL_1]) are never modified.
Not covered (by design, conservative): unlabelled names, free-text paraphrases, precise timestamps.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import urlsplit, urlunsplit

from .detect import luhn_ok, verhoeff_ok

MASK = "[MASKED]"
_MARKER = re.compile(r"\[REDACTED:([A-Z][A-Z0-9_]*)\]|\[([A-Z][A-Z0-9_]*?)_[1-9]\d{0,5}(?: [a-z]{2,12})?\]")
_ECHO_KINDS = {"OTP", "PHONE", "CARD", "AADHAAR", "EMAIL", "BANK_ACCOUNT"}
_MONTHS = "jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec"
CITIES = ("Pune", "Mumbai", "New Delhi", "Delhi", "Bengaluru", "Bangalore", "Chennai", "Hyderabad", "Kolkata",
          "Kochi", "Nashik", "Jaipur", "Ahmedabad", "Lucknow", "Indore", "Chandigarh", "Bhopal", "Nagpur", "Surat",
          "Coimbatore")
_EXT = r"(?:com|in|org|net|io|co|dev|app|html?|css|js|png|jpe?g|gif|svg|pdf|json|txt|csv|xml|php|aspx)"


def redacted_kinds(text: str) -> set[str]:
    """Kinds visible as [REDACTED:KIND] or pseudonym tokens [KIND_N] in text."""
    return {m.group(1) or m.group(2) for m in _MARKER.finditer(text)}


def _protect(text: str) -> tuple[str, list[str]]:
    """Swap markers for inert placeholders so no rule can touch them."""
    saved: list[str] = []

    def keep(m):
        saved.append(m.group(0))
        return f"\x00{len(saved) - 1}\x00"
    return _MARKER.sub(keep, text), saved


def _restore(text: str, saved: list[str]) -> str:
    return re.sub(r"\x00(\d+)\x00", lambda m: saved[int(m.group(1))], text)


class _Ctx:
    def __init__(self, kinds: set[str], context: bool):
        self.kinds, self.context, self.notes = kinds, context, []

    def sub(self, pat, repl, text, rule, reason, flags=0):
        out, n = re.subn(pat, repl, text, flags=flags)
        if n:
            self.notes.append({"rule": rule, "reason": reason, "count": n})
        return out


def _hint(t, c):
    return c.sub(r"(?i)\b((?:password\s+)?hint|memorable\s+(?:word|answer|information)|security\s+answer)"
                 r"(\s*(?:[:\-–]|\bis\b)\s*)(?:[^\n;|.]|\.(?=\S))+",
                 r"\1\2[REMOVED]", t, "hint", "password hint or memorable answer removed")


def _masked_email(t, c):
    t = c.sub(r"(?<![\w.+-])[\w.+-]*\*+[\w.+-]*(?=\x00\d+\x00)", "***", t, "masked_email",
              "visible characters before a redacted email removed")
    return c.sub(r"(?<![\w.+-])[\w.+-]*\*[\w.*+-]*(@[\w-]+(?:\.[\w-]+)+)", r"***\1", t, "masked_email",
                 "visible characters of a masked email removed")


def _masked_number(t, c):
    def repl(m):
        tok = re.sub(r"[ \-]", "", m.group(0))
        masks = len(re.findall(r"[X*•●]|x{2,}", tok))
        digits = sum(ch.isdigit() for ch in tok)
        return MASK if masks and digits and len(tok) >= 7 else m.group(0)
    out = re.sub(r"(?<![\w*•●])[0-9X*•●x](?:[ \-]?[0-9X*•●x])+(?![\w*•●])", repl, t)
    if out != t:
        c.notes.append({"rule": "masked_number", "reason": "partially masked number dropped (visible digits leak)",
                        "count": out.count(MASK) - t.count(MASK)})
    return out


def _partial(t, c):
    return c.sub(r"(?i)\b(ending(?:\s+(?:in|with))?|ends?\s+(?:in|with)|last\s+(?:4|four)(?:\s+digits)?"
                 r"(?:\s+(?:are|is))?)(\s*[:\-]?\s*)\d{2,6}\b", rf"\1\2{MASK}", t, "partial_value",
                 "trailing digits of a sensitive number removed")


_DOB_LAB = r"(?i:\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)\s*[:\-]?\s*)"


def _dob(t, c):
    pats = [rf"({_DOB_LAB})\d{{1,2}}[/\-. ]\d{{1,2}}[/\-. ](\d{{4}})\b",
            rf"({_DOB_LAB})(\d{{4}})-\d{{2}}-\d{{2}}\b",
            rf"({_DOB_LAB})\d{{1,2}}(?:st|nd|rd|th)? (?i:{_MONTHS})[a-z]*\.?,? (\d{{4}})\b",
            rf"({_DOB_LAB})(?i:{_MONTHS})[a-z]* \d{{1,2}}(?:st|nd|rd|th)?,? (\d{{4}})\b"]
    for p in pats:
        t = c.sub(p, r"\1\2", t, "dob", "date of birth generalised to year")
    return t


def _band(m, g):
    a = int(m.group(g))
    return f"{a // 10 * 10}-{a // 10 * 10 + 9}"


def _age(t, c):
    n0 = len(c.notes)
    out = re.sub(r"(?i)\b(age[d]?\s*[:\-]?\s*)(\d{1,3})\b(?!\s*-\d)", lambda m: m.group(1) + _band(m, 2), t)
    out = re.sub(r"(?i)\b(\d{1,3})([- ]?(?:years?|yrs?)[- ]old)\b", lambda m: _band(m, 1) + m.group(2), out)
    out = re.sub(r"(?i)\b(\d{1,3})(\s*y/o)\b", lambda m: _band(m, 1) + m.group(2), out)
    if out != t and len(c.notes) == n0:
        c.notes.append({"rule": "age", "reason": "exact age generalised to a 10-year band", "count": 1})
    return out


def _pin(t, c):
    t = c.sub(r"(?i)\b(pin\s*code|pincode|postal\s*code|zip(?:\s*code)?|pin)(\s*[:\-]?\s*)([1-9]\d{2})\s?\d{3}\b",
              r"\1\2\3xxx", t, "pin_code", "PIN code generalised to sorting district")
    cities = "|".join(re.escape(x) for x in CITIES)
    return c.sub(rf"\b({cities})(\s*[,\-–]?\s*)([1-9]\d{{2}})\s?\d{{3}}\b", r"\1\2\3xxx", t, "pin_code",
                 "PIN code generalised to sorting district")


def _ifsc(t, c):
    # only with IFSC/branch/bank context: bare 4-letters+0+6 tokens are often SKUs / part numbers
    return c.sub(r"((?i:\b(?:ifsc|branch|bank)\b)[^\n]{0,24}?)\b([A-Z]{4})0[A-Z0-9]{6}\b", r"\1\g<2>0xxxxxx", t,
                 "ifsc", "IFSC branch code generalised to bank")


def _echo(t, c):
    notes = []

    def repl(m):
        s, d = m.group(0), re.sub(r"\D", "", m.group(0))
        st, en = m.span()
        before, after = t[st - 1:st], t[en:en + 1]
        glued = bool(re.match(r"[A-Za-z_]", before) or re.match(r"[A-Za-z_]", after)
                     or (before == "-" and re.match(r"[A-Za-z]", t[st - 2:st - 1] or " ")))
        tok_s = t.rfind(" ", 0, st) + 1
        tok_e = t.find(" ", en)
        tok = t[tok_s:len(t) if tok_e < 0 else tok_e]
        ident = glued or bool(re.search(r"[/_=]|\.[A-Za-z]\w{1,3}$", tok))  # ".00" in ₹18,499.00 is not a file ext
        where = c.context or ident
        # OTP echoes live in URLs/query strings or metadata; ticket-style IDs (TKT-20431, SR-77120-B) are not echoes.
        otp_where = c.context or bool(re.search(r"[/=?&_]", tok))
        n, k = len(d), c.kinds
        kind = None
        if 13 <= n <= 19 and luhn_ok(d) and (glued or c.context or "CARD" in k):
            kind = "CARD"
        elif n == 12 and d[0] in "23456789" and verhoeff_ok(d) and (glued or c.context or "AADHAAR" in k):
            kind = "AADHAAR"
        elif "PHONE" in k and where and ((n == 10 and d[0] in "6789") or (n == 12 and d[:2] == "91" and d[2] in "6789")):
            kind = "PHONE"
        elif "OTP" in k and otp_where and 4 <= n <= 8 and not (n == 4 and 1900 <= int(d) <= 2099):
            kind = "OTP"
        elif "BANK_ACCOUNT" in k and where and 9 <= n <= 18:
            kind = "BANK_ACCOUNT"
        if not kind:
            return s
        notes.append(kind)
        return MASK
    out = re.sub(r"(?<!\d)\d(?:[ .\-]?\d)*(?!\d)", repl, t)
    for kind in sorted(set(notes)):
        c.notes.append({"rule": "echo", "reason": f"number shaped like a {kind} in a title/URL/label/identifier",
                        "count": notes.count(kind)})
    return out


def _name(t, c):
    return c.sub(r"\b(Signed in as|Logged in as|Welcome(?: back)?,?|Hi,?|Hello,?|Account holder:?|Cardholder:?|"
                 r"Name:)(\s+)[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b", r"\1\2[NAME]", t, "name",
                 "labelled person name removed (can rebuild email usernames)")


def _slug(t, c):
    if "EMAIL" not in c.kinds or not c.context:
        return t
    def repl(m):
        return m.group(0) if re.search(rf"\.{_EXT}$", m.group(1)) else MASK
    out = re.sub(r"(?<![\w.@])([a-z]+(?:[._][a-z]+){1,2})\d*(?![\w@])", repl, t)
    if out != t:
        c.notes.append({"rule": "username_slug", "reason": "username-shaped token near a redacted email removed",
                        "count": 1})
    return out


_RULES = (_hint, _masked_email, _masked_number, _partial, _dob, _age, _pin, _ifsc, _echo, _name, _slug)


def minimize(text: str, kinds: set[str] | None = None, context: bool = False) -> tuple[str, list[dict]]:
    """Minimise one string. kinds: redacted kinds present on the page (default: markers found in text).
    context=True for metadata fields (title, URL path, alt/aria, placeholder, field name)."""
    if not text:
        return text, []
    c = _Ctx(set(redacted_kinds(text)) if kinds is None else set(kinds), context)
    t, saved = _protect(text)
    for rule in _RULES:
        t = rule(t, c)
    return _restore(t, saved), c.notes


def _view_kinds(view: dict) -> set[str]:
    kinds = redacted_kinds(str(view.get("title") or "") + " " + str(view.get("url") or ""))
    for el in view.get("elements", []):
        if el.get("sensitive"):
            kinds.add(str(el["sensitive"]))
        for k in ("name", "text", "value", "placeholder", "field_name"):
            if isinstance(el.get(k), str):
                kinds |= redacted_kinds(el[k])
    return kinds


def minimize_view(view: dict, kinds: set[str] | None = None) -> tuple[dict, list[dict]]:
    """Minimise every model-visible string of a sanitized view. Returns a new view; the input is untouched."""
    kinds = _view_kinds(view) if kinds is None else set(kinds)
    out, notes = copy.deepcopy(view), []

    def run(s, where, ctx):
        res, n = minimize(s, kinds, ctx)
        notes.extend({**x, "where": where} for x in n)
        return res
    if isinstance(out.get("url"), str) and out["url"]:
        u = urlsplit(out["url"])
        out["url"] = urlunsplit((u.scheme, u.netloc, run(u.path, "url", True), u.query, u.fragment))
    if isinstance(out.get("title"), str):
        out["title"] = run(out["title"], "title", True)
    for el in out.get("elements", []):
        for k in ("name", "text", "value", "placeholder", "field_name"):
            if isinstance(el.get(k), str) and el[k]:
                el[k] = run(el[k], f"{el.get('id')}.{k}", k in ("name", "placeholder", "field_name"))
    return out, notes
