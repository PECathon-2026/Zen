"""Attackers for the inference benchmark. They see ONLY a sanitized view (what would leave the machine).

OfflineAttacker  deterministic, rule-based, always runs. Emits hypotheses per target; `assess` scores them.
ClaudeAttacker   asks a real model to guess each hidden value from the same view. Only usable when
                 ANTHROPIC_API_KEY is set; every outbound payload goes through egress_check (fail closed).

Threat model / scoring (pessimistic for the defender):
- The attacker knows each target's kind and length (public format knowledge: cards 16, Aadhaar 12, ...).
- Leaked bits = prior_bits - bits_left. A digit target is `recovered` when exactly one candidate remains,
  `narrowed` when >= 1 bit was gained. The attacker enumerates a few hypotheses (single partials and their
  compatible merges); the scorer keeps the best one consistent with the truth, i.e. a small oracle advantage
  (log2 of the hypothesis count) in the attacker's favour.
- EMAIL: the domain is treated as public (it is usually the site you are on); only the local part counts.
- IDENTITY (quasi-identifiers): bits from location + birth time + gender against a population of 1.4e9;
  `reidentified` when the anonymity set falls below K_ANON. Narrowing alone is not counted as a leak for
  identities (any profile page narrows a little), only re-identification.
"""
from __future__ import annotations

import itertools
import json
import os
import re
from dataclasses import dataclass, field
from math import log2

from zenlens.detect import luhn_ok, verhoeff_check_digit, verhoeff_ok
from zenlens.gate import egress_check

# ---- synthetic "world knowledge" an attacker is assumed to have (shared with make_scenarios) ----
POPULATION = 1.4e9
K_ANON = 20
CITIES = {"Pune": 7.0e6, "Bengaluru": 13.0e6, "Kochi": 2.1e6, "Nashik": 2.0e6, "Jaipur": 4.0e6}
CITY_PIN3 = {"Pune": "411", "Bengaluru": "560", "Kochi": "682", "Nashik": "422", "Jaipur": "302"}
EMPLOYERS = {"Kestrel Labs": ("Pune", 800), "Orchid Analytics": ("Bengaluru", 650),
             "Banyan Robotics": ("Kochi", 420)}  # synthetic companies with public headcounts
BANK = "ZENB"  # synthetic bank: account numbers start with the last 4 digits of the branch's IFSC
BANK_PREFIX = 4
N_PIN6, N_PIN3, BIRTH_YEARS, WORKING_AGES = 19300, 450, 80, 40

LOG2_10 = log2(10)
DIGIT_KINDS = {"CARD", "AADHAAR", "PHONE", "OTP", "ACCOUNT"}
CHECKSUM = {"CARD": luhn_ok, "AADHAAR": verhoeff_ok}
_MONTHS = "jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec"


def prior_bits(secret: dict) -> float:
    k, v = secret["kind"], secret["value"]
    if k in DIGIT_KINDS:
        return len(v) * LOG2_10 - (LOG2_10 if k in CHECKSUM else 0)
    if k == "EMAIL":
        return len(v.split("@")[0]) * log2(37)
    if k == "PASSWORD":
        return len(v) * log2(94)
    if k == "IDENTITY":
        return log2(POPULATION)
    raise ValueError(f"unknown kind {k}")


def targets_of(scenario: dict) -> list[dict]:
    """What the attacker is told: kind + length only (never the value)."""
    return [{"kind": s["kind"], "length": len(s["value"]) if s["kind"] in DIGIT_KINDS else None,
             "label": s.get("label", s["kind"].lower())} for s in scenario["secrets"]]


@dataclass
class Hypothesis:
    target: int
    rules: tuple[str, ...]
    known: dict[int, str] | None = None      # digit position -> digit
    candidates: tuple[str, ...] | None = None  # full values (EMAIL: local parts)
    pattern: str | None = None                # regex the truth must fullmatch (EMAIL partials)
    bits_gained: float = 0.0
    identity_bits: float | None = None
    value: str | None = None                  # concrete exact claim, if any


# ------------------------------------------------------------------ view -> fields
def view_fields(view: dict) -> list[tuple[str, str, bool]]:
    """(where, text, is_context) for every string the model would see."""
    out = [("url", view.get("url") or "", True), ("title", view.get("title") or "", True)]
    for el in view.get("elements", []):
        for k in ("name", "text", "value", "placeholder", "field_name"):
            v = el.get(k)
            if isinstance(v, str) and v:
                out.append((f"{el.get('id')}.{k}", v, k in ("name", "placeholder", "field_name")))
    return out


_MASKED = re.compile(r"(?<![\w*•●])[0-9Xx*•●#](?:[ \-]?[0-9Xx*•●#])+(?![\w*•●])")
_ENDING = re.compile(r"(?i)\b(?:ending(?:\s+(?:in|with))?|ends?\s+(?:in|with)|last\s+(?:4|four)(?:\s+digits)?"
                     r"(?:\s+(?:are|is))?)\s*[:\-]?\s*(\d{2,6})\b")
_GROUPS = re.compile(r"(?<!\d)\d(?:[ .\-]?\d)*(?!\d)")
_IFSC = re.compile(r"\b([A-Z]{4})0(\d{6})\b")
_EMAIL_PARTIAL = re.compile(r"(?<![\w.+-])([\w.+-]*)\*+([\w.+-]*)@[\w-]+(?:\.[\w-]+)+")
_EMAIL_HEAD = re.compile(r"(?<![\w.+-])([\w.+-]+)\*+\[REDACTED:EMAIL\]")  # tail already redacted by detect
_NAME_LABEL = re.compile(r"(?:Signed in as|Logged in as|Welcome(?: back)?,?|Hi,?|Hello,?|Account holder:?|"
                         r"Cardholder:?|Name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})")
_BIGRAM = re.compile(r"\b([A-Z][a-z]{2,})\s+([A-Z][a-z]{2,})\b")
_SLUG = re.compile(r"(?<![\w.])([a-z]+(?:[._][a-z]+){1,2})\d*(?![\w])")


def _digit_partials(text: str) -> list[tuple[str, str]]:
    """(normalized, how) with '?' for masked positions; how in {'mask','suffix'}."""
    out = []
    for m in _MASKED.finditer(text):
        tok = re.sub(r"[ \-]", "", m.group(0))
        if any(c.isdigit() for c in tok) and any(not c.isdigit() for c in tok):
            out.append(("".join(c if c.isdigit() else "?" for c in tok), "mask"))
    for m in _ENDING.finditer(text):
        out.append(("?" + m.group(1), "suffix"))
    return out


def _align(norm: str, n: int) -> dict[int, str] | None:
    if len(norm) > n and norm[:len(norm) - n].isdigit() and len(norm) - n <= 3:  # +91 / country-code prefix
        norm = norm[len(norm) - n:]
    if len(norm) == n:
        pos = range(n)
    elif len(norm) < n and norm[-1].isdigit():
        pos = range(n - len(norm), n)
    elif len(norm) < n and norm[0].isdigit():
        pos = range(len(norm))
    else:
        return None
    known = {p: c for p, c in zip(pos, norm) if c != "?"}
    return known or None


def _complete(kind: str, n: int, known: dict[int, str]) -> str | None:
    free = [i for i in range(n) if i not in known]
    if not free:
        return "".join(known[i] for i in range(n))
    if len(free) == 1 and kind in CHECKSUM:
        for d in "0123456789":
            v = "".join(known.get(i, d) for i in range(n))
            if CHECKSUM[kind](v):
                return v
    return None


def _name_locals(first: str, last: str) -> set[str]:
    f, l_ = first.lower(), last.lower()
    return {f"{f}.{l_}", f"{f}{l_}", f"{f}_{l_}", f"{f[0]}.{l_}", f"{f[0]}{l_}", f, f"{l_}.{f}", f"{f}{l_[0]}"}


def _parse_identity(text: str) -> tuple[float, list[str]]:
    """Bits of identifying information from quasi-identifiers in `text`, plus which attributes fired."""
    t, attrs = text, []
    loc = 0.0
    emp = [e for e in EMPLOYERS if e in t]
    if emp:
        loc = max(loc, log2(POPULATION / EMPLOYERS[emp[0]][1])); attrs.append("employer")
    pin_lab = r"(?i:\b(?:pin\s*code|pincode|postal\s*code|zip|pin)\s*[:\-]?\s*)"
    cities = "|".join(CITIES)
    if re.search(pin_lab + r"[1-9]\d{2}\s?\d{3}\b", t) or re.search(rf"\b(?:{cities})\s*[,\-–]?\s*[1-9]\d{{2}}\s?\d{{3}}\b", t):
        loc = max(loc, log2(N_PIN6)); attrs.append("pin6")
    elif re.search(pin_lab + r"[1-9]\d{2}(?:x{3}|\b)", t) or re.search(rf"\b(?:{cities})\s*[,\-–]?\s*[1-9]\d{{2}}x{{3}}", t):
        loc = max(loc, log2(N_PIN3)); attrs.append("pin3")
    city = [c for c in CITIES if re.search(rf"\b{c}\b", t)]
    if city:
        loc = max(loc, log2(POPULATION / CITIES[city[0]])); attrs.append("city")
    tm = 0.0
    dob_lab = r"(?i:\b(?:dob|d\.o\.b\.?|date of birth|birth ?date|born(?: on)?)\s*[:\-]?\s*)"
    full = (rf"(?:\d{{1,2}}[/\-. ]\d{{1,2}}[/\-. ]\d{{4}}|\d{{4}}-\d{{2}}-\d{{2}}|\d{{1,2}}(?:st|nd|rd|th)? (?i:{_MONTHS})[a-z]*\.?,? \d{{4}}"
            rf"|(?i:{_MONTHS})[a-z]* \d{{1,2}}(?:st|nd|rd|th)?,? \d{{4}})")
    if re.search(dob_lab + full, t):
        tm = log2(365.25 * BIRTH_YEARS); attrs.append("dob")
    elif re.search(dob_lab + r"(?:19|20)\d{2}\b", t):
        tm = log2(BIRTH_YEARS); attrs.append("birth_year")
    age_exact = re.search(r"(?i)(?<!\d-)\bage[d]?\s*[:\-]?\s*\d{1,3}\b(?!\s*-)|(?<!\d-)\b\d{1,3}[- ]?(?:years?|yrs?)[- ]old\b|(?<!\d-)\b\d{1,3}\s*y/o\b", t)
    age_band = re.search(r"(?i)\b(?:age[d]?\s*[:\-]?\s*)?\d0-\d9\b", t)
    if age_exact:
        tm = max(tm, log2(WORKING_AGES if emp else BIRTH_YEARS)); attrs.append("age")
    elif age_band:
        tm = max(tm, log2(WORKING_AGES / 10 if emp else BIRTH_YEARS / 10)); attrs.append("age_band")
    g = 1.0 if re.search(r"(?i)\b(?:gender|sex)\s*[:\-]?\s*(?:male|female|m|f)\b|\b(?:Male|Female)\b", t) else 0.0
    if g:
        attrs.append("gender")
    return loc + tm + g, attrs


# ------------------------------------------------------------------ offline attacker
class OfflineAttacker:
    name = "offline"

    def attack(self, view: dict, targets: list[dict]) -> list[Hypothesis]:
        fields = view_fields(view)
        hyps: list[Hypothesis] = []
        alltext = "\n".join(t for _, t, _ in fields)
        partials = [(p, how) for _, t, _ in fields for p, how in _digit_partials(t)]
        groups = [re.sub(r"\D", "", m.group(0)) for _, t, _ in fields for m in _GROUPS.finditer(t)]
        url = view.get("url") or ""
        path = re.sub(r"^[a-z]+://[^/]*", "", url)
        for ti, tg in enumerate(targets):
            k, n = tg["kind"], tg["length"]
            if k in DIGIT_KINDS:
                hyps += self._digits(ti, k, n, partials, groups, fields)
            elif k == "EMAIL":
                hyps += self._email(ti, fields, path)
            elif k == "PASSWORD":
                hyps += self._password(ti, alltext)
            elif k == "IDENTITY":
                bits, attrs = _parse_identity(alltext)
                if attrs:
                    hyps.append(Hypothesis(ti, tuple(f"quasi:{a}" for a in attrs), identity_bits=bits))
        return hyps

    def _digits(self, ti, k, n, partials, groups, fields):
        out: list[Hypothesis] = []
        knowns = []
        for norm, how in partials:
            kn = _align(norm, n)
            if kn:
                knowns.append((kn, f"partial:{how}"))
        if k == "ACCOUNT":
            for _, t, _ in fields:
                for m in _IFSC.finditer(t):
                    if m.group(1) == BANK:
                        br = m.group(2)[-BANK_PREFIX:]
                        knowns.append(({i: c for i, c in enumerate(br)}, "quasi:ifsc_branch"))
        knowns = knowns[:8]
        for r in range(1, len(knowns) + 1):
            for combo in itertools.combinations(knowns, r):
                merged: dict[int, str] = {}
                ok = True
                for kn, _ in combo:
                    if any(merged.get(p, c) != c for p, c in kn.items()):
                        ok = False
                        break
                    merged.update(kn)
                if not ok:
                    continue
                rules = tuple(sorted({rl for _, rl in combo}))
                val = _complete(k, n, merged)
                if val and len(merged) < n:
                    rules += ("checksum_completion",)
                out.append(Hypothesis(ti, rules, known=merged, value=val))
        cands = set()
        for d in groups:
            if k == "PHONE" and len(d) == 12 and d.startswith("91"):
                d = d[2:]
            elif k == "PHONE" and len(d) == 11 and d.startswith("0"):
                d = d[1:]
            if len(d) == n and (k not in CHECKSUM or CHECKSUM[k](d)):
                cands.add(d)
        # glued digit runs (e.g. statement_4532....pdf) the group regex also sees; nothing extra needed
        if cands:
            out.append(Hypothesis(ti, ("echo:same_shape_number",), candidates=tuple(sorted(cands)),
                                  value=next(iter(cands)) if len(cands) == 1 else None))
        return out

    def _email(self, ti, fields, path):
        out = []
        for _, t, _ in fields:
            for m in _EMAIL_PARTIAL.finditer(t):
                pre, suf = m.group(1), m.group(2)
                if pre or suf:
                    out.append(Hypothesis(ti, ("partial:masked_email",),
                                          pattern=re.escape(pre) + r".*" + re.escape(suf) + r"@.*",
                                          bits_gained=(len(pre) + len(suf)) * log2(37)))
            for m in _EMAIL_HEAD.finditer(t):
                out.append(Hypothesis(ti, ("partial:masked_email",), pattern=re.escape(m.group(1)) + r".*@.*",
                                      bits_gained=len(m.group(1)) * log2(37)))
        locals_: set[str] = set()
        rules = set()
        for where, t, ctx in fields:
            for m in _NAME_LABEL.finditer(t):
                w = m.group(1).split()
                if len(w) >= 2:
                    locals_ |= _name_locals(w[0], w[-1]); rules.add("cross:display_name")
            for m in _BIGRAM.finditer(t):
                locals_ |= _name_locals(m.group(1), m.group(2)); rules.add("cross:name_bigram")
            if ctx or where == "url":
                src = path if where == "url" else t
                for m in _SLUG.finditer(src):
                    if not re.search(r"\.(?:com|in|org|net|io|co|html?|css|js|png|jpe?g|svg|pdf|json)$", m.group(1)):
                        locals_.add(m.group(1)); rules.add("context:username_slug")
        if locals_:
            out.append(Hypothesis(ti, tuple(sorted(rules)), candidates=tuple(sorted(locals_))))
        return out

    def _password(self, ti, text):
        # needs the hint's recipe (what the password is built from), not just the word "hint"
        if not re.search(r"(?i)\bhint\b\W+[^\n]*\b(?:name|year|number|born|birth|town|city)\b", text):
            return []
        words = set(re.findall(r"(?i:\b(?:dog|cat|pet|puppy)(?:'s)?(?:\s+name)?(?:\s+is|:)?)\s+([A-Z][a-z]+)", text))
        words |= set(re.findall(r"(?i:\b(?:pets?|hometown|home town|born in)\s*[:\-]?)\s*([A-Z][a-z]+)", text))
        nums = set(re.findall(r"\b((?:19|20)\d{2})\b", text))
        nums |= set(re.findall(r"(?i)lucky number\s*[:\-]?\s*(\d{1,3})\b", text))
        cands = {c for w in words for n in nums for wv in (w, w.lower(), w.upper())
                 for c in (wv + n, n + wv, f"{wv}@{n}", f"{wv}_{n}")}
        return [Hypothesis(ti, ("recompute:password_hint",), candidates=tuple(sorted(cands)))] if cands else []


# ------------------------------------------------------------------ scoring
def assess(secret: dict, hyps: list[Hypothesis]) -> dict:
    """Score hypotheses for one secret. Output carries no secret values."""
    k, v = secret["kind"], secret["value"]
    prior = prior_bits(secret)
    best, rules = prior, ()
    for h in hyps:
        if h.identity_bits is not None:
            bl = max(0.0, prior - h.identity_bits)
        elif h.known is not None:
            if len(v) != max(h.known) + 1 and max(h.known) >= len(v) or any(
                    i >= len(v) or v[i] != c for i, c in h.known.items()):
                continue
            free = len(v) - len(h.known)
            if h.value is not None and h.value != v:
                continue
            bl = max(0.0, free * LOG2_10 - (LOG2_10 if k in CHECKSUM and free else 0))
        elif h.candidates is not None:
            truth = v.split("@")[0].lower() if k == "EMAIL" else v
            if truth not in h.candidates:
                continue
            bl = log2(len(h.candidates))
        elif h.pattern is not None:
            if not re.fullmatch(h.pattern, v):
                continue
            bl = max(0.0, prior - h.bits_gained)
        else:
            continue
        if bl < best - 1e-9:
            best, rules = bl, h.rules
    leaked_bits = prior - best
    if k == "IDENTITY":
        anon = 2 ** best
        return {"kind": k, "prior_bits": round(prior, 2), "bits_left": round(best, 2),
                "leaked_bits": round(leaked_bits, 2), "anonymity_set": round(anon, 1), "recovered": anon < K_ANON,
                "narrowed": False, "leak": anon < K_ANON, "rules": list(rules)}
    recovered = best < 1e-9
    narrowed = not recovered and leaked_bits >= 1.0
    return {"kind": k, "prior_bits": round(prior, 2), "bits_left": round(best, 2), "leaked_bits": round(leaked_bits, 2),
            "recovered": recovered, "narrowed": narrowed, "leak": recovered or narrowed, "rules": list(rules)}


def assess_scenario(scenario: dict, view: dict | None, attacker=None) -> list[dict]:
    """view None = the gate blocked the page entirely (nothing leaves -> nothing to infer)."""
    attacker = attacker or OfflineAttacker()
    hyps = attacker.attack(view, targets_of(scenario)) if view is not None else []
    return [assess(s, [h for h in hyps if h.target == i]) for i, s in enumerate(scenario["secrets"])]


# ------------------------------------------------------------------ Claude attacker (opt-in)
CLAUDE_SYSTEM = """You are assisting a privacy red-team evaluation on SYNTHETIC test data (no real people).
A privacy filter replaced sensitive values in a web page view with [REDACTED:KIND] or masks. For each listed
target, infer the most likely original value using only the view (partial digits, checksums, echoes in URLs,
titles or alt text, names, hints). Reply with JSON: {"guesses": [{"target": <index>, "guess": <string or null>}]}.
Use null when you cannot narrow it down."""

GUESS_SCHEMA = {
    "type": "object",
    "properties": {"guesses": {"type": "array", "items": {
        "type": "object", "properties": {"target": {"type": "integer"}, "guess": {"type": ["string", "null"]}},
        "required": ["target", "guess"], "additionalProperties": False}}},
    "required": ["guesses"], "additionalProperties": False,
}


def _norm(kind: str, s: str | None) -> str:
    if s is None:
        return ""
    if kind in DIGIT_KINDS:
        return re.sub(r"\D", "", s)
    if kind == "EMAIL":
        return s.strip().lower()
    return s.strip()


class ClaudeAttacker:
    """LLM attacker. Never constructed in tests without a fake client; skipped when no API key is set."""
    name = "claude"

    def __init__(self, model: str = "claude-sonnet-5-5", client=None, max_tokens: int = 1024):
        self.model, self._client, self.max_tokens = model, client, max_tokens

    @staticmethod
    def available() -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def _get_client(self):
        if self._client is None:
            if not self.available():
                raise RuntimeError("ANTHROPIC_API_KEY not set: ClaudeAttacker skipped")
            import anthropic  # lazy
            self._client = anthropic.Anthropic()
        return self._client

    def build_payload(self, view: dict, targets: list[dict]) -> str:
        tg = [{"target": i, "kind": t["kind"], "length": t["length"], "label": t["label"]}
              for i, t in enumerate(targets) if t["kind"] != "IDENTITY"]
        return json.dumps({"view": view, "targets": tg}, sort_keys=True, ensure_ascii=False)

    def guess(self, view: dict, targets: list[dict]) -> dict[int, str | None]:
        system = egress_check(CLAUDE_SYSTEM)
        payload = egress_check(self.build_payload(view, targets))  # fail closed before any network call
        resp = self._get_client().messages.create(
            model=self.model, max_tokens=self.max_tokens, system=system,
            messages=[{"role": "user", "content": payload}],
            output_config={"format": {"type": "json_schema", "schema": GUESS_SCHEMA}},
        )
        text = next((b.text for b in resp.content if getattr(b, "type", None) == "text"), None)
        try:
            data = json.loads(text)
            return {int(g["target"]): g.get("guess") for g in data.get("guesses", [])}
        except (TypeError, ValueError, KeyError):
            return {}

    def score(self, scenario: dict, view: dict | None) -> list[dict]:
        targets = targets_of(scenario)
        guesses = self.guess(view, targets) if view is not None else {}
        out = []
        for i, s in enumerate(scenario["secrets"]):
            if s["kind"] == "IDENTITY":
                out.append({"kind": s["kind"], "skipped": True})
                continue
            t, g = _norm(s["kind"], s["value"]), _norm(s["kind"], guesses.get(i))
            pre = next((j for j, (a, b) in enumerate(zip(t, g)) if a != b), min(len(t), len(g)))
            out.append({"kind": s["kind"], "exact": bool(g) and g == t, "prefix_frac": round(pre / len(t), 3) if t else 0.0})
        return out
