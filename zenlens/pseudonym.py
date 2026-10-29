"""Consistent pseudonyms: each distinct sensitive value -> a stable session token like [EMAIL_1], [CARD_2].

The model can then tell that the email in the chat is the one on the invoice, without ever seeing it.
token -> value lives only in this object: repr shows counts, pickling is refused, errors carry tokens only.
Optional hints (`hints=True`) reveal nothing about the value beyond a card network from its IIN range;
no last-4, email domains or phone prefixes, ever.
"""
import re

from .detect import _NATIVE_DIGITS, Span, detect

# [KIND_N] or [KIND_N hint]. KIND as in detect/structural/custom rules (A-Z, 0-9, _).
TOKEN = re.compile(r"\[([A-Z][A-Z0-9_]*?)_([1-9]\d{0,5})(?: ([a-z]{2,12}))?\]")
ALIAS = {"NAME": "PERSON"}  # structural NAME -> [PERSON_n]
_DIGIT_KINDS = {"CARD", "AADHAAR", "CVV", "OTP", "PIN", "CARD_EXP"}
_NORM_CANARY = {"CARD", "PHONE", "AADHAAR", "EMAIL"}  # normalised form also blocked at the gate
_FOLD = {"PERSON", "ADDRESS"}
MIN_CANARY = 4  # shorter values (3-digit CVVs) would collide with bbox numbers; they are field-redacted anyway

# token kind -> executor field kinds it may be typed into (anything else: rejected)
TOKEN_FIELDS = {"EMAIL": {"email", "text"}, "CARD": {"card"}, "CVV": {"card"}, "CARD_EXP": {"card"},
                "OTP": {"otp"}, "PASSWORD": {"password"}, "PIN": {"password"}, "API_KEY": {"password"},
                "TOKEN": {"password"}, "SECRET": {"password"}}
CARD_KINDS = {"CARD", "CVV", "CARD_EXP"}


class PseudonymError(Exception):
    """Message carries tokens and kinds only."""


def kind_of(kind: str) -> str:
    return ALIAS.get(kind, kind)


def normalise(kind: str, value: str) -> str:
    v = (value or "").translate(_NATIVE_DIGITS).strip()
    d = re.sub(r"\D", "", v)
    if kind in _DIGIT_KINDS and d:
        return d
    if kind == "PHONE":
        return d[-10:] if len(d) >= 10 else d
    if kind in ("EMAIL", "IP"):
        return v.lower()
    if kind == "PAN":
        return v.upper().replace(" ", "")
    v = " ".join(v.split())
    return v.casefold() if kind in _FOLD else v


def card_network(digits: str) -> str | None:
    """Network from the IIN range only (first 1-4 digits); reveals nothing else about the number."""
    d = digits
    if len(d) < 13:
        return None
    if d[0] == "4":
        return "visa"
    if d[:2] in ("34", "37"):
        return "amex"
    if "51" <= d[:2] <= "55" or "2221" <= d[:4] <= "2720":
        return "mastercard"
    if d[:2] in ("60", "81", "82") or d[:3] == "508" or d[:4] in ("6521", "6522"):
        return "rupay"
    if d[:4] == "6011" or d[:2] == "65" or "644" <= d[:3] <= "649":
        return "discover"
    return None


def neutralise(text: str) -> str:
    """Token look-alikes already in page/user text become (KIND_N): a page cannot plant a token for the model."""
    return TOKEN.sub(lambda m: "(" + m.group(0)[1:-1] + ")", text)


class Pseudonymizer:
    """Session-scoped value <-> token map. Numbering per kind, in order of first appearance."""
    __slots__ = ("_ids", "_vals", "_raw", "_next", "_count", "hints")

    def __init__(self, hints: bool = False):
        self.hints = hints
        self._ids: dict[tuple[str, str], int] = {}       # (kind, normalised) -> n
        self._vals: dict[tuple[str, int], str] = {}      # (kind, n) -> first raw value (what gets typed/shown)
        self._raw: dict[tuple[str, int], set[str]] = {}  # (kind, n) -> every raw form seen (canaries, page matching)
        self._next: dict[str, int] = {}
        self._count: dict[tuple[str, int], int] = {}

    # ---- forward
    def _hint(self, kind: str, n: int) -> str | None:
        if self.hints and kind == "CARD":
            return card_network(normalise("CARD", self._vals[(kind, n)]))
        return None

    def _render(self, kind: str, n: int) -> str:
        h = self._hint(kind, n)
        return f"[{kind}_{n} {h}]" if h else f"[{kind}_{n}]"

    def _key(self, kind: str, value: str) -> tuple[str, int]:
        kind = kind_of(kind)
        norm = normalise(kind, value)
        n = self._ids.get((kind, norm))
        if n is None:
            n = self._next[kind] = self._next.get(kind, 0) + 1
            self._ids[(kind, norm)] = n
            self._vals[(kind, n)] = value.strip()
            self._raw[(kind, n)] = set()
        self._raw[(kind, n)].add(value.strip())
        return kind, n

    def token(self, kind: str, value: str, count: bool = True) -> str:
        """Token for one known-sensitive value (e.g. a structurally flagged field)."""
        k = self._key(kind, value)
        if count:
            self._count[k] = self._count.get(k, 0) + 1
        return self._render(*k)

    def _known_spans(self, text: str, taken: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
        """Values already seen this session (e.g. a name from a flagged field) found again in free text."""
        out = []
        forms = sorted(((r, k) for (k, _), rs in self._raw.items() for r in rs if len(r) >= MIN_CANARY),
                       key=lambda x: -len(x[0]))
        for raw, kind in forms:
            for m in re.finditer(r"(?<!\w)" + re.escape(raw) + r"(?!\w)", text):
                s, e = m.span()
                if not any(s < b and a < e for a, b, _ in taken + out):
                    out.append((s, e, kind))
        return out

    def pseudonymize(self, text: str, spans=None) -> tuple[str, list[Span]]:
        """Replace sensitive spans with tokens. `spans` defaults to detect(text) (Span or (start, end, kind)).
        A token that would itself trip the detector in context (e.g. 'password: [PASSWORD_1]') is emitted as
        [REDACTED:KIND] for that occurrence, so the output always passes egress_check."""
        if not text:
            return text, []
        text = neutralise(text)
        sp = [(s.start, s.end, s.kind) if isinstance(s, Span) else tuple(s) for s in
              (detect(text) if spans is None else spans)]
        sp = sorted(sp + self._known_spans(text, sp))
        keys = [self._key(k, text[s:e]) for s, e, k in sp]
        opaque: set[int] = set()
        for _ in range(2):
            out, pos, where = [], 0, []
            for i, ((s, e, k), key) in enumerate(zip(sp, keys)):
                tok = f"[REDACTED:{k}]" if i in opaque else self._render(*key)
                out.append(text[pos:s])
                start = sum(map(len, out))
                out.append(tok)
                where.append((start, start + len(tok)))
                pos = e
            out.append(text[pos:])
            res = "".join(out)
            bad = {i for i, (a, b) in enumerate(where) if i not in opaque
                   and any(h.start < b and a < h.end for h in detect(res))}
            if not bad:
                break
            opaque |= bad
        for i, key in enumerate(keys):
            if i not in opaque:
                self._count[key] = self._count.get(key, 0) + 1
        return res, [Span(s, e, k) for s, e, k in sp]

    # ---- backward (local only)
    def _lookup(self, m: re.Match) -> tuple[str, int] | None:
        k = (m.group(1), int(m.group(2)))
        if k not in self._vals or (m.group(3) and m.group(3) != self._hint(*k)):
            return None
        return k

    def resolve_token(self, token: str) -> tuple[str, str]:
        """Exactly one token -> (kind, real value). Raises PseudonymError (token name only) if unknown."""
        m = TOKEN.fullmatch((token or "").strip())
        if not m:
            raise PseudonymError("not a pseudonym token")
        k = self._lookup(m)
        if k is None:
            raise PseudonymError(f"unknown token {m.group(0)}")
        return k[0], self._vals[k]

    def rehydrate(self, text: str) -> str:
        """Tokens -> real values for LOCAL display. Unknown tokens are left as they are."""
        if not text:
            return text
        return TOKEN.sub(lambda m: self._vals[k] if (k := self._lookup(m)) else m.group(0), text)

    def is_token(self, text: str) -> bool:
        return bool(TOKEN.fullmatch((text or "").strip()))

    def canaries(self) -> tuple[str, ...]:
        """Every real form seen (and normalised card/phone/email), for egress_check(canaries=...)."""
        out = set()
        for (kind, n), raws in self._raw.items():
            out |= raws
            if kind in _NORM_CANARY:
                out |= {normalise(kind, r) for r in raws}
        return tuple(sorted(c for c in out if len(c) >= MIN_CANARY))

    def legend(self) -> list[dict]:
        """[{token, kind, count}] in kind/number order. Never values."""
        return [{"token": self._render(k, n), "kind": k, "count": self._count.get((k, n), 0)}
                for k, n in sorted(self._vals)]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for k, _ in self._vals:
            out[k] = out.get(k, 0) + 1
        return dict(sorted(out.items()))

    def __len__(self):
        return len(self._vals)

    def __repr__(self):
        return f"Pseudonymizer(tokens={self.counts()})"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Pseudonymizer is not serializable")
