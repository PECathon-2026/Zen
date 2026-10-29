"""Local PII detection: regex + checksum validators. Nothing here touches the network."""
import ipaddress
import re
from dataclasses import dataclass

_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],
      [4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],
      [8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
      [9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_ok(num: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(num)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _digits(s): return re.sub(r"\D", "", s)


def _ipv6_ok(s):
    try:
        ipaddress.IPv6Address(s)
        return sum(1 for g in s.split(":") if g) >= 3  # skip short tokens like a::b, C++ scopes
    except ValueError:
        return False


# (kind, regex, group, validator). Order = priority when spans overlap.
_RULES = [
    ("API_KEY", r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,})\b", 0, None),
    ("API_KEY", r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])", 1, None),
    ("TOKEN", r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}", 0, None),
    ("CARD", r"\b\d(?:[ .-]{0,2}\d){12,18}\b", 0, lambda s: luhn_ok(_digits(s))),
    ("AADHAAR", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", 0, lambda s: verhoeff_ok(_digits(s))),
    ("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b", 0, None),
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 0, None),
    # 5+5 splits, +91/91/0 prefixes; skip "#123..." / "ID is ..." and repeated-digit sentinels like 9999999999.
    ("PHONE", r"(?<![\w#-])(?<!(?i:\bid) )(?<!(?i:\bid:) )(?<!(?i:\bid is) )(?:(?:\+?91|0)[ -]?)?[6-9]\d{4}[ -]?\d{5}\b", 0,
     lambda s: len(set(_digits(s)[-10:])) > 2),
    # IPv4: octets 0-255; not in a longer dotted run (1.2.3.4.5), not after v/version/release/build.
    ("IP", r"(?<![\w.])(?<!(?i:\bversion) )(?<!(?i:\brelease) )(?<!(?i:\bbuild) )(?<!(?i:\bver) )(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\.?\d|\w)", 0, None),
    ("IP", r"(?<![\w:.])(?=[0-9A-Fa-f:]*[0-9A-Fa-f]:[0-9A-Fa-f]*:)[0-9A-Fa-f:]{3,39}(?![\w:])", 0, _ipv6_ok),
    ("PASSWORD", r"(?i)(?<![a-z])(?:password|passwd|pwd|पासवर्ड)\s*(?:[:=]|is\b|hai\b)\s*(?!\[REDACTED)(?!\*+(?:\s|$))(\S+?)[,;]?(?=\s|$)", 1, None),
    ("OTP", r"(?i)\b(?:otp|verification code|one[- ]time (?:code|password)|login code|security code|code is)\D{0,20}?(\d{4,8})\b(?!\s*(?:seconds|secs?|minutes|mins?)\b)", 1, None),
]


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str


_NATIVE_DIGITS = {0x0966 + i: str(i) for i in range(10)}  # Devanagari -> ASCII, same length so spans still map


def detect(text: str) -> list[Span]:
    text = text.translate(_NATIVE_DIGITS)
    spans: list[Span] = []
    for kind, pat, grp, ok in _RULES:
        for m in re.finditer(pat, text):
            if ok and not ok(m.group(0)):
                continue
            s, e = m.span(grp)
            if not any(s < b.end and b.start < e for b in spans):
                spans.append(Span(s, e, kind))
    return sorted(spans, key=lambda x: x.start)
