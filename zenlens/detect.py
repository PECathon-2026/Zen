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


_GST_CS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_char(first14: str) -> str:
    """Official GSTIN mod-36 check character over the first 14 chars (factors 1,2,1,2,...)."""
    total = 0
    for i, ch in enumerate(first14):
        p = _GST_CS.index(ch) * (1 if i % 2 == 0 else 2)
        total += p // 36 + p % 36
    return _GST_CS[(36 - total % 36) % 36]


def gstin_ok(s: str) -> bool:
    s = s.upper()
    return (len(s) == 15 and all(c in _GST_CS for c in s) and 1 <= int(s[:2]) <= 38
            and gstin_check_char(s[:14]) == s[14])


# Indian RTO state / UT codes (incl. legacy OR, DN, DD and TG for Telangana).
VEHICLE_STATES = frozenset(
    "AN AP AR AS BR CG CH DD DL DN GA GJ HP HR JH JK KA KL LA LD MH ML MN MP MZ NL OD OR PB PY RJ SK TG TN "
    "TR TS UK UP WB".split())
_PLATE = re.compile(r"([A-Z]{2})([ -]?)([0-9]{1,2})\2([A-Z]{1,3})\2([0-9]{4})")


def vehicle_ok(s: str) -> bool:
    """State code must exist; district is 2 digits (Delhi may use 1); district and number non-zero."""
    m = _PLATE.fullmatch(s)
    if not m:
        return False
    st, _, dist, _, num = m.groups()
    return (st in VEHICLE_STATES and (len(dist) == 2 or st == "DL") and int(dist) > 0 and int(num) > 0)


def bh_plate_ok(s: str) -> bool:
    """Bharat series (2021+): YY BH NNNN XX."""
    return int(s[:2]) >= 21 and int(_digits(s)[2:]) > 0


# UPI PSP handles (the part after @ in a VPA). A VPA has no dot-TLD after the handle.
UPI_HANDLES = (
    "okhdfcbank okicici oksbi okaxis okbizaxis ybl ibl axl paytm pthdfc ptsbi ptyes ptaxis upi apl yapl "
    "fbl ratn rbl kotak kmbl icici hdfcbank sbi axisbank axisb idfcbank idfcfirst ikwik freecharge airtel "
    "jio waaxis wahdfcbank wasbi waicici yesbank yesbankltd indus federal aubank barodampay boi cnrb pnb "
    "unionbank mahb kbl idbi dbs hsbc citi sliceaxis jupiteraxis abfspay timecosmos dlb pockets ezeepay "
    "postbank ippb"
).split()
_UPI_ALT = "|".join(UPI_HANDLES)
# IFSC bank codes accepted without an "IFSC" keyword nearby (major Indian banks).
IFSC_BANKS = (
    "SBIN HDFC ICIC UTIB PUNB BARB CNRB UBIN BKID IOBA IDIB UCBA CBIN MAHB KKBK YESB INDB IDFB FDRL KARB "
    "SIBL CIUB KVBL TMBL DCBL RATN AUBL BDBL ESFB UJVN JAKA PSIB IBKL CSBK DLXB NTBL HSBC SCBL CITI DBSS "
    "DEUT AIRP PYTM FINO JSFB SURY NSPB USFB IPOS"
).split()
_IFSC_ALT = "|".join(IFSC_BANKS)


def _ctx(keys: str) -> str:
    """Context prefix: keyword, up to two connector words (no/number/card/...), optional ':'/'is'/'hai'."""
    return (rf"(?:{keys})(?:\s*(?i:no\.?|number|num|code|card|sankhya|#|संख्या|नंबर|कोड)){{0,2}}"
            rf"\s*(?:[:=#-]|(?i:is|hai)\b|है)?\s*")


# (kind, regex, group, validator). Order = priority when spans overlap.
_RULES = [
    ("API_KEY", r"\b(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_-]{35}|xox[abprs]-[A-Za-z0-9-]{10,})\b", 0, None),
    ("API_KEY", r"(?i)aws_secret_access_key\s*[:=]\s*([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])", 1, None),
    ("TOKEN", r"\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}", 0, None),
    # GSTIN: state 01-38 + PAN (4th letter = holder type) + entity no + 'Z' + mod-36 check char.
    ("GSTIN", r"\b[0-9]{2}[A-Z]{3}[ABCFGHJLPT][A-Z][0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b", 0, gstin_ok),
    # UPI VPA: local@psp-handle, never followed by a dot-TLD (that is an EMAIL). Before PHONE/CARD.
    ("UPI_ID", rf"(?<![\w.+-])\w[\w.-]*@(?i:{_UPI_ALT})(?![\w-]|\.[\w-])", 0, None),
    ("IFSC", _ctx(r"(?i:\bifsc)|आईएफएससी") + r"([A-Z]{4}0[A-Z0-9]{6})\b", 1, None),
    ("IFSC", rf"\b(?:{_IFSC_ALT})0[A-Z0-9]{{6}}\b", 0, None),
    # Context-only kinds: bare values are too ambiguous (prefer false negatives).
    ("BANK_ACCOUNT", _ctx(r"(?i:\b(?:a/c|acct|account|khata))|खाता") + r"([0-9]{9,18})\b", 1, None),
    ("VOTER_ID", _ctx(r"(?i:\b(?:voter\s*id|voter\s*card|epic))|मतदाता पहचान पत्र|वोटर आईडी|वोटर कार्ड")
     + r"([A-Z]{3}[0-9]{7})\b", 1, None),
    ("PASSPORT", _ctx(r"(?i:\bpassport)|पासपोर्ट") + r"([A-PR-WY][1-9][0-9]{5}[1-9])\b", 1, None),
    ("CARD", r"\b\d(?:[ .-]{0,2}\d){12,18}\b", 0, lambda s: luhn_ok(_digits(s))),
    ("AADHAAR", r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b", 0, lambda s: verhoeff_ok(_digits(s))),
    # 4th letter = holder type (P person, C company, H HUF, F firm, A AOP, T trust, B BOI, L local, J AJP, G govt)
    ("PAN", r"\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b", 0, None),
    ("EMAIL", r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b", 0, None),
    # Vehicle plates: MH 12 AB 1234 / DL3CAB1234 (same separator throughout) and BH series 22 BH 1234 AA.
    ("VEHICLE", r"\b[A-Z]{2}([ -]?)[0-9]{1,2}\1[A-Z]{1,3}\1[0-9]{4}\b", 0, vehicle_ok),
    ("VEHICLE", r"\b[0-9]{2}([ -]?)BH\1[0-9]{4}\1[A-Z]{1,2}\b", 0, bh_plate_ok),
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
