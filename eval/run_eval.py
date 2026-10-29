"""Measure recall/precision on synthetic labelled cases and leakage after sanitize+gate.
Run: python -m eval.run_eval
"""
from zenlens.detect import detect, verhoeff_check_digit
from zenlens.gate import Blocked, egress_check
from zenlens.sanitize import redact

AADHAAR = (p := "23456789012") and p + verhoeff_check_digit(p)
AADHAAR = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"

# (scenario, text, [(value, kind)]) -- all values synthetic
CASES = [
    ("checkout", "Pay with card 4111 1111 1111 1111, ship to anu@example.com", [("4111 1111 1111 1111", "CARD"), ("anu@example.com", "EMAIL")]),
    ("checkout", "Order total 4999 INR, ref 1234567", []),
    ("auth", "Login: password: Hunter2!x and your OTP is 482913", [("Hunter2!x", "PASSWORD"), ("482913", "OTP")]),
    ("auth", f"KYC Aadhaar {AADHAAR} PAN ABCDE1234F", [(AADHAAR, "AADHAAR"), ("ABCDE1234F", "PAN")]),
    ("support", "Call me on +91 9876543210 about ticket 5521", [("+91 9876543210", "PHONE")]),
    ("support", "Ticket 998877 resolved on 2026-01-05", []),
    ("devsettings", "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz123456 AWS=AKIAABCDEFGHIJKLMNOP", [("sk-abcdefghijklmnopqrstuvwxyz123456", "API_KEY"), ("AKIAABCDEFGHIJKLMNOP", "API_KEY")]),
    ("video", "Participants: Ravi (ravi.k@corp.in), 12 online", [("ravi.k@corp.in", "EMAIL")]),
]


def main() -> int:
    tp = fp = fn = 0
    leaks = 0
    for scen, text, truth in CASES:
        got = {(text[s.start:s.end], s.kind) for s in detect(text)}
        want = set(truth)
        tp += len(got & want); fp += len(got - want); fn += len(want - got)
        for miss in want - got: print(f"MISS [{scen}] {miss}")
        for extra in got - want: print(f"FALSE+ [{scen}] {extra}")
        clean, _ = redact(text)
        leaks += sum(v in clean for v, _ in truth)
        try:
            egress_check(clean)
        except Blocked as e:
            leaks += 1; print(f"GATE blocked sanitized text [{scen}]: {e}")
        try:
            egress_check(text)
            if truth: leaks += 1; print(f"GATE let raw PII through [{scen}]")
        except Blocked:
            pass
    rec = tp / (tp + fn) if tp + fn else 1.0
    prec = tp / (tp + fp) if tp + fp else 1.0
    print(f"cases={len(CASES)} recall={rec:.2f} precision={prec:.2f} leaks={leaks}")
    return 0 if leaks == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
