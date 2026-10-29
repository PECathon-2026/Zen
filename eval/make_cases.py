"""Deterministic generator for eval/cases.jsonl (synthetic data only).

Run: python -m eval.make_cases            # rewrites eval/cases.jsonl
     python -m eval.make_cases --check    # exit 1 if the file on disk is stale

Every checksum-bearing value (card, Aadhaar) is computed here, never hand-typed, so the
dataset is regenerable bit-for-bit from SEED. Each case is one JSON object:
  {"id", "scenario", "text", "truth": [[value, kind], ...], "tags": [...], "canaries": [...]}
Tags: positive / hard_negative / format_variant / mixed_lang / adversarial / known_gap / canary.
`known_gap` = the current detector is known to miss this; reported, but excluded from the
eval's exit condition. Remove the tag once detect.py handles it (the eval prints a hint).
"""
from __future__ import annotations

import json
import random
import string
import sys
from pathlib import Path

from zenlens.detect import luhn_ok, verhoeff_check_digit, verhoeff_ok

SEED = 20260214
OUT = Path(__file__).with_name("cases.jsonl")


class Gen:
    def __init__(self, seed: int = SEED):
        self.r = random.Random(seed)
        self.n = 0

    # ---- primitive synthetic values ----
    def digits(self, n: int) -> str:
        return "".join(self.r.choice(string.digits) for _ in range(n))

    def luhn_complete(self, payload: str) -> str:
        for d in "0123456789":
            if luhn_ok(payload + d):
                return payload + d
        raise AssertionError

    def card(self, prefix: str = "4", length: int = 16) -> str:
        return self.luhn_complete(prefix + self.digits(length - len(prefix) - 1))

    def card_invalid(self, prefix: str = "4", length: int = 16) -> str:
        c = self.card(prefix, length)
        bad = c[:-1] + str((int(c[-1]) + 1) % 10)
        assert not luhn_ok(bad)
        return bad

    def aadhaar(self) -> str:
        p = self.r.choice("23456789") + self.digits(10)
        return p + verhoeff_check_digit(p)

    def aadhaar_invalid(self) -> str:
        a = self.aadhaar()
        bad = a[:-1] + str((int(a[-1]) + 1) % 10)
        assert not verhoeff_ok(bad)
        return bad

    def phone(self) -> str:
        return self.r.choice("6789") + self.digits(9)

    def pan(self) -> str:
        up = string.ascii_uppercase
        return ("".join(self.r.choice(up) for _ in range(3)) + "P" + self.r.choice(up)
                + self.digits(4) + self.r.choice(up))

    def alnum(self, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    def otp(self, n: int = 6) -> str:
        return self.r.choice("123456789") + self.digits(n - 1)

    def canary(self) -> str:
        return "ZLCANARY-" + self.alnum(10, string.ascii_uppercase + string.digits)


def g4(s: str, sep: str = " ") -> str:
    return sep.join(s[i:i + 4] for i in range(0, len(s), 4))


def amex(s: str, sep: str = " ") -> str:
    return f"{s[:4]}{sep}{s[4:10]}{sep}{s[10:]}"


def phone_split(p: str, sep: str = " ") -> str:
    return f"{p[:5]}{sep}{p[5:]}"


def build(seed: int = SEED) -> list[dict]:
    g = Gen(seed)
    cases: list[dict] = []

    def C(scenario, text, truth=(), tags=(), canaries=()):
        cases.append({"id": f"{scenario}-{len(cases) + 1:03d}", "scenario": scenario, "text": text,
                      "truth": [list(t) for t in truth],
                      "tags": sorted(set(tags) | ({"positive"} if truth else {"hard_negative"})
                                     | ({"canary"} if canaries else set())),
                      "canaries": list(canaries)})

    # ============================ checkout ============================
    v = g.card(); C("checkout", f"Pay with card {g4(v)}, expiry 08/29", [(g4(v), "CARD")])
    v = g.card(); C("checkout", f"Card number: {g4(v, '-')}", [(g4(v, "-"), "CARD")], ["format_variant"])
    v = g.card(); C("checkout", f"cc={v}&amount=4999", [(v, "CARD")], ["format_variant"])
    v = g.card("5"); C("checkout", f"Mastercard {g4(v)} saved for next time", [(g4(v), "CARD")])
    v = g.card("37", 15); C("checkout", f"Amex {amex(v)} CVV on file", [(amex(v), "CARD")], ["format_variant"])
    v = g.card("34", 15); C("checkout", f"AMEX:{v}", [(v, "CARD")], ["format_variant"])
    v = g.card("60", 16); C("checkout", f"RuPay card {g4(v)} linked", [(g4(v), "CARD")])
    v = g.card(); e = f"buyer.{g.alnum(4).lower()}@example.com"
    C("checkout", f"Pay with card {g4(v)}, receipt to {e}", [(g4(v), "CARD"), (e, "EMAIL")])
    v = g.card(); e = "riya+orders@mail.example.co.in"
    C("checkout", f"Bill to {e}, card ending {v[-4:]}", [(e, "EMAIL")], ["format_variant"])
    C("checkout", "Order #7012345678 total 4999 INR", [], ["order_id"])
    C("checkout", "Order total 4999 INR, ref 1234567", [])
    C("checkout", "Price: Rs 1,49,999.00 incl. GST (18%)", [])
    v = g.card_invalid(); C("checkout", f"Gift voucher {g4(v)} (not a card)", [], ["luhn_invalid"])
    v = g.card_invalid(); C("checkout", f"Tracking no {v}", [], ["luhn_invalid"])
    C("checkout", "Invoice INV-2026-000123 dated 2026-01-05 14:32:07", [])
    C("checkout", "Coupon code ERROR4040X applied", [], ["pan_like"])
    C("checkout", "Model MODEL2025S in stock: 12 units", [], ["pan_like"])
    v = g.card(); C("checkout", f"Card {g4(v)} (GST no 29ABCDE1234F1Z5)", [(g4(v), "CARD")])
    v = g.card(); c = g.canary()
    C("checkout", f"Saved card {g4(v)} for user {c}", [(g4(v), "CARD")], canaries=[c])
    v = g.card(); C("checkout", f"Card: {v[:4]}  {v[4:8]}  {v[8:12]}  {v[12:]}",
                    [(f"{v[:4]}  {v[4:8]}  {v[8:12]}  {v[12:]}", "CARD")], ["format_variant"])
    v = g.card(); C("checkout", f"card no. {g4(v, '.')}", [(g4(v, "."), "CARD")], ["format_variant"])
    v = g.card(); C("checkout", f"Mera card number {g4(v)} hai, payment kar do", [(g4(v), "CARD")], ["mixed_lang"])
    v = g.card(); C("checkout", f"कार्ड नंबर {g4(v)} से भुगतान करें", [(g4(v), "CARD")], ["mixed_lang"])
    v = g.card(); C("checkout", f"card: {' '.join(v)}", [(" ".join(v), "CARD")], ["adversarial"])
    C("checkout", "epoch_ms=1735689600127 cart updated", [], ["timestamp"])
    C("checkout", "epoch_ms=1735689600123 cart updated", [], ["timestamp"])

    # ============================ auth ============================
    pw = "Hunter2!x"; o = g.otp()
    C("auth", f"Login: password: {pw} and your OTP is {o}", [(pw, "PASSWORD"), (o, "OTP")])
    a = g.aadhaar(); p = g.pan()
    C("auth", f"KYC Aadhaar {g4(a)} PAN {p}", [(g4(a), "AADHAAR"), (p, "PAN")])
    a = g.aadhaar(); C("auth", f"Aadhaar: {g4(a, '-')}", [(g4(a, "-"), "AADHAAR")], ["format_variant"])
    a = g.aadhaar(); C("auth", f"uid={a}", [(a, "AADHAAR")], ["format_variant"])
    a = g.aadhaar_invalid(); C("auth", f"Application no {g4(a)}", [], ["verhoeff_invalid"])
    a = g.aadhaar_invalid(); C("auth", f"Ref {a} generated", [], ["verhoeff_invalid"])
    p = g.pan(); C("auth", f"pan_number={p}", [(p, "PAN")])
    p = g.pan(); C("auth", f"PAN card: {p.lower()}", [(p.lower(), "PAN")], ["adversarial"])
    pw = "S3cure#" + g.alnum(5); C("auth", f"pwd={pw}", [(pw, "PASSWORD")], ["format_variant"])
    pw = "Tr0ub4dor&" + g.alnum(3); C("auth", f"Password = {pw}", [(pw, "PASSWORD")], ["format_variant"])
    pw = "Monsoon@" + g.digits(4); C("auth", f"my password is {pw}", [(pw, "PASSWORD")])
    pw = "Chai@" + g.digits(4); C("auth", f"mera password hai {pw}, kisi ko mat batana", [(pw, "PASSWORD")],
                                  ["mixed_lang"])
    pw = "Diwali#" + g.digits(3); C("auth", f"पासवर्ड: {pw}", [(pw, "PASSWORD")], ["mixed_lang"])
    C("auth", "Forgot password? Reset it from the login page", [])
    C("auth", "password: ********", [], ["masked"])
    o = g.otp(); C("auth", f"Your verification code: {o}", [(o, "OTP")])
    o = g.otp(4); C("auth", f"OTP {o} valid for 5 min", [(o, "OTP")], ["format_variant"])
    o = g.otp(); C("auth", f"Use one-time password {o} to sign in", [(o, "OTP")])
    o = g.otp(); C("auth", f"aapka OTP {o} hai, kisi ko share na karein", [(o, "OTP")], ["mixed_lang"])
    o = g.otp(); C("auth", f"आपका OTP {o} है", [(o, "OTP")], ["mixed_lang"])
    o = g.otp(); C("auth", f"Your login code is {o}", [(o, "OTP")])
    C("auth", "OTP valid for 1800 seconds", [], ["otp_like"])
    C("auth", "OTP sent at 10:45, expires in 10 minutes", [])
    e = "Admin.User@corp.example.org"; C("auth", f"Username {e}", [(e, "EMAIL")], ["format_variant"])
    e = "a_b-c.d@sub-domain.example.io"; C("auth", f"login as {e}", [(e, "EMAIL")], ["format_variant"])
    pw = "Pa55w0rd!" + g.alnum(3); c = g.canary()
    C("auth", f"session {c} password: {pw}", [(pw, "PASSWORD")], canaries=[c])
    o = g.otp(); C("auth", f"OTP: {' '.join(o)}", [(" ".join(o), "OTP")], ["adversarial"])

    # ============================ support ============================
    ph = g.phone(); C("support", f"Call me on +91 {ph} about ticket 5521", [(f"+91 {ph}", "PHONE")])
    ph = g.phone(); C("support", f"My number is {ph}", [(ph, "PHONE")], ["format_variant"])
    ph = g.phone(); C("support", f"WhatsApp +91{ph}", [(f"+91{ph}", "PHONE")], ["format_variant"])
    ph = g.phone(); C("support", f"Reach me at +91-{ph}", [(f"+91-{ph}", "PHONE")], ["format_variant"])
    ph = g.phone(); C("support", f"landline-style 0{ph}", [(f"0{ph}", "PHONE")], ["format_variant"])
    ph = g.phone(); C("support", f"call {phone_split(ph)} after 6pm", [(phone_split(ph), "PHONE")],
                      ["format_variant"])
    ph = g.phone(); C("support", f"Phone: +91 {phone_split(ph)}", [(f"+91 {phone_split(ph)}", "PHONE")],
                      ["format_variant"])
    ph = g.phone(); C("support", f"tel: 91{ph}", [(f"91{ph}", "PHONE")], ["format_variant"])
    ph = g.phone(); C("support", f"mera number {ph} hai", [(ph, "PHONE")], ["mixed_lang"])
    ph = g.phone(); C("support", f"bhai {ph} pe call karo jaldi", [(ph, "PHONE")], ["mixed_lang"])
    ph = g.phone(); C("support", f"मेरा नंबर {ph} है", [(ph, "PHONE")], ["mixed_lang"])
    ph = g.phone(); C("support", f"मोबाइल:{ph}", [(ph, "PHONE")], ["mixed_lang"])
    ph = g.phone(); e = f"help.{g.alnum(3).lower()}@support.example.com"
    C("support", f"Customer {e} called from +91 {ph}", [(e, "EMAIL"), (f"+91 {ph}", "PHONE")])
    C("support", "Ticket 998877 resolved on 2026-01-05", [])
    C("support", "Your ticket ID is 8123456789, keep it for reference", [], ["order_id"])
    C("support", "Refund of Rs 2,499 processed; ETA 5-7 business days", [])
    C("support", "Logged at 2026-01-05T09:15:22+05:30 by agent 42", [], ["timestamp"])
    ph = g.phone(); c = g.canary()
    C("support", f"note {c}: callback +91 {ph}", [(f"+91 {ph}", "PHONE")], canaries=[c])
    ph = g.phone(); C("support", f"call {' '.join(ph)}", [(" ".join(ph), "PHONE")], ["adversarial"])
    ph = g.phone(); dev = ph.translate(str.maketrans("0123456789", "०१२३४५६७८९"))
    C("support", f"नंबर {dev}", [(dev, "PHONE")], ["adversarial", "mixed_lang"])
    ph = g.phone(); C("support", f"number is {ph[:3]}.{ph[3:6]}.{ph[6:]}", [(f"{ph[:3]}.{ph[3:6]}.{ph[6:]}", "PHONE")],
                      ["adversarial"])
    e = "anu at example dot com"; C("support", f"email me: {e}", [(e, "EMAIL")], ["adversarial"])
    e = "ravi[at]example[dot]in"; C("support", f"write to {e}", [(e, "EMAIL")], ["adversarial"])
    e = "priya.s@example.in"; C("support", f"mujhe {e} pe mail karo", [(e, "EMAIL")], ["mixed_lang"])
    e = "dev+support@example.com"; C("support", f"Write to {e}.", [(e, "EMAIL")], ["format_variant"])

    # ============================ video ============================
    e = "ravi.k@corp.in"; C("video", f"Participants: Ravi ({e}), 12 online", [(e, "EMAIL")])
    e = "meera.n@team.example.com"; e2 = "arjun@example.org"
    C("video", f"Invitees: {e}; {e2}", [(e, "EMAIL"), (e2, "EMAIL")])
    C("video", "Meeting ID 845 2210 9934, passcode shared in chat", [], ["meeting_id"])
    C("video", "Recording 00:42:17 of 01:05:00, 1080p, 30fps", [], ["timestamp"])
    C("video", "Room 6 has 9 participants; bitrate 2500 kbps", [])
    ph = g.phone(); C("video", f"Dial-in: +91 {ph}", [(f"+91 {ph}", "PHONE")])
    e = "neha@example.com"; C("video", f"neha ({e}) ne screen share kiya", [(e, "EMAIL")], ["mixed_lang"])
    e = "host@example.com"; c = g.canary()
    C("video", f"Host {e} meeting token {c}", [(e, "EMAIL")], canaries=[c])
    C("video", "Session 550e8400-e29b-41d4-a716-446655440000 started", [], ["uuid"])
    C("video", "Join at meet.example.com/abc-defg-hij", [])
    ph = g.phone(); C("video", f"chat: mera whatsapp {ph} hai, wahan bhej do", [(ph, "PHONE")], ["mixed_lang"])
    e = "s.iyer@example.net"; C("video", f"Screen share shows inbox of {e} (3 unread)", [(e, "EMAIL")])
    o = g.otp(); C("video", f"Popup over shared screen: Your OTP is {o}", [(o, "OTP")])
    v = g.card(); C("video", f"Shared tab visible: card {g4(v)} on billing page", [(g4(v), "CARD")])
    C("video", "Webinar 2026-03-14 at 18:30 IST, 250 seats, ID 98765", [], ["timestamp"])
    C("video", "Breakout room 7, timer 15:00, 4 of 6 joined", [])
    C("video", "Participant Ananya Rao joined from Pune", [("Ananya Rao", "NAME")], ["known_gap", "ner"])
    e = "Kiran​@example.com"; C("video", f"cohost {e}", [(e, "EMAIL")], ["adversarial"])

    # ============================ devsettings ============================
    k1 = "sk-" + g.alnum(32); k2 = "AKIA" + g.alnum(16, string.ascii_uppercase + string.digits)
    C("devsettings", f"OPENAI_KEY={k1} AWS={k2}", [(k1, "API_KEY"), (k2, "API_KEY")])
    k = "ghp_" + g.alnum(36); C("devsettings", f"GITHUB_TOKEN={k}", [(k, "API_KEY")])
    k = "AIza" + g.alnum(35, string.ascii_letters + string.digits + "_-")
    # avoid trailing '-' / '_' which breaks the \b boundary (would be an artifact, not a test)
    k = k[:-1] + "Q"; C("devsettings", f"maps_key: {k}", [(k, "API_KEY")])
    k = "sk-proj-" + g.alnum(40); C("devsettings", f"export OPENAI_API_KEY='{k}'", [(k, "API_KEY")], ["format_variant"])
    g.digits(12), g.digits(13)  # keep RNG stream (and every other case) unchanged
    k = "xoxb-SYNTHETIC-" + g.alnum(24)  # not Slack-shaped digits, so GitHub push protection stays quiet
    C("devsettings", f"SLACK_BOT_TOKEN={k}", [(k, "API_KEY")])
    k = "eyJhbGciOiJIUzI1NiJ9." + g.alnum(40) + "." + g.alnum(43)
    C("devsettings", f"Authorization: Bearer {k}", [(k, "TOKEN")])
    k = g.alnum(40, string.ascii_letters + string.digits + "/+")
    C("devsettings", f"aws_secret_access_key = {k}", [(k, "API_KEY")])
    pw = "pg_" + g.alnum(12); C("devsettings", f"DB_PASSWORD={pw}", [(pw, "PASSWORD")])
    pw = "r3dis!" + g.alnum(6); C("devsettings", f"redis.password: {pw}", [(pw, "PASSWORD")])
    ip = "10.24.3.17"; C("devsettings", f"DB_HOST={ip}", [(ip, "IP")], ["ip"])
    ip = "192.168.1.20"; C("devsettings", f"Allowed origin http://{ip}:8080", [(ip, "IP")], ["ip"])
    ip = "203.0.113.45"; C("devsettings", f"Last login from {ip}", [(ip, "IP")], ["ip"])
    C("devsettings", "version 2.10.0.1 released; requires python>=3.11", [], ["version"])
    C("devsettings", "Deployed v6.12.3 build 9876 on node-7", [], ["version"])
    C("devsettings", "commit 3f2a9c8e1b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39 merged", [], ["git_sha"])
    C("devsettings", "request_id=550e8400-e29b-41d4-a716-446655440000", [], ["uuid"])
    C("devsettings", "sk-short and AKIA123 are placeholders, not keys", [], ["key_like"])
    C("devsettings", "PORT=8080 TIMEOUT_MS=30000 MAX_CONN=9999999999", [], ["config_number"])
    C("devsettings", "STRIPE_PUBLISHABLE=pk_test_placeholder", [])
    C("devsettings", "curl https://10.0.12.34/api/v1 from server 172.16.5.4.", [("10.0.12.34", "IP"), ("172.16.5.4", "IP")], ["ip"])
    C("devsettings", "IPv6 gateway fd00:1234:5678::25 and link 2001:db8::8a2e:370:7334",
      [("fd00:1234:5678::25", "IP"), ("2001:db8::8a2e:370:7334", "IP")], ["ip"])
    C("devsettings", "Invalid 999.1.1.1 and 256.10.0.1; uptime 12:30:45; MAC aa:bb:cc:dd:ee:ff; std::vector", [], ["ip"])
    ph = g.phone(); C("support", f"call +91 {ph} or ping 8.8.8.8", [(f"+91 {ph}", "PHONE"), ("8.8.8.8", "IP")], ["ip"])
    C("checkout", "Order ORD-2026-118934 on 29 Oct 2026, SKU 88213409, total 1,499.00", [])
    C("video", "Meeting ID 845 2210 9931, duration 00:42:17, Room 4B", [])
    k = "ghp_" + g.alnum(36); c = g.canary()
    C("devsettings", f"CI_SECRET={c} TOKEN={k}", [(k, "API_KEY")], canaries=[c])
    k = "sk-" + g.alnum(32); C("devsettings", f"key ye hai {k}, kisi ko mat dena", [(k, "API_KEY")], ["mixed_lang"])
    k = "sk-" + g.alnum(32); C("devsettings", f"OPENAI_KEY=\"{k[:16]}\" \"{k[16:]}\"", [(k[:16], "API_KEY")],
                               ["adversarial"])

    for cs in cases:
        for val, _ in cs["truth"]:
            assert val in cs["text"], (cs["id"], val)
    return cases


def dumps(cases: list[dict]) -> str:
    return "".join(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in cases)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    text = dumps(build())
    if "--check" in argv:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("cases.jsonl up to date" if ok else "cases.jsonl is stale: run python -m eval.make_cases")
        return 0 if ok else 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} ({text.count(chr(10))} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
