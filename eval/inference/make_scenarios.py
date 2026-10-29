"""Deterministic generator for eval/inference/scenarios.jsonl (synthetic data only).

Run: python -m eval.inference.make_scenarios           # rewrite scenarios.jsonl
     python -m eval.inference.make_scenarios --check   # exit 1 if stale

Each scenario is a page (url, title, element list shaped like capture.Element) where a sensitive value is
redacted or masked but nearby context leaks it or narrows it down. Fields:
  {"id", "category", "subcategory", "url", "title", "elements": [...],
   "secrets": [{"kind", "value", "label"}], "expect": "exact" | "narrowed" | "reidentified", "tags": [...]}
Categories: partial / recompute / quasi_id / cross_field / context.
`expect` = what the offline attacker can recover from plain redaction (exact value, a reduced candidate set,
or re-identification for IDENTITY secrets). Tags: `known_gap` = minimize.py is known not to fix it (excluded
from the runner's exit condition); `detector_gap` = the full value survives redaction (a detect.py miss).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from eval.inference.attack import BANK, BANK_PREFIX, CITY_PIN3
from eval.make_cases import Gen, g4

SEED = 20261030
OUT = Path(__file__).with_name("scenarios.jsonl")

FIRST = ["Ravi", "Meera", "Arjun", "Ananya", "Kiran", "Priya", "Rohan", "Neha", "Vikram", "Isha"]
LAST = ["Kumar", "Nair", "Mehta", "Rao", "Iyer", "Sharma", "Das", "Pillai", "Joshi", "Menon"]
PETS = ["Bruno", "Coco", "Simba", "Tiger", "Mylo"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_ROLE = {"a": "link", "button": "button", "img": "img", "h1": "heading", "h2": "heading", "li": "listitem",
         "label": "label"}


def T(text, tag="p", name=""):
    return {"tag": tag, "role": _ROLE.get(tag, "text"), "name": name, "text": text}


def IMG(alt):
    return {"tag": "img", "role": "img", "name": alt, "text": ""}


def INP(label, value, type_="text", field_name=None, placeholder=None, autocomplete=None):
    return {"tag": "input", "role": "textbox", "name": label, "text": "", "type": type_, "value": value,
            "field_name": field_name, "placeholder": placeholder, "autocomplete": autocomplete}


def sec(kind, value, label=None):
    return {"kind": kind, "value": value, "label": label or kind.lower()}


def build(seed: int = SEED) -> list[dict]:
    g = Gen(seed)
    r = g.r
    out: list[dict] = []

    def S(category, sub, elements, secrets, expect, url="https://shop.example.com/account", title="My account",
          tags=()):
        els = [{"id": f"e{i}", **e} for i, e in enumerate(elements, 1)]
        out.append({"id": f"{category}-{len(out) + 1:03d}", "category": category, "subcategory": sub,
                    "url": url, "title": title, "elements": els, "secrets": secrets, "expect": expect,
                    "tags": sorted(tags)})

    def person():
        return r.choice(FIRST), r.choice(LAST)

    def mask(s, keep, ch="X"):
        return "".join(c if i in keep else ch for i, c in enumerate(s))

    # ============================ partial values ============================
    v = g.card()
    S("partial", "card_last4", [T("Saved cards"), T(f"Visa card ending {v[-4:]}"), T(f"Card number: {g4(v)}")],
      [sec("CARD", v, "card number")], "narrowed", url="https://shop.example.com/checkout", title="Checkout")
    v = g.card()
    S("partial", "card_masked", [T("Pay with"), T(f"XXXX XXXX XXXX {v[-4:]}")], [sec("CARD", v, "card number")],
      "narrowed", url="https://shop.example.com/checkout", title="Checkout")
    v = g.card("5")
    S("partial", "card_bullets", [T("Mastercard"), T(f"•••• {v[-4:]}"), INP("Card number", g4(v), autocomplete="cc-number")],
      [sec("CARD", v, "card number")], "narrowed", url="https://shop.example.com/pay", title="Payment")
    v = g.card()
    S("partial", "card_bin_last4", [T("Receipt"), T(f"Card {g4(mask(v, set(range(6)) | set(range(12, 16)), '•'))}")],
      [sec("CARD", v, "card number")], "narrowed", url="https://shop.example.com/orders/receipt", title="Receipt")
    p = g.phone()
    S("partial", "phone_masked", [T("OTP sent to your mobile"), T(mask(p, {0, 1, 7, 8, 9}))],
      [sec("PHONE", p, "mobile number")], "narrowed", url="https://bank.example.com/login", title="Sign in")
    p = g.phone()
    S("partial", "phone_stars", [T(f"Registered mobile: {p}"), T(f"Alerts go to +91 {mask(p, {6, 7, 8, 9}, '*')}")],
      [sec("PHONE", p, "mobile number")], "narrowed", url="https://bank.example.com/profile", title="Profile")
    f, l_ = person(); e = f"{f.lower()}.{l_.lower()}@example.com"
    S("partial", "email_masked", [T("We sent a reset link to"), T(f"{e[0]}***@example.com"), T(f"Account: {e}")],
      [sec("EMAIL", e, "email address")], "narrowed", url="https://mail.example.com/reset", title="Reset password")
    f, l_ = person(); e = f"{f.lower()}{l_.lower()}@example.com"
    S("partial", "email_prefix_suffix", [T(f"Verify {e[:2]}****{e.split('@')[0][-2:]}@example.com")],
      [sec("EMAIL", e, "email address")], "narrowed", url="https://mail.example.com/verify", title="Verify email")
    a = g.aadhaar()
    S("partial", "aadhaar_masked", [T("e-KYC"), T(f"Aadhaar XXXX XXXX {a[-4:]}"), T(f"Aadhaar: {g4(a)}")],
      [sec("AADHAAR", a, "Aadhaar number")], "narrowed", url="https://kyc.example.com/status", title="KYC status")
    a = g.aadhaar()
    S("partial", "aadhaar_input", [T(f"Linked Aadhaar: xxxx-xxxx-{a[-4:]}")],
      [sec("AADHAAR", a, "Aadhaar number")], "narrowed", url="https://kyc.example.com/link", title="Link Aadhaar")
    acc = g.digits(12)
    S("partial", "account_masked", [T("Savings account"), T(f"A/c XXXXXXXX{acc[-4:]}")],
      [sec("ACCOUNT", acc, "bank account number")], "narrowed", url="https://bank.example.com/accounts", title="Accounts")
    p = g.phone()
    S("partial", "phone_ends_with", [T(f"Mobile {p[:5]} {p[5:]}"), {**T("Edit"), "tag": "button", "role": "button",
                                                                     "name": f"Edit number ending in {p[-4:]}"}],
      [sec("PHONE", p, "mobile number")], "narrowed", url="https://bank.example.com/profile", title="Profile")

    # ============================ recomputable ============================
    v = g.card()
    S("recompute", "card_one_digit_hidden", [T("Confirm card"), T(f"Card {g4(mask(v, set(range(16)) - {13}))}")],
      [sec("CARD", v, "card number")], "exact", url="https://shop.example.com/confirm", title="Confirm")
    v = g.card()
    S("recompute", "card_check_digit_dropped", [T(f"Card on file: {g4(v[:15] + 'X')}")],
      [sec("CARD", v, "card number")], "exact", url="https://shop.example.com/wallet", title="Wallet")
    v = g.card()
    S("recompute", "card_two_masks", [T(f"Statement: {g4(mask(v, set(range(6)) | set(range(12, 16))))}"),
                                      T(f"SMS alert: {g4(mask(v, set(range(6, 11)), '*'))}")],
      [sec("CARD", v, "card number")], "exact", url="https://bank.example.com/cards", title="Cards")
    a = g.aadhaar()
    S("recompute", "aadhaar_one_digit_hidden", [T(f"UID {g4(mask(a, set(range(12)) - {10}))}")],
      [sec("AADHAAR", a, "Aadhaar number")], "exact", url="https://kyc.example.com/verify", title="Verify UID")
    a = g.aadhaar()
    S("recompute", "aadhaar_two_masks", [T(f"Aadhaar XXXX XXXX {a[-4:]}"), T(f"Document ref {a[:6]}XXXXXX")],
      [sec("AADHAAR", a, "Aadhaar number")], "narrowed", url="https://kyc.example.com/docs", title="Documents")
    o = g.otp()
    S("recompute", "otp_in_url", [T(f"Your OTP is {o}"), T("Do not share it with anyone")],
      [sec("OTP", o, "one-time password")], "exact", url=f"https://bank.example.com/verify/{o}", title="Verify")
    o = g.otp()
    S("recompute", "otp_in_title", [T(f"Your verification code: {o}")], [sec("OTP", o, "one-time password")],
      "exact", url="https://bank.example.com/verify", title=f"Verify {o} | ZenBank")
    o = g.otp()
    S("recompute", "otp_in_alt", [T(f"OTP {o} valid for 5 min"), IMG(f"code-{o}.png")],
      [sec("OTP", o, "one-time password")], "exact", url="https://bank.example.com/verify", title="Verify")
    o = g.otp()
    S("recompute", "otp_in_button_text", [T(f"Your OTP is {o}"), {**T(f"Autofill {o}"), "tag": "button", "role": "button"}],
      [sec("OTP", o, "one-time password")], "exact", url="https://bank.example.com/verify", title="Verify",
      tags=["known_gap"])
    pet, yr = r.choice(PETS), str(r.randint(1975, 2000)); pw = pet + yr
    S("recompute", "password_hint_pet_year", [T(f"Saved password: {pw}"), T("Password hint: my dog's name + birth year"),
                                              T(f"Our dog {pet} turned 7 today"), T(f"Date of birth: 12/05/{yr}")],
      [sec("PASSWORD", pw, "password")], "narrowed", url="https://social.example.com/settings", title="Settings")
    town, num = "Nashik", str(r.randint(10, 99)); pw = town.lower() + num
    S("recompute", "password_hint_town_number", [T(f"password: {pw}"), T("Hint: hometown + lucky number"),
                                                 T(f"Hometown: {town}"), T(f"Lucky number: {num}")],
      [sec("PASSWORD", pw, "password")], "narrowed", url="https://forum.example.com/profile", title="Profile")

    # ============================ quasi-identifiers ============================
    def dob():
        return r.randint(1, 28), r.randint(1, 12), r.randint(1960, 2002)

    for i, fmt in enumerate(["dmy", "text", "iso", "dmy"]):
        d, m, y = dob()
        city = r.choice(list(CITY_PIN3))
        pin = CITY_PIN3[city] + g.digits(3)
        ds = {"dmy": f"{d:02d}/{m:02d}/{y}", "text": f"{d} {MONTHS[m - 1]} {y}", "iso": f"{y}-{m:02d}-{d:02d}"}[fmt]
        gen = r.choice(["Male", "Female"])
        els = [T("Profile"), T(f"Date of birth: {ds}")]
        els.append(T(f"PIN code: {pin}") if i % 2 == 0 else T(f"Address: 14 MG Road, {city} {pin}"))
        if i < 3:
            els.append(T(f"Gender: {gen}"))
        S("quasi_id", f"dob_pin_gender_{fmt}" if i < 3 else "dob_pin", els,
          [sec("IDENTITY", f"person-{i}", "identity")], "reidentified",
          url="https://health.example.com/profile", title="Patient profile")
    for emp in ["Kestrel Labs", "Orchid Analytics"]:
        age, gen = r.randint(25, 58), r.choice(["Male", "Female"])
        S("quasi_id", "age_employer_gender", [T(f"{age}-year-old engineer at {emp}"), T(f"Gender: {gen}")],
          [sec("IDENTITY", f"emp-{emp}", "identity")], "reidentified",
          url="https://jobs.example.com/candidate", title="Candidate")
    age = r.randint(25, 58)
    S("quasi_id", "age_employer", [T(f"Age: {age}"), T("Employer: Banyan Robotics"), T("Male")],
      [sec("IDENTITY", "emp-banyan", "identity")], "reidentified", url="https://jobs.example.com/candidate",
      title="Candidate")
    for _ in range(2):
        br = g.digits(6); acc = br[-BANK_PREFIX:] + g.digits(12 - BANK_PREFIX)
        S("quasi_id", "ifsc_account_suffix", [T(f"Beneficiary branch: {BANK}0{br}"), T(f"Account ending {acc[-4:]}")],
          [sec("ACCOUNT", acc, "bank account number")], "narrowed",
          url="https://bank.example.com/beneficiary", title="Beneficiary")

    # ============================ cross-field ============================
    for lab in ["Signed in as", "Welcome,"]:
        f, l_ = person(); e = f"{f.lower()}.{l_.lower()}@example.com"
        S("cross_field", "email_from_display_name", [T(f"{lab} {f} {l_}"), T(f"Contact email: {e}")],
          [sec("EMAIL", e, "email address")], "narrowed", url="https://mail.example.com/inbox", title="Inbox")
    f, l_ = person(); e = f"{f.lower()}{l_.lower()}@example.com"
    S("cross_field", "email_from_unlabelled_name", [T(f"{f} {l_} · Premium member"), T(f"Email: {e}")],
      [sec("EMAIL", e, "email address")], "narrowed", url="https://mail.example.com/inbox", title="Inbox",
      tags=["known_gap"])
    p = g.phone()
    S("cross_field", "phone_in_alt_regrouped", [T(f"Mobile: {p}"), IMG(f"Call {p[:3]} {p[3:6]} {p[6:]}")],
      [sec("PHONE", p, "mobile number")], "exact", url="https://shop.example.com/contact", title="Contact",
      tags=["detector_gap"])
    p = g.phone()
    S("cross_field", "phone_in_field_name", [T(f"Mobile: +91 {p}"), INP("Contact", "", field_name=f"contact_{p}")],
      [sec("PHONE", p, "mobile number")], "exact", url="https://shop.example.com/contact", title="Contact",
      tags=["detector_gap"])
    p = g.phone()
    S("cross_field", "phone_in_aria", [T(f"Phone {p}"), {**T("Call"), "tag": "a", "role": "link", "name": f"tel-{p}"}],
      [sec("PHONE", p, "mobile number")], "exact", url="https://shop.example.com/contact", title="Contact",
      tags=["detector_gap"])
    f, l_ = person(); e = f"{f.lower()}.{l_.lower()}@example.com"
    S("cross_field", "email_username_in_url", [T(f"Email: {e}"), T("Edit profile")],
      [sec("EMAIL", e, "email address")], "exact", url=f"https://social.example.com/people/{e.split('@')[0]}",
      title="Profile")
    v = g.card()
    S("cross_field", "card_in_field_name", [T(f"Card {g4(v)}"), INP("Nickname", "", field_name=f"card_{v}")],
      [sec("CARD", v, "card number")], "exact", url="https://shop.example.com/wallet", title="Wallet",
      tags=["detector_gap"])

    # ============================ context leaks ============================
    f, l_ = person(); p = g.phone()
    S("context", "phone_in_url_slug", [T(f"Mobile: {p}"), T("Seller profile")],
      [sec("PHONE", p, "mobile number")], "exact",
      url=f"https://market.example.com/u/{f.lower()}-{l_.lower()}-{p}", title="Seller", tags=["detector_gap"])
    v = g.card()
    S("context", "card_in_filename", [T(f"Card {g4(v)}"), {**T(f"statement_{v}.pdf"), "tag": "a", "role": "link"}],
      [sec("CARD", v, "card number")], "exact", url="https://bank.example.com/statements", title="Statements",
      tags=["detector_gap"])
    a = g.aadhaar()
    S("context", "aadhaar_in_filename", [T(f"Aadhaar {g4(a)}"), {**T(f"aadhaar_{a}.pdf"), "tag": "a", "role": "link"}],
      [sec("AADHAAR", a, "Aadhaar number")], "exact", url="https://kyc.example.com/uploads", title="Uploads",
      tags=["detector_gap"])
    v = g.card()
    S("context", "card_last4_in_aria", [T(f"Card {g4(v)}"), {**T("Remove"), "tag": "button", "role": "button",
                                                             "name": f"Remove card ending {v[-4:]}"}],
      [sec("CARD", v, "card number")], "narrowed", url="https://shop.example.com/wallet", title="Wallet")
    a = g.aadhaar()
    S("context", "aadhaar_mask_in_url", [T(f"Aadhaar {g4(a)}")], [sec("AADHAAR", a, "Aadhaar number")], "narrowed",
      url=f"https://kyc.example.com/kyc/{a[:4]}XXXX{a[-4:]}", title="KYC")
    p = g.phone()
    S("context", "phone_in_placeholder", [T(f"Mobile: {p}"), INP("Alternate number", "", placeholder=f"Registered: {p[:5]}.{p[5:]}")],
      [sec("PHONE", p, "mobile number")], "exact", url="https://bank.example.com/profile", title="Profile",
      tags=["detector_gap"])
    f, l_ = person(); e = f"{f.lower()}.{l_.lower()}@example.com"
    S("context", "email_username_in_title", [T(f"Email: {e}")], [sec("EMAIL", e, "email address")], "exact",
      url="https://mail.example.com/home", title=f"{e.split('@')[0]}'s dashboard")
    o = g.otp()
    S("context", "otp_in_url_and_alt", [T(f"Login code is {o}"), IMG(f"qr_{o}")], [sec("OTP", o, "one-time password")],
      "exact", url=f"https://bank.example.com/login/confirm-{o}", title="Confirm")
    return out


def dumps(scenarios: list[dict]) -> str:
    return "".join(json.dumps(s, ensure_ascii=False, sort_keys=True) + "\n" for s in scenarios)


def load(path: Path | str = OUT) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    text = dumps(build())
    if "--check" in argv:
        ok = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("scenarios.jsonl up to date" if ok else "scenarios.jsonl is stale: run python -m eval.inference.make_scenarios")
        return 0 if ok else 1
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT} ({text.count(chr(10))} scenarios)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
