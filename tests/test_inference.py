import json
import re
from types import SimpleNamespace

import pytest

from eval.inference import make_scenarios, run
from eval.inference.attack import ClaudeAttacker, OfflineAttacker, assess_scenario, targets_of
from zenlens.gate import Blocked
from zenlens.minimize import minimize, minimize_view

CATS = {"partial", "recompute", "quasi_id", "cross_field", "context"}


@pytest.fixture(scope="module")
def scenarios():
    return make_scenarios.load()


@pytest.fixture(scope="module")
def result(scenarios):
    return run.evaluate(scenarios)


def test_dataset_deterministic_fresh_and_well_formed(scenarios):
    a = make_scenarios.dumps(make_scenarios.build())
    assert a == make_scenarios.dumps(make_scenarios.build())
    assert make_scenarios.OUT.read_text(encoding="utf-8") == a, "run: python -m eval.inference.make_scenarios"
    assert make_scenarios.dumps(make_scenarios.build(seed=1)) != a
    assert 40 <= len(scenarios) <= 60 and len({s["id"] for s in scenarios}) == len(scenarios)
    assert {s["category"] for s in scenarios} == CATS
    for s in scenarios:
        assert s["secrets"] and s["expect"] in ("exact", "narrowed", "reidentified")


def test_attacker_finds_leaks_in_plain_mode(result, scenarios):
    plain = {(r["id"], r["secret"]): r for r in result["rows"] if r["mode"] == "plain"}
    for s in scenarios:
        r = plain[(s["id"], 0)]
        assert r["leak"], s["id"]
        if s["expect"] in ("exact", "reidentified"):
            assert r["recovered"], s["id"]
    for cat in CATS:
        assert result["by_category"][cat]["plain"]["leak"] == 1.0


def test_minimize_removes_leaks(result):
    assert result["failing"] == []
    for r in result["rows"]:
        if r["mode"] == "minimized" and not r["known_gap"]:
            assert not r["leak"], r["id"]
    assert run.main(["--json", "/dev/null"]) == 0


def test_utility_cost_bounded():
    u = run.utility_cost()
    assert u["hard_negatives"]["tokens"] > 100
    assert u["hard_negatives"]["fraction"] <= 0.02
    assert u["all_cases"]["fraction"] <= 0.02


@pytest.mark.parametrize("text", [
    "Order ORD-2026-118934 on 29 Oct 2026, SKU 88213409, total 1,499.00",
    "Invoice INV-2026-000123 dated 2026-01-05 14:32:07",
    "Webinar 2026-03-14 at 18:30 IST, 250 seats, ID 98765",
    "Resolution 1920x1080, 5 years warranty, Rs 2,499",
    "SKU ABCD0123456 and part QWER0X1Y2Z3 in stock",
])
def test_minimize_keeps_ordinary_numbers(text):
    assert minimize(text)[0] == text


def test_minimize_rules_and_notes_carry_no_values():
    src = ("Card ending 4242, a/c XXXXXXXX9934, ravi***@example.com. Date of birth: 14/03/1991, Age: 34, "
           "PIN code: 411038. Password hint: dog's name. Signed in as Ravi Kumar. IFSC ZENB0004821")
    out, notes = minimize(src)
    for frag in ("4242", "9934", "ravi", "14/03", "34", "411038", "dog", "Ravi Kumar", "0004821"):
        assert frag not in out, frag
    assert "1991" in out and "30-39" in out and "411xxx" in out and "ZENB0xxxxxx" in out
    assert {n["rule"] for n in notes} >= {"partial_value", "masked_number", "masked_email", "dob", "age", "pin_code",
                                         "hint", "name", "ifsc"}
    blob = json.dumps(notes)
    assert not re.search(r"\d{3,}", blob.replace('"count"', "")) and "ravi" not in blob.lower()


def test_minimize_never_introduces_values(scenarios):
    for s in scenarios:
        v = run.plain_view(s)
        before = json.dumps(v, ensure_ascii=False)
        after = json.dumps(minimize_view(v)[0], ensure_ascii=False)
        for d in set(re.findall(r"\d+", re.sub(r"\b\d*0-\d*9\b", "", after))):  # age bands are new by design
            assert d in before, (s["id"], d)
        assert before == json.dumps(v, ensure_ascii=False)  # input view not mutated


def test_minimize_keeps_markers_and_pseudonym_tokens():
    t = "Pay [CARD_1 visa] ending 4242 to [EMAIL_2]; OTP [REDACTED:OTP] ok"
    out, _ = minimize(t)
    assert "[CARD_1 visa]" in out and "[EMAIL_2]" in out and "[REDACTED:OTP]" in out and "4242" not in out
    assert minimize(out)[0] == out  # idempotent


def test_minimize_view_masks_echo_in_title_and_url():
    view = {"url": "https://bank.example.com/verify/482913", "title": "Verify 482913",
            "elements": [{"id": "e1", "text": "Your OTP is [REDACTED:OTP]", "name": "", "value": None}]}
    out, notes = minimize_view(view)
    assert "482913" not in json.dumps(out) and {n["where"] for n in notes} == {"url", "title"}


def test_attack_without_view_finds_nothing(scenarios):
    assert all(not r["leak"] for r in assess_scenario(scenarios[0], None))


def test_claude_attacker_skipped_without_key(monkeypatch, scenarios):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert not ClaudeAttacker.available()
    assert run.claude_eval(scenarios) == {"skipped": "ANTHROPIC_API_KEY not set"}
    with pytest.raises(RuntimeError):
        ClaudeAttacker().guess({"url": "", "elements": []}, [])


def test_claude_attacker_goes_through_egress_gate(scenarios):
    class Fake:
        def __init__(self):
            self.messages = SimpleNamespace(create=self.create)
            self.calls = []

        def create(self, **kw):
            self.calls.append(kw)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=json.dumps({"guesses": []}))])
    fake = Fake()
    att = ClaudeAttacker(client=fake)
    s = scenarios[0]
    res = att.score(s, run.plain_view(s))
    assert len(fake.calls) == 1 and all(not r.get("exact") for r in res)
    with pytest.raises(Blocked):  # a view with raw PII never reaches the client
        att.guess({"url": "", "elements": [{"id": "e1", "text": "card 4111 1111 1111 1111"}]}, targets_of(s))
    assert len(fake.calls) == 1


def test_offline_attacker_checksum_completion():
    from zenlens.detect import luhn_ok
    v = next(f"453201511283{i:04d}" for i in range(10000) if luhn_ok(f"453201511283{i:04d}"))
    shown = f"{v[:4]} {v[4:8]} {v[8:12]} {v[12:14]}X{v[15]}"
    view = {"url": "", "title": "", "elements": [{"id": "e1", "text": f"Card {shown}"}]}
    hyps = OfflineAttacker().attack(view, [{"kind": "CARD", "length": 16, "label": "card"}])
    assert any(h.value == v for h in hyps)


def test_minimize_keeps_amounts_and_ticket_ids_next_to_redacted_otp():
    from zenlens.minimize import minimize
    t = ("OTP is [REDACTED:OTP]. Refund of ₹18,499.00 for ticket TKT-20431, reference SR-77120-B, "
         "order ORD-2026-118934, invoice total 2,55,024.00.")
    out, notes = minimize(t)
    assert out == t and notes == []


def test_minimize_still_removes_otp_echoed_in_url():
    from zenlens.minimize import minimize
    out, notes = minimize("OTP is [REDACTED:OTP]. Continue at https://bank.example/verify?otp=482913&s=1")
    assert "482913" not in out and any(n["rule"] == "echo" for n in notes)
