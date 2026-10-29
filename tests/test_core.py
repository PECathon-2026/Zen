import pytest

from zenlens.detect import detect, luhn_ok, verhoeff_check_digit, verhoeff_ok
from zenlens.gate import Blocked, egress_check
from zenlens.sanitize import redact


def test_validators():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    p = "23456789012"
    assert verhoeff_ok(p + verhoeff_check_digit(p))
    assert not verhoeff_ok(p + str((int(verhoeff_check_digit(p)) + 1) % 10))


def test_redact_removes_values():
    clean, spans = redact("card 4111 1111 1111 1111 mail a@b.co")
    assert "4111" not in clean and "a@b.co" not in clean
    assert "[REDACTED:CARD]" in clean and len(spans) == 2


def test_invalid_card_not_flagged():
    assert detect("number 4111 1111 1111 1112") == []


def test_gate_blocks_and_passes():
    with pytest.raises(Blocked):
        egress_check("my mail a@b.co")
    with pytest.raises(Blocked):
        egress_check("hello SECRET-CANARY-1", canaries=("SECRET-CANARY-1",))
    assert egress_check("hello [REDACTED:EMAIL]") == "hello [REDACTED:EMAIL]"


def test_gate_fails_closed(monkeypatch):
    monkeypatch.setattr("zenlens.gate.detect", lambda t: 1 / 0)
    with pytest.raises(Blocked):
        egress_check("anything")
