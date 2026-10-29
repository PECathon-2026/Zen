import json
from pathlib import Path

import pytest

from zenlens.capture import Element, PageSnapshot, sanitized_view, sensitive_kind
from zenlens.gate import Blocked, egress_check

FIXTURE = Path(__file__).parent / "fixtures" / "capture_page.html"
PII = ["asha.test@example.com", "9876543210", "482913", "2345 6789 0124", "ABCPE1234F",
       "Tr0ub4dor-xyz", "4111 1111 1111 1111", "4111111111111111", "sk-test_abcdefghijklmnopqrstuvwxyz"]


def _snap(*els):
    return PageSnapshot(url="https://shop.example/pay?token=abc", title="Pay", elements=list(els), html="<x>", screenshot=b"")


def test_sensitive_inputs_redacted_without_browser():
    pw = Element("e1", "input", "textbox", name="Secret word", type="password", value="hunter-two")
    cvv = Element("e2", "input", "textbox", name="CVV", type="text", value="123")
    city = Element("e3", "input", "textbox", name="City", type="text", value="Pune")
    v = sanitized_view(_snap(pw, cvv, city))
    vals = {e["id"]: e["value"] for e in v["elements"]}
    assert vals["e1"] == "[REDACTED:PASSWORD]" and vals["e2"] in ("[REDACTED:CARD]", "[REDACTED:CVV]") and vals["e3"] == "Pune"
    assert "token" not in v["url"] and "html" not in v and "screenshot" not in v
    assert sensitive_kind(Element("e4", "input", "textbox", autocomplete="one-time-code")) == "OTP"


def test_canary_blocks():
    with pytest.raises(Blocked):
        sanitized_view(_snap(Element("e1", "p", "text", text="ref ZLCANARY42")), canaries=("ZLCANARY42",))


@pytest.fixture(scope="module")
def snaps():
    pytest.importorskip("playwright")
    from zenlens.capture import capture
    try:
        return capture(str(FIXTURE)), capture(FIXTURE.as_uri())
    except Exception as e:  # chromium binary missing
        pytest.skip(f"chromium unavailable: {e}")


def test_raw_snapshot_is_local_and_complete(snaps):
    s = snaps[0]
    assert s.title == "ZenLens Capture Fixture"
    assert s.screenshot[:8] == b"\x89PNG\r\n\x1a\n" and "asha.test@example.com" in s.html
    assert all(e.id.startswith("e") and len(e.bbox) == 4 for e in s.elements)
    assert not any(e.value and "sk-test" in e.value for e in s.elements)  # hidden input skipped


def test_sanitized_view_has_no_pii_and_passes_gate(snaps):
    v = sanitized_view(snaps[0])
    dumped = json.dumps(v, ensure_ascii=False)
    for p in PII:
        assert p not in dumped, p
    assert egress_check(dumped) == dumped
    assert "Pay now" in dumped and "Help centre" in dumped  # context preserved


def test_secret_inputs_always_redacted(snaps):
    by_ac = {e["autocomplete"]: e for e in sanitized_view(snaps[0])["elements"] if e["tag"] == "input"}
    assert by_ac["current-password"]["value"] == "[REDACTED:PASSWORD]"
    assert by_ac["one-time-code"]["value"] == "[REDACTED:OTP]"
    assert by_ac["cc-number"]["value"] == "[REDACTED:CARD]"


def test_ids_stable_across_captures(snaps):
    a, b = snaps
    assert [(e.id, e.tag, e.name, e.text) for e in a.elements] == [(e.id, e.tag, e.name, e.text) for e in b.elements]


def test_locator_resolves_in_session():
    pytest.importorskip("playwright")
    from zenlens.capture import Session
    try:
        with Session() as s:
            snap = s.goto(str(FIXTURE))
            city = next(e for e in snap.elements if e.name == "City" and e.tag == "input")
            snap.locator_for(city.id).fill("Nagpur")
            assert s.capture().elements[[e.id for e in snap.elements].index(city.id)].value == "Nagpur"
            with pytest.raises(KeyError):
                snap.locator_for("e9999")
    except ImportError:
        raise
    except Exception as e:
        if "Executable doesn't exist" in str(e):
            pytest.skip("chromium unavailable")
        raise
