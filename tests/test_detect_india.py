"""India-first detectors: UPI_ID, IFSC, BANK_ACCOUNT, GSTIN, VEHICLE, VOTER_ID, PASSPORT (synthetic values only)."""
import pytest

from zenlens.detect import bh_plate_ok, detect, gstin_check_char, gstin_ok, vehicle_ok
from zenlens.gate import Blocked, egress_check
from zenlens.structural import element_kind


def hits(t):
    return [(t[s.start:s.end], s.kind) for s in detect(t)]


def kinds(t):
    return {k for _, k in hits(t)}


def _gstin(body="27ABCPE1234F1Z"):
    return body + gstin_check_char(body)


# ---------- validators ----------
def test_gstin_checksum_valid_and_corrupted():
    g = _gstin()
    assert g == "27ABCPE1234F1ZB"  # computed by the mod-36 algorithm
    assert gstin_ok(g)
    for bad in (g[:-1] + "C", g[:5] + "X" + g[6:], "39" + g[2:-1] + gstin_check_char("39" + g[2:14])):
        assert not gstin_ok(bad), bad
    assert not gstin_ok("29ABCDE1234F1Z5")  # long-standing hard negative in the eval set


def test_vehicle_validators():
    assert vehicle_ok("MH 12 AB 1234") and vehicle_ok("DL3CAB1234") and vehicle_ok("KA-01-AB-0001")
    assert not vehicle_ok("ZZ 12 AB 1234")   # unknown state
    assert not vehicle_ok("HR 2 FY 2026")    # 1-digit district only allowed for Delhi
    assert not vehicle_ok("MH 00 AB 1234") and not vehicle_ok("MH 12 AB 0000")
    assert not vehicle_ok("MH 12-AB 1234")   # mixed separators
    assert bh_plate_ok("22 BH 1234 AA") and not bh_plate_ok("20 BH 1234 AA")


# ---------- UPI vs EMAIL ----------
@pytest.mark.parametrize("vpa", ["9876543210@ybl", "riya.k@okhdfcbank", "shop-12@paytm", "x_y@oksbi", "abc@YBL"])
def test_upi_found(vpa):
    assert hits(f"pay to {vpa}, thanks") == [(vpa, "UPI_ID")]


@pytest.mark.parametrize("email", ["rahul@paytm.com", "help@upi.example.in", "a@ybl.co", "dev@gmail.com"])
def test_upi_does_not_steal_email(email):
    assert hits(f"mail {email} today") == [(email, "EMAIL")]


def test_upi_negatives_and_phone_priority():
    assert hits("follow @paytm; me@unknownbank; z+w@ybl") == []
    assert hits("UPI 9876543210@ybl") == [("9876543210@ybl", "UPI_ID")]  # not PHONE
    assert hits("मेरा UPI kiran12@oksbi है") == [("kiran12@oksbi", "UPI_ID")]


# ---------- IFSC / BANK_ACCOUNT ----------
def test_ifsc():
    assert hits("branch HDFC0001234") == [("HDFC0001234", "IFSC")]
    assert hits("IFSC code: QZXW0123456") == [("QZXW0123456", "IFSC")]
    assert hits("आईएफएससी कोड UTIB0001234") == [("UTIB0001234", "IFSC")]
    assert hits("SKU ABCD0123456 / QWER0X1Y2Z3") == []  # unknown bank code and no IFSC context


@pytest.mark.parametrize("text,acct", [
    ("A/c no. 123456789012", "123456789012"), ("account number is 000123456789", "000123456789"),
    ("mera khata number 12345678901234 hai", "12345678901234"), ("खाता संख्या: 98765432109", "98765432109"),
    ("Account number 9876543210 credited", "9876543210"),  # context beats PHONE
])
def test_bank_account(text, acct):
    assert hits(text) == [(acct, "BANK_ACCOUNT")]


def test_bank_account_negatives():
    assert "BANK_ACCOUNT" not in kinds("Account ID 123456789012 created")
    assert "BANK_ACCOUNT" not in kinds("order 123456789012 shipped")
    assert "BANK_ACCOUNT" not in kinds("a/c no 12345678")                # < 9 digits
    assert "BANK_ACCOUNT" not in kinds("a/c no 1234567890123456789")     # > 18 digits


# ---------- GSTIN ----------
def test_gstin_detection():
    g = _gstin()
    assert hits(f"GSTIN: {g}") == [(g, "GSTIN")]
    assert hits(f"GSTIN {g[:-1]}C") == []
    assert hits("GST no 29ABCDE1234F1Z5") == []


# ---------- VEHICLE ----------
@pytest.mark.parametrize("plate", ["MH 12 AB 1234", "DL3CAB1234", "KA-01-AB-0001", "TN09BC4321", "22 BH 1234 AA"])
def test_vehicle_found(plate):
    assert hits(f"vehicle {plate} parked") == [(plate, "VEHICLE")]


@pytest.mark.parametrize("text", ["Product XY12AB3456", "ZZ 01 AB 1234", "HR 2 FY 2026 report", "20 BH 1234 AA"])
def test_vehicle_negatives(text):
    assert "VEHICLE" not in kinds(text)


# ---------- VOTER_ID / PASSPORT (context required) ----------
def test_voter_id():
    assert hits("Voter ID: ABC1234567") == [("ABC1234567", "VOTER_ID")]
    assert hits("EPIC no XYZ7654321") == [("XYZ7654321", "VOTER_ID")]
    assert hits("वोटर आईडी DEF1112223 जमा करें") == [("DEF1112223", "VOTER_ID")]
    assert hits("Batch ABC1234567 shipped") == []


def test_passport():
    assert hits("Passport No. J1234567, valid till 2031") == [("J1234567", "PASSPORT")]
    assert hits("पासपोर्ट नंबर K7654321 है") == [("K7654321", "PASSPORT")]
    assert hits("coupon J1234567 applied") == []
    assert hits("passport A0123456") == []  # second digit must be 1-9


def test_gate_blocks_new_kinds():
    with pytest.raises(Blocked, match="UPI_ID"):
        egress_check("send to 9876543210@ybl")
    with pytest.raises(Blocked, match="GSTIN"):
        egress_check(f"invoice {_gstin()}")


# ---------- structural (Hinglish labels) ----------
@pytest.mark.parametrize("el,kind", [
    ({"tag": "input", "field_name": "upiId"}, "UPI_ID"), ({"tag": "input", "name": "Enter UPI PIN"}, "PIN"),
    ({"tag": "input", "field_name": "ifsc_code"}, "IFSC"), ({"tag": "input", "name": "Khata Sankhya"}, "BANK_ACCOUNT"),
    ({"tag": "input", "name": "A/C No"}, "BANK_ACCOUNT"), ({"tag": "input", "field_name": "gstin"}, "GSTIN"),
    ({"tag": "input", "name": "Voter ID"}, "VOTER_ID"), ({"tag": "input", "name": "Passport No"}, "PASSPORT"),
    ({"tag": "input", "name": "Gaadi Number"}, "VEHICLE"), ({"tag": "input", "name": "Mob No"}, "PHONE"),
    ({"tag": "input", "name": "Aapka naam"}, "NAME"), ({"tag": "input", "name": "Ghar ka pata"}, "ADDRESS"),
])
def test_structural_keywords(el, kind):
    assert element_kind(el) == kind
