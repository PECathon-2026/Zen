import json
from pathlib import Path

import pytest

from zenlens.structural import sanitize_html, scan_html

PAGES = Path(__file__).resolve().parent.parent / "testpages"
NAMES = ["checkout", "auth", "support_chat", "video_call", "dev_settings"]


def load(name):
    return (PAGES / f"{name}.html").read_text(), json.loads((PAGES / f"{name}.truth.json").read_text())


@pytest.mark.parametrize("name", NAMES)
def test_page_recall(name):
    html, truth = load(name)
    got = {(f.elem_id, f.value, f.kind) for f in scan_html(html)}
    missing = [t for t in truth["items"] if (t["id"], t["value"], t["kind"]) not in got]
    assert not missing


@pytest.mark.parametrize("name", NAMES)
def test_page_negatives_kept(name):
    html, truth = load(name)
    clean, found = sanitize_html(html)
    for neg in truth["negatives"]:
        assert not any(f.value and neg in f.value for f in found), neg
        assert neg in clean, neg


@pytest.mark.parametrize("name", NAMES)
def test_page_sanitized_has_no_truth_values(name):
    html, truth = load(name)
    clean, _ = sanitize_html(html)
    for t in truth["items"]:
        if t["value"]:
            assert t["value"] not in clean, t
    assert "[REDACTED:" in clean


def test_structure_beats_regex():
    # Values no text regex would catch: flagged by type/autocomplete/label/aria-label.
    html = ('<label for="x">CVC</label><input id="x" value="913">'
            '<input id="p" type="password" value="abc">'
            '<input id="o" autocomplete="one-time-code" value="5521">'
            '<span id="k" aria-label="Client secret">zx-91-qq</span>'
            '<h2 id="h">Password</h2><button id="b">Show PIN</button>')
    got = {(f.elem_id, f.kind, f.value) for f in scan_html(html)}
    assert got == {("x", "CVV", "913"), ("p", "PASSWORD", "abc"), ("o", "OTP", "5521"), ("k", "SECRET", "zx-91-qq")}
    clean, _ = sanitize_html(html)
    assert all(v not in clean for v in ("913", "abc", "5521", "zx-91-qq"))
    assert "Password</h2>" in clean and "Show PIN" in clean


def test_attrs_comments_scripts_and_entities():
    html = ('<!-- debug: a@b.co --><div id="d" title="call 9812345670">ok &amp; fine</div>'
            '<script>var k="AKIAZZTESTSYNTH00012";</script>')
    clean, found = sanitize_html(html)
    assert {f.kind for f in found} == {"EMAIL", "PHONE", "API_KEY"}
    for v in ("a@b.co", "9812345670", "AKIAZZTESTSYNTH00012"):
        assert v not in clean
    assert "ok &amp; fine" in clean


def test_empty_sensitive_field_and_clean_page():
    assert [(f.elem_id, f.value) for f in scan_html('<input id="pw" type="password">')] == [("pw", None)]
    html = "<p>Order ORD-1182 total 1,499.00 on 29/10/2026</p>"
    assert scan_html(html) == [] and sanitize_html(html)[0] == html


def test_element_kind_hook():
    from zenlens.structural import element_kind
    assert element_kind({"tag": "input", "name": "CVV", "field_name": "f3", "value": "737"}) == "CVV"
    assert element_kind({"tag": "input", "type": "password"}) == "PASSWORD"
    assert element_kind({"tag": "input", "autocomplete": "one-time-code"}) == "OTP"
    assert element_kind({"tag": "button", "name": "Show PIN", "text": "Show PIN"}) is None
    assert element_kind({"tag": "input", "name": "Search", "type": "search"}) is None
