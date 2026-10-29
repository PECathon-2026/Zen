"""Agent Shield end to end: the real extension in real Chromium. Slow (~1 min); skipped without browser/OCR."""
import pytest

pytest.importorskip("playwright")


@pytest.fixture(scope="module")
def report():
    from zenlens.screenshot import available_backend
    if available_backend() is None:
        pytest.skip("no local OCR backend")
    from eval import shield_eval
    try:
        return shield_eval.run(), shield_eval
    except Exception as e:  # no chromium build / extension launch unsupported
        if "Executable doesn't exist" in str(e) or "channel" in str(e).lower():
            pytest.skip(f"chromium unavailable: {type(e).__name__}")
        raise


def test_baseline_values_are_visible_so_zero_means_something(report):
    rep, mod = report
    assert mod.summarize(rep)["baseline_ocr_visible"] >= 15


def test_shield_leaks_nothing_on_the_five_scenarios(report):
    rep, mod = report
    s = mod.summarize(rep)
    assert s["shielded_ocr_leaks"] == 0 and s["shielded_dom_text_leaks"] == 0 and s["shielded_dom_value_leaks"] == 0
    assert s["uncovered_items"] == []


def test_shield_keeps_context_and_is_fast(report):
    rep, mod = report
    s = mod.summarize(rep)
    assert s["context_kept"] >= 0.95
    assert s["focus_cover"] >= 0.7  # focusing a field (as an agent does) must not drop its cover
    assert s["latency"]["covered"] == s["latency"]["trials"] and s["latency"]["max_ms"] < 250


def test_covers_follow_scrolling_and_survive_reload(report):
    rep, mod = report
    sc = mod.summarize(rep)["scroll"]
    assert sc["scrolled_field"] and min(sc["scrolled_field"] + sc["fixed_field"]) >= 0.7
    assert sc["after_reload"] >= 0.7
