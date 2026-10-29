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


def test_adversarial_cases_are_protected(report):
    rep, mod = report
    adv = mod.summarize(rep)["adversarial"]
    assert adv["failed"] == [], adv  # shadow DOM, split text, attributes, faces/video/avatars, animation, iframe


def test_copy_from_covered_content_yields_no_real_values(report):
    rep, mod = report
    c = mod.summarize(rep)["copy_leaks"]
    assert c["baseline"], "without the extension's guard copy must leak, else this test proves nothing"
    assert c["mask"] == [] and c["shield"] == []


def test_faces_in_photos_are_covered_text_clear_images_left_alone(report):
    rep, mod = report
    f = mod.summarize(rep)["faces"]
    assert f["same"] >= 0.6 and f["cross"] >= 0.6 and f["fit"] >= 0.6, f  # same-origin, cross-origin (worker fetch), object-fit: cover
    assert f["clean_covered"] < 0.25, f  # an image with no face and no text is not blanked
    if f["ocr_up"]:
        assert not f["text_image_ocr_leak"] and f["canvas_text_hidden"], f


def test_covers_follow_a_moving_field_at_every_instant(report):
    rep, mod = report
    m = mod.summarize(rep)["moving"]
    assert len(m) >= 6 and min(m) >= 0.7, m
