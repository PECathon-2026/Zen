import io
import os

import pytest

Image = pytest.importorskip("PIL.Image")
from PIL import ImageDraw, ImageFont  # noqa: E402

from zenlens import screenshot as ss  # noqa: E402

needs_ocr = pytest.mark.skipif(ss.available_backend() is None, reason="no local OCR backend")


def _font(size=32):
    for p in ("/System/Library/Fonts/Supplemental/Arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default(size=size)


def _png(lines, size=(1000, 80 + 70 * 3)):
    im = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(im)
    for i, t in enumerate(lines):
        d.text((30, 30 + 70 * i), t, fill="black", font=_font())
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


@needs_ocr
def test_redacts_card_and_email_keeps_hard_negative():
    png = _png(["Card 4111 1111 1111 1111", "Order 12345 shipped", "Mail priya.test@example.com"])
    before = ss.ocr_text(png)
    assert "4111" in before and "example.com" in before  # sanity: OCR reads the input
    out, reds = ss.redact_image(png)
    after = ss.ocr_text(out)
    assert {r.kind for r in reds} >= {"CARD", "EMAIL"}
    assert "4111" not in after and "1111" not in after and "example" not in after
    assert "Order 12345" in after and "Card" in after


@needs_ocr
def test_extra_boxes_filled():
    png = _png(["Hello world"])
    out, reds = ss.redact_image(png, extra_boxes=[(600, 150, 700, 200)])
    im = Image.open(io.BytesIO(out)).convert("RGB")
    assert im.getpixel((650, 175)) == (0, 0, 0)
    assert any(r.kind == "EXTRA" for r in reds)
    assert "Hello world" in ss.ocr_text(out)


def test_fail_closed_on_ocr_error(monkeypatch):
    def boom(img):
        raise OSError("ocr crashed")
    monkeypatch.setattr(ss, "ocr_lines", boom)
    with pytest.raises(ss.RedactionError):
        ss.redact_image(_png(["Card 4111 1111 1111 1111"]))


def test_fail_closed_without_backend(monkeypatch):
    monkeypatch.setattr(ss, "available_backend", lambda: None)
    with pytest.raises(ss.RedactionError):
        ss.redact_image(_png(["Card 4111 1111 1111 1111"]))


def test_faces_flag_no_crash_on_blank():
    pytest.importorskip("cv2")
    assert ss._face_boxes(Image.new("RGB", (200, 200), "white")) == []
