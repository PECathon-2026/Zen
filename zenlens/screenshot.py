"""Local screenshot redaction: OCR word boxes -> detect() on line text -> black boxes. No network.

OCR backends (auto-picked, override with ZENLENS_OCR=tesseract|vision):
- tesseract: pytesseract + the `tesseract` binary (portable).
- vision: Apple Vision via pyobjc (macOS only, on-device).

Fail closed: if no backend is available or OCR errors, redact_image raises RedactionError.
It never returns the input image unredacted.
"""
import io
import os
import shutil
import sys
from dataclasses import dataclass

from PIL import Image, ImageDraw

from zenlens.detect import detect

PAD = 4
Box = tuple[int, int, int, int]  # x0, y0, x1, y1 in pixels


class RedactionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Redaction:
    box: Box
    kind: str  # detector kind, "EXTRA" or "FACE"; never the redacted value


@dataclass(frozen=True)
class Word:
    text: str
    box: Box


def _tesseract_lines(img: Image.Image) -> list[list[Word]]:
    import pytesseract
    d = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    lines: dict[tuple, list[Word]] = {}
    for i, t in enumerate(d["text"]):
        if t.strip():
            x, y, w, h = d["left"][i], d["top"][i], d["width"][i], d["height"][i]
            key = (d["block_num"][i], d["par_num"][i], d["line_num"][i])
            lines.setdefault(key, []).append(Word(t.strip(), (x, y, x + w, y + h)))
    return list(lines.values())


def _vision_lines(img: Image.Image) -> list[list[Word]]:
    import Vision
    from Foundation import NSData
    buf = io.BytesIO()
    img.save(buf, "PNG")
    data = buf.getvalue()
    req = Vision.VNRecognizeTextRequest.alloc().init()
    req.setRecognitionLevel_(0)  # accurate
    req.setUsesLanguageCorrection_(False)  # keep digits/ids verbatim
    h = Vision.VNImageRequestHandler.alloc().initWithData_options_(NSData.dataWithBytes_length_(data, len(data)), None)
    ok, err = h.performRequests_error_([req], None)
    if not ok:
        raise RedactionError(f"vision OCR failed: {err}")
    W, H = img.size

    def px(r):  # normalized, bottom-left origin -> pixel box
        o, s = r.origin, r.size
        return (int(o.x * W), int((1 - o.y - s.height) * H), int((o.x + s.width) * W + 0.999), int((1 - o.y) * H + 0.999))

    out = []
    for obs in req.results() or []:
        cand = obs.topCandidates_(1)[0]
        s, words, i = cand.string(), [], 0
        for tok in s.split():
            i = s.index(tok, i)
            r, _ = cand.boundingBoxForRange_error_((i, len(tok)), None)
            words.append(Word(tok, px(r.boundingBox()) if r else px(obs.boundingBox())))
            i += len(tok)
        out.append(words)
    return out


def _vision_ok() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        import Vision  # noqa: F401
        return True
    except ImportError:
        return False


def _tesseract_ok() -> bool:
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        return False
    return shutil.which("tesseract") is not None


_BACKENDS = {"tesseract": (_tesseract_ok, _tesseract_lines), "vision": (_vision_ok, _vision_lines)}


def available_backend() -> str | None:
    want = os.environ.get("ZENLENS_OCR")
    for name in ([want] if want else ["tesseract", "vision"]):
        if name in _BACKENDS and _BACKENDS[name][0]():
            return name
    return None


def ocr_lines(img: Image.Image) -> list[list[Word]]:
    name = available_backend()
    if name is None:
        raise RedactionError("no local OCR backend (brew install tesseract, or pip install pyobjc-framework-Vision on macOS)")
    return _BACKENDS[name][1](img)


def ocr_text(png_bytes: bytes) -> str:
    img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    return "\n".join(" ".join(w.text for w in line) for line in ocr_lines(img))


def _sensitive_boxes(lines: list[list[Word]]) -> list[Redaction]:
    out = []
    for words in lines:
        text, offs = "", []
        for w in words:
            offs.append((len(text), len(text) + len(w.text)))
            text += w.text + " "
        for sp in detect(text):
            hit = [w.box for w, (s, e) in zip(words, offs) if s < sp.end and sp.start < e]
            if hit:
                out.append(Redaction((min(b[0] for b in hit), min(b[1] for b in hit),
                                      max(b[2] for b in hit), max(b[3] for b in hit)), sp.kind))
    return out


def _face_boxes(img: Image.Image) -> list[Redaction]:
    try:
        import cv2
        import numpy as np
    except ImportError:
        raise RedactionError("faces=True needs opencv-python-headless<5 and numpy") from None
    if not hasattr(cv2, "CascadeClassifier"):  # OpenCV 5 dropped Haar cascades; needs opencv<5
        raise RedactionError("faces=True needs opencv<5 (Haar cascades)")
    cc = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    gray = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2GRAY)
    return [Redaction((int(x), int(y), int(x + w), int(y + h)), "FACE")
            for x, y, w, h in cc.detectMultiScale(gray, 1.1, 5, minSize=(30, 30))]


def redact_image(png_bytes: bytes, extra_boxes=(), faces: bool = False) -> tuple[bytes, list[Redaction]]:
    """Black out detected PII text, `extra_boxes` (x0,y0,x1,y1 px, e.g. DOM password inputs) and,
    if faces=True and OpenCV is installed, faces. Returns (png_bytes, redactions).
    Raises RedactionError when OCR is unavailable or fails (fail closed, never returns the original)."""
    try:
        img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
        reds = _sensitive_boxes(ocr_lines(img))
    except RedactionError:
        raise
    except Exception as e:
        raise RedactionError(f"OCR failed: {type(e).__name__}") from e
    reds += [Redaction(tuple(int(v) for v in b), "EXTRA") for b in extra_boxes]
    if faces:
        reds += _face_boxes(img)
    W, H = img.size
    draw = ImageDraw.Draw(img)
    for r in reds:
        x0, y0, x1, y1 = r.box
        draw.rectangle((max(0, x0 - PAD), max(0, y0 - PAD), min(W - 1, x1 + PAD), min(H - 1, y1 + PAD)), fill="black")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue(), reds
