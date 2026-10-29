"""Agent Shield evaluation: load the real extension into Chromium, take agent-style screenshots, measure leakage.

Run:  python -m eval.shield_eval [--json out.json]        (needs: playwright + chromium; OCR via Apple Vision/Tesseract if present)

What an agent sees is simulated the way agents get it: `page.screenshot()` (CDP Page.captureScreenshot, i.e. the
composited pixels) and `document.body.innerText` (get_page_text style DOM read). Conditions per page:
  baseline  shield off          -> proves the values ARE visible and OCR can read them (otherwise a 0 means nothing)
  shielded  default settings    -> Playwright sets navigator.webdriver, so Auto mode must switch the shield on by itself
Metrics (synthetic pages from testpages/*.truth.json only):
  pixel coverage   share of each sensitive FORM FIELD's rectangle painted with the solid cover colour (text is replaced in the DOM)
  OCR leakage      truth values still readable by OCR in the shielded screenshot
  DOM-text leakage truth values still present in body.innerText (text elements) / in input.value (fields)
  context kept     share of non-sensitive "negatives" still readable by OCR (shield must not blank the page)
  latency          ms from injecting new sensitive text to the page no longer showing it
"""
import argparse
import functools
import http.server
import io
import json
import re
import statistics
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
PAGES = ROOT / "testpages"
SCENARIOS = ["checkout", "auth", "support_chat", "video_call", "dev_settings"]
CLEAR = 0.7  # a field counts as covered when this share of its box is opaque cover colour (the kind label takes some)


def _serve():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(PAGES))
    h.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("localhost", 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://localhost:{srv.server_port}"


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _ocr(png: bytes) -> str:
    from zenlens.screenshot import ocr_text
    return ocr_text(png)


def _cover_fraction(png: bytes, rect: dict) -> float:
    """Share of the rectangle painted by an opaque shield cover: dark, saturated per-kind colours (luma < 130).
    Real fields render white/light, so an uncovered field scores ~0."""
    from PIL import Image
    im = Image.open(io.BytesIO(png)).convert("RGB")
    x0, y0 = max(0, int(rect["x"])), max(0, int(rect["y"]))
    x1, y1 = min(im.width, int(rect["x"] + rect["width"])), min(im.height, int(rect["y"] + rect["height"]))
    if x1 <= x0 or y1 <= y0:
        return 0.0
    px = im.crop((x0, y0, x1, y1)).getdata()
    return sum(1 for r, g, b in px if 0.299 * r + 0.587 * g + 0.114 * b < 130) / len(px)


def _launch(p, tmp):
    return p.chromium.launch_persistent_context(
        tmp, channel="chromium", headless=True, viewport={"width": 1000, "height": 900},
        args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])


def _set_mode(ctx, mode: str):
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=10000)
    sw.evaluate("m => chrome.storage.sync.set({shieldMode: m})", mode)


def _truth(name):
    return json.loads((PAGES / f"{name}.truth.json").read_text())


def _item_rect(page, item):
    """Bounding box of the truth item: by element id when given, else by text search."""
    if item.get("id"):
        r = page.evaluate("id => { const e = document.getElementById(id); if (!e) return null; const r = e.getBoundingClientRect();"
                          " return {x: r.x, y: r.y, width: r.width, height: r.height}; }", item["id"])
        if r:
            return r
    return None


def eval_page(ctx, base, name, mode):
    truth = _truth(name)
    page = ctx.new_page()
    page.goto(f"{base}/{name}.html", wait_until="load")
    page.wait_for_timeout(700)
    png = page.screenshot()
    dom_text = page.evaluate("document.body.innerText")
    dom_vals = page.evaluate("[...document.querySelectorAll('input,textarea,select')].map(e => e.value || '').join('\\n')")
    ocr = _norm(_ocr(png))
    items = [i for i in truth["items"] if i.get("value")]
    res = {"page": name, "mode": mode, "items": len(items), "ocr_leaks": [], "dom_text_leaks": [], "dom_value_leaks": [],
           "coverage": [], "uncovered": []}
    for it in items:
        v, nv = it["value"], _norm(it["value"])
        if len(nv) >= 4 and nv in ocr:
            res["ocr_leaks"].append(it["kind"])
        if v in dom_text:
            res["dom_text_leaks"].append(it["kind"])
        if v in dom_vals:
            res["dom_value_leaks"].append(it["kind"])
        # Form fields stay in place and get the solid cover; text is replaced by [REDACTED:KIND] in the DOM instead.
        if it.get("id") and page.evaluate("id => /^(INPUT|TEXTAREA)$/.test((document.getElementById(id) || {}).tagName || '')", it["id"]):
            rect = _item_rect(page, it)
            if rect and rect["width"] > 0 and rect["height"] > 0:  # hidden inputs draw nothing; they are checked via DOM values
                f = _cover_fraction(png, rect)
                res["coverage"].append(round(f, 3))
                if f < CLEAR:
                    res["uncovered"].append(f'{it["kind"]}:{it.get("id")}')
    negs = [n for n in truth.get("negatives", []) if len(_norm(n)) >= 4]
    res["context_kept"] = round(sum(1 for n in negs if _norm(n) in ocr) / len(negs), 3) if negs else None
    res["negatives"] = len(negs)
    page.close()
    return res


def latency(ctx, base, trials=5):
    """ms from DOM insertion of a card number until the page no longer shows it (it is replaced by [REDACTED:CARD])."""
    out = []
    for _ in range(trials):
        page = ctx.new_page()
        page.goto(f"{base}/support_chat.html", wait_until="load")
        page.wait_for_timeout(500)
        page.evaluate("() => { const p = document.createElement('p'); p.id = 'dyn'; p.style.cssText = 'position:fixed;left:40px;top:300px;"
                      "font:20px sans-serif;background:#fff'; p.textContent = 'Card 4111 1111 1111 1111'; window.__t0 = performance.now();"
                      " document.body.appendChild(p); }")
        t0, done = time.perf_counter(), None
        while time.perf_counter() - t0 < 1.5:  # what a DOM read or a screenshot would now show
            if "4111" not in page.evaluate("document.getElementById('dyn').textContent"):
                done = (time.perf_counter() - t0) * 1000
                break
        out.append(done)
        page.close()
    ok = [x for x in out if x is not None]
    return {"trials": trials, "covered": len(ok), "median_ms": round(statistics.median(ok), 1) if ok else None,
            "max_ms": round(max(ok), 1) if ok else None}


_LONG = """<!doctype html><html><body style="margin:0"><div style="height:1500px"></div>
<input id="cc" autocomplete="cc-number" value="4111 1111 1111 1111" style="width:300px;height:30px;margin-left:60px">
<div style="height:2500px"></div>
<input id="fx" type="email" value="rahul.synthetic@example.org" style="position:fixed;top:120px;right:40px;width:260px;height:30px">
</body></html>"""


def scroll_reload(ctx, base):
    """Covers must track scrolling (document-anchored and fixed content) and be up right after a reload."""
    page = ctx.new_page()
    page.route("**/long.html", lambda r: r.fulfill(body=_LONG, content_type="text/html"))
    page.goto(f"{base}/long.html", wait_until="load")
    page.wait_for_timeout(800)
    rect = lambda i: page.evaluate("id => {const r = document.getElementById(id).getBoundingClientRect(); return {x: r.x, y: r.y, width: r.width, height: r.height}}", i)
    scrolled, fixed = [], []
    for step in (900, 400):  # wheel scrolls, screenshot straight after (30 ms), no settling
        page.mouse.move(500, 400); page.mouse.wheel(0, step); page.wait_for_timeout(30)
        png = page.screenshot()
        if 0 < rect("cc")["y"] < 800:
            scrolled.append(_cover_fraction(png, rect("cc")))
        fixed.append(_cover_fraction(png, rect("fx")))
    page.reload(); page.wait_for_timeout(300)
    after = _cover_fraction(page.screenshot(), rect("fx"))
    page.close()
    return {"scrolled_field": [round(x, 2) for x in scrolled], "fixed_field": [round(x, 2) for x in fixed], "after_reload": round(after, 2)}


def adversarial(ctx, base):
    """Shadow DOM, text split over elements, attribute leaks, faces/video/avatars, animated fields, iframes."""
    truth = json.loads((PAGES / "adversarial.truth.json").read_text())
    page = ctx.new_page()
    page.goto(f"{base}/adversarial.html", wait_until="load")
    page.wait_for_timeout(1200)
    png = page.screenshot()
    html = page.evaluate("document.documentElement.outerHTML + [...document.querySelectorAll('*')].filter(e => e.shadowRoot).map(e => e.shadowRoot.innerHTML).join('')")
    text = page.evaluate("document.body.innerText")
    ocr = _norm(_ocr(png))
    res, bad = {}, []
    for it in truth["items"]:
        how, iid = it["how"], it["id"]
        if how == "text":
            ok = _norm(it["value"]) not in ocr and it["value"] not in text
        elif how == "attr":
            ok = it["value"] not in html
        else:
            if how == "frame-field":
                fr = page.frame_locator("#frame").locator("#fin")
                box = fr.bounding_box()
                rect = {"x": box["x"], "y": box["y"], "width": box["width"], "height": box["height"]}
            else:
                js = ("id => { const e = document.getElementById(id) || document.getElementById('shadow-host').shadowRoot.getElementById(id);"
                      " const r = e.getBoundingClientRect(); return {x: r.x, y: r.y, width: r.width, height: r.height}; }")
                if how == "field" and iid == "anim":  # sample a moving field at an arbitrary instant
                    page.wait_for_timeout(430)
                rect = page.evaluate(js, iid)
                png = page.screenshot() if (how == "field" and iid == "anim") else png
            ok = _cover_fraction(png, rect) >= CLEAR
        res[iid] = ok
        if not ok:
            bad.append(f'{it["kind"]}:{iid}({how})')
    page.close()
    return {"items": len(truth["items"]), "protected": sum(res.values()), "failed": bad}


FACE_REF = (177, 66, 95, 95)  # OpenCV Haar box of the 512x512 public-domain NASA portrait (testpages/img)


def _color_fraction(png: bytes, rect: dict, rgb, tol=22) -> float:
    from PIL import Image
    im = Image.open(io.BytesIO(png)).convert("RGB")
    x0, y0, x1, y1 = (max(0, int(rect["x"])), max(0, int(rect["y"])), min(im.width, int(rect["x"] + rect["width"])), min(im.height, int(rect["y"] + rect["height"])))
    if x1 <= x0 or y1 <= y0:
        return 0.0
    px = list(im.crop((x0, y0, x1, y1)).getdata())
    return sum(1 for p in px if all(abs(p[i] - rgb[i]) <= tol for i in range(3))) / len(px)


def _ocr_server():
    """Start the local Zen server (OCR) on :8765 if nothing answers there; returns (proc|None, up)."""
    import subprocess, sys, urllib.request
    def up():
        try:
            return json.load(urllib.request.urlopen("http://localhost:8765/api/health", timeout=1)).get("features", {}).get("ocr", False)
        except Exception:
            return None
    st = up()
    if st is not None:
        return None, bool(st)
    proc = subprocess.Popen([sys.executable, "-m", "app.server", "--port", "8765"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(30):
        time.sleep(0.5)
        st = up()
        if st is not None:
            return proc, bool(st)
    proc.terminate()
    return None, False


def faces(ctx, base, base2, ocr_up):
    """Faces in ordinary photos (bundled detector), object-fit mapping, no over-covering, text in images/canvas (needs OCR server)."""
    page = ctx.new_page()
    page.goto(f"{base}/faces.html#x={base2}", wait_until="load")
    page.wait_for_timeout(3500)  # analysis in the service worker
    png = page.screenshot()
    rect = lambda i: page.evaluate("id => {const r = document.getElementById(id).getBoundingClientRect(); return {x: r.x, y: r.y, width: r.width, height: r.height}}", i)
    def face_rect(i, fit):
        r = rect(i); fx, fy, fw, fh = FACE_REF
        if fit == "fill":
            sx, sy, ox, oy = r["width"] / 512, r["height"] / 512, 0, 0
        else:  # contain
            sx = sy = min(r["width"], r["height"]) / 512; ox, oy = (r["width"] - 512 * sx) / 2, (r["height"] - 512 * sy) / 2
        # inner 60% of the reference face box
        cx, cy, w, h = fx + fw / 2, fy + fh / 2, fw * 0.6, fh * 0.6
        return {"x": r["x"] + ox + (cx - w / 2) * sx, "y": r["y"] + oy + (cy - h / 2) * sy, "width": w * sx, "height": h * sy}
    FACE_RGB = (44, 62, 147)  # kind colour of FACE (#364fc7) as the opaque cover renders it
    res = {}
    for i, fit in (("same", "fill"), ("cross", "fill"), ("fit", "contain")):
        res[i] = round(_color_fraction(png, face_rect(i, fit), FACE_RGB), 2)
    res["clean_covered"] = round(1 - _color_fraction(png, rect("clean"), (235, 228, 195), tol=60), 2)  # share NOT light gradient
    res["ocr_up"] = ocr_up
    if ocr_up:
        res["text_image_ocr_leak"] = "4111111111111111" in _norm(_ocr(png))
        res["canvas_text_hidden"] = _norm("4111 1111 1111 1111") not in _norm(_ocr(png))
    page.close()
    return res


def copy_guard(p, base):
    """Select + copy covered content (field, then whole page): the clipboard must never hold the real values."""
    import tempfile as _t
    out = {}
    for label, patch in (("baseline", {"shieldMode": "off", "maskByDefault": False, "highlight": False}), ("mask", {"shieldMode": "off", "maskByDefault": True}), ("shield", {"shieldMode": "on", "maskByDefault": False})):
        with _t.TemporaryDirectory() as tmp:
            ctx = _launch(p, tmp)
            sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=10000)
            sw.evaluate("v => chrome.storage.sync.set(v)", patch)
            time.sleep(0.4)
            ctx.grant_permissions(["clipboard-read", "clipboard-write"], origin=base)
            pg = ctx.new_page()
            pg.goto(f"{base}/checkout.html", wait_until="load")
            pg.wait_for_timeout(900)
            leaks = []
            for step in ("field", "page"):
                pg.evaluate("navigator.clipboard.writeText('sentinel')")
                if step == "field":
                    pg.click("#cc-number")
                else:
                    pg.click("h1")
                pg.keyboard.press("ControlOrMeta+A")
                pg.keyboard.press("ControlOrMeta+C")
                clip = pg.evaluate("navigator.clipboard.readText()")
                leaks += [v for v in ("4111", "meera.synthetic", "Meera Iyer", "Gulmohar", "737") if v in clip]
            out[label] = sorted(set(leaks))
            ctx.close()
    return out


def run():
    from playwright.sync_api import sync_playwright
    srv, base = _serve()
    report = {"baseline": [], "shielded": [], "focus": None, "latency": None, "scroll": None, "adversarial": None, "copy": None, "faces": None}
    try:
        with sync_playwright() as p:
            for mode, key in (("off", "baseline"), ("auto", "shielded")):
                with tempfile.TemporaryDirectory() as tmp:
                    ctx = _launch(p, tmp)
                    _set_mode(ctx, mode)
                    time.sleep(0.5)
                    for name in SCENARIOS:
                        report[key].append(eval_page(ctx, base, name, mode))
                    if mode == "auto":
                        report["latency"] = latency(ctx, base)
                        report["scroll"] = scroll_reload(ctx, base)
                        report["adversarial"] = adversarial(ctx, base)
                        pg = ctx.new_page()
                        pg.goto(f"{base}/checkout.html", wait_until="load"); pg.wait_for_timeout(600)
                        pg.focus("#cc-number")  # an agent clicking the field must not drop the cover
                        pg.wait_for_timeout(150)
                        rect = pg.evaluate("(() => { const r = document.getElementById('cc-number').getBoundingClientRect(); return {x: r.x, y: r.y, width: r.width, height: r.height}; })()")
                        report["focus"] = round(_cover_fraction(pg.screenshot(), rect), 3)
                    ctx.close()
            report["copy"] = copy_guard(p, base)
            srv2, base2 = _serve()
            proc, ocr_up = _ocr_server()
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    ctx = _launch(p, tmp)
                    _set_mode(ctx, "on")
                    time.sleep(0.5)
                    report["faces"] = faces(ctx, base, base2, ocr_up)
                    ctx.close()
            finally:
                srv2.shutdown()
                if proc:
                    proc.terminate()
    finally:
        srv.shutdown()
    return report


def summarize(r):
    def tot(rows, k): return sum(len(x[k]) for x in rows)
    n = sum(x["items"] for x in r["shielded"])
    s = {"items": n,
         "baseline_ocr_visible": tot(r["baseline"], "ocr_leaks"),
         "shielded_ocr_leaks": tot(r["shielded"], "ocr_leaks"),
         "shielded_dom_text_leaks": tot(r["shielded"], "dom_text_leaks"),
         "shielded_dom_value_leaks": tot(r["shielded"], "dom_value_leaks"),
         "uncovered_items": [u for x in r["shielded"] for u in x["uncovered"]],
         "mean_coverage": round(statistics.mean(c for x in r["shielded"] for c in x["coverage"]), 3) if any(x["coverage"] for x in r["shielded"]) else None,
         "context_kept": round(statistics.mean(x["context_kept"] for x in r["shielded"] if x["context_kept"] is not None), 3),
         "focus_cover": r["focus"], "latency": r["latency"], "scroll": r["scroll"], "adversarial": r["adversarial"], "copy_leaks": r["copy"], "faces": r["faces"]}
    return s


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    a = ap.parse_args()
    rep = run()
    for key in ("baseline", "shielded"):
        print(f"\n[{key}]")
        for x in rep[key]:
            print(f'  {x["page"]:13} items={x["items"]:2} ocr_leaks={len(x["ocr_leaks"])} dom_text={len(x["dom_text_leaks"])} '
                  f'dom_values={len(x["dom_value_leaks"])} uncovered={x["uncovered"]} context={x["context_kept"]}')
    print("\nsummary", json.dumps(summarize(rep), indent=1))
    if a.json:
        Path(a.json).write_text(json.dumps({"report": rep, "summary": summarize(rep)}, indent=1))
