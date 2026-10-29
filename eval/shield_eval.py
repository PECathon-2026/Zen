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
COVER = (0x1B, 0x1C, 0x1A)  # overlay .b.s background #1b1c1a


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
    from PIL import Image
    im = Image.open(io.BytesIO(png)).convert("RGB")
    x0, y0 = max(0, int(rect["x"])), max(0, int(rect["y"]))
    x1, y1 = min(im.width, int(rect["x"] + rect["width"])), min(im.height, int(rect["y"] + rect["height"]))
    if x1 <= x0 or y1 <= y0:
        return 0.0
    px = im.crop((x0, y0, x1, y1)).getdata()
    hit = sum(1 for p in px if all(abs(p[i] - COVER[i]) <= 6 for i in range(3)))
    return hit / len(px)


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
                if f < 0.85:
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


def run():
    from playwright.sync_api import sync_playwright
    srv, base = _serve()
    report = {"baseline": [], "shielded": [], "focus": None, "latency": None}
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
                        pg = ctx.new_page()
                        pg.goto(f"{base}/checkout.html", wait_until="load"); pg.wait_for_timeout(600)
                        pg.focus("#cc-number")  # an agent clicking the field must not drop the cover
                        pg.wait_for_timeout(150)
                        rect = pg.evaluate("(() => { const r = document.getElementById('cc-number').getBoundingClientRect(); return {x: r.x, y: r.y, width: r.width, height: r.height}; })()")
                        report["focus"] = round(_cover_fraction(pg.screenshot(), rect), 3)
                    ctx.close()
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
         "focus_cover": r["focus"], "latency": r["latency"]}
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
