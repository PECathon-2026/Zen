"""Run the extension against many real public sites (read-only: we load pages, never type or submit anything).

Run:  python -m eval.sites_eval [--workers 4] [--json out.json] [--sites url1 url2 ...]

Per site, twice (shield off = baseline, shield on):
  loads        page reached DOMContentLoaded within the timeout
  blank        shielded screenshot is (nearly) uniform while the baseline is not => the shield blanked or broke the page
  content      shielded innerText length / baseline length (DOM redaction must not eat the page)
  findings     what the detector flags on the untouched public page (false-positive review, kinds only)
  scan_ms      time of one full rescan inside the page
  load_delta   extra load time with the extension
  canary       synthetic card / email / password injected into the live DOM: must disappear from innerText, input.value
               and from a screenshot (OCR)
No credentials are ever entered; canary values are synthetic.
"""
import argparse
import concurrent.futures as cf
import json
import statistics
import tempfile
import time
from pathlib import Path

SITES = """
https://example.com
https://en.wikipedia.org/wiki/Privacy
https://news.ycombinator.com
https://www.bbc.com/news
https://www.python.org
https://developer.mozilla.org/en-US/docs/Web/HTML/Element/input
https://stackoverflow.com/questions
https://www.reddit.com
https://github.com/login
https://accounts.google.com/signin
https://www.amazon.in/ap/signin
https://login.microsoftonline.com
https://www.linkedin.com/login
https://www.paypal.com/signin
https://www.facebook.com/login
https://www.netflix.com/login
https://login.live.com
https://www.w3schools.com/html/html_forms.asp
https://www.saucedemo.com
https://demoqa.com/text-box
https://the-internet.herokuapp.com/login
https://practicetestautomation.com/practice-test-login
https://www.selenium.dev/selenium/web/web-form.html
https://httpbin.org/forms/post
https://pypi.org/account/login
https://www.npmjs.com/login
https://dashboard.stripe.com/login
https://vercel.com/login
https://www.youtube.com
https://www.google.com
https://www.instagram.com
https://www.flipkart.com
https://www.myntra.com
https://www.irctc.co.in
https://www.hdfcbank.com
https://onlinesbi.sbi
https://www.zomato.com
https://web.whatsapp.com
https://www.notion.so/login
https://slack.com/signin
""".split()

EXT = Path(__file__).resolve().parent.parent / "extension"
CANARY_HTML = """<div id="zen-canary" style="position:fixed;top:12px;left:12px;z-index:2147483000;background:#fff;color:#000;
font:22px/1.3 Arial,sans-serif;padding:8px 12px;border:2px solid #000">Card 4111 1111 1111 1111 mail canary.synthetic@example.org
<br><input id="zen-cc" autocomplete="cc-number" value="4111 1111 1111 1111" style="font:20px Arial;width:340px">
<input id="zen-pw" type="password" value="Synth3tic!Pass" style="font:20px Arial;width:200px"></div>"""


def _digits(s): return "".join(c for c in s if c.isalnum()).lower()


def _launch(p, tmp, mode):
    ctx = p.chromium.launch_persistent_context(
        tmp, channel="chromium", headless=True, viewport={"width": 1280, "height": 800},
        args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
    pg = ctx.new_page(); pg.goto("about:blank")
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=10000)
    sw.evaluate("m => chrome.storage.sync.set({shieldMode: m})", mode)
    time.sleep(0.4); pg.close()
    return ctx


def _ext_eval(ctx, page, expr):
    """Evaluate in the extension's content-script world (isolated from the site)."""
    cdp = ctx.new_cdp_session(page)
    ids = []
    cdp.on("Runtime.executionContextCreated", lambda e: ids.append(e["context"]))
    cdp.send("Runtime.disable"); cdp.send("Runtime.enable")
    time.sleep(0.3)
    ext = [c for c in ids if "chrome-extension" in c.get("origin", "")]
    if not ext:
        return None
    r = cdp.send("Runtime.evaluate", {"contextId": ext[-1]["id"], "expression": expr, "returnByValue": True, "awaitPromise": True})
    return r.get("result", {}).get("value")


def visit(ctx, url, timeout=25000):
    page = ctx.new_page()
    out = {"url": url, "ok": False}
    errs = []
    page.on("pageerror", lambda e: errs.append(str(e)[:120]))
    t0 = time.perf_counter()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        out["dcl_ms"] = round((time.perf_counter() - t0) * 1000)
        page.wait_for_timeout(2500)
        out["ok"] = True
        out["final_url"] = page.url[:100]
        out["text_len"] = page.evaluate("document.body ? document.body.innerText.length : 0")
        png = page.screenshot()
        from PIL import Image
        import io
        im = Image.open(io.BytesIO(png)).convert("L").resize((160, 100))
        px = list(im.getdata())
        out["shot_std"] = round(statistics.pstdev(px), 1)
    except Exception as e:
        out["error"] = type(e).__name__
    out["page_errors"] = len(errs)
    return page, out


def run_site(ctx_off, ctx_on, url):
    row = {"url": url}
    pg0, base = visit(ctx_off, url)
    row["baseline"] = base
    pg0.close()
    pg, on = visit(ctx_on, url)
    row["shielded"] = on
    if on["ok"]:
        try:
            info = _ext_eval(ctx_on, pg, """(() => { const s = __ZenContent.state; const c = {};
              for (const f of s.findings) c[f.kind] = (c[f.kind]||0)+1; for (const r of s.domRedacted) for (const k of r.kinds) c[k]=(c[k]||0)+1;
              const t = performance.now(); __ZenContent.scan(); return {kinds: c, scan_ms: Math.round(performance.now()-t), shield: s.settings.shieldMode, enabled: s.enabled}; })()""")
            row["ext"] = info
        except Exception as e:
            row["ext"] = {"error": type(e).__name__}
        # canary injection
        try:
            pg.evaluate("h => { const d = document.createElement('div'); d.innerHTML = h; document.body.appendChild(d.firstElementChild); }", CANARY_HTML)
            pg.wait_for_timeout(600)
            txt = pg.evaluate("document.getElementById('zen-canary') ? document.getElementById('zen-canary').innerText : ''")
            vals = pg.evaluate("['zen-cc','zen-pw'].map(i => (document.getElementById(i) || {}).value || '')")
            png = pg.screenshot(clip={"x": 0, "y": 0, "width": 700, "height": 130})
            from zenlens.screenshot import ocr_text
            ocr = _digits(ocr_text(png))
            row["canary"] = {"text_leak": "4111" in txt or "canary.synthetic" in txt, "value_leak": any("4111" in v or "Synth3tic" in v for v in vals),
                             "ocr_leak": "4111111111111111" in ocr or "canarysyntheticexampleorg" in ocr, "ocr_len": len(ocr)}
        except Exception as e:
            row["canary"] = {"error": type(e).__name__}
    pg.close()
    return row


def worker(urls):
    from playwright.sync_api import sync_playwright
    rows = []
    with sync_playwright() as p, tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
        off, on = _launch(p, t1, "off"), _launch(p, t2, "on")
        for u in urls:
            try:
                rows.append(run_site(off, on, u))
            except Exception as e:
                rows.append({"url": u, "fatal": type(e).__name__})
        off.close(); on.close()
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json")
    ap.add_argument("--sites", nargs="*")
    a = ap.parse_args()
    sites = a.sites or SITES
    chunks = [sites[i::a.workers] for i in range(a.workers)]
    rows = []
    with cf.ProcessPoolExecutor(a.workers) as ex:
        for part in ex.map(worker, chunks):
            rows += part
    rows.sort(key=lambda r: sites.index(r["url"]))
    for r in rows:
        b, s, c, e = r.get("baseline", {}), r.get("shielded", {}), r.get("canary", {}), r.get("ext") or {}
        print(f'{r["url"][8:48]:40} base={"ok" if b.get("ok") else b.get("error","-")} on={"ok" if s.get("ok") else s.get("error","-")} '
              f'text={s.get("text_len")}/{b.get("text_len")} std={s.get("shot_std")}/{b.get("shot_std")} scan={e.get("scan_ms")}ms '
              f'find={sum((e.get("kinds") or {}).values())} canary={"LEAK" if any(c.get(k) for k in ("text_leak","value_leak","ocr_leak")) else ("ok" if c and "error" not in c else c.get("error","-"))}')
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1))


if __name__ == "__main__":
    main()
