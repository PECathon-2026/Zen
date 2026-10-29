"""ZenLens local server: JSON API + installable PWA.

Privacy model
- Runs on the user's own machine. Default bind 127.0.0.1; `--lan` binds 0.0.0.0 so a phone on the same
  network can use it, and then every POST needs the pairing token (header X-ZenLens-Token).
- Detection/sanitization/OCR are local. The only path that can reach a third party is /api/agent/run in
  "claude" mode, which goes through zenlens.runner -> ClaudeLLM -> egress_check (fail closed).
- Request/response bodies are never logged. Findings carry offsets/kinds/reasons, never values.

Run:  python -m app.server            (http://127.0.0.1:8765)
      python -m app.server --lan      (prints LAN URL with #token=... and a QR code)
"""
from __future__ import annotations

import argparse
import hmac
import importlib
import importlib.util
import io
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from zenlens.detect import detect
from zenlens.gate import Blocked, egress_check

VERSION = "0.1.0"
PORT = 8765
ROOT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / "static"
TESTPAGES = ROOT / "testpages"

MAX_JSON = 2 * 1024 * 1024          # 2 MB for JSON bodies (HTML pages can be big)
MAX_IMAGE = 15 * 1024 * 1024        # 15 MB for photos
MAX_PIXELS = 40_000_000             # decompression-bomb guard
OCR_MAX_SIDE = 3000                 # downscale huge phone photos before OCR
MAX_TEXT = 200_000                  # chars for /api/sanitize and /api/gate
MAX_RULES, MAX_PATTERN = 20, 200
EXT_ORIGIN = re.compile(r"^chrome-extension://[a-z0-9]{16,64}$")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}

log = logging.getLogger("zenlens.app")


# ---------------------------------------------------------------- user-defined rules
class Rule(BaseModel):
    kind: str = Field(max_length=24)
    pattern: str = Field(max_length=MAX_PATTERN)


_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,)")


def compile_rules(rules: list[Rule] | None) -> list[tuple[str, re.Pattern]]:
    """Validate user regexes: count/length caps, KIND format, compiles, no empty match, no nested quantifiers."""
    if not rules:
        return []
    if len(rules) > MAX_RULES:
        raise HTTPException(422, f"too many extra_rules (max {MAX_RULES})")
    out = []
    for i, r in enumerate(rules):
        kind = r.kind.strip().upper()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,23}", kind):
            raise HTTPException(422, f"extra_rules[{i}].kind must be A-Z, 0-9, _ (start with a letter)")
        if not r.pattern:
            raise HTTPException(422, f"extra_rules[{i}].pattern is empty")
        if _NESTED_QUANT.search(r.pattern):
            raise HTTPException(422, f"extra_rules[{i}].pattern has nested quantifiers (catastrophic backtracking risk)")
        try:
            rx = re.compile(r.pattern)
        except re.error as e:
            raise HTTPException(422, f"extra_rules[{i}].pattern is not a valid regex: {e.msg}") from None
        if rx.search(""):
            raise HTTPException(422, f"extra_rules[{i}].pattern matches the empty string")
        out.append((kind, rx))
    return out


def spans_with_rules(text: str, rules) -> list[tuple[int, int, str]]:
    spans = [(s.start, s.end, s.kind) for s in detect(text)]
    for kind, rx in rules:
        for m in rx.finditer(text):
            s, e = m.span()
            if e > s and not any(s < b and a < e for a, b, _ in spans):
                spans.append((s, e, kind))
    return sorted(spans)


def redact_spans(text: str, spans) -> str:
    out, pos = [], 0
    for s, e, k in spans:
        out += [text[pos:s], f"[REDACTED:{k}]"]
        pos = e
    out.append(text[pos:])
    return "".join(out)


# ---------------------------------------------------------------- request models
class SanitizeReq(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    extra_rules: list[Rule] | None = None


class SanitizeHtmlReq(BaseModel):
    html: str = Field(max_length=MAX_JSON)


class GateReq(BaseModel):
    payload: str = Field(max_length=MAX_TEXT)
    extra_rules: list[Rule] | None = None


class PreviewReq(BaseModel):
    url: str = Field(max_length=2048)


class AgentReq(BaseModel):
    goal: str = Field(max_length=2000)
    url: str = Field(max_length=2048)
    mode: str = "scripted"
    script: list[dict] | None = Field(default=None, max_length=50)
    auto_approve: bool = False
    max_steps: int = Field(default=10, ge=1, le=25)


# ---------------------------------------------------------------- helpers
def _runner():
    """zenlens.runner is built by another workstream; import lazily so the app works without it."""
    try:
        return importlib.import_module("zenlens.runner")
    except ImportError as e:
        raise HTTPException(503, f"agent runner unavailable (zenlens.runner: {type(e).__name__}); "
                                 "text, HTML, image and gate endpoints still work") from None


def features(local_only: bool) -> dict:
    try:
        from zenlens.screenshot import available_backend
        ocr = available_backend() is not None
    except Exception:
        ocr = False
    claude = (not local_only and importlib.util.find_spec("anthropic") is not None
              and bool(os.environ.get("ANTHROPIC_API_KEY")))
    return {"ocr": ocr, "playwright": importlib.util.find_spec("playwright") is not None, "claude": claude}


def testpage_names() -> list[str]:
    return sorted(p.stem for p in TESTPAGES.glob("*.html")) if TESTPAGES.is_dir() else []


_pages_srv: dict = {}
_pages_lock = threading.Lock()


def testpages_base() -> str:
    """Serve testpages/ on a private localhost port (lazy, once) via demo.serve (quiet, no request logging).
    The executor only acts on http(s) origins, so bundled pages need a real origin for the agent demo."""
    with _pages_lock:
        if "url" not in _pages_srv:
            try:
                from demo.serve import start
                srv, url = start(port=0)
            except ImportError:  # fallback: same behaviour, stdlib only
                from functools import partial
                from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

                class Quiet(SimpleHTTPRequestHandler):
                    def log_message(self, *a):
                        pass

                srv = ThreadingHTTPServer(("localhost", 0), partial(Quiet, directory=str(TESTPAGES)))
                threading.Thread(target=srv.serve_forever, daemon=True, name="zenlens-testpages").start()
                url = f"http://localhost:{srv.server_address[1]}"
            _pages_srv.update(srv=srv, url=url)
        return _pages_srv["url"]


# Synthetic secrets for the bundled demo pages only (the model sees {{SECRET:name}}, never these values).
DEMO_SECRETS = {"login_email": "zl.user@example.net", "login_password": "Zen-Synth-9931", "otp_code": "604215",
                "card_number": "5555 5555 5555 4444", "card_cvv": ("card", "913")}


def _demo_vault():
    try:
        from demo.run_demo import VAULT
        return VAULT
    except Exception:
        from zenlens.vault import Vault
        return Vault(DEMO_SECRETS)


def resolve_target(url: str) -> str:
    """Bundled test page name -> its local http URL; otherwise only http(s) URLs (no file:// from clients)."""
    u = url.strip()
    if re.fullmatch(r"[a-z0-9_]{1,40}", u):
        if (TESTPAGES / f"{u}.html").is_file():
            return f"{testpages_base()}/{u}.html"
        raise HTTPException(404, "unknown test page")
    parts = urlsplit(u)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise HTTPException(422, "url must be http(s) or a bundled test page name")
    return u


class _Recorder:
    """Wraps the planner: records the exact sanitized payload it is given, after egress_check (fail closed)."""

    def __init__(self, inner, sink: list[str]):
        self.inner, self.sink = inner, sink

    def next_action(self, goal, view, history):
        from zenlens.llm import build_payload
        payload = egress_check(build_payload(goal, view, history))  # raises Blocked -> nothing recorded or sent
        self.sink.append(payload)
        return self.inner.next_action(goal, view, history)


def _err(status: int, msg: str) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=status)


# ---------------------------------------------------------------- app factory
def create_app(*, lan: bool = False, token: str | None = None, local_only: bool = False,
               allowed_hosts: set[str] | None = None) -> FastAPI:
    token = token or secrets.token_urlsafe(18)
    app = FastAPI(title="ZenLens", version=VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token, app.state.lan, app.state.local_only = token, lan, local_only

    def host_ok(host: str) -> bool:
        if lan:
            return True  # token guards LAN mode
        name = re.sub(r":\d+$", "", host or "").lower()
        return name in LOCAL_HOSTS or name in (allowed_hosts or set())

    @app.middleware("http")
    async def guard(request: Request, call_next):
        # 1. DNS-rebinding guard in localhost mode.
        host = request.headers.get("host", "")
        if not host_ok(host):
            return _err(403, "host not allowed")
        # 2. Origin: chrome-extension://* or same-origin only. Anything else is refused outright.
        origin = request.headers.get("origin")
        same = origin is not None and origin in (f"http://{host}", f"https://{host}")
        ext = origin is not None and EXT_ORIGIN.match(origin) is not None
        if origin is not None and not (same or ext):
            return _err(403, "origin not allowed")
        is_api = request.url.path.startswith("/api/")
        if request.method == "OPTIONS" and is_api:  # CORS preflight (extension only; same-origin never preflights)
            if not ext:
                return _err(403, "origin not allowed")
            return Response(status_code=204, headers=_cors(origin, preflight=True))
        # 3. Pairing token on POSTs when reachable from the network.
        if request.method == "POST" and lan:
            got = request.headers.get("x-zenlens-token", "")
            if not hmac.compare_digest(got.encode(), token.encode()):
                resp = _err(401, "missing or bad X-ZenLens-Token")
                if ext:
                    resp.headers.update(_cors(origin))
                return resp
        # 4. Body size limit (Content-Length; chunked bodies are capped in _read_capped).
        if request.method == "POST":
            limit = MAX_IMAGE if request.url.path == "/api/redact_image" else MAX_JSON
            cl = request.headers.get("content-length")
            if cl is not None and (not cl.isdigit() or int(cl) > limit):
                return _err(413, f"body too large (max {limit} bytes)")
        resp = await call_next(request)
        if ext and is_api:
            resp.headers.update(_cors(origin))
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if not is_api:
            resp.headers.setdefault("Content-Security-Policy", CSP)
        if is_api:
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        return _err(exc.status_code, str(exc.detail))

    @app.exception_handler(RequestValidationError)
    async def validation_exc(request: Request, exc: RequestValidationError):
        # FastAPI's default echoes the offending input back; report field paths and messages only.
        errs = [{"loc": [str(x) for x in e.get("loc", ())], "msg": e.get("msg", "")} for e in exc.errors()]
        return JSONResponse({"error": "invalid request", "fields": errs}, status_code=422)

    # ---------------- API
    @app.get("/api/health")
    def health():
        return {"ok": True, "version": VERSION, "features": features(local_only)}

    @app.get("/api/info")
    def info():
        """Extra (not in the extension contract): data the PWA needs for its pickers and settings screen."""
        return {"version": VERSION, "lan": lan, "local_only": local_only, "testpages": testpage_names(),
                "runner": importlib.util.find_spec("zenlens.runner") is not None, "features": features(local_only)}

    @app.post("/api/sanitize")
    def sanitize(req: SanitizeReq):
        rules = compile_rules(req.extra_rules)
        spans = spans_with_rules(req.text, rules)
        counts: dict[str, int] = {}
        for _, _, k in spans:
            counts[k] = counts.get(k, 0) + 1
        return {"sanitized": redact_spans(req.text, spans),
                "findings": [{"start": s, "end": e, "kind": k} for s, e, k in spans], "counts": counts}

    @app.post("/api/sanitize_html")
    def sanitize_html(req: SanitizeHtmlReq):
        from zenlens.structural import sanitize_html as _san
        html, found = _san(req.html)
        counts: dict[str, int] = {}
        for f in found:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return {"html": html, "findings": [{"elem_id": f.elem_id, "kind": f.kind, "reason": f.reason} for f in found],
                "counts": counts}

    @app.post("/api/redact_image")
    async def redact_image(image: UploadFile = File(...), faces: bool = Form(False)):
        data = await _read_capped(image, MAX_IMAGE)
        if not (data.startswith(b"\x89PNG\r\n\x1a\n") or data.startswith(b"\xff\xd8\xff")):
            return _err(415, "image must be PNG or JPEG")
        try:
            png = _normalise_image(data)
        except Exception as e:
            return _err(422, f"could not decode image: {type(e).__name__}")
        from zenlens import screenshot as ss
        try:
            out, reds = ss.redact_image(png, faces=faces)
        except ss.RedactionError as e:
            return _err(422, f"redaction failed, image not returned: {e}")
        except Exception as e:  # fail closed: never echo the input
            return _err(422, f"redaction failed, image not returned: {type(e).__name__}")
        hdr = json.dumps([{"box": list(r.box), "kind": r.kind} for r in reds], separators=(",", ":"))
        return Response(out, media_type="image/png", headers={"X-ZenLens-Redactions": hdr})

    @app.post("/api/gate")
    def gate(req: GateReq):
        rules = compile_rules(req.extra_rules)
        try:
            egress_check(req.payload)
        except Blocked as e:
            return {"allowed": False, "reason": str(e)}
        hit = sorted({k for k, rx in rules if rx.search(req.payload)})
        if hit:
            return {"allowed": False, "reason": f"blocked, detected: {', '.join(hit)}"}
        return {"allowed": True, "reason": None}

    @app.get("/api/demo_scripts")
    def demo_scripts():
        """Scripted-planner presets for the bundled pages (ids from demo/run_demo.py; names, never values)."""
        try:
            from demo import run_demo as d
        except Exception:
            return {"presets": {}}
        return {"presets": {
            "auth": {"goal": "Sign in to ZenBank with my saved login", "script": d.AUTH},
            "checkout": {"goal": "Pay for my order with my saved card", "script": d.CHECKOUT},
            "injection": {"goal": "Reply 'thanks' to the forum post", "script": d.HIJACK}}}

    @app.get("/api/testpages")
    def testpages():
        return {"pages": testpage_names()}

    @app.post("/api/preview")
    def preview(req: PreviewReq):
        target = resolve_target(req.url)
        runner = _runner()
        try:
            return runner.preview(target)
        except Blocked as e:
            return _err(409, f"egress gate blocked the view: {e}")
        except Exception as e:
            log.warning("preview failed: %s", type(e).__name__)
            return _err(502, f"preview failed: {type(e).__name__}")

    @app.post("/api/agent/run")
    def agent_run(req: AgentReq):
        if req.mode not in ("scripted", "claude"):
            raise HTTPException(422, "mode must be 'scripted' or 'claude'")
        if req.mode == "claude" and local_only:
            raise HTTPException(403, "server is in local-only mode: Claude mode is disabled")
        target = resolve_target(req.url)
        runner = _runner()
        from zenlens.llm import Action, ClaudeLLM, ScriptedLLM
        if req.mode == "scripted":
            try:
                inner = ScriptedLLM([Action.from_dict(a) for a in (req.script or [])])
            except ValueError as e:
                raise HTTPException(422, f"invalid script: {e}") from None
        else:
            if not features(local_only)["claude"]:
                raise HTTPException(503, "Claude mode unavailable: install `anthropic` and set ANTHROPIC_API_KEY")
            inner = ClaudeLLM()
        sent: list[str] = []
        try:
            from zenlens.vault import Vault
            demo = target.startswith(testpages_base() + "/")
            vault = _demo_vault() if demo else Vault.from_env()  # real sites: ZENLENS_SECRET_<NAME> env vars
            report = runner.run_task(req.goal, target, llm=_Recorder(inner, sent), vault=vault,
                                     approve=True if req.auto_approve else None,
                                     max_steps=req.max_steps, headless=True)
            report["llm"] = req.mode
            report["secrets_available"] = [f"{{{{SECRET:{n}}}}}" for n in vault.names()]  # names only
            # Exactly what the planner received each step (already egress-checked). In scripted mode the
            # planner is local, so these payloads are what *would* have been sent; nothing left the device.
            report["egress"] = {"sent_to_third_party": req.mode == "claude" and bool(sent),
                                "destination": "Anthropic API (Claude)" if req.mode == "claude" else None,
                                "payloads": [json.loads(p) for p in sent]}
            return report
        except Blocked as e:
            return _err(409, f"egress gate blocked: {e}")
        except Exception as e:
            log.warning("agent run failed: %s", type(e).__name__)
            return _err(502, f"agent run failed: {type(e).__name__}")

    @app.api_route("/api/{rest:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def api_404(rest: str):
        return _err(404, "no such endpoint")

    # ---------------- PWA (service worker + manifest must be served from the root scope)
    @app.get("/sw.js")
    def sw():
        return FileResponse(STATIC / "sw.js", media_type="text/javascript",
                            headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})

    @app.get("/manifest.webmanifest")
    def manifest():
        return FileResponse(STATIC / "manifest.webmanifest", media_type="application/manifest+json")

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
    return app


CSP = ("default-src 'self'; img-src 'self' blob: data:; style-src 'self'; script-src 'self'; "
       "connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")


def _cors(origin: str, preflight: bool = False) -> dict:
    h = {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
         "Access-Control-Expose-Headers": "X-ZenLens-Redactions"}
    if preflight:
        h.update({"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                  "Access-Control-Allow-Headers": "Content-Type, X-ZenLens-Token",
                  "Access-Control-Max-Age": "600"})
    return h


async def _read_capped(f: UploadFile, limit: int) -> bytes:
    buf = io.BytesIO()
    while chunk := await f.read(1 << 20):
        buf.write(chunk)
        if buf.tell() > limit:
            raise HTTPException(413, f"image too large (max {limit} bytes)")
    return buf.getvalue()


def _normalise_image(data: bytes) -> bytes:
    """Decode, apply EXIF rotation (phone photos), drop metadata, cap size; return PNG bytes for OCR."""
    from PIL import Image, ImageOps
    with Image.open(io.BytesIO(data)) as im:
        if im.width * im.height > MAX_PIXELS:
            raise ValueError("too many pixels")
        im = ImageOps.exif_transpose(im).convert("RGB")
    if max(im.size) > OCR_MAX_SIDE:
        im.thumbnail((OCR_MAX_SIDE, OCR_MAX_SIDE))
    out = io.BytesIO()
    im.save(out, "PNG")
    return out.getvalue()


# ---------------------------------------------------------------- CLI
def lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent for UDP connect; just picks the LAN interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def ascii_qr(text: str) -> str | None:
    try:
        import qrcode
    except ImportError:
        return None
    qr = qrcode.QRCode(border=1)
    qr.add_data(text)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=True)
    return buf.getvalue()


class _NoBodies(logging.Filter):
    """Belt and braces: access logs only ever carry method, path and status (no query strings)."""

    def filter(self, record):
        if record.args and isinstance(record.args, tuple) and len(record.args) >= 5:
            client, method, path, ver, status = record.args[:5]
            record.args = (client, method, str(path).split("?", 1)[0], ver, status)
        return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m app.server", description="ZenLens local server + PWA")
    ap.add_argument("--lan", action="store_true", help="bind 0.0.0.0 so a phone on this network can connect (token required)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--local-only", action="store_true", help="disable Claude mode / any third-party egress")
    ap.add_argument("--token", default=os.environ.get("ZENLENS_TOKEN"), help="pairing token (default: random)")
    ap.add_argument("--cert", help="TLS certificate (e.g. from mkcert) so the PWA can install on a phone")
    ap.add_argument("--key", help="TLS private key")
    a = ap.parse_args(argv)
    import uvicorn

    app = create_app(lan=a.lan, token=a.token, local_only=a.local_only)
    host = "0.0.0.0" if a.lan else "127.0.0.1"
    scheme = "https" if a.cert else "http"
    tok = app.state.token
    print(f"\nZenLens {VERSION}  (local-only: {'on' if a.local_only else 'off'})")
    print(f"  This computer:  {scheme}://127.0.0.1:{a.port}/")
    print(f"  Pairing token:  {tok}")
    if a.lan:
        url = f"{scheme}://{lan_ip()}:{a.port}/#token={tok}"
        print(f"  Phone (same Wi-Fi): {url}\n  (the token is in the #fragment, so it never reaches server logs)")
        qr = ascii_qr(url)
        print(qr if qr else "  (pip install qrcode to show a QR code)")
    else:
        print("  Bound to localhost only. Use --lan to pair a phone.")
    print(flush=True)
    logging.getLogger("uvicorn.access").addFilter(_NoBodies())
    uvicorn.run(app, host=host, port=a.port, log_level="info", ssl_certfile=a.cert, ssl_keyfile=a.key,
                server_header=False)


if __name__ == "__main__":
    sys.exit(main())
