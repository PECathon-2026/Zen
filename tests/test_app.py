"""app/server.py: API contract, privacy properties (no values in findings/errors), token, CORS, fail-closed images."""
import io
import json
import importlib.util

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from app import server as srv  # noqa: E402

BASE = "http://127.0.0.1:8765"
EXT = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
CARD, EMAIL, PHONE = "4111 1111 1111 1111", "meera.synthetic@example.org", "98765 43210"  # synthetic
TEXT = f"Card {CARD}, mail {EMAIL}, call {PHONE}. Version 2.4.1.0"
VAULT_VALUES = ["zl.user@example.net", "Zen-Synth-9931", "604215", "5555 5555 5555 4444", "913"]


@pytest.fixture
def client():
    return TestClient(srv.create_app(), base_url=BASE)


@pytest.fixture
def lan():
    return TestClient(srv.create_app(lan=True, token="pair-token-123"), base_url="http://192.168.1.20:8765")


def _png(lines=("Order 4412 (synthetic)", f"Card {CARD}"), size=(900, 200)):
    from PIL import Image, ImageDraw, ImageFont
    im = Image.new("RGB", size, "white")
    d = ImageDraw.Draw(im)
    try:
        f = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial.ttf", 32)
    except OSError:
        f = ImageFont.load_default(size=32)
    for i, t in enumerate(lines):
        d.text((30, 30 + 70 * i), t, fill="black", font=f)
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


# ---------------------------------------------------------------- health / static
def test_health_shape(client):
    j = client.get("/api/health").json()
    assert j["ok"] is True and isinstance(j["version"], str)
    assert set(j["features"]) == {"ocr", "playwright", "claude"} and all(isinstance(v, bool) for v in j["features"].values())


def test_local_only_disables_claude_feature():
    c = TestClient(srv.create_app(local_only=True), base_url=BASE)
    assert c.get("/api/health").json()["features"]["claude"] is False


def test_pwa_shell_served_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "ZenLens" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert "connect-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/sw.js").headers["content-type"].startswith("text/javascript")
    m = client.get("/manifest.webmanifest").json()
    assert m["display"] == "standalone" and m["icons"]
    for p in ("/app.js", "/app.css", "/icons/icon-192.png", "/icons/icon-512.png", "/icons/icon.svg"):
        assert client.get(p).status_code == 200, p


def test_static_has_no_external_urls():
    import re
    from pathlib import Path
    for f in Path(srv.STATIC).rglob("*"):
        if f.suffix in (".html", ".js", ".css", ".webmanifest"):
            assert not re.search(r"(?:src|href)=[\"']https?://|url\(https?://|import .*https?://", f.read_text()), f


def test_unknown_api_is_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and "error" in r.json()


# ---------------------------------------------------------------- /api/sanitize
def test_sanitize_contract_and_no_values(client):
    j = client.post("/api/sanitize", json={"text": TEXT}).json()
    assert set(j) == {"sanitized", "findings", "counts"}
    assert CARD not in j["sanitized"] and EMAIL not in j["sanitized"] and "[REDACTED:CARD]" in j["sanitized"]
    assert "2.4.1.0" in j["sanitized"]
    assert j["counts"] == {"CARD": 1, "EMAIL": 1, "PHONE": 1}
    for f in j["findings"]:
        assert set(f) == {"start", "end", "kind"} and isinstance(f["start"], int)
    assert [TEXT[f["start"]:f["end"]] for f in j["findings"]] == [CARD, EMAIL, PHONE]
    blob = json.dumps(j["findings"]) + json.dumps(j["counts"])
    assert CARD not in blob and EMAIL not in blob and PHONE not in blob


def test_sanitize_offsets_are_code_points(client):
    t = f"\U0001F600 {EMAIL}"
    f = client.post("/api/sanitize", json={"text": t}).json()["findings"][0]
    assert t[f["start"]:f["end"]] == EMAIL  # Python str indices = code points; the PWA slices with Array.from


def test_sanitize_extra_rules(client):
    t = "Ticket for EMP-123456 and EMP-654321"
    j = client.post("/api/sanitize", json={"text": t, "extra_rules": [{"kind": "emp_id", "pattern": r"EMP-\d{6}"}]}).json()
    assert j["sanitized"] == "Ticket for [REDACTED:EMP_ID] and [REDACTED:EMP_ID]" and j["counts"] == {"EMP_ID": 2}


def test_extra_rules_do_not_override_builtin_spans(client):
    j = client.post("/api/sanitize", json={"text": f"mail {EMAIL}", "extra_rules": [{"kind": "X", "pattern": "example"}]}).json()
    assert j["counts"] == {"EMAIL": 1}


@pytest.mark.parametrize("rules,why", [
    ([{"kind": "A", "pattern": "("}], "not a valid regex"),
    ([{"kind": "A", "pattern": "x*"}], "empty string"),
    ([{"kind": "A", "pattern": "(a+)+$"}], "nested quantifiers"),
    ([{"kind": "1BAD", "pattern": "abc"}], "kind"),
    ([{"kind": "A", "pattern": ""}], "empty"),
    ([{"kind": f"K{i}", "pattern": "abc"} for i in range(21)], "too many"),
])
def test_extra_rules_validation(client, rules, why):
    r = client.post("/api/sanitize", json={"text": "abc", "extra_rules": rules})
    assert r.status_code == 422 and why in r.json()["error"]


def test_extra_rule_pattern_length_capped_and_not_echoed(client):
    r = client.post("/api/sanitize", json={"text": "abc", "extra_rules": [{"kind": "A", "pattern": "Z" * 201}]})
    assert r.status_code == 422 and "Z" * 50 not in r.text


def test_validation_errors_never_echo_input(client):
    r = client.post("/api/sanitize", json={"text": CARD * 20000})  # over MAX_TEXT
    assert r.status_code == 422 and CARD not in r.text


# ---------------------------------------------------------------- /api/sanitize_html
def test_sanitize_html_contract(client):
    html = (f'<form><label for="cc">Card number</label><input id="cc" autocomplete="cc-number" value="{CARD}">'
            f'<input id="pw" type="password" value="Synth3tic!Pass"><p id="m">{EMAIL}</p></form>')
    j = client.post("/api/sanitize_html", json={"html": html}).json()
    assert set(j) == {"html", "findings", "counts"}
    assert CARD not in j["html"] and "Synth3tic!Pass" not in j["html"] and EMAIL not in j["html"]
    assert j["counts"].get("CARD") and j["counts"].get("PASSWORD") and j["counts"].get("EMAIL")
    for f in j["findings"]:
        assert set(f) == {"elem_id", "kind", "reason"}
    blob = json.dumps(j["findings"])
    assert CARD not in blob and "Synth3tic" not in blob and EMAIL not in blob


# ---------------------------------------------------------------- /api/gate
def test_gate(client):
    assert client.post("/api/gate", json={"payload": "click the blue button"}).json() == {"allowed": True, "reason": None}
    j = client.post("/api/gate", json={"payload": f"pay with {CARD}"}).json()
    assert j["allowed"] is False and "CARD" in j["reason"] and CARD not in j["reason"]
    j = client.post("/api/gate", json={"payload": "EMP-123456", "extra_rules": [{"kind": "EMP", "pattern": r"EMP-\d+"}]}).json()
    assert j == {"allowed": False, "reason": "blocked, detected: EMP"}


# ---------------------------------------------------------------- /api/redact_image
def test_redact_image_fail_closed_on_ocr_error(client, monkeypatch):
    from zenlens import screenshot as ss

    def boom(*a, **k):
        raise ss.RedactionError("no local OCR backend")
    monkeypatch.setattr(ss, "redact_image", boom)
    png = _png()
    r = client.post("/api/redact_image", files={"image": ("a.png", png, "image/png")})
    assert r.status_code == 422 and r.headers["content-type"].startswith("application/json")
    assert "error" in r.json() and png[:64] not in r.content and "X-ZenLens-Redactions" not in r.headers


def test_redact_image_fail_closed_on_unexpected_error(client, monkeypatch):
    from zenlens import screenshot as ss
    monkeypatch.setattr(ss, "redact_image", lambda *a, **k: 1 / 0)
    r = client.post("/api/redact_image", files={"image": ("a.png", _png(), "image/png")})
    assert r.status_code == 422 and r.headers["content-type"].startswith("application/json")


def test_redact_image_rejects_non_images(client):
    r = client.post("/api/redact_image", files={"image": ("a.txt", b"hello " * 10, "text/plain")})
    assert r.status_code == 415


def test_redact_image_contract_with_stub(client, monkeypatch):
    from zenlens import screenshot as ss
    seen = {}

    def fake(png, faces=False, extra_boxes=()):
        seen["faces"] = faces
        return b"\x89PNG\r\n\x1a\nREDACTED", [ss.Redaction((1, 2, 3, 4), "CARD")]
    monkeypatch.setattr(ss, "redact_image", fake)
    r = client.post("/api/redact_image", files={"image": ("a.png", _png(), "image/png")}, data={"faces": "true"})
    assert r.status_code == 200 and r.headers["content-type"] == "image/png" and r.content.endswith(b"REDACTED")
    assert json.loads(r.headers["X-ZenLens-Redactions"]) == [{"box": [1, 2, 3, 4], "kind": "CARD"}]
    assert seen["faces"] is True


@pytest.mark.skipif(not __import__("zenlens.screenshot", fromlist=["x"]).available_backend(), reason="no local OCR")
def test_redact_image_real_ocr(client):
    png = _png()
    r = client.post("/api/redact_image", files={"image": ("a.png", png, "image/png")})
    assert r.status_code == 200 and r.content != png
    kinds = [b["kind"] for b in json.loads(r.headers["X-ZenLens-Redactions"])]
    assert "CARD" in kinds


# ---------------------------------------------------------------- token / host / CORS / limits
def test_lan_requires_token_on_posts(lan):
    assert lan.get("/api/health").status_code == 200  # GETs carry no data
    assert lan.post("/api/sanitize", json={"text": "x"}).status_code == 401
    assert lan.post("/api/sanitize", json={"text": "x"}, headers={"X-ZenLens-Token": "wrong"}).status_code == 401
    r = lan.post("/api/sanitize", json={"text": "x"}, headers={"X-ZenLens-Token": "pair-token-123"})
    assert r.status_code == 200
    assert lan.post("/api/redact_image", files={"image": ("a.png", b"x", "image/png")}).status_code == 401


def test_localhost_mode_needs_no_token_but_rejects_foreign_host(client):
    assert client.post("/api/sanitize", json={"text": "x"}).status_code == 200
    r = client.post("/api/sanitize", json={"text": "x"}, headers={"Host": "evil.example"})
    assert r.status_code == 403  # DNS-rebinding guard


def test_cors_extension_preflight_and_response(client):
    r = client.options("/api/sanitize", headers={"Origin": EXT, "Access-Control-Request-Method": "POST",
                                                 "Access-Control-Request-Headers": "content-type,x-zenlens-token"})
    assert r.status_code == 204 and r.headers["access-control-allow-origin"] == EXT
    assert "x-zenlens-token" in r.headers["access-control-allow-headers"].lower()
    r = client.post("/api/sanitize", json={"text": "x"}, headers={"Origin": EXT})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == EXT
    assert "X-ZenLens-Redactions" in r.headers["access-control-expose-headers"]


def test_cors_refuses_other_origins(client):
    for o in ("https://evil.example", "http://localhost:3000", "null"):
        assert client.options("/api/sanitize", headers={"Origin": o, "Access-Control-Request-Method": "POST"}).status_code == 403
        r = client.post("/api/sanitize", json={"text": "x"}, headers={"Origin": o})
        assert r.status_code == 403 and "access-control-allow-origin" not in r.headers


def test_same_origin_allowed_without_cors_headers(client):
    r = client.post("/api/sanitize", json={"text": "x"}, headers={"Origin": BASE})
    assert r.status_code == 200 and "access-control-allow-origin" not in r.headers


def test_lan_401_still_readable_by_extension(lan):
    r = lan.post("/api/sanitize", json={"text": "x"}, headers={"Origin": EXT})
    assert r.status_code == 401 and r.headers["access-control-allow-origin"] == EXT


def test_body_size_limit(client):
    r = client.post("/api/sanitize", content=b"{" + b" " * (srv.MAX_JSON + 10) + b"}",
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_access_log_filter_drops_query_strings():
    import logging
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                            ("1.2.3.4:1", "GET", "/x?card=4111", "1.1", 200), None)
    srv._NoBodies().filter(rec)
    assert "4111" not in rec.getMessage()


def test_cli_qr_and_lan_ip():
    assert srv.lan_ip()
    q = srv.ascii_qr("http://192.168.1.20:8765/#token=abc")
    assert q is None or len(q.splitlines()) > 10


# ---------------------------------------------------------------- runner-backed endpoints
def test_runner_missing_gives_503(client, monkeypatch):
    real = srv.importlib.import_module

    def fake(name, *a, **k):
        if name == "zenlens.runner":
            raise ImportError("missing")
        return real(name, *a, **k)
    monkeypatch.setattr(srv.importlib, "import_module", fake)
    r = client.post("/api/preview", json={"url": "checkout"})
    assert r.status_code == 503 and "runner" in r.json()["error"]
    r = client.post("/api/agent/run", json={"goal": "g", "url": "auth", "mode": "scripted", "auto_approve": False})
    assert r.status_code == 503


def test_target_validation(client):
    assert client.post("/api/preview", json={"url": "file:///etc/passwd"}).status_code == 422
    assert client.post("/api/preview", json={"url": "no_such_page"}).status_code == 404
    r = client.post("/api/agent/run", json={"goal": "g", "url": "auth", "mode": "gpt", "auto_approve": False})
    assert r.status_code == 422


def test_claude_mode_refused_when_local_only():
    c = TestClient(srv.create_app(local_only=True), base_url=BASE)
    r = c.post("/api/agent/run", json={"goal": "g", "url": "auth", "mode": "claude", "auto_approve": False})
    assert r.status_code == 403 and "local-only" in r.json()["error"]


def test_invalid_script_rejected(client):
    if importlib.util.find_spec("zenlens.runner") is None:
        pytest.skip("zenlens.runner not present")
    r = client.post("/api/agent/run", json={"goal": "g", "url": "auth", "mode": "scripted", "script": [{"nope": 1}],
                                            "auto_approve": False})
    assert r.status_code == 422


def _need_browser():
    if importlib.util.find_spec("zenlens.runner") is None:
        pytest.skip("zenlens.runner not present")
    pytest.importorskip("playwright")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch().close()
    except Exception as e:
        pytest.skip(f"chromium unavailable: {type(e).__name__}")


def test_preview_bundled_page(client):
    _need_browser()
    j = client.post("/api/preview", json={"url": "checkout"}).json()
    assert j["view"]["elements"] and sum(j["redactions"].values()) >= 5
    assert j["url"].startswith("http://localhost:")
    assert j["screenshot"] is None or isinstance(j["screenshot"], str)
    truth = [i["value"] for i in json.loads((srv.TESTPAGES / "checkout.truth.json").read_text())["items"] if i["value"]]
    j.pop("screenshot")
    blob = json.dumps(j)
    assert [v for v in truth if v in blob] == []


def test_agent_run_presets_and_egress_panel(client):
    _need_browser()
    presets = client.get("/api/demo_scripts").json()["presets"]
    if "auth" not in presets:
        pytest.skip("demo presets unavailable")
    p = presets["auth"]
    r = client.post("/api/agent/run", json={"goal": p["goal"], "url": "auth", "mode": "scripted", "script": p["script"],
                                            "auto_approve": True})
    j = r.json()
    assert r.status_code == 200 and j["status"] == "done" and j["llm"] == "scripted"
    assert any(s["verdict"] == "rejected" for s in j["steps"]) and any(s["verdict"] == "ok" for s in j["steps"])
    eg = j["egress"]
    assert eg["sent_to_third_party"] is False and len(eg["payloads"]) == len(j["steps"])
    assert all("elements" in pl and "goal" in pl for pl in eg["payloads"])
    blob = json.dumps(j)
    assert [v for v in VAULT_VALUES if v in blob] == [] and "{{SECRET:login_password}}" in blob
    truth = [i["value"] for i in json.loads((srv.TESTPAGES / "auth.truth.json").read_text())["items"] if i["value"]]
    assert [v for v in truth if v in blob] == []


def test_agent_run_default_deny_without_approval(client):
    _need_browser()
    p = client.get("/api/demo_scripts").json()["presets"].get("checkout")
    if not p:
        pytest.skip("demo presets unavailable")
    j = client.post("/api/agent/run", json={"goal": p["goal"], "url": "checkout", "mode": "scripted",
                                            "script": p["script"], "auto_approve": False}).json()
    acts = [s for s in j["steps"] if s["verdict"] != "done"]
    assert acts and all(s["verdict"] == "rejected" for s in acts)
