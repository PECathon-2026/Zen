"""Redact-before-you-share: manifest share_target, share page + CSP, share-target fallback, --https logic."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from app import server as srv  # noqa: E402
from app import share  # noqa: E402

STATIC = Path(srv.STATIC)
FAKE_IMAGE = b"\x89PNG\r\n\x1a\n" + b"SYNTHETIC-CARD-4111111111111111" * 50


@pytest.fixture
def client():
    return TestClient(srv.create_app(), base_url="http://127.0.0.1:8765")


@pytest.fixture
def lan():
    return TestClient(srv.create_app(lan=True, token="pair-token-123"), base_url="http://192.168.1.20:8765")


# ---------------------------------------------------------------- manifest + service worker
def test_manifest_share_target(client):
    r = client.get("/manifest.webmanifest")
    assert r.status_code == 200
    m = json.loads(r.text)
    st = m["share_target"]
    assert st["action"] == share.SHARE_PATH and st["method"] == "POST"
    assert st["enctype"] == "multipart/form-data"
    files = st["params"]["files"]
    assert files and files[0]["name"] == "image" and "image/*" in files[0]["accept"]
    assert "text" not in st["params"] and "title" not in st["params"]  # shared text is not taken in
    assert m["scope"] == "/" and m["display"] == "standalone"
    assert any(i["sizes"] == "512x512" for i in m["icons"]) and any(i["sizes"] == "192x192" for i in m["icons"])


def test_service_worker_handles_share_post_locally():
    sw = (STATIC / "sw.js").read_text()
    assert "'/share-target'" in sw and "formData()" in sw and "zenlens-share-inbox" in sw
    for f in ("/share.html", "/share.js", "/share.css"):
        assert f"'{f}'" in sw
    assert "fetch(" not in sw.split("async function receiveShare")[1].split("self.addEventListener")[0]


def test_share_js_only_talks_to_local_redact_endpoint():
    js = (STATIC / "share.js").read_text()
    import re
    assert re.findall(r"fetch\(\s*'([^']+)'", js) == ["/api/redact_image"]
    assert "http://" not in js and "https://" not in js
    assert "inbox.delete('/__share-inbox/' + id)" in js  # shared original removed right after reading
    assert "X-ZenLens-Token" in js and "store.get('token'" in js  # reuses the main app's pairing token
    assert "navigator.share" in js and "download" in js


# ---------------------------------------------------------------- share page served with strict CSP
@pytest.mark.parametrize("path,ctype", [("/share.html", "text/html"), ("/share.js", "javascript"),
                                        ("/share.css", "text/css")])
def test_share_assets_served_with_csp(client, path, ctype):
    r = client.get(path)
    assert r.status_code == 200 and ctype in r.headers["content-type"]
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "connect-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"


def test_share_html_has_no_inline_code(client):
    html = client.get("/share.html").text
    import re
    for tag in re.findall(r"<script[^>]*>", html):
        assert "src=" in tag
    assert "<style" not in html and " style=" not in html and "onclick" not in html.lower()
    assert 'href="/share.css"' in html and 'src="/share.js"' in html


# ---------------------------------------------------------------- server-side fallback never touches the image
@pytest.mark.parametrize("which", ["client", "lan"])
def test_share_target_post_redirects_without_echo(request, which, tmp_path, monkeypatch):
    c = request.getfixturevalue(which)
    monkeypatch.chdir(tmp_path)
    r = c.post(share.SHARE_PATH, files={"image": ("s.png", FAKE_IMAGE, "image/png")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/share.html?error=nosw"
    assert r.content == b"" and b"4111" not in r.content
    assert "4111" not in json.dumps(dict(r.headers))
    assert r.headers["cache-control"] == "no-store"
    assert list(tmp_path.iterdir()) == []  # nothing written


def test_share_target_big_body_still_redirects(lan):
    # The share POST can't carry the pairing token and may exceed the JSON cap; it must not 401/413,
    # and it is never read or processed.
    big = b"\xff\xd8\xff" + b"0" * (3 * 1024 * 1024)
    r = lan.post(share.SHARE_PATH, files={"image": ("s.jpg", big, "image/jpeg")}, follow_redirects=False)
    assert r.status_code == 303


def test_share_target_get_redirects(client):
    r = client.get(share.SHARE_PATH, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/share.html"


def test_other_posts_still_need_token(lan):
    assert lan.post("/api/sanitize", json={"text": "hi"}).status_code == 401
    assert lan.post("/share-targetX", files={"image": ("s.png", FAKE_IMAGE, "image/png")}).status_code == 401


# ---------------------------------------------------------------- cert dir never served
def test_cert_dir_outside_static_and_not_served(client):
    assert STATIC.resolve() not in share.CERT_DIR.resolve().parents
    assert share.CERT_DIR.resolve() != STATIC.resolve()
    for p in ("/certs/zenlens-key.pem", "/app/certs/zenlens-key.pem", "/../certs/zenlens-key.pem",
              "/%2e%2e/certs/zenlens-key.pem"):
        r = client.get(p)
        assert r.status_code in (400, 404), p
        assert b"PRIVATE KEY" not in r.content


# ---------------------------------------------------------------- --https / mkcert logic
def _fake_mkcert(calls):
    def run(cmd, **kw):
        calls.append(cmd)
        if "-CAROOT" in cmd:
            return SimpleNamespace(returncode=0, stdout="/fake/caroot\n", stderr="")
        cert = Path(cmd[cmd.index("-cert-file") + 1])
        key = Path(cmd[cmd.index("-key-file") + 1])
        cert.write_text("CERT")
        key.write_text("KEY")
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    return run


def test_https_with_mkcert_issues_cert_for_lan_ip(tmp_path):
    calls = []
    cert, key, msg = share.resolve_tls(https=True, cert=None, key=None, lan_ip="192.168.1.20",
                                       cert_dir=tmp_path / "certs", mkcert="/usr/local/bin/mkcert",
                                       run=_fake_mkcert(calls))
    assert Path(cert).read_text() == "CERT" and Path(key).read_text() == "KEY"
    assert calls[0][0] == "/usr/local/bin/mkcert"
    assert calls[0][-4:] == ["localhost", "127.0.0.1", "::1", "192.168.1.20"]
    assert (Path(key).stat().st_mode & 0o077) == 0
    assert "192.168.1.20" in msg
    # reused while the IP is unchanged ...
    share.resolve_tls(https=True, cert=None, key=None, lan_ip="192.168.1.20", cert_dir=tmp_path / "certs",
                      mkcert="/usr/local/bin/mkcert", run=_fake_mkcert(calls))
    assert len(calls) == 1
    # ... and reissued when the phone network gives the laptop a new IP
    share.resolve_tls(https=True, cert=None, key=None, lan_ip="10.0.0.7", cert_dir=tmp_path / "certs",
                      mkcert="/usr/local/bin/mkcert", run=_fake_mkcert(calls))
    assert len(calls) == 2 and calls[1][-1] == "10.0.0.7"


def test_https_without_mkcert_explains_install(tmp_path, monkeypatch):
    monkeypatch.setattr(share.shutil, "which", lambda name: None)
    with pytest.raises(share.TLSSetupError) as e:
        share.resolve_tls(https=True, cert=None, key=None, lan_ip="192.168.1.20", cert_dir=tmp_path)
    assert "brew install mkcert" in str(e.value) and "--cert" in str(e.value)
    assert not any(tmp_path.iterdir())


def test_explicit_cert_wins_and_plain_http_default(tmp_path, monkeypatch):
    monkeypatch.setattr(share.shutil, "which", lambda name: None)
    assert share.resolve_tls(https=True, cert="c.pem", key="k.pem", lan_ip=None)[:2] == ("c.pem", "k.pem")
    assert share.resolve_tls(https=False, cert=None, key=None, lan_ip=None) == (None, None, "")
    with pytest.raises(share.TLSSetupError):
        share.resolve_tls(https=False, cert="c.pem", key=None, lan_ip=None)


def test_mkcert_failure_is_reported(tmp_path):
    def run(cmd, **kw):
        return SimpleNamespace(returncode=1, stdout="", stderr="ERROR: failed to read the CA key\n")
    with pytest.raises(share.TLSSetupError, match="exit 1"):
        share.ensure_mkcert_cert("192.168.1.20", cert_dir=tmp_path, mkcert="mkcert", run=run)


def test_bad_lan_ip_rejected(tmp_path):
    with pytest.raises(share.TLSSetupError):
        share.ensure_mkcert_cert("not-an-ip; rm -rf /", cert_dir=tmp_path, mkcert="mkcert", run=_fake_mkcert([]))


def test_main_https_missing_mkcert_exits_2(monkeypatch, capsys):
    monkeypatch.setattr(share.shutil, "which", lambda name: None)
    monkeypatch.setattr(srv, "lan_ip", lambda: "192.168.1.20")
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start without TLS"))
    assert srv.main(["--lan", "--https"]) == 2
    assert "brew install mkcert" in capsys.readouterr().err


def test_main_https_with_mkcert_passes_cert_to_uvicorn(monkeypatch, tmp_path, capsys):
    calls, got = [], {}
    monkeypatch.setattr(share.shutil, "which", lambda name: "/opt/mkcert")
    monkeypatch.setattr(share, "CERT_DIR", tmp_path)
    monkeypatch.setattr(share.subprocess, "run", _fake_mkcert(calls))
    monkeypatch.setattr(share.resolve_tls, "__kwdefaults__",
                        {**share.resolve_tls.__kwdefaults__, "cert_dir": tmp_path, "run": _fake_mkcert(calls)})
    monkeypatch.setattr(share.mkcert_caroot, "__defaults__", (None, _fake_mkcert(calls)))
    monkeypatch.setattr(srv, "lan_ip", lambda: "192.168.1.20")
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: got.update(kw))
    srv.main(["--lan", "--https", "--token", "tok-123456"])
    assert got["ssl_certfile"] == str(tmp_path / share.CERT_FILE)
    assert got["ssl_keyfile"] == str(tmp_path / share.KEY_FILE)
    out = capsys.readouterr().out
    assert "https://192.168.1.20:8765/#token=tok-123456" in out
    assert "/fake/caroot/rootCA.pem" in out and "Web Share Target" in out
