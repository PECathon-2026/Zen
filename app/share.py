"""Redact-before-you-share: Web Share Target plumbing + HTTPS (mkcert) helpers for the PWA.

Flow (Android, installed PWA): Gallery -> Share -> Zen. Chrome POSTs the image (multipart) to
SHARE_PATH; the service worker (static/sw.js) intercepts that POST, stashes the file in Cache Storage
under a random id and redirects to /share.html?id=... . share.js reads the file, deletes the stash at
once, sends it only to this server's /api/redact_image and offers the redacted PNG to the share sheet.

Server side there is deliberately no upload handler: if a share POST ever reaches the server (service
worker not active yet), `ShareFallback` answers with a redirect WITHOUT reading the body, so the image
is never parsed, stored, logged or echoed. It runs outside the token guard because Chrome's share
POST cannot carry X-Zen-Token; it never does any work with the request, so nothing is exposed.

HTTPS: Android Chrome only installs a PWA (and only then offers it as a share target) from a trusted
secure context. `--https` uses mkcert (a local CA you install on the phone) to issue a cert for the LAN
IP + localhost into CERT_DIR (outside static/, so it is never served).
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from pathlib import Path

SHARE_PATH = "/share-target"
CERT_DIR = Path(__file__).resolve().parent / "certs"
CERT_FILE, KEY_FILE, HOSTS_FILE = "zenlens.pem", "zenlens-key.pem", "hosts.txt"


# ---------------------------------------------------------------- share-target fallback (ASGI)
class ShareFallback:
    """Pure ASGI middleware: any request to SHARE_PATH gets a 303 to /share.html, body unread.

    GET (someone opened the URL) -> /share.html ; POST without a service worker -> /share.html?error=nosw
    so the page can explain "open Zen once, then share again"."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("path") != SHARE_PATH:
            return await self.app(scope, receive, send)
        loc = "/share.html?error=nosw" if scope.get("method") == "POST" else "/share.html"
        await send({"type": "http.response.start", "status": 303, "headers": [
            (b"location", loc.encode()), (b"cache-control", b"no-store"), (b"content-length", b"0"),
            (b"referrer-policy", b"no-referrer"), (b"x-content-type-options", b"nosniff")]})
        await send({"type": "http.response.body", "body": b""})


def install(app) -> None:
    """Call from create_app (before the static mount). Adds the share-target fallback."""
    app.add_middleware(ShareFallback)


# ---------------------------------------------------------------- HTTPS via mkcert
class TLSSetupError(RuntimeError):
    pass


MKCERT_MISSING = """\
--https needs mkcert (a tiny local certificate authority). It is not installed.
  macOS:   brew install mkcert            (Linux: apt install mkcert / see github.com/FiloSottile/mkcert)
  then:    mkcert -install                (trusts the CA on this computer)
Or bring your own certificate:  python -m app.server --lan --cert CERT.pem --key KEY.pem
(A self-signed cert you click through is NOT enough on Android: Chrome will not register the service
worker or install the app on a certificate error. The CA must be installed on the phone.)"""


def mkcert_path() -> str | None:
    return shutil.which("mkcert")


def _hosts_for(lan_ip: str | None) -> list[str]:
    hosts = ["localhost", "127.0.0.1", "::1"]
    if lan_ip:
        try:
            ipaddress.ip_address(lan_ip)
        except ValueError:
            raise TLSSetupError(f"not an IP address: {lan_ip!r}") from None
        if lan_ip not in hosts:
            hosts.append(lan_ip)
    return hosts


def ensure_mkcert_cert(lan_ip: str | None, cert_dir: Path = CERT_DIR, mkcert: str | None = None,
                       run=subprocess.run) -> tuple[Path, Path]:
    """Return (cert, key) for localhost + lan_ip, (re)issuing with mkcert when missing or the IP changed."""
    mkcert = mkcert or mkcert_path()
    if not mkcert:
        raise TLSSetupError(MKCERT_MISSING)
    hosts = _hosts_for(lan_ip)
    cert, key, stamp = cert_dir / CERT_FILE, cert_dir / KEY_FILE, cert_dir / HOSTS_FILE
    if cert.is_file() and key.is_file() and stamp.is_file() and stamp.read_text().split() == hosts:
        return cert, key
    cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    r = run([mkcert, "-cert-file", str(cert), "-key-file", str(key), *hosts],
            capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not cert.is_file() or not key.is_file():
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["no output"]
        raise TLSSetupError(f"mkcert failed (exit {r.returncode}): {tail[0]}")
    key.chmod(0o600)
    stamp.write_text(" ".join(hosts) + "\n")
    return cert, key


def mkcert_caroot(mkcert: str | None = None, run=subprocess.run) -> str | None:
    mkcert = mkcert or mkcert_path()
    if not mkcert:
        return None
    try:
        r = run([mkcert, "-CAROOT"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() or None if r.returncode == 0 else None


def phone_steps(url: str, caroot: str | None) -> str:
    ca = f"{caroot}/rootCA.pem" if caroot else "$(mkcert -CAROOT)/rootCA.pem"
    return f"""\
  Phone setup (Android, once):
    1. Copy {ca} to the phone (rename to zenlens-rootCA.crt).
       Never copy rootCA-key.pem anywhere.
    2. Settings > Security & privacy > More security settings > Encryption & credentials >
       Install a certificate > CA certificate > pick the file. (Remove it there when you are done.)
    3. Open {url} in Chrome, then menu > Install app (or Add to Home screen).
    4. In Gallery/Photos: Share > Zen > Share redacted.
  iPhone/iPad: iOS Safari has no Web Share Target, so Zen will not appear in the share sheet.
    Open Zen > "Redact a photo" (/share.html) and pick the image; sharing the result still works.
    (For https on iOS install the same rootCA via Settings > General > VPN & Device Management, then
    enable it in Settings > General > About > Certificate Trust Settings.)"""


def resolve_tls(*, https: bool, cert: str | None, key: str | None, lan_ip: str | None,
                cert_dir: Path = CERT_DIR, mkcert: str | None = None, run=subprocess.run
                ) -> tuple[str | None, str | None, str]:
    """Decide which cert/key uvicorn gets. Returns (cert, key, message to print).

    Explicit --cert/--key always win. --https: mkcert if installed, else raise TLSSetupError with the
    install command (caller exits non-zero rather than silently serving plain HTTP)."""
    if bool(cert) != bool(key):
        raise TLSSetupError("--cert and --key must be given together")
    if cert:
        return cert, key, "  TLS: using the certificate from --cert/--key"
    if not https:
        return None, None, ""
    mk = mkcert or mkcert_path()
    if not mk:
        raise TLSSetupError(MKCERT_MISSING)
    c, k = ensure_mkcert_cert(lan_ip, cert_dir=cert_dir, mkcert=mk, run=run)
    return str(c), str(k), f"  TLS: mkcert certificate for {', '.join(_hosts_for(lan_ip))} ({c.parent})"
