"""Local executor: validates every model Action, asks the user for risky ones (default deny), then acts on the page.

Real secret values exist only inside `run()` between vault.resolve() and page.fill(); they are never logged or raised.
"""
import re
from dataclasses import dataclass
from typing import Callable, Protocol
from urllib.parse import urlsplit

from .detect import detect
from .llm import ACTION_TYPES, Action
from .vault import PLACEHOLDER, Vault, VaultError, secret_name


class Page(Protocol):
    """Sanitized, id-addressed page. capture.py implements this over Playwright (id -> locator stays local)."""
    def url(self) -> str: ...
    def elements(self) -> list[dict]: ...  # {"id","role","tag","label"/"text","type"?,"autocomplete"?}
    def click(self, id: str) -> None: ...
    def fill(self, id: str, text: str) -> None: ...
    def navigate(self, url: str) -> None: ...


class FakePage:
    """In-memory Page for tests. `filled` holds what reached the page (real values, local only)."""

    def __init__(self, url: str, elements: list[dict]):
        self._url, self._els = url, [dict(e) for e in elements]
        self.ops: list[tuple[str, str]] = []
        self.filled: dict[str, str] = {}

    def url(self): return self._url
    def elements(self): return [dict(e) for e in self._els]
    def click(self, id): self.ops.append(("click", id))

    def fill(self, id, text):
        self.ops.append(("fill", id))
        self.filled[id] = text

    def navigate(self, url):
        self.ops.append(("navigate", url))
        self._url = url


class Rejected(Exception):
    """Action refused. Message contains only ids, kinds and placeholder names."""


Approve = Callable[[Action, str], bool]
SENSITIVE_FIELDS = {"password", "otp", "card"}
IRREVERSIBLE = re.compile(r"(?i)\b(submit|pay|purchase|buy|order|checkout|delete|remove|send|transfer|confirm|"
                          r"post|publish|sign ?up|register|unsubscribe|cancel)\b")


def origin(url: str) -> str:
    p = urlsplit(url or "")
    return f"{p.scheme}://{p.netloc}".lower() if p.scheme in ("http", "https") and p.netloc else ""


def field_kind(el: dict) -> str:
    if el.get("field_kind"):  # capture/structural detector may annotate directly
        return el["field_kind"]
    t, ac = (el.get("type") or "").lower(), (el.get("autocomplete") or "").lower()
    lbl = f'{el.get("label") or ""} {el.get("text") or ""} {el.get("name") or ""}'.lower()
    if t == "password" or ac in ("current-password", "new-password"):
        return "password"
    if ac == "one-time-code" or re.search(r"\botp\b|one[- ]time|verification code", lbl):
        return "otp"
    if ac.startswith("cc-") or re.search(r"card number|\bcvv\b|\bcvc\b|expiry", lbl):
        return "card"
    if t == "email" or ac == "email":
        return "email"
    return "text"


def _safe(s) -> str:
    """Echo model-supplied tokens only if they look like ids; anything else could carry a value."""
    return s if isinstance(s, str) and re.fullmatch(r"[A-Za-z_][\w-]{0,15}", s) and not detect(s) else "<invalid>"


def describe(a: Action) -> str:
    """Log-safe one-liner: ids, origins, placeholder names, text length. Never raw text."""
    parts = [_safe(a.type)]
    if a.target:
        parts.append(f"target={_safe(a.target)}")
    if a.text is not None:
        n = secret_name(a.text)
        parts.append(f"text={{{{SECRET:{n}}}}}" if n else f"text=<{len(a.text)} chars>")
    if a.url is not None:
        parts.append(f"url={origin(a.url) or '<invalid>'}")
    return " ".join(parts)


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str = ""
    approval: str = ""  # non-empty => needs user approval, with this reason


class Executor:
    def __init__(self, page: Page, allowed_origins=(), vault: Vault | None = None, approve: Approve | None = None):
        self.page, self.vault, self.approve = page, vault or Vault(), approve
        self.allowed = {origin(o) or o.lower().rstrip("/") for o in allowed_origins}

    def check(self, a: Action, view: dict) -> Verdict:
        if a.type not in ACTION_TYPES:
            return Verdict(False, f"action type not allowed: {_safe(a.type)}")
        if a.type in ("done", "ask_user"):
            return Verdict(True)
        if origin(self.page.url()) not in self.allowed:
            return Verdict(False, "current page origin not allowed")
        if a.type == "navigate":
            o = origin(a.url or "")
            if not o:
                return Verdict(False, "navigate: only http(s) URLs")
            return Verdict(True) if o in self.allowed else Verdict(False, f"navigate: origin not allowed: {o}")
        els = {e.get("id"): e for e in view.get("elements", [])}
        if not a.target or a.target not in els:
            return Verdict(False, f"unknown target: {_safe(a.target)}")
        el = els[a.target]
        if a.type == "click":
            label = f'{el.get("label") or ""} {el.get("name") or ""} {el.get("text") or ""} {el.get("value") or ""}'
            if (el.get("type") or "").lower() == "submit" or IRREVERSIBLE.search(label):
                return Verdict(True, approval=f"irreversible click on {a.target}")
            return Verdict(True)
        return self._check_type(a, el)

    def _check_type(self, a: Action, el: dict) -> Verdict:
        text, fk = a.text, field_kind(el)
        if not isinstance(text, str) or not text:
            return Verdict(False, "type: empty text")
        if PLACEHOLDER.search(text):
            name = secret_name(text)
            if not name:
                return Verdict(False, "type: secret placeholder must be the whole text")
            if name not in self.vault:
                return Verdict(False, f"type: unknown secret {name}")
            sk = self.vault.kind(name)
            if sk != fk:
                return Verdict(False, f"type: {sk} secret {name} not allowed in {fk} field {a.target}")
            return Verdict(True, approval=f"fill secret {name} ({sk}) into {a.target}")
        if "[REDACTED:" in text:
            return Verdict(False, "type: cannot type a redacted value")
        hits = detect(text)
        if hits:
            return Verdict(False, f"type: text contains sensitive data ({', '.join(sorted({h.kind for h in hits}))})")
        if fk in SENSITIVE_FIELDS:
            return Verdict(False, f"type: {fk} field {a.target} requires a vault placeholder")
        return Verdict(True)

    def _approved(self, a: Action, reason: str) -> bool:
        if self.approve is None:
            return False
        try:
            return self.approve(a, reason) is True
        except Exception:
            return False

    def run(self, a: Action, view: dict) -> str:
        v = self.check(a, view)
        if not v.ok:
            raise Rejected(v.reason)
        if v.approval and not self._approved(a, v.approval):
            raise Rejected(f"not approved: {v.approval}")
        try:
            if a.type == "click":
                self.page.click(a.target)
            elif a.type == "type":
                self.page.fill(a.target, self.vault.resolve(a.text))
            elif a.type == "navigate":
                self.page.navigate(a.url)
        except VaultError as e:
            raise Rejected(str(e)) from None
        except Exception as e:  # never chain: the original message could contain the filled value
            raise Rejected(f"{a.type} failed on {a.target or origin(a.url or '')}: {type(e).__name__}") from None
        return "ok"
