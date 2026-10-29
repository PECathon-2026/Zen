"""PlaywrightPage: executor.Page over a live capture.Session. ids -> locators stay local; elements() is sanitized.

Re-snapshots after every action. Real values exist only in the live DOM and the raw snapshot; never logged or raised.
"""
import re
from dataclasses import replace
from urllib.parse import urljoin

from .capture import PageSnapshot, Session, sanitized_view, to_url
from .executor import field_kind, origin
from .pseudonym import TOKEN

# capture/structural kinds -> executor/vault field kinds (secret kinds only accept matching vault placeholders)
FIELD_KIND = {"PASSWORD": "password", "PIN": "password", "API_KEY": "password", "TOKEN": "password",
              "SECRET": "password", "OTP": "otp", "CARD": "card", "CVV": "card", "CARD_EXP": "card", "EMAIL": "email"}
_REDACTED = re.compile(r"\[REDACTED:([A-Z_]+)\]")


def redaction_counts(view: dict) -> dict[str, int]:
    """kind -> number of [REDACTED:KIND] placeholders (and [KIND_n] pseudonym tokens) in a sanitized view."""
    out: dict[str, int] = {}
    for e in view.get("elements", []):
        for v in (e.get("text"), e.get("value"), e.get("name"), e.get("placeholder")):
            for k in _REDACTED.findall(v or "") + [m.group(1) for m in TOKEN.finditer(v or "")]:
                out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


class PlaywrightPage:
    """Page protocol over capture.Session. `canaries` (vault values) are masked out of any re-captured text/value,
    so a secret the executor filled never re-enters the view. Navigations to origins outside `allowed_origins`
    are aborted in the browser (backstop for link clicks; the executor already origin-checks navigate).
    With a `pseudonymizer`, the view carries stable tokens ([EMAIL_1]) instead of [REDACTED:KIND]."""

    def __init__(self, session: Session, allowed_origins=(), canaries: tuple[str, ...] = (), pseudonymizer=None,
                 minimize: bool = False):
        self.session, self.canaries = session, tuple(c for c in canaries if c)
        self.pseudonymizer, self.minimize = pseudonymizer, minimize
        self.allowed = {origin(o) or o.lower().rstrip("/") for o in allowed_origins}
        self.snap: PageSnapshot | None = None
        self._view: dict | None = None
        if self.allowed:
            session.page.route("**/*", self._guard)

    def _ok(self, url: str) -> bool:
        return url.startswith(("about:", "data:")) or origin(url) in self.allowed

    def _guard(self, route):
        r = route.request
        if r.is_navigation_request() and not self._ok(r.url):
            route.abort("blockedbyclient")
        else:
            route.continue_()

    def refresh(self) -> PageSnapshot:
        self.snap, self._view = self.session.capture(), None
        return self.snap

    def goto(self, target: str):
        self.session.page.goto(to_url(target), wait_until="load")
        self.refresh()

    def _masked(self) -> PageSnapshot:
        if not self.canaries:
            return self.snap

        def m(s):
            for c in self.canaries:
                if s and c in s:
                    s = s.replace(c, "[REDACTED:SECRET]")
            return s
        return replace(self.snap, elements=[replace(e, value=m(e.value), text=m(e.text), name=m(e.name))
                                            for e in self.snap.elements])

    def view(self) -> dict:
        """Sanitized, egress-checked view (raises gate.Blocked on residue). Elements carry `field_kind`."""
        if self.snap is None:
            self.refresh()
        if self._view is None:
            v = sanitized_view(self._masked(), self.canaries, self.pseudonymizer, minimize=self.minimize)
            for e in v["elements"]:
                e["field_kind"] = FIELD_KIND.get(e.get("sensitive") or "") or field_kind(e)
            self._view = v
        return self._view

    # --- executor.Page protocol ---
    def url(self) -> str:
        return self.session.page.url

    def elements(self) -> list[dict]:
        return [dict(e) for e in self.view()["elements"]]

    def _loc(self, id: str):
        if self.snap is None:
            self.refresh()
        return self.snap.locator_for(id)

    def click(self, id: str) -> None:
        loc = self._loc(id)
        href = loc.get_attribute("href")
        if href and not self._ok(urljoin(self.url(), href)) and not href.startswith("#"):
            raise PermissionError(f"link {id} leads to a disallowed origin")
        try:
            loc.click(timeout=5000)
            self.session.page.wait_for_load_state("load")
        finally:
            self.refresh()

    def fill(self, id: str, text: str) -> None:
        try:
            self._loc(id).fill(text, timeout=5000)
        except Exception as e:  # Playwright messages can echo the value: never chain
            raise RuntimeError(f"fill failed on {id}: {type(e).__name__}") from None
        finally:
            self.refresh()

    def navigate(self, url: str) -> None:
        try:
            self.session.page.goto(url, wait_until="load")
        finally:
            self.refresh()

    def dom_value(self, id: str) -> str:
        """Local-only: the live input value (tests/demo verification). Never send or log it."""
        return self._loc(id).input_value()
