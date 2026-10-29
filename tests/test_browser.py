"""PlaywrightPage over real headless Chromium on testpages served from localhost."""
import json

import pytest

from zenlens.executor import Executor, Rejected
from zenlens.llm import Action
from zenlens.vault import Vault

pytest.importorskip("playwright")
from demo.serve import start  # noqa: E402
from zenlens.browser import PlaywrightPage  # noqa: E402
from zenlens.capture import Session  # noqa: E402

PW, NOTE = "Zen-Synth-9931", "zl-note-58213-synthetic"  # synthetic


@pytest.fixture(scope="module")
def base():
    srv, url = start()
    yield url
    srv.shutdown()


@pytest.fixture
def session():
    try:
        with Session() as s:
            yield s
    except Exception as e:  # chromium binary missing
        pytest.skip(f"chromium unavailable: {e}")


def _ids(page):
    """dom-id -> view id, read locally from the live DOM (test-only)."""
    return {page.snap.page.locator(f'[data-zl-id="{e.id}"]').get_attribute("id"): e.id for e in page.snap.elements}


def test_elements_sanitized_with_field_kind(base, session):
    p = PlaywrightPage(session, [base])
    p.goto(base + "/checkout.html")
    ids, els = _ids(p), {e["id"]: e for e in p.elements()}
    assert els[ids["cc-number"]]["field_kind"] == "card" and els[ids["f3"]]["field_kind"] == "card"  # CVV
    assert els[ids["pay"]]["type"] == "submit"
    dumped = json.dumps(p.elements())
    assert "4111 1111 1111 1111" not in dumped and "737" not in dumped and "Checkout" in dumped
    p.goto(base + "/auth.html")
    ids, els = _ids(p), {e["id"]: e for e in p.elements()}
    kinds = {d: els[ids[d]]["field_kind"] for d in ("login-email", "login-password", "otp-input", "upi-pin")}
    assert kinds == {"login-email": "email", "login-password": "password", "otp-input": "otp", "upi-pin": "password"}


def test_secret_reaches_dom_not_view(base, session):
    vault = Vault({"login_password": PW})
    p = PlaywrightPage(session, [base], vault.canaries())
    p.goto(base + "/auth.html")
    pw = _ids(p)["login-password"]
    ex = Executor(p, [base], vault, approve=lambda a, r: True)
    assert ex.run(Action("type", target=pw, text="{{SECRET:login_password}}"), {"elements": p.elements()}) == "ok"
    assert p.dom_value(pw) == PW  # arrived in the real input
    assert PW not in json.dumps(p.view()) and _ids(p)["login-password"] == pw  # re-snapshot keeps ids stable


def test_canary_masked_in_unflagged_field(base, session):
    vault = Vault({"note": ("text", NOTE)})
    p = PlaywrightPage(session, [base], vault.canaries())
    p.goto(base + "/injection.html")
    c = _ids(p)["comment"]
    Executor(p, [base], vault, approve=lambda a, r: True).run(
        Action("type", target=c, text="{{SECRET:note}}"), {"elements": p.elements()})
    assert p.dom_value(c) == NOTE
    el = next(e for e in p.elements() if e["id"] == c)
    assert el["value"] == "[REDACTED:SECRET]" and NOTE not in json.dumps(p.view())


def test_offsite_link_and_navigation_blocked(base, session):
    p = PlaywrightPage(session, [base])
    p.goto(base + "/injection.html")
    with pytest.raises(PermissionError):
        p.click(_ids(p)["phish"])
    with pytest.raises(Exception):
        p.navigate("https://evil.example/collect")  # aborted inside the browser
    assert not p.url().startswith("https://evil.example")


def test_fill_failure_does_not_echo_value(base, session):
    p = PlaywrightPage(session, [base])
    p.goto(base + "/auth.html")
    ex = Executor(p, [base], Vault({"login_password": PW}), approve=lambda a, r: True)
    h1 = next(e["id"] for e in p.elements() if e["tag"] == "h1")
    view = {"elements": [dict(e, field_kind="password") if e["id"] == h1 else e for e in p.elements()]}
    with pytest.raises(Rejected) as ei:
        ex.run(Action("type", target=h1, text="{{SECRET:login_password}}"), view)
    assert PW not in str(ei.value) and ei.value.__cause__ is None
