import pytest

from zenlens.executor import Executor, FakePage, Rejected, describe, field_kind
from zenlens.llm import Action
from zenlens.vault import Vault

PW = "Synth-Pass-4471"  # synthetic
ORIGIN = "http://localhost:8000"
ELS = [
    {"id": "e1", "role": "textbox", "tag": "input", "label": "Email", "type": "email"},
    {"id": "e2", "role": "textbox", "tag": "input", "label": "Password:", "type": "password"},
    {"id": "e3", "role": "textbox", "tag": "input", "label": "One-time code", "autocomplete": "one-time-code"},
    {"id": "e4", "role": "textbox", "tag": "textarea", "label": "Comment"},
    {"id": "e5", "role": "button", "tag": "button", "label": "Pay now"},
    {"id": "e6", "role": "link", "tag": "a", "label": "Help"},
    {"id": "e7", "role": "textbox", "tag": "input", "label": "Card number", "autocomplete": "cc-number"},
]


def mk(approve=None):
    page = FakePage(ORIGIN + "/checkout", ELS)
    vault = Vault({"login_password": PW, "work_email": "demo.user@example.test"})
    return page, Executor(page, [ORIGIN], vault, approve)


def view(page):
    return {"url": page.url(), "elements": page.elements()}


def reject(ex, page, a):
    with pytest.raises(Rejected) as e:
        ex.run(a, view(page))
    assert PW not in str(e.value)
    return str(e.value)


def test_field_kinds():
    assert [field_kind(e) for e in ELS] == ["email", "password", "otp", "text", "text", "text", "card"]


def test_allowlist_and_targets():
    page, ex = mk()
    assert "not allowed" in reject(ex, page, Action("eval", target="e1"))
    assert "unknown target" in reject(ex, page, Action("click", target="e99"))
    assert "unknown target" in reject(ex, page, Action("click"))
    assert ex.run(Action("click", target="e6"), view(page)) == "ok" and page.ops == [("click", "e6")]


def test_navigate_origins():
    page, ex = mk()
    assert "origin not allowed" in reject(ex, page, Action("navigate", url="https://evil.example/x"))
    assert "http(s)" in reject(ex, page, Action("navigate", url="javascript:alert(1)"))
    assert "origin not allowed" in reject(ex, page, Action("navigate", url="http://localhost:8000.evil.example/"))
    ex.run(Action("navigate", url=ORIGIN + "/other"), view(page))
    assert page.url() == ORIGIN + "/other"


def test_acting_on_disallowed_current_origin():
    page, ex = mk()
    page.navigate("https://evil.example/")
    assert "current page origin" in reject(ex, page, Action("click", target="e6"))


def test_type_plain_and_sensitive_text():
    page, ex = mk()
    assert ex.run(Action("type", target="e4", text="Thanks, that worked"), view(page)) == "ok"
    assert "EMAIL" in reject(ex, page, Action("type", target="e4", text="mail me at someone@example.test"))
    assert "PHONE" in reject(ex, page, Action("type", target="e4", text="call 9876543210"))
    assert "redacted" in reject(ex, page, Action("type", target="e4", text="[REDACTED:EMAIL]"))
    assert "requires a vault placeholder" in reject(ex, page, Action("type", target="e2", text="hunter2"))
    assert "requires a vault placeholder" in reject(ex, page, Action("type", target="e3", text="code"))
    assert "empty" in reject(ex, page, Action("type", target="e4", text=""))


def test_secret_rules_and_approval():
    page, ex = mk()
    a = Action("type", target="e2", text="{{SECRET:login_password}}")
    assert "not approved" in reject(ex, page, a)  # default deny
    assert page.filled == {}
    assert "not allowed in text field" in reject(ex, page, Action("type", target="e4", text=a.text))
    assert "not allowed in card field" in reject(ex, page, Action("type", target="e7", text=a.text))
    assert "whole text" in reject(ex, page, Action("type", target="e2", text="x{{SECRET:login_password}}"))
    assert "unknown secret" in reject(ex, page, Action("type", target="e2", text="{{SECRET:nope}}"))
    seen = []
    page, ex = mk(lambda act, why: seen.append((act, why)) or True)
    assert ex.run(a, view(page)) == "ok"
    assert page.filled["e2"] == PW  # real value reaches the page, locally
    assert seen[0][0].text == "{{SECRET:login_password}}" and PW not in seen[0][1]
    ex.run(Action("type", target="e1", text="{{SECRET:work_email}}"), view(page))
    assert page.filled["e1"] == "demo.user@example.test"


def test_irreversible_click_needs_approval():
    page, ex = mk()
    assert "not approved" in reject(ex, page, Action("click", target="e5"))
    page, ex = mk(lambda a, r: 1 / 0)  # raising approver = deny
    assert "not approved" in reject(ex, page, Action("click", target="e5"))
    page, ex = mk(lambda a, r: "yes")  # only literal True approves
    assert "not approved" in reject(ex, page, Action("click", target="e5"))
    page, ex = mk(lambda a, r: True)
    assert ex.run(Action("click", target="e5"), view(page)) == "ok"


def test_fill_error_does_not_leak_value():
    page, ex = mk(lambda a, r: True)

    def boom(id, text):
        raise RuntimeError(f"cannot fill {text}")
    page.fill = boom
    msg = reject(ex, page, Action("type", target="e2", text="{{SECRET:login_password}}"))
    assert "RuntimeError" in msg


def test_describe_is_log_safe():
    d = describe(Action("type", target="e4", text="someone@example.test"))
    assert "someone" not in d and "20 chars" in d
    assert "{{SECRET:login_password}}" in describe(Action("type", target="e2", text="{{SECRET:login_password}}"))
    assert describe(Action("navigate", url="https://evil.example/a?u=someone@example.test")) == \
        "navigate url=https://evil.example"
    assert "9876543210" not in describe(Action("click", target="9876543210"))
