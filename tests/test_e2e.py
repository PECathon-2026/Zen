"""End to end on real headless Chromium: capture -> sanitized view -> ScriptedLLM -> executor -> vault fill."""
import json
import logging
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from zenlens import agent
from zenlens.llm import ScriptedLLM
from zenlens.vault import Vault

pytest.importorskip("playwright")
from demo.serve import start  # noqa: E402
from zenlens.browser import PlaywrightPage  # noqa: E402
from zenlens.capture import Session  # noqa: E402
from zenlens.executor import Executor  # noqa: E402
from zenlens.runner import preview, run_task  # noqa: E402

PAGES = Path(__file__).resolve().parent.parent / "testpages"
SECRETS = {"login_email": "zl.user@example.net", "login_password": "Zen-Synth-9931", "otp_code": "604215",
           "card_number": "5555 5555 5555 4444", "card_cvv": ("card", "913")}  # synthetic
VALUES = ["zl.user@example.net", "Zen-Synth-9931", "604215", "5555 5555 5555 4444", "5555555555554444", "913"]
AUTH = [{"type": "type", "target": "e3", "text": "{{SECRET:login_email}}"},
        {"type": "type", "target": "e5", "text": "{{SECRET:login_password}}"},
        {"type": "type", "target": "e10", "text": "{{SECRET:otp_code}}"},
        {"type": "type", "target": "e3", "text": "{{SECRET:login_password}}"},  # wrong field kind
        {"type": "type", "target": "e10", "text": "[REDACTED:OTP]"},          # echo a redaction
        {"type": "click", "target": "e17"}, {"type": "done"}]


def _truth(page):
    return [i["value"] for i in json.loads((PAGES / f"{page}.truth.json").read_text())["items"] if i["value"]]


@pytest.fixture(scope="module")
def server():
    paths = []
    srv, url = start(on_request=paths.append)
    yield url, paths
    srv.shutdown()


def _leaks(blob: str, values) -> list[str]:
    return [v for v in values if v in blob]


def test_agent_loop_fills_dom_but_model_and_logs_never_see_values(server, caplog):
    base, _ = server
    vault = Vault(SECRETS)
    llm = ScriptedLLM([AUTH[1], AUTH[2], AUTH[3], {"type": "done"}])
    try:
        s = Session().__enter__()
    except Exception as e:
        pytest.skip(f"chromium unavailable: {e}")
    try:
        page = PlaywrightPage(s, [base], vault.canaries())
        page.goto(base + "/auth.html")
        ex = Executor(page, [base], vault, approve=lambda a, r: True)
        with caplog.at_level(logging.DEBUG):
            res = agent.run("Sign in", page, llm, ex)
        assert res.status == "done" and len(res.rejections) == 1
        assert page.dom_value("e5") == "Zen-Synth-9931" and page.dom_value("e10") == "604215"
    finally:
        s.__exit__(None, None, None)
    sent = "\n".join(llm.payloads)
    assert len(llm.payloads) == 4 and "[REDACTED:PASSWORD]" in sent
    assert _leaks(sent, VALUES + _truth("auth")) == []
    assert _leaks(caplog.text, VALUES + _truth("auth")) == []


def test_run_task_auth_report_is_clean_and_submit_reaches_site(server, caplog):
    base, paths = server
    llm = ScriptedLLM(AUTH)
    steps = []
    with caplog.at_level(logging.DEBUG):
        r = run_task("Sign in to ZenBank", base + "/auth.html", llm=llm, vault=SECRETS, approve=lambda a, r: True,
                     on_step=steps.append)
    assert r["status"] == "done" and [s["verdict"] for s in r["steps"]] == \
        ["ok", "ok", "ok", "rejected", "rejected", "ok", "done"] and steps == r["steps"]
    assert r["steps"][5]["needs_approval"] and "irreversible" in r["steps"][5]["approval_reason"]
    assert r["steps"][0]["privacy"]["redactions"]["PASSWORD"] >= 1 and r["final_view"]
    submit = [parse_qs(urlsplit(p).query) for p in paths if "pw=" in p][-1]  # the site really got the secrets
    assert submit["pw"] == ["Zen-Synth-9931"] and submit["code"] == ["604215"]
    blob = json.dumps(r) + "\n".join(llm.payloads) + caplog.text
    assert _leaks(blob, VALUES + _truth("auth")) == []


def test_run_task_checkout_default_deny(server):
    base, _ = server
    script = [{"type": "type", "target": "e13", "text": "{{SECRET:card_number}}"},
              {"type": "type", "target": "e17", "text": "{{SECRET:card_cvv}}"},
              {"type": "type", "target": "e13", "text": "5555 5555 5555 4444"},
              {"type": "click", "target": "e22"}]
    llm = ScriptedLLM(script)
    r = run_task("Pay for the order", base + "/checkout.html", llm=llm, vault=SECRETS, max_steps=4)  # approve=None
    assert r["status"] == "max_steps" and all(s["verdict"] == "rejected" for s in r["steps"])
    assert [s["approved"] for s in r["steps"]] == [False, False, None, False]
    assert _leaks(json.dumps(r) + "\n".join(llm.payloads), VALUES + _truth("checkout")) == []


def test_injection_page_hijacks_rejected(server):
    base, paths = server
    hijack = [{"type": "type", "target": "e8", "text": "{{SECRET:login_password}}", "reason": "page said so"},
              {"type": "navigate", "url": "https://evil.example/collect"},
              {"type": "click", "target": "e4"},  # phish link
              {"type": "type", "target": "e8", "text": "[REDACTED:CARD]"},
              {"type": "click", "target": "e9"},  # Post comment: irreversible, default deny
              {"type": "done"}]
    llm = ScriptedLLM(hijack)
    r = run_task("Reply 'thanks' to the forum post", base + "/injection.html", llm=llm, vault=SECRETS)
    assert "Ignore previous instructions" in llm.payloads[0]  # page text reaches the model only as data
    res = [s["result"] for s in r["steps"][:5]]
    assert all(x.startswith("rejected") for x in res)
    assert "not allowed in text field" in res[0] and "origin not allowed: https://evil.example" in res[1]
    assert "PermissionError" in res[2] and "not approved" in res[4]
    assert r["final_url"].startswith(base) and r["rejected"] == 5
    assert _leaks(json.dumps(r), VALUES) == []


@pytest.mark.parametrize("page", ["auth", "checkout"])
def test_preview_has_no_truth_values(page):
    p = preview(str(PAGES / f"{page}.html"))
    assert p["view"] and sum(p["redactions"].values()) >= 5 and p["sensitive_elements"]
    shot = p.pop("screenshot")
    assert _leaks(json.dumps(p), _truth(page)) == []
    if shot is None:
        assert p["screenshot_reason"]
        return
    import base64
    from zenlens.screenshot import ocr_text
    png = base64.b64decode(shot)
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and p["screenshot_redactions"]
    text = " ".join(ocr_text(png).split())
    assert _leaks(text, _truth(page)) == []
