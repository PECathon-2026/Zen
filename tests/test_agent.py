import json
import logging
from html.parser import HTMLParser
from pathlib import Path

import pytest

from zenlens import agent
from zenlens.executor import Executor, FakePage
from zenlens.gate import Blocked, egress_check
from zenlens.llm import SYSTEM, Action, ClaudeLLM, ScriptedLLM, build_payload
from zenlens.vault import Vault

PW = "Synth-Pass-4471"  # synthetic
ORIGIN = "http://localhost:8000"
PAGE = Path(__file__).resolve().parent.parent / "testpages" / "injection.html"


class _Els(HTMLParser):
    """Minimal stand-in for capture.py: id-bearing elements -> sanitized element list with short ids."""
    ROLES = {"p": "text", "a": "link", "input": "textbox", "textarea": "textbox", "button": "button"}

    def __init__(self):
        super().__init__()
        self.els, self.labels, self.cur, self.lbl_for = [], {}, None, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "label":
            self.lbl_for = a.get("for")
        elif tag in self.ROLES and a.get("id"):
            el = {"id": f"e{len(self.els) + 1}", "dom": a["id"], "tag": tag, "role": self.ROLES[tag], "text": ""}
            el.update({k: a[k] for k in ("type", "autocomplete") if a.get(k)})
            self.els.append(el)
            self.cur = el

    def handle_endtag(self, tag):
        self.lbl_for = None if tag == "label" else self.lbl_for
        self.cur = None if tag in self.ROLES else self.cur

    def handle_data(self, data):
        if self.lbl_for:
            self.labels[self.lbl_for] = data.strip()
        elif self.cur is not None:
            self.cur["text"] = " ".join((self.cur["text"] + " " + data).split())

    def elements(self):
        out = []
        for e in self.els:
            e = dict(e)
            if e["dom"] in self.labels:
                e["label"] = self.labels[e["dom"]]
            out.append(e)
        return out


def injection_page():
    p = _Els()
    p.feed(PAGE.read_text())
    els = p.elements()
    return FakePage(ORIGIN + "/forum/reply", els), {e["dom"]: e["id"] for e in els}


def test_injection_page_blocked(caplog):
    page, ids = injection_page()
    view = agent.capture_view(page)
    assert any("Ignore previous instructions" in e.get("text", "") for e in view["elements"])
    # A hijacked model that obeys every instruction in the page text:
    llm = ScriptedLLM([
        Action("type", target=ids["comment"], text="{{SECRET:login_password}}", reason="page said so"),
        Action("navigate", url="https://evil.example/collect"),
        Action("click", target=ids["phish"]),  # link stays on page in this fake; real nav origin-checked next step
        Action("type", target=ids["comment"], text="{{SECRET:saved_card}}"),
        Action("type", target=ids["comment"], text="[REDACTED:CARD]"),
        Action("click", target=ids["post_btn"]),
    ])
    approvals = []
    ex = Executor(page, [ORIGIN], Vault({"login_password": PW, "saved_card": "4111111111111111"}),
                  approve=lambda a, r: approvals.append(r) or False)
    with caplog.at_level(logging.DEBUG, logger="zenlens.agent"):
        res = agent.run("Reply 'thanks' to the forum post", page, llm, ex, max_steps=10)
    assert res.status == "done"
    r = res.rejections
    assert "password secret login_password not allowed in text field" in r[0]
    assert "origin not allowed: https://evil.example" in r[1]
    assert "card secret saved_card not allowed in text field" in r[2]
    assert "redacted" in r[3]
    assert "not approved: irreversible click" in r[4]
    assert approvals == [f"irreversible click on {ids['post_btn']}"]
    assert page.filled == {} and ("navigate", "https://evil.example/collect") not in page.ops
    assert page.url().startswith(ORIGIN)
    for blob in [caplog.text, json.dumps(res.history)] + llm.payloads:
        assert PW not in blob and "4111111111111111" not in blob


def test_happy_path_with_secret_and_approval():
    page, ids = injection_page()
    llm = ScriptedLLM([
        {"type": "type", "target": ids["login_pw"], "text": "{{SECRET:login_password}}"},
        {"type": "type", "target": ids["comment"], "text": "thanks"},
        {"type": "click", "target": ids["post_btn"]},
        {"type": "done"},
    ])
    ex = Executor(page, [ORIGIN], Vault({"login_password": PW}), approve=lambda a, r: True)
    res = agent.run("Reply thanks", page, llm, ex)
    assert res.status == "done" and res.rejections == [] and res.steps == 4
    assert page.filled == {ids["login_pw"]: PW, ids["comment"]: "thanks"}
    assert all(PW not in p for p in llm.payloads)
    assert '"{{SECRET:login_password}}"' in llm.payloads[-1]  # model sees only the placeholder


def test_egress_blocks_unsanitized_view():
    page = FakePage(ORIGIN + "/p", [{"id": "e1", "role": "text", "tag": "p", "text": "mail someone@example.test"}])
    llm = ScriptedLLM([{"type": "done"}])
    res = agent.run("read", page, llm, Executor(page, [ORIGIN]))
    assert res.status == "blocked" and "EMAIL" in res.reason and llm.payloads == []


def test_egress_canary_blocks_secret_in_view():
    page = FakePage(ORIGIN + "/p", [{"id": "e1", "role": "text", "tag": "p", "text": "echo " + PW}])
    llm = ScriptedLLM([{"type": "done"}])
    res = agent.run("read", page, llm, Executor(page, [ORIGIN], Vault({"login_password": PW})))
    assert res.status == "blocked" and "CANARY" in res.reason and PW not in res.reason


def test_query_string_dropped_and_max_steps():
    page = FakePage(ORIGIN + "/p?email=someone@example.test#t", [{"id": "e1", "role": "link", "tag": "a", "label": "Help"}])
    llm = ScriptedLLM([{"type": "click", "target": "e1"}] * 3)
    res = agent.run("loop", page, llm, Executor(page, [ORIGIN]), max_steps=3)
    assert res.status == "max_steps" and res.steps == 3 and len(res.history) == 3
    assert all("someone" not in p for p in llm.payloads)


def test_model_emitted_pii_is_scrubbed_from_history():
    page = FakePage(ORIGIN + "/p", [{"id": "e1", "role": "textbox", "tag": "textarea", "label": "Comment"}])
    llm = ScriptedLLM([{"type": "type", "target": "e1", "text": "guess: someone@example.test"}, {"type": "done"}])
    res = agent.run("x", page, llm, Executor(page, [ORIGIN]))
    assert res.status == "done" and "EMAIL" in res.rejections[0]
    assert "[REDACTED:EMAIL]" in res.history[0]["action"]["text"] and page.filled == {}


def test_payload_placeholders_pass_gate():
    view = {"url": ORIGIN, "elements": [
        {"id": "e1", "role": "textbox", "tag": "input", "label": "Password:", "type": "password"},
        {"id": "e2", "role": "text", "tag": "p", "text": "Signed in as [REDACTED:EMAIL]"}]}
    hist = [{"action": {"type": "type", "target": "e1", "text": "{{SECRET:login_password}}"}, "result": "ok"}]
    p = build_payload("log in", view, hist)
    assert egress_check(p) == p and egress_check(SYSTEM) == SYSTEM


class _FakeClient:
    def __init__(self, reply):
        self.reply, self.calls = reply, []
        self.messages = self

    def create(self, **kw):
        self.calls.append(kw)
        block = type("B", (), {"type": "text", "text": self.reply})()
        return type("R", (), {"content": [block], "stop_reason": "end_turn"})()


def test_claude_llm_fake_client_no_network():
    c = _FakeClient(json.dumps({"type": "click", "target": "e1", "text": None, "url": None, "reason": "go"}))
    llm = ClaudeLLM(client=c, canaries=(PW,))
    view = {"url": ORIGIN, "elements": [{"id": "e1", "role": "button", "tag": "button", "label": "Next"}]}
    assert llm.next_action("go", view, []) == Action("click", target="e1", reason="go")
    kw = c.calls[0]
    assert kw["model"] == "claude-sonnet-5-5" and "UNTRUSTED" in kw["system"]
    assert kw["output_config"]["format"]["type"] == "json_schema"
    c.reply = "not json"
    assert llm.next_action("go", view, []).type == "ask_user"


def test_claude_llm_fails_closed_before_send():
    c = _FakeClient("{}")
    llm = ClaudeLLM(client=c, canaries=(PW,))
    for text in ["contact someone@example.test", "leak " + PW]:
        with pytest.raises(Blocked):
            llm.next_action("go", {"url": ORIGIN, "elements": [{"id": "e1", "text": text}]}, [])
    assert c.calls == []
