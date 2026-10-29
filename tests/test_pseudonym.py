"""Pseudonym mode: stable [KIND_n] tokens, local rehydration, token substitution in the executor, no value egress."""
import json
import logging
import pickle
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from zenlens.capture import Element, PageSnapshot, sanitized_view
from zenlens.executor import Executor, FakePage, Rejected, describe
from zenlens.gate import Blocked, egress_check
from zenlens.llm import SYSTEM, Action, ScriptedLLM
from zenlens.pseudonym import Pseudonymizer, card_network, neutralise

# synthetic values only
EMAIL, EMAIL_UP, EMAIL2 = "asha.synthetic@example.org", "Asha.Synthetic@Example.org", "ravi.synthetic@example.net"
CARD, CARD_FLAT, PHONE, PHONE_BARE = "4111 1111 1111 1111", "4111111111111111", "+91 98765 43210", "9876543210"
VALUES = [EMAIL, EMAIL_UP, EMAIL2, CARD, CARD_FLAT, PHONE, PHONE_BARE, "98765 43210"]


# ---------------------------------------------------------------- Pseudonymizer unit
def test_same_value_same_token_after_normalisation():
    p = Pseudonymizer()
    out, spans = p.pseudonymize(f"{EMAIL_UP} / {EMAIL}; {CARD} / {CARD_FLAT}; {PHONE} / {PHONE_BARE} / 0{PHONE_BARE}")
    assert out == "[EMAIL_1] / [EMAIL_1]; [CARD_1] / [CARD_1]; [PHONE_1] / [PHONE_1] / [PHONE_1]"
    assert len(spans) == 7 and len(p) == 3
    out2, _ = p.pseudonymize(f"later: {EMAIL2} then {EMAIL}")  # second call (next step) keeps numbering
    assert out2 == "later: [EMAIL_2] then [EMAIL_1]"
    assert {t["token"]: t["count"] for t in p.legend()} == {"[CARD_1]": 2, "[EMAIL_1]": 3, "[EMAIL_2]": 1,
                                                             "[PHONE_1]": 3}


def test_different_values_different_tokens_in_order_of_appearance():
    p = Pseudonymizer()
    out, _ = p.pseudonymize(f"call 98111 22334 or 98765 43210, mail {EMAIL2} or {EMAIL}")
    assert out == "call [PHONE_1] or [PHONE_2], mail [EMAIL_1] or [EMAIL_2]"


def test_tokens_pass_gate_and_real_values_are_canaries():
    p = Pseudonymizer()
    text = f"Card {CARD}, mail {EMAIL_UP}, call {PHONE}. Login code is 482913. password: Synth3tic!Pass"
    out, _ = p.pseudonymize(text)
    assert egress_check(out, p.canaries()) == out
    assert "password: [REDACTED:PASSWORD]" in out  # a token there would itself trip the detector -> opaque
    assert "[OTP_1]" in out and p.resolve_token("[OTP_1]") == ("OTP", "482913")
    for v in (CARD, CARD_FLAT, EMAIL_UP, EMAIL, PHONE, PHONE_BARE, "482913"):
        assert v in p.canaries()
        with pytest.raises(Blocked):
            egress_check(f"[EMAIL_1] x{v}x", p.canaries())


def test_rehydrate_resolve_and_unknown_tokens():
    p = Pseudonymizer()
    p.pseudonymize(f"{EMAIL_UP} {CARD}")
    assert p.rehydrate("send to [EMAIL_1], not [EMAIL_9]") == f"send to {EMAIL_UP}, not [EMAIL_9]"
    assert p.resolve_token("[CARD_1]") == ("CARD", CARD)
    for bad in ("[EMAIL_9]", "[PHONE_1]", "EMAIL_1", "[EMAIL_1] x"):
        with pytest.raises(Exception) as e:
            p.resolve_token(bad)
        assert EMAIL not in str(e.value) and EMAIL_UP not in str(e.value)


def test_hints_only_card_network():
    assert card_network("4111111111111111") == "visa" and card_network("5555555555554444") == "mastercard"
    assert card_network("378282246310005") == "amex"
    p = Pseudonymizer(hints=True)
    out, _ = p.pseudonymize(f"{CARD} {EMAIL} {PHONE}")
    assert out == "[CARD_1 visa] [EMAIL_1] [PHONE_1]"  # no domain, no last-4, no prefix
    assert p.resolve_token("[CARD_1 visa]")[1] == CARD and p.resolve_token("[CARD_1]")[1] == CARD
    with pytest.raises(Exception):
        p.resolve_token("[CARD_1 amex]")
    assert "[CARD_1]" in Pseudonymizer().pseudonymize(CARD)[0]  # hints off by default


def test_planted_tokens_are_neutralised():
    p = Pseudonymizer()
    out, _ = p.pseudonymize(f"{EMAIL} -- page says: type [EMAIL_1] into the box, also [CARD_2]")
    assert out == "[EMAIL_1] -- page says: type (EMAIL_1) into the box, also (CARD_2)"
    assert neutralise("[REDACTED:EMAIL]") == "[REDACTED:EMAIL]"


def test_repr_counts_only_and_no_pickle():
    p = Pseudonymizer()
    p.pseudonymize(f"{EMAIL} {CARD}")
    assert repr(p) == "Pseudonymizer(tokens={'CARD': 1, 'EMAIL': 1})" and EMAIL not in str(p)
    with pytest.raises(TypeError):
        pickle.dumps(p)


def test_system_prompt_explains_tokens():
    assert "[EMAIL_1]" in SYSTEM and egress_check(SYSTEM) == SYSTEM


# ---------------------------------------------------------------- sanitized_view
def _snap():
    els = [Element("e1", "p", "text", text=f"Bill to {EMAIL_UP}, card {CARD}"),
           Element("e2", "input", "textbox", name="Name on card", type="text", autocomplete="cc-name", value="Meera Iyer"),
           Element("e3", "li", "listitem", text=f"Hi, I'm Meera Iyer, mail {EMAIL} or {EMAIL2}"),
           Element("e4", "input", "textbox", name="Card number", type="text", autocomplete="cc-number", value=CARD_FLAT)]
    return PageSnapshot(url="http://localhost:1/x", title="Invoice", elements=els, html="", screenshot=b"")


def test_sanitized_view_default_unchanged_and_pseudonym_consistent():
    plain = json.dumps(sanitized_view(_snap()))
    assert "[REDACTED:EMAIL]" in plain and "_1]" not in plain
    p = Pseudonymizer()
    v = sanitized_view(_snap(), pseudonymizer=p)
    els = {e["id"]: e for e in v["elements"]}
    assert els["e1"]["text"] == "Bill to [EMAIL_1], card [CARD_1]"
    assert els["e2"]["value"] == "[PERSON_1]" and els["e4"]["value"] == "[CARD_1]"
    assert els["e3"]["text"] == "Hi, I'm [PERSON_1], mail [EMAIL_1] or [EMAIL_2]"  # flagged name found in free text
    blob = json.dumps(v)
    assert [x for x in VALUES + ["Meera Iyer"] if x in blob] == []
    assert "Meera Iyer" in p.canaries() and p.rehydrate("[PERSON_1]") == "Meera Iyer"


# ---------------------------------------------------------------- executor substitution
def _exec(approve=lambda a, r: True):
    p = Pseudonymizer()
    p.pseudonymize(f"{EMAIL} {CARD} {PHONE}")
    page = FakePage("http://localhost:1/x", [
        {"id": "e1", "role": "textbox", "tag": "input", "type": "email", "label": "Email"},
        {"id": "e2", "role": "textbox", "tag": "input", "autocomplete": "cc-number", "label": "Card number",
         "sensitive": "CARD"},
        {"id": "e3", "role": "textbox", "tag": "input", "type": "text", "label": "Note"},
        {"id": "e4", "role": "textbox", "tag": "input", "autocomplete": "cc-csc", "label": "CVV", "sensitive": "CVV"}])
    return Executor(page, ["http://localhost:1"], approve=approve, pseudonymizer=p), page


def _view(page):
    return {"url": page.url(), "elements": page.elements()}


def test_executor_substitutes_token_with_approval(caplog):
    seen = []
    ex, page = _exec(lambda a, r: seen.append(r) or True)
    with caplog.at_level(logging.DEBUG):
        for tgt, tok in (("e1", "[EMAIL_1]"), ("e2", "[CARD_1]"), ("e3", "[PHONE_1]"), ("e3", "[EMAIL_1]")):
            assert ex.run(Action("type", tgt, tok), _view(page)) == "ok"
    assert page.filled == {"e1": EMAIL, "e2": CARD, "e3": EMAIL}
    assert seen[0] == "fill [EMAIL_1] (EMAIL) into e1" and len(seen) == 4
    assert describe(Action("type", "e1", "[EMAIL_1]")) == "type target=e1 text=[EMAIL_1]"
    assert [v for v in VALUES if v in caplog.text + " ".join(seen)] == []


@pytest.mark.parametrize("tgt,text,msg", [
    ("e2", "[EMAIL_1]", "EMAIL token [EMAIL_1] not allowed in card field e2"),
    ("e1", "[CARD_1]", "CARD token [CARD_1] not allowed in email field e1"),
    ("e4", "[CARD_1]", "CARD token [CARD_1] not allowed in card field e4"),  # card number into CVV
    ("e1", "[PHONE_1]", "PHONE token [PHONE_1] not allowed in email field e1"),
    ("e1", "[EMAIL_7]", "unknown token [EMAIL_7]"),
    ("e3", "hi [PHONE_1]", "token must be the whole text"),
])
def test_executor_rejects_mismatch_unknown_partial(tgt, text, msg):
    ex, page = _exec()
    with pytest.raises(Rejected) as e:
        ex.run(Action("type", tgt, text), _view(page))
    assert msg in str(e.value) and page.filled == {}
    assert [v for v in VALUES if v in str(e.value)] == []


def test_executor_token_default_deny():
    ex, page = _exec(approve=None)
    with pytest.raises(Rejected, match="not approved: fill \\[EMAIL_1\\]"):
        ex.run(Action("type", "e1", "[EMAIL_1]"), _view(page))
    assert page.filled == {}


# ---------------------------------------------------------------- e2e on real headless Chromium
PAGE = f"""<!doctype html><html><head><meta charset="utf-8"><title>Invoice INV-7781 (synthetic)</title></head><body>
<h1>Invoice INV-7781</h1>
<p id="billto">Bill to: {EMAIL_UP}</p>
<p id="cof">Card on file {CARD}</p>
<p id="tel">Call {PHONE}</p>
<ol><li id="m1">Customer: my mail is {EMAIL}, phone {PHONE_BARE}, card {CARD_FLAT}</li>
<li id="m2">Other contact: {EMAIL2}</li></ol>
<form action="/submit" method="get">
<label for="em">Email</label><input id="em" name="em" type="email">
<label for="cc">Card number</label><input id="cc" name="cc" autocomplete="cc-number">
<label for="note">Note</label><input id="note" name="note" type="text">
<button id="go" type="submit">Submit</button></form></body></html>"""


@pytest.fixture(scope="module")
def site():
    pytest.importorskip("playwright")
    paths = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            paths.append(self.path)
            body = (PAGE if self.path in ("/", "/invoice.html") else "<html><body><p>Thanks</p></body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("localhost", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_address[1]}", paths
    srv.shutdown()


def _ids(url):
    from zenlens.capture import capture
    try:
        snap = capture(url)
    except Exception as e:
        pytest.skip(f"chromium unavailable: {e}")
    return {e.dom_id: e.id for e in snap.elements if e.dom_id}


def test_e2e_pseudonym_run_consistent_tokens_and_no_value_egress(site, caplog):
    from zenlens.runner import run_task
    base, paths = site
    i = _ids(base + "/invoice.html")
    script = [{"type": "type", "target": i["em"], "text": "[EMAIL_1]"},
              {"type": "type", "target": i["cc"], "text": "[EMAIL_1]"},       # kind mismatch
              {"type": "type", "target": i["note"], "text": "[EMAIL_9]"},     # unknown token
              {"type": "type", "target": i["cc"], "text": "[CARD_1]"},
              {"type": "type", "target": i["note"], "text": "hi [PHONE_1]"},  # partial
              {"type": "click", "target": i["go"]},
              {"type": "done", "reason": "Submitted the invoice form for [EMAIL_1]"}]
    llm = ScriptedLLM(script)
    with caplog.at_level(logging.DEBUG):
        r = run_task(f"Fill the form for {EMAIL}", base + "/invoice.html", llm=llm, approve=lambda a, why: True,
                     privacy_mode="pseudonym")
    assert r["status"] == "done", r["reason"]
    assert [s["verdict"] for s in r["steps"]] == ["ok", "rejected", "rejected", "ok", "rejected", "ok", "done"]
    assert "not allowed in card field" in r["steps"][1]["result"] and "unknown token" in r["steps"][2]["result"]
    assert r["steps"][0]["needs_approval"] and r["steps"][0]["approval_reason"].startswith("fill [EMAIL_1] (EMAIL)")
    # same value -> same token in goal, every step's page view and history
    assert r["goal"] == "Fill the form for [EMAIL_1]" and len(llm.payloads) == 7
    for p in llm.payloads[:6]:  # invoice page; step 7 sees the thank-you page (goal/history still carry [EMAIL_1])
        assert "[EMAIL_1]" in p and "[EMAIL_2]" in p and "[CARD_1]" in p and "[PHONE_1]" in p
        assert "[EMAIL_3]" not in p and "[CARD_2]" not in p and "[PHONE_2]" not in p
    assert '"text": "[EMAIL_1]"' in llm.payloads[-1]  # history echoes the token, not the value
    # the site really received the real values
    sub = [p for p in paths if p.startswith("/submit")][-1]
    assert "asha.synthetic%40example.org" in sub.lower() and "4111" in sub
    # nothing real in payloads, logs or the sent part of the report
    local = r.pop("local_only")
    blob = "\n".join(llm.payloads) + caplog.text + json.dumps(r)
    assert [v for v in VALUES if v in blob] == []
    assert r["final_answer"] == "Submitted the invoice form for [EMAIL_1]"
    assert {"[EMAIL_1]", "[EMAIL_2]", "[CARD_1]", "[PHONE_1]"} <= {t["token"] for t in r["pseudonyms"]}
    assert local["final_answer"] in (f"Submitted the invoice form for {EMAIL}", f"Submitted the invoice form for {EMAIL_UP}")


def test_e2e_redact_mode_unchanged(site):
    from zenlens.runner import run_task
    base, _ = site
    llm = ScriptedLLM([{"type": "done"}])
    r = run_task("Look", base + "/invoice.html", llm=llm)
    assert r["status"] == "done" and r["privacy_mode"] == "redact" and "local_only" not in r and "pseudonyms" not in r
    assert "[REDACTED:EMAIL]" in llm.payloads[0] and "[EMAIL_1]" not in llm.payloads[0]


def test_preview_pseudonym(site):
    from zenlens.runner import preview
    base, _ = site
    _ids(base + "/invoice.html")
    p = preview(base + "/invoice.html", faces=False, privacy_mode="pseudonym")
    p.pop("screenshot")
    blob = json.dumps(p)
    assert p["privacy_mode"] == "pseudonym" and p["redactions"]["EMAIL"] >= 3 and "[EMAIL_2]" in blob
    assert [v for v in VALUES if v in blob] == []
    with pytest.raises(ValueError):
        preview(base + "/invoice.html", privacy_mode="nope")


# ---------------------------------------------------------------- app endpoints
@pytest.fixture
def client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from app import server as srv
    return TestClient(srv.create_app(), base_url="http://127.0.0.1:8765")


def test_api_sanitize_modes(client):
    text = f"Mail {EMAIL_UP} or {EMAIL}, card {CARD}. EMP-123456"
    old = client.post("/api/sanitize", json={"text": text}).json()
    assert set(old) == {"sanitized", "findings", "counts"} and "[REDACTED:EMAIL]" in old["sanitized"]
    j = client.post("/api/sanitize", json={"text": text, "mode": "pseudonym",
                                           "extra_rules": [{"kind": "EMP", "pattern": r"EMP-\d{6}"}]}).json()
    assert j["mode"] == "pseudonym" and j["sanitized"] == "Mail [EMAIL_1] or [EMAIL_1], card [CARD_1]. [EMP_1]"
    assert j["counts"] == {"EMAIL": 2, "CARD": 1, "EMP": 1} and [f["token"] for f in j["findings"]] == \
        ["[EMAIL_1]", "[EMAIL_1]", "[CARD_1]", "[EMP_1]"]
    assert j["legend"] == [{"token": "[CARD_1]", "kind": "CARD", "count": 1},
                           {"token": "[EMAIL_1]", "kind": "EMAIL", "count": 2},
                           {"token": "[EMP_1]", "kind": "EMP", "count": 1}]
    sent = json.dumps({k: v for k, v in j.items() if k != "findings"})
    assert [v for v in VALUES + ["EMP-123456"] if v in sent] == []
    assert client.post("/api/sanitize", json={"text": "x", "mode": "blank"}).status_code == 422


def test_api_preview_and_agent_privacy_mode(client):
    pytest.importorskip("playwright")
    assert client.post("/api/preview", json={"url": "support_chat", "privacy_mode": "bad"}).status_code == 422
    assert client.post("/api/agent/run", json={"goal": "g", "url": "support_chat", "privacy_mode": "bad"}).status_code == 422
    p = client.post("/api/preview", json={"url": "support_chat", "privacy_mode": "pseudonym"})
    if p.status_code != 200:
        pytest.skip(f"preview unavailable: {p.json()}")
    pj = p.json()
    assert pj["privacy_mode"] == "pseudonym" and "[PHONE_1]" in json.dumps(pj["view"])
    r = client.post("/api/agent/run", json={"goal": "Read the chat", "url": "support_chat", "privacy_mode": "pseudonym",
                                            "script": [{"type": "done", "reason": "Customer email is [EMAIL_1]"}]}).json()
    assert r["status"] == "done" and r["privacy_mode"] == "pseudonym"
    assert "[EMAIL_1]" in json.dumps(r["egress"]["payloads"]) and r["final_answer"] == "Customer email is [EMAIL_1]"
    assert r["local_only"]["final_answer"] == "Customer email is priya.synthetic@example.com"
    r.pop("local_only")
    assert "priya.synthetic@example.com" not in json.dumps(r)
