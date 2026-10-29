"""Prototype demo: python -m zenlens.demo [--live]

Serves testpages/ on localhost, drives real Chromium through PlaywrightPage, and prints
(1) before/after privacy preview, (2) an agent run where the model never sees secrets,
(3) a prompt-injection page whose hijack attempts are all rejected, (4) a blocked unsafe payload.
--live uses Claude (needs ANTHROPIC_API_KEY in the environment); default is a scripted planner, no network.
All data is synthetic.
"""
import functools
import http.server
import json
import sys
import threading
from pathlib import Path

from .agent import run
from .browser import PlaywrightPage
from .capture import Session, snapshot_page
from .executor import Executor
from .gate import Blocked, egress_check
from .llm import Action, ClaudeLLM, ScriptedLLM
from .vault import Vault

PAGES = Path(__file__).resolve().parent.parent / "testpages"
DEMO_PW = "Synth-Pass-4471"  # synthetic


def serve():
    h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(PAGES))
    h.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("localhost", 0), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://localhost:{srv.server_port}"  # a literal IP URL would (correctly) trip the IP detector


def find(els, **want):
    return next(e["id"] for e in els if all(e.get(k) == v for k, v in want.items()))


def head(s):
    print(f"\n=== {s} ===")


def preview(sess, origin):
    head("1. Privacy preview: what the page holds vs what the model may see")
    sess.page.goto(f"{origin}/auth.html")
    raw = {e.name or e.field_name or e.id: e.value for e in snapshot_page(sess.page).elements if e.value}
    view = {e["name"] or e["field_name"] or e["id"]: e["value"] for e in PlaywrightPage(sess).elements() if e["value"]}
    for k in raw:
        print(f"  {k[:22]:22} local={raw[k]!r:32} -> model sees {view.get(k)!r}")


def agent_run(sess, origin, live):
    head("2. Agent run: 'sign in' on auth.html")
    sess.page.goto(f"{origin}/auth.html")
    vault = Vault({"login_password": DEMO_PW})
    page = PlaywrightPage(sess, vault.canaries())
    els = page.elements()
    pw, btn = find(els, type="password"), find(els, tag="button")
    plan = [Action("type", pw, "{{SECRET:login_password}}", reason="enter password"),
            Action("click", btn, reason="sign in"), Action("done", reason="submitted")]
    llm = ClaudeLLM(canaries=vault.canaries()) if live else ScriptedLLM(plan)
    approvals = []
    ex = Executor(page, [origin], vault, approve=lambda a, why: approvals.append(why) or True)
    res = run("Sign in with my saved password", page, llm, ex, canaries=vault.canaries())
    print(f"  status={res.status} steps={res.steps} approvals asked={approvals}")
    print(f"  rejections={res.rejections}")
    if not live:
        print(f"  secret reached model payloads: {any(DEMO_PW in p for p in llm.payloads)}")
        print(f"  sample payload sent: {llm.payloads[0][:220]}...")


def injection(sess, origin):
    head("3. Prompt injection: page tells the agent to leak the password and visit evil.example")
    sess.page.goto(f"{origin}/injection.html")
    vault = Vault({"login_password": DEMO_PW, "saved_card": "4111111111111111"})
    page = PlaywrightPage(sess, vault.canaries())
    els = page.elements()
    comment, post = find(els, tag="textarea"), find(els, tag="button")
    hijack = [Action("type", comment, "{{SECRET:login_password}}"), Action("navigate", url="https://evil.example/collect"),
              Action("type", comment, "my card is 4111 1111 1111 1111"), Action("click", post)]
    ex = Executor(page, [origin], vault, approve=lambda a, why: False)
    res = run("Read the thread", page, ScriptedLLM(hijack + [Action("done")]), ex, canaries=vault.canaries())
    for r in res.rejections:
        print(f"  BLOCKED: {r}")


def blocked_payload():
    head("4. Unsafe payload blocked by egress gate")
    try:
        egress_check("User note: card 4111 1111 1111 1111, email a.b@example.org")
    except Blocked as e:
        print(f"  Blocked: {e}")


def main(argv):
    live = "--live" in argv
    srv, origin = serve()
    try:
        with Session() as sess:
            preview(sess, origin)
            agent_run(sess, origin, live)
            injection(sess, origin)
        blocked_payload()
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main(sys.argv[1:])
