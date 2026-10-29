import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from zenlens.gate import Blocked
from zenlens.llm import OllamaLLM, ollama_status, pick_ollama_model

VIEW = {"url": "http://localhost/x", "elements": [{"id": "e1", "role": "button", "tag": "button", "text": "Go"}]}


@pytest.fixture
def fake_ollama():
    seen, reply = [], {"content": json.dumps({"type": "click", "target": "e1", "text": None, "url": None, "reason": "go"})}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def _send(self, obj):
            b = json.dumps(obj).encode()
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        def do_GET(self):
            self._send({"models": [{"name": "qwen2.5:3b"}]})

        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self._send({"message": {"role": "assistant", "content": reply["content"]}})

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}", seen, reply
    srv.shutdown()


def test_next_action_roundtrip_and_request_shape(fake_ollama):
    host, seen, _ = fake_ollama
    a = OllamaLLM(model="qwen2.5:3b", host=host).next_action("click go", VIEW, [])
    assert (a.type, a.target) == ("click", "e1")
    req = seen[0]
    assert req["stream"] is False and req["model"] == "qwen2.5:3b" and req["format"]["required"]
    assert "[REDACTED" in req["messages"][0]["content"] and "click go" in req["messages"][1]["content"]


def test_unparseable_reply_asks_user(fake_ollama):
    host, _, reply = fake_ollama
    reply["content"] = "not json"
    assert OllamaLLM(model="m", host=host).next_action("g", VIEW, []).type == "ask_user"


def test_egress_blocks_before_any_request(fake_ollama):
    host, seen, _ = fake_ollama
    bad = {"url": "http://localhost/", "elements": [{"id": "e1", "tag": "p", "role": "text", "text": "card 4111 1111 1111 1111"}]}
    with pytest.raises(Blocked):
        OllamaLLM(model="m", host=host).next_action("g", bad, [])
    assert seen == []


@pytest.mark.parametrize("host", ["http://example.com:11434", "http://10.0.0.5:11434", "evil.example"])
def test_remote_host_refused(host):
    with pytest.raises(ValueError):
        OllamaLLM(model="m", host=host)


def test_status_and_model_pick(fake_ollama):
    host, _, _ = fake_ollama
    assert ollama_status(host) == {"up": True, "models": ["qwen2.5:3b"]}
    assert ollama_status("http://127.0.0.1:1") == {"up": False, "models": []}
    assert ollama_status("http://example.com") == {"up": False, "models": []}
    assert pick_ollama_model(["qwen2.5:3b"], "llama3.2:3b") == "qwen2.5:3b"  # wanted model absent: use what exists
    assert pick_ollama_model(["a", "b"], "b") == "b"
