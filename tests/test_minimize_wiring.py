"""zenlens.minimize wired into capture.sanitized_view, runner defaults and the web app API. Synthetic data only."""
import inspect
import json

import pytest

from zenlens import runner
from zenlens.capture import Element, PageSnapshot, sanitized_view

LEAKS = ["4242", "98XXXXX210"]


def _snap():
    return PageSnapshot(url="https://shop.example/pay", title="Pay", html="<x>", screenshot=b"", elements=[
        Element("e1", "p", "text", text="Saved card: 4111 1111 1111 1111"),
        Element("e2", "p", "text", text="Pay with card ending 4242 on file"),
        Element("e3", "p", "text", text="We'll call 98XXXXX210 to confirm"),
        Element("e4", "p", "text", text="Order ORD-2026-118934, total 1,499.00"),
    ])


def test_view_minimized_only_when_asked():
    plain = json.dumps(sanitized_view(_snap()))
    assert all(v in plain for v in LEAKS) and "minimized" not in plain
    view = sanitized_view(_snap(), minimize=True)
    out = json.dumps(view)
    assert not any(v in out for v in LEAKS)
    assert "ORD-2026-118934" in out and "1,499.00" in out  # hard negatives survive
    rules = {n["rule"] for n in view["minimized"]}
    assert {"partial_value", "masked_number"} <= rules
    assert not any(v in json.dumps(view["minimized"]) for v in LEAKS)  # notes never carry values


def test_runner_minimizes_by_default():
    for fn in (runner.run_task, runner.preview):
        assert inspect.signature(fn).parameters["minimize"].default is True


fastapi = pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from app import server as srv  # noqa: E402

TEXT = "Card 4111 1111 1111 1111 saved; card ending 4242 is the backup. Phone 98XXXXX210."


@pytest.fixture
def client():
    return TestClient(srv.create_app(), base_url="http://127.0.0.1:8765")


def test_sanitize_minimize_is_opt_in(client):
    r = client.post("/api/sanitize", json={"text": TEXT}).json()
    assert "minimized" not in r and "4242" in r["sanitized"]  # extension contract unchanged by default
    r = client.post("/api/sanitize", json={"text": TEXT, "minimize": True}).json()
    assert not any(v in r["sanitized"] for v in LEAKS) and r["minimized"]
    assert not any(v in json.dumps(r["minimized"]) for v in LEAKS)


def test_sanitize_minimize_pseudonym_mode(client):
    r = client.post("/api/sanitize", json={"text": TEXT, "mode": "pseudonym", "minimize": True}).json()
    assert "[CARD_1]" in r["sanitized"] and "4242" not in r["sanitized"] and r["minimized"]
