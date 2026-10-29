"""Serve testpages/ on http://localhost:PORT (quiet: request lines can carry submitted form values).

Run: .venv/bin/python demo/serve.py [--port 8000]
"""
import argparse
import functools
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "testpages"


class _Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a):  # GET form submits put values in the query string: never log them
        pass


def start(port: int = 0, root: Path = ROOT, on_request=None) -> tuple[ThreadingHTTPServer, str]:
    """Start in a daemon thread; port 0 picks a free one. Returns (server, base_url); call server.shutdown().
    on_request(path) sees each GET path incl. query (local test hook: proves submitted values reached the site)."""
    class H(_Quiet):
        def do_GET(self):
            if on_request:
                on_request(self.path)
            super().do_GET()
    srv = ThreadingHTTPServer(("localhost", port), functools.partial(H, directory=str(root)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://localhost:{srv.server_address[1]}"


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    srv, base = start(ap.parse_args().port)
    print(f"serving {ROOT} at {base}/  (Ctrl-C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
