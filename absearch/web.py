"""Tiny localhost-only server for the generated offline dashboard."""

from __future__ import annotations

import webbrowser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # noqa: A003
        pass


def serve_report(
    directory: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    block: bool = True,
) -> ThreadingHTTPServer:
    """Serve a report directory on localhost and return the HTTP server."""

    handler = partial(QuietHandler, directory=str(Path(directory)))
    server = ThreadingHTTPServer((host, port), handler)
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"\nAB Search dashboard: {url}")
    print("(offline, localhost only — press Ctrl+C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    if block:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nDashboard server stopped.")
        finally:
            server.server_close()
    return server
