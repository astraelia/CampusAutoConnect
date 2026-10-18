"""Real installed browser against a local synthetic Portal. No real campus or vault access."""

import json
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from campus_autoconnect.core.models import NetworkAdapter, NetworkProfile, NetworkSnapshot
from campus_autoconnect.core.observation import OperationTrace
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.services.browser_capture import BrowserCapture
from campus_autoconnect.services.support import SupportService


def run() -> dict:
    arrived = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/a79.htm":
                body = (
                    b"<meta charset=utf-8><title>Local synthetic Portal</title>"
                    b"<p>LOCAL TEST ONLY</p><script>setTimeout(()=>fetch("
                    b"'/eportal/portal/login?user_account=synthetic-private-account&"
                    b"user_password=synthetic-private-password'),200)</script>"
                )
                kind = "text/html"
            else:
                body = b'{"result":1,"msg":"login success","token":"synthetic-private-token"}'
                kind = "application/json"
                arrived.set()
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "synthetic-private-cookie=one")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with (
            tempfile.TemporaryDirectory(prefix="dev8-browser-") as folder,
            ExitStack() as resources,
        ):
            directory = Path(folder)
            snapshot = NetworkSnapshot(
                (
                    NetworkAdapter(
                        7,
                        "Synthetic",
                        "synthetic",
                        True,
                        ssid="Example-Campus",
                        ipv4=("192.0.2.10",),
                    ),
                )
            )
            network = SimpleNamespace(snapshot=lambda: snapshot, route_allows=lambda *_: True)
            profiles = ProfileService(ConfigStore(directory / "config.json"))
            origin = f"http://127.0.0.1:{server.server_port}"
            profiles.upsert(
                NetworkProfile(
                    "synthetic",
                    "示例",
                    "Example-Campus",
                    portal_page_url=origin + "/a79.htm",
                    bjut_api_origin=origin,
                    allow_http_auth=True,
                )
            )
            auth = SimpleNamespace(network=network, profiles=profiles, trace=OperationTrace())
            support = SupportService(directory, auth, directory / "reports")
            resources.callback(support.close)
            capture = BrowserCapture(support)
            cancel = threading.Event()

            def stop():
                arrived.wait(30)
                time.sleep(0.8)
                cancel.set()

            stopper = threading.Thread(target=stop, daemon=True)
            stopper.start()
            summary = capture.run(cancel)
            stopper.join(2)
            text = (support.session.directory / "PortalCapture_session.json").read_text(
                encoding="utf-8"
            )
            results = {
                "real_installed_browser_started": summary["request_count"] >= 2,
                "automatic_navigation_and_local_login_observed": summary["login_request_observed"],
                "server_summary_observed": summary["server_success_summary_observed"],
                "synthetic_secrets_hidden": all(
                    s not in text
                    for s in (
                        "synthetic-private-account",
                        "synthetic-private-password",
                        "synthetic-private-token",
                        "synthetic-private-cookie",
                    )
                ),
                "json_and_text_saved": (
                    support.session.directory / "PortalCapture_session.txt"
                ).is_file(),
                "real_campus_authentication": "not_attempted",
                "vault_access": "not_attempted",
            }
            results["passed"] = all(v is not False for v in results.values())
            return results
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


if __name__ == "__main__":
    try:
        result = run()
    except Exception as exc:
        result = {"passed": False, "failure_type": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
