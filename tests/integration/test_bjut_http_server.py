"""Local HTTP socket exercise of the production adapter; all credentials are synthetic."""

import json
import logging
import threading
from contextlib import suppress
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from campus_autoconnect.adapters.eportal import CONFIG_PATH, LOGIN_PATH
from campus_autoconnect.core.models import AuthState, ConnectivityResult, Credentials, ErrorCode
from campus_autoconnect.services.authentication import AuthenticationService
from tests.unit.test_authentication import SequenceConnectivity

pytestmark = pytest.mark.mock


@pytest.mark.parametrize("redirect", [False, True])
@pytest.mark.parametrize("full_account", [False, True])
@pytest.mark.parametrize("zero_context", [False, True])
def test_production_eportal_get_over_real_local_http_socket(
    network, profiles, profile, credentials, redirect, full_account, zero_context, caplog
):
    queries = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # GET request paths can contain secrets; never let the test server print them.

        def do_GET(self):
            parts = urlsplit(self.path)
            query = parse_qs(parts.query, keep_blank_values=True)
            status, headers = 200, {}
            if parts.path == "/a79.htm":
                body = b"var v46ip='192.0.2.10';var ss4='020000000007';var vlanid='12';"
                if zero_context:
                    body = body.replace(b"020000000007", b"000000000000").replace(
                        b"vlanid='12'", b"vlanid='0'"
                    )
            elif parts.path == CONFIG_PATH:
                assert query["wlan_vlan_id"] == ["0" if zero_context else "12"]
                data = dict.fromkeys(
                    (
                        "en_md5",
                        "password_cut",
                        "account_prefix",
                        "enable_alias",
                        "io_mode",
                        "ipv6_state",
                        "enable_hotelop_login",
                        "en_perceive",
                        "enable_https",
                    ),
                    "0",
                )
                data.update(
                    login_method="1",
                    account_suffix="@synthetic-school",
                    ep_http_port=str(self.server.server_port),
                    ep_https_port="802",
                    domain_name="",
                )
                body = (
                    query["callback"][0] + "(" + json.dumps({"code": 1, "data": data}) + ")"
                ).encode()
            elif parts.path == LOGIN_PATH:
                queries.append(query)
                if redirect:
                    status, body = 302, b""
                    headers["Location"] = "http://untrusted.example.test/never-follow"
                else:
                    body = (query["callback"][0] + '({"result":1});').encode()
            else:
                status, body = 404, b""
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        profiles.upsert(
            replace(
                profile,
                portal_page_url=origin + "/a79.htm",
                bjut_api_origin=origin,
                allow_http_auth=True,
                allow_zero_mac=zero_context,
            )
        )
        username = "synthetic+user" + ("@synthetic-school" if full_account else "")
        credentials.set("shared", Credentials(username, "synthetic +&密码"))
        service = AuthenticationService(
            network,
            profiles,
            credentials,
            SequenceConnectivity(
                ConnectivityResult(portal_url=origin + "/a79.htm"), ConnectivityResult(online=True)
            ),
        )
        with caplog.at_level(logging.DEBUG):
            result = service.login()
        assert len(queries) == 1
        assert result.progress.login_request_attempted is True
        assert queries[0]["user_account"] == ["synthetic+user@synthetic-school"]
        assert queries[0]["user_password"] == ["synthetic +&密码"]
        assert queries[0]["lang"] == ["zh-cn", "zh"]
        assert queries[0]["wlan_user_mac"] == ["000000000000" if zero_context else "020000000007"]
        if redirect:
            assert result.code == ErrorCode.UNTRUSTED_TARGET
        else:
            assert result.state == AuthState.AUTHENTICATED
        assert "synthetic" not in result.message
        assert "synthetic+user" not in caplog.text
        assert "user_password" not in caplog.text
        assert "synthetic%20" not in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
