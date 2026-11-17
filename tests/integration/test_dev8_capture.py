import threading
from contextlib import nullcontext

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.services.browser_capture import BrowserCapture
from campus_autoconnect.services.support import SupportService

pytest_plugins = ["tests.unit.test_bjut_auth"]
pytestmark = pytest.mark.mock


@pytest.mark.parametrize("write_failure", [False, True])
@pytest.mark.parametrize("ending", ["stop", "browser_closed", "driver_error"])
def test_browser_capture_auto_navigation_redaction_and_auth_mutex(
    bjut_service, tmp_path, credentials, monkeypatch, write_failure, ending
):
    from playwright.sync_api import Error as PlaywrightError

    auth, requests, _, _ = bjut_service
    auth._operation_lock = FileMutex(tmp_path / "authentication.lock")
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    capture = BrowserCapture(support)
    cancel = threading.Event()
    urls = []

    class Request:
        resource_type = "document"
        method = "GET"

        def __init__(self, url):
            self.url = url

        def response(self):
            return Response(self)

    class Response:
        status = 200
        headers = {
            "content-type": "application/json",
            "content-length": "64",
            "set-cookie": "secret-cookie",
        }

        def __init__(self, request):
            self.request = request

        def body(self):
            return b'{"result":1,"msg":"login success","token":"secret-token"}'

    class Context:
        callbacks = {}
        pages = []

        def on(self, name, callback):
            self.callbacks[name] = callback

        def new_page(self):
            self.pages = [self]
            return self

        def goto(self, url, **kwargs):
            urls.append(url)
            for address in (
                url,
                "http://portal.example.edu:801/eportal/portal/page/loadConfig",
                "http://portal.example.edu:801/eportal/portal/login"
                "?user_account=secret-account&user_password=secret-password",
            ):
                req = Request(address)
                self.callbacks["request"](req)
                self.callbacks["response"](Response(req))
                self.callbacks["requestfinished"](req)
            if ending == "stop":
                cancel.set()

        def wait_for_timeout(self, _):
            if ending == "browser_closed":
                self.pages = []
                raise PlaywrightError("Target page has been closed")
            raise RuntimeError("synthetic driver interruption")

    class Browser:
        closed = False

        def new_context(self, **kwargs):
            assert kwargs == {"accept_downloads": False}
            assert auth.login().code == ErrorCode.BUSY
            assert credentials.reads == 0
            return Context()

        def close(self):
            self.closed = True
            if ending == "browser_closed":
                raise PlaywrightError("Browser has already been closed")

        def is_connected(self):
            return not self.closed

    browser = Browser()
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: nullcontext(object()))
    original_write = support.session.write
    ssid = auth.network.snapshot().ssid
    if write_failure:

        def deny(*_):
            raise CampusError(ErrorCode.CONFIG_ERROR, "模拟保存失败。")

        monkeypatch.setattr(support.session, "write", deny)
        with pytest.raises(CampusError):
            capture.run(cancel, launcher=lambda _: browser, wifi_ssid=ssid)
        assert capture.state == "failed" and capture.last_payload is not None
        monkeypatch.setattr(support.session, "write", original_write)
        result = capture.retry_save()
    else:
        result = capture.run(cancel, launcher=lambda _: browser, wifi_ssid=ssid)
    assert urls == ["http://portal.example.edu/a79.htm"]
    assert result["login_request_observed"] and result["server_success_summary_observed"]
    assert (
        result["capture_state"]
        == {"stop": "stopped", "browser_closed": "browser_closed", "driver_error": "partial"}[
            ending
        ]
    )
    assert capture.wifi_configuration() == (
        ssid,
        "http://portal.example.edu/a79.htm",
        "http://portal.example.edu:801",
    )
    assert capture.saved_path == support.session.directory / "PortalCapture_session.json"
    assert capture.saved_path.with_suffix(".txt").is_file()
    output = capture.saved_path.read_text(encoding="utf-8")
    assert all(
        v not in output
        for v in ("secret-account", "secret-password", "secret-token", "secret-cookie")
    )
    assert not requests and credentials.reads == 0 and browser.closed
    mutex = FileMutex(tmp_path / "authentication.lock")
    assert mutex.acquire()
    mutex.release()


def test_browser_start_failure_does_not_create_success_capture(bjut_service, tmp_path, monkeypatch):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    capture = BrowserCapture(support)
    monkeypatch.setattr("playwright.sync_api.sync_playwright", lambda: nullcontext(object()))

    def fail(_):
        raise CampusError(ErrorCode.CONFIG_ERROR, "浏览器不可用。")

    with pytest.raises(CampusError):
        capture.run(threading.Event(), launcher=fail)
    assert capture.state == "failed"
    assert not list(support.session.directory.glob("PortalCapture*"))
