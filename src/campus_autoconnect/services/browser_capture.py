"""Dedicated-browser capture under the same cross-process authentication lock."""

import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.core.portal import validate_target
from campus_autoconnect.infrastructure.capture_sanitizer import (
    outcome,
    safe_post,
    safe_url,
    should_watch,
)
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.services.capture_analysis import analyze_capture
from campus_autoconnect.services.support import SupportService


class BrowserCapture:
    def __init__(self, support: SupportService) -> None:
        self.support = support
        self.count = 0
        self.state = "idle"
        self.truncated = False
        self.probe_requested = threading.Event()
        self.last_payload: dict | None = None
        self.record_bytes = 0

    def _target(self) -> str:
        auth = self.support.authentication
        network = auth.network.snapshot()
        profile = auth.profiles.match(network.ssid)
        if profile is None or not profile.portal_page_url:
            return "http://www.msftconnecttest.com/connecttest.txt"
        validate_target(profile.portal_page_url, profile)
        if not auth.network.route_allows(profile.portal_page_url, network):
            raise CampusError(
                ErrorCode.ROUTE_UNCONFIRMED, "抓包前无法确认校园网路由，请先查看诊断。"
            )
        return profile.portal_page_url

    @staticmethod
    def launch(playwright):
        import os
        from pathlib import Path

        candidates = [{"channel": "msedge"}, {"channel": "chrome"}]
        for environment in ("LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)"):
            base = os.environ.get(environment)
            if base:
                for relative in (
                    "Microsoft/Edge/Application/msedge.exe",
                    "Google/Chrome/Application/chrome.exe",
                ):
                    path = Path(base) / relative
                    if path.is_file():
                        candidates.append({"executable_path": str(path)})
        for candidate in candidates:
            try:
                return playwright.chromium.launch(**candidate, headless=False, timeout=12000)
            except Exception:
                continue
        raise CampusError(
            ErrorCode.CONFIG_ERROR,
            "无法启动专用 Edge/Chrome，请确认已安装且能正常打开；未生成成功抓包。",
        )

    def run(self, cancel: threading.Event, *, launcher: Callable | None = None) -> dict:
        if self.state in {"saved", "empty"}:
            self.support.finish()
        self.support.begin()
        mutex = FileMutex(self.support.directory / "authentication.lock")
        records: list[dict] = []
        lookup: dict = {}
        started = datetime.now(UTC).isoformat()
        self.state, self.count, self.truncated = "waiting", 0, False
        self.last_payload, self.record_bytes = None, 0
        self.probe_requested.clear()
        deadline = time.monotonic() + 25
        acquired = False
        try:
            while not cancel.is_set():
                if mutex.acquire():
                    acquired = True
                    break
                if time.monotonic() >= deadline:
                    raise CampusError(
                        ErrorCode.BUSY, "已有认证仍在结束，未启动网页抓包；请等待后重试。"
                    )
                time.sleep(0.1)
            if not acquired or cancel.is_set():
                raise CampusError(ErrorCode.CANCELLED, "抓包启动已取消。")
            target = self._target()
            from playwright.sync_api import sync_playwright

            with sync_playwright() as driver:
                browser = (launcher or self.launch)(driver)
                try:
                    context = browser.new_context(accept_downloads=False)

                    def request(req):
                        if not should_watch(req.url, req.resource_type):
                            return
                        if len(records) >= 600:
                            self.truncated = True
                            return
                        try:
                            uri = safe_url(req.url)
                            if "invalid_url" in uri:
                                return
                            entry = {
                                "number": len(records) + 1,
                                "time": datetime.now(UTC).isoformat(),
                                "method": req.method
                                if req.method in {"GET", "POST", "HEAD"}
                                else "OTHER",
                                "kind": req.resource_type
                                if req.resource_type
                                in {"document", "xhr", "fetch", "script", "other"}
                                else "other",
                                "url": uri,
                            }
                            if req.method not in {"GET", "HEAD"}:
                                entry["post_data"] = safe_post(
                                    req.post_data, req.headers.get("content-type", "")
                                )
                            size = len(
                                json.dumps(entry, ensure_ascii=False, indent=2).encode("utf-8")
                            )
                            if self.record_bytes + size > 1024 * 1024:
                                self.truncated = True
                                return
                            self.record_bytes += size
                            records.append(entry)
                            lookup[req] = entry
                            self.count = len(records)
                        except Exception:
                            self.state = "partial"

                    def response(resp):
                        entry = lookup.get(resp.request)
                        if entry is not None:
                            entry["http_status"] = resp.status
                            location = resp.headers.get("location")
                            if location:
                                from urllib.parse import urljoin

                                redirect = safe_url(urljoin(resp.url, location))
                                size = len(
                                    json.dumps(redirect, ensure_ascii=False, indent=2).encode(
                                        "utf-8"
                                    )
                                )
                                if self.record_bytes + size <= 1024 * 1024:
                                    entry["redirect_location"] = redirect
                                    self.record_bytes += size
                                else:
                                    self.truncated = True

                    def finished(req):
                        entry = lookup.get(req)
                        if entry is None:
                            return
                        try:
                            resp = req.response()
                            if resp and any(
                                t in resp.headers.get("content-type", "").lower()
                                for t in ("json", "javascript", "text/plain")
                            ):
                                length = resp.headers.get("content-length")
                                # Avoid materializing an unbounded browser response into Python.
                                if length and length.isdecimal() and int(length) <= 65536:
                                    summary = outcome(resp.body())
                                    if summary:
                                        entry["response_summary"] = summary
                        except Exception:
                            self.state = "partial"

                    def failed(req):
                        if req in lookup:
                            lookup[req]["network_failure"] = "request_failed"

                    context.on("request", request)
                    context.on("response", response)
                    context.on("requestfinished", finished)
                    context.on("requestfailed", failed)
                    page = context.new_page()
                    self.state = "recording"
                    try:
                        page.goto(target, wait_until="domcontentloaded", timeout=14000)
                    except Exception:
                        self.state = "navigation_failed"
                    while not cancel.is_set() and browser.is_connected() and context.pages:
                        if self.probe_requested.is_set():
                            self.probe_requested.clear()
                            try:
                                context.pages[0].goto(
                                    target, wait_until="domcontentloaded", timeout=14000
                                )
                            except Exception:
                                self.state = "navigation_failed"
                        context.pages[0].wait_for_timeout(180)
                finally:
                    browser.close()
            payload = {
                "tool": "Campus Portal Capture / sanitized v1.2.0",
                "source": "dedicated_browser",
                "started_at": started,
                "finished_at": datetime.now(UTC).isoformat(),
                "count": len(records),
                "truncated": self.truncated,
                "capture_state": "stopped" if self.state == "recording" else self.state,
                "privacy": (
                    "本地保留目标主机/端口供配置；账号密码、Cookie、Token、原始正文不保存。"
                    "请勿直接分享此文件。"
                ),
                "requests": records,
            }
            self.last_payload = payload
            return self.retry_save()
        except CampusError:
            self.state = "failed"
            raise
        except ImportError as exc:
            self.state = "failed"
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "抓包依赖缺失，请重新完整解压新版程序包。"
            ) from exc
        except Exception as exc:
            self.state = "failed"
            raise CampusError(
                ErrorCode.UNKNOWN, "浏览器抓包异常结束，未报告为成功；可查看已保存的诊断。"
            ) from exc
        finally:
            if acquired:
                mutex.release()

    def retry_save(self) -> dict:
        if self.last_payload is None:
            raise CampusError(ErrorCode.CONFIG_ERROR, "尚无可重试保存的抓包记录。")
        try:
            path = self.support.session.write("PortalCapture_session.json", self.last_payload)
            summary = (
                analyze_capture(path)
                if self.last_payload["count"]
                else {
                    "request_count": 0,
                    "login_request_observed": False,
                    "server_success_summary_observed": False,
                    "limitations": ["空记录不证明认证成功；请只在专用浏览器中操作。"],
                }
            )
            summary["truncated"] = self.last_payload["truncated"]
            summary["capture_state"] = self.last_payload["capture_state"]
            self.support.session.write(
                "PortalCapture_session.txt",
                "浏览器抓包摘要\n" + json.dumps(summary, ensure_ascii=False, indent=2),
            )
            self.support.capture_summary = summary
            self.support.save()
            self.state = "saved" if self.last_payload["count"] else "empty"
            return summary
        except (CampusError, OSError):
            self.state = "failed"
            raise
