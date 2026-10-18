"""SYNTHETIC TEST PROTOCOL, never a BJUT interface and not shipped in the wheel."""

import httpx

from campus_autoconnect.adapters.base import AdapterDetection, AdapterReply
from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.core.portal import validate_target
from campus_autoconnect.services.connectivity import request_error_code


class SyntheticPortalAdapter:
    def __init__(self, client_factory) -> None:
        self.client_factory = client_factory
        self.calls = 0
        self.state = AuthState.UNKNOWN

    def detect(self, profile, result):
        validate_target(result.portal_url, profile)
        return AdapterDetection(True, target_url=result.portal_url)

    def authenticate(self, target_url, credentials):
        self.calls += 1
        self.state = AuthState.AUTHENTICATING
        try:
            with self.client_factory() as client:
                response = client.post(
                    target_url,
                    json={"username": credentials.username, "password": credentials.password},
                )
            if 300 <= response.status_code < 400:
                return AdapterReply(False, ErrorCode.UNTRUSTED_TARGET, "Mock: 拒绝认证重定向。")
            if response.status_code >= 500:
                return AdapterReply(False, ErrorCode.SERVER_ERROR, "Mock: 服务器异常。")
            payload = response.json()
            code = {
                "bad_credentials": ErrorCode.INVALID_CREDENTIALS,
                "captcha": ErrorCode.MANUAL_ACTION,
                "changed": ErrorCode.PROTOCOL_CHANGED,
            }.get(payload.get("error"), ErrorCode.UNKNOWN)
            if payload.get("ok") is True:
                return AdapterReply(True)
            return AdapterReply(False, code, "Mock: 合成协议拒绝请求。")
        except httpx.RequestError as exc:
            return AdapterReply(False, request_error_code(exc), "Mock: 请求失败。")
        except (ValueError, AttributeError):
            return AdapterReply(False, ErrorCode.PROTOCOL_CHANGED, "Mock: 响应结构变化。")

    def prepare(self, profile, network, guard):
        pass  # The synthetic protocol has no page/configuration preflight.

    def verify(self, result):
        self.state = AuthState.AUTHENTICATED if result.online else AuthState.UNKNOWN
        return result.online

    def get_status(self):
        return self.state
