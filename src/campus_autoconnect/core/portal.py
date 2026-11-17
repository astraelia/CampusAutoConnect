"""Strict origin validation. Redirect discovery never confers trust."""

import ipaddress
import re
from urllib.parse import urlsplit

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode, NetworkProfile, ProfileIssue

BJUT_WIRED_HOST = "lgn.bjut.edu.cn"
BJUT_WIRED_URL = f"https://{BJUT_WIRED_HOST}/"
BJUT_WIRED_PAGE = BJUT_WIRED_URL + "a79.htm"
BJUT_WIRED_STATUS = BJUT_WIRED_URL + "drcom/chkstatus"
BJUT_WIRED_LOGIN = BJUT_WIRED_URL + "drcom/login"
BJUT_WIRED_API = f"https://{BJUT_WIRED_HOST}:802/eportal/"
BJUT_WIRED_CONFIG = BJUT_WIRED_API + "portal/page/loadConfig"
_WIRED_TEMPLATE = re.compile(
    re.escape(BJUT_WIRED_API) + r"extern/[A-Za-z0-9_-]{1,48}/[A-Za-z0-9_-]{1,48}/pc\.js"
)

PROFILE_ISSUE_LABELS = {
    ProfileIssue.DISABLED: "档案已停用",
    ProfileIssue.PAGE_MISSING: "未填写认证页地址",
    ProfileIssue.API_MISSING: "未填写认证服务地址",
    ProfileIssue.HTTP_PERMISSION: "尚未明确允许 HTTP 认证",
    ProfileIssue.HTTPS_TRUST: "HTTPS 认证目标尚未加入精确信任列表",
    ProfileIssue.WIRED_PROTOCOL: "此入口的自动认证协议待核对，可手动打开",
}


def normalize_authority(value: str, *, default_port: int = 443) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("认证主机不能为空或包含首尾空白。")
    if re.search(r"[\s/@?#\\*%]", value):
        raise ValueError("填写精确主机名或主机名:端口，不得填写 URL、通配符或用户信息。")
    try:
        parts = urlsplit("https://" + value)
        host = parts.hostname
        port = parts.port
        if not host or parts.username or parts.password or parts.path:
            raise ValueError
        try:
            address = ipaddress.ip_address(host)
            normalized = f"[{address.compressed}]" if address.version == 6 else str(address)
        except ValueError:
            normalized = host.encode("idna").decode("ascii").lower()
            if normalized.endswith(".") or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in normalized.split(".")
            ):
                raise ValueError from None
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        return normalized if port in (None, default_port) else f"{normalized}:{port}"
    except (ValueError, UnicodeError) as exc:
        raise ValueError("认证主机格式无效。") from exc


def normalize_bjut_endpoints(page_url: str, api_origin: str) -> tuple[str, str]:
    """Explicit origins only. A captured HTTP URL never implies permission to use it."""
    if not isinstance(page_url, str) or not isinstance(api_origin, str):
        raise ValueError("认证页和认证服务地址必须为文本。")
    if not page_url and not api_origin:
        return "", ""
    normalized = []
    for value, page in ((page_url, True), (api_origin, False)):
        try:
            if not value or len(value) > 2048 or re.search(r"[\s\\]", value):
                raise ValueError
            parts = urlsplit(value)
            if (
                parts.scheme not in {"http", "https"}
                or parts.username is not None
                or parts.password is not None
                or parts.query
                or parts.fragment
                or parts.path not in (("/a79.htm",) if page else ("", "/"))
            ):
                raise ValueError
            authority = normalize_authority(
                parts.netloc, default_port=80 if parts.scheme == "http" else 443
            )
            normalized.append(f"{parts.scheme}://{authority}" + ("/a79.htm" if page else ""))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "填写实测认证页完整地址（/a79.htm）和认证服务源地址（含端口）。"
            ) from exc
    page, api = map(urlsplit, normalized)
    if page.scheme != api.scheme or page.hostname != api.hostname:
        raise ValueError("已验证分支要求认证页与认证服务使用相同协议和精确主机；不允许降级。")
    return normalized[0], normalized[1]


def normalize_wired_portal(url: str) -> tuple[str, str]:
    try:
        if not isinstance(url, str) or not 1 <= len(url) <= 2048 or re.search(r"[\s\\?#]", url):
            raise ValueError
        parts = urlsplit(url)
        path = parts.path or "/"
        if (
            parts.scheme != "https"
            or not re.fullmatch(r"/[a-zA-Z0-9._~/-]*", path)
            or "//" in path
            or {".", ".."}.intersection(path.split("/"))
        ):
            raise ValueError
        authority = normalize_authority(parts.netloc)
        return f"https://{authority}{path}", authority
    except (ValueError, TypeError) as exc:
        raise ValueError("请输入完整的 HTTPS 登录网址，去掉用户名、查询参数和片段。") from exc


def bjut_wired_portal_supported(url: str) -> bool:
    return url in (BJUT_WIRED_URL, BJUT_WIRED_PAGE)


def validate_target(url: str, profile: NetworkProfile) -> str:
    try:
        if profile.is_wired:
            entry, authority = normalize_wired_portal(profile.portal_page_url)
            if entry != profile.portal_page_url or profile.trusted_portal_hosts != (authority,):
                raise ValueError
            if url == entry:
                return authority
            if not bjut_wired_portal_supported(entry):
                raise ValueError
            if url not in {
                BJUT_WIRED_URL,
                BJUT_WIRED_PAGE,
                BJUT_WIRED_STATUS,
                BJUT_WIRED_LOGIN,
                BJUT_WIRED_CONFIG,
            } and not _WIRED_TEMPLATE.fullmatch(url):
                raise ValueError
            return BJUT_WIRED_HOST
        if re.search(r"[\s\\]", url):
            raise ValueError
        parts = urlsplit(url)
        if (
            parts.scheme not in {"http", "https"}
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or not parts.netloc
        ):
            raise ValueError
        if parts.scheme == "http":
            if profile.allow_http_auth is not True:
                raise CampusError(
                    ErrorCode.UNTRUSTED_TARGET,
                    "发现 HTTP 认证入口；本档案尚未明确允许 HTTP 兼容，未读取或提交凭据。",
                )
            page_url, api_origin = normalize_bjut_endpoints(
                profile.portal_page_url, profile.bjut_api_origin
            )
            authority = normalize_authority(parts.netloc, default_port=80)
            # The exception is limited to the two user-configured origins and observed paths.
            allowed_urls = {
                page_url,
                api_origin + "/eportal/portal/page/loadConfig",
                api_origin + "/eportal/portal/login",
            }
            if f"http://{authority}{parts.path}" not in allowed_urls:
                raise ValueError
            return authority
        authority = normalize_authority(parts.netloc)
        allowed = {normalize_authority(host) for host in profile.trusted_portal_hosts}
        if authority not in allowed:
            raise ValueError
        return authority
    except (ValueError, TypeError) as exc:
        raise CampusError(
            ErrorCode.UNTRUSTED_TARGET, "认证目标未获档案信任或未使用安全 HTTPS，已阻止提交。"
        ) from exc


def portal_entry(hint: str | None, profile: NetworkProfile) -> str | None:
    if profile.is_wired and hint:
        # An exact first-party discovery hint can identify the gateway; the app
        # opens its configured HTTPS entry independently and drops all query data.
        try:
            parts = urlsplit(hint)
            if re.search(r"[\s\\]", hint) or parts.fragment:
                raise ValueError
            authority = normalize_authority(
                parts.netloc, default_port=80 if parts.scheme == "http" else 443
            )
            path = parts.path or "/"
            if parts.scheme == "https" and f"https://{authority}{path}" == profile.portal_page_url:
                return profile.portal_page_url
            if (
                bjut_wired_portal_supported(profile.portal_page_url)
                and parts.scheme in {"http", "https"}
                and authority == BJUT_WIRED_HOST
                and path in {"/", "/a79.htm"}
            ):
                return profile.portal_page_url
        except ValueError:
            pass
        raise CampusError(ErrorCode.UNTRUSTED_TARGET, "发现的入口与有线档案确认的网关不一致。")
    return hint or profile.portal_page_url or None


def profile_setup_issues(
    profile: NetworkProfile, portal_url: str | None = None
) -> tuple[ProfileIssue, ...]:
    """Local readiness only; this never grants trust or replaces live protocol checks."""
    issues = []
    if not profile.enabled:
        issues.append(ProfileIssue.DISABLED)
    if profile.is_wired:
        if not profile.portal_page_url:
            return (*issues, ProfileIssue.PAGE_MISSING)
        try:
            validate_target(profile.portal_page_url, profile)
        except CampusError:
            issues.append(ProfileIssue.HTTPS_TRUST)
        else:
            if not bjut_wired_portal_supported(profile.portal_page_url):
                issues.append(ProfileIssue.WIRED_PROTOCOL)
        return tuple(issues)
    if not profile.portal_page_url:
        issues.append(ProfileIssue.PAGE_MISSING)
    if not profile.bjut_api_origin:
        issues.append(ProfileIssue.API_MISSING)
    if (
        any(
            value and value.startswith("http://")
            for value in (profile.portal_page_url, profile.bjut_api_origin, portal_url)
        )
        and not profile.allow_http_auth
    ):
        issues.append(ProfileIssue.HTTP_PERMISSION)
    for target in (profile.portal_page_url, profile.bjut_api_origin):
        if target.startswith("https://"):
            try:
                validate_target(target, profile)
            except CampusError:
                issues.append(ProfileIssue.HTTPS_TRUST)
                break
    return tuple(issues)


def profile_setup_summary(profile: NetworkProfile) -> str:
    issues = profile_setup_issues(profile)
    if issues:
        return "待补全：" + "；".join(PROFILE_ISSUE_LABELS[issue] for issue in issues)
    summary = "入口已配置，待实时核对"
    if profile.allow_zero_mac:
        summary += "；已允许页面全零 MAC"
    return summary
