"""Chinese CLI sharing application services. Passwords only enter via hidden prompt."""

import argparse
import getpass
import json
import sys
import uuid
import warnings
from collections.abc import Sequence
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthState, Credentials, NetworkProfile
from campus_autoconnect.core.portal import (
    normalize_authority,
    normalize_bjut_endpoints,
    profile_setup_summary,
)
from campus_autoconnect.services.application import ApplicationServices, build_services


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="campus", description="Campus AutoConnect · 校园网检测与有限自动认证"
    )
    commands = cli.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="检测网络和互联网状态，不读取认证凭据")
    commands.add_parser("scan", help="查看当前网络适配器、SSID、IP、网关及 DNS")
    commands.add_parser("profiles", help="列出已配置网络档案")
    capture = commands.add_parser("capture", help="只读分析本地脱敏抓包，不登录、不保存参数值")
    capture.add_argument("path", type=Path, help="Campus Portal Capture 1.1.0 的 JSON 结果文件")
    profile = commands.add_parser("profile", help="管理网络档案").add_subparsers(
        dest="profile_command", required=True
    )
    add = profile.add_parser("add", help="添加精确 SSID 档案")
    add.add_argument("--ssid", required=True, help="完整 SSID，精确区分大小写")
    add.add_argument("--name", required=True, help="显示名称")
    add.add_argument("--reference", default="shared", help="凭据引用，默认 shared")
    add.add_argument(
        "--trusted-host", action="append", default=[], help="实测可信 HTTPS 主机，可重复"
    )
    add.add_argument("--disabled", action="store_true", help="保存为停用档案")
    add.add_argument("--portal-page", default="", help="实测认证页完整地址，以 /a79.htm 结尾")
    add.add_argument("--api-origin", default="", help="实测认证服务源地址，包含协议和端口")
    add.add_argument(
        "--allow-http-auth",
        action="store_true",
        help="明确允许此档案的 HTTP 未加密认证，默认不允许",
    )
    add.add_argument(
        "--allow-zero-mac", action="store_true", help="明确允许本档案兼容页面全零 MAC，先手动测试"
    )
    add.add_argument(
        "--auto-auth", action="store_true", help="允许此档案自动认证；还需全局开关及后台"
    )
    remove = profile.add_parser("remove", help="删除档案，不删除共享凭据")
    remove.add_argument("profile_id", help="profiles 命令显示的档案 ID")
    credentials = commands.add_parser("credentials", help="Windows 安全凭据").add_subparsers(
        dest="credential_command", required=True
    )
    for name, help_text in (
        ("set", "隐藏提示输入密码并保存/更新"),
        ("delete", "删除指定引用的安全凭据"),
        ("status", "主动检查指定引用是否已保存，不显示内容"),
    ):
        sub = credentials.add_parser(name, help=help_text)
        sub.add_argument("--reference", default="shared", help="凭据引用，默认 shared")
    commands.add_parser("login", help="在当前可信档案执行一次认证，绝不自动重试")
    commands.add_parser("diagnose", help="检测后显示脱敏诊断，不包含网络标识或秘密")
    automation = commands.add_parser(
        "automation", help="全局自动认证开关，默认关闭"
    ).add_subparsers(dest="automation_command", required=True)
    for name in ("status", "enable", "disable"):
        automation.add_parser(name)
    monitor = commands.add_parser("monitor", help="独立后台监视进程").add_subparsers(
        dest="monitor_command", required=True
    )
    foreground = monitor.add_parser("run", help="前台运行，可用 Ctrl+C 或另一个终端的 stop 停止")
    foreground.add_argument("--duration", type=float, help="可选的有界运行秒数，最多 86400")
    for name in ("start", "stop", "status"):
        sub = monitor.add_parser(name)
        if name == "start":
            sub.add_argument("--duration", type=float, help="可选的后台运行秒数，最多 86400")
    startup = commands.add_parser(
        "startup", help="当前用户登录启动任务，默认未安装"
    ).add_subparsers(dest="startup_command", required=True)
    for name in ("status", "enable", "disable", "repair"):
        startup.add_parser(name)
    return cli


def _read_credentials() -> Credentials:
    if not sys.stdin.isatty():
        raise ValueError("凭据录入必须在交互终端中进行；不接收参数或管道密码。")
    username = input("校园网账号：").strip()
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("校园网密码（隐藏输入）：")
        except getpass.GetPassWarning as exc:
            raise ValueError("终端不能隐藏密码，请改用 GUI。") from exc
    if not username or not password:
        raise ValueError("账号和密码不能为空。")
    return Credentials(username, password)


def run(args: argparse.Namespace, services: ApplicationServices) -> int:
    match args.command:
        case "capture":
            print(json.dumps(services.analyze_capture(args.path), ensure_ascii=False, indent=2))
        case "profiles":
            profiles = services.profiles.list()
            for p in profiles:
                print(
                    f"{p.profile_id} | {p.display_name} | SSID={p.ssid} | "
                    f"启用={p.enabled} | 档案自动认证={p.auto_auth} | "
                    f"凭据={p.credential_ref} | {profile_setup_summary(p)}"
                )
            if not profiles:
                print("尚无档案，使用 campus profile add 或 GUI 添加。")
            if services.profiles.store.warning:
                print(services.profiles.store.warning)
        case "profile":
            if args.profile_command == "add":
                page, api = normalize_bjut_endpoints(args.portal_page, args.api_origin)
                profile = NetworkProfile(
                    uuid.uuid4().hex,
                    args.name,
                    args.ssid,
                    enabled=not args.disabled,
                    auto_auth=args.auto_auth,
                    credential_ref=args.reference,
                    trusted_portal_hosts=tuple(normalize_authority(h) for h in args.trusted_host),
                    portal_page_url=page,
                    bjut_api_origin=api,
                    allow_http_auth=args.allow_http_auth,
                    allow_zero_mac=args.allow_zero_mac,
                )
                services.profiles.upsert(profile)
                print(f"档案已保存，ID：{profile.profile_id}")
            else:
                services.profiles.remove(args.profile_id)
                print("档案已删除。共享凭据未删除。")
        case "credentials":
            if args.credential_command == "set":
                value = _read_credentials()
                services.credentials.set(args.reference, value)
                del value
                print("凭据已保存至 Windows Credential Manager。")
            elif args.credential_command == "delete":
                services.credentials.delete(args.reference)
                print("该引用的安全凭据已删除。")
            else:
                print("已保存。" if services.credentials.exists(args.reference) else "尚未保存。")
        case "scan":
            snapshot = services.authentication.network.snapshot()
            for a in snapshot.adapters:
                print(f"接口 {a.index} | {a.name} | 连接={a.connected} | SSID={a.ssid or '未识别'}")
                print(f"  IPv4={', '.join(a.ipv4) or '—'} | IPv6={', '.join(a.ipv6) or '—'}")
                print(f"  网关={', '.join(a.gateways) or '—'} | DNS={', '.join(a.dns) or '—'}")
            for warning in snapshot.warnings:
                print(f"网络查询提示：{warning}")
        case "status" | "login" | "diagnose":
            method = (
                services.authentication.login
                if args.command == "login"
                else services.authentication.check
            )
            result = method()
            services.record_result(result)
            if services.log_unavailable:
                print("提示：用户日志目录不可写，本次结果仍可查看。", file=sys.stderr)
            if args.command == "diagnose":
                print(json.dumps(services.diagnostics(), ensure_ascii=False, indent=2))
            else:
                print(f"{result.state.value} [{result.code.value}] {result.message}")
                if result.network.ssid:
                    print(f"当前 SSID：{result.network.ssid}")
            return 0 if result.state in {AuthState.AUTHENTICATED, AuthState.AUTH_REQUIRED} else 1
        case "automation" | "monitor" | "startup":
            automation = services.automation
            if automation is None:
                raise ValueError("自动认证服务未配置。")
            if args.command == "automation":
                if args.automation_command == "status":
                    print(f"全局自动认证：{automation.settings.load().enabled}")
                else:
                    enabled = args.automation_command == "enable"
                    automation.set_enabled(enabled)
                    print(
                        "全局自动认证已开启，需启用档案并运行后台。"
                        if enabled
                        else "全局自动认证已关闭；手动认证仍可用。"
                    )
            elif args.command == "startup":
                status = getattr(automation.startup, args.startup_command)()
                print(json.dumps(status, ensure_ascii=False, indent=2))
            else:
                match args.monitor_command:
                    case "run":
                        automation.run(args.duration)
                    case "start":
                        automation.start_background(args.duration)
                        print("后台进程已确认运行；用 campus monitor status 查看状态。")
                    case "stop":
                        queued = automation.stop_background()
                        print(
                            "已请求取消并停止后台，请稍后刷新状态。" if queued else "后台未运行。"
                        )
                    case "status":
                        print(json.dumps(automation.control.status(), ensure_ascii=False, indent=2))
    return 0


def main(argv: Sequence[str] | None = None, *, services: ApplicationServices | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args, services if services is not None else build_services())
    except CampusError as exc:
        print(f"错误 [{exc.code.value}]：{exc.message}", file=sys.stderr)
        return 1
    except ValueError:
        print("输入无效或档案存在重复，请检查参数及现有档案。", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("操作已取消。", file=sys.stderr)
        return 130
    except Exception:
        print("操作失败；未输出可能含敏感信息的底层异常。", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
