"""Bounded public-interface calls and launch observation; never inject into an EXE."""

import hashlib
import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.infrastructure.process_environment import system_process_environment
from campus_autoconnect.services.inspection import read_json, safe_version
from campus_autoconnect.services.inspection_records import Evidence, Outcome, Step


@dataclass(frozen=True)
class Target:
    executable: Path = field(repr=False)
    cli: Path | None = field(repr=False)
    digest: str
    version: str | None
    manifest_matches: bool | None


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            digest.update(data)
    return digest.hexdigest()


def inspect_target(path: Path) -> Target:
    path = path.resolve(strict=True)
    if path.name.lower() != "campusautoconnect.exe" or not path.is_file():
        raise ValueError("select the known GUI executable")
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("not a Windows executable")
    if path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("executable too large")
    cli = path.with_name("CampusAutoConnect-CLI.exe")
    if not cli.is_file():
        cli = None
    version = None
    try:
        info = read_json(path.parent / "BUILD_INFO.json", 64 * 1024)
        if isinstance(info, dict):
            version = safe_version(info.get("version"))
    except (OSError, ValueError, TypeError, RecursionError):
        pass
    digest = file_hash(path)
    matched = None
    try:
        manifest = read_json(path.parent / "SHA256SUMS.json", 512 * 1024)
        if not isinstance(manifest, dict):
            raise ValueError
        expected = manifest.get(path.name)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError
        matched = expected == digest
        if cli is not None:
            matched = matched and manifest.get(cli.name) == file_hash(cli)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, RecursionError):
        matched = False
    return Target(path, cli, digest, version, matched)


@dataclass(frozen=True)
class CommandResult:
    code: str
    returncode: int | None = None
    payload: object = field(default=None, repr=False)


def bounded_json(
    arguments: list[str],
    cancel: threading.Event,
    *,
    timeout: float = 40,
    limit: int = 64 * 1024,
) -> CommandResult:
    """Capture stdout only in bounded memory. stderr is never saved or displayed."""
    if cancel.is_set():
        return CommandResult("cancelled")
    try:
        with system_process_environment() as environment:
            environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            process = subprocess.Popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(Path(arguments[0]).parent),
                env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
    except OSError:
        return CommandResult("helper_start_failed")
    captured = bytearray()
    overflow = threading.Event()

    def drain() -> None:
        try:
            while data := process.stdout.read(4096):
                if len(captured) + len(data) > limit:
                    overflow.set()
                    break
                captured.extend(data)
        except (OSError, ValueError):
            overflow.set()

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    failure = None
    while process.poll() is None:
        if cancel.is_set():
            failure = "cancelled"
        elif overflow.is_set():
            failure = "helper_output_limit"
        elif time.monotonic() >= deadline:
            failure = "helper_timeout"
        if failure:
            # Only our short-lived CLI helper is stopped, never the GUI or its background.
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            break
        cancel.wait(0.025)
    reader.join(timeout=2)
    process.stdout.close()
    if failure:
        return CommandResult(failure, process.returncode)
    if overflow.is_set() or reader.is_alive():
        return CommandResult("helper_output_limit", process.returncode)
    try:
        # Reuse the strict duplicate-field/nonfinite handling without a temporary raw file.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        payload = json.loads(
            captured.decode("utf-8-sig"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return CommandResult("helper_invalid_output", process.returncode)
    return CommandResult("helper_result", process.returncode, payload)


def command_step(target: Target, mode: str, cancel: threading.Event) -> Step:
    if mode not in {"runtime", "diagnose"}:
        raise ValueError("unsupported public command")
    title = "EXE 运行环境自检" if mode == "runtime" else "EXE 新一次网络检测"
    if target.cli is None:
        return Step(
            mode,
            title,
            Outcome.SKIPPED,
            "cli_missing",
            "同目录缺少 CLI，无法读取公开 JSON 接口。",
            Evidence.EXE,
        )
    if target.manifest_matches is False:
        return Step(
            mode,
            title,
            Outcome.SKIPPED,
            "manifest_mismatch",
            "程序校验清单不匹配；未执行辅助进程。",
            Evidence.EXE,
        )
    started = time.monotonic()
    args = (
        [str(target.cli), "--self-check", "runtime"]
        if mode == "runtime"
        else [str(target.cli), "diagnose"]
    )
    result = bounded_json(args, cancel)
    facts = {"returncode": result.returncode}
    if result.code != "helper_result" or not isinstance(result.payload, dict):
        return Step(
            mode,
            title,
            Outcome.ERROR,
            result.code,
            "辅助检查未返回可用结果；原始标准输出和异常文本均未保存。",
            Evidence.EXE,
            facts,
            round((time.monotonic() - started) * 1000),
        )
    raw = result.payload
    version = safe_version(raw.get("version"))
    if version:
        facts["version"] = version
    if mode == "runtime":
        checks = raw.get("results")
        required = (
            "background_executable_available",
            "tls_certificate_verification",
            "windows_vault_backend_available",
        )
        passed = (
            raw.get("passed") is True
            and result.returncode == 0
            and raw.get("check") == "runtime"
            and version is not None
            and isinstance(checks, dict)
            and all(checks.get(key) is True for key in required)
        )
        if isinstance(checks, dict):
            for key in (
                "background_executable_available",
                "tls_certificate_verification",
                "windows_vault_backend_available",
            ):
                if type(checks.get(key)) is bool:
                    facts[key] = checks[key]
        return Step(
            mode,
            title,
            Outcome.PASS if passed else Outcome.ERROR,
            "runtime_passed" if passed else "runtime_failed",
            "此结果来自选定包的 runtime 自检；不含凭据写入或任务注册自检。",
            Evidence.EXE,
            facts,
            round((time.monotonic() - started) * 1000),
        )
    try:
        facts["state"] = AuthState(raw["state"]).value
        code = ErrorCode(raw["error_code"])
        facts["error_code"] = code.value
        for key in ("ssid_known", "portal_discovered", "log_unavailable"):
            if type(raw.get(key)) is bool:
                facts[key] = raw[key]
        checked_at = raw.get("checked_at")
        if isinstance(checked_at, str) and len(checked_at) <= 40:
            facts["checked_at"] = datetime.fromisoformat(checked_at).isoformat()
    except (ValueError, TypeError, KeyError):
        return Step(
            mode,
            title,
            Outcome.ERROR,
            "helper_invalid_output",
            "EXE 诊断字段不符合支持的结构，未回显原始结果。",
            Evidence.EXE,
        )
    ok = facts["state"] in {"AUTHENTICATED", "AUTH_REQUIRED"}
    return Step(
        mode,
        title,
        Outcome.PASS if ok else Outcome.WARNING,
        code.value,
        "这是调用 EXE diagnose 后产生的另一次检测，不代表 GUI 上一次点击的内部轨迹。",
        Evidence.EXE,
        facts,
        round((time.monotonic() - started) * 1000),
    )


class LaunchObserver:
    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.reported_exit = False

    def launch(self, target: Target) -> Step:
        if target.manifest_matches is False:
            return Step(
                "launch",
                "启动原软件",
                Outcome.BLOCKED,
                "manifest_mismatch",
                "EXE 与包内校验清单不匹配，未启动。",
                Evidence.TOOL,
            )
        try:
            with system_process_environment() as environment:
                environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
                self.process = subprocess.Popen(
                    [str(target.executable)],
                    cwd=str(target.executable.parent),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            return Step(
                "launch",
                "启动原软件",
                Outcome.PASS,
                "process_started",
                "启动请求已提交；是否出现窗口需人工确认。停止监测不会关闭原软件。",
                Evidence.TOOL,
            )
        except OSError:
            return Step(
                "launch",
                "启动原软件",
                Outcome.ERROR,
                "process_start_failed",
                "Windows 未能启动选定 EXE；未输出本机路径或原始异常。",
                Evidence.TOOL,
            )

    def poll(self) -> Step | None:
        if self.process is None or self.reported_exit:
            return None
        code = self.process.poll()
        if code is None:
            return None
        self.reported_exit = True
        return Step(
            "process_exit",
            "启动进程退出",
            Outcome.INFO if code == 0 else Outcome.ERROR,
            "process_returned" if code == 0 else "process_abnormal_exit",
            "进程正常返回；单实例可能已转交现有窗口，不能据此判定主窗口关闭。"
            if code == 0
            else "观测到启动进程异常退出；退出码不等于具体根因，需要结合其他证据。",
            Evidence.TOOL,
            {"returncode": code, "windows_exit_code": f"0x{code & 0xFFFFFFFF:08X}"},
        )


def default_target(anchor: Path) -> Path | None:
    for ancestor in (anchor, *list(anchor.parents)[:5]):
        dist = ancestor / "dist"
        if not dist.is_dir():
            continue
        candidates = list(dist.glob("CampusAutoConnect-*-win-x64/CampusAutoConnect.exe"))
        if candidates:

            def version_key(path):
                return tuple(int(x) for x in re.findall(r"\d+", path.parent.name))

            return max(candidates, key=version_key)
    return None
