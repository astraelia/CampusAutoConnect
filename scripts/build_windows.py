"""Reproducible local build entry. Artifacts stay under the workspace dist/build dirs."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from campus_autoconnect import __version__

ROOT = Path(__file__).resolve().parents[1]
NAME = f"CampusAutoConnect-{__version__}-win-x64"
PACKAGE = ROOT / "dist" / NAME


def validate_distribution_tree(package: Path) -> None:
    """Reject runtime data instead of silently putting it in a public archive."""
    forbidden_directories = {"reports", "logs", "private", "diagnostics", ".git", ".cache"}
    forbidden_names = {
        "config.json",
        "automation.json",
        "desktop.json",
        "report-policy.json",
        "credential-status.json",
        "monitor-status.json",
        "monitor-stop.json",
    }
    for path in package.rglob("*"):
        relative = path.relative_to(package)
        if path.is_symlink() or path.is_junction():
            raise ValueError("分发目录包含链接，请使用干净的构建输出目录。")
        if any(part.lower() in forbidden_directories for part in relative.parts):
            raise ValueError("分发目录包含运行资料，请保管后使用干净输出目录。")
        name = path.name.lower()
        if (
            any(name == item or name.startswith(item + ".") for item in forbidden_names)
            or name.startswith(("portalcapture_", "campus-profiles", ".env"))
            or name.endswith((".log", ".har", ".pcap", ".pcapng", ".io.lock"))
        ):
            raise ValueError("分发目录包含运行配置或私人记录，拒绝打包。")


def web_manual(content: str) -> str:
    return re.sub(r"\]\(page:([a-z]+)\)", r"](FEATURES.md#\1)", content)


def finalize() -> None:
    if not (PACKAGE / "CampusAutoConnect.exe").is_file():
        raise ValueError("Build the executables first")
    validate_distribution_tree(PACKAGE)
    documents = PACKAGE / "使用与核验"
    documents.mkdir(exist_ok=True)
    document_mapping = (
        ("docs/release/QUICK_START.md", "快速开始.md"),
        ("docs/release/USER_MANUAL.md", "使用手册.md"),
        ("docs/release/MANUAL_CHECKLIST.md", "人工核验清单.md"),
        ("docs/release/FEEDBACK_TEMPLATE.md", "问题反馈模板.md"),
        ("docs/release/INSTALL_UNINSTALL.md", "安装升级与卸载.md"),
        ("docs/release/CHANGELOG.md", "版本记录与已知限制.md"),
        ("docs/release/CONFIGURATION.md", "首次配置指南.md"),
        ("docs/release/FEATURES.md", "各功能使用帮助.md"),
        ("docs/release/PRIVACY.md", "隐私与默认配置.md"),
        ("docs/release/FAQ.md", "常见问题.md"),
        ("docs/PROJECT_HISTORY.md", "项目历史与已知问题.md"),
    )
    for source, target in document_mapping:
        content = (ROOT / source).read_text(encoding="utf-8")
        for old, new in document_mapping:
            content = re.sub(
                r"(?<=\()(?:\.\./)?" + re.escape(Path(old).name) + r"(?=[)#])",
                new,
                content,
            )
        (documents / target).write_text(content, encoding="utf-8")
    (PACKAGE / "先读我.txt").write_text(
        f"Campus AutoConnect {__version__} · Windows 10/11 x64\n\n"
        "请完整解压，双击 CampusAutoConnect.exe；保留同目录的 _internal。\n"
        "内嵌使用帮助含 12 章教程；诊断及抓包报告在程序目录 reports。凭据留空不表示未保存。\n"
        "无需安装 Python。先阅读“使用与核验/快速开始.md”和“人工核验清单.md”。\n"
        "空白网络档案、不附带账号密码或认证入口；新电脑需本人重新配置。\n"
        "中蓝公寓宿舍校园网已实测自动连接；本部其他区域和其他校区待验证。\n"
        "本版使用原生网络查询及受控 PowerShell 回退；HTTP 兼容需在对应档案中明确勾选。\n"
        "先退出旧版及其托盘窗口，再启动本版；完整保留 _internal 文件夹。\n"
        "检测网络 → 配置当前网络 → 从脱敏抓包填写认证地址，核对后明确允许 HTTP。\n"
        "旧档案显示待补全；修改入口后自动认证默认取消勾选，先手动测试。\n"
        "认证页全零 MAC 需在当前档案明确允许兼容；VLAN=0 保留页面原值。\n"
        "手动成功后再配置自动认证；后台可保存并启动，旧任务可主动修复到当前目录。\n"
        "自动认证默认关闭，登录启动任务默认不安装。\n"
        "登录后立即创建托盘，网络就绪后认证；升级后请主动修复旧任务以移除旧延迟。\n"
        "新电脑需重新保存 Windows 安全凭据并核对网络档案。日常连接不自动保存完整报告。\n"
        "报告清理默认 7 天/20 组/50 MiB；抓包默认保留，旧报告先预览确认。\n"
        "关闭窗口可收起到托盘；“退出程序”停止后台后退出。\n"
        "核验结果和问题请填写“使用与核验/问题反馈模板.md”交回。\n",
        encoding="utf-8-sig",
    )
    licenses = PACKAGE / "第三方许可"
    licenses.mkdir(exist_ok=True)
    runtime_packages = (
        "PySide6",
        "PySide6_Essentials",
        "PySide6_Addons",
        "shiboken6",
        "playwright",
        "greenlet",
        "pyee",
        "httpx",
        "httpcore",
        "anyio",
        "certifi",
        "idna",
        "h11",
        "keyring",
        "pywin32-ctypes",
        "jaraco.classes",
        "jaraco.context",
        "jaraco.functools",
        "more-itertools",
        "PyInstaller",
        "cffi",
        "pycparser",
        "setuptools",
        "packaging",
        "Pygments",
        "typing_extensions",
    )
    versions = {}
    for name in runtime_packages:
        distribution = importlib.metadata.distribution(name)
        versions[name] = distribution.version
        for item in distribution.files or ():
            if any(word in item.name.lower() for word in ("license", "copying", "notice")):
                source = Path(distribution.locate_file(item))
                if source.is_file():
                    target = licenses / name / Path(*item.parts[-3:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    (licenses / "NOTICE.txt").write_text(
        "Third-party components remain under their own licenses.\n"
        "PySide6/Qt: dynamically linked LGPLv3/GPL/commercial distributions.\n"
        "PyInstaller bootloader: GPLv2+ with an exception for bundled programs.\n"
        "Qt libraries are replaceable in _internal/PySide6; consult the copied licenses.\n"
        "Artwork was supplied by the user; no new artwork license is granted here.\n"
        "Project license: GNU GPL v3.0, included as LICENSE.\n",
        encoding="utf-8",
    )
    for source in (Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE"):
        if source.is_file():
            shutil.copyfile(source, licenses / "Python-LICENSE.txt")
            break
    shutil.copyfile(ROOT / "LICENSE", PACKAGE / "LICENSE")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True))
    information = {
        "version": __version__,
        "build_utc": datetime.now(UTC).isoformat(),
        "source_commit": commit,
        "source_dirty": dirty,
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "dependencies": versions,
        "signed": False,
        "real_bjut_authentication": "implemented_limited_branch_current_environment_user_confirmed",
        "field_verification": {
            "source": "user_feedback_2026_10_18",
            "confirmed_version": "1.0.0",
            "current_environment_login_and_logon_auto_login": "confirmed",
            "current_release_performance": "pending_retest",
            "other_computers_and_regions": "not_verified",
        },
        "protocol_detection": "observed_eportal_explicit_profile_http_opt_in",
        "distribution_defaults": {
            "network_profiles": "empty",
            "credentials_included": False,
            "automatic_authentication": False,
            "startup_task_included": False,
            "runtime_data_included": False,
        },
    }
    (PACKAGE / "BUILD_INFO.json").write_text(
        json.dumps(information, indent=2) + "\n", encoding="utf-8"
    )
    validate_distribution_tree(PACKAGE)
    manifest = {}
    for path in sorted(PACKAGE.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.json":
            manifest[path.relative_to(PACKAGE).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    (PACKAGE / "SHA256SUMS.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    archive = ROOT / "dist" / (NAME + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(PACKAGE.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(PACKAGE.parent).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(
        digest + "  " + archive.name + "\n", encoding="ascii"
    )
    print(
        json.dumps(
            {
                "package": NAME,
                "files": len(manifest),
                "zip_bytes": archive.stat().st_size,
                "zip_sha256": digest,
                "source_commit": commit,
                "source_dirty": dirty,
            },
            indent=2,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--finalize-only", action="store_true")
    args = parser.parse_args()
    (ROOT / "docs/release/USER_MANUAL.md").write_text(
        web_manual((ROOT / "src/campus_autoconnect/assets/help.md").read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    if not args.finalize_only:
        if PACKAGE.exists():
            validate_distribution_tree(PACKAGE)
        if platform.system() != "Windows" or platform.machine().lower() not in {"amd64", "x86_64"}:
            raise ValueError("Windows x64 is required")
        for target in (ROOT / "build", ROOT / "dist", PACKAGE):
            if (
                not target.resolve().is_relative_to(ROOT.resolve())
                or target.resolve() == ROOT.resolve()
            ):
                raise ValueError("Build output must remain inside the workspace")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--distpath",
                str(ROOT / "dist"),
                "--workpath",
                str(ROOT / "build"),
                str(ROOT / "packaging/CampusAutoConnect.spec"),
            ],
            cwd=ROOT,
            check=True,
            env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(ROOT / ".cache" / "pyinstaller")},
        )
    finalize()


if __name__ == "__main__":
    main()
