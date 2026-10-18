"""Export only approved current source and public docs; never copy private Git history."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCUMENTS = (
    "QUICK_START.md",
    "USER_MANUAL.md",
    "INSTALL_UNINSTALL.md",
    "MANUAL_CHECKLIST.md",
    "FEEDBACK_TEMPLATE.md",
    "CONFIGURATION.md",
    "FEATURES.md",
    "PRIVACY.md",
    "FAQ.md",
)
FORBIDDEN_PARTS = {"reports", "logs", "private", "diagnostics", "acceptance-evidence"}
SECRET_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{24,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{24,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)[a-z]:[\\/](?:users|documents|desktop)[\\/]"),
)


def public_files() -> dict[str, Path]:
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode("utf-8")
    selected = {}
    for name in tracked.split("\0"):
        if not name:
            continue
        path = Path(name)
        if name.startswith(("src/", "tests/", "scripts/", "packaging/")) or (
            name.startswith("软件检测/") and path.suffix in {".py", ".spec", ".cmd"}
        ):
            selected[name] = ROOT / name
    for directory in ("src", "tests", "scripts", "packaging"):
        for path in (ROOT / directory).rglob("*"):
            if (
                path.is_file()
                and path.suffix in {".py", ".spec", ".txt", ".cmd", ".ps1"}
                and "__pycache__" not in path.parts
            ):
                selected[path.relative_to(ROOT).as_posix()] = path
    for name in (
        "README.md",
        "LICENSE",
        ".gitignore",
        ".env.example",
        "pyproject.toml",
        "uv.lock",
        "Campus_AutoConnect_V0.1.md",
        "config/config.example.json",
    ):
        selected[name] = ROOT / name
    for path in ROOT.glob("*.png"):
        selected[path.name] = path
    for name in PUBLIC_DOCUMENTS:
        selected[f"docs/release/{name}"] = ROOT / "docs/release" / name
    for source, target in (
        ("docs/PROJECT_HISTORY.md", "docs/PROJECT_HISTORY.md"),
        ("docs/publication/ARCHITECTURE.md", "docs/architecture.md"),
        ("docs/publication/DEVELOPMENT.md", "docs/testing.md"),
        ("docs/publication/SECURITY.md", "docs/security.md"),
        ("docs/publication/CHANGELOG.md", "docs/release/CHANGELOG.md"),
        ("docs/publication/INSPECTOR.md", "软件检测/README.md"),
        ("docs/publication/INSPECTOR.md", "软件检测/使用说明.md"),
        ("docs/publication/INSPECTOR.md", "软件检测/测试与交接.md"),
    ):
        selected[target] = ROOT / source if (ROOT / source).is_file() else ROOT / target
    return selected


def audit_file(name: str, data: bytes) -> None:
    path = Path(name)
    if any(part.lower() in FORBIDDEN_PARTS for part in path.parts):
        raise ValueError("公开清单包含运行或私人资料。")
    if path.suffix.lower() in {".png", ".ico"}:
        return
    text = data.decode("utf-8-sig")
    if any(pattern.search(text) for pattern in SECRET_PATTERNS):
        raise ValueError(f"公开文件需要隐私复核：{name}")
    if name == "config/config.example.json" and json.loads(text) != {
        "schema_version": 1,
        "profiles": [],
    }:
        raise ValueError("公开配置必须为空网络档案。")


def export(destination: Path) -> dict:
    destination = destination.resolve()
    if destination == ROOT or not destination.is_relative_to(ROOT / ".cache"):
        raise ValueError("公开准备目录必须位于工作区.cache，且不能覆盖源码根。")
    selected = public_files()
    hashes = {}
    for name, source in selected.items():
        data = source.read_bytes()
        audit_file(name, data)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        hashes[name] = hashlib.sha256(data).hexdigest()
    instructions = (
        "# Campus AutoConnect development rules\n\n"
        "Windows 10/11 x64, Python 3.12+. Keep GUI/CLI on shared services.\n"
        "Use exact SSID and endpoint permission, TLS verification, Windows WinVault only, "
        "single manual submission and bounded retries. Never commit real credentials, "
        "network profiles, logs, reports or captures. Default profiles must be empty and "
        "automatic authentication disabled.\n\n"
        "Read README.md, docs/architecture.md, docs/security.md and docs/testing.md. "
        "Run full pytest, ruff check and ruff format --check before delivery. "
        "Mock success does not imply field acceptance.\n"
    )
    (destination / "AGENTS.md").write_text(instructions, encoding="utf-8")
    hashes["AGENTS.md"] = hashlib.sha256(instructions.encode()).hexdigest()
    return {
        "files": len(hashes),
        "sha256": dict(sorted(hashes.items())),
        "private_git_history_copied": False,
        "default_profiles": [],
        "credentials_included": False,
        "runtime_data_included": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    result = export(args.destination)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"files": result["files"], "default_profiles": [], "private_data": False}))


if __name__ == "__main__":
    main()
