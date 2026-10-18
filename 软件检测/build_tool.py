"""Build only this companion tool. Never replaces the existing application bundles."""

import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from campus_inspector import __version__

from campus_autoconnect import __version__ as reference_version

TOOL = Path(__file__).resolve().parent
ROOT = TOOL.parent
PACKAGE = TOOL / "dist" / f"CampusInspector-{__version__}-win-x64"


def finalize() -> None:
    for document in ("使用说明.md", "测试与交接.md"):
        shutil.copyfile(TOOL / document, PACKAGE / document)
    licenses = PACKAGE / "第三方许可"
    licenses.mkdir(exist_ok=True)
    dependencies = {}
    for name in (
        "PySide6",
        "PySide6_Essentials",
        "PySide6_Addons",
        "shiboken6",
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
        "packaging",
        "typing_extensions",
    ):
        distribution = importlib.metadata.distribution(name)
        dependencies[name] = distribution.version
        for item in distribution.files or ():
            if any(word in item.name.lower() for word in ("license", "copying", "notice")):
                source = Path(distribution.locate_file(item))
                if source.is_file():
                    target = licenses / name / Path(*item.parts[-3:])
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    if python_license.is_file():
        shutil.copyfile(python_license, licenses / "Python-LICENSE.txt")
    (licenses / "NOTICE.txt").write_text(
        "Private local Windows diagnostic companion.\n"
        "PySide6/Qt is dynamically linked; see LGPL/GPL/commercial terms in copied licenses.\n"
        "Qt libraries remain replaceable in _internal/PySide6.\n"
        "PyInstaller's bootloader has its GPL exception for bundled applications.\n"
        "Other components retain their own licenses.\n",
        encoding="utf-8",
    )
    source = {}
    for base, prefix in (
        (TOOL / "campus_inspector", "campus_inspector"),
        (ROOT / "src/campus_autoconnect", "campus_autoconnect"),
    ):
        for path in sorted(base.rglob("*.py")):
            source[prefix + "/" + path.relative_to(base).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    source["inspector.py"] = hashlib.sha256((TOOL / "inspector.py").read_bytes()).hexdigest()
    information = {
        "version": __version__,
        "built_at_utc": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "dependencies": dependencies,
        "reference_application_version": reference_version,
        "source_sha256": source,
        "signed": False,
        "real_login": "not_attempted",
    }
    (PACKAGE / "BUILD_INFO.json").write_text(
        json.dumps(information, indent=2) + "\n",
        encoding="utf-8",
    )
    sums = {
        p.relative_to(PACKAGE).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(PACKAGE.rglob("*"))
        if p.is_file() and p.name != "SHA256SUMS.json"
    }
    (PACKAGE / "SHA256SUMS.json").write_text(
        json.dumps(sums, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    archive = TOOL / "dist" / f"CampusInspector-{__version__}-win-x64.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as output:
        for path in sorted(PACKAGE.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(PACKAGE.parent).as_posix())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(
        digest + "  " + archive.name + "\n",
        encoding="ascii",
    )
    print(
        json.dumps({"files": len(sums), "zip_bytes": archive.stat().st_size, "zip_sha256": digest})
    )


def main() -> None:
    if "--finalize-only" not in sys.argv[1:]:
        if platform.system() != "Windows":
            raise ValueError("Windows is required")
        # All outputs are fixed descendants of this new companion folder.
        for path in (TOOL / "build", TOOL / "dist", PACKAGE):
            if not path.resolve().is_relative_to(TOOL.resolve()):
                raise ValueError("output outside tool folder")
        subprocess.run(
            [
                sys.executable,
                "-m",
                "PyInstaller",
                "--noconfirm",
                "--distpath",
                str(TOOL / "dist"),
                "--workpath",
                str(TOOL / "build"),
                str(TOOL / "CampusInspector.spec"),
            ],
            check=True,
            cwd=TOOL,
            env={**os.environ, "PYINSTALLER_CONFIG_DIR": str(ROOT / ".cache/pyinstaller")},
        )
    finalize()


if __name__ == "__main__":
    main()
