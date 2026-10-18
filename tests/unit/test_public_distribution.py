"""Publication must reject personal runtime data and preserve blank defaults."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_build", ROOT / "scripts/build_windows.py")
assert SPEC is not None and SPEC.loader is not None
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)


@pytest.mark.parametrize(
    "name",
    [
        "reports/diagnostic.json",
        "logs/campus.log",
        "config.json",
        "config.json.bak",
        "automation.json",
        "desktop.json",
        "report-policy.json",
        "credential-status.json",
        "PortalCapture_example.json",
        "campus-profiles-export.json",
        "private/input.txt",
        "sample.har",
        "sample.pcapng",
        ".env",
        "nested/config.json.io.lock",
    ],
)
def test_public_build_rejects_runtime_artifacts(tmp_path, name):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("synthetic private artifact", encoding="utf-8")
    with pytest.raises(ValueError):
        BUILD.validate_distribution_tree(tmp_path)


def test_public_build_accepts_only_runtime_libraries_and_public_docs(tmp_path):
    (tmp_path / "_internal").mkdir()
    (tmp_path / "_internal/library.dll").write_bytes(b"synthetic binary")
    (tmp_path / "LICENSE").write_text("synthetic license", encoding="utf-8")
    BUILD.validate_distribution_tree(tmp_path)


def test_repository_example_contains_no_network_identity():
    value = json.loads((ROOT / "config/config.example.json").read_text(encoding="utf-8"))
    assert value == {"schema_version": 1, "profiles": []}


def test_web_manual_links_have_real_web_targets():
    assert BUILD.web_manual("[检测](page:overview) [凭据](page:credentials)") == (
        "[检测](FEATURES.md#overview) [凭据](FEATURES.md#credentials)"
    )
