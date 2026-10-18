import json
from dataclasses import asdict, replace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.config import ConfigStore, validate_profile

pytestmark = pytest.mark.mock


def test_config_round_trip_and_backup(profiles, profile):
    changed = replace(profile, display_name="活动室", credential_ref="independent")
    profiles.upsert(changed)
    assert profiles.list() == [changed]
    backup = profiles.store.path.with_suffix(".json.bak")
    assert ConfigStore(backup).load() == [profile]
    assert "synthetic-password" not in profiles.store.path.read_text(encoding="utf-8")


def test_exact_multi_ssid_match(profiles, profile):
    other = replace(profile, profile_id="study", ssid="Example-Study")
    disabled = replace(profile, profile_id="off", ssid="Example-Disabled", enabled=False)
    profiles.upsert(other)
    profiles.upsert(disabled)
    assert profiles.match("Example-Campus") == profile
    assert profiles.match("Example-Study") == other
    assert profiles.match("example-campus") is None
    assert profiles.match("Example-Disabled") is None
    assert profiles.match("BJUT-Unknown") is None
    assert profiles.match(None) is None


def test_duplicate_enabled_ssid_rejected_without_change(profiles, profile):
    before = profiles.store.path.read_bytes()
    with pytest.raises(CampusError):
        profiles.upsert(replace(profile, profile_id="duplicate"))
    assert profiles.store.path.read_bytes() == before


def test_remove_profile_keeps_others(profiles, profile):
    profiles.upsert(replace(profile, profile_id="other", ssid="Other"))
    profiles.remove(profile.profile_id)
    assert [p.profile_id for p in profiles.list()] == ["other"]
    with pytest.raises(ValueError):
        profiles.remove("missing")


def test_corrupt_primary_recovers_valid_backup_and_refuses_overwrite(profiles, profile):
    profiles.upsert(replace(profile, display_name="最新档案"))
    profiles.store.path.write_text("{broken", encoding="utf-8")
    assert profiles.list() == [profile]
    assert profiles.store.warning
    assert profiles.match(profile.ssid) is None
    with pytest.raises(CampusError):
        profiles.upsert(profile)
    assert profiles.store.path.read_text(encoding="utf-8") == "{broken"


@pytest.mark.parametrize("payload", ["[]", "null", "{}", '{"schema_version":99,"profiles":[]}'])
def test_bad_config_safe_empty(tmp_path, payload):
    path = tmp_path / "config.json"
    path.write_text(payload, encoding="utf-8")
    store = ConfigStore(path)
    assert store.load() == []
    assert store.warning


def test_reject_secret_field(tmp_path, profile):
    raw = asdict(profile)
    raw["password"] = "NEVER_ACCEPT_THIS"
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"schema_version": 1, "profiles": [raw]}), encoding="utf-8")
    store = ConfigStore(path)
    assert store.load() == []
    assert store.warning


@pytest.mark.parametrize(
    "field,value",
    [
        ("ssid", ""),
        ("ssid", "测" * 11),
        ("display_name", "\n"),
        ("enabled", "yes"),
        ("auto_auth", 1),
        ("credential_ref", "../bad"),
        ("trusted_portal_hosts", ("*.example.edu",)),
        ("adapter_id", "invented"),
        ("last_verified_at", "invalid"),
    ],
)
def test_profile_validation(profile, field, value):
    with pytest.raises((ValueError, TypeError)):
        validate_profile(replace(profile, **{field: value}))


def test_empty_store_is_non_mutating(tmp_path):
    path = tmp_path / "config.json"
    assert ProfileService(ConfigStore(path)).list() == []
    assert not path.exists()


def test_legacy_profile_has_no_implicit_http_permission(profile):
    raw = asdict(profile)
    for field in ("portal_page_url", "bjut_api_origin", "allow_http_auth"):
        raw.pop(field)
    loaded = ConfigStore.decode(json.dumps({"schema_version": 1, "profiles": [raw]}))[0]
    assert not loaded.allow_http_auth
    assert loaded.portal_page_url == loaded.bjut_api_origin == ""


@pytest.mark.parametrize("value", [1, "true", None, []])
def test_http_permission_requires_boolean(profile, value):
    with pytest.raises(ValueError):
        validate_profile(replace(profile, allow_http_auth=value))


def test_http_permission_cannot_be_granted_without_precise_endpoints(profile):
    with pytest.raises(ValueError):
        validate_profile(replace(profile, allow_http_auth=True))


def test_http_profile_round_trip_and_import_revokes_permission(profiles, profile, tmp_path):
    profile = replace(
        profile,
        portal_page_url="http://portal.example.edu/a79.htm",
        bjut_api_origin="http://portal.example.edu:801",
        allow_http_auth=True,
    )
    profiles.upsert(profile)
    assert profiles.list() == [profile]
    path = tmp_path / "profiles-export.json"
    profiles.export_to(path)
    profiles.import_from(path)
    imported = profiles.list()[-1]
    assert not imported.allow_http_auth
    assert not imported.enabled and not imported.auto_auth
    assert imported.credential_ref != profile.credential_ref
    assert imported.portal_page_url == profile.portal_page_url


def test_example_config_is_valid_and_has_no_preconfigured_network():
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "config" / "config.example.json"
    assert ConfigStore(path).load() == []


def test_atomic_primary_write_failure_preserves_previous_file(profiles, profile, monkeypatch):
    from campus_autoconnect.infrastructure import config

    original = profiles.store.path.read_bytes()
    real_replace = config.os.replace

    def fail_primary(source, target):
        if target == profiles.store.path:
            raise OSError("synthetic write failure")
        real_replace(source, target)

    monkeypatch.setattr(config.os, "replace", fail_primary)
    with pytest.raises(CampusError):
        profiles.upsert(replace(profile, display_name="不会写入"))
    assert profiles.store.path.read_bytes() == original
    assert not list(profiles.store.path.parent.glob(".campus-*"))


def test_deeply_nested_config_recovers_and_rejects_overwrite(tmp_path, profile):
    path = tmp_path / "config.json"
    raw = "[" * 2000 + "]" * 2000
    path.write_text(raw, encoding="utf-8")
    store = ConfigStore(path)
    assert store.load() == []
    assert store.warning
    with pytest.raises(CampusError):
        store.save([profile])
    assert path.read_text(encoding="utf-8") == raw
