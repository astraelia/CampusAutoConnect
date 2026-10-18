"""Local setup guidance must not silently grant network or transport trust."""

import json
from dataclasses import asdict, replace

import pytest

from campus_autoconnect.core.models import ProfileIssue
from campus_autoconnect.core.portal import profile_setup_issues, profile_setup_summary
from campus_autoconnect.infrastructure.config import ConfigStore, validate_profile

pytestmark = pytest.mark.mock


def test_legacy_profile_is_readable_but_requires_explicit_setup(profile):
    raw = asdict(profile)
    for key in ("portal_page_url", "bjut_api_origin", "allow_http_auth"):
        raw.pop(key)
    loaded = ConfigStore.decode(json.dumps({"schema_version": 1, "profiles": [raw]}))[0]
    assert profile_setup_issues(loaded, "http://portal.example.edu/a79.htm") == (
        ProfileIssue.PAGE_MISSING,
        ProfileIssue.API_MISSING,
        ProfileIssue.HTTP_PERMISSION,
    )
    assert "待补全" in profile_setup_summary(loaded)
    assert not loaded.allow_http_auth and not loaded.portal_page_url


def test_http_endpoint_fill_does_not_grant_permission(profile):
    draft = replace(
        profile,
        portal_page_url="http://portal.example.edu/a79.htm",
        bjut_api_origin="http://portal.example.edu:801",
    )
    assert profile_setup_issues(draft) == (ProfileIssue.HTTP_PERMISSION,)
    approved = replace(draft, allow_http_auth=True)
    assert profile_setup_issues(approved) == ()
    assert "待实时核对" in profile_setup_summary(approved)


def test_https_requires_both_explicit_authorities(profile):
    draft = replace(
        profile,
        portal_page_url="https://portal.example.edu/a79.htm",
        bjut_api_origin="https://portal.example.edu:802",
    )
    assert profile_setup_issues(draft) == (ProfileIssue.HTTPS_TRUST,)
    approved = replace(draft, trusted_portal_hosts=("portal.example.edu", "portal.example.edu:802"))
    assert not profile_setup_issues(approved)


def test_old_profiles_never_gain_zero_mac_permission(profile):
    raw = asdict(profile)
    raw.pop("allow_zero_mac")
    loaded = ConfigStore.decode(json.dumps({"schema_version": 1, "profiles": [raw]}))[0]
    assert not loaded.allow_zero_mac
    with pytest.raises(ValueError):
        validate_profile(replace(profile, allow_zero_mac=True))


@pytest.mark.parametrize("value", [1, "true", None])
def test_zero_mac_permission_is_strict_boolean(profile, value):
    with pytest.raises(ValueError):
        validate_profile(replace(profile, allow_zero_mac=value))


def test_zero_mac_permission_persists_but_never_survives_import(profiles, profile, tmp_path):
    approved = replace(
        profile,
        portal_page_url="https://portal.example.edu/a79.htm",
        bjut_api_origin="https://portal.example.edu:802",
        allow_zero_mac=True,
    )
    profiles.upsert(approved)
    assert profiles.match(profile.ssid).allow_zero_mac
    path = tmp_path / "export.json"
    profiles.export_to(path)
    profiles.import_from(path)
    imported = profiles.list()[-1]
    assert not imported.allow_zero_mac and not imported.auto_auth and not imported.enabled
