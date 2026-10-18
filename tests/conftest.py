"""All normal tests use synthetic networks and credentials, never the host's secrets."""

import os
import threading
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from campus_autoconnect.core.models import (
    Credentials,
    NetworkAdapter,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.config import ConfigStore


class MemoryCredentials:
    def __init__(self) -> None:
        self.values: dict[str, Credentials] = {}
        self.reads = 0

    def exists(self, reference: str) -> bool:
        return reference in self.values

    def get(self, reference: str) -> Credentials | None:
        self.reads += 1
        return self.values.get(reference)

    def set(self, reference: str, value: Credentials) -> None:
        self.values[reference] = value

    def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class FakeNetwork:
    def __init__(self, snapshot: NetworkSnapshot) -> None:
        self.current = snapshot
        self.route_safe = True
        self.calls = 0
        self.on_snapshot = None

    def snapshot(self) -> NetworkSnapshot:
        self.calls += 1
        if self.on_snapshot:
            self.on_snapshot(self.calls)
        return self.current

    def route_allows(self, url: str, snapshot: NetworkSnapshot) -> bool:
        return self.route_safe


@pytest.fixture
def snapshot() -> NetworkSnapshot:
    return NetworkSnapshot(
        (
            NetworkAdapter(
                7,
                "Example Wi-Fi",
                "00000000-0000-0000-0000-000000000007",
                True,
                ssid="Example-Campus",
                ipv4=("192.0.2.10",),
                ipv6=("2001:db8::10",),
                gateways=("192.0.2.1",),
                dns=("192.0.2.53",),
            ),
        )
    )


@pytest.fixture
def network(snapshot) -> FakeNetwork:
    return FakeNetwork(snapshot)


@pytest.fixture
def profile() -> NetworkProfile:
    return NetworkProfile(
        "dorm", "示例宿舍", "Example-Campus", trusted_portal_hosts=("portal.example.edu",)
    )


@pytest.fixture
def profiles(tmp_path: Path, profile) -> ProfileService:
    service = ProfileService(ConfigStore(tmp_path / "config.json"))
    service.upsert(profile)
    return service


@pytest.fixture
def credentials() -> MemoryCredentials:
    value = MemoryCredentials()
    value.set("shared", Credentials("synthetic-account", "synthetic-password-only-for-tests"))
    return value


@pytest.fixture
def cancel() -> threading.Event:
    return threading.Event()
