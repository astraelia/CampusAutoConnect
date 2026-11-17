"""Profile operations shared by GUI and CLI."""

import uuid
from dataclasses import replace
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    BJUT_WIRED_ADAPTER,
    ErrorCode,
    NetworkAdapter,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.portal import normalize_wired_portal
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.files import read_text_shared


class ProfileService:
    def __init__(self, store: ConfigStore) -> None:
        self.store = store

    def list(self) -> list[NetworkProfile]:
        return self.store.load()

    def match(self, ssid: str | None) -> NetworkProfile | None:
        profiles = self.list()
        if self.store.warning:
            return None
        matches = [p for p in profiles if p.enabled and not p.is_wired and p.ssid == ssid]
        return matches[0] if len(matches) == 1 else None

    def match_network(self, snapshot: NetworkSnapshot) -> NetworkProfile | None:
        adapter = snapshot.selected
        if adapter is None:
            return None
        profiles = self.list()
        if self.store.warning:
            return None
        matches = [p for p in profiles if p.enabled and p.matches_adapter(adapter)]
        return matches[0] if len(matches) == 1 else None

    def for_edit(self, adapter: NetworkAdapter) -> NetworkProfile | None:
        profiles = self.list()
        if self.store.warning:
            raise CampusError(ErrorCode.CONFIG_ERROR, "档案配置不可用，请先修复配置。")
        matches = [p for p in profiles if p.matches_adapter(adapter)]
        enabled = [p for p in matches if p.enabled]
        if len(enabled) == 1:
            return enabled[0]
        if len(matches) > 1:
            raise CampusError(ErrorCode.UNTRUSTED_NETWORK, "请在网络档案中选定要编辑的条目。")
        return matches[0] if matches else None

    def upsert(self, profile: NetworkProfile) -> None:
        self.store.update(
            lambda profiles: [p for p in profiles if p.profile_id != profile.profile_id] + [profile]
        )

    def remove(self, profile_id: str) -> None:
        def remove(profiles: list[NetworkProfile]) -> list[NetworkProfile]:
            if not any(p.profile_id == profile_id for p in profiles):
                raise ValueError("未找到指定档案。")
            return [p for p in profiles if p.profile_id != profile_id]

        self.store.update(remove)

    def export_to(self, path: Path) -> None:
        profiles = self.list()
        if self.store.warning:
            raise ValueError("请先修复本机档案配置。")
        ConfigStore._atomic_write(path, ConfigStore.encode(profiles) + "\n")

    def import_from(self, path: Path) -> int:
        profiles = ConfigStore.decode(read_text_shared(path, ConfigStore.MAX_BYTES))
        references = {profile.credential_ref: "import_" + uuid.uuid4().hex for profile in profiles}
        incoming = [
            replace(
                profile,
                profile_id=uuid.uuid4().hex,
                enabled=False,
                auto_auth=False,
                allow_http_auth=False,
                allow_zero_mac=False,
                credential_ref=references[profile.credential_ref],
                last_verified_at=None,
            )
            for profile in profiles
        ]
        self.store.update(lambda existing: existing + incoming)
        return len(incoming)


def new_wired_profile(adapter: NetworkAdapter, url: str = "") -> NetworkProfile:
    if not adapter.ethernet_ready:
        raise CampusError(ErrorCode.UNTRUSTED_NETWORK, "物理网卡尚未取得可用的 IPv4 地址和网关。")
    page, host = normalize_wired_portal(url) if url else ("", "")
    return NetworkProfile(
        uuid.uuid4().hex,
        "有线网络",
        "",
        adapter_id=BJUT_WIRED_ADAPTER,
        trusted_portal_hosts=(host,) if host else (),
        portal_page_url=page,
        wired_interface=adapter.guid,
        wired_gateways=adapter.wired_gateways,
    )
