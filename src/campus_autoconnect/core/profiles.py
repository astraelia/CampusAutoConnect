"""Profile operations shared by GUI and CLI."""

import json
import uuid
from dataclasses import asdict, replace
from pathlib import Path

from campus_autoconnect.core.models import NetworkProfile
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
        matches = [p for p in profiles if p.enabled and p.ssid == ssid]
        return matches[0] if len(matches) == 1 else None

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
        payload = {"schema_version": 1, "profiles": [asdict(profile) for profile in profiles]}
        ConfigStore._atomic_write(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")

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
