import json

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials, ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.security.credentials import WindowsCredentialStore
from campus_autoconnect.services.credential_management import CredentialManagement

pytestmark = pytest.mark.mock


def test_receipt_survives_restart_without_reading_secrets(tmp_path, credentials):
    manager = CredentialManagement(credentials, tmp_path)
    new = Credentials("private-input-account", "private-input-password")
    assert manager.save("shared", new).state == "confirmed"
    reads = credentials.reads
    restarted = CredentialManagement(credentials, tmp_path)
    status = restarted.snapshot("shared")
    assert status.state == "confirmed" and status.historical
    assert "本次启动尚未重新检查" in status.label()
    assert credentials.reads == reads
    text = (tmp_path / "credential-status.json").read_text(encoding="utf-8")
    assert new.username not in text and new.password not in text
    # An external deletion invalidates current presence without falsifying the past receipt.
    credentials.delete("shared")
    assert restarted.snapshot("shared").historical
    assert restarted.check("shared").state == "absent"
    assert restarted.snapshot("another").state == "unknown"


@pytest.mark.parametrize("mode", ["lost", "corrupt", "unreadable"])
def test_windows_write_is_not_confirmed_if_readback_fails(monkeypatch, mode):
    class Vault:
        def set_password(self, *_):
            pass

        def get_password(self, *_):
            if mode == "unreadable":
                raise RuntimeError("private-do-not-echo")
            return None if mode == "lost" else '{"username":"bad","password":"bad"}'

    monkeypatch.setattr(WindowsCredentialStore, "_backend", staticmethod(Vault))
    with pytest.raises(CampusError) as raised:
        WindowsCredentialStore().set("shared", Credentials("new-account", "new-secret"))
    assert raised.value.code == ErrorCode.CREDENTIAL_VERIFY
    assert "private-do-not-echo" not in raised.value.message


def test_check_failure_is_distinct_from_absent(tmp_path, credentials, monkeypatch):
    manager = CredentialManagement(credentials, tmp_path)
    assert manager.check("shared").state == "present"

    def fail(_):
        raise CampusError(ErrorCode.CREDENTIAL_STORE, "安全存储不可用。")

    monkeypatch.setattr(credentials, "exists", fail)
    status = manager.check("shared")
    assert status.state == "error"
    assert "无法确认" in status.label()
    assert "shared" not in json.dumps(manager.diagnostic())
    restarted = CredentialManagement(credentials, tmp_path)
    assert restarted.snapshot("shared").state == "error"
    assert restarted.snapshot("shared").historical


def test_receipt_write_failure_does_not_undo_verified_credential(
    tmp_path, credentials, monkeypatch
):
    def fail(*_):
        raise OSError("synthetic-permission-error")

    monkeypatch.setattr(ConfigStore, "_atomic_write", fail)
    manager = CredentialManagement(credentials, tmp_path)
    value = Credentials("new-account", "new-secret")
    status = manager.save("shared", value)
    assert status.state == "confirmed" and not status.receipt_saved
    assert credentials.get("shared") == value


def test_corrupt_receipt_cannot_claim_current_presence(tmp_path, credentials):
    (tmp_path / "credential-status.json").write_text(
        '{"schema_version":true,"receipts":{"shared":{"state":"confirmed","checked_at":"2026-10-18"}}}',
        encoding="utf-8",
    )
    manager = CredentialManagement(credentials, tmp_path)
    assert manager.snapshot("shared").state == "unknown"
    assert credentials.reads == 0
