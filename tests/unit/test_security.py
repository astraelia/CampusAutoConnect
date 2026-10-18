import logging

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials, ErrorCode
from campus_autoconnect.core.portal import normalize_authority, validate_target
from campus_autoconnect.infrastructure.logging import SafeFormatter, redact
from campus_autoconnect.security.credentials import WindowsCredentialStore

pytestmark = pytest.mark.mock


def test_credential_selfcheck_never_uses_the_application_service(monkeypatch):
    from campus_autoconnect.selfcheck import credential_check

    services = []

    class IsolatedVault:
        SERVICE = "CampusAutoConnect/v1"

        def __init__(self):
            self.values = {}

        def set(self, reference, value):
            assert self.SERVICE.startswith("CampusAutoConnect/selfcheck/")
            services.append(self.SERVICE)
            self.values[reference] = value

        def get(self, reference):
            return self.values.get(reference)

        def delete(self, reference):
            self.values.pop(reference, None)

        def exists(self, reference):
            return reference in self.values

    monkeypatch.setattr(
        "campus_autoconnect.security.credentials.WindowsCredentialStore", IsolatedVault
    )
    assert all(credential_check().values())
    assert len(set(services)) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://portal.example.edu/login",
        "https://portal.example.edu.evil.test/",
        "https://evil.test@portal.example.edu/",
        "https://portal.example.edu:8443/",
        "https://portal.example.edu./",
        "file:///secret",
        "https://portal.example.edu\\@evil.test/",
        "https://portal.example.edu/#secret",
        "https://portal.example.edu%2eevil.test/",
    ],
)
def test_untrusted_target_rejected(profile, url):
    with pytest.raises(CampusError) as error:
        validate_target(url, profile)
    assert error.value.code == ErrorCode.UNTRUSTED_TARGET


def test_exact_https_host_and_default_port(profile):
    assert (
        validate_target("https://PORTAL.example.edu:443/login?challenge=test", profile)
        == "portal.example.edu"
    )
    assert normalize_authority("[2001:db8::1]:8443") == "[2001:db8::1]:8443"


def test_credential_repr_has_no_secret():
    assert "secret" not in repr(Credentials("private-account", "secret"))
    assert "private-account" not in repr(Credentials("private-account", "secret"))


def test_win_vault_read_write_delete(monkeypatch):
    values = {}

    class FakeVault:
        def set_password(self, service, ref, value):
            values[(service, ref)] = value

        def get_password(self, service, ref):
            return values.get((service, ref))

        def delete_password(self, service, ref):
            del values[(service, ref)]

    monkeypatch.setattr(WindowsCredentialStore, "_backend", staticmethod(lambda: FakeVault()))
    store = WindowsCredentialStore()
    assert not store.exists("shared")
    first = Credentials("synthetic-one", "password-one")
    second = Credentials("synthetic-two", "password-two")
    store.set("shared", first)
    assert store.get("shared") == first
    store.set("shared", second)
    assert store.get("shared") == second
    store.delete("shared")
    assert not store.exists("shared")
    store.delete("shared")


@pytest.mark.parametrize("operation", ["get", "set", "delete", "exists"])
def test_credential_failure_no_raw_exception(monkeypatch, operation, tmp_path):
    def fail():
        raise RuntimeError("password=LEAK_ME token=DO_NOT_PRINT")

    monkeypatch.setattr(WindowsCredentialStore, "_backend", staticmethod(fail))
    store = WindowsCredentialStore()
    with pytest.raises(CampusError) as error:
        if operation == "set":
            store.set("shared", Credentials("fake", "fake"))
        else:
            getattr(store, operation)("shared")
    assert "LEAK_ME" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


def test_backend_ignores_user_plaintext_selection(monkeypatch):
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyrings.alt.file.PlaintextKeyring")
    from keyring.backends.Windows import WinVaultKeyring

    assert type(WindowsCredentialStore._backend()) is WinVaultKeyring


def test_log_redacts_secrets_urls_headers_and_exceptions():
    raw = (
        "password=abc\nAuthorization: Bearer hi\nCookie: session=hi\n"
        "https://p.test/?x=y 192.0.2.1\nknown-secret"
    )
    safe = redact(raw, ("known-secret",))
    assert all(
        value not in safe
        for value in ("abc", "Bearer", "session=", "x=y", "192.0.2.1", "known-secret")
    )
    record = logging.LogRecord("test", logging.ERROR, "", 0, "safe event", (), None)
    record.exc_info = (ValueError, ValueError("password=LEAK"), None)
    assert "LEAK" not in SafeFormatter().format(record)


def test_application_event_log_contains_only_state_and_code(
    tmp_path, profiles, credentials, snapshot
):
    from campus_autoconnect.core.models import AuthResult, AuthState
    from campus_autoconnect.infrastructure.logging import setup_logging
    from campus_autoconnect.services.application import ApplicationServices

    logger = setup_logging(tmp_path)
    services = ApplicationServices(profiles, credentials, None, event_logger=logger)
    try:
        services.record_result(
            AuthResult(
                AuthState.UNKNOWN,
                ErrorCode.UNKNOWN,
                "password=DO_NOT_LOG",
                snapshot,
                "https://portal.example.edu/?token=DO_NOT_LOG",
            )
        )
        for handler in logger.handlers:
            handler.flush()
        content = (tmp_path / "campus.log").read_text(encoding="utf-8")
        assert "state=UNKNOWN code=unknown" in content
        assert all(
            secret not in content
            for secret in (
                "DO_NOT_LOG",
                "portal.example.edu",
                "192.0.2.10",
                "Example-Campus",
            )
        )
    finally:
        for handler in list(logger.handlers):
            handler.close()
            logger.removeHandler(handler)
