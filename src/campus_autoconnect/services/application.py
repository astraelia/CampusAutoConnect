"""Composition root and privacy-preserving diagnostic projection."""

import logging
from dataclasses import dataclass
from pathlib import Path

from campus_autoconnect import __version__
from campus_autoconnect.core.models import AuthResult
from campus_autoconnect.core.network import WindowsNetworkProvider
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.config import ConfigStore, user_data_dir
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.logging import (
    log_operation_timing,
    log_result,
    setup_logging,
)
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.security.credentials import CredentialStore, WindowsCredentialStore
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.automation import AutomationCoordinator
from campus_autoconnect.services.automation_application import AutomationService
from campus_autoconnect.services.capture_analysis import analyze_capture
from campus_autoconnect.services.connectivity import ConnectivityService
from campus_autoconnect.services.credential_management import CredentialManagement
from campus_autoconnect.services.desktop import DesktopService
from campus_autoconnect.services.monitor import MonitorControl, MonitorRuntime
from campus_autoconnect.services.support import SupportService


@dataclass
class ApplicationServices:
    profiles: ProfileService
    credentials: CredentialStore
    authentication: AuthenticationService
    last_result: AuthResult | None = None
    event_logger: logging.Logger | None = None
    log_unavailable: bool = False
    automation: AutomationService | None = None
    desktop: DesktopService | None = None
    credential_management: CredentialManagement | None = None
    support: SupportService | None = None

    def __post_init__(self) -> None:
        if self.credential_management is None:
            self.credential_management = CredentialManagement(
                self.credentials, self.profiles.store.path.parent
            )

    def analyze_capture(self, path: Path) -> dict:
        # Deliberately never retained in last_result, logs, configuration or diagnostics.
        return analyze_capture(path)

    def record_result(self, result: AuthResult) -> None:
        self.last_result = result
        if self.event_logger is not None:
            try:
                log_result(self.event_logger, result)
                trace = getattr(self.authentication, "trace", None)
                if trace is not None:
                    log_operation_timing(self.event_logger, trace.snapshot())
                self.log_unavailable |= any(
                    getattr(handler, "failed", False) for handler in self.event_logger.handlers
                )
            except OSError:
                self.log_unavailable = True
        if self.support is not None:
            try:
                self.support.record(self.diagnostics())
            except Exception:
                self.support.save_error = True

    def diagnostics(self) -> dict:
        result = self.last_result
        return {
            "version": __version__,
            "phase": "M3_manual_verification_pending",
            "real_bjut_protocol": "observed_eportal_implemented_http_opt_in",
            "field_verification": {
                "source": "user_feedback_2026_10_18",
                "version": "1.0.0",
                "current_environment_manual_login": "confirmed",
                "windows_logon_autostart_and_auto_login": "confirmed",
                "current_release_performance": "pending_retest",
                "other_computers_and_regions": "not_verified",
            },
            "state": result.state.value if result else "NOT_CHECKED",
            "error_code": result.code.value if result else "none",
            "authentication": result.progress.diagnostic() if result else None,
            "checked_at": result.checked_at if result else None,
            "adapter_count": len(result.network.adapters) if result else 0,
            "ssid_known": result.network.ssid is not None if result else False,
            "portal_discovered": result.portal_url is not None if result else False,
            "network_warnings": list(result.network.warnings) if result else [],
            "environment_proxy_policy": "ignored",
            "tls_verification": "required",
            "log_unavailable": self.log_unavailable,
            "automation": self.automation.cached_status if self.automation else None,
            "identifiers": "SSID/account/IP/host/profile/URL/body are withheld",
            "credential_management": self.credential_management.diagnostic()
            if self.credential_management
            else None,
            "network_query": self.authentication.network.diagnostics()
            if callable(getattr(getattr(self.authentication, "network", None), "diagnostics", None))
            else None,
            "network_query_scope": "current_gui_or_cli_process",
        }


def build_services(
    directory: Path | None = None, *, report_root: Path | None = None
) -> ApplicationServices:
    directory = directory if directory is not None else user_data_dir()
    profiles = ProfileService(ConfigStore(directory / "config.json"))
    operation_lock = FileMutex(directory / "authentication.lock")
    credentials = WindowsCredentialStore(mutation_lock=operation_lock)
    try:
        logger = setup_logging(directory / "logs")
    except OSError:
        logger = None
    network = WindowsNetworkProvider()
    services = ApplicationServices(
        profiles,
        credentials,
        AuthenticationService(
            network,
            profiles,
            credentials,
            ConnectivityService(),
            operation_lock=operation_lock,
        ),
        event_logger=logger,
        log_unavailable=logger is None,
        desktop=DesktopService(directory),
    )
    settings = AutomationStore(directory / "automation.json")
    control = MonitorControl(directory)
    services.automation = AutomationService(
        settings,
        control,
        WindowsStartupService(),
        lambda: MonitorRuntime(
            AutomationCoordinator(
                services.authentication, profiles, settings, record_result=services.record_result
            ),
            network,
            profiles,
            settings,
            control,
            logger=logger,
        ),
    )
    services.support = SupportService(directory, services.authentication, report_root)
    return services
