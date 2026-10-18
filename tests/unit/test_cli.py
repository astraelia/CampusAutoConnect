import pytest

from campus_autoconnect.cli.main import main, parser
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.automation_application import AutomationService
from campus_autoconnect.services.connectivity import ConnectivityService
from campus_autoconnect.services.monitor import MonitorControl

pytestmark = pytest.mark.mock


@pytest.fixture
def app_services(network, profiles, credentials):
    return ApplicationServices(
        profiles,
        credentials,
        AuthenticationService(network, profiles, credentials, ConnectivityService()),
    )


def test_cli_profiles_add_remove(app_services, capsys):
    assert (
        main(["profile", "add", "--ssid", "Study", "--name", "活动室"], services=app_services) == 0
    )
    assert main(["profiles"], services=app_services) == 0
    assert "活动室" in capsys.readouterr().out
    profile = app_services.profiles.match("Study")
    assert main(["profile", "remove", profile.profile_id], services=app_services) == 0
    assert app_services.profiles.match("Study") is None


def test_password_cli_argument_rejected():
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["credentials", "set", "--password", "synthetic"])
    assert error.value.code == 2


def test_no_secret_echo_in_credential_status(app_services, capsys):
    assert main(["credentials", "status"], services=app_services) == 0
    output = capsys.readouterr().out
    assert "已保存" in output
    assert "synthetic" not in output


def test_credential_set_refuses_pipe(app_services, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["credentials", "set"], services=app_services) == 2
    assert "synthetic-password" not in capsys.readouterr().err


def test_m2_global_and_monitor_cli_are_independent_from_manual_and_startup(
    app_services, tmp_path, credentials, capsys
):
    class Startup:
        calls = 0

        def status(self):
            self.calls += 1
            return {"installed": False, "owned": False, "configured": False, "enabled": False}

    startup = Startup()
    settings = AutomationStore(tmp_path / "automation.json")
    app_services.automation = AutomationService(settings, MonitorControl(tmp_path), startup, None)
    assert main(["automation", "status"], services=app_services) == 0
    assert "False" in capsys.readouterr().out
    assert main(["automation", "enable"], services=app_services) == 0
    assert settings.load().enabled
    assert startup.calls == credentials.reads == 0
    assert main(["monitor", "status"], services=app_services) == 0
    assert '"running": false' in capsys.readouterr().out
    assert main(["monitor", "stop"], services=app_services) == 0
    assert main(["startup", "status"], services=app_services) == 0
    assert startup.calls == 1
    assert main(["automation", "disable"], services=app_services) == 0
    assert not settings.load().enabled
