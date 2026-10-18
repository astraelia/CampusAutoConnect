"""Exercise task registration/removal with a unique name and a disabled logon trigger."""

import json
import re
import subprocess
import uuid
from contextlib import suppress

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.network import _run_powershell
from campus_autoconnect.infrastructure.startup import WindowsStartupService


def main() -> int:
    prefix = "CampusAutoConnect-M2-Smoke-" + uuid.uuid4().hex + "-"
    diagnostics = {}

    def temporary_runner(script: str, input_text: str) -> str:
        original_name = "$name = 'CampusAutoConnect-M2-' + $sid"
        original_trigger = "$trigger.Delay = 'PT0S'"
        if script.count(original_name) != 1 or script.count(original_trigger) != 1:
            raise ValueError("启动实现已变更，需要复核临时检查。")
        # Prefix is generated here, has no user input, and never identifies the formal task.
        script = script.replace(original_name, f"$name = '{prefix}' + $sid")
        script = script.replace(
            original_trigger, original_trigger + "\n    $trigger.Enabled = $false"
        )
        script = script.replace(
            "$xml.Task.Triggers.LogonTrigger.Enabled -ne 'false' -and",
            "$xml.Task.Triggers.LogonTrigger.Enabled -eq 'false' -and",
        )
        script = script.replace(
            "ConvertTo-Json -Compress -InputObject (Inspect-ManagedTask $existing)",
            r"""
if ($existing) {
    $xml = [xml](Export-ScheduledTask -TaskPath '\' -TaskName $name)
    if ($xml.Task.Triggers.LogonTrigger.Enabled -ne 'false') {
        throw 'Temporary smoke trigger must remain disabled'
    }
}
ConvertTo-Json -Compress -InputObject (Inspect-ManagedTask $existing)
""",
        )
        script = script.replace(
            "    Register-ScheduledTask -TaskPath",
            r"""
    ConvertTo-Json -Compress -InputObject @{
        principal_logon = [string]$principal.LogonType
        principal_level = [string]$principal.RunLevel
        principal_user_matches = ($principal.UserId -eq $sid)
        trigger_user_matches = ($trigger.UserId -eq $sid)
        trigger_delay = [string]$trigger.Delay
        trigger_enabled = [bool]$trigger.Enabled
        execution_limit = [string]$settings.ExecutionTimeLimit
        multiple_instances = [string]$settings.MultipleInstances
        action_is_file = [bool](Test-Path -LiteralPath $action.Execute -PathType Leaf)
    }
    Register-ScheduledTask -TaskPath""",
        )
        diagnostics["last_operation"] = json.loads(input_text)["command"]
        try:
            output = _run_powershell(script, input_text)
            return output.splitlines()[-1]
        except CampusError as exc:
            underlying = exc.__cause__
            diagnostics["safe_failure_type"] = type(underlying).__name__
            if isinstance(underlying, subprocess.CalledProcessError):
                with suppress(ValueError, TypeError):
                    diagnostics["definition"] = json.loads(underlying.stdout)
                diagnostics["hresults"] = sorted(
                    set(re.findall(r"0x[0-9A-Fa-f]{8}", underlying.stderr or ""))
                )
                diagnostics["permission_denied"] = "PermissionDenied" in (underlying.stderr or "")
                diagnostics["parse_error"] = "ParserError" in (underlying.stderr or "")
                failing = re.search(
                    r"FullyQualifiedErrorId\s*:\s*[^,\r\n]+,([A-Za-z][A-Za-z0-9-]+)",
                    underlying.stderr or "",
                )
                diagnostics["failing_cmdlet"] = failing.group(1) if failing else "unknown"
            raise

    startup = WindowsStartupService(runner=temporary_runner)
    result = {}
    try:
        if startup.status()["installed"]:
            raise ValueError("临时任务名发生冲突。")
        fields = ("installed", "owned", "configured", "enabled")
        enabled = startup.enable()
        result["registered_with_disabled_trigger"] = all(enabled[key] for key in fields)
        status = startup.status()
        result["queried_owned_current_user_limited_configuration"] = all(
            status[key] for key in fields
        )
    except CampusError as exc:
        result["failure_code"] = exc.code.value
        result["diagnostics"] = dict(diagnostics)
    finally:
        try:
            result["removed"] = not startup.disable()["installed"]
        except CampusError as exc:
            result["cleanup_failure_code"] = exc.code.value
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return (
        0
        if set(result)
        == {
            "registered_with_disabled_trigger",
            "queried_owned_current_user_limited_configuration",
            "removed",
        }
        and all(result.values())
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
