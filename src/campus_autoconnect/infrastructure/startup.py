"""Explicit current-user Task Scheduler integration; never asks for a Windows password."""

import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.core.network import _PREFIX, _run_powershell
from campus_autoconnect.infrastructure.launch import (
    FROZEN_STARTUP_ARGUMENTS,
    SOURCE_STARTUP_ARGUMENTS,
    LaunchCommand,
    startup_command,
)

_SCRIPT = (
    _PREFIX
    + r"""
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$name = 'CampusAutoConnect-M2-' + $sid
$marker = 'Campus AutoConnect M2 current-user managed task v1'
$arguments = [string]$request.arguments
function Is-CurrentUser([string]$value) {
    if ($value -eq $sid) { return $true }
    try {
        $account = [Security.Principal.NTAccount]::new($value)
        return ($account.Translate([Security.Principal.SecurityIdentifier]).Value -eq $sid)
    } catch { return $false }
}
function Find-ManagedTask {
    try {
        return Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
    } catch {
        if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { return $null }
        throw
    }
}
function Inspect-ManagedTask($existing) {
    $owned = $false
    $configured = $false
    if ($existing) {
    $xml = [xml](Export-ScheduledTask -TaskPath '\' -TaskName $name)
    $principal = $xml.Task.Principals.Principal
    $exec = @($xml.Task.Actions.Exec)
    $knownAction = ($exec.Count -eq 1 -and (
        ([IO.Path]::GetFileName([string]$exec[0].Command) -eq 'pythonw.exe' -and
         $exec[0].Arguments -in @('-X utf8 -m campus_autoconnect.cli.main monitor run',
                                '-X utf8 -m campus_autoconnect --startup')) -or
        ([IO.Path]::GetFileName([string]$exec[0].Command) -eq 'CampusAutoConnect.exe' -and
         $exec[0].Arguments -in @('--background', '--startup'))))
    $owned = ($existing.Description -eq $marker -and
        @($xml.Task.Principals.Principal).Count -eq 1 -and (Is-CurrentUser $principal.UserId) -and
        $principal.LogonType -eq 'InteractiveToken' -and
        $existing.Principal.RunLevel -eq 'Limited' -and
        ([string]::IsNullOrEmpty([string]$principal.RunLevel) -or
            $principal.RunLevel -eq 'LeastPrivilege') -and
        $xml.Task.Actions.ChildNodes.Count -eq 1 -and
        $knownAction)
    $configured = ($owned -and $exec[0].Command -eq $request.executable -and
        $exec[0].Arguments -eq $arguments -and
        $xml.Task.Triggers.ChildNodes.Count -eq 1 -and
        (Is-CurrentUser $xml.Task.Triggers.LogonTrigger.UserId) -and
        $xml.Task.Triggers.LogonTrigger.Enabled -ne 'false' -and
        ([string]::IsNullOrEmpty([string]$xml.Task.Triggers.LogonTrigger.Delay) -or
            $xml.Task.Triggers.LogonTrigger.Delay -eq 'PT0S') -and
        $exec[0].WorkingDirectory -eq [IO.Path]::GetDirectoryName([string]$request.executable) -and
        $xml.Task.Settings.MultipleInstancesPolicy -eq 'IgnoreNew' -and
        $xml.Task.Settings.Hidden -eq 'true')
    }
    $lastRun = $null
    $lastResult = $null
    $running = $false
    $pathValid = $false
    if ($owned) {
        $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $name -ErrorAction Stop
        if ($info.LastRunTime.Year -ge 2000) {
            $lastRun = $info.LastRunTime.ToUniversalTime().ToString('o')
            $lastResult = ('0x{0:X8}' -f [uint32]$info.LastTaskResult)
        }
        $running = ($existing.State -eq 'Running')
        $pathValid = (Test-Path -LiteralPath ([string]$exec[0].Command) -PathType Leaf)
    }
    return @{
        installed = [bool]$existing
        owned = [bool]$owned
        configured = [bool]$configured
        enabled = [bool]($existing -and $existing.State -ne 'Disabled')
        running = [bool]$running
        executable_exists = [bool]$pathValid
        last_run_at = $lastRun
        last_result = $lastResult
    }
}
$existing = Find-ManagedTask
$before = Inspect-ManagedTask $existing
if ($request.command -in @('enable', 'repair')) {
    if ($existing -and -not $before.owned) { throw 'Task ownership conflict' }
    if ($request.command -eq 'repair' -and -not $existing) { throw 'Managed task not found' }
    $action = New-ScheduledTaskAction -Execute $request.executable -Argument $arguments `
        -WorkingDirectory ([IO.Path]::GetDirectoryName([string]$request.executable))
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $sid
    $trigger.Delay = 'PT0S'
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser `
        -LogonType Interactive -RunLevel Limited
    if (-not (Is-CurrentUser $principal.UserId)) { throw 'Task principal identity mismatch' }
    $keepDisabled = ($request.command -eq 'repair' -and -not $before.enabled)
    $settings = New-ScheduledTaskSettingsSet -Hidden -MultipleInstances IgnoreNew `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -Disable:$keepDisabled
    Register-ScheduledTask -TaskPath '\' -TaskName $name -Description $marker `
        -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Force | Out-Null
    $existing = Find-ManagedTask
} elseif ($request.command -eq 'disable' -and $existing) {
    if (-not $before.owned) { throw 'Task ownership conflict' }
    Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false
    $existing = Find-ManagedTask
}
ConvertTo-Json -Compress -InputObject (Inspect-ManagedTask $existing)
"""
)


class WindowsStartupService:
    def __init__(
        self,
        *,
        executable: Path | None = None,
        arguments: tuple[str, ...] | None = None,
        runner: Callable[[str, str], str] = _run_powershell,
    ) -> None:
        launch = startup_command()
        self.executable = executable if executable is not None else launch.executable
        self.arguments = (
            arguments
            if arguments is not None
            else (
                FROZEN_STARTUP_ARGUMENTS
                if self.executable.name.lower() == "campusautoconnect.exe"
                else SOURCE_STARTUP_ARGUMENTS
            )
        )
        self._runner = runner

    def status(self) -> dict:
        return self._operate("status")

    def enable(self) -> dict:
        LaunchCommand(self.executable, self.arguments).validate()
        return self._operate("enable")

    def disable(self) -> dict:
        return self._operate("disable")

    def repair(self) -> dict:
        """Migrate only our existing task; preserve disabled state and never run it."""
        LaunchCommand(self.executable, self.arguments).validate()
        return self._operate("repair")

    def _operate(self, command: str) -> dict:
        try:
            raw = json.loads(
                self._runner(
                    _SCRIPT,
                    json.dumps(
                        {
                            "command": command,
                            "executable": str(self.executable),
                            "arguments": " ".join(self.arguments),
                        }
                    ),
                )
            )
            fields = {"installed", "owned", "configured", "enabled"}
            details = {"running", "executable_exists", "last_run_at", "last_result"}
            if (
                not isinstance(raw, dict)
                or set(raw) not in (fields, fields | details)
                or any(type(raw[key]) is not bool for key in fields)
            ):
                raise ValueError
            if details <= raw.keys():
                if any(type(raw[key]) is not bool for key in ("running", "executable_exists")):
                    raise ValueError
                stamp = raw["last_run_at"]
                if stamp is not None and (
                    not isinstance(stamp, str)
                    or len(stamp) > 40
                    or datetime.fromisoformat(stamp).tzinfo is None
                ):
                    raise ValueError
                result = raw["last_result"]
                if result is not None and (
                    not isinstance(result, str)
                    or len(result) != 10
                    or not result.startswith("0x")
                    or any(c not in "0123456789ABCDEF" for c in result[2:])
                ):
                    raise ValueError
            if command == "enable" and not all(raw[key] for key in fields):
                raise ValueError
            if command == "repair" and not all(raw[key] for key in fields - {"enabled"}):
                raise ValueError
            if command == "disable" and raw["installed"]:
                raise ValueError
            return raw
        except (CampusError, OSError, ValueError, TypeError, RecursionError) as exc:
            raise CampusError(
                ErrorCode.STARTUP_ERROR,
                "登录启动任务操作失败；请检查任务计划服务、当前用户权限或同名任务冲突。",
            ) from exc
