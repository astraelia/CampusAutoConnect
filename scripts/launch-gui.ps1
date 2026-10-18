$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$taskPython = Join-Path $taskRoot '.venv\Scripts\pythonw.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    throw 'Run uv sync in the project directory first.'
}
Start-Process -FilePath $taskPython -ArgumentList '-m', 'campus_autoconnect' -WorkingDirectory $taskRoot -WindowStyle Hidden
