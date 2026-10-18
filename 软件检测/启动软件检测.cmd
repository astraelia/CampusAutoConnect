@echo off
setlocal
if exist "%~dp0dist\CampusInspector-0.1.2-win-x64\CampusInspector.exe" (
  start "" "%~dp0dist\CampusInspector-0.1.2-win-x64\CampusInspector.exe"
  exit /b
)
if exist "%~dp0..\.venv\Scripts\pythonw.exe" (
  start "" "%~dp0..\.venv\Scripts\pythonw.exe" -B -X utf8 "%~dp0inspector.py"
  exit /b
)
echo Please extract the complete CampusInspector package or use the project Python environment.
pause
