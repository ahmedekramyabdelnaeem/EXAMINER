@echo off
set "SCRIPT_DIR=%~dp0"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py "%SCRIPT_DIR%main.py" %*
) else (
  python "%SCRIPT_DIR%main.py" %*
)
