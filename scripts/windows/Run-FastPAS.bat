@echo off
setlocal

set "APP_DIR=%~dp0"
set "WEBVIEW2_BROWSER_EXECUTABLE_FOLDER=%APP_DIR%WebView2Runtime"

if not exist "%APP_DIR%FastPAS.exe" (
  echo FastPAS.exe not found in %APP_DIR%
  exit /b 1
)

if not exist "%WEBVIEW2_BROWSER_EXECUTABLE_FOLDER%" (
  echo WebView2Runtime folder not found in %WEBVIEW2_BROWSER_EXECUTABLE_FOLDER%
  exit /b 1
)

"%APP_DIR%FastPAS.exe" %*
