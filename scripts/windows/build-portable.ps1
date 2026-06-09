param(
  [Parameter(Mandatory = $true)]
  [string]$WebView2RuntimePath
)

$ErrorActionPreference = "Stop"

function Resolve-AbsolutePath([string]$PathValue) {
  return (Resolve-Path -LiteralPath $PathValue).Path
}

function Find-AppExe([string]$RepoRoot) {
  $candidates = @(
    (Join-Path $RepoRoot "src-tauri\target\release\FastPAS.exe"),
    (Join-Path $RepoRoot "src-tauri\target\release\fastpas.exe")
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) {
      return $candidate
    }
  }
  throw "Could not find built FastPAS executable under src-tauri\target\release."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-AbsolutePath (Join-Path $scriptDir "..\..")
$webView2Source = Resolve-AbsolutePath $WebView2RuntimePath
$portableRoot = Join-Path $repoRoot "dist\FastPAS-portable"
$runtimeDest = Join-Path $portableRoot "WebView2Runtime"
$launcherSource = Join-Path $scriptDir "Run-FastPAS.bat"
$launcherDest = Join-Path $portableRoot "Run-FastPAS.bat"
$exeDest = Join-Path $portableRoot "FastPAS.exe"

if (-not (Test-Path -LiteralPath $launcherSource)) {
  throw "Missing launcher file: $launcherSource"
}

if (-not (Test-Path -LiteralPath $webView2Source)) {
  throw "WebView2 runtime path does not exist: $webView2Source"
}

Write-Host "Building FastPAS release binary..."
Push-Location $repoRoot
try {
  npm run tauri:build -- --bundles none
}
finally {
  Pop-Location
}

$builtExe = Find-AppExe $repoRoot

Write-Host "Preparing portable output: $portableRoot"
if (Test-Path -LiteralPath $portableRoot) {
  Remove-Item -LiteralPath $portableRoot -Recurse -Force
}
New-Item -Path $portableRoot -ItemType Directory | Out-Null

Copy-Item -LiteralPath $builtExe -Destination $exeDest -Force
Copy-Item -LiteralPath $launcherSource -Destination $launcherDest -Force
Copy-Item -LiteralPath $webView2Source -Destination $runtimeDest -Recurse -Force

$portableReadme = @"
FastPAS Portable Package
========================

This folder is self-contained for Windows use.

Run:
  Run-FastPAS.bat

Notes:
- Do not remove or rename the WebView2Runtime folder.
- Run-FastPAS.bat sets WEBVIEW2_BROWSER_EXECUTABLE_FOLDER to the local runtime.
"@

Set-Content -LiteralPath (Join-Path $portableRoot "README-portable.txt") -Value $portableReadme -Encoding UTF8

Write-Host ""
Write-Host "Portable package ready:"
Write-Host "  $portableRoot"
Write-Host ""
Write-Host "Zip this folder and give it to your customer."
