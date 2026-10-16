#!/usr/bin/env pwsh

param(
    [switch]$Global,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
Push-Location $ProjectRoot

try {
    # Uninstall the target scope only — the other can coexist
    $scope = if ($Global) { "global" } else { "local" }
    $installed = (dotnet tool list "--$scope" 2>$null | Select-String -SimpleMatch -Quiet "keyvault-certsync")

    if ($installed) {
        Write-Host "Removing existing $scope tool..." -ForegroundColor Yellow
        $out = dotnet tool uninstall "--$scope" keyvault-certsync 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host ($out | Out-String).Trim() -ForegroundColor Red
            throw "Could not remove the $scope tool."
        }
    }

    if ($Uninstall) {
        Write-Host ""
        if (-not $installed) {
            Write-Host "No $scope keyvault-certsync tool is installed; nothing removed." -ForegroundColor Yellow
        } else {
            Write-Host "Removed the $scope tool." -ForegroundColor Cyan
        }
        return
    }

    # Clean old packages
    Remove-Item -Recurse -Force nupkg -ErrorAction SilentlyContinue

    # The version rarely changes, so install would reuse the cached package over the one just packed.
    # Evict only this package rather than clearing the shared NuGet cache.
    Write-Host "Evicting cached keyvault-certsync package..." -ForegroundColor Yellow
    $packagesRoot = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $HOME ".nuget/packages" }
    Remove-Item -Recurse -Force (Join-Path $packagesRoot "keyvault-certsync") -ErrorAction SilentlyContinue

    # Build and pack
    Write-Host "Building and packing tool..." -ForegroundColor Green
    dotnet pack -c Release
    if ($LASTEXITCODE -ne 0) { throw "Pack failed" }

    # Install
    Write-Host "Installing tool..." -ForegroundColor Green
    if ($Global) {
        dotnet tool install --global --add-source nupkg keyvault-certsync
        if ($LASTEXITCODE -ne 0) { throw "Tool install failed" }
        Write-Host ""
        Write-Host "Done! Run 'keyvault-certsync' from any directory." -ForegroundColor Cyan
        Write-Host "If it is not found, add the .NET tools directory to PATH: $(Join-Path $HOME '.dotnet' 'tools')" -ForegroundColor DarkGray
    } else {
        # A local install needs a manifest; newer SDKs may write it to the repo root rather than
        # .config/, so look in both.
        $hasManifest = (Test-Path (Join-Path $ProjectRoot ".config" "dotnet-tools.json")) -or
                       (Test-Path (Join-Path $ProjectRoot "dotnet-tools.json"))
        if (-not $hasManifest) {
            dotnet new tool-manifest | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not create tool manifest" }
        }
        dotnet tool install --local --add-source nupkg keyvault-certsync
        if ($LASTEXITCODE -ne 0) { throw "Tool install failed" }
        Write-Host ""
        Write-Host "Done! Run 'dotnet keyvault-certsync' from the repo root." -ForegroundColor Cyan
    }
}
finally {
    Pop-Location
}

<#
.SYNOPSIS
    Install or reinstall keyvault-certsync as a .NET tool.

.DESCRIPTION
    Builds and packs the tool, then installs it locally (or globally with -Global). -Uninstall removes it instead.
    Local and global installations may coexist. Works the same on Windows, macOS and Linux.

.PARAMETER Global
    Install globally so `keyvault-certsync` is available from any directory. Without this switch,
    installs locally and is invoked as `dotnet keyvault-certsync` from this repository.

.PARAMETER Uninstall
    Remove the installed tool at the selected scope (local, or global with -Global) and stop,
    without building or reinstalling.

.EXAMPLE
    pwsh install-tool.ps1 -Global

.EXAMPLE
    pwsh install-tool.ps1

.EXAMPLE
    pwsh install-tool.ps1 -Uninstall
    pwsh install-tool.ps1 -Uninstall -Global
#>
