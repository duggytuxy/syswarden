<#
.SYNOPSIS
    SysWarden Micro-Modular Compiler (Windows/PowerShell 7+ Edition)
.DESCRIPTION
    Compiles individual bash function scripts into a single universal deployment artifact.
    Guarantees strict Unix (LF) line endings and UTF-8 encoding.
#>

$ErrorActionPreference = 'Stop'

$DistDir = "dist"
$OutputFile = "$DistDir/install-syswarden.sh"

Write-Host "[*] Initializing SysWarden Universal Build (PowerShell Edition)..." -ForegroundColor Cyan

# Create dist directory if it doesn't exist
if (!(Test-Path $DistDir)) {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}

# Initialize an array to hold all script chunks
$ScriptParts = @()

# ==========================================
# 1. BASE SECURITY HEADERS
# ==========================================
$Header = @"
#!/bin/bash
# SysWarden - Enterprise Compiled Build
# Copyright (C) 2026 duggytuxy - Laurent M.
#
# --- STRICT RUNTIME ENVIRONMENT ---
set -euo pipefail
IFS=$'\n\t'
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

"@
$ScriptParts += $Header

# ==========================================
# 2. INJECT CORE CONFIGURATION
# ==========================================
Write-Host "[*] Injecting core configurations..." -ForegroundColor Cyan
if (Test-Path "src/core") {
    $CoreFiles = Get-ChildItem -Path "src/core" -Filter "*.sh" -File | Sort-Object Name
    foreach ($File in $CoreFiles) {
        $Content = Get-Content -Path $File.FullName -Raw
        $ScriptParts += $Content
        $ScriptParts += "`n"
    }
}

# ==========================================
# 3. INJECT UNIVERSAL FUNCTIONS
# ==========================================
Write-Host "[*] Injecting universal modules..." -ForegroundColor Cyan
if (Test-Path "src/universel") {
    $UniversalFiles = Get-ChildItem -Path "src/universel" -Filter "*.sh" -File | Sort-Object Name
    foreach ($File in $UniversalFiles) {
        $ScriptParts += "# --- SOURCE: $($File.Name) ---`n"
        $Content = Get-Content -Path $File.FullName -Raw
        $ScriptParts += $Content
        $ScriptParts += "`n"
    }
}

# ==========================================
# 4. INJECT MAIN ORCHESTRATOR
# ==========================================
Write-Host "[*] Injecting main orchestrator..." -ForegroundColor Cyan
$MainScript = "src/main.sh"
if (Test-Path $MainScript) {
    $ScriptParts += "# --- SOURCE: main.sh ---`n"
    $Content = Get-Content -Path $MainScript -Raw
    $ScriptParts += $Content
} else {
    Write-Host "[-] CRITICAL: src/main.sh not found. Build aborted." -ForegroundColor Red
    exit 1
}

# ==========================================
# 5. ENFORCE LINUX COMPATIBILITY & SAVE
# ==========================================
Write-Host "[*] Enforcing strict Unix (LF) line endings..." -ForegroundColor Cyan
$FinalScript = $ScriptParts -join ""

# Strip any Windows CRLF endings and replace with strict Linux LF
$FinalScript = $FinalScript -replace "`r`n", "`n"

# Write using .NET classes to guarantee UTF-8 without BOM (Byte Order Mark)
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText("$PWD/$OutputFile", $FinalScript, $Utf8NoBom)

Write-Host "[+] Build complete. Artifact generated at: $OutputFile" -ForegroundColor Green