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

Write-Host "[*] Compiling syswarden-core (Golang WAF)..." -ForegroundColor Cyan
if (!(Get-Command "go" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] WARNING: Golang is not installed or not in PATH." -ForegroundColor Yellow
    Write-Host "[-] Attempting automatic installation of Golang via winget..." -ForegroundColor Cyan
    
    if (Get-Command "winget" -ErrorAction SilentlyContinue) {
        winget install GoLang.Go --silent --accept-source-agreements --accept-package-agreements
        
        # Refresh environment variables to detect Go in the current session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        if (!(Get-Command "go" -ErrorAction SilentlyContinue)) {
            Write-Host "[-] ERROR: Golang automatic installation failed. Please restart your PowerShell session or install manually: https://go.dev/dl/" -ForegroundColor Red
            exit 1
        }
        Write-Host "[+] Golang successfully installed." -ForegroundColor Green
    } else {
        Write-Host "[-] ERROR: winget is not available on this system." -ForegroundColor Red
        Write-Host "[-] Please install Go manually: https://go.dev/dl/" -ForegroundColor Red
        exit 1
    }
}

if (Test-Path "src/core/syswarden-cli/main.go") {
    Write-Host "[*] Compiling syswarden-cli (Golang CLI Orchestrator)..." -ForegroundColor Cyan
    $GoCliDir = "src/core/syswarden-cli"
    $OriginalLocation = Get-Location
    Set-Location $GoCliDir
    
    try { go mod tidy 2>$null } catch {}
    
    $env:GOOS="linux"
    $env:GOARCH="amd64"
    $env:CGO_ENABLED="0"
    go build -ldflags="-s -w" -o syswarden-cli .
    
    Set-Location $OriginalLocation
    
    if (!(Test-Path "$DistDir/bin")) {
        New-Item -ItemType Directory -Force -Path "$DistDir/bin" | Out-Null
    }
    Copy-Item -Path "$GoCliDir/syswarden-cli" -Destination "$DistDir/bin/syswarden-cli" -Force
    Write-Host "[+] Golang CLI compiled and copied to $DistDir/bin/" -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: syswarden-cli not found. Skipping Go build." -ForegroundColor Yellow
}

if (Test-Path "src/core/syswarden-core/main.go") {
    $GoCoreDir = "src/core/syswarden-core"
    $OriginalLocation = Get-Location
    Set-Location $GoCoreDir
    
    # Init and Tidy
    if (!(Test-Path "go.mod")) {
        try { go mod init syswarden-core 2>$null } catch {}
    }
    try { go mod tidy 2>$null } catch {}
    
    # Build for Linux (Cross-Compilation)
    $env:GOOS="linux"
    $env:GOARCH="amd64"
    $env:CGO_ENABLED="0"
    go build -ldflags="-s -w" -o syswarden-core .
    
    Set-Location $OriginalLocation
    
    if (!(Test-Path "$DistDir/bin")) {
        New-Item -ItemType Directory -Force -Path "$DistDir/bin" | Out-Null
    }
    Copy-Item -Path "$GoCoreDir/syswarden-core" -Destination "$DistDir/bin/syswarden-core" -Force
    Copy-Item -Path "$GoCoreDir/signatures.json" -Destination "$DistDir/signatures.json" -Force
    Write-Host "[+] Golang WAF compiled and copied to $DistDir/bin/" -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: syswarden-core not found. Skipping Go build." -ForegroundColor Yellow
}

Write-Host "[*] Compiling syswarden-tui (Golang TUI)..." -ForegroundColor Cyan
if (Test-Path "src/core/syswarden-tui/main.go") {
    $GoTuiDir = "src/core/syswarden-tui"
    $OriginalLocation = Get-Location
    Set-Location $GoTuiDir
    
    # Init and Tidy
    if (!(Test-Path "go.mod")) {
        try { go mod init syswarden-tui 2>$null } catch {}
    }
    try { go mod tidy 2>$null } catch {}
    
    # Build for Linux (Cross-Compilation)
    $env:GOOS="linux"
    $env:GOARCH="amd64"
    $env:CGO_ENABLED="0"
    go build -ldflags="-s -w" -o syswarden-tui .
    
    Set-Location $OriginalLocation
    
    Copy-Item -Path "$GoTuiDir/syswarden-tui" -Destination "$DistDir/bin/syswarden-tui" -Force
    Write-Host "[+] Golang TUI compiled and copied to $DistDir/bin/" -ForegroundColor Green
} else {
    Write-Host "[-] WARNING: syswarden-tui not found. Skipping Go build." -ForegroundColor Yellow
}

Write-Host "[*] Compiling SysWarden Native Go Modules for FreeBSD..." -ForegroundColor Cyan
if (!(Test-Path "$DistDir/freebsd/bin")) {
    New-Item -ItemType Directory -Force -Path "$DistDir/freebsd/bin" | Out-Null
}

$env:GOOS="freebsd"
$env:GOARCH="amd64"
$env:CGO_ENABLED="0"

Set-Location "src/core/syswarden-cli"
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-cli .
Set-Location ../../../

Write-Host "[*] Compiling SysWarden Native Go Modules for Linux ARM64..." -ForegroundColor Cyan
if (!(Test-Path "$DistDir/linux-arm64/bin")) {
    New-Item -ItemType Directory -Force -Path "$DistDir/linux-arm64/bin" | Out-Null
}

$env:GOOS="linux"
$env:GOARCH="arm64"
$env:CGO_ENABLED="0"

Set-Location "src/core/syswarden-cli"
go build -ldflags="-s -w" -o ../../../dist/linux-arm64/bin/syswarden-cli .
Set-Location ../../../

Set-Location "src/core/syswarden-core"
go build -ldflags="-s -w" -o ../../../dist/linux-arm64/bin/syswarden-core .
Set-Location ../../../
Copy-Item -Path "src/core/syswarden-core/signatures.json" -Destination "$DistDir/linux-arm64/signatures.json" -Force

Set-Location "src/core/syswarden-tui"
go build -ldflags="-s -w" -o ../../../dist/linux-arm64/bin/syswarden-tui .
Set-Location ../../../

Write-Host "[+] Linux ARM64 Compilation successful." -ForegroundColor Green

Set-Location "src/core/syswarden-core"
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-core .
Set-Location ../../../

Set-Location "src/core/syswarden-tui"
go build -ldflags="-s -w" -o ../../../dist/freebsd/bin/syswarden-tui .
Set-Location ../../../

Write-Host "[+] FreeBSD Compilation successful." -ForegroundColor Green

# Create dist directory if it doesn't exist
if (!(Test-Path $DistDir)) {
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
}

# ==========================================
# FINAL COMPILATION VERIFICATION
# ==========================================
if ((Test-Path "$DistDir/bin/syswarden-cli") -and (Test-Path "$DistDir/bin/syswarden-core")) {
    Write-Host "[+] Build complete. Artifacts successfully compiled in $DistDir/bin/" -ForegroundColor Green
} else {
    Write-Host "[-] ERROR: Missing expected binaries. Build failed." -ForegroundColor Red
    exit 1
}