<#
.SYNOPSIS
    SysWarden native binary compiler (PowerShell 7+ edition).
.DESCRIPTION
    Builds the SysWarden CLI, core, and TUI for every configured build target.
    The build is read-only with respect to Go module manifests and verifies every
    generated binary before reporting success.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot
$DistDir = Join-Path $RepoRoot 'dist'

$Components = @(
    [PSCustomObject]@{
        Name = 'syswarden-cli'
        SourceDir = Join-Path $RepoRoot 'src/core/syswarden-cli'
    },
    [PSCustomObject]@{
        Name = 'syswarden-core'
        SourceDir = Join-Path $RepoRoot 'src/core/syswarden-core'
    },
    [PSCustomObject]@{
        Name = 'syswarden-tui'
        SourceDir = Join-Path $RepoRoot 'src/core/syswarden-tui'
    }
)

$Targets = @(
    [PSCustomObject]@{
        Name = 'Linux AMD64'
        GOOS = 'linux'
        GOARCH = 'amd64'
        BuildMode = 'pie'
        OutputDir = Join-Path $DistDir 'bin'
    }
)

function Get-DisplayPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetRelativePath($RepoRoot, $Path)
}

function Assert-GoArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedOS,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedArch
    )

    $DisplayPath = Get-DisplayPath -Path $Path
    if (!(Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Missing expected artifact: $DisplayPath"
    }

    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "Generated artifact is empty: $DisplayPath"
    }

    $Header = [byte[]]::new(64)
    $Stream = [System.IO.File]::OpenRead($Path)
    try {
        if ($Stream.Read($Header, 0, $Header.Length) -ne $Header.Length) {
            throw "Generated artifact has an incomplete ELF header: $DisplayPath"
        }
    } finally {
        $Stream.Dispose()
    }

    if (($Header[0] -ne 0x7f) -or ($Header[1] -ne 0x45) -or
        ($Header[2] -ne 0x4c) -or ($Header[3] -ne 0x46)) {
        throw "Generated artifact is not an ELF binary: $DisplayPath"
    }

    if (($Header[4] -ne 2) -or ($Header[5] -ne 1)) {
        throw "Generated artifact is not a 64-bit little-endian ELF binary: $DisplayPath"
    }

    $Machine = [int]$Header[18] -bor ([int]$Header[19] -shl 8)
    $ExpectedMachine = switch ($ExpectedArch) {
        'amd64' { 0x3e }
        default { throw "Unsupported artifact architecture check: $ExpectedArch" }
    }

    if ($Machine -ne $ExpectedMachine) {
        throw "Generated artifact has the wrong ELF architecture: $DisplayPath"
    }

    $ElfType = [int]$Header[16] -bor ([int]$Header[17] -shl 8)
    if (($ExpectedOS -eq 'linux') -and ($ElfType -ne 3)) {
        throw "Generated Linux artifact is not an ELF PIE executable: $DisplayPath"
    }

    $BuildInfo = (& go version -m $Path 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read Go build information from artifact: $DisplayPath"
    }

    $ExpectedOSPattern = '(?m)^\s*build\s+GOOS=' + [regex]::Escape($ExpectedOS) + '\s*$'
    $ExpectedArchPattern = '(?m)^\s*build\s+GOARCH=' + [regex]::Escape($ExpectedArch) + '\s*$'
    $CgoPattern = '(?m)^\s*build\s+CGO_ENABLED=0\s*$'
    $TrimPathPattern = '(?m)^\s*build\s+-trimpath=true\s*$'

    if ($BuildInfo -notmatch $ExpectedOSPattern) {
        throw "Generated artifact has the wrong target OS (expected $ExpectedOS): $DisplayPath"
    }

    if ($BuildInfo -notmatch $ExpectedArchPattern) {
        throw "Generated artifact has the wrong target architecture (expected $ExpectedArch): $DisplayPath"
    }

    if ($BuildInfo -notmatch $CgoPattern) {
        throw "Generated artifact was not built with CGO_ENABLED=0: $DisplayPath"
    }

    if ($BuildInfo -notmatch $TrimPathPattern) {
        throw "Generated artifact does not attest path-independent compilation: $DisplayPath"
    }
}

function Invoke-GoBuild {
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Component,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Target
    )

    $OutputPath = Join-Path $Target.OutputDir $Component.Name
    $TemporaryOutputPath = "$OutputPath.tmp"
    $DisplayPath = Get-DisplayPath -Path $OutputPath

    if (Test-Path -LiteralPath $TemporaryOutputPath) {
        Remove-Item -LiteralPath $TemporaryOutputPath -Force
    }

    $BuildArguments = @('build', '-mod=readonly', '-trimpath')
    if ($null -ne $Target.BuildMode) {
        $BuildArguments += "-buildmode=$($Target.BuildMode)"
    }
    $BuildArguments += '-ldflags=-s -w'
    $BuildArguments += '-o'
    $BuildArguments += $TemporaryOutputPath
    $BuildArguments += '.'

    Write-Host "[*] Building $($Component.Name) for $($Target.Name)..." -ForegroundColor Cyan
    Push-Location $Component.SourceDir
    try {
        & go @BuildArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Go build failed for $($Component.Name) on $($Target.Name)."
        }
    } finally {
        Pop-Location
    }

    Assert-GoArtifact `
        -Path $TemporaryOutputPath `
        -ExpectedOS $Target.GOOS `
        -ExpectedArch $Target.GOARCH

    Move-Item -LiteralPath $TemporaryOutputPath -Destination $OutputPath -Force
    Write-Host "[+] Verified $DisplayPath ($($Target.GOOS)/$($Target.GOARCH))." -ForegroundColor Green
}

function Assert-ExactDistInventory {
    $ExpectedFiles = @(
        @(
            'bin/syswarden-cli'
            'bin/syswarden-core'
            'bin/syswarden-tui'
            'signatures.json'
        ) | Sort-Object
    )
    $ExpectedDirectories = @(
        @(
            'bin'
        ) | Sort-Object
    )

    $Entries = @(Get-ChildItem -LiteralPath $DistDir -Recurse -Force)
    foreach ($Entry in $Entries) {
        if (($Entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Build inventory contains a link or reparse point: $(Get-DisplayPath -Path $Entry.FullName)"
        }
    }

    $ActualFiles = @(
        @(
            $Entries | Where-Object { !$_.PSIsContainer } | ForEach-Object {
                [System.IO.Path]::GetRelativePath($DistDir, $_.FullName).Replace('\', '/')
            }
        ) | Sort-Object
    )
    $ActualDirectories = @(
        @(
            $Entries | Where-Object { $_.PSIsContainer } | ForEach-Object {
                [System.IO.Path]::GetRelativePath($DistDir, $_.FullName).Replace('\', '/')
            }
        ) | Sort-Object
    )

    if ($ActualFiles.Count -ne $ExpectedFiles.Count) {
        throw "Build inventory expected $($ExpectedFiles.Count) files but found $($ActualFiles.Count): $($ActualFiles -join ', ')"
    }
    for ($Index = 0; $Index -lt $ExpectedFiles.Count; $Index++) {
        if ($ActualFiles[$Index] -ne $ExpectedFiles[$Index]) {
            throw "Build file inventory mismatch. Expected: $($ExpectedFiles -join ', '); actual: $($ActualFiles -join ', ')"
        }
    }
    if ($ActualDirectories.Count -ne $ExpectedDirectories.Count) {
        throw "Build inventory expected $($ExpectedDirectories.Count) directories but found $($ActualDirectories.Count): $($ActualDirectories -join ', ')"
    }
    for ($Index = 0; $Index -lt $ExpectedDirectories.Count; $Index++) {
        if ($ActualDirectories[$Index] -ne $ExpectedDirectories[$Index]) {
            throw "Build directory inventory mismatch. Expected: $($ExpectedDirectories -join ', '); actual: $($ActualDirectories -join ', ')"
        }
    }
}

Write-Host '[*] Initializing SysWarden native build (PowerShell edition)...' -ForegroundColor Cyan

if (!(Get-Command 'go' -ErrorAction SilentlyContinue)) {
    throw 'Go is required to build SysWarden. Install the repository-required Go version and retry.'
}

foreach ($Component in $Components) {
    $MainFile = Join-Path $Component.SourceDir 'main.go'
    $ModuleFile = Join-Path $Component.SourceDir 'go.mod'

    if (!(Test-Path -LiteralPath $MainFile -PathType Leaf)) {
        throw "Missing required source file: $(Get-DisplayPath -Path $MainFile)"
    }

    if (!(Test-Path -LiteralPath $ModuleFile -PathType Leaf)) {
        throw "Missing required Go module file: $(Get-DisplayPath -Path $ModuleFile)"
    }
}

$SignaturesSource = Join-Path $RepoRoot 'src/core/syswarden-core/signatures.json'
if (!(Test-Path -LiteralPath $SignaturesSource -PathType Leaf)) {
    throw "Missing required signatures file: $(Get-DisplayPath -Path $SignaturesSource)"
}

foreach ($Target in $Targets) {
    New-Item -ItemType Directory -Force -Path $Target.OutputDir | Out-Null
}

$PreviousGoOS = [System.Environment]::GetEnvironmentVariable('GOOS', 'Process')
$PreviousGoArch = [System.Environment]::GetEnvironmentVariable('GOARCH', 'Process')
$PreviousCgoEnabled = [System.Environment]::GetEnvironmentVariable('CGO_ENABLED', 'Process')

try {
    $env:CGO_ENABLED = '0'

    foreach ($Target in $Targets) {
        $env:GOOS = $Target.GOOS
        $env:GOARCH = $Target.GOARCH

        foreach ($Component in $Components) {
            Invoke-GoBuild -Component $Component -Target $Target
        }
    }
} finally {
    [System.Environment]::SetEnvironmentVariable('GOOS', $PreviousGoOS, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOARCH', $PreviousGoArch, 'Process')
    [System.Environment]::SetEnvironmentVariable('CGO_ENABLED', $PreviousCgoEnabled, 'Process')
}

Copy-Item `
    -LiteralPath $SignaturesSource `
    -Destination (Join-Path $DistDir 'signatures.json') `
    -Force

$VerifiedArtifactCount = 0
foreach ($Target in $Targets) {
    foreach ($Component in $Components) {
        $ArtifactPath = Join-Path $Target.OutputDir $Component.Name
        Assert-GoArtifact `
            -Path $ArtifactPath `
            -ExpectedOS $Target.GOOS `
            -ExpectedArch $Target.GOARCH
        $VerifiedArtifactCount++
    }
}

if ($VerifiedArtifactCount -ne 3) {
    throw "Build verification expected 3 binaries but verified $VerifiedArtifactCount."
}

Assert-ExactDistInventory

Write-Host "[+] Build complete. Verified all $VerifiedArtifactCount native binaries and the exact 4-file AMD64 distribution inventory." -ForegroundColor Green
