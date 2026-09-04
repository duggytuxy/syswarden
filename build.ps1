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

$GitEnvironmentVariables = @(
    'GIT_DIR'
    'GIT_WORK_TREE'
    'GIT_COMMON_DIR'
    'GIT_INDEX_FILE'
    'GIT_OBJECT_DIRECTORY'
    'GIT_ALTERNATE_OBJECT_DIRECTORIES'
    'GIT_ATTR_SOURCE'
    'GIT_CEILING_DIRECTORIES'
    'GIT_DISCOVERY_ACROSS_FILESYSTEM'
    'GIT_NAMESPACE'
    'GIT_REPLACE_REF_BASE'
    'GIT_SHALLOW_FILE'
    'GIT_GRAFT_FILE'
    'GIT_QUARANTINE_PATH'
    'GIT_CONFIG_COUNT'
    'GIT_CONFIG_PARAMETERS'
    'GIT_CONFIG_GLOBAL'
    'GIT_CONFIG_SYSTEM'
    'GIT_EXEC_PATH'
)
foreach ($GitEnvironmentVariable in $GitEnvironmentVariables) {
    if ($null -ne [System.Environment]::GetEnvironmentVariable(
        $GitEnvironmentVariable,
        'Process'
    )) {
        throw "Refusing inherited Git repository influence: $GitEnvironmentVariable"
    }
}
$env:GIT_NO_REPLACE_OBJECTS = '1'

$RepositoryTopLevel = (& git -c core.fsmonitor=false -C $RepoRoot rev-parse --show-toplevel 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to derive the Git repository root.'
}
$ResolvedRepoRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
    (Resolve-Path -LiteralPath $RepoRoot).Path
)
$ResolvedRepositoryTopLevel = [System.IO.Path]::TrimEndingDirectorySeparator(
    (Resolve-Path -LiteralPath $RepositoryTopLevel).Path
)
if ($ResolvedRepositoryTopLevel -cne $ResolvedRepoRoot) {
    throw 'Git repository root does not match the builder location.'
}

$SourceRevision = (& git -c core.fsmonitor=false -C $RepoRoot rev-parse --verify 'HEAD^{commit}' 2>&1 | Out-String).Trim()
if (($LASTEXITCODE -ne 0) -or ($SourceRevision -notmatch '^[0-9a-f]{40}$')) {
    throw 'Unable to derive the exact source commit.'
}

$SourceDateEpochText = (& git -c core.fsmonitor=false -C $RepoRoot log -1 --format=%ct HEAD 2>&1 | Out-String).Trim()
$SourceDateEpoch = 0L
if (($LASTEXITCODE -ne 0) -or
    (![long]::TryParse($SourceDateEpochText, [ref]$SourceDateEpoch)) -or
    ($SourceDateEpoch -le 0)) {
    throw 'Unable to derive the exact source commit time.'
}
$SourceVcsTime = [System.DateTimeOffset]::FromUnixTimeSeconds(
    $SourceDateEpoch
).UtcDateTime.ToString(
    "yyyy-MM-dd'T'HH:mm:ss'Z'",
    [System.Globalization.CultureInfo]::InvariantCulture
)

$SourceGitDir = (& git -c core.fsmonitor=false -C $RepoRoot rev-parse --absolute-git-dir 2>&1 | Out-String).Trim()
if (($LASTEXITCODE -ne 0) -or ![System.IO.Path]::IsPathFullyQualified($SourceGitDir)) {
    throw 'Git returned an invalid repository directory.'
}
$SourceGitDirItem = Get-Item -LiteralPath $SourceGitDir -Force
if (!$SourceGitDirItem.PSIsContainer -or
    (($SourceGitDirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Refusing an unsafe Git repository directory.'
}
$SourceGitCommonDir = (& git -c core.fsmonitor=false -C $RepoRoot `
    rev-parse --path-format=absolute --git-common-dir 2>&1 | Out-String).Trim()
if (($LASTEXITCODE -ne 0) -or ![System.IO.Path]::IsPathFullyQualified($SourceGitCommonDir)) {
    throw 'Git returned an invalid common repository directory.'
}
$SourceGitCommonDirItem = Get-Item -LiteralPath $SourceGitCommonDir -Force
if (!$SourceGitCommonDirItem.PSIsContainer -or
    (($SourceGitCommonDirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'Refusing an unsafe common Git repository directory.'
}

$SourceStatus = (& git -c core.fsmonitor=false -C $RepoRoot status --porcelain=v1 --untracked-files=normal 2>&1 | Out-String).Trim()
if (($LASTEXITCODE -ne 0) -or ($SourceStatus.Length -ne 0)) {
    throw 'Release builds require a clean exact commit.'
}

$SourceWorkspace = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("syswarden-powershell-source-" + [System.Guid]::NewGuid().ToString('N'))
$SourceRoot = Join-Path $SourceWorkspace 'source'
$SourceArchive = Join-Path $SourceWorkspace 'source.tar'
$GoCache = Join-Path $SourceWorkspace 'go-cache'
$GoPath = Join-Path $SourceWorkspace 'go-path'
$GoModuleCache = Join-Path $GoPath 'pkg/mod'
$GoTemporaryDirectory = Join-Path $SourceWorkspace 'go-tmp'
New-Item -ItemType Directory -Path `
    $SourceRoot, $GoCache, $GoPath, $GoModuleCache, $GoTemporaryDirectory | Out-Null
if (-not [System.OperatingSystem]::IsWindows()) {
    & chmod 0700 -- `
        $SourceWorkspace $SourceRoot $GoCache $GoPath $GoModuleCache $GoTemporaryDirectory
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to secure the private source workspace.'
    }
}

try {
& git -c core.fsmonitor=false -C $RepoRoot archive `
    --format=tar "--output=$SourceArchive" $SourceRevision
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to materialize the exact source commit.'
}
& tar --extract "--file=$SourceArchive" "--directory=$SourceRoot" `
    --no-same-owner --no-same-permissions
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to extract the exact source commit.'
}
Remove-Item -LiteralPath $SourceArchive -Force
if (Test-Path -LiteralPath (Join-Path $SourceRoot '.git')) {
    throw 'Refusing a materialized source tree containing Git control data.'
}
$MaterializedStatus = (& git -c core.fsmonitor=false `
    "--git-dir=$SourceGitDir" "--work-tree=$SourceRoot" `
    status --porcelain=v1 --untracked-files=all 2>&1 | Out-String).Trim()
if (($LASTEXITCODE -ne 0) -or ($MaterializedStatus.Length -ne 0)) {
    throw 'Materialized source does not match the exact source commit.'
}
$VcsSentinel = Join-Path $SourceRoot '.git'
New-Item -ItemType Directory -Path $VcsSentinel | Out-Null
if (-not [System.OperatingSystem]::IsWindows()) {
    & chmod 0500 -- $VcsSentinel
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to secure the controlled VCS discovery sentinel.'
    }
}
$VcsSentinelItem = Get-Item -LiteralPath $VcsSentinel -Force
if (!$VcsSentinelItem.PSIsContainer -or
    (($VcsSentinelItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
    (@(Get-ChildItem -LiteralPath $VcsSentinel -Force).Count -ne 0)) {
    throw 'Refusing an unsafe VCS discovery sentinel.'
}

$Components = @(
    [PSCustomObject]@{
        Name = 'syswarden-cli'
        SourceDir = Join-Path $SourceRoot 'src/core/syswarden-cli'
        Package = './src/core/syswarden-cli'
    },
    [PSCustomObject]@{
        Name = 'syswarden-core'
        SourceDir = Join-Path $SourceRoot 'src/core/syswarden-core'
        Package = './src/core/syswarden-core'
    },
    [PSCustomObject]@{
        Name = 'syswarden-tui'
        SourceDir = Join-Path $SourceRoot 'src/core/syswarden-tui'
        Package = './src/core/syswarden-tui'
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
    $ExpectedAmd64LevelPattern = '(?m)^\s*build\s+GOAMD64=v1\s*$'
    $CgoPattern = '(?m)^\s*build\s+CGO_ENABLED=0\s*$'
    $TrimPathPattern = '(?m)^\s*build\s+-trimpath=true\s*$'
    $VcsGitPattern = '(?m)^\s*build\s+vcs=git\s*$'
    $VcsRevisionPattern = '(?m)^\s*build\s+vcs\.revision=' + [regex]::Escape($SourceRevision) + '\s*$'
    $VcsTimePattern = '(?m)^\s*build\s+vcs\.time=' + [regex]::Escape($SourceVcsTime) + '\s*$'
    $VcsCleanPattern = '(?m)^\s*build\s+vcs\.modified=false\s*$'
    $VcsFieldPattern = '(?m)^\s*build\s+vcs(?:\.|=)'

    if ($BuildInfo -notmatch $ExpectedOSPattern) {
        throw "Generated artifact has the wrong target OS (expected $ExpectedOS): $DisplayPath"
    }

    if ($BuildInfo -notmatch $ExpectedArchPattern) {
        throw "Generated artifact has the wrong target architecture (expected $ExpectedArch): $DisplayPath"
    }

    if (($ExpectedArch -eq 'amd64') -and ($BuildInfo -notmatch $ExpectedAmd64LevelPattern)) {
        throw "Generated artifact does not attest the baseline AMD64 feature level: $DisplayPath"
    }

    if ($BuildInfo -notmatch $CgoPattern) {
        throw "Generated artifact was not built with CGO_ENABLED=0: $DisplayPath"
    }

    if ($BuildInfo -notmatch $TrimPathPattern) {
        throw "Generated artifact does not attest path-independent compilation: $DisplayPath"
    }

    foreach ($VcsPattern in @(
        $VcsGitPattern
        $VcsRevisionPattern
        $VcsTimePattern
        $VcsCleanPattern
    )) {
        if ([regex]::Matches($BuildInfo, $VcsPattern).Count -ne 1) {
            throw "Generated artifact does not attest the clean exact source commit: $DisplayPath"
        }
    }
    if ([regex]::Matches($BuildInfo, $VcsFieldPattern).Count -ne 4) {
        throw "Generated artifact contains an unexpected VCS provenance field: $DisplayPath"
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

    $BuildArguments = @('build', '-buildvcs=true', '-mod=readonly', '-trimpath')
    if ($null -ne $Target.BuildMode) {
        $BuildArguments += "-buildmode=$($Target.BuildMode)"
    }
    $BuildArguments += '-ldflags=-s -w'
    $BuildArguments += '-o'
    $BuildArguments += $TemporaryOutputPath
    $BuildArguments += $Component.Package

    Write-Host "[*] Building $($Component.Name) for $($Target.Name)..." -ForegroundColor Cyan
    Push-Location $SourceRoot
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

$SignaturesSource = Join-Path $SourceRoot 'src/core/syswarden-core/signatures.json'
if (!(Test-Path -LiteralPath $SignaturesSource -PathType Leaf)) {
    throw "Missing required signatures file: $(Get-DisplayPath -Path $SignaturesSource)"
}
$WorkspaceFile = Join-Path $SourceRoot 'go.work'
if (!(Test-Path -LiteralPath $WorkspaceFile -PathType Leaf)) {
    throw "Missing required Go workspace file: $(Get-DisplayPath -Path $WorkspaceFile)"
}

foreach ($Target in $Targets) {
    New-Item -ItemType Directory -Force -Path $Target.OutputDir | Out-Null
}

$PreviousGoOS = [System.Environment]::GetEnvironmentVariable('GOOS', 'Process')
$PreviousGoArch = [System.Environment]::GetEnvironmentVariable('GOARCH', 'Process')
$PreviousCgoEnabled = [System.Environment]::GetEnvironmentVariable('CGO_ENABLED', 'Process')
$PreviousGoFlags = [System.Environment]::GetEnvironmentVariable('GOFLAGS', 'Process')
$PreviousGoWork = [System.Environment]::GetEnvironmentVariable('GOWORK', 'Process')
$PreviousGoEnv = [System.Environment]::GetEnvironmentVariable('GOENV', 'Process')
$PreviousGoAmd64 = [System.Environment]::GetEnvironmentVariable('GOAMD64', 'Process')
$PreviousGoExperiment = [System.Environment]::GetEnvironmentVariable('GOEXPERIMENT', 'Process')
$PreviousGoToolchain = [System.Environment]::GetEnvironmentVariable('GOTOOLCHAIN', 'Process')
$PreviousGoCache = [System.Environment]::GetEnvironmentVariable('GOCACHE', 'Process')
$PreviousGoCacheProgram = [System.Environment]::GetEnvironmentVariable('GOCACHEPROG', 'Process')
$PreviousGoModuleCache = [System.Environment]::GetEnvironmentVariable('GOMODCACHE', 'Process')
$PreviousGoPath = [System.Environment]::GetEnvironmentVariable('GOPATH', 'Process')
$PreviousGoTemporaryDirectory = [System.Environment]::GetEnvironmentVariable('GOTMPDIR', 'Process')
$PreviousGitDir = [System.Environment]::GetEnvironmentVariable('GIT_DIR', 'Process')
$PreviousGitCommonDir = [System.Environment]::GetEnvironmentVariable('GIT_COMMON_DIR', 'Process')
$PreviousGitWorkTree = [System.Environment]::GetEnvironmentVariable('GIT_WORK_TREE', 'Process')
$PreviousGitConfigCount = [System.Environment]::GetEnvironmentVariable('GIT_CONFIG_COUNT', 'Process')
$PreviousGitConfigKey = [System.Environment]::GetEnvironmentVariable('GIT_CONFIG_KEY_0', 'Process')
$PreviousGitConfigValue = [System.Environment]::GetEnvironmentVariable('GIT_CONFIG_VALUE_0', 'Process')

try {
    $env:CGO_ENABLED = '0'
    $env:GOFLAGS = '-mod=readonly'
    $env:GOWORK = 'off'
    $env:GOENV = 'off'
    $env:GOAMD64 = 'v1'
    $env:GOEXPERIMENT = ''
    $env:GOTOOLCHAIN = 'local'
    $env:GOCACHE = $GoCache
    $env:GOCACHEPROG = ''
    $env:GOMODCACHE = $GoModuleCache
    $env:GOPATH = $GoPath
    $env:GOTMPDIR = $GoTemporaryDirectory

    $GoVersion = (& go env GOVERSION 2>&1 | Out-String).Trim()
    if (($LASTEXITCODE -ne 0) -or ($GoVersion -ne 'go1.26.6')) {
        throw 'Native release builds require exactly Go 1.26.6.'
    }

    foreach ($Component in $Components) {
        Push-Location $Component.SourceDir
        try {
            & go mod download
            if ($LASTEXITCODE -ne 0) {
                throw "Locked module download failed for $($Component.Name)."
            }
            & go mod verify
            if ($LASTEXITCODE -ne 0) {
                throw "Module cache verification failed for $($Component.Name)."
            }
        } finally {
            Pop-Location
        }
    }

    $env:GIT_COMMON_DIR = $SourceGitCommonDir
    $env:GIT_DIR = $SourceGitDir
    $env:GIT_WORK_TREE = $SourceRoot
    $env:GIT_CONFIG_COUNT = '1'
    $env:GIT_CONFIG_KEY_0 = 'core.fsmonitor'
    $env:GIT_CONFIG_VALUE_0 = 'false'
    $env:GOWORK = $WorkspaceFile

    foreach ($Target in $Targets) {
        $env:GOOS = $Target.GOOS
        $env:GOARCH = $Target.GOARCH

        foreach ($Component in $Components) {
            Invoke-GoBuild -Component $Component -Target $Target
        }
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
} finally {
    [System.Environment]::SetEnvironmentVariable('GOOS', $PreviousGoOS, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOARCH', $PreviousGoArch, 'Process')
    [System.Environment]::SetEnvironmentVariable('CGO_ENABLED', $PreviousCgoEnabled, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOFLAGS', $PreviousGoFlags, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOWORK', $PreviousGoWork, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOENV', $PreviousGoEnv, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOAMD64', $PreviousGoAmd64, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOEXPERIMENT', $PreviousGoExperiment, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOTOOLCHAIN', $PreviousGoToolchain, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOCACHE', $PreviousGoCache, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOCACHEPROG', $PreviousGoCacheProgram, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOMODCACHE', $PreviousGoModuleCache, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOPATH', $PreviousGoPath, 'Process')
    [System.Environment]::SetEnvironmentVariable('GOTMPDIR', $PreviousGoTemporaryDirectory, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_DIR', $PreviousGitDir, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_COMMON_DIR', $PreviousGitCommonDir, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_WORK_TREE', $PreviousGitWorkTree, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_CONFIG_COUNT', $PreviousGitConfigCount, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_CONFIG_KEY_0', $PreviousGitConfigKey, 'Process')
    [System.Environment]::SetEnvironmentVariable('GIT_CONFIG_VALUE_0', $PreviousGitConfigValue, 'Process')
}
} finally {
    if (Test-Path -LiteralPath $SourceWorkspace) {
        $ResolvedTemporaryRoot = [System.IO.Path]::TrimEndingDirectorySeparator(
            [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        )
        $ResolvedSourceWorkspace = [System.IO.Path]::GetFullPath($SourceWorkspace)
        $ExpectedPrefix = $ResolvedTemporaryRoot + [System.IO.Path]::DirectorySeparatorChar +
            'syswarden-powershell-source-'
        if (!$ResolvedSourceWorkspace.StartsWith(
            $ExpectedPrefix,
            [System.StringComparison]::Ordinal
        )) {
            throw "Refusing to remove an unexpected source workspace: $ResolvedSourceWorkspace"
        }
        if (-not [System.OperatingSystem]::IsWindows()) {
            $ResolvedGoModuleCache = [System.IO.Path]::GetFullPath($GoModuleCache)
            $ExpectedCachePrefix = $ResolvedSourceWorkspace +
                [System.IO.Path]::DirectorySeparatorChar
            if (!$ResolvedGoModuleCache.StartsWith(
                $ExpectedCachePrefix,
                [System.StringComparison]::Ordinal
            )) {
                throw "Refusing to change permissions on an unexpected Go module cache: $ResolvedGoModuleCache"
            }
            $GoModuleCacheItem = Get-Item -LiteralPath $ResolvedGoModuleCache -Force
            if (!$GoModuleCacheItem.PSIsContainer -or
                (($GoModuleCacheItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                throw "Refusing unsafe Go module cache cleanup: $ResolvedGoModuleCache"
            }
            & chmod -R u+w -- $ResolvedGoModuleCache
            if ($LASTEXITCODE -ne 0) {
                throw "Unable to make the private Go module cache removable: $ResolvedGoModuleCache"
            }
        }
        Remove-Item -LiteralPath $ResolvedSourceWorkspace -Recurse -Force
    }
}
