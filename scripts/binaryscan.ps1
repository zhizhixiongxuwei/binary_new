param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'doctor', 'init', 'import', 'build', 'up', 'init-admin', 'deploy', 'verify', 'status', 'logs', 'down')]
    [string]$Command = 'help',
    [Parameter(Position = 1)]
    [string]$Argument = ''
)

$ErrorActionPreference = 'Stop'
$projectRootInfo = Resolve-Path (Join-Path $PSScriptRoot '..')
$ProjectRoot = $projectRootInfo.ProviderPath
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) { $ProjectRoot = $projectRootInfo.Path }
$ComposeFile = Join-Path $ProjectRoot 'compose.yaml'
$EnvFile = Join-Path $ProjectRoot '.env'
$DefaultInitialAdminPassword = 'admin123456789'
if ($PSVersionTable.PSEdition -ne 'Desktop' -and $IsWindows -ne $true) {
    throw 'binaryscan.ps1 supports Windows only; use scripts/binaryscan.sh on Linux or macOS'
}

function Fail([string]$Message) {
    throw $Message
}

function Invoke-Docker([string[]]$DockerArguments) {
    & docker @DockerArguments
    if ($LASTEXITCODE -ne 0) {
        Fail "docker command failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Compose([string[]]$ComposeArguments) {
    $arguments = @(
        'compose', '--project-directory', $ProjectRoot,
        '--env-file', $EnvFile, '--file', $ComposeFile
    ) + $ComposeArguments
    Invoke-Docker $arguments
}

function Import-EnvDefaults([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $value = $line.Trim()
        if ($value.Length -eq 0 -or $value.StartsWith('#')) {
            continue
        }
        $parts = $value.Split('=', 2)
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Z0-9_]+$') {
            Fail "invalid environment line in $Path`: $line"
        }
		$name = $parts[0]
		if ($null -ne [Environment]::GetEnvironmentVariable($name, 'Process')) {
			continue
		}
		$parsed = $parts[1]
		if ($parsed.Length -ge 2 -and (
			($parsed.StartsWith('"') -and $parsed.EndsWith('"')) -or
			($parsed.StartsWith("'") -and $parsed.EndsWith("'"))
		)) {
			$parsed = $parsed.Substring(1, $parsed.Length - 2)
		}
		elseif ($parsed.StartsWith('"') -or $parsed.StartsWith("'")) {
			Fail "unterminated quoted value in $Path`: $name"
		}
		[Environment]::SetEnvironmentVariable($name, $parsed, 'Process')
    }
}

function Import-ComposeEnvironment {
    $arguments = @(
        'compose', '--project-directory', $ProjectRoot,
        '--env-file', $EnvFile, '--file', $ComposeFile,
        'config', '--environment'
    )
    $lines = @(& docker @arguments)
    if ($LASTEXITCODE -ne 0) {
        Fail 'could not parse .env with Docker Compose'
    }
    foreach ($line in $lines) {
        $parts = ([string]$line).Split('=', 2)
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^BINARYSCAN_[A-Z0-9_]+$') {
            continue
        }
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}

function Load-Settings {
	# Compose owns dotenv parsing and process-environment precedence.
	Import-ComposeEnvironment
	Import-EnvDefaults (Join-Path $ProjectRoot 'images.lock.env')
}

function Assert-DirectoryUsable([string]$Path) {
    $probe = Join-Path $Path ".binaryscan-write-test-$PID-$([Guid]::NewGuid().ToString('N'))"
    try {
        Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 1 | Out-Null
        $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Dispose()
    }
    catch {
        Fail "data directory must be readable and writable: $Path"
    }
    finally {
        if (Test-Path -LiteralPath $probe) {
            Remove-Item -LiteralPath $probe -Force
        }
    }
}

function Test-RunningOnWindows {
    return $PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows -eq $true
}

function Assert-WindowsPathWithoutReparsePoint([string]$Path) {
    $runningOnWindows = Test-RunningOnWindows
    if (-not $runningOnWindows) { return }

    $candidate = [IO.Path]::GetFullPath($Path)
    while (-not (Test-Path -LiteralPath $candidate)) {
        $parent = [IO.Directory]::GetParent($candidate)
        if ($null -eq $parent) { break }
        $candidate = $parent.FullName
    }
    if (-not (Test-Path -LiteralPath $candidate)) { return }

    $item = Get-Item -LiteralPath $candidate
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "BINARYSCAN_DATA_ROOT must not contain a junction or symbolic link: $($item.FullName)"
        }
        $item = $item.Parent
    }
}

function Initialize-DataDirectories {
    Load-Settings
    $configuredRoot = $env:BINARYSCAN_DATA_ROOT
    if ([string]::IsNullOrWhiteSpace($configuredRoot)) { $configuredRoot = './runtime/data' }
    if ($configuredRoot -match '(?:^|[\\/])\.\.(?:[\\/]|$)') {
        Fail 'BINARYSCAN_DATA_ROOT must not contain a parent-directory component'
    }
    if (Test-RunningOnWindows) {
        if ($configuredRoot -match '^[A-Za-z]:(?:$|[^\\/])' -or
            $configuredRoot -match '^[\\/](?![\\/])') {
            Fail 'BINARYSCAN_DATA_ROOT must be relative to the project or a fully qualified drive/UNC path'
        }
        $fullyQualified = (
            $configuredRoot -match '^[A-Za-z]:[\\/]' -or
            $configuredRoot -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+'
        )
        if (-not $fullyQualified) {
            $configuredRoot = Join-Path $ProjectRoot $configuredRoot
        }
    }
    elseif (-not [IO.Path]::IsPathRooted($configuredRoot)) {
        $configuredRoot = Join-Path $ProjectRoot $configuredRoot
    }
    Assert-WindowsPathWithoutReparsePoint $configuredRoot
    New-Item -ItemType Directory -Force -Path $configuredRoot | Out-Null
    Assert-WindowsPathWithoutReparsePoint $configuredRoot
    $resolvedRoot = Resolve-Path -LiteralPath $configuredRoot
    $dataRoot = $resolvedRoot.ProviderPath
    if ([string]::IsNullOrWhiteSpace($dataRoot)) { $dataRoot = $resolvedRoot.Path }
    $filesystemRoot = [IO.Path]::GetPathRoot($dataRoot).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    if ($dataRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) -eq $filesystemRoot) {
        Fail 'BINARYSCAN_DATA_ROOT must not be the filesystem root'
    }

    $mysqlDirectory = Join-Path $dataRoot 'mysql'
    $archiveSandboxDirectory = Join-Path $dataRoot 'archive-sandbox'
	$archiveSandboxDirectories = @(
		$archiveSandboxDirectory,
		(Join-Path $archiveSandboxDirectory 'input'),
		(Join-Path $archiveSandboxDirectory 'output'),
		(Join-Path $archiveSandboxDirectory 'run')
	)
    $applicationDirectory = Join-Path $dataRoot 'application'
	$applicationDirectories = @(
		$applicationDirectory,
		(Join-Path $applicationDirectory 'uploads'),
		(Join-Path $applicationDirectory 'repository'),
		(Join-Path $applicationDirectory 'repository/.staging'),
		(Join-Path $applicationDirectory 'repository/.staging/uploads'),
		(Join-Path $applicationDirectory 'task-work')
	)
	foreach ($directory in @($mysqlDirectory) + $archiveSandboxDirectories + $applicationDirectories) {
        if (Test-Path -LiteralPath $directory) {
            $item = Get-Item -LiteralPath $directory
            if (-not $item.PSIsContainer) { Fail "data path is not a directory: $directory" }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail "data directory must not be a symbolic link: $directory"
            }
        }
        else {
            New-Item -ItemType Directory -Path $directory | Out-Null
        }
    }

    Assert-DirectoryUsable $dataRoot
    Assert-DirectoryUsable $mysqlDirectory
	foreach ($directory in $applicationDirectories) {
		Assert-DirectoryUsable $directory
	}
	foreach ($directory in $archiveSandboxDirectories) {
		Assert-DirectoryUsable $directory
	}

    $env:BINARYSCAN_DATA_ROOT = $dataRoot
    Write-Host "data root ready: $dataRoot"
}

function New-RandomHex {
    $bytes = New-Object byte[] 32
    $provider = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $provider.GetBytes($bytes)
    }
    finally {
        $provider.Dispose()
    }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Assert-LocalDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "runtime directory must be a real directory: $Path"
        }
        return
    }
    New-Item -ItemType Directory -Path $Path | Out-Null
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "runtime directory must be a real directory: $Path"
    }
}

function Write-NewFile([string]$Path, [byte[]]$Content) {
    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $stream.Write($Content, 0, $Content.Length)
        $stream.Flush()
    }
    finally {
        $stream.Dispose()
    }
}

function Initialize-Runtime {
	if (Test-Path -LiteralPath $EnvFile) {
        $envItem = Get-Item -LiteralPath $EnvFile -Force
        if ($envItem.PSIsContainer -or
            ($envItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail '.env must be a regular file, not a directory or reparse point'
        }
    }
    else {
        $templateBytes = [IO.File]::ReadAllBytes((Join-Path $ProjectRoot '.env.example'))
        Write-NewFile $EnvFile $templateBytes
		Write-Host 'created .env from .env.example'
    }
	$runtimeDirectory = Join-Path $ProjectRoot 'runtime'
	$secretDirectory = Join-Path $runtimeDirectory 'secrets'
    Assert-LocalDirectory $runtimeDirectory
    Assert-LocalDirectory $secretDirectory
	$createdAdmin = $false
	foreach ($name in @('mysql_root_password', 'mysql_app_password', 'initial_admin_password')) {
		$path = Join-Path $secretDirectory $name
		if (Test-Path -LiteralPath $path) {
            $secretItem = Get-Item -LiteralPath $path -Force
            if ($secretItem.PSIsContainer -or $secretItem.Length -eq 0 -or
                ($secretItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail "existing secret must be a non-empty regular file: $path"
            }
        }
        else {
            $secretValue = if ($name -eq 'initial_admin_password') {
                $DefaultInitialAdminPassword
            }
            else {
                New-RandomHex
            }
            $secretBytes = [Text.Encoding]::ASCII.GetBytes($secretValue)
            Write-NewFile $path $secretBytes
			if ($name -eq 'initial_admin_password') {
				$createdAdmin = $true
			}
		}
	}
	if ($createdAdmin) {
        Write-Host "default administrator credentials: admin / $DefaultInitialAdminPassword"
    }
    Initialize-DataDirectories
}

function Load-ExistingRuntime {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        Fail '.env is missing; run .\scripts\binaryscan.ps1 init first'
    }
    Load-Settings
}

function Assert-Image([string]$Image, [string]$ExpectedID = '') {
    $actual = (& docker image inspect $Image --format '{{.Id}}' 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($actual)) {
        Fail "required image is not loaded: $Image"
    }
    $actual = $actual.Trim()
    $labels = (& docker image inspect $Image --format '{{json .Config.Labels}}' 2>$null)
    if ($LASTEXITCODE -ne 0) { Fail "cannot inspect image labels: $Image" }
    if ($labels -match 'com\.binaryscan\.installation-id|sigstore|signature_status|trust-key') {
        Fail "image carries removed installation/signing metadata: $Image"
    }
    if ($ExpectedID -and $actual -ne $ExpectedID) {
        Fail "image ID mismatch for $Image`: got $actual, want $ExpectedID"
    }
    Write-Host "verified image $Image ($actual)"
}

function Assert-LockedImage([string]$Image, [string]$ExpectedID) {
    if ([string]::IsNullOrWhiteSpace($ExpectedID)) {
        Fail "frozen image ID is missing for $Image"
    }
    Assert-Image $Image $ExpectedID
}

function Assert-DependencyImages {
    Load-Settings
    Assert-LockedImage $env:BINARYSCAN_BUILDER_IMAGE $env:BINARYSCAN_BUILDER_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_MYSQL_IMAGE $env:BINARYSCAN_MYSQL_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE $env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_ARCHIVE_TOOLS_IMAGE $env:BINARYSCAN_ARCHIVE_TOOLS_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_JAVA_RUNTIME_IMAGE $env:BINARYSCAN_JAVA_RUNTIME_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE $env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_C_CHECKER_BUILDER_IMAGE $env:BINARYSCAN_C_CHECKER_BUILDER_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE $env:BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE_ID
    Assert-LockedImage $env:BINARYSCAN_C_CHECKER_JRE_IMAGE $env:BINARYSCAN_C_CHECKER_JRE_IMAGE_ID
}

function Product-Image([string]$Name, [string]$Fallback) {
    $value = [Environment]::GetEnvironmentVariable($Name, 'Process')
    if ([string]::IsNullOrWhiteSpace($value)) { return $Fallback }
    return $value
}

function Assert-ProductImages {
    Assert-Image (Product-Image 'BINARYSCAN_APP_IMAGE' 'binaryscan/app:0.1.0')
    Assert-Image (Product-Image 'BINARYSCAN_SCANNER_IMAGE' 'binaryscan/scanner:0.1.0')
    Assert-Image (Product-Image 'BINARYSCAN_JAVA_IMAGE' 'binaryscan/java:0.1.0')
    Assert-Image (Product-Image 'BINARYSCAN_GHIDRA_IMAGE' 'binaryscan/ghidra:0.1.0')
    Assert-Image (Product-Image 'BINARYSCAN_C_CHECKER_IMAGE' 'binaryscan/c-checker:0.1.0')
    Assert-Image (Product-Image 'BINARYSCAN_JAVA_CHECKER_IMAGE' 'binaryscan/java-checker:0.1.0')
}

function Assert-SourceManifest {
    $manifest = Join-Path $ProjectRoot 'MANIFEST.sha256'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) { return }
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line -notmatch '^([a-f0-9]{64})  (.+)$') {
            Fail "invalid source manifest line: $line"
        }
        $path = Join-Path $ProjectRoot $Matches[2]
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "source manifest file is missing: $($Matches[2])"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
        if ($actual -ne $Matches[1]) {
            Fail "source hash mismatch: $($Matches[2])"
        }
    }
    Write-Host 'source manifest verified'
}

function Invoke-Doctor {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Fail 'Docker Desktop is required'
    }
    Invoke-Docker @('info')
    Initialize-Runtime
    Assert-SourceManifest
    $services = (& docker compose --project-directory $ProjectRoot --env-file $EnvFile --file $ComposeFile config --services)
    if ($LASTEXITCODE -ne 0) { Fail 'compose configuration is invalid' }
    if (@($services).Count -ne 7) { Fail "compose must define exactly seven services, got $(@($services).Count)" }
    $services | ForEach-Object { Write-Host $_ }
    Write-Host 'doctor check passed'
}

function Import-Images([string]$Directory) {
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        Fail 'import requires an existing IMAGE_DIR'
    }
    $hashManifest = Join-Path $Directory 'IMAGE_FILES.sha256'
    if (-not (Test-Path -LiteralPath $hashManifest -PathType Leaf)) {
        Fail 'IMAGE_FILES.sha256 is missing'
    }
    $manifestItem = Get-Item -LiteralPath $hashManifest -Force
    if (($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'IMAGE_FILES.sha256 must not be a reparse point'
    }
    $expectedArchives = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($line in Get-Content -LiteralPath $hashManifest -Encoding UTF8) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line -notmatch '^([a-f0-9]{64})  ([A-Za-z0-9._-]+\.(?:tar(?:\.gz)?|tgz))$') {
            Fail "invalid image hash line: $line"
        }
        $name = $Matches[2]
        if (-not $expectedArchives.Add($name)) { Fail "duplicate image archive in manifest: $name" }
        $archive = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            Fail "image archive is missing: $name"
        }
        $archiveItem = Get-Item -LiteralPath $archive -Force
        if (($archiveItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "image archive must not be a reparse point: $name"
        }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
        if ($actual -ne $Matches[1]) { Fail "image archive hash mismatch: $name" }
    }
    if ($expectedArchives.Count -eq 0) { Fail 'IMAGE_FILES.sha256 contains no image archives' }
    $archives = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object { $_.Name -match '\.(tar|tar\.gz|tgz)$' } |
        Sort-Object Name
    foreach ($archive in $archives) {
        if (-not $expectedArchives.Contains($archive.Name)) {
            Fail "unlisted image archive: $($archive.Name)"
        }
        Write-Host "loading $($archive.Name)"
        Invoke-Docker @('load', '--input', $archive.FullName)
    }
    Write-Host 'image archive hashes verified'
    Assert-DependencyImages
}

function Get-SourceRevision {
    $sourceCommit = Join-Path $ProjectRoot 'SOURCE_COMMIT'
    if (Test-Path -LiteralPath $sourceCommit -PathType Leaf) {
        return (Get-Content -LiteralPath $sourceCommit -Raw).Trim()
    }
    $revision = (& git -C $ProjectRoot rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -eq 0) { return $revision.Trim() }
    return 'sealed-source'
}

function Get-ManifestHash {
    $manifest = Join-Path $ProjectRoot 'MANIFEST.sha256'
    if (Test-Path -LiteralPath $manifest -PathType Leaf) {
        return (Get-FileHash -Algorithm SHA256 -LiteralPath $manifest).Hash.ToLowerInvariant()
    }
    return 'unsealed'
}

function Build-One([string]$Name, [string]$Dockerfile, [string]$Tag, [string[]]$Extra) {
    Write-Host "building $Name as $Tag"
    $arguments = @(
        'build', '--pull=false', '--network=none', '--platform', $env:BINARYSCAN_PLATFORM,
        '--file', (Join-Path $ProjectRoot $Dockerfile), '--tag', $Tag,
        '--build-arg', "BUILDER_IMAGE=$($env:BINARYSCAN_BUILDER_IMAGE)",
        '--build-arg', "BINARYSCAN_VERSION=$script:Version",
        '--build-arg', "BINARYSCAN_REVISION=$script:Revision",
        '--build-arg', "BINARYSCAN_SOURCE_MANIFEST_SHA256=$script:ManifestHash"
    ) + $Extra + @($ProjectRoot)
    Invoke-Docker $arguments
}

function Build-Images {
    Initialize-Runtime
    Assert-SourceManifest
    Assert-DependencyImages
    $script:Version = (Get-Content -LiteralPath (Join-Path $ProjectRoot 'VERSION') -Raw).Trim()
    $script:Revision = Get-SourceRevision
    $script:ManifestHash = Get-ManifestHash
    $app = Product-Image 'BINARYSCAN_APP_IMAGE' "binaryscan/app:$script:Version"
    $scanner = Product-Image 'BINARYSCAN_SCANNER_IMAGE' "binaryscan/scanner:$script:Version"
    $java = Product-Image 'BINARYSCAN_JAVA_IMAGE' "binaryscan/java:$script:Version"
    $ghidra = Product-Image 'BINARYSCAN_GHIDRA_IMAGE' "binaryscan/ghidra:$script:Version"
    $cChecker = Product-Image 'BINARYSCAN_C_CHECKER_IMAGE' "binaryscan/c-checker:$script:Version"
    $javaChecker = Product-Image 'BINARYSCAN_JAVA_CHECKER_IMAGE' "binaryscan/java-checker:$script:Version"
    Build-One 'app' 'docker/app.Dockerfile' $app @()
    Build-One 'scanner' 'docker/scanner.Dockerfile' $scanner @(
        '--build-arg', "TRIVY_RUNTIME_DB_IMAGE=$($env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE)",
        '--build-arg', "ARCHIVE_TOOLS_IMAGE=$($env:BINARYSCAN_ARCHIVE_TOOLS_IMAGE)"
    )
    Build-One 'java' 'docker/java.Dockerfile' $java @('--build-arg', "JAVA_RUNTIME_IMAGE=$($env:BINARYSCAN_JAVA_RUNTIME_IMAGE)")
    Build-One 'ghidra' 'docker/ghidra.Dockerfile' $ghidra @('--build-arg', "GHIDRA_RUNTIME_IMAGE=$($env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE)")
    Write-Host "building c-checker as $cChecker"
    Invoke-Docker @(
        'build', '--pull=false', '--network=none', '--platform', $env:BINARYSCAN_PLATFORM,
        '--file', (Join-Path $ProjectRoot 'c-checker/Dockerfile'), '--tag', $cChecker,
        '--build-arg', "C_CHECKER_BUILDER_IMAGE=$($env:BINARYSCAN_C_CHECKER_BUILDER_IMAGE)",
        '--build-arg', "C_CHECKER_JRE_IMAGE=$($env:BINARYSCAN_C_CHECKER_JRE_IMAGE)",
        '--build-arg', "BINARYSCAN_VERSION=$script:Version",
        '--build-arg', "BINARYSCAN_REVISION=$script:Revision",
        '--build-arg', "BINARYSCAN_SOURCE_MANIFEST_SHA256=$script:ManifestHash",
        (Join-Path $ProjectRoot 'c-checker')
    )
    Write-Host "building java-checker as $javaChecker"
    Invoke-Docker @(
        'build', '--pull=false', '--network=none', '--platform', $env:BINARYSCAN_PLATFORM,
        '--file', (Join-Path $ProjectRoot 'java-checker/Dockerfile'), '--tag', $javaChecker,
        '--build-arg', "JAVA_CHECKER_BUILDER_IMAGE=$($env:BINARYSCAN_JAVA_CHECKER_BUILDER_IMAGE)",
        '--build-arg', "JAVA_CHECKER_JRE_IMAGE=$($env:BINARYSCAN_C_CHECKER_JRE_IMAGE)",
        '--build-arg', "BINARYSCAN_VERSION=$script:Version",
        '--build-arg', "BINARYSCAN_REVISION=$script:Revision",
        '--build-arg', "BINARYSCAN_SOURCE_MANIFEST_SHA256=$script:ManifestHash",
        (Join-Path $ProjectRoot 'java-checker')
    )
    Invoke-Docker @('run', '--rm', '--network', 'none', '--entrypoint', '/usr/local/bin/binaryscan-bundle-check', $scanner)
    Write-Host 'offline product image build passed'
}

function Start-Services {
    Initialize-Runtime
    Assert-ProductImages
    Invoke-Compose @('up', '--detach', '--wait')
    $port = if ($env:BINARYSCAN_HTTP_PORT) { $env:BINARYSCAN_HTTP_PORT } else { '8080' }
    Write-Host "BinaryScan is available at http://127.0.0.1:$port"
}

function Initialize-Administrator {
    Initialize-Runtime
    $marker = Join-Path $env:BINARYSCAN_DATA_ROOT '.admin-initialized'
    if (Test-Path -LiteralPath $marker) {
        $markerItem = Get-Item -LiteralPath $marker -Force
        if ($markerItem.PSIsContainer -or
            ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "administrator marker must be a regular file: $marker"
        }
        Write-Host 'initial administrator was already created for this runtime directory'
        return
    }
    Invoke-Compose @('exec', '--no-TTY', 'app', '/usr/local/bin/binaryscan-maintenance', 'init-admin', '--username', 'admin', '--display-name', 'Administrator', '--password-file', '/run/secrets/initial_admin_password')
    try {
        $markerStream = [IO.File]::Open(
            $marker, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None
        )
        $markerStream.Dispose()
    }
    catch {
        if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) { throw }
        $markerItem = Get-Item -LiteralPath $marker -Force
        if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
    }
    Write-Host 'administrator created: admin'
}

function Verify-Running {
    Assert-SourceManifest
    Invoke-Compose @('ps')
    Invoke-Compose @('exec', '--no-TTY', 'app', '/usr/local/bin/binaryscan-maintenance', 'healthcheck')
    Invoke-Compose @('exec', '--no-TTY', 'scanner', '/usr/local/bin/binaryscan-supervisor', 'healthcheck', 'scanner')
    Invoke-Compose @('exec', '--no-TTY', 'scanner', '/usr/local/bin/binaryscan-bundle-check')
    Invoke-Compose @('exec', '--no-TTY', 'java', '/usr/local/bin/binaryscan-worker', 'healthcheck', '--role', 'bytecode')
    Invoke-Compose @('exec', '--no-TTY', 'ghidra', '/usr/local/bin/binaryscan-worker', 'healthcheck', '--role', 'native')
    Invoke-Compose @('exec', '--no-TTY', 'c-checker', '/opt/binaryscan/bin/c-checker-healthcheck')
    Invoke-Compose @('exec', '--no-TTY', 'java-checker', '/opt/binaryscan/bin/java-checker-healthcheck')
    Write-Host 'runtime verification passed'
}

switch ($Command) {
    'doctor' { Invoke-Doctor }
    'init' { Initialize-Runtime }
    'import' { Import-Images $Argument }
    'build' { Build-Images }
    'up' { Start-Services }
    'init-admin' { Initialize-Administrator }
    'deploy' {
        Invoke-Doctor
        Import-Images $Argument
        Build-Images
        Start-Services
        Initialize-Administrator
        Verify-Running
    }
    'verify' { Load-ExistingRuntime; Verify-Running }
    'status' { Load-ExistingRuntime; Invoke-Compose @('ps') }
    'logs' {
        Load-ExistingRuntime
        if ($Argument) { Invoke-Compose @('logs', '--follow', $Argument) }
        else { Invoke-Compose @('logs', '--follow') }
    }
    'down' { Load-ExistingRuntime; Invoke-Compose @('down', '--remove-orphans') }
    default {
        Write-Host 'Usage: .\scripts\binaryscan.ps1 doctor|init|import|build|up|init-admin|deploy|verify|status|logs|down [ARG]'
    }
}
