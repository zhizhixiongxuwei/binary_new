param(
    [Parameter(Position = 0)]
    [ValidateSet('help', 'doctor', 'init', 'import', 'build', 'up', 'init-admin', 'deploy', 'verify', 'status', 'logs', 'down')]
    [string]$Command = 'help',
    [Parameter(Position = 1)]
    [string]$Argument = ''
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ComposeFile = Join-Path $ProjectRoot 'compose.yaml'
$EnvFile = Join-Path $ProjectRoot '.env'

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

function Import-EnvFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }
    foreach ($line in Get-Content -LiteralPath $Path) {
        $value = $line.Trim()
        if ($value.Length -eq 0 -or $value.StartsWith('#')) {
            continue
        }
        $parts = $value.Split('=', 2)
        if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[A-Z0-9_]+$') {
            Fail "invalid environment line in $Path`: $line"
        }
        [Environment]::SetEnvironmentVariable($parts[0], $parts[1], 'Process')
    }
}

function Load-Settings {
    Import-EnvFile (Join-Path $ProjectRoot 'images.lock.env')
    Import-EnvFile $EnvFile
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

function Initialize-Runtime {
    if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
        Copy-Item -LiteralPath (Join-Path $ProjectRoot '.env.example') -Destination $EnvFile
        Write-Host 'created .env from .env.example'
    }
    $secretDirectory = Join-Path $ProjectRoot 'runtime/secrets'
    New-Item -ItemType Directory -Force -Path $secretDirectory | Out-Null
    $createdAdmin = $false
    foreach ($name in @('mysql_root_password', 'mysql_app_password', 'initial_admin_password')) {
        $path = Join-Path $secretDirectory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item $path).Length -eq 0) {
            New-RandomHex | Set-Content -LiteralPath $path -NoNewline -Encoding ascii
            if ($name -eq 'initial_admin_password') {
                $createdAdmin = $true
            }
        }
    }
    if ($createdAdmin) {
        $password = Get-Content -LiteralPath (Join-Path $secretDirectory 'initial_admin_password') -Raw
        Write-Host "initial administrator password: $password"
        Write-Host 'store this password securely; it is not included in the source package'
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

function Assert-DependencyImages {
    Load-Settings
    Assert-Image $env:BINARYSCAN_BUILDER_IMAGE $env:BINARYSCAN_BUILDER_IMAGE_ID
    Assert-Image $env:BINARYSCAN_MYSQL_IMAGE $env:BINARYSCAN_MYSQL_IMAGE_ID
    Assert-Image $env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE $env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE_ID
    Assert-Image $env:BINARYSCAN_JAVA_RUNTIME_IMAGE $env:BINARYSCAN_JAVA_RUNTIME_IMAGE_ID
    Assert-Image $env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE $env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE_ID
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
    if (@($services).Count -ne 5) { Fail "compose must define exactly five services, got $(@($services).Count)" }
    $services | ForEach-Object { Write-Host $_ }
    Write-Host 'doctor check passed'
}

function Import-Images([string]$Directory) {
    if (-not $Directory -or -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        Fail 'import requires an existing IMAGE_DIR'
    }
    $hashManifest = Join-Path $Directory 'IMAGE_FILES.sha256'
    if (Test-Path -LiteralPath $hashManifest -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $hashManifest) {
            if ($line -notmatch '^([a-f0-9]{64})  (.+)$') { Fail "invalid image hash line: $line" }
            $archive = Join-Path $Directory $Matches[2]
            $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
            if ($actual -ne $Matches[1]) { Fail "image archive hash mismatch: $($Matches[2])" }
        }
        Write-Host 'image archive hashes verified'
    }
    $archives = Get-ChildItem -LiteralPath $Directory -File |
        Where-Object { $_.Name -match '\.(tar|tar\.gz|tgz)$' } |
        Sort-Object Name
    foreach ($archive in $archives) {
        Write-Host "loading $($archive.Name)"
        Invoke-Docker @('load', '--input', $archive.FullName)
    }
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
    Build-One 'app' 'docker/app.Dockerfile' $app @()
    Build-One 'scanner' 'docker/scanner.Dockerfile' $scanner @('--build-arg', "TRIVY_RUNTIME_DB_IMAGE=$($env:BINARYSCAN_TRIVY_RUNTIME_DB_IMAGE)")
    Build-One 'java' 'docker/java.Dockerfile' $java @('--build-arg', "JAVA_RUNTIME_IMAGE=$($env:BINARYSCAN_JAVA_RUNTIME_IMAGE)")
    Build-One 'ghidra' 'docker/ghidra.Dockerfile' $ghidra @('--build-arg', "GHIDRA_RUNTIME_IMAGE=$($env:BINARYSCAN_GHIDRA_RUNTIME_IMAGE)")
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
    $marker = Join-Path $ProjectRoot 'runtime/.admin-initialized'
    if (Test-Path -LiteralPath $marker) {
        Write-Host 'initial administrator was already created for this runtime directory'
        return
    }
    Invoke-Compose @('exec', '--no-TTY', 'app', '/usr/local/bin/binaryscan-maintenance', 'init-admin', '--username', 'admin', '--display-name', 'Administrator', '--password-file', '/run/secrets/initial_admin_password')
    New-Item -ItemType File -Force -Path $marker | Out-Null
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
    'verify' { Initialize-Runtime; Verify-Running }
    'status' { Initialize-Runtime; Invoke-Compose @('ps') }
    'logs' {
        Initialize-Runtime
        if ($Argument) { Invoke-Compose @('logs', '--follow', $Argument) }
        else { Invoke-Compose @('logs', '--follow') }
    }
    'down' { Initialize-Runtime; Invoke-Compose @('down', '--remove-orphans') }
    default {
        Write-Host 'Usage: .\scripts\binaryscan.ps1 doctor|init|import|build|up|init-admin|deploy|verify|status|logs|down [ARG]'
    }
}
