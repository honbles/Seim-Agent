#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs, uninstalls, or updates the OpenSIEM Agent Windows service.

.DESCRIPTION
    This script:
      1. Copies agent.exe and config files to the install directory.
      2. Creates the ProgramData working directory.
      3. Registers the service with the Windows Service Control Manager.
      4. Optionally generates a self-signed agent certificate for mTLS.

.PARAMETER Action
    install   - Install the service (default)
    uninstall - Stop and remove the service
    update    - Replace the binary and restart the service
    status    - Show current service status

.PARAMETER InstallDir
    Destination directory. Default: C:\Program Files\OpenSIEM\Agent

.PARAMETER ConfigPath
    Path to agent.yaml. Default: <InstallDir>\agent.yaml

.PARAMETER BackendURL
    Backend ingest URL, written into agent.yaml during install.

.PARAMETER AgentID
    Override agent ID (default: hostname).

.EXAMPLE
    .\install.ps1 -Action install -BackendURL "https://siem.corp.internal:8443"

.EXAMPLE
    .\install.ps1 -Action uninstall
#>

param(
    [ValidateSet("install","uninstall","update","status")]
    [string]$Action = "install",

    [string]$InstallDir   = "C:\Program Files\OpenSIEM\Agent",
    [string]$DataDir      = "C:\ProgramData\OpenSIEM",
    [string]$ConfigPath   = "",       # defaults to $InstallDir\agent.yaml
    [string]$BackendURL   = "",
    [string]$AgentID      = "",
    [switch]$GenerateCert = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ────────────────────────────────────────────────────────────────
$ServiceName        = "OpenSIEMAgent"
$ServiceDisplayName = "OpenSIEM Security Agent"
$ServiceDescription = "Collects Windows security telemetry and forwards it to the OpenSIEM backend."
$AgentExeName       = "agent.exe"

# Resolve defaults
if (-not $ConfigPath) { $ConfigPath = Join-Path $InstallDir "agent.yaml" }

# ── Helper functions ─────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host "  >> $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "  [OK] $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  [WARN] $msg" -ForegroundColor Yellow
}

function Stop-AgentService {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Step "Stopping service..."
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
}

function Remove-AgentService {
    Stop-AgentService
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Step "Removing service..."
        sc.exe delete $ServiceName | Out-Null
        Write-OK "Service removed."
    }
}

# ── Actions ──────────────────────────────────────────────────────────────────

function Install-Agent {
    Write-Host "`nOpenSIEM Agent Installer" -ForegroundColor White
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray

    # 1. Create directories
    Write-Step "Creating directories..."
    foreach ($dir in @($InstallDir, $DataDir, "$InstallDir\certs", "$DataDir\logs")) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    Write-OK "Directories ready."

    # 2. Copy binary
    $srcExe = Join-Path $PSScriptRoot $AgentExeName
    if (-not (Test-Path $srcExe)) {
        # Fall back to current directory
        $srcExe = Join-Path (Get-Location) $AgentExeName
    }
    if (-not (Test-Path $srcExe)) {
        throw "Cannot find $AgentExeName. Place it next to install.ps1 before running."
    }
    Write-Step "Copying binary..."
    Copy-Item -Path $srcExe -Destination (Join-Path $InstallDir $AgentExeName) -Force
    Write-OK "Binary installed to $InstallDir."

    # 3. Write config
    if (-not (Test-Path $ConfigPath)) {
        Write-Step "Writing default config..."
        $srcConfig = Join-Path $PSScriptRoot "..\configs\agent.yaml"
        if (Test-Path $srcConfig) {
            Copy-Item -Path $srcConfig -Destination $ConfigPath -Force
        } else {
            Write-Warn "Default config not found; writing minimal config."
            Write-MinimalConfig
        }
    } else {
        Write-Warn "Config already exists at $ConfigPath — skipping."
    }

    # Patch BackendURL into config if supplied
    if ($BackendURL) {
        Write-Step "Setting backend_url in config..."
        (Get-Content $ConfigPath) -replace 'backend_url:.*', "backend_url: `"$BackendURL`"" |
            Set-Content $ConfigPath
    }

    # Patch agent ID if supplied
    if ($AgentID) {
        (Get-Content $ConfigPath) -replace '^  id:.*', "  id: `"$AgentID`"" |
            Set-Content $ConfigPath
    }

    # Patch queue db_path to DataDir
    (Get-Content $ConfigPath) -replace 'db_path:.*', "db_path: `"$DataDir\queue.db`"" |
        Set-Content $ConfigPath

    Write-OK "Config written to $ConfigPath."

    # 4. Optional self-signed cert generation (dev / lab use)
    if ($GenerateCert) {
        Write-Step "Generating self-signed agent certificate (dev only)..."
        $certDir = Join-Path $InstallDir "certs"
        $cert = New-SelfSignedCertificate `
            -Subject "CN=opensiem-agent-$(hostname)" `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -NotAfter (Get-Date).AddYears(5)
        $pwd = ConvertTo-SecureString -String "changeme" -Force -AsPlainText
        Export-PfxCertificate -Cert $cert -FilePath "$certDir\agent.pfx" -Password $pwd | Out-Null
        Write-Warn "Self-signed cert exported to $certDir\agent.pfx (password: changeme)."
        Write-Warn "Convert to PEM with: openssl pkcs12 -in agent.pfx -out agent.crt -nokeys"
        Write-Warn "                      openssl pkcs12 -in agent.pfx -out agent.key -nocerts -nodes"
    }

    # 5. Register the Windows service
    Write-Step "Registering Windows service..."
    $agentExePath = Join-Path $InstallDir $AgentExeName
    $binPath = "`"$agentExePath`" -config `"$ConfigPath`""

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Warn "Service already exists. Run with -Action update to replace."
    } else {
        New-Service `
            -Name $ServiceName `
            -DisplayName $ServiceDisplayName `
            -Description $ServiceDescription `
            -BinaryPathName $binPath `
            -StartupType Automatic | Out-Null
        Write-OK "Service registered."
    }

    # 6. Set recovery actions (restart on failure)
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Write-OK "Recovery actions configured."

    # 7. Start service
    Write-Step "Starting service..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    $svc = Get-Service -Name $ServiceName
    Write-OK "Service status: $($svc.Status)"

    Write-Host "`n✓ OpenSIEM Agent installed successfully.`n" -ForegroundColor Green
}

function Uninstall-Agent {
    Write-Host "`nUninstalling OpenSIEM Agent..." -ForegroundColor Yellow
    Remove-AgentService

    $remove = Read-Host "Remove install directory $InstallDir ? [y/N]"
    if ($remove -match "^[Yy]") {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Install directory removed."
    }

    $removeData = Read-Host "Remove data directory $DataDir (queue DB, logs)? [y/N]"
    if ($removeData -match "^[Yy]") {
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK "Data directory removed."
    }

    Write-Host "`n✓ OpenSIEM Agent uninstalled.`n" -ForegroundColor Green
}

function Update-Agent {
    Write-Host "`nUpdating OpenSIEM Agent binary..." -ForegroundColor Cyan
    Stop-AgentService

    $srcExe = Join-Path $PSScriptRoot $AgentExeName
    Copy-Item -Path $srcExe -Destination (Join-Path $InstallDir $AgentExeName) -Force
    Write-OK "Binary updated."

    Start-Service -Name $ServiceName
    Write-OK "Service restarted."
}

function Show-Status {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Write-Host "`nService : $ServiceName"
        Write-Host "Status  : $($svc.Status)"
        Write-Host "Start   : $($svc.StartType)"
    } else {
        Write-Warn "Service $ServiceName is not installed."
    }
}

function Write-MinimalConfig {
    @"
agent:
  id: ""
  version: "0.1.0"
collector:
  event_log:
    enabled: true
    channels: [Security, System, Application]
    poll_interval: 5s
  sysmon:
    enabled: false
  network:
    enabled: true
    poll_interval: 30s
  process:
    enabled: true
  registry:
    enabled: true
    keys:
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
forwarder:
  backend_url: "$BackendURL"
  batch_size: 200
  flush_interval: 5s
queue:
  db_path: "$DataDir\queue.db"
  max_rows: 100000
log:
  level: info
  format: json
"@ | Set-Content $ConfigPath
}

# ── Dispatch ─────────────────────────────────────────────────────────────────
switch ($Action) {
    "install"   { Install-Agent   }
    "uninstall" { Uninstall-Agent }
    "update"    { Update-Agent    }
    "status"    { Show-Status     }
}
