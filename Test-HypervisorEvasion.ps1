<#
.SYNOPSIS
    Test-HypervisorEvasion.ps1 - WSL and VM-Layer Evasion Detection Framework
.DESCRIPTION
    Tests your EDR/SIEM visibility into two major detection blind spots:
      1. Windows Subsystem for Linux (WSL) command execution
      2. Virtual Machine-based payload hiding (Ragnar Locker / Maze / Akira technique)

    Adversaries use WSL and VMs to execute tools in environments where EDR
    agents have zero visibility. This framework safely emulates those TTPs
    and validates whether your detection stack catches the activity.

    MITRE: T1202, T1564.006, T1059.004
    Actors: Ragnar Locker, Maze, Conti, Akira, MirrorFace, CronTrap
    Source: SpecterOps WSL2 research, Sophos Ragnar Locker report
.PARAMETER Mode
    wsl       - WSL evasion tests only
    vm        - VM/hypervisor detection tests only
    full      - All tests
    audit     - Posture check only (no execution)
.PARAMETER OutputDir
    Results directory. Default: .\HypervisorEvasion_Results
.PARAMETER SkipWSL
    Skip WSL tests (useful if WSL is not installed)
.PARAMETER SkipVM
    Skip VM/hypervisor tests
.EXAMPLE
    .\Test-HypervisorEvasion.ps1 -Mode audit
.EXAMPLE
    .\Test-HypervisorEvasion.ps1 -Mode full
.EXAMPLE
    .\Test-HypervisorEvasion.ps1 -Mode wsl
#>
[CmdletBinding()]
param(
    [ValidateSet("wsl","vm","full","audit")]
    [string]$Mode = "full",
    [string]$OutputDir = ".\HypervisorEvasion_Results",
    [switch]$SkipWSL,
    [switch]$SkipVM,
    [switch]$HTMLReport
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$RunID = [guid]::NewGuid().ToString().Substring(0,8)

Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Magenta
Write-Host "   Hypervisor-Layer Evasion Detection Framework v1.0" -ForegroundColor Magenta
Write-Host "   WSL Abuse + VM-Based Payload Hiding" -ForegroundColor Magenta
Write-Host "   MITRE: T1202 | T1564.006 | T1059.004" -ForegroundColor DarkGray
Write-Host "  ================================================================" -ForegroundColor Magenta
Write-Host "   Run: $RunID | Mode: $Mode | Host: $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host ""

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ============================================================================
# RESULTS
# ============================================================================
$Script:Results = New-Object System.Collections.ArrayList

function Add-Result {
    param([string]$Layer,[string]$Test,[string]$Target,[string]$Result,[string]$Detail,[string]$Sev="Medium",[string]$Mitre="T1202")
    $entry = New-Object PSObject -Property @{
        Timestamp=$((Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        RunID=$RunID; Layer=$Layer; TestName=$Test; Target=$Target
        Result=$Result; Severity=$Sev; Detail=$Detail; MitreID=$Mitre
        Hostname=$env:COMPUTERNAME
    }
    $Script:Results.Add($entry) | Out-Null
    switch ($Result) {
        "PASS"       { $c = "Green" }
        "BLOCKED"    { $c = "Green" }
        "DETECTED"   { $c = "Green" }
        "FAIL"       { $c = "Red" }
        "UNDETECTED" { $c = "Red" }
        "WARN"       { $c = "Yellow" }
        "SKIP"       { $c = "Gray" }
        default      { $c = "Cyan" }
    }
    Write-Host "  [$Layer] $Test " -NoNewline
    Write-Host "$Result" -ForegroundColor $c -NoNewline
    Write-Host " | $Detail"
}

# ============================================================================
# POSTURE: WSL & HYPERVISOR ENVIRONMENT CHECK
# ============================================================================
function Test-Posture {
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  [POSTURE] Environment Assessment" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Cyan

    # --- WSL installed? ---
    $wslExe = Join-Path $env:SystemRoot "System32\wsl.exe"
    $Script:WSLInstalled = Test-Path $wslExe
    if ($Script:WSLInstalled) {
        Add-Result "POSTURE" "WSL Binary" "wsl.exe" "INFO" "WSL is installed at $wslExe"
        # Check WSL version
        try {
            $wslStatus = & wsl.exe --status 2>&1 | Out-String
            if ($wslStatus -match "WSL version:\s*(\S+)") {
                Add-Result "POSTURE" "WSL Version" "wsl.exe" "INFO" "WSL version: $($Matches[1])"
            }
            if ($wslStatus -match "Default Version:\s*(\d)") {
                Add-Result "POSTURE" "Default WSL Version" "wsl.exe" "INFO" "Default: WSL$($Matches[1])"
            }
        }
        catch {
            Add-Result "POSTURE" "WSL Status" "wsl.exe" "WARN" "Could not query WSL status"
        }
        # List installed distros
        try {
            $distros = & wsl.exe --list --quiet 2>&1 | Out-String
            $distroList = ($distros -split "`n" | Where-Object { $_.Trim() -ne "" }) -join ", "
            if ($distroList) {
                Add-Result "POSTURE" "WSL Distros" "wsl.exe" "INFO" "Installed: $distroList"
            }
            else {
                Add-Result "POSTURE" "WSL Distros" "wsl.exe" "INFO" "No distros installed (WSL present but inactive)"
            }
        }
        catch {
            Add-Result "POSTURE" "WSL Distros" "wsl.exe" "WARN" "Could not list distros"
        }
    }
    else {
        Add-Result "POSTURE" "WSL Binary" "wsl.exe" "INFO" "WSL is NOT installed"
        $Script:WSLInstalled = $false
    }

    # --- WSL registry config ---
    $wslRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    if (Test-Path $wslRegPath) {
        Add-Result "POSTURE" "WSL Registry" $wslRegPath "INFO" "WSL Lxss registry key exists" "Low"
    }

    # --- Hyper-V ---
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction Stop
        if ($hyperv.State -eq "Enabled") {
            Add-Result "POSTURE" "Hyper-V" "Windows Feature" "INFO" "Hyper-V is ENABLED"
        }
        else {
            Add-Result "POSTURE" "Hyper-V" "Windows Feature" "INFO" "Hyper-V is not enabled"
        }
    }
    catch {
        Add-Result "POSTURE" "Hyper-V" "Windows Feature" "WARN" "Cannot check Hyper-V status"
    }

    # --- VirtualBox ---
    $vboxPaths = @(
        "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe",
        "C:\Program Files (x86)\Oracle\VirtualBox\VBoxManage.exe"
    )
    $Script:VBoxInstalled = $false
    foreach ($vp in $vboxPaths) {
        if (Test-Path $vp) {
            $Script:VBoxInstalled = $true
            $Script:VBoxPath = $vp
            Add-Result "POSTURE" "VirtualBox" $vp "INFO" "VirtualBox is installed"
            break
        }
    }
    if (-not $Script:VBoxInstalled) {
        Add-Result "POSTURE" "VirtualBox" "Not found" "INFO" "VirtualBox is not installed"
    }

    # --- VMware ---
    $vmwarePaths = @(
        "C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe",
        "C:\Program Files\VMware\VMware Workstation\vmware.exe"
    )
    foreach ($vmp in $vmwarePaths) {
        if (Test-Path $vmp) {
            Add-Result "POSTURE" "VMware" $vmp "INFO" "VMware Workstation is installed"
            break
        }
    }

    # --- Sysmon ---
    $sysmonSvc = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    if ($sysmonSvc -and $sysmonSvc.Status -eq "Running") {
        Add-Result "POSTURE" "Sysmon" "Service" "PASS" "Sysmon running (Events 1,6,17,18 available)"
    }
    else {
        Add-Result "POSTURE" "Sysmon" "Service" "FAIL" "Sysmon NOT running - WSL child process telemetry limited" "High"
    }

    # --- EDR ---
    $edrMap = @{
        "csfalconservice"="CrowdStrike"; "SentinelAgent"="SentinelOne"
        "MsSense"="Defender for Endpoint"; "elastic-agent"="Elastic Agent"
    }
    $foundEDR = $false
    foreach ($proc in $edrMap.Keys) {
        $p = Get-Process -Name $proc -ErrorAction SilentlyContinue
        if ($p) {
            Add-Result "POSTURE" "EDR" $edrMap[$proc] "INFO" "Detected (PID: $($p.Id))"
            $foundEDR = $true
        }
    }
    if (-not $foundEDR) {
        Add-Result "POSTURE" "EDR" "None" "WARN" "No EDR agent detected" "High"
    }

    # --- Windows Sandbox ---
    try {
        $sandbox = Get-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -ErrorAction Stop
        if ($sandbox.State -eq "Enabled") {
            Add-Result "POSTURE" "Windows Sandbox" "Feature" "INFO" "Windows Sandbox is ENABLED (T1564.006 vector)"
        }
    }
    catch {
        # Not available on all SKUs
        Add-Result "POSTURE" "Windows Sandbox" "Feature" "INFO" "Cannot check (may not be available on this SKU)"
    }
}

# ============================================================================
# WSL TESTS
# ============================================================================
function Test-WSLEvasion {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  [WSL] Windows Subsystem for Linux Evasion Tests" -ForegroundColor Cyan
    Write-Host "  T1202 Indirect Command Execution | T1059.004 Unix Shell" -ForegroundColor DarkCyan
    Write-Host "  ================================================================" -ForegroundColor Cyan

    if (-not $Script:WSLInstalled) {
        Add-Result "WSL" "WSL Availability" "wsl.exe" "SKIP" "WSL not installed - skipping WSL tests"
        return
    }

    # Check if any distro is actually available to run commands
    $hasDistro = $false
    try {
        $distroCheck = & wsl.exe --list --quiet 2>&1 | Out-String
        if ($distroCheck.Trim().Length -gt 0 -and $distroCheck -notmatch "no installed") {
            $hasDistro = $true
        }
    }
    catch {
        $hasDistro = $false
    }

    if (-not $hasDistro) {
        Add-Result "WSL" "WSL Distro" "wsl.exe" "SKIP" "No WSL distros installed - cannot run live WSL tests"
        # Still test detection of wsl.exe invocation patterns
        Write-Host "  [*] Running WSL invocation pattern tests (no distro needed)..." -ForegroundColor Yellow
    }

    # --- TEST 1: Basic wsl.exe command execution ---
    # This is the core blind spot: commands run inside WSL generate minimal Windows telemetry
    if ($hasDistro) {
        Write-Host ""
        Write-Host "  -- Test Group: WSL Command Execution Visibility --" -ForegroundColor White

        # Benign hostname command
        try {
            $output = & wsl.exe hostname 2>&1 | Out-String
            Add-Result "WSL" "Basic Command (hostname)" "wsl.exe hostname" "UNDETECTED" "Executed. Output: $($output.Trim()). Did your EDR log this?" "High" "T1059.004"
        }
        catch {
            Add-Result "WSL" "Basic Command (hostname)" "wsl.exe" "BLOCKED" "WSL execution was blocked: $($_.Exception.Message)" "High" "T1059.004"
        }

        # whoami inside WSL (recon)
        try {
            $output = & wsl.exe whoami 2>&1 | Out-String
            Add-Result "WSL" "Recon Command (whoami)" "wsl.exe whoami" "UNDETECTED" "Executed: $($output.Trim()). Check for Sysmon Event 1 with wsl.exe parent." "High" "T1059.004"
        }
        catch {
            Add-Result "WSL" "Recon Command (whoami)" "wsl.exe" "BLOCKED" "Blocked" "High" "T1059.004"
        }

        # --- TEST 2: Network recon from WSL (attacker would use this to scan) ---
        Write-Host ""
        Write-Host "  -- Test Group: WSL Network Activity --" -ForegroundColor White

        # DNS lookup from WSL (touches Windows network stack)
        try {
            $output = & wsl.exe nslookup example.com 2>&1 | Out-String
            Add-Result "WSL" "DNS from WSL (nslookup)" "wsl.exe nslookup" "UNDETECTED" "DNS query executed from WSL. Did your NDR/proxy see it?" "High" "T1016"
        }
        catch {
            Add-Result "WSL" "DNS from WSL" "wsl.exe" "INFO" "nslookup not available in WSL distro"
        }

        # curl from WSL to external host
        try {
            $output = & wsl.exe curl -s -o /dev/null -w "%{http_code}" https://example.com 2>&1 | Out-String
            Add-Result "WSL" "HTTP from WSL (curl)" "wsl.exe curl" "UNDETECTED" "HTTP request from WSL returned: $($output.Trim()). Check proxy/firewall logs." "High" "T1071.001"
        }
        catch {
            Add-Result "WSL" "HTTP from WSL" "wsl.exe" "INFO" "curl not available in distro or blocked"
        }

        # --- TEST 3: File system access from WSL to Windows ---
        Write-Host ""
        Write-Host "  -- Test Group: WSL Cross-Boundary File Access --" -ForegroundColor White

        # WSL accessing Windows filesystem via /mnt/c
        try {
            $output = & wsl.exe ls /mnt/c/Users 2>&1 | Out-String
            Add-Result "WSL" "Windows FS Access (/mnt/c)" "wsl.exe ls /mnt/c/Users" "UNDETECTED" "WSL listed Windows user dirs. Did your EDR detect cross-boundary access?" "High" "T1005"
        }
        catch {
            Add-Result "WSL" "Windows FS Access" "wsl.exe" "INFO" "Could not access /mnt/c"
        }

        # Write a canary file from WSL to Windows temp
        $canaryName = "wsl_evasion_test_$RunID.txt"
        $canaryWinPath = Join-Path $env:TEMP $canaryName
        $canaryWSLPath = "/mnt/c/Users/$env:USERNAME/AppData/Local/Temp/$canaryName"
        try {
            & wsl.exe bash -c "echo 'BYOVD_WSL_TEST' > '$canaryWSLPath'" 2>&1 | Out-Null
            if (Test-Path $canaryWinPath) {
                Add-Result "WSL" "Cross-Boundary File Write" $canaryWinPath "UNDETECTED" "WSL wrote file to Windows filesystem. Check EDR for file create from wslhost.exe." "Critical" "T1105"
                Remove-Item $canaryWinPath -Force -ErrorAction SilentlyContinue
            }
            else {
                Add-Result "WSL" "Cross-Boundary File Write" $canaryWSLPath "INFO" "File write did not succeed or path mismatch"
            }
        }
        catch {
            Add-Result "WSL" "Cross-Boundary File Write" "wsl.exe" "INFO" "Could not write canary file: $($_.Exception.Message)"
        }

        # --- TEST 4: Reverse shell pattern (benign - just tests the command pattern) ---
        Write-Host ""
        Write-Host "  -- Test Group: WSL Suspicious Command Patterns --" -ForegroundColor White

        # bash -c with piped commands (common in WSL-based attacks)
        try {
            $output = & wsl.exe bash -c "echo 'test' | cat" 2>&1 | Out-String
            Add-Result "WSL" "Piped bash -c Execution" "wsl.exe bash -c" "UNDETECTED" "bash -c with pipe executed. Pattern matches WSL malware loader TTPs." "High" "T1059.004"
        }
        catch {
            Add-Result "WSL" "Piped bash -c" "wsl.exe" "BLOCKED" "Execution blocked" "High" "T1059.004"
        }

        # Python execution from WSL (how Black Lotus Labs malware operated)
        try {
            $output = & wsl.exe python3 -c "print('wsl_python_test')" 2>&1 | Out-String
            if ($output -match "wsl_python_test") {
                Add-Result "WSL" "Python from WSL" "wsl.exe python3 -c" "UNDETECTED" "Python executed inside WSL. ELF-based malware uses this exact pattern." "High" "T1059.006"
            }
            else {
                Add-Result "WSL" "Python from WSL" "wsl.exe" "INFO" "Python3 not available in WSL distro"
            }
        }
        catch {
            Add-Result "WSL" "Python from WSL" "wsl.exe" "INFO" "Python not available or blocked"
        }
    }

    # --- TEST 5: wsl.exe invocation detection (works without distro) ---
    Write-Host ""
    Write-Host "  -- Test Group: WSL Binary Invocation Detection --" -ForegroundColor White

    # Test if EDR monitors wsl.exe being called at all
    try {
        $output = & wsl.exe --help 2>&1 | Out-String
        Add-Result "WSL" "wsl.exe Invocation" "wsl.exe --help" "UNDETECTED" "wsl.exe executed. Check Sysmon Event 1 / EDR process create." "Medium" "T1202"
    }
    catch {
        Add-Result "WSL" "wsl.exe Invocation" "wsl.exe" "BLOCKED" "wsl.exe execution blocked" "Medium" "T1202"
    }

    # Test bash.exe invocation (alternate WSL entry point)
    $bashExe = Join-Path $env:SystemRoot "System32\bash.exe"
    if (Test-Path $bashExe) {
        try {
            $output = & $bashExe --help 2>&1 | Out-String
            Add-Result "WSL" "bash.exe Invocation" "bash.exe --help" "UNDETECTED" "Legacy bash.exe entry point exists and executes." "Medium" "T1202"
        }
        catch {
            Add-Result "WSL" "bash.exe Invocation" "bash.exe" "INFO" "bash.exe exists but could not execute"
        }
    }

    # Check for wslhost.exe (the WSL2 VM host process)
    $wslhost = Get-Process -Name "wslhost" -ErrorAction SilentlyContinue
    if ($wslhost) {
        Add-Result "WSL" "wslhost.exe Running" "wslhost.exe" "INFO" "WSL2 VM host is active (PID: $($wslhost.Id)). All WSL activity runs through this process."
    }
}

# ============================================================================
# VM / HYPERVISOR EVASION TESTS
# ============================================================================
function Test-VMEvasion {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  [VM] Virtual Machine Evasion Tests" -ForegroundColor Cyan
    Write-Host "  T1564.006 Run Virtual Instance (Ragnar Locker / Maze / Akira)" -ForegroundColor DarkCyan
    Write-Host "  ================================================================" -ForegroundColor Cyan

    # --- TEST 1: VirtualBox detection artifacts ---
    Write-Host ""
    Write-Host "  -- Test Group: VirtualBox Artifacts (Ragnar Locker TTP) --" -ForegroundColor White

    # Check for VBoxDrv service (Ragnar Locker installs this)
    $vboxDrv = Get-Service -Name "VBoxDrv" -ErrorAction SilentlyContinue
    if ($vboxDrv) {
        Add-Result "VM" "VBoxDrv Service" "VBoxDrv" "INFO" "VirtualBox driver service exists (Status: $($vboxDrv.Status))" "Medium" "T1564.006"
    }
    else {
        Add-Result "VM" "VBoxDrv Service" "VBoxDrv" "INFO" "VBoxDrv not present (good - Ragnar Locker installs this)" "Low" "T1564.006"
    }

    # Check VBox COM registrations (Ragnar Locker registers VBoxC.dll)
    $vboxCOM = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)' -match "VirtualBox" } |
        Select-Object -First 1
    if ($vboxCOM) {
        Add-Result "VM" "VBox COM Registration" "Registry" "INFO" "VirtualBox COM objects registered in CLSID" "Low" "T1564.006"
    }

    # Simulate the Ragnar Locker detection pattern: VBoxHeadless.exe process
    $vboxHeadless = Get-Process -Name "VBoxHeadless" -ErrorAction SilentlyContinue
    if ($vboxHeadless) {
        Add-Result "VM" "VBoxHeadless Running" "VBoxHeadless.exe" "WARN" "VirtualBox headless VM is running! This is the exact Ragnar Locker evasion technique." "Critical" "T1564.006"
    }
    else {
        Add-Result "VM" "VBoxHeadless Running" "VBoxHeadless.exe" "INFO" "No headless VBox VMs running"
    }

    # Check for suspicious VirtualAppliances folder (Ragnar Locker staging)
    $ragnarPath = "C:\Program Files (x86)\VirtualAppliances"
    if (Test-Path $ragnarPath) {
        Add-Result "VM" "Ragnar Staging Folder" $ragnarPath "FAIL" "Ragnar Locker staging folder EXISTS! Investigate immediately." "Critical" "T1564.006"
    }
    else {
        Add-Result "VM" "Ragnar Staging Folder" $ragnarPath "PASS" "Ragnar Locker staging folder not present"
    }

    # --- TEST 2: Hyper-V VM creation detection ---
    Write-Host ""
    Write-Host "  -- Test Group: Hyper-V Abuse Detection --" -ForegroundColor White

    if ($IsAdmin) {
        # Check if we can enumerate Hyper-V VMs (detection should log this)
        try {
            $vms = Get-VM -ErrorAction Stop
            Add-Result "VM" "Hyper-V VM Enumeration" "Get-VM" "UNDETECTED" "Enumerated $($vms.Count) VMs. Check for PowerShell logging of Get-VM." "Medium" "T1564.006"
        }
        catch {
            if ($_.Exception.Message -match "not recognized|not found") {
                Add-Result "VM" "Hyper-V VM Enumeration" "Get-VM" "INFO" "Hyper-V cmdlets not available"
            }
            else {
                Add-Result "VM" "Hyper-V VM Enumeration" "Get-VM" "INFO" "Cannot enumerate VMs: $($_.Exception.Message)"
            }
        }
    }
    else {
        Add-Result "VM" "Hyper-V Tests" "Privileges" "SKIP" "Hyper-V tests require admin"
    }

    # --- TEST 3: Windows Sandbox detection ---
    Write-Host ""
    Write-Host "  -- Test Group: Windows Sandbox Abuse (CronTrap TTP) --" -ForegroundColor White

    # Check for WindowsSandbox.exe
    $sandboxExe = Join-Path $env:SystemRoot "System32\WindowsSandbox.exe"
    if (Test-Path $sandboxExe) {
        Add-Result "VM" "Windows Sandbox Binary" $sandboxExe "INFO" "Windows Sandbox is available (T1564.006 via .wsb files)" "Medium" "T1564.006"

        # Test if .wsb file execution would be detected
        # Create a benign .wsb config (does NOT launch sandbox)
        $wsbPath = Join-Path $OutputDir "test_sandbox_$RunID.wsb"
        $wsbContent = @()
        $wsbContent += '<Configuration>'
        $wsbContent += '  <VGpu>Disable</VGpu>'
        $wsbContent += '  <Networking>Disable</Networking>'
        $wsbContent += '  <LogonCommand>'
        $wsbContent += '    <Command>cmd.exe /c echo SANDBOX_TEST</Command>'
        $wsbContent += '  </LogonCommand>'
        $wsbContent += '</Configuration>'
        $wsbContent -join "`r`n" | Out-File -FilePath $wsbPath -Encoding UTF8

        Add-Result "VM" "WSB Config Created" $wsbPath "UNDETECTED" "Created .wsb file with LogonCommand. Check if EDR alerts on .wsb file creation." "High" "T1564.006"
        # Cleanup
        Remove-Item $wsbPath -Force -ErrorAction SilentlyContinue
    }
    else {
        Add-Result "VM" "Windows Sandbox" "Not installed" "INFO" "Windows Sandbox not available"
    }

    # --- TEST 4: QEMU detection (CronTrap/Securonix technique) ---
    Write-Host ""
    Write-Host "  -- Test Group: Lightweight Emulator Detection --" -ForegroundColor White

    # Check for QEMU binaries
    $qemuPaths = @(
        "C:\Program Files\qemu\qemu-system-x86_64.exe",
        "C:\qemu\qemu-system-x86_64.exe",
        (Join-Path $env:TEMP "qemu-system-x86_64.exe")
    )
    foreach ($qp in $qemuPaths) {
        if (Test-Path $qp) {
            Add-Result "VM" "QEMU Binary" $qp "WARN" "QEMU found! CronTrap/Securonix campaigns use QEMU for evasion." "High" "T1564.006"
        }
    }

    # Check for suspicious .vdi, .vmdk, .qcow2 files in temp/download locations
    $suspiciousPaths = @($env:TEMP, "$env:USERPROFILE\Downloads", "C:\ProgramData")
    $vmExtensions = @("*.vdi","*.vmdk","*.qcow2","*.vhd","*.vhdx","*.ova")
    foreach ($sp in $suspiciousPaths) {
        if (-not (Test-Path $sp)) { continue }
        foreach ($ext in $vmExtensions) {
            $found = Get-ChildItem -Path $sp -Filter $ext -ErrorAction SilentlyContinue | Select-Object -First 3
            foreach ($f in $found) {
                Add-Result "VM" "VM Disk Image Found" $f.FullName "WARN" "VM disk image in suspicious location ($($f.Length / 1MB) MB)" "High" "T1564.006"
            }
        }
    }

    # --- TEST 5: Service creation patterns matching Ragnar Locker ---
    Write-Host ""
    Write-Host "  -- Test Group: VM Service Installation Detection --" -ForegroundColor White

    if ($IsAdmin) {
        # Simulate Ragnar Locker's VBoxDrv service creation
        $testSvcName = "BYOVDTest_VBoxDrv"
        $fakePath = "C:\Windows\Temp\NONEXISTENT_vboxdrv.sys"
        try {
            $output = & sc.exe create $testSvcName type= kernel binPath= $fakePath 2>&1 | Out-String
            if ($output -match "SUCCESS") {
                Add-Result "VM" "VBoxDrv Service Create" $testSvcName "UNDETECTED" "Mimicked Ragnar Locker VBoxDrv install. Check Event 7045." "Critical" "T1564.006"
                & sc.exe delete $testSvcName 2>&1 | Out-Null
            }
            else {
                Add-Result "VM" "VBoxDrv Service Create" $testSvcName "BLOCKED" "Service creation blocked" "Critical" "T1564.006"
            }
        }
        catch {
            Add-Result "VM" "VBoxDrv Service Create" $testSvcName "BLOCKED" "Exception: $($_.Exception.Message)" "Critical" "T1564.006"
        }
    }
    else {
        Add-Result "VM" "Service Creation" "Privileges" "SKIP" "Requires admin for service creation tests"
    }

    # --- TEST 6: Shared folder mapping detection ---
    Write-Host ""
    Write-Host "  -- Test Group: VM Shared Folder Pattern Detection --" -ForegroundColor White

    # Check for VirtualBox shared folder net use patterns
    # Ragnar Locker maps host drives as \\VBOXSVR\sharename
    $netShares = net use 2>&1 | Out-String
    if ($netShares -match "VBOXSVR") {
        Add-Result "VM" "VBox Shared Folders" "net use" "FAIL" "VBOXSVR shares detected! Matches Ragnar Locker shared folder pattern." "Critical" "T1564.006"
    }
    else {
        Add-Result "VM" "VBox Shared Folders" "net use" "PASS" "No VBOXSVR shares (Ragnar Locker maps host drives this way)"
    }
}

# ============================================================================
# TELEMETRY VALIDATION
# ============================================================================
function Test-Telemetry {
    Write-Host ""
    Write-Host "  ================================================================" -ForegroundColor Cyan
    Write-Host "  [TELEMETRY] Detection Coverage for WSL and VM Activity" -ForegroundColor Cyan
    Write-Host "  ================================================================" -ForegroundColor Cyan

    # Sysmon Event 1 (Process Create) for wsl.exe / bash.exe
    try {
        $wslEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = 1
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 500 -ErrorAction Stop | Where-Object {
            $_.Message -match "wsl\.exe|wslhost\.exe|bash\.exe"
        }
        if ($wslEvents) {
            Add-Result "TELEMETRY" "Sysmon WSL Process Events" "Event 1" "PASS" "Found $($wslEvents.Count) WSL-related process events in last 7 days"
        }
        else {
            Add-Result "TELEMETRY" "Sysmon WSL Process Events" "Event 1" "WARN" "No WSL process events found in Sysmon (may not be configured)"
        }
    }
    catch {
        Add-Result "TELEMETRY" "Sysmon WSL Process Events" "Sysmon" "FAIL" "Cannot query Sysmon - likely not installed" "High"
    }

    # Event 4688 (Process Create with command line)
    try {
        $cmdlineEvents = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            Id = 4688
            StartTime = (Get-Date).AddMinutes(-30)
        } -MaxEvents 100 -ErrorAction Stop | Where-Object {
            $_.Message -match "wsl\.exe"
        }
        if ($cmdlineEvents) {
            Add-Result "TELEMETRY" "Security 4688 (WSL)" "Security Log" "PASS" "WSL process creation logged in Security event log"
        }
        else {
            Add-Result "TELEMETRY" "Security 4688 (WSL)" "Security Log" "WARN" "No recent 4688 events for wsl.exe. Enable command line logging."
        }
    }
    catch {
        Add-Result "TELEMETRY" "Security 4688" "Security Log" "WARN" "Cannot query Security log (may need admin)"
    }

    # Check for PowerShell ScriptBlock logging (would catch Get-VM, sandbox creation)
    try {
        $psLog = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction Stop
        if ($psLog.EnableScriptBlockLogging -eq 1) {
            Add-Result "TELEMETRY" "PS ScriptBlock Logging" "Registry" "PASS" "PowerShell ScriptBlock logging enabled"
        }
        else {
            Add-Result "TELEMETRY" "PS ScriptBlock Logging" "Registry" "WARN" "ScriptBlock logging not enabled"
        }
    }
    catch {
        Add-Result "TELEMETRY" "PS ScriptBlock Logging" "Registry" "WARN" "Cannot determine ScriptBlock logging status"
    }
}

# ============================================================================
# EXECUTE
# ============================================================================
switch ($Mode) {
    "audit" {
        Test-Posture
        Test-Telemetry
    }
    "wsl" {
        Test-Posture
        Test-WSLEvasion
        Test-Telemetry
    }
    "vm" {
        Test-Posture
        Test-VMEvasion
        Test-Telemetry
    }
    "full" {
        Test-Posture
        if (-not $SkipWSL) { Test-WSLEvasion }
        if (-not $SkipVM) { Test-VMEvasion }
        Test-Telemetry
    }
}

# ============================================================================
# EXPORT
# ============================================================================
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "  EXPORTING RESULTS" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan

$csvPath = Join-Path $OutputDir "hypervisor_evasion_${Timestamp}.csv"
$jsonPath = Join-Path $OutputDir "hypervisor_evasion_${Timestamp}.json"
$summaryPath = Join-Path $OutputDir "hypervisor_evasion_summary_${Timestamp}.txt"

$Script:Results | Select-Object Timestamp,RunID,Layer,TestName,Target,Result,Severity,MitreID,Detail,Hostname |
    Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "  [+] CSV:  $csvPath" -ForegroundColor Green

$Script:Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host "  [+] JSON: $jsonPath" -ForegroundColor Green

$passN = ($Script:Results | Where-Object { $_.Result -in @("PASS","BLOCKED","DETECTED") }).Count
$failN = ($Script:Results | Where-Object { $_.Result -in @("FAIL","UNDETECTED") }).Count
$warnN = ($Script:Results | Where-Object { $_.Result -eq "WARN" }).Count

$sl = @()
$sl += "============================================================"
$sl += "HYPERVISOR-LAYER EVASION DETECTION SUMMARY"
$sl += "============================================================"
$sl += "Run: $RunID | Host: $env:COMPUTERNAME | Mode: $Mode"
$sl += "Tests: $($Script:Results.Count) | Pass: $passN | Fail: $failN | Warn: $warnN"
$sl += ""
$sl += "--- CRITICAL GAPS ---"
$gaps = $Script:Results | Where-Object { $_.Result -in @("FAIL","UNDETECTED") -and $_.Severity -in @("Critical","High") }
foreach ($g in $gaps) {
    $sl += "  [!] $($g.TestName): $($g.Detail)"
}
if ($gaps.Count -eq 0) { $sl += "  None found." }
$sl += ""
$sl += "--- WSL REMEDIATIONS ---"
$sl += "  1. Deploy Sysmon with wsl.exe/wslhost.exe/bash.exe process monitoring"
$sl += "  2. Enable Elastic/Sigma rule: Execution via Windows Subsystem for Linux"
$sl += "  3. Monitor /mnt/c cross-boundary file writes from WSL processes"
$sl += "  4. Block WSL on endpoints where it is not business-required"
$sl += "  5. Log wsl.exe parent-child chains in EDR (child of wsl = suspicious)"
$sl += ""
$sl += "--- VM EVASION REMEDIATIONS ---"
$sl += "  1. Alert on VirtualBox/QEMU installation or driver loading on servers"
$sl += "  2. Block VBoxDrv.sys service creation (Event 7045)"
$sl += "  3. Monitor for .vdi/.vmdk/.qcow2 files in temp/download directories"
$sl += "  4. Detect VBoxHeadless.exe process execution (Ragnar Locker indicator)"
$sl += "  5. Alert on VBOXSVR shared folder mounts (net use pattern)"
$sl += "  6. Monitor .wsb file creation (Windows Sandbox abuse)"
$sl += ""
$sl += "--- REFERENCES ---"
$sl += "  MITRE T1564.006: https://attack.mitre.org/techniques/T1564/006/"
$sl += "  MITRE T1202:     https://attack.mitre.org/techniques/T1202/"
$sl += "  Sophos Ragnar:   sophos.com/en-us/blog/ragnar-locker-ransomware"
$sl += "  SpecterOps WSL2: Offensive WSL2 research (2025-2026)"
$sl += "  Elastic Rule:    detection.fyi WSL child process detection"
$sl += "============================================================"

$summaryText = $sl -join "`r`n"
$summaryText | Out-File -FilePath $summaryPath -Encoding UTF8
Write-Host "  [+] Summary: $summaryPath" -ForegroundColor Green

# --- HTML REPORT ---
if ($HTMLReport) {
    $htmlPath = Join-Path $OutputDir "hypervisor_evasion_report_${Timestamp}.html"
    $totalN = $Script:Results.Count
    if (($passN + $failN) -eq 0) { $scorePct = 0 } else { $scorePct = [math]::Round(($passN / ($passN + $failN)) * 100, 1) }
    if ($scorePct -ge 80) { $scoreHex = "#00ff88" } elseif ($scorePct -ge 50) { $scoreHex = "#ff8c42" } else { $scoreHex = "#ff3b3b" }

    $w = New-Object System.IO.StreamWriter($htmlPath, $false, [System.Text.Encoding]::UTF8)
    $w.WriteLine('<!DOCTYPE html><html><head><meta charset="UTF-8">')
    $w.WriteLine('<title>Hypervisor Evasion Detection Report</title>')
    $w.WriteLine('<style>')
    $w.WriteLine('body{background:#0d1117;color:#c9d1d9;font-family:Consolas,monospace;margin:0;padding:20px}')
    $w.WriteLine('h1{color:#bc4aff;border-bottom:2px solid #bc4aff;padding-bottom:10px}')
    $w.WriteLine('h2{color:#58a6ff;margin-top:30px}')
    $w.WriteLine('.score{display:inline-block;background:#161b22;border:2px solid ' + $scoreHex + ';border-radius:10px;padding:20px 40px;margin:20px 0;text-align:center}')
    $w.WriteLine('.score-n{font-size:48px;font-weight:bold;color:' + $scoreHex + '}')
    $w.WriteLine('.score-l{font-size:14px;color:#6b8299}')
    $w.WriteLine('.stats{display:flex;gap:20px;margin:20px 0}')
    $w.WriteLine('.stat{background:#161b22;padding:15px 25px;border-radius:8px;text-align:center}')
    $w.WriteLine('.sn{font-size:28px;font-weight:bold}.sl{font-size:12px;color:#6b8299}')
    $w.WriteLine('table{width:100%;border-collapse:collapse;margin-top:10px}')
    $w.WriteLine('th{background:#58a6ff;color:#0d1117;padding:10px;text-align:left;font-size:13px}')
    $w.WriteLine('td{padding:8px 10px;border-bottom:1px solid #21262d;font-size:13px}')
    $w.WriteLine('.p{background:#00ff88;color:#000;padding:2px 8px;border-radius:3px;font-weight:bold}')
    $w.WriteLine('.f{background:#ff3b3b;color:#fff;padding:2px 8px;border-radius:3px;font-weight:bold}')
    $w.WriteLine('.wr{background:#ff8c42;color:#000;padding:2px 8px;border-radius:3px;font-weight:bold}')
    $w.WriteLine('.i{background:#58a6ff;color:#000;padding:2px 8px;border-radius:3px;font-weight:bold}')
    $w.WriteLine('.footer{margin-top:30px;padding-top:15px;border-top:1px solid #21262d;color:#484f58;font-size:11px}')
    $w.WriteLine('a{color:#58a6ff}')
    $w.WriteLine('</style></head><body>')
    $w.WriteLine('<h1>Hypervisor-Layer Evasion Detection Report</h1>')
    $w.WriteLine('<p style="color:#484f58;font-size:12px">Run: ' + $RunID + ' | Host: ' + $env:COMPUTERNAME + ' | Mode: ' + $Mode + ' | ' + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + '</p>')
    $w.WriteLine('<div class="score"><div class="score-n">' + $scorePct + '%</div><div class="score-l">Detection Score</div></div>')
    $w.WriteLine('<div class="stats">')
    $w.WriteLine('<div class="stat"><div class="sn" style="color:#00ff88">' + $passN + '</div><div class="sl">PASSED</div></div>')
    $w.WriteLine('<div class="stat"><div class="sn" style="color:#ff3b3b">' + $failN + '</div><div class="sl">GAPS</div></div>')
    $w.WriteLine('<div class="stat"><div class="sn" style="color:#ff8c42">' + $warnN + '</div><div class="sl">WARNINGS</div></div>')
    $w.WriteLine('<div class="stat"><div class="sn" style="color:#58a6ff">' + $totalN + '</div><div class="sl">TOTAL</div></div>')
    $w.WriteLine('</div>')

    $w.WriteLine('<h2>Test Results</h2>')
    $w.WriteLine('<table><tr><th>Layer</th><th>Test</th><th>Target</th><th>Result</th><th>MITRE</th><th>Detail</th></tr>')
    foreach ($r in $Script:Results) {
        switch ($r.Result) {
            "PASS"       { $badge = '<span class="p">PASS</span>';       $bg = "#0d2818" }
            "BLOCKED"    { $badge = '<span class="p">BLOCKED</span>';    $bg = "#0d2818" }
            "FAIL"       { $badge = '<span class="f">FAIL</span>';       $bg = "#280d0d" }
            "UNDETECTED" { $badge = '<span class="f">UNDETECTED</span>'; $bg = "#280d0d" }
            "WARN"       { $badge = '<span class="wr">WARN</span>';      $bg = "#28200d" }
            default      { $badge = '<span class="i">' + $r.Result + '</span>'; $bg = "#0d1722" }
        }
        $w.Write('<tr style="background:' + $bg + '">')
        $w.Write('<td>' + $r.Layer + '</td>')
        $w.Write('<td>' + $r.TestName + '</td>')
        $w.Write('<td>' + $r.Target + '</td>')
        $w.Write('<td>' + $badge + '</td>')
        $w.Write('<td>' + $r.MitreID + '</td>')
        $w.Write('<td style="font-size:12px">' + $r.Detail + '</td>')
        $w.WriteLine('</tr>')
    }
    $w.WriteLine('</table>')

    $w.WriteLine('<div class="footer">')
    $w.WriteLine('<p>Hypervisor-Layer Evasion Detection Framework v1.0 | MITRE T1202, T1564.006, T1059.004</p>')
    $w.WriteLine('<p>No malicious payloads were executed. All tests use benign commands.</p>')
    $w.WriteLine('</div></body></html>')
    $w.Close()
    Write-Host "  [+] HTML:  $htmlPath" -ForegroundColor Green
}

Write-Host ""
Write-Host $summaryText
Write-Host ""
Write-Host "  [*] Next: Check SIEM/EDR for alerts during this test window." -ForegroundColor Yellow
Write-Host "  [*] Key question: Did your EDR see ANYTHING beyond 'wsl.exe started'?" -ForegroundColor Yellow
Write-Host ""
