# WSL & Hypervisor-Layer Evasion Detection Framework

Test your EDR/SIEM visibility into two of the largest detection blind spots in modern enterprise environments: **Windows Subsystem for Linux** command execution and **Virtual Machine-based payload hiding**.

> **MITRE ATT&CK:** T1202, T1564.006, T1059.004  
> **Threat Actors:** Ragnar Locker, Maze, Conti, Akira, MirrorFace, CronTrap, Black Lotus Labs WSL malware  
> **Research:** SpecterOps WSL2 offensive research, Sophos Ragnar Locker report, Securonix CronTrap analysis

---

## The Blind Spot

EDR agents instrument Windows processes, file system calls, and registry activity. Two environments let attackers operate completely outside that visibility:

**WSL2** runs as a lightweight Hyper-V virtual machine with its own Linux kernel. Commands executed inside WSL generate minimal Windows telemetry — your EDR typically sees `wsl.exe` start and nothing else. SpecterOps demonstrated that beacon object files can reach into any WSL2 distro, run arbitrary commands, and read files without raising alerts. Real-world WSL malware (Black Lotus Labs, 2021-2025) achieves near-zero detection rates on VirusTotal because most AV engines don't scan ELF binaries.

**VM-based evasion** (T1564.006) deploys a full virtual machine on the endpoint and runs the payload inside it. Ragnar Locker pioneered this in 2020 by deploying VirtualBox with a Windows XP guest, mounting host drives as shared folders, and encrypting them from inside the VM where no EDR agent exists. Maze, Conti, and Akira followed. The CronTrap campaign (2024) used QEMU, and MirrorFace (2025) abused Windows Sandbox `.wsb` files.

---

## What This Tests

| Layer | Tests | Detection Source |
|---|---|---|
| **Posture** | WSL install, distros, version, Hyper-V, VirtualBox, VMware, QEMU, Sysmon, EDR, Sandbox | Preventive controls |
| **WSL Execution** | Command execution, network recon, cross-boundary file access/write, bash -c patterns, Python from WSL | Sysmon Event 1, EDR process telemetry |
| **WSL Network** | DNS queries and HTTP requests originating from inside WSL guest | NDR, proxy, firewall |
| **VM Artifacts** | VBoxDrv service, COM registrations, VBoxHeadless process, staging folders, VBOXSVR shares | EDR, Event 7045 |
| **VM Emulators** | QEMU binaries, VM disk images in temp paths, Windows Sandbox .wsb files | File monitoring |
| **VM Service Install** | Simulated VBoxDrv kernel service creation (Ragnar Locker pattern) | Event 7045, EDR |
| **Telemetry** | Sysmon WSL process events, Security 4688 command line logging, PowerShell ScriptBlock logging | SIEM pipeline |

---

## Quick Start

```powershell
# Posture check only (safe for production, no execution)
powershell -ExecutionPolicy Bypass -File .\Test-HypervisorEvasion.ps1 -Mode audit

# Full test suite with HTML report
powershell -ExecutionPolicy Bypass -File .\Test-HypervisorEvasion.ps1 -Mode full -HTMLReport

# WSL tests only
powershell -ExecutionPolicy Bypass -File .\Test-HypervisorEvasion.ps1 -Mode wsl

# VM tests only
powershell -ExecutionPolicy Bypass -File .\Test-HypervisorEvasion.ps1 -Mode vm

# Full test, skip WSL (no WSL installed)
powershell -ExecutionPolicy Bypass -File .\Test-HypervisorEvasion.ps1 -Mode full -SkipWSL -HTMLReport
```

---

## Test Modes

### `audit` — Posture check only
Checks what is installed (WSL, Hyper-V, VirtualBox, QEMU, Sandbox), lists WSL distros, verifies Sysmon and EDR presence, and validates telemetry coverage. Zero command execution. Production-safe.

### `wsl` — WSL evasion tests
Executes benign commands through WSL and validates EDR visibility at each step:

- **Basic execution:** `wsl.exe hostname`, `wsl.exe whoami` — does your EDR log what ran inside WSL, or just that `wsl.exe` started?
- **Network from WSL:** DNS lookups and HTTP requests from the Linux guest — does your proxy/NDR see traffic originating from WSL?
- **Cross-boundary file access:** WSL reading Windows user directories via `/mnt/c` — does your EDR detect this?
- **Cross-boundary file write:** WSL writing a canary file to Windows temp — the exact mechanism WSL malware uses to stage payloads
- **Suspicious patterns:** `bash -c` with pipes, Python execution from WSL — matches documented WSL malware TTPs
- **Binary invocation:** `wsl.exe`, `bash.exe`, `wslhost.exe` detection

### `vm` — VM/hypervisor evasion tests
Tests detection of VM-based attack patterns without deploying any VMs:

- **VirtualBox artifacts:** VBoxDrv service, COM registrations, VBoxHeadless process (Ragnar Locker indicators)
- **Ragnar Locker staging:** Checks for the `C:\Program Files (x86)\VirtualAppliances` folder
- **VBOXSVR shares:** Detects the shared folder mounts Ragnar Locker uses to encrypt host drives from inside the VM
- **Lightweight emulators:** Scans for QEMU binaries in suspicious locations (CronTrap technique)
- **VM disk images:** Looks for `.vdi`, `.vmdk`, `.qcow2`, `.vhd` files in temp/download directories
- **Windows Sandbox:** Creates a benign `.wsb` config file to test if EDR alerts on sandbox abuse (CronTrap/MirrorFace)
- **Service creation:** Simulates Ragnar Locker's VBoxDrv kernel service installation via `sc.exe` (requires admin, immediately deleted)
- **Hyper-V enumeration:** Runs `Get-VM` to test PowerShell logging coverage

### `full` — All of the above

---

## Output

| File | Description |
|---|---|
| `hypervisor_evasion_<ts>.csv` | Full results, SIEM-importable |
| `hypervisor_evasion_<ts>.json` | Full results, programmatic |
| `hypervisor_evasion_summary_<ts>.txt` | Gap analysis with remediations |
| `hypervisor_evasion_report_<ts>.html` | Visual HTML report (with `-HTMLReport`) |

### Result Values

| Result | Meaning |
|---|---|
| `PASS` / `BLOCKED` | Your controls detected or would block this |
| `FAIL` / `UNDETECTED` | Gap — activity was not visible to your stack |
| `WARN` | Partial coverage or concerning finding |
| `INFO` | Informational (posture data) |
| `SKIP` | Test skipped (missing prereqs or privileges) |

---

## Detection Gap Workflow

1. Run `.\Test-HypervisorEvasion.ps1 -Mode full -HTMLReport`
2. Open the HTML report
3. For every `UNDETECTED` result, check your SIEM for the test time window
4. The key question: **did your EDR see anything beyond "wsl.exe started"?**
5. If WSL commands, network activity, or file writes went unlogged — you have a blind spot
6. Deploy remediations and re-test

---

## Remediation Priority

### WSL Blind Spots

| Priority | Action |
|---|---|
| **P0** | Block WSL on endpoints where it is not business-required (DISM, Group Policy, or Intune) |
| **P1** | Deploy Sysmon with wsl.exe/wslhost.exe/bash.exe parent-child process monitoring |
| **P1** | Enable Elastic detection rule: "Execution via Windows Subsystem for Linux" |
| **P2** | Monitor cross-boundary file writes from WSL processes to Windows filesystem |
| **P2** | Alert on wsl.exe child processes that are not in a known-safe exclusion list |
| **P3** | Audit WSL distro installations via registry (HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss) |

### VM Evasion Blind Spots

| Priority | Action |
|---|---|
| **P0** | Alert on VirtualBox/QEMU silent installation or driver loading on servers |
| **P0** | Block VBoxDrv.sys kernel service creation (Event 7045 + service name match) |
| **P1** | Detect VBoxHeadless.exe process execution (immediate Ragnar Locker indicator) |
| **P1** | Monitor for VM disk images (.vdi, .vmdk, .qcow2) in temp/download directories |
| **P2** | Alert on VBOXSVR shared folder mounts via net use |
| **P2** | Monitor .wsb file creation (Windows Sandbox abuse vector) |
| **P3** | Application control: block hypervisor software on endpoints that don't need it |

---

## Safety

- All WSL commands are benign (hostname, whoami, ls, curl to example.com, echo to a temp file)
- The cross-boundary canary file is immediately deleted after the test
- No VMs are created, started, or deployed
- The `.wsb` sandbox config file is created and immediately deleted (Sandbox is never launched)
- Service creation tests use non-existent file paths and are immediately cleaned up
- `audit` mode makes zero modifications to the system

---

## Requirements

- Windows 10/11 or Server 2019+ (PowerShell 5.1+)
- WSL installed with at least one distro for full WSL tests (gracefully skips if absent)
- Administrator for service creation and Hyper-V tests (non-admin skips those tests)
- Internet for WSL network tests (curl/nslookup from inside WSL)

---

## Threat Intelligence Context

### WSL Abuse Timeline
- **2017:** Check Point demonstrates Bashware proof-of-concept
- **2021:** Black Lotus Labs discovers first real-world WSL malware (ELF loaders with near-zero AV detection)
- **2023-2024:** WSL malware variants continue evolving with improved Windows API integration
- **2025-2026:** SpecterOps demonstrates WSL2 offensive tradecraft — beacon into any distro, run commands, read files, zero alerts. Cryxos JavaScript recon malware scans WSL mounts for browser data.

### VM Evasion Timeline
- **2020:** Ragnar Locker deploys VirtualBox XP VM to encrypt host drives (Sophos report)
- **2020:** Maze ransomware adopts same technique with Windows 7 VM
- **2021:** Conti affiliates deploy VirtualBox VMs on compromised servers
- **2023:** Akira ransomware weaponizes VMs to bypass EDR (CyberCX report)
- **2024:** CronTrap campaign uses QEMU lightweight emulator (Securonix)
- **2025:** MirrorFace/Operation AkaiRyu abuses Windows Sandbox .wsb files (ESET)

---

## References

- [MITRE T1564.006 - Run Virtual Instance](https://attack.mitre.org/techniques/T1564/006/)
- [MITRE T1202 - Indirect Command Execution](https://attack.mitre.org/techniques/T1202/)
- [MITRE T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [Sophos - Ragnar Locker deploys VM to dodge security](https://www.sophos.com/en-us/blog/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security)
- [Elastic - Execution via Windows Subsystem for Linux](https://detection.fyi/elastic/detection-rules/windows/defense_evasion_wsl_child_process/)
- [Black Lotus Labs - WSL malware discovery](https://www.bleepingcomputer.com/news/security/new-malware-uses-windows-subsystem-for-linux-for-stealthy-attacks/)
- [SpecterOps - WSL2 offensive research (2025-2026)](https://www.cryptika.com/attackers-are-using-wsl2-as-a-stealthy-hideout-inside-windows-systems/)
- [Securonix - CronTrap QEMU-based evasion (2024)](https://attack.mitre.org/techniques/T1564/006/)
- [Atomic Red Team T1564.006 tests](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.006/T1564.006.md)
