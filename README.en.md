# Bulwark (磐垒主动防御)

English | [简体中文](README.md)

A Host-based Intrusion Prevention System (HIPS) for Windows, comparable in category to antivirus / EDR products.

**Core idea:** monitor sensitive system behavior → a rule engine decides → prompt the user for a verdict when needed (Allow / Block / Remember).

Bulwark is built as three cooperating layers — a **kernel-mode driver (R0)** for true pre-action interception, a **user-mode Windows service (R3)** that hosts the decision logic, and an **Avalonia desktop UI** for status, live logs, prompts and rule management. The driver and service talk over a Filter Manager communication port; the service and UI talk over a named pipe. A single `RuleEngine` is the decision center across all event sources, enriched by threat heuristics, LOLBin abuse detection, MITRE ATT&CK annotation, credential-access detection, and multi-engine hash reputation.

> **Status:** the full `Kernel driver (R0) ↔ user-mode service (R3) ↔ UI` pipeline is working, and all six protection milestones (M1–M6) are complete.
> - **M1+**: service↔UI channel, real WMI process observation, Authenticode signature verification, SHA-256, rule management, service installation.
> - **M2–M6 (kernel driver)**: process interception, file protection, registry protection, self-protection, network egress blocking. The driver builds into `Bulwark.sys` — see `Bulwark.Driver/README.md`.

## Event sources (switchable)

Configured via `EventSource` in `appsettings.json`:

- **Driver** — kernel-mode interception (true pre-action blocking; covers process / file / registry / self-protection / network milestones M2–M6).
- **Wmi** — user-mode observation (cannot block before the action; blocking is compensated by terminating the actor).
- **Simulated** — demo mode, no real-system monitoring.

## Screenshots

| | |
|:---:|:---:|
| ![](docs/screenshots/screenshot-01.png) | ![](docs/screenshots/screenshot-02.png) |
| ![](docs/screenshots/screenshot-03.png) | ![](docs/screenshots/screenshot-04.png) |
| ![](docs/screenshots/screenshot-05.png) | ![](docs/screenshots/screenshot-06.png) |
| ![](docs/screenshots/screenshot-07.png) | ![](docs/screenshots/screenshot-08.png) |
| ![](docs/screenshots/screenshot-09.png) | ![](docs/screenshots/screenshot-10.png) |

## Solution structure

```
Bulwark.sln
├─ Bulwark.Core      Shared layer: event models, verdicts, rules, rule engine, IPC protocol
│   ├─ Models/          SecurityEvent / Verdict / DefenseRule / Evidence (evidence chain)
│   ├─ Engine/          RuleEngine (decision center) + ThreatDetector / LolbinAnalyzer
│   │                   / KillChainAnalyzer / AttackCatalog + AttackAnnotator (ATT&CK), etc.
│   └─ Ipc/             IpcMessage (named-pipe message protocol)
├─ Bulwark.Driver    Kernel driver (R0): process-create interception + Filter Manager port
├─ Bulwark.Service   User-mode service (R3): decision host + named-pipe server
│   ├─ Monitoring/      IEventSource implementations: Driver / WMI / Simulated
│   ├─ Reputation/      Hash reputation (VirusTotal / ThreatBook / MetaDefender / OTX)
│   ├─ Storage/         RuleStore (rules persisted as JSON)
│   └─ Worker.cs        Main defense loop
└─ Bulwark.UI.Scifi  Avalonia UI: status, live log, behavior prompts, rule management
```

## Requirements

- Windows 10/11 (x64)
- .NET 8.0 SDK — https://dotnet.microsoft.com/download/dotnet/8.0

## Configuration (the `Bulwark` section of `appsettings.json`)

```jsonc
{
  "Bulwark": {
    "EventSource": "Wmi",        // Driver = kernel interception / Wmi = observation / Simulated = demo
    "TrustSignedActors": true,    // auto-allow trusted-signed actors
    "DefaultAction": "Allow",     // fallback when no rule matches / on timeout: Allow or Block
    "PromptTimeoutSeconds": 30
  }
}
```

### API keys (do NOT commit real keys)

Threat-intelligence and AI keys are **intentionally left blank** in this repository. Provide them locally via environment variables (preferred) or by filling the blank fields in `appsettings.json` on your own machine:

| Capability        | Environment variable        |
|-------------------|-----------------------------|
| AI model (mimo)   | `BULWARK_AI_APIKEY`         |
| VirusTotal        | `BULWARK_VT_APIKEY`         |
| ThreatBook        | `BULWARK_THREATBOOK_APIKEY` |
| MetaDefender      | `BULWARK_MDC_APIKEY`        |
| AlienVault OTX    | `BULWARK_OTX_APIKEY`        |

Environment variables take precedence over values in `appsettings.json`. The AI key can also be entered on the UI Settings page.

## Run (development)

Real process monitoring (WMI) needs **administrator privileges**. Use two terminals — start the service first, then the UI, **both as administrator**:

```powershell
# Terminal 1: run the service (console mode)
dotnet run --project Bulwark.Service

# Terminal 2: run the UI (manifest already requests requireAdministrator)
dotnet run --project Bulwark.UI.Scifi
```

A green status dot at the top of the UI means it is connected to the service. For real process launches:
- trusted-signed processes → auto-allowed and shown in the log;
- unsigned processes → a prompt asks you to Allow / Block; tick "Remember my choice" to create a persistent rule.

Rules are persisted at `%ProgramData%\Bulwark\rules.json`.

> To try the demo without monitoring real processes, set `EventSource` to `"Simulated"` in `appsettings.json`.

## Install as a Windows service (administrator)

```powershell
# Run PowerShell as administrator
.\scripts\install-service.ps1     # publish and register an auto-start service
.\scripts\uninstall-service.ps1   # uninstall
```

## Decision priority (RuleEngine)

1. A matched rule → Allow/Block directly.
2. Threat score / hard malicious indicators.
3. A strongly-trusted signature → Allow.
4. Otherwise → prompt the user (timeout falls back to the default policy).

## Highlights

- **Evidence-chain timeline (explainability):** every event carries a structured `EvidenceChain` (source analyzer / category / risk-score contribution / description), rendered as a colored timeline in the prompt and used as input to the AI analysis.
- **LOLBins abuse analysis:** detects abuse of Microsoft-signed system binaries (regsvr32, rundll32, mshta, certutil, msbuild, wmic, comsvcs, etc.); high-confidence abuse acts as a hard indicator and bypasses the signature-trust allowance.
- **MITRE ATT&CK annotation:** maps analyzer hits to ATT&CK technique IDs (e.g. T1218.010, T1003.001, T1490).
- **Credential access / LSASS protection:** detects LSASS dumping/injection, SAM/SECURITY hive export, NTDS.dit extraction, browser/DPAPI credential theft.
- **Persistence audit view:** read-only enumeration of seven autostart persistence points (Run/RunOnce, Startup folder, services, scheduled tasks, IFEO, Winlogon, AppInit_DLLs). Never modifies autostart entries.
- **ECS structured alert export:** formats handled events into Elastic Common Schema JSON-lines for SIEM ingestion (off by default).
- **Tiered reputation cache + offline fallback:** malicious verdicts cached permanently, clean verdicts per-day TTL; reputation only adds/subtracts score and never acts on its own.

## Kernel driver (R0): true pre-action blocking

`Bulwark.Driver` is the kernel-mode component that lets Bulwark stop dangerous actions **before** they happen, rather than only observing them. It uses **only Microsoft-documented APIs** — no SSDT hooking — so it stays PatchGuard-friendly. It registers a **Minifilter** that both hooks I/O callbacks and borrows the Filter Manager **communication port** (`FltCreateCommunicationPort` / `FltSendMessage`) to talk to the user-mode service.

The five protected dimensions:

| Dimension | Kernel mechanism | What it intercepts |
|-----------|------------------|--------------------|
| **Process (M2)** | `PsSetCreateProcessNotifyRoutineEx` | Every process creation, before it runs |
| **File (M3)** | Minifilter pre-op `IRP_MJ_CREATE` (delete-on-close) + `IRP_MJ_SET_INFORMATION` (rename/disposition) | Deletion/rename of protected files |
| **Registry (M4)** | `CmRegisterCallbackEx` (`RegNtPreSetValueKey` / `RegNtPreDeleteValueKey` / `RegNtPreDeleteKey`) | Writes/deletes to protected keys (e.g. autostart) |
| **Self-protection (M5)** | `ObRegisterCallbacks` | Strips dangerous rights (terminate / write-memory / remote-thread / suspend) when other processes try to open Bulwark's protected processes |
| **Network (M6)** | WFP callout + filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` | Outbound connections matching a blocklist |

**Decision flow:** process / file / registry events are sent to user mode and **synchronously wait for a verdict** (up to ~5 s, configurable). Self-protection and network blocking run at high IRQL, so they **do not block** — they act immediately and log asynchronously. On a `Block` verdict the driver sets `CreationStatus = STATUS_ACCESS_DENIED` (process), returns `STATUS_ACCESS_DENIED` (file/registry), or applies `FWP_ACTION_BLOCK` (network). Protected paths, registry keys, process PIDs and the network blocklist are pushed down from user mode via `FilterSendMessage`.

```
New process starts
   │  (kernel callback, PASSIVE_LEVEL)
   ▼
ProcessMonitor builds event ──FltSendMessage──▶ user-mode service (DriverEventSource)
   ▲                                                  │
   │                                          RuleEngine evaluates / UI prompt
   │                                                  ▼
   └──────FilterReplyMessage (verdict) ◀────────── Allow / Block
   │
   ▼
Block → CreationStatus = STATUS_ACCESS_DENIED (process denied)
Allow → process starts normally
```

**Driver source files** (`Bulwark.Driver/`):
- `Driver.c` — DriverEntry / unload / Minifilter registration (I/O callbacks + instance attach) + network device object
- `ProcessMonitor.c` — process-create callback and interception
- `FileMonitor.c` — file delete/rename interception + protected-item matching
- `RegistryMonitor.c` — registry set/delete value/key interception + protected-key management
- `SelfProtect.c` — `ObRegisterCallbacks` handle callbacks that strip dangerous rights
- `NetMonitor.c` — WFP callout/filter + blocklist management
- `ImageMonitor.c` / `ThreadMonitor.c` — image-load and remote-thread monitoring
- `Comms.c` — communication port, `FltSendMessage` verdict wait / async reporting, config messages
- `Protocol.h` — kernel↔user-mode message layout (mirrored by `DriverStructs.cs` on the C# side)

### Build the driver (needs WDK + VS2022 Build Tools)

```powershell
.\scripts\build-driver.ps1 -Configuration Debug   # produces build\driver\Debug\Bulwark.sys
```

### ⚠ Load only inside a snapshotted test VM

A faulty kernel callback can **bluescreen (BSOD)** the machine. Always test in a VM with a snapshot:

```powershell
# 1) enable test signing, then reboot
bcdedit /set testsigning on

# 2) create test cert, sign, install and start the driver
.\scripts\deploy-driver-vm.ps1 -Configuration Debug

# 3) set EventSource to "Driver" in appsettings.json, run service + UI as administrator
# 4) watch [Bulwark] kernel logs in DebugView (enable "Capture Kernel")
```

The driver is linked with `/INTEGRITYCHECK` (required for `ObRegisterCallbacks`) and must carry a valid signature; a production release needs an EV certificate + Microsoft WHQL/attestation signing.

## Protection milestones

| Milestone | Scope | Key kernel mechanism (all Microsoft-documented APIs) | Status |
|-----------|-------|------------------------------------------------------|--------|
| M2 | Process | `PsSetCreateProcessNotifyRoutineEx` | ✅ Done |
| M3 | File | Minifilter I/O callbacks (`IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION`) | ✅ Done |
| M4 | Registry | `CmRegisterCallbackEx` | ✅ Done |
| M5 | Self-protection | `ObRegisterCallbacks` | ✅ Done |
| M6 | Network | WFP (`ALE_AUTH_CONNECT_V4` blocklist) | ✅ Done |

> The driver requires a digital signature. During development, enable test signing (`bcdedit /set testsigning on`) and use a **snapshotted test VM** — a faulty callback can cause a BSOD. Production release needs an EV certificate and WHQL certification.

## Design principles

- **Only act on genuinely dangerous behavior.** Soft signals alone (unsigned, suspicious path, first-seen, recently-issued cert) never trigger a block or prompt; they only raise score and require corroboration from a hard indicator.
- **Minimize false positives / user nagging.** Healthy, trusted-signed actors are allowed without prompting.
- **Self-protection must stay user-controllable.** This is a legitimate security tool and always keeps a normal, user-driven uninstall path.
