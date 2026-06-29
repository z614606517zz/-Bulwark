# Bulwark (磐垒主动防御)

English | [简体中文](README.md)

A Host-based Intrusion Prevention System (HIPS) for Windows, comparable in category to antivirus / EDR products.

**Core idea:** monitor sensitive system behavior → a rule engine decides → prompt the user for a verdict when needed (Allow / Block / Remember).

> **Status:** the full `Kernel driver (R0) ↔ user-mode service (R3) ↔ UI` pipeline is working, and all six protection milestones (M1–M6) are complete.
> - **M1+**: service↔UI channel, real WMI process observation, Authenticode signature verification, SHA-256, rule management, service installation.
> - **M2–M6 (kernel driver)**: process interception, file protection, registry protection, self-protection, network egress blocking. The driver builds into `Bulwark.sys` — see `Bulwark.Driver/README.md`.

## Event sources (switchable)

Configured via `EventSource` in `appsettings.json`:

- **Driver** — kernel-mode interception (true pre-action blocking; covers process / file / registry / self-protection / network milestones M2–M6).
- **Wmi** — user-mode observation (cannot block before the action; blocking is compensated by terminating the actor).
- **Simulated** — demo mode, no real-system monitoring.

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
