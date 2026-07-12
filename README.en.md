# Bulwark (磐垒主动防御)

English | [简体中文](README.md)

A Host-based Intrusion Prevention System (HIPS) for Windows, comparable in category to antivirus / EDR products. **Core idea:** monitor sensitive system behavior → a rule engine decides → prompt the user for a verdict when needed (Allow / Block / Remember).

Bulwark is built as three cooperating layers: a **kernel-mode driver (R0)** for true "before-the-action" interception, a **user-mode Windows service (R3)** that hosts the decision logic, and a **Qt desktop UI** for status, live logs, behavior prompts and rule management. The driver and service talk over a Filter Manager communication port; the service and UI talk over a named pipe. Whatever the event source, a single `RuleEngine` acts as the decision center, enriched by threat heuristics, LOLBin abuse detection, MITRE ATT&CK annotation, credential-access detection, and multi-engine hash reputation.

> **Current status:** this project is a **C++ / Qt** implementation (ported from an earlier .NET prototype). The user-mode pipeline `service (R3) ↔ UI` plus **live ETW observation** compiles and runs directly; the **kernel driver (R0)** builds into `Bulwark.sys`, and its user-mode integration (connect / protocol handshake / event intake / verdict write-back) is complete. All six protection dimensions (M1–M6) are implemented at the code level.
> - **User mode (R3 + UI):** service↔UI named-pipe channel, live ETW process/network/registry/file observation, Authenticode signature verification, SHA-256, rule management, SCM service install (`bulwark_service.exe --install`).
> - **Kernel driver (M2–M6):** process telemetry, file protection, registry protection, self-protection, network egress blocking. See `Bulwark.Driver/README.md` and the section at the end.

> ⚠ **The driver has not yet been validated end-to-end for interception inside a real kernel.** `Bulwark.sys` must be loaded with test-signing enabled inside a **snapshotted test VM** before it can truly enable "before-the-action" kernel interception (see the driver section at the end). The default release artifacts run the ETW user-mode observation pipeline.

> Three switchable event sources (`EventSource` in `appsettings.json`): `Driver` (kernel driver + ETW observation, includes all of M2–M6), `Wmi` (ETW user-mode observation only; the value name "Wmi" is kept for historical reasons), `Simulated` (demo, does not monitor the real system).

## Solution structure

```
cpp/                     C++ / Qt implementation (top-level CMake: cpp/CMakeLists.txt)
├─ shared/            Shared contract layer (static lib, depends only on Qt6::Core; used by service + UI)
│   ├─ src/models/       SecurityEvent / Verdict / DefenseRule / Evidence (evidence chain)
│   ├─ src/engine/       RuleEngine (decision center) + ThreatDetector / LolbinAnalyzer (LOLBins)
│   │                    / KillChainAnalyzer / AttackCatalog + AttackAnnotator (ATT&CK)
│   │                    / CredentialAccessAnalyzer / PersistenceAnalyzer / DefaultRules, etc.
│   └─ src/ipc/          IpcMessage (named-pipe message protocol)
├─ service/           User-mode service (R3, builds bulwark_service.exe): decision host + named-pipe server
│   ├─ src/main.cpp                Wiring + SCM integration (--install / --uninstall / --service)
│   ├─ src/Worker.cpp              Main defense loop: event → enrich → engine → verdict → act/cleanup
│   ├─ src/IpcServer.cpp           Named-pipe server (talks to the UI)
│   ├─ src/EventSourceCoordinator.cpp  Merges ETW + user-mode behavior sources + (hot-swappable) kernel driver source
│   ├─ src/DriverEventSource.cpp   Connects \BulwarkPort: handshake + push config + receive events + write back verdicts
│   ├─ src/DriverControl.cpp       On-demand register / load Bulwark.sys (minifilter, idempotent)
│   ├─ src/EtwProcessEventSource.cpp / SimulatedEventSource.cpp  Two base event sources
│   ├─ src/monitoring/ProcessInspector.cpp  Signature / hash / command-line forensics
│   ├─ src/reputation/             VirusTotal / ThreatBook / MalwareBazaar / OTX, etc. reputation clients
│   └─ src/*Store.cpp              Rules / quarantine / event history, etc. JSON persistence
└─ ui/                Desktop UI (builds bulwark_ui.exe): Qt Widgets, connects to the service via named pipe

Bulwark.Driver/         Kernel driver (R0), sibling of cpp/, built with MSBuild + WDK: Minifilter + communication port
├─ Driver.c             DriverEntry / unload / Minifilter registration + network device object
├─ ProcessMonitor.c     PsSetCreateProcessNotifyRoutineEx process telemetry
├─ FileMonitor.c / RegistryMonitor.c / SelfProtect.c / NetMonitor.c / ImageMonitor.c / ThreadMonitor.c
├─ Comms.c              Communication port + FltSendMessage reporting / config intake
└─ Protocol.h           Kernel↔service message structs (user-mode DriverEventSource reuses this header directly, single source of truth)

scripts/
├─ build-driver.ps1      Build the kernel driver (WDK + MSBuild) → build\driver\<Cfg>\Bulwark.sys
└─ deploy-driver-vm.ps1  Sign / register minifilter / load the driver inside a test VM
```

## Configuration (the `Bulwark` section of `appsettings.json`)

```jsonc
{
  "Bulwark": {
    "EventSource": "Driver",       // Driver = kernel driver + ETW / Wmi = ETW observation only / Simulated = demo
    "KernelDriverEnabled": true,   // enable the kernel driver (implied when EventSource = Driver)
    "TrustSignedActors": true,     // auto-allow trusted-signed programs
    "PromptTimeoutSeconds": 30,    // prompt wait timeout
    "ProtectedPaths": [            // protected file paths (substring match): kernel-blocked in Driver mode, ETW observation set in Wmi mode
      "\\Start Menu\\Programs\\Startup\\", "\\System32\\drivers\\etc\\hosts", "\\Tasks\\"
    ],
    "ProtectedRegistryKeys": [     // protected registry keys (substring match)
      "\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce", "\\Winlogon", "\\Services\\"
    ],
    "MemoryProtectionTargets": [ "lsass.exe" ],   // anti-injection protection targets (Driver mode only)
    "BlockedRemoteEndpoints": [ ],                // network blocklist IP[:port] (Driver mode only)
    "Etw": { "Enabled": true, "KernelNetwork": true, "KernelRegistry": true, "KernelFile": true }
  }
}
```

> The full default configuration is in `cpp/service/appsettings.json` (must sit in the same folder as `bulwark_service.exe`). It also carries each threat-intelligence source (`VirusTotal` / `MalwareBazaar` / `Otx` / `ThreatBook` / `MetaDefender` / `HybridAnalysis` / `ThreatFoxFeed`) and an `Ai` large-model node, all off by default.

## Quick start (one click)

The repository root provides two one-click scripts. They auto-request administrator privileges and, in order: build → deploy to `cpp\dist` → install and start `BulwarkService` → open the UI.

- **`一键启动-仅用户态.bat`** — recommended for first use. Runs only the user-mode ETW observation pipeline, **does not load the kernel driver, does not touch test signing, no BSOD risk.**
- **`一键启动.bat`** — the full pipeline; additionally builds and loads the kernel driver `Bulwark.sys` (enables test signing and requires one reboot). ⚠ **A faulty kernel callback can bluescreen (BSOD) the machine — always run inside a snapshotted test VM.**

Other root scripts: `启用驱动.bat` (load the kernel driver separately), `诊断驱动.bat` (driver-load diagnostics, results written to `driver_diag.txt`).

> Requires **Visual Studio 2022 (with the C++ toolchain)** and **Qt 6.8**. The scripts default the Qt path to `C:\Qt\6.8.3\msvc2022_64`; edit `cpp\scripts\dev-all.ps1` to adjust.

## Build and run (development)

Requires **Visual Studio 2022 (with the C++ toolchain)** and **Qt 6.8**. Both ETW live observation and the kernel driver need **administrator privileges**.

```powershell
# 1) Configure + build (the top-level CMake builds shared / service / ui together)
cmake -G "Visual Studio 17 2022" -A x64 -S cpp -B cpp\build -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64"
cmake --build cpp\build --config Release

# 2) Run the service and UI as administrator (appsettings.json must sit next to bulwark_service.exe)
.\cpp\build\service\Release\bulwark_service.exe   # Terminal 1: service (console debug mode)
.\cpp\build\ui\Release\bulwark_ui.exe             # Terminal 2: UI (manifest already declares requireAdministrator)
```

A green status dot at the top of the UI means it is connected to the service. Whenever the system has a **real process launch**:
- a trusted-signed process → the engine auto-allows it and it appears directly in the log;
- an unsigned process → a prompt lets you choose Allow / Block, and you can tick "Remember my choice" to create a persistent rule.

Click "Rules" to view/delete saved rules. Rules are persisted at `%ProgramData%\Bulwark\rules.json`.

> A packaged build already exists under `cpp\dist\` (`bulwark_service.exe` + `bulwark_ui.exe` + Qt runtime), runnable directly as administrator.
> To see the demo without monitoring the real system, set `EventSource` to `"Simulated"` in `appsettings.json`; to enable kernel "before-the-action" interception, set it to `"Driver"` and load the driver in a test VM per the section at the end.

## UI features and how to use them

The left sidebar has 10 pages (in the order below). A green status dot at the top (link online) means it is connected to the service. The sidebar footer shows `v1.0.0 · Qt Edition`. Closing the main window minimizes to the system tray and protection keeps running in the background.

### ▣ Dashboard
Overview page, display-only. Includes: a top "protected / disconnected" status banner with ONLINE/OFFLINE; a **KERNEL** row showing the driver connection status and text; an **AI CREDITS** monthly-usage progress bar (prefers official Xiaomi-platform usage, otherwise a local estimate, plus a per-AI-feature call/credit breakdown); four stat cards **ALLOWED / BLOCKED / AI SCANS / TOTAL**; and a bottom **LIVE LOG** that scrolls handled process/file/registry/network events in real time.

### 📋 Intercept log
Deterministic high-risk actions that were **blocked outright**. Each entry shows a type badge, actor name + action, target, actor path, time, and a "blocked" mark. **Double-click any entry to open the "Attack Timeline" window** and trace the whole attack chain.

### 📡 Activity log
The fuller event stream: scored allows, ask-prompts, and blocks are all here. Each entry shows type, actor + action, target, path, time, the (color-coded) verdict text, and a risk score. **Double-click to view the attack timeline.** Event history is persisted and backfilled on restart.

### ⚡ Rules
View and manage defense rules. Each row shows: rule description, actor, match condition, status tag (temporary/session/disabled), event type, and action (Block = red / Allow·Ask = cyan). Actions:
- **+ New rule** — open the rule editor to create one manually (the actor is auto-recognized as an exact path / wildcard / bare file name).
- **🤖 AI generate** — describe a requirement in natural language (e.g. "block wscript from spawning child processes"); the AI proposes 1–5 candidate rules, click **Adopt** on each to add it.
- **↻ Refresh** / **Delete** per row.
- Tip: ticking "Remember my choice" in a behavior prompt also creates a rule automatically.

### ✓ Trust
An allowlist of trusted programs and directories; behavior of listed targets is **allowed directly, no longer inspected**. Actions: **+ Add trust** to pick an executable **or an entire directory** (a trusted directory allows all programs under it), **Remove** per row, **↻ Refresh**. Each row shows the path and note.

### 🗃 Quarantine
Files confirmed malicious and quarantined. Columns: FILE (name + original path) / REASON / DATE (quarantine time) / OPS. Actions: **Restore** (back to original location), **Delete** (permanent), **↻ Refresh**.

### ⚓ Persistence
Click **↻ Scan** to read-only enumerate seven classes of autostart persistence points: registry Run/RunOnce, Startup folder, Windows services, scheduled tasks, image hijack (IFEO), Winlogon, AppInit_DLLs. Each row shows category, name, command, location, matched ATT&CK techniques, reason, plus a risk level + score (color-coded by level). **Read-only — never modifies any autostart entry**; cleanup still goes through the rule/quarantine flow.

### ☁ Reputation
A multi-engine hash-reputation query center aggregating six sources: **VirusTotal (flagship, built-in default key) + ThreatBook + MalwareBazaar + OTX + MetaDefender + HybridAnalysis**. The page has: each source's enabled/connected **status** and a connection test, manual lookup **by file/hash**, and **VirusTotal query history** (launching an unsigned/first-seen program auto-uploads and records a trail here: file name, source, path, SHA256, status and time). A malicious/suspicious hit auto-opens a behavior-relationship detail window.

### 🤖 AI scan
The Xiaomi MiMo large model judges a file's maliciousness from **static content features** (signature/path/PE structure/script source/strings/entropy, etc.) — it **does not execute the sample**. Buttons: **🔍 Scan & trace** (pick one file, get a detailed report after analysis), **📄 Scan file**, **📁 Scan folder**, **⏹ Stop**. Top stats: SCANNED / CLEAN / SUSPICIOUS / MALICIOUS; the result list has file path + SHA256, verdict, confidence, summary, with a **Trace** button per row.

### ⚙ Settings
- **Active protection** master switch (off = all events are allowed directly).
- **Protection dimensions**: process / file / registry / self-protection / network, each toggleable.
- **Decision policy**: auto-trust signed programs, default-block (fallback on no-rule/timeout), silent mode (auto-allow ask-events, block only deterministic high-risk), quarantine-on-block.
- **Kernel driver**: enable-driver toggle, with connection status / kernel status / current event source.
- **Threat intelligence**: enable VirusTotal background reputation lookups, test connection, manual lookup by file path.
- **AI / large-model analysis**: AI scan on double-click launch, suspend process during analysis, block-on-analysis-failure (strict mode), gray-zone AI consult, credit-budget guard + monthly quota (100M), official usage display (paste Cookie) + test fetch.
- **Continuous behavior protection (post-execution)**: user-mode continuous behavior monitor, ransomware canary (decoy files), behavior-baseline anomaly detection.
- **Model config**: API base URL / API key / model, with a "Test AI" button.
- **Scan content limits**: script-source cap (KB), binary-sample cap (MB), extracted-strings count.

### Prompts and notifications
- **Behavior prompt (PromptDialog):** shown when no rule matches and the actor is untrusted. A risk-level-colored header banner + level badge; two cards (digital signature + VirusTotal intel); program / description / command line / behavior (with ATT&CK tags) / target details; SHA256 + risk score; expandable "**Process lineage**" and "**Verdict rationale · evidence-chain timeline**"; a "🤖 AI security assistant" that generates an attack narrative; and at the bottom "Don't remind again (remember this choice)" + a scope dropdown (Permanent / This session / 1 hour / 1 day) + **✓ Allow** / **✕ Block**.
- **Block notification (ToastWindow · Block):** a corner toast when a deterministic high-risk action is blocked outright (stacked and managed by `ToastNotifier`).
- **AI scan toast (ToastWindow · AiScan):** a lightweight toast when a double-click launch triggers an AI verdict.
- **Tray:** closing the main window minimizes to the system tray; protection keeps running in the background.

## Install as a Windows service (administrator)

The service ships with its own SCM registration, no extra scripts needed (the user-mode service name is `BulwarkService`, distinct from the kernel driver service `Bulwark`):

```powershell
# Run as administrator
.\bulwark_service.exe --install     # register as an auto-start service
sc start BulwarkService             # start
.\bulwark_service.exe --uninstall   # stop and uninstall
```

## Decision priority (RuleEngine)

1. A matched existing rule → Allow/Block directly.
2. Actor has a trusted signature and trust is enabled → Allow.
3. Otherwise → prompt the user (on timeout, fall back to the default policy: Allow by default, can be changed to Block).

## Explainability and advanced detection (complete)

Under the "only act on genuinely dangerous behavior, low false positives, mutual corroboration" principle, the following mutually-reinforcing capabilities were added:

- **Evidence-chain timeline (explainability):** every event carries a structured `EvidenceChain` that records, item by item, "source analyzer / category (hard indicator · soft signal · corroboration upgrade · trust · rule · verdict) / risk-score contribution / description", ending with a "final verdict". The behavior prompt renders this as a colored timeline showing "why it was judged this way", not just a single isolated score; the same structured data also feeds the AI analysis. It coexists with the old flat `RiskReasons` and is fully backward compatible.

- **LOLBins abuse analysis (`LolbinAnalyzer`):** detects known techniques where Microsoft-signed system binaries (regsvr32 / rundll32 / mshta / certutil / bitsadmin / msbuild / installutil / msiexec / wmic / mavinject, etc.) are abused via "binary + signature arguments" (Squiblydoo, remote HTA, certutil download, msbuild inline task, wmic remote execution, comsvcs LSASS dump, etc.). High-confidence abuse acts as a hard indicator and invalidates the `TrustPolicy` "strongly-trusted / healthy-signature allow" gate — the key reinforcement of "signed ≠ behavior-trusted" (signature alone can never catch LOLBin abuse).

- **MITRE ATT&CK annotation (`AttackCatalog` + `AttackAnnotator`):** maps each analyzer hit uniformly to ATT&CK technique IDs (e.g. T1218.010 Squiblydoo, T1003.001 LSASS dump, T1490 inhibit system recovery), writing them back to each piece of evidence and deduplicating on the event. The behavior prompt shows technique tags, upgrading alerts and AI reports from "a one-line reason" to standardized technique tags. Near-zero runtime cost (table lookup + text extraction).

- **Credential access / LSASS protection (`CredentialAccessAnalyzer`):** identifies credential theft from "target/path + command line + behavior type" — LSASS memory dump/injection (T1003.001), SAM/SECURITY hive export (T1003.002), domain-controller NTDS.dit extraction (T1003.003), browser credential store/DPAPI (T1555). High-confidence attacks act as hard indicators and strip the trusted-allow exemption from signed system tools (reg.exe / ntdsutil, etc.) when they perform credential export.

- **Persistence audit view (`PersistenceScanner` + `PersistenceAnalyzer` + persistence audit page):** read-only enumeration of seven classes of autostart persistence points — registry Run/RunOnce, Startup folder, Windows services, scheduled tasks, image hijack (IFEO), Winlogon, AppInit_DLLs; each reuses the ThreatDetector heuristic scoring and is annotated with ATT&CK persistence techniques (T1547/T1543/T1546/T1053). The UI displays them sorted and color-coded by risk level (high/suspicious/watch/normal) to help spot suspicious residency quickly. Never modifies any autostart entry; cleanup still goes through the existing rule/quarantine flow.

- **ECS structured alert export (`EcsAlertFormatter` + `AlertExporter`):** formats every handled event into Elastic Common Schema-style JSON-lines (`event.* / process.code_signature.* / destination.* / threat.technique[] / threat.tactic[]`, keeping the evidence chain and reasons under `bulwark.*`), written to `%ProgramData%\Bulwark\alerts\alerts-yyyyMMdd.jsonl` for seamless SIEM ingestion (Elastic/Splunk/OpenSearch). Controlled by the `ExportEcsAlerts` switch in `appsettings.json`, off by default, changes no verdict.

- **Rule expiry and scope:** `DefenseRule` supports an optional expiry time (`ExpiresUtc`) and a "this session only" scope (`SessionOnly`). The behavior prompt's "Remember my choice" offers a scope — Permanent / This session / 1 hour / 1 day: session rules are not persisted and expire on restart; timed rules expire and are cleaned up automatically. This lowers the risk of a one-time "remember" causing a permanent false-allow.

- **Tiered reputation cache TTL + offline fallback (`ReputationCache`):** malicious verdicts cached permanently, clean verdicts on a per-day TTL, suspicious verdicts on their own shorter TTL (faster re-check), Unknown on short-term negative cache. Enrichment reads (`TryGetForEnrichment`) still return the last known verdict after the TTL expires, so enrichment still works from the "most recent known reputation" when offline / on query failure; freshness is handled by a background re-query. Reputation only ever adds/subtracts score, never acts on its own, and going offline does not affect real-time protection.

## Kernel driver (R0): true "before-the-action" interception

`Bulwark.Driver` is Bulwark's kernel-mode component, letting Bulwark stop dangerous actions **before** they happen rather than only observing after the fact. It uses **only Microsoft-documented APIs**, does no SSDT hooking, and is therefore **PatchGuard-friendly**. It registers a **Minifilter** that both hooks I/O callbacks and borrows the Filter Manager **communication port** (`FltCreateCommunicationPort` / `FltSendMessage`) to talk to the user-mode service.

Five protection dimensions:

| Dimension | Kernel mechanism | What it intercepts |
|-----------|------------------|--------------------|
| **Process (M2)** | `PsSetCreateProcessNotifyRoutineEx` | Every process creation (telemetry reporting; on a match, user mode terminates the process tree immediately after launch) |
| **File (M3)** | Minifilter pre-op `IRP_MJ_CREATE` (delete-on-close) + `IRP_MJ_SET_INFORMATION` (rename/disposition) | Deletion and rename of protected files |
| **Registry (M4)** | `CmRegisterCallbackEx` (`RegNtPreSetValueKey` / `RegNtPreDeleteValueKey` / `RegNtPreDeleteKey`) | Set/delete value and delete key on protected keys (e.g. autostart) |
| **Self-protection (M5)** | `ObRegisterCallbacks` | When another process tries to open a Bulwark-protected process with dangerous rights (terminate / write-memory / remote-thread / suspend), strip those rights |
| **Network (M6)** | WFP callout + filter (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) | Outbound connections matching a blocklist |

**Handling model** (modeled on Sysmon / EDR, stability first):

- **Process creation** uses **fire-and-forget telemetry + post-launch compensation**: the kernel allowlists system directories / critical processes directly (zero latency); other processes are **reported only, not blocked**; if the user-mode verdict is `Block`, user mode immediately `TerminateProcess`-es that process tree (samples usually run only for tens of milliseconds). **Process creation is no longer suspended**, avoiding a user-mode stall dragging down the whole system.
- **File / registry hard blocks** (`FileHardBlocks` / `RegistryHardBlocks` exact lists) return `STATUS_ACCESS_DENIED` **locally in the kernel** — no IPC, no waiting on user mode, a true in-place block at zero latency.
- **Self-protection / anti-injection / network** run at high IRQL and **do not block**: they strip dangerous handle rights / apply `FWP_ACTION_BLOCK` directly and log asynchronously.

Protected paths, registry keys, hard-block lists, protected process PIDs, anti-injection targets, and the network blocklist are all pushed down from user mode via `FilterSendMessage`.

```
New process starts
   │  (kernel callback, PASSIVE_LEVEL)
   ▼
System dir / critical process? ──yes──▶ allow directly (zero latency, no IPC)
   │no
   ▼
ProcessMonitor builds event ──FltSendMessage (telemetry, no wait)──▶ user-mode DriverEventSource
   │                                                          │
   ▼                                                   RuleEngine evaluates / UI prompt
process starts normally right away                            │
                                                              ▼
                                        verdict = Block → user-mode TerminateProcess ends the process tree
```

> File / registry hard blocks, self-protection, anti-injection and the network blocklist are different: they block **immediately** locally in the kernel (or at high IRQL), and do not go through the post-launch compensation path above.

**Driver source files** (`Bulwark.Driver/`):
- `Driver.c` — DriverEntry / unload / Minifilter registration (I/O callbacks + instance attach) + network device object
- `ProcessMonitor.c` — process-create callback and interception
- `FileMonitor.c` — file delete/rename interception + protected-item matching
- `RegistryMonitor.c` — registry set/delete value/key interception + protected-key management
- `SelfProtect.c` — `ObRegisterCallbacks` handle callbacks that strip dangerous rights on protected processes
- `NetMonitor.c` — WFP callout/filter + blocklist management
- `ImageMonitor.c` / `ThreadMonitor.c` — image-load and remote-thread monitoring
- `Comms.c` — communication port, `FltSendMessage` verdict wait / async reporting, config message intake
- `Protocol.h` — kernel↔user-mode message structs (user-mode `DriverEventSource.cpp` `#include`s this header directly as the single source of truth, eliminating struct-layout drift)

Brief flow:

```powershell
# 1) Build the driver (a local WDK is enough)
.\scripts\build-driver.ps1 -Configuration Debug   # produces build\driver\Debug\Bulwark.sys

# 2) Load ONLY inside a [snapshotted test VM] (a faulty callback will BSOD!)
.\scripts\deploy-driver-vm.ps1                    # enable test signing / create test cert / sign / install / start

# 3) Set EventSource to "Driver" in appsettings.json, run the service + UI as administrator
```

Process creation uses the "telemetry + post-launch kill" model (see "Handling model" above); file / registry hard blocks, self-protection, anti-injection and the network blocklist block immediately, locally in the kernel. The driver is linked with `/INTEGRITYCHECK` (required for `ObRegisterCallbacks` self-protection) and the image must carry a valid signature; a production release needs an EV certificate + Microsoft WHQL/attestation signing.

## Milestones

| Milestone | Scope | Key kernel mechanism (all Microsoft-documented APIs) | Status |
|-----------|-------|------------------------------------------------------|--------|
| M2 | Process protection | `PsSetCreateProcessNotifyRoutineEx` | ✅ Done |
| M3 | File protection | Minifilter I/O callbacks (`IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION`) | ✅ Done |
| M4 | Registry protection | `CmRegisterCallbackEx` (set/delete value/key) | ✅ Done |
| M5 | Self-protection | `ObRegisterCallbacks` (strip dangerous handle rights) | ✅ Done |
| M6 | Network protection | WFP (`ALE_AUTH_CONNECT_V4` blocklist blocking) | ✅ Done |

Adding a new protection dimension **needs no changes to the UI / rule engine**: add a callback in the driver and report events over the same communication port, then have the service-side `DriverEventSource` parse the new event type.

> The driver requires a digital signature: during development, enable test signing (`bcdedit /set testsigning on`) + a test VM; a production release needs an EV certificate and WHQL certification. Always debug inside a snapshotted VM — a faulty callback will cause a BSOD.

## Security note

This project is a legitimate endpoint security tool (in the same category as antivirus / EDR). Self-protection keeps a normal, user-controllable uninstall path and is never made "impossible to remove".
