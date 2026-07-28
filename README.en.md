# Bulwark (磐垒主动防御)

English | [简体中文](README.md)

A Host-based Intrusion Prevention System (HIPS) for Windows, in the same category as antivirus / EDR. **Core idea:** monitor sensitive system behavior → a rule engine decides → prompt the user for a verdict on gray-zone behavior (Allow / Block / Remember). It only acts on genuinely dangerous behavior and tries hard not to nag.

Bulwark is built as three cooperating layers: a **kernel-mode driver (R0)** for "before-the-action" interception, a **user-mode Windows service (R3)** that hosts all decision and remediation logic, and a **Qt desktop UI** for status, live logs, behavior prompts, rule management and AI research. The driver and service talk over a Filter Manager communication port; the service and UI over a named pipe. Whatever the event source, a single `RuleEngine` is the decision center, backed by threat heuristics, several dedicated analyzers, stateful temporal detection, multi-engine hash reputation, a threat-intel feed and AI research.

> This project is a **C++ / Qt** implementation (ported from an earlier .NET prototype).
> - **User mode (R3 + UI) compiles and runs directly**: service↔UI named-pipe link, live ETW observation (process / network / DNS / registry / file), user-mode continuous behavior monitoring (autostart + ransomware decoys), Authenticode signature + certificate-profile verification, SHA-256, rule / trust / quarantine management, multi-engine cloud reputation, AI research, SCM service install.
> - **The kernel driver (R0) builds into `Bulwark.sys`**; its user-mode integration (connect / protocol handshake / event intake / config push / verdict compensation) is complete, and all six protection dimensions are implemented at the code level.

> ⚠ **The kernel driver has not yet been validated end-to-end inside a real kernel.** `Bulwark.sys` must be loaded with test-signing enabled inside a **snapshotted test VM** before it can truly enable "before-the-action" kernel interception; a faulty kernel callback can bluescreen (BSOD). The default release artifacts run the **ETW user-mode observation pipeline**.

## Two switchable event sources

Chosen via `EventSource` in `appsettings.json`; the decision logic and UI are identical whichever you pick:

- **`Driver`** — kernel driver + ETW observation. The kernel blocks hard-block lists / protected items / the network blocklist / self-protection "before the action". Process creation has **both** paths: **kernel-local pre-create denial** (image on the "exec-block" list, or the creator itself is a banned malicious actor → `STATUS_ACCESS_DENIED`) and **telemetry + post-launch kill** compensation for gray-zone processes that match no local list.
- **`Wmi`** — ETW user-mode observation only (the value name "Wmi" is historical; it is actually ETW). Cannot block before the action; blocking is compensated by terminating the offending process tree afterward.

> Whatever the source, user mode always runs a parallel "continuous behavior source" (autostart-persistence watch + ransomware decoys) to cover the blind spot *after* a program is running.

## Screenshots

| | |
|:---:|:---:|
| **Dashboard**<br>![Dashboard](docs/screenshots/screenshot-01.png) | **Intercept log**<br>![Intercept log](docs/screenshots/screenshot-02.png) |
| **Activity log**<br>![Activity log](docs/screenshots/screenshot-03.png) | **Rules**<br>![Rules](docs/screenshots/screenshot-04.png) |
| **Trust**<br>![Trust](docs/screenshots/screenshot-05.png) | **Quarantine**<br>![Quarantine](docs/screenshots/screenshot-06.png) |
| **Persistence**<br>![Persistence](docs/screenshots/screenshot-07.png) | **Reputation**<br>![Reputation](docs/screenshots/screenshot-08.png) |
| **AI research**<br>![AI research](docs/screenshots/screenshot-09.png) | **Settings**<br>![Settings](docs/screenshots/screenshot-10.png) |

## Solution structure

```
cpp/                     C++ / Qt implementation (top-level CMake: cpp/CMakeLists.txt, C++20)
├─ shared/            Shared contract layer (static lib, depends only on Qt6::Core; used by service + UI)
│   ├─ src/models/       SecurityEvent / Verdict / DefenseRule (expiry + session scope) / Evidence (chain), etc.
│   ├─ src/engine/       Decision + detection core (see "Detection"): RuleEngine + a dozen analyzers / monitors
│   └─ src/ipc/          IpcMessage (named-pipe message protocol)
├─ service/           User-mode service (R3, builds bulwark_service.exe): decision host + remediation + pipe server
│   ├─ src/main.cpp                Wires everything + SCM (--install / --uninstall / --service / --inspect)
│   ├─ src/Worker.cpp              Main loop: event → enrich → engine → verdict → IPC / act / cleanup + background workers
│   ├─ src/EtwProcessEventSource.cpp   krabsetw live observation (5 ETW providers)
│   ├─ src/UserModeBehaviorSource.cpp  user-mode continuous behavior (autostart + ransomware decoys)
│   ├─ src/DriverEventSource.cpp / DriverControl.cpp  kernel-source link + on-demand load of Bulwark.sys (minifilter)
│   ├─ src/EventSourceCoordinator.cpp  merges ETW + behavior source + (hot-swappable) kernel source
│   ├─ src/monitoring/ProcessInspector.cpp  signature / cert-profile / hash / command-line / parent forensics
│   ├─ src/reputation/             VirusTotal / ThreatBook / MalwareBazaar / OTX / MetaDefender / HybridAnalysis + ThreatFox feed
│   ├─ src/QuarantineManager.cpp / ThreatRemediator.cpp  reversible quarantine + malicious-footprint cleanup
│   ├─ src/PersistenceScanner.cpp  read-only enumeration of 7 autostart persistence classes
│   └─ src/*Store.cpp              rules / settings / first-seen / baseline / event history / VT history / audit / ECS alerts
└─ ui/                Desktop UI (builds bulwark_ui.exe): Qt Widgets, connects to the service over a named pipe
    ├─ src/MainWindow.cpp / pages/  12 feature pages
    ├─ src/dialogs/                 behavior prompt / toast / scan progress / cleanup report / attack timeline
    └─ src/ai/                      UI-side AI research (static feature extraction + LLM)

Bulwark.Driver/         Kernel driver (R0), sibling of cpp/, built with MSBuild + WDK: Minifilter + communication port
├─ Driver.c ProcessMonitor.c FileMonitor.c RegistryMonitor.c SelfProtect.c
├─ NetMonitor.c ImageMonitor.c ThreadMonitor.c Comms.c
├─ HashScan.c           kernel-local known-bad SHA-256 scan (self-contained pure-C SHA-256, async worker, kill on hit)
├─ Policy.c             kernel-side policy / list containers
└─ Protocol.h           kernel↔service message structs (user-mode DriverEventSource reuses this header, single source of truth)

server/bulwark-broker/  optional central reputation broker (broker.py, pure Python stdlib + SQLite) — see "Central reputation service"
Bulwark.Sandbox/        Windows Sandbox (.wsb) configs + sample-drop scripts for running samples in isolation
ml/                     offline training scripts (LightGBM); not part of the C++ build and **no model is loaded by the product**
scripts/                build-driver.ps1 (build driver) / deploy-driver-vm.ps1 (sign+load in a test VM) + local deploy scripts
```

> `ml/` is a leftover offline experiment directory. **There is no model-inference path anywhere in the current code** — detection comes entirely from rules + heuristics + analyzers + cloud reputation, with no machine-learning model dependency.

## Decision flow (RuleEngine)

Each event entering `RuleEngine::evaluate` runs a fixed-priority pipeline (not a simple three-way choice) and returns on the first match:

1. **Unconditional allow**: Bulwark's own components (by image name + install-dir prefix), and user-trusted files / folders (trust = skip all further detection and background scans).
2. **Installed known security products**: coexistence allow (`TrustPolicy::isTrustedSecurityProduct`).
3. **Known-benign vendor apps** (QQ / WeChat / WeCom / TIM): when the image name is on the built-in list **and** the binary carries a healthy vendor signature, **network-egress and DNS events only** are allowed ahead of the temporal detectors (`TrustPolicy::isTrustedVendorApp`), so normal keep-alive traffic isn't scored as C2 beaconing. **This tier does not cover other dimensions** — process creation / module load / file write / registry write / injection events from the same process still run the full pipeline, so IM sideloading and group-control hook-module loads are still detected.
4. **Threat analysis**: `ThreatDetector::analyze` computes a risk score and sets the "hard malicious indicator" flag (below).
5. **Stateful temporal detection**: file write/delete → ransomware monitor (touching a decoy = immediate Block); network egress → C2 beacon + DGA domain + egress rate; DNS query → DGA domain.
6. **Behavior-baseline deviation** (toggleable): a soft signal when a program deviates from its own history, escalated only if corroborated by a hard indicator.
7. **Explicit rules**: matched and sorted by "tier (exact actor > hard-override > wildcard) > specificity > action strength > recency"; strongly-trusted OS components / dev tools are exempt from "ask" rules.
8. **Strongly-trusted actor** → allow (cert-thumbprint allowlist, or Microsoft-signed + system dir, with a healthy signature and no dangerous behavior).
9. **Signature anomaly** (revoked cert / signed after cert expiry) → Block.
10. **Healthy signature** → allow (excludes hard indicators and the "shell-company new cert" profile).
11. **Act only if a hard indicator exists**: risk score ≥ high-risk threshold → Block, otherwise → Ask (prompt).
12. **No hard indicator → always allow** (log only; soft signals never convict on their own).

> **Mind where the trust channels sit**: steps 1–3 above run **before** explicit rule matching, and threat analysis also runs before rules. Writing a Block rule therefore does **not** override those three channels — an event allowed by own-component / security-product-coexistence / (network-dimension) vendor-app trust never reaches step 7.

After deciding, a "final verdict" evidence entry is appended and `AttackAnnotator` annotates MITRE ATT&CK techniques. Verdict actions are **Allow / Block / Ask**; the source is tagged Rule / Heuristic / Trusted-signer / User-prompt / Timeout / Default-policy.

## Detection capabilities (all from the actual code)

The **threat-analysis center `ThreatDetector`** aggregates built-in heuristics and orchestrates several dedicated analyzers; every hit writes a structured evidence entry (hard indicator / soft signal / corroboration / trust / rule / info):

Built-in heuristics: no trusted signature; **signature-verification mismatch / revoked cert / signed after cert expiry**; first-seen + shell-company new cert; **oversized unsigned file (file bloat to evade scanners)**; execution from suspicious dirs (Temp / Public / ProgramData / Downloads / Roaming / Desktop, etc.); **non-standard Windows sub-directory masquerade**; **abnormal parent-child chain** (Office / browser spawning a LOLBin — macro-virus / phishing); a large command-line signal table covering many ATT&CK techniques (`-enc` encoded command, `DownloadString` / `Invoke-WebRequest` in-memory download, `IEX` dynamic exec, `mimikatz` / `sekurlsa` / `comsvcs.dll` credential theft, `vssadmin delete` shadow-copy deletion, etc.); **process masquerade** (system process name outside its legit directory, T1036.005); **typosquatting / homoglyph impersonation** (`svch0st` / `1sass` / Cyrillic letters, edit distance ≤ 1); **double extension** (T1036.007); **NTFS Alternate Data Stream execution** (T1564.004); cloud-reputation hits (below).

Dedicated analyzers:

- **LOLBins abuse** — Microsoft-signed system binaries (regsvr32 / rundll32 / mshta / certutil / bitsadmin / msbuild / wmic / comsvcs, etc.) abused via "binary + signature arguments" (Squiblydoo, remote HTA, certutil download, msbuild inline task, wmic remote exec, comsvcs LSASS dump, etc.). High-confidence abuse is a hard indicator and **invalidates the signature-trust exemption** — signed ≠ behavior-trusted.
- **Credential access / LSASS protection** — LSASS memory dump/injection, SAM/SECURITY hive export, domain-controller NTDS.dit extraction, browser credential store / DPAPI reads.
- **Defense evasion** — tampering/disabling Defender, AMSI/ETW blinding, clearing event logs, disabling firewall/UAC, killing security software.
- **Remote control / RMM abuse** — RDP hijack, reverse shells, unattended remote control, and instant-messenger (WeChat / QQ) group-control injection / sideloading.
- **Process injection / DLL sideloading** — cross-process remote threads (hollowing / APC / hijack landing), loading unsigned modules from writable dirs (sideloading).
- **Command-line obfuscation** (signature-free) — Shannon entropy / symbol ratio / known obfuscation constructs / long Base64 blocks.
- **Script content static analysis** — dangerous-command / obfuscation / encoding / network detection on PowerShell / VBS / JS / Batch script bodies (e.g. after `-EncodedCommand` decode).
- **Kill-chain stage analysis** — classifies events across one process tree into ATT&CK tactic stages, scoring only when ≥3 distinct stages are covered (multi-stage attacks).

Stateful temporal monitors (per-PID / per-series sliding windows, thread-safe):

- **Ransomware monitor** — burst rewrite rate, extension homogenization, ransom-note writes, **decoy touch (immediate Block)**.
- **C2 beacon detector** — per (PID | remote) egress timeline, analyzing periodicity / jitter (coefficient of variation) for beaconing.
- **Egress rate / fan-out monitor** — rate bursts and target fan-out (soft signal, needs corroboration).
- **DGA domain analyzer** — domain-string statistics only (entropy / vowel ratio / consonant runs / digit interleaving), no blocklist.
- **Behavior baseline / anomaly** — per-program child / host / write-dir profiles with a learning period; significant deviation is a soft signal; snapshot export/import.
- **Process-chain tracker** — stitches isolated events into a process tree for lineage context, dropper detection (recently-written executables), and whole-tree footprint cleanup.

**`TrustPolicy`** tiers: known-security-product coexistence, strongly-trusted (may skip behavior detection), healthy-signed, benign-signer (score discount only), and OS component exempt from sensitive rules. In any tier, a dangerous command line / LOLBin abuse / credential attack / signature anomaly stops the allow.

**Design principle**: soft signals (unsigned, suspicious path, first-seen, new cert) **never trigger a block or prompt on their own** — they only add score and must be corroborated by a hard indicator; healthy-signed legitimate programs are allowed without nagging.

## Cloud reputation, threat intel and AI research

- **Multi-engine hash reputation** — transported via `curl.exe`, tiered cache (`%ProgramData%\Bulwark\reputation.jsonl`: malicious permanent / clean 7 days / suspicious 24 h / unknown short negative cache, with last-known fallback for enrichment when offline), rate-limited. Aggregates 6 sources and takes the strongest verdict (Malicious > Suspicious > Clean > Unknown): **VirusTotal (flagship, full-file upload+scan + per-engine detail), ThreatBook (微步, plus IP reputation), MalwareBazaar, OTX, MetaDefender, HybridAnalysis (plus sandbox behavior profile)**. Each source can be toggled independently; reputation only adds/subtracts score, never acts alone, and going offline does not affect real-time protection.
- **Central reputation service (hash lookups go through a server by default; can be turned off)** — see the dedicated "Central reputation service" section below. **This is the only feature that produces outbound requests even when you have supplied no API keys at all**, so read that section before deciding whether to keep it enabled.

> **Code default vs shipped config**: in **code**, every intel source defaults to off (`Enabled = false` in `BulwarkOptions.h`). But the `cpp/service/appsettings.json` shipped alongside the service turns VirusTotal / MalwareBazaar / OTX / ThreatBook / MetaDefender / HybridAnalysis / the ThreatFox feed / the central reputation service **all to `true`** for out-of-the-box convenience. The config file overrides the code default, so a packaged build arrives fully enabled. For a genuinely local-only run, set the relevant `Enabled` to `false`, or turn each off on the UI Settings page.

> The open-source build **bundles no vendor keys** — every key field in the source and in the `cpp/service/appsettings.json` template is blank (VirusTotal's built-in key is only injectable at build time via `-DBULWARK_VT_BUILTIN_KEY`, and is not injected by default). ⚠ This does **not** apply to `cpp/dist/`, which is a developer run directory excluded by `.gitignore` and not in version control — its `appsettings.json` may still hold the developer's real keys. **Do not hand out the whole `cpp/dist/` folder**; regenerate the config from the blank-key template before distributing.
- **Threat-intel feed (ThreatFox / abuse.ch)** — periodically pulls recent malicious IOCs (by confidence threshold) and **auto-generates hash / IP / domain block rules** (source-tagged, with expiry); also manual "refresh / preview / adopt" in the UI.
- **Network egress IP intel** — only for suspicious egress, a rate-limited background ThreatBook IP-reputation lookup (very low monthly quota + 7-day hard cache + in-flight dedup); on confirmed malice it compensates by terminating the egress process tree.
- **Double-click / dropped-payload malware scan** — double-click launches, dropper-spawned children, recently-dropped executables, and double-clicked MSI/MSP installers are hash-queried against VT, then the full file is uploaded for a cloud scan if unknown; progress streams to a UI card, results are deduped into VT history, and confirmed malice triggers compensation.
- **AI research (UI-side LLM)** — OpenAI-compatible, async, fail-open on any error. Two capabilities: (1) judge a file's maliciousness from **static content features only** (**never executes the sample**); (2) turn a natural-language security intent into 1–5 reviewable defense rules. Static features are extracted bounds-safely by `StaticFeatureExtractor`: PE header + per-section Shannon entropy (packing, entropy > 7.2), dangerous Win32 APIs / URLs / IPs in ASCII/UTF-16 strings, capability tags (injection / anti-debug / keylogging / ransomware / download / persistence / privilege escalation / discovery / command exec), script snippet. AI history is persisted at `%ProgramData%\Bulwark\ai_scan_history.json`.
- **AI gray-zone policy** — consults the model only for "Ask" gray-zone events: AI-malicious → escalate to Block; AI-clean with no hard indicator → downgrade to Allow (less nagging); otherwise keep the original verdict. **AI never suppresses a hard indicator, and never overrides a deterministic block or a strongly-trusted allow.**

## Central reputation service (ReputationProxy)

⚠ **This is enabled by default, and it sends the SHA-256 of files on your machine to a third-party server.** Read this section before deciding whether to keep or disable it.

**What it is** — a hash-reputation proxy. When enabled, hash lookups go to that server **first** instead of directly to each intel source: the server holds the upstream API keys and maintains one shared cache for every endpoint that connects (a hash someone else already looked up is a zero-round-trip hit for you). It is implemented as `ProxyReputationService`, a proxy-first decorator wrapped around `AggregateReputationService` and installed on `ReputationManager`, the single choke point — so **the background reputation queue, memory-protection VT re-verification, and manual UI lookups all go through it**. The server code lives in this repo at `server/bulwark-broker/` (`broker.py`, pure Python stdlib + SQLite).

**What leaves your machine** — only the **SHA-256 digest** (plus an optional bearer token). **File contents are not uploaded.** Full-file upload scanning remains a separate feature that talks directly to VirusTotal and does not go through this proxy.

**Defaults** — identical in `cpp/service/appsettings.json` and `cpp/dist/appsettings.json`:

```jsonc
"ReputationProxy": {
  "Enabled": true,                              // ← on by default
  "BaseUrl": "https://vt.bulwark.icu",          // ← instance run by the project maintainer
  "BearerToken": "",                            // BULWARK_REPPROXY_TOKEN overrides this
  "QueryTimeoutSeconds": 8
}
```

**How to disable** — set `Enabled` to `false`. Hash lookups then fall back entirely to local direct-to-source aggregation; **protection capability does not degrade** (you only lose the shared cache and the server-side keys).

**Failure behaviour** — any failure (proxy disabled / network / HTTP / parse error / no authoritative answer from the server) falls back **transparently** to local direct aggregation. When offline, a client-side circuit breaker skips the hop and half-open-retries every 60s, so you never pay a timeout per query. The server currently aggregates VirusTotal + ThreatBook only; the other four sources are always served locally.

**Self-hosting** — `server/bulwark-broker/broker.py` can be deployed as-is; point `BaseUrl` at your own instance so hashes never leave your infrastructure.

## Intel sources & AI keys (all optional — it works without them)

Cloud reputation, the threat-intel feed and AI research are all **enhancements**: the local heuristics + behavior detection run fine with no keys at all. To enable one, enter its API key on the UI **Settings** page and flip the switch; most sources have a **free tier**.

> ⚠ **The default is not "everything off"**: the shipped `appsettings.json` sets every intel source **and the central reputation service** to `Enabled: true` (see "Code default vs shipped config" above). Sources with no key simply fail and fall back silently, which does not affect protection — but **the central reputation service works without any key of yours**, meaning hashes do go out. For a fully offline setup, explicitly set each `Enabled` to `false`.

> 🔐 **Key safety**: keys you enter are stored only on your machine at `%ProgramData%\Bulwark\settings.json` (or as environment variables) — they are **never written into source, never uploaded, never committed**. Every key field in the `cpp/service/appsettings.json` template is blank. (`cpp/dist/` is a local run directory excluded by `.gitignore` and may contain the developer's own keys — don't distribute it wholesale.)

| Intel / AI source | Purpose | Sign-up | Notes |
|----|------|---------|-------|
| **VirusTotal** | flagship hash reputation (70+ engines) + full-file upload scan | https://www.virustotal.com/ | after signup, get the key under avatar → API Key; free public quota |
| **ThreatBook (微步)** | hash reputation + network IP reputation | https://x.threatbook.com/ | community tier, key in the personal center; low monthly IP-intel quota |
| **MalwareBazaar / ThreatFox** (abuse.ch) | malware-hash lookup + intel feed that auto-generates rules | https://auth.abuse.ch/ | one free Auth-Key, shared by both |
| **AlienVault OTX** | community threat intel (pulses) | https://otx.alienvault.com/ | key under Settings → API; free |
| **MetaDefender Cloud** (OPSWAT) | multi-engine hash reputation | https://metadefender.opswat.com/ | key on the account page; free tier |
| **Hybrid Analysis** | sandbox reputation + behavior profile | https://www.hybrid-analysis.com/ | key under Profile → API key; free |
| **Xiaomi MiMo LLM** | AI behavior research + natural-language rule generation | https://mimo.mi.com/ | log in with a Xiaomi account, apply under Console → API Keys; base URL / model in the `Ai` section of `appsettings.json` |

> Three ways to supply a key (precedence: env var > config file): ① the **UI Settings page** per source (easiest, instant); ② **environment variables** (`BULWARK_VT_APIKEY` / `BULWARK_THREATBOOK_APIKEY` / `BULWARK_MDC_APIKEY` / `BULWARK_OTX_APIKEY` / `BULWARK_HA_APIKEY` / `BULWARK_MB_AUTHKEY` (abuse.ch) / `BULWARK_AI_APIKEY`); ③ the matching field in a local `appsettings.json` — **don't commit a config that contains real keys**.
>
> 🔑 **VirusTotal multi-key / higher quota**: VT accepts several comma-separated keys (e.g. `key1,key2,key3`). **Each key is metered independently and quotas truly stack**; a key that hits rate-limit (429) or fails auth (401) is auto-cooled and skipped. Each key may optionally carry its own limits as `KEY:perDay:perMinute` to mix free and premium, e.g. `freeKey,yourPremiumKey:100000:1000` (unannotated keys use the free-tier defaults, 500/day, 4/min). When running as a (SYSTEM) service, set the env var at **machine scope** — user-scope variables aren't visible to SYSTEM.
>
> ⚠️ VT's terms forbid registering multiple free accounts to bypass limits, and the public API may not be used in commercial products. Multi-key is intended for **Premium / enterprise keys** or keys you legitimately own; for sustained high-volume use, get the VT Premium API.

## Enforcement, quarantine and footprint cleanup

- **Blocking**: the kernel source denies before the action (hard blocks / protected items / network blocklist / self-protection); observation sources can't block first, so `Worker` compensates by **terminating the offending process tree** afterward (with critical-process guards).
- **Quarantine**: confirmed-malicious payloads are XOR-neutralized into a vault (`%ProgramData%\Bulwark\quarantine\`) and the original is deleted (scheduled for reboot-delete if locked); **fully reversible restore**.
- **Footprint cleanup (`ThreatRemediator`)**: for a confirmed-malicious process tree, quarantine its related files in user-writable drop zones and remove registry Run / IFEO / service persistence pointing to the malicious files (taking ownership to force-delete when needed); per-persistence-entry cleanup is also supported (Run value / IFEO / Winlogon / AppInit_DLLs / startup folder / scheduled task / service). Results are shown as a report; unhandled remnants can be retried from the UI.
- **Intel behavior rules**: after confirming malice, IOCs from the reputation behavior profile (dropped files / registry / egress IPs / domains) are turned into deduped proactive block rules and persisted.
- **ECS structured alert export** (toggleable): handled events are formatted into Elastic Common Schema JSON-lines (`event.* / process.code_signature.* / threat.technique[]`, keeping the evidence chain under `bulwark.*`), written to `%ProgramData%\Bulwark\alerts\` for SIEM ingestion.

## Explainability

Every event carries a structured **evidence chain**: each entry records "source analyzer / category (hard indicator · soft signal · corroboration · trust · rule · verdict) / risk-score contribution / description", ending with the final verdict. The behavior prompt renders this as a colored timeline showing "why it was judged this way" rather than a lone score; the same structured data feeds the AI. **Rules support an expiry time and a "this session only" scope** — the prompt's "remember" offers Permanent / Session / 1 hour / 1 day; session rules aren't persisted and timed rules auto-expire, reducing the risk of a one-time choice becoming a permanent false-allow.

## Configuration (the `Bulwark` section of `appsettings.json`)

The config file must sit next to `bulwark_service.exe`; missing keys keep defaults. Intel-source keys can be overridden by environment variables (`BULWARK_VT_APIKEY` / `BULWARK_THREATBOOK_APIKEY`, etc.; env vars take precedence over config fields).

```jsonc
{
  "Bulwark": {
    "EventSource": "Driver",       // Driver = kernel + ETW / Wmi = ETW observation only
    "KernelDriverEnabled": true,   // enable the kernel driver (implied when EventSource = Driver)
    "TrustSignedActors": true,     // auto-allow strongly-trusted signed programs
    "DefaultAction": "Allow",      // default action for no-rule gray zone, and the action taken when a prompt times out
    "PromptTimeoutSeconds": 30,    // prompt timeout in seconds; on timeout the DefaultAction above is applied
    "ExportEcsAlerts": false,      // ECS JSON-lines alert export (SIEM)
    "OnlineCertRevocationCheck": false,  // online cert revocation (default: local cached CRL only, never blocks enrichment)

    "ProtectedPaths": [            // protected paths (substring): kernel delete/rename block / ETW watch set
      "\\Start Menu\\Programs\\Startup\\", "\\System32\\drivers\\etc\\hosts", "\\Tasks\\"
    ],
    "FileHardBlocks": [],          // kernel hard-block files (exact substring): deny all write/del/rename/overwrite-open, read allowed
    "ProtectedRegistryKeys": [     // protected registry keys (substring): Run/RunOnce/IFEO/Winlogon/Services...
      "\\CurrentVersion\\Run", "\\Winlogon", "\\Services\\"
    ],
    "RegistryHardBlocks": [],      // kernel hard-block registry (exact!): kernel-local STATUS_ACCESS_DENIED on hit
    "MemoryProtectionTargets": [ "lsass.exe" ],   // anti-injection targets (kernel strips write-mem/remote-thread rights)
    "BlockedRemoteEndpoints": [],  // network blocklist "ip" or "ip:port" (Driver mode only)

    "Etw": { "Enabled": true, "DnsClient": true, "KernelNetwork": true,
             "KernelRegistry": true, "KernelFile": true,
             "NetworkUntrustedOnly": true, "SuspiciousOnly": true },

    "VirusTotal": { "Enabled": true }, "MalwareBazaar": { "Enabled": true },
    "Otx": { "Enabled": true }, "ThreatBook": { "Enabled": true },
    "MetaDefender": { "Enabled": true }, "HybridAnalysis": { "Enabled": true },
    "ThreatFoxFeed": { "Enabled": true },

    // Central reputation service: ON by default; sends file SHA-256 to this address. See its own section.
    "ReputationProxy": { "Enabled": true, "BaseUrl": "https://vt.bulwark.icu",
                         "BearerToken": "", "QueryTimeoutSeconds": 8 },

    "Ai": { "BaseUrl": "https://token-plan-sgp.xiaomimimo.com/v1", "ApiKey": "", "Model": "mimo-v2.5-pro" }
  }
}
```

> The full default config is in `cpp/service/appsettings.json`. The snippet above is abridged; the following keys **exist in code but are omitted here**: per-source rate limits (`RequestsPerMinute` / `RequestsPerDay`), timeouts and malicious-verdict thresholds; `VirusTotal.PriorityDailyReserve` (daily quota reserved for priority re-verification); the `Etw` section actually has 14 keys (besides the toggles shown: `PerProcessNetPerMinute` / `PerProcessRegPerMinute` / `PerProcessFilePerMinute` / `PerProcessDnsPerMinute` per-process per-minute report caps, `DedupWindowSeconds`, `RawChannelCapacity`, `SessionName`); `ProxyUrl` (global proxy), `TrustedDirectories` (whole-directory trust), and `EnforceUiClientSignature` with `UiClientAllowedThumbprints` / `UiClientAllowedPublishers` (only a UI with the given signature may connect to the pipe — IPC self-protection).
>
> ⚠ **Intel sources and the central reputation service are enabled in the shipped config** (code defaults are off; the config file overrides them). API keys are hot-updatable from the UI or overridable via environment variables. Set `Enabled: false` explicitly for a local-only run.

## Beginner guide (from source to running)

No prior experience needed. Everything here requires **administrator privileges** (real-time monitoring is a system-level capability).

**Step 1 · Install two things**
1. **Visual Studio 2022** (Community is free): during setup, check the "**Desktop development with C++**" workload.
2. **Qt 6.8** (open-source edition is free): in the Qt online installer pick the **MSVC 2022 64-bit** component, default path `C:\Qt\6.8.3\msvc2022_64`.

> You can skip the WDK for a quick try; you only need the **Windows Driver Kit (WDK)** to build the kernel driver.

**Step 2 · Get the code**
```powershell
git clone https://github.com/z614606517zz/-Bulwark.git
cd -Bulwark
```

**Step 3 · Easiest: double-click a one-click script**
Double-click **`一键启动-仅用户态.bat`** in the repo root. It auto-requests administrator, then: build → package to `cpp\dist` → install and start `BulwarkService` → open the UI. **No kernel driver, no test signing, no BSOD risk** — ideal for a first try.
(If the Qt path in the script differs from yours, edit `cpp\scripts\dev-all.ps1`.)

**Step 3 (alternative) · Build manually**
```powershell
cmake -G "Visual Studio 17 2022" -A x64 -S cpp -B cpp\build -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64"
cmake --build cpp\build --config Release
```
The outputs are `cpp\build\service\Release\bulwark_service.exe` and `cpp\build\ui\Release\bulwark_ui.exe`. Run the service first, then the UI, **both as administrator** (`appsettings.json` must sit next to the service exe).

**Step 4 · Use it**
- A **green** status dot at the sidebar bottom ("connected") means you're ready.
- It runs quietly; a suspicious gray-zone action pops a **prompt** to Allow / Block, with an optional "remember" that creates a rule.
- Closing the main window **minimizes to the tray** and keeps protecting; right-click the tray icon to quit.

**Step 5 (optional) · Enable cloud scanning / AI**: enter API keys on the **Settings** page and flip the switches (sign-up links in "Intel sources & AI keys" above). It works without them — you just lose cloud reputation and AI research.

**Step 6 (optional · advanced) · Try kernel "before-the-action" blocking**: ⚠ this enables test signing and loads the kernel driver, and **a faulty callback can BSOD**. Double-click `一键启动.bat` **only inside a snapshotted test VM**, never on your daily machine.

**Troubleshooting**
- **UI stuck on "not connected"**: usually not running as administrator, or the service didn't start. Re-run elevated, or `sc start BulwarkService`.
- **CMake can't find Qt**: make sure `-DCMAKE_PREFIX_PATH` points at your real `Qt\...\msvc2022_64` directory.
- **No events at all**: real-time monitoring (ETW) needs administrator privileges.

## Quick start (one click)

The repo root provides one-click scripts that auto-request administrator and, in order: build → deploy to `cpp\dist` → install and start `BulwarkService` → open the UI.

- **`一键启动-仅用户态.bat`** — recommended for first use. Runs only the user-mode ETW observation pipeline, **does not load the kernel driver, does not touch test signing, no BSOD risk.**
- **`一键启动.bat`** — full pipeline; additionally builds and loads the kernel driver `Bulwark.sys` (enables test signing and requires one reboot). ⚠ **A faulty kernel callback can bluescreen — always run inside a snapshotted test VM.**

Other scripts: `启用驱动.bat` (load the kernel driver separately), `诊断驱动.bat` (driver-load diagnostics → `driver_diag.txt`).

> Requires **Visual Studio 2022 (with the C++ toolchain)** and **Qt 6.8**. The scripts default the Qt path to `C:\Qt\6.8.3\msvc2022_64`; edit `cpp\scripts\dev-all.ps1` to adjust.

## Build and run (development)

Both ETW live observation and the kernel driver need **administrator privileges**.

```powershell
# 1) Configure + build (the top-level CMake builds shared / service / ui together)
cmake -G "Visual Studio 17 2022" -A x64 -S cpp -B cpp\build -DCMAKE_PREFIX_PATH="C:/Qt/6.8.3/msvc2022_64"
cmake --build cpp\build --config Release

# 2) Run the service and UI as administrator (appsettings.json must sit next to bulwark_service.exe)
.\cpp\build\service\Release\bulwark_service.exe   # Terminal 1: service (console debug mode)
.\cpp\build\ui\Release\bulwark_ui.exe             # Terminal 2: UI (manifest already declares requireAdministrator)
```

A green status dot at the top of the UI means it is connected. On real process launches: strongly-trusted-signed ones are auto-allowed and logged; a gray-zone launch with a hard indicator prompts you to Allow / Block, with an optional "remember" + scope that creates a rule. Rules persist at `%ProgramData%\Bulwark\rules.json`.

> A packaged build already exists under `cpp\dist\` (both exes + Qt runtime), runnable directly as administrator. Diagnostic: `bulwark_service.exe --inspect <path>` read-only prints a file's signature / cert profile / hash forensics without starting any monitoring.

## UI features (12 pages)

The sidebar has 12 pages (in this order); a green status dot means connected, and the sidebar footer shows `v1.0.0 · Qt Edition`. Closing the main window minimizes to the system tray and protection keeps running (tray menu: Show / Scan now / Quit).

1. **Dashboard** — protected / disconnected banner, kernel connection status, AI Credits monthly usage, four stat cards ALLOWED / BLOCKED / AI SCANS / TOTAL, a scrolling LIVE LOG.
2. **Intercept log** — deterministic high-risk actions that were blocked outright; double-click an entry to open the "Attack Timeline" and trace the chain.
3. **Activity log** — the fuller event stream (allows / asks / blocks with risk score and verdict text), persisted and backfilled on restart; double-click for the timeline.
4. **Event timeline** — a *query* view over the on-disk history (`events.jsonl`, far deeper than the 500-entry in-memory ring), so you can go back to "what happened around 3pm yesterday". Filter by time window / event type / verdict / minimum risk / PID (optionally the whole process tree) / free text. A dedicated **launch origin** column shows the concrete service or scheduled task behind a host process. Right-click any row to open the attack graph.
5. **Processes** — a process view with forensics and provenance, not a Task Manager clone: launch origin (which *service* is inside that `svchost.exe`, which *scheduled task* spawned this process), signature / publisher / signature-mismatch, static hints (unsigned, user-writable directory, system-process name outside the system directory), memory / threads / session / elevation / user, and user-initiated actions (terminate, terminate tree, suspend, resume, terminate + quarantine image, add to trust). Every action requires an explicit click and a confirmation; the service refuses to touch Bulwark's own components (self-protection) and critical system processes, and always reports *why* an action did not go through.
6. **Rules** — view / manage rules. **+ New rule** (actor auto-recognized as exact path / wildcard / bare file name), **🤖 AI generate** (natural language → 1–5 candidate rules to adopt), refresh / delete; ticking "remember" in a prompt also creates a rule.
7. **Trust** — trusted programs / directories, allowed directly without further detection. **+ Add trust** (pick an executable **or a whole directory**), remove, refresh.
8. **Quarantine** — quarantined threat files. Columns: file / reason / date; **Restore** (back to original) or **Delete** (permanent).
9. **Persistence** — scan to read-only enumerate 7 autostart persistence classes (registry Run/RunOnce, Startup folder, Windows services, scheduled tasks, image hijack IFEO, Winlogon, AppInit_DLLs), each heuristically scored + ATT&CK-annotated, color-coded by risk. **Read-only — never modifies any autostart entry.**
10. **Reputation** — multi-engine hash-reputation center: per-source enable/connection status + test, manual lookup by file/hash, VirusTotal query history; a malicious/suspicious hit auto-opens a behavior-relationship detail window.
11. **AI research** — the LLM judges a file from static features (never executes). Scan & trace / scan file / scan folder / stop; stats SCANNED / CLEAN / SUSPICIOUS / MALICIOUS, results with path + SHA256, verdict, confidence, summary, per-row trace.
12. **Settings** — see below.

**Prompts and notifications:**
- **Behavior prompt** — shown when no rule matches and the actor is untrusted. Shows actor + signature/publisher, command line, target, SHA256, risk factors, evidence-chain highlights, ATT&CK tags; bottom "remember" + scope (Permanent / Session / 1 hour / 1 day) + Allow / Block; a countdown auto-decides per `PromptTimeoutSeconds`; can open the Attack Timeline.
- **Corner toasts** — stacked notifications when a deterministic high-risk action is blocked, or when AI research is triggered.
- **Scan-progress card** — live progress + verdict of a double-click/dropped-payload scan; AI research also finalizes here.
- **Cleanup report** — pops after malicious-footprint cleanup (quarantined / removed persistence / unhandled items with one-click retry).
- **Attack graph** — opened from an intercept / activity / timeline row (right-click), from the Attack Timeline window, or from a process row. Given one event (or one PID) as the seed, the *service* reconstructs the events in that time window into a layered directed graph: nodes are processes / files / registry keys / remote endpoints / domains / modules / **services** / **scheduled tasks**; edges are individual actions carrying time, risk score, verdict and the *real* enforcement outcome. Dashed edges are relations *derived* from process parentage or launch origin, visually distinct from observed events. The correlation lives only in the service (`AttackGraphBuilder`) and the whole graph is shipped to the UI, so what the graph shows can never drift from what the engine actually reasoned over.

### Settings page (all real toggles)

- **Master**: active protection (master switch), default-block unknown behavior (stricter on no-rule gray zone), silent mode (auto-allow ask-events, block only deterministic high-risk).
- **Protection dimensions**: process / file / registry / self-protection / network, each toggleable; memory protection (anti-injection) and its VT re-verify.
- **Decision policy**: auto-trust signed programs, quarantine-on-block.
- **Kernel driver**: enable toggle + connection status / kernel status / current event source.
- **Threat intelligence**: VirusTotal / ThreatBook / MalwareBazaar / OTX / MetaDefender / HybridAnalysis per-source toggle + API key + test connection + ThreatBook network IP-intel toggle.
- **AI / LLM**: AI scan on double-click, suspend process during analysis, block-on-analysis-failure (strict), gray-zone AI consult, credit-budget guard + monthly budget, API base URL / key / model + test.
- **Continuous behavior protection**: user-mode continuous behavior monitor, ransomware canary decoys, behavior-baseline anomaly detection.
- **Scan content limits**: script source cap (KB), binary sample cap (MB), extracted-strings count.

## Install as a Windows service (administrator)

The service ships with its own SCM registration (user-mode service name `BulwarkService`, distinct from the kernel driver service `Bulwark`):

```powershell
.\bulwark_service.exe --install     # register as an auto-start service
sc start BulwarkService             # start
.\bulwark_service.exe --uninstall   # stop and uninstall
```

## Kernel driver (R0): before-the-action interception

`Bulwark.Driver` uses **only Microsoft-documented APIs**, no SSDT hooking (**PatchGuard-friendly**), and is linked with `/INTEGRITYCHECK`. It registers a **Minifilter** that both hooks I/O callbacks and borrows the Filter Manager **communication port** (`FltCreateCommunicationPort` / `FltSendMessage`) to talk to the service; on connect it performs a **protocol handshake** (checks version + every struct size) and user mode refuses to intercept on any mismatch (degrade, never mis-block from a struct-layout drift).

| Dimension | Kernel mechanism | Handling |
|-----------|------------------|----------|
| **Process (M2)** | `PsSetCreateProcessNotifyRoutineEx` + `HashScan.c` | Three paths: (1) **pre-create denial** — the new image is on the "exec-block" list, or the creator itself is in the banned set → `CreationStatus = STATUS_ACCESS_DENIED` right in the callback, so the sample never starts (zero user-mode round trip, no race; lists are re-pushed after reboot and still block); (2) **kernel-local hash scan** — when the known-bad SHA-256 set is non-empty the PID is queued and a dedicated system thread hashes the image at PASSIVE_LEVEL, `ZwTerminateProcess` on a hit; (3) **telemetry + compensation** — everything else is not suspended: report, let user mode decide, terminate the process tree on Block. The kernel allowlists system dirs / critical processes with a zero-latency allow, and critical system processes are **never** subject to pre-create denial (guards against `CRITICAL_PROCESS_DIED`) |
| **File (M3)** | Minifilter pre-op `IRP_MJ_CREATE` (delete-on-close / execute-map intent) + `IRP_MJ_SET_INFORMATION` (rename / dispose) + `IRP_MJ_WRITE` (in-place ransomware-encryption telemetry) | Hard-block list / protected path / no-load list hit → **kernel-local `STATUS_ACCESS_DENIED`** |
| **Registry (M4)** | `CmRegisterCallbackEx` | Exact hard-block hit → **kernel-local deny of set/delete value/key**; protected keys reported asynchronously |
| **Self-protection (M5)** | `ObRegisterCallbacks` | When an untrusted process opens a protected process with dangerous rights (terminate / write-memory / remote-thread / suspend), **those rights are stripped**; anti-injection targets (e.g. lsass.exe) likewise |
| **Network (M6)** | WFP callout (`FWPM_LAYER_ALE_AUTH_CONNECT_V4`) | Outbound connections matching the blocklist → `FWP_ACTION_BLOCK` |

Two more **notification-only** callbacks exist — `PsSetLoadImageNotifyRoutine` (image load) and `PsSetCreateThreadNotifyRoutine` (remote thread) — used for reporting only (a callback can't block a load; "no-load" is enforced via M3's execute-map interception).

**Handling model (stability first)**: hot paths **never do synchronous IPC** — `FltSendMessage` uses a 0 timeout and never blocks on a user-mode verdict; a background sender thread with a preallocated ring buffer does the sending (queue full → drop telemetry). Within that constraint, kernel handling splits in two:

- **Kernel-local immediate block (no user mode required)**: file / registry hard blocks, the no-load list, the process "exec-block" list, banned-actor child creation, self-protection, anti-injection / anti-credential-dump, and the network blocklist. These are decided entirely in kernel and **stay in force when the service is not installed, not started, or has been killed** — `ProcessMonitor.c` deliberately evaluates banned actors and exec-block *before* the "no client → fast allow" shortcut, and the lists are persisted to the registry and re-pushed after reboot. This is the driver's self-sufficient baseline.
- **Telemetry + compensating kill**: gray-zone process creations that match none of those local lists are reported, decided by user mode, and on Block the whole process tree is terminated (user mode enumerates descendants first, then a kernel-level `ZwTerminateProcess` on the root PID as a backstop).

Protected paths/keys, hard-block lists, the exec-block list, the known-bad hash set, protected process PIDs, anti-injection targets and the network blocklist are all pushed down from user mode via config messages.

```powershell
# 1) Build the driver (a local WDK is enough)
.\scripts\build-driver.ps1 -Configuration Debug   # produces build\driver\Debug\Bulwark.sys
# 2) Load ONLY inside a [snapshotted test VM] (a faulty callback will BSOD!)
.\scripts\deploy-driver-vm.ps1                    # enable test signing / create test cert / sign / install / start
# 3) Set EventSource to "Driver" in appsettings.json, run the service + UI as administrator
```

## Protection milestones

| Milestone | Dimension | Key kernel mechanism (all Microsoft-documented APIs) | Status |
|-----------|-----------|------------------------------------------------------|--------|
| M2 | Process | `PsSetCreateProcessNotifyRoutineEx` | ✅ Implemented |
| M3 | File | Minifilter I/O callbacks (`IRP_MJ_CREATE` / `IRP_MJ_SET_INFORMATION` / `IRP_MJ_WRITE`) | ✅ Implemented |
| M4 | Registry | `CmRegisterCallbackEx` | ✅ Implemented |
| M5 | Self-protection / anti-injection | `ObRegisterCallbacks` | ✅ Implemented |
| M6 | Network | WFP (`ALE_AUTH_CONNECT_V4` blocklist) | ✅ Implemented |

> The driver requires a digital signature: during development enable test signing (`bcdedit /set testsigning on`) + a test VM; a production release needs an EV certificate + WHQL/attestation signing. Always debug inside a snapshotted VM — a faulty callback can cause a BSOD.

## Security note

This project is a legitimate endpoint security tool (in the same category as antivirus / EDR). Self-protection always keeps a normal, user-controllable uninstall path and is never made "impossible to remove".
