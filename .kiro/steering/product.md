# Product Overview

**Bulwark (磐垒主动防御)** is a Host-based Intrusion Prevention System (HIPS) for Windows, comparable in category to antivirus/EDR products.

## Core Idea

Monitor sensitive system behavior → rule engine decides → prompt the user for a verdict when needed (Allow / Block / Remember).

## How It Works

1. A monitoring layer captures sensitive behaviors (process creation, remote thread injection, image/driver load, file write/delete, registry writes, network egress, self-protection events).
2. The `RuleEngine` (decision center) evaluates each event and produces a `Verdict`.
3. Decision priority is a **pipeline**, not a three-way choice, and the trust channels come **before** rule matching. Actual order in `RuleEngine::evaluateInternal`:
   1. unconditional allow — own components, user-trusted files/folders;
   2. installed third-party security products (coexistence allow);
   3. known-benign vendor apps (IM clients) — **network/DNS events only**, to stop periodic keep-alive traffic being scored as C2 beaconing. Deliberately scoped: it must **not** exempt other event types, or the rules targeting IM sideloading / group-control hook-module loads get bypassed;
   4. `ThreatDetector::analyze` — threat score + hard malicious indicators;
   5. stateful temporal detectors (ransomware / beacon / DGA / egress rate);
   6. behavioural-baseline deviation (soft signal only);
   7. **explicit rules** (tier > specificity > action strength > recency);
   8. strongly-trusted actor allow;
   9. certificate anomalies (revoked / signed after expiry) → Block;
   10. healthy-signature allow;
   11. hard-indicator gate: score >= high-risk → Block, else → Ask;
   12. no hard indicator → allow.

   Consequence worth remembering: writing a Block rule does **not** override steps 1–3. A rule can only take effect if the event reaches step 7.
4. When no rule applies and the actor is untrusted, the UI shows a behavior prompt; the user can choose Allow/Block and optionally persist the choice as a rule.

## Two Switchable Event Sources

Configured via `EventSource` in `appsettings.json`:
- **Driver** — kernel-mode interception (true pre-action blocking; covers process/file/registry/self-protection/network milestones M2–M6). The driver keeps a **self-sufficient baseline**: hard-block lists, the process "exec-block" list, banned-actor child denial, self-protection and the local known-bad SHA-256 set are all decided in kernel and stay in force even when the user-mode service is not running. Hot paths never do synchronous IPC (`FltSendMessage` with 0 timeout).
- **Wmi** — user-mode observation (cannot block before the action; blocking is compensated by terminating the actor).

## Design Principles

- **Only act on genuinely dangerous behavior.** "Soft signals" alone (unsigned, runs from a suspicious path, first-seen on this machine, recently-issued cert) never trigger a block or prompt; they only raise score and require corroboration (mutual-evidence) from a hard indicator.
- **Minimize false positives / user nagging.** Healthy, trusted-signed actors are allowed without prompting.
- **Self-protection must stay user-controllable.** This is a legitimate security tool — it always keeps a normal, user-driven uninstall path and is never made "impossible to remove."
