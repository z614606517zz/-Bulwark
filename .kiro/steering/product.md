# Product Overview

**Bulwark (磐垒主动防御)** is a Host-based Intrusion Prevention System (HIPS) for Windows, comparable in category to antivirus/EDR products.

## Core Idea

Monitor sensitive system behavior → rule engine decides → prompt the user for a verdict when needed (Allow / Block / Remember).

## How It Works

1. A monitoring layer captures sensitive behaviors (process creation, remote thread injection, image/driver load, file write/delete, registry writes, network egress, self-protection events).
2. The `RuleEngine` (decision center) evaluates each event and produces a `Verdict`.
3. Decision priority: matched rule → threat score / hard malicious indicators → strongly-trusted signature → default policy.
4. When no rule applies and the actor is untrusted, the UI shows a behavior prompt; the user can choose Allow/Block and optionally persist the choice as a rule.

## Three Switchable Event Sources

Configured via `EventSource` in `appsettings.json`:
- **Driver** — kernel-mode interception (true pre-action blocking; covers process/file/registry/self-protection/network milestones M2–M6).
- **Wmi** — user-mode observation (cannot block before the action; blocking is compensated by terminating the actor).
- **Simulated** — demo mode, no real-system monitoring.

## Design Principles

- **Only act on genuinely dangerous behavior.** "Soft signals" alone (unsigned, runs from a suspicious path, first-seen on this machine, recently-issued cert) never trigger a block or prompt; they only raise score and require corroboration (mutual-evidence) from a hard indicator.
- **Minimize false positives / user nagging.** Healthy, trusted-signed actors are allowed without prompting.
- **Self-protection must stay user-controllable.** This is a legitimate security tool — it always keeps a normal, user-driven uninstall path and is never made "impossible to remove."
