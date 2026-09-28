# Collector node setup notes

Hard-won details that a fresh OS install silently drops. Everything here was
discovered by rebuilding node 245 from scratch after a reinstall wiped it.

## The service account needs a group, not just a user

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin bulwarkintel
usermod -aG systemd-journal bulwarkintel        # <-- easy to forget
```

`dashboard.py` builds its "today" counters by shelling out to `journalctl` and
parsing harvest's `done {...}` lines. Without `systemd-journal` membership that
call returns rc=1 and zero lines, so every page renders `looked=0`,
`vt_calls=0`, `vt_left=None` while the harvester is in fact working perfectly.
The dashboard shows no error for this -- the numbers are simply, quietly wrong,
which is worse than a visible failure.

## harvest.py's service_url default assumes the node terminates TLS

`harvest.py` defaults to `https://127.0.0.1:8787`. That is correct on the
master (23), which holds a real Let's Encrypt cert for its public domain. A
collector node that only ever talks to its own loopback `app.py` has no reason
to hold a cert, so `tls_cert`/`tls_key` are left empty there and `app.py`
falls back to plain HTTP -- at which point the https default fails every
lookup with `SSL: WRONG_VERSION_NUMBER`.

Set this explicitly in a collector node's `config.json`:

```json
"harvest": { "service_url": "http://127.0.0.1:8787" }
```

Do NOT "fix" this by editing harvest.py: it is byte-identical across nodes on
purpose, and the https default is right for the master.

## Reinstalls change the SSH host key, the IP, and sshd defaults

- Clear the stale host key on the master: `ssh-keygen -f ~/.ssh/known_hosts -R <ip>`
- A reinstall may hand out a **new public IP**; `bulwark-sync.py`'s
  `BULWARK_MASTER` and the master's `authorized_keys` comment both need review.
- This provider's image ships `PubkeyAuthentication no` in `/etc/ssh/sshd_config`.
  Pushing a key appears to succeed and then login still fails with
  `Permission denied (publickey)` even though perms/ownership are correct,
  because the server never offers the pubkey method at all. Flip it to `yes`
  and reload sshd.

## The master itself can be the thing that disappears

On 2026-09-01 the master was lost outright (billing lapsed, instance reclaimed) --
not reinstalled, gone. Everything below was written assuming the master is the
stable end of the pair, and that assumption is what hurt:

- The **only** copy of `<node-access-key>` lived on the master, so losing the
  master also lost shell access to the node. The node kept running and kept
  serving its dashboard on `<dashboard-port>`, but nothing could log into it.
  There is no HTTP route on the node that can change configuration (the
  dashboard's only writes are sample submit and the VT-key endpoints), so
  `BULWARK_MASTER` cannot be repointed remotely -- it needs the provider's console.
- Lesson: keep a second copy of the node-access key somewhere that does not share
  a failure domain with the master, and treat "can I still reach the node if the
  master dies right now?" as a thing to check, not assume.

Moving to a replacement master touches exactly two kinds of address:

- **Everything client-facing** goes through the public domain, and the Let's Encrypt
  cert is issued for that name, so the DNS A record is the single switch that moves
  the whole fleet. Do not rewrite those call sites to an IP: a bare IP cannot hold a
  publicly trusted certificate, so hardcoding one turns every client lookup into a
  TLS verification failure.
- **The node's push target** is SSH, not HTTPS, so it uses a bare IP and must be set
  per-machine in a drop-in (see `bulwark-sync.service` for the exact path). It is
  deliberately absent from the tracked unit file.

## Trust direction, and which key lives where

- `master -> 245`: private key `<node-access-key>` lives on the **master**. A 245
  reinstall does not destroy it; only 245's `authorized_keys` entry needs
  restoring. Losing the *master*, however, destroys it -- see above.
- `245 -> master`: private key `<node-sync-key>` lives on **245** and IS destroyed by a
  reinstall. Generate a new pair and replace the corresponding line in the
  master's `authorized_keys`, keeping the forced command:

```
restrict,command="/usr/local/sbin/bulwark-ingest-wrapper.sh" ssh-ed25519 AAAA... bulwark-245-sync-to-23
```

Remove the old node's line at the same time; a wiped node's key is dead weight
that still grants ingest access if the private half ever leaked.

## Unit wiring

`bulwark-sync.service` is deliberately **not** enabled and has no timer. It runs
only via `OnSuccess=bulwark-sync.service` on `bulwark-harvest.service`, so a
harvest that systemd killed on timeout (marked failed) never pushes a partial
batch. Keep the ordering `max_run_seconds` < `TimeoutStartSec` < timer interval,
currently 1500s < 2400s < 3600s.
