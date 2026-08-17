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

## Trust direction, and which key lives where

- `23 -> 245`: private key `id_bulwark_node245` lives on **23**. A 245 reinstall
  does not destroy it; only 245's `authorized_keys` entry needs restoring.
- `245 -> 23`: private key `id_sync23` lives on **245** and IS destroyed by a
  reinstall. Generate a new pair and replace the corresponding line in 23's
  `authorized_keys`, keeping the forced command:

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
