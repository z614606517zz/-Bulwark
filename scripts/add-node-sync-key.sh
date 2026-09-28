#!/bin/bash
# Runs ON the master. Installs a collector node's sync public key into root's
# authorized_keys, wrapped in the forced command that keeps it from being a shell.
#
# Why this is a script instead of "paste the key into the file": the line has to
# carry `restrict` and `command="..."`. A bare public key looks almost identical on
# the page and grants a full root shell to whoever holds the private half. That
# difference is invisible at a glance and total in effect, so it is not left to
# whoever is doing the pasting.
#
#   Usage:  add-node-sync-key.sh 'ssh-ed25519 AAAA... comment'
#           add-node-sync-key.sh --file /path/to/<node-sync-key>.pub
set -u
WRAPPER=/usr/local/sbin/bulwark-ingest-wrapper.sh
AK=/root/.ssh/authorized_keys
COMMENT_TAG=bulwark-node-sync
fail() { echo "FAIL: $*" >&2; exit 1; }

if [ "${1:-}" = "--file" ]; then
  [ -f "${2:-}" ] || fail "need a readable file"
  KEY=$(cat "$2")
else
  KEY=${1:-}
fi
[ -n "$KEY" ] || fail "usage: $0 'ssh-ed25519 AAAA... comment'  |  $0 --file key.pub"

# Validate before anything touches authorized_keys. A malformed line does not just
# fail to work: sshd rejects the whole file, which locks out every key at once.
#
# Order matters, and not for correctness -- for the diagnosis. An input that already
# carries `restrict,command=...` fails the key-type test too, so if that test ran
# first the message would say "not a public key" about something that IS one. That
# sends the reader off to regenerate a key when all they had to do was drop the
# prefix. Check the specific, recognisable mistake first.
case "$KEY" in
  *"
"*) fail "refusing a multi-line value -- one key per run" ;;
  *command=*|*restrict*) fail "pass the BARE public key; this script adds the options" ;;
esac
case "$KEY" in
  ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*\ *) : ;;
  *) fail "does not look like an SSH public key (must start with a key type)" ;;
esac
[ -x "$WRAPPER" ] || fail "$WRAPPER missing or not executable"

install -d -m 700 /root/.ssh
touch "$AK"
chmod 600 "$AK"
cp -p "$AK" "$AK.bak.$(date +%s)"

FP=$(printf '%s\n' "$KEY" | ssh-keygen -lf - 2>/dev/null) || fail "not a valid key"
echo "=== key ==="
echo "  $FP"
echo

# Match on type+blob only, ignoring the trailing comment: re-running this after a
# node regenerates its key must replace the line, not accumulate a second one with
# possibly different options.
BODY=$(printf '%s' "$KEY" | awk '{print $1" "$2}')
if grep -qF "$BODY" "$AK"; then
  echo "already present -- dropping the old line so the options cannot drift"
  grep -vF "$BODY" "$AK" > "$AK.tmp" && mv "$AK.tmp" "$AK"
  chmod 600 "$AK"
fi

printf 'restrict,command="%s" %s %s\n' "$WRAPPER" "$BODY" "$COMMENT_TAG" >> "$AK"

echo "=== authorized_keys now ==="
# Options and comment only; the key blob adds nothing worth reading.
awk '{printf "  %-72s ... %s\n", substr($1,1,72), $NF}' "$AK"
echo

echo "=== sanity: sshd still accepts the file ==="
sshd -t && echo "  sshd -t OK" || fail "sshd -t failed -- authorized_keys is broken"
echo
echo "Test from the node:"
echo "  ssh -i /root/.ssh/<node-sync-key> root@<this-host> export-ledger"
echo "A forced-command channel answers with the wrapper's output, never a prompt."
echo
echo "DONE"
