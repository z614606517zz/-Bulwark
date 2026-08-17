#!/bin/sh
# Forced command for the satellite sync key in root's authorized_keys:
#   restrict,command="/usr/local/sbin/bulwark-ingest-wrapper.sh" ssh-ed25519 ...
# That key therefore cannot get a shell; it can only reach the three actions below.
#
# The requested action arrives in SSH_ORIGINAL_COMMAND. It is matched exactly and
# never interpolated into a command line, so a satellite cannot turn it into
# arbitrary execution. Every branch drops to bulwarkintel first -- root must not
# write cache.db, or the journal file ends up root-owned and app.py's next write
# fails.
#
# Order matters: the catch-all '*' branch is the vt_reports ingest (the pusher
# sends that payload with no command at all), so any NAMED action has to be
# matched before it or it would be swallowed.
case "$SSH_ORIGINAL_COMMAND" in
  export-ledger)
    exec /usr/sbin/runuser -u bulwarkintel -- /usr/bin/python3 /usr/local/sbin/bulwark-ledger-export.py
    ;;
  ingest-benign)
    # Quarantine-cleared white samples from a collector node. Separate script and
    # separate table from the threat ingest: benign_reports is the attack-chain
    # engine's negative control, and mixing the two would corrupt both the threat
    # counters and the corpus.
    exec /usr/sbin/runuser -u bulwarkintel -- /usr/bin/python3 /usr/local/sbin/bulwark-ingest-benign.py
    ;;
  *)
    exec /usr/sbin/runuser -u bulwarkintel -- /usr/bin/python3 /usr/local/sbin/bulwark-ingest.py
    ;;
esac
