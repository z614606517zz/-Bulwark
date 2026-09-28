#!/bin/bash
# Runs ON the master. Issues the Let's Encrypt certificate and switches
# bulwark-intel from plain HTTP to in-process TLS.
#
# Written while rebuilding the master on a fresh host (2026-09-01). Each step below
# exists because of something that is easy to get wrong and hard to notice
# afterwards; the reasoning is kept inline rather than in a runbook nobody opens.
#
#   Usage:  enable-master-tls.sh [domain]
#           BW_ACME_EMAIL=you@example.com enable-master-tls.sh
set -u
DOMAIN=${1:-vt.bulwark.icu}
CONF=/etc/bulwark-intel/config.json
fail() { echo "FAIL: $*" >&2; exit 1; }

echo "=== 1) does $DOMAIN actually point at this host? ==="
# Checked first, and treated as fatal. The HTTP-01 challenge is fetched over the
# public name, so a stale A record does not merely fail -- it spends a real attempt
# against the ACME account's failure quota while validating some other machine.
MYIP=$(curl -s --max-time 15 https://api.ipify.org || true)
[ -n "$MYIP" ] || MYIP=$(hostname -I | awk '{print $1}')
RESOLVED=$(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u | tr '\n' ' ')
echo "  this host        : $MYIP"
echo "  $DOMAIN -> ${RESOLVED:-(does not resolve)}"
case " $RESOLVED " in
  *" $MYIP "*) echo "  match" ;;
  *) fail "$DOMAIN does not resolve to this host yet -- update the A record first" ;;
esac
echo

echo "=== 2) port 80 has to be free for the standalone challenge ==="
# app.py listens on 8787, so 80 is normally free. Checked anyway because certbot's
# bind failure reads like a firewall problem and sends you looking in the wrong place.
if ss -ltn | awk '{print $4}' | grep -qE '(^|:)80$'; then
  ss -ltnp | grep -E '(^|:)80\b'
  fail "something is already listening on port 80"
fi
echo "  free"
echo

echo "=== 3) issue the certificate ==="
if [ -n "${BW_ACME_EMAIL:-}" ]; then
  MAILARG="-m $BW_ACME_EMAIL --no-eff-email"
else
  MAILARG="--register-unsafely-without-email"
  echo "  (no BW_ACME_EMAIL: registering without an address, so there will be no"
  echo "   expiry reminders if automatic renewal ever silently stops)"
fi
certbot certonly --standalone --non-interactive --agree-tos $MAILARG \
        --preferred-challenges http -d "$DOMAIN" || fail "certbot failed"
LIVE=/etc/letsencrypt/live/$DOMAIN
[ -f "$LIVE/fullchain.pem" ] || fail "$LIVE/fullchain.pem missing after issuance"
echo
openssl x509 -in "$LIVE/fullchain.pem" -noout -subject -dates -issuer | sed 's/^/  /'
echo

echo "=== 4) let bulwarkintel read the private key ==="
# app.py terminates TLS in-process and runs as bulwarkintel -- there is no nginx to
# read the key as root. certbot's default 0700 on live/ and archive/ makes the key
# unreadable to that account, and the service then fails to start with a bare
# PermissionError that says nothing about certbot. Group-read on those two
# directories is the narrowest fix.
chgrp -R bulwarkintel /etc/letsencrypt/live /etc/letsencrypt/archive
chmod g+rX /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rX /etc/letsencrypt/live/"$DOMAIN" /etc/letsencrypt/archive/"$DOMAIN"
ls -la "$LIVE"/ | sed 's/^/  /'
echo

echo "=== 5) point config.json at the cert AND flip harvest to https ==="
# Both in the same edit, deliberately. harvest.py defaults to https://127.0.0.1:8787;
# against a plain-HTTP listener every lookup dies with SSL: WRONG_VERSION_NUMBER, and
# the reverse (http:// against a TLS listener) fails just as silently. The two values
# describe one fact -- what scheme this host speaks -- so they move together.
python3 - "$CONF" "$LIVE" <<'PY'
import json, shutil, sys, time
conf, live = sys.argv[1], sys.argv[2]
shutil.copy2(conf, conf + ".bak-" + time.strftime("%Y%m%d-%H%M%S"))
d = json.load(open(conf, encoding="utf-8"))
d["tls_cert"] = live + "/fullchain.pem"
d["tls_key"] = live + "/privkey.pem"
h = d.setdefault("harvest", {})
h["service_url"] = "https://127.0.0.1:8787"
json.dump(d, open(conf, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("  tls_cert            =", d["tls_cert"])
print("  tls_key             =", d["tls_key"])
print("  harvest.service_url =", h["service_url"])
PY
chown root:bulwarkintel "$CONF"
chmod 640 "$CONF"
echo

echo "=== 6) restart and verify over TLS ==="
systemctl restart bulwark-intel.service
sleep 4
systemctl is-active bulwark-intel.service
journalctl -u bulwark-intel -n 8 --no-pager -o cat | sed 's/^/  /'
echo
echo "  --- loopback, cert intentionally not verified (127.0.0.1 never matches) ---"
curl -sk --max-time 15 https://127.0.0.1:8787/health; echo
echo "  --- through the public name, FULL verification ---"
# This is the check that matters: shipped clients leave SelfHostedTls empty, which
# means they validate against the public CA store. If this line passes, they work.
curl -s --max-time 20 "https://$DOMAIN:8787/health"; echo
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "https://$DOMAIN:8787/health")
[ "$code" = "200" ] || fail "https through $DOMAIN returned $code"
echo "  verified: a client doing ordinary public-CA validation can reach this host"
echo

echo "=== 7) renewal has to restart the service ==="
# app.py reads the cert once at startup. Without this hook the renewal succeeds on
# disk and the process keeps presenting the old chain -- so the failure surfaces
# ~90 days later as an expired certificate, with a renewal log full of successes.
install -d -m 755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/10-bulwark-intel.sh <<'EOF'
#!/bin/sh
# TLS terminates inside app.py, so a renewed cert only takes effect on restart.
set -e
chgrp -R bulwarkintel /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
systemctl restart bulwark-intel.service
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/10-bulwark-intel.sh
echo "  hook installed"
systemctl list-timers 'certbot*' --no-pager | sed 's/^/  /'
echo
echo "  --- dry-run the whole renewal path, hook included ---"
certbot renew --dry-run 2>&1 | tail -8 | sed 's/^/  /'
echo
echo "DONE"
