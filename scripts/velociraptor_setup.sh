#!/usr/bin/env bash
# Compensated Anarchist - Velociraptor server setup.
#
# Copy this file to the Velociraptor SERVER and run it as root:
#     sudo ./velociraptor_setup.sh --harness-ip <ip of the Compensated Anarchist host> [--admin]
#
# It sets up everything the harness's Velociraptor connector needs:
#   1. finds the installation (service, binary, config, service user) from systemd
#   2. creates the API client config(s): `canarchist` (investigator,api) and, with --admin, `canarchist_admin`
#      (administrator,api - evidence download, quarantine, server VQL)
#   3. makes the API listen on an address the harness can reach, and allows TCP to it from the harness host
#      ONLY (firewalld / ufw; otherwise it tells you which network rule to add)
#   4. restarts the server so it loads the new API users, then verifies each key with a read-only query
#   5. prints a report (no secrets), including a ready-to-paste scope block for the harness's roe.local.yaml
#
# Safety: it asks before every change (unless --yes), backs up server.config.yaml first, never prints key
# contents, never touches clients, hunts or artifacts, and has --dry-run. Key files are written root-only (600).
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./velociraptor_setup.sh --harness-ip IP [options]

Required:
  --harness-ip IP        the Compensated Anarchist host that will connect to this server's API

Options:
  --admin                also create the administrator key (evidence download, quarantine, server VQL).
                         Powerful: server VQL can run commands on this server. Leave it out unless needed.
  --name NAME            API user name (default: canarchist; the admin user is NAME_admin)
  --api-address ADDR     address the harness uses to reach this server (default: this server's IP on the
                         route to the harness host)
  --bind ADDR            API listen address (default: the --api-address; 0.0.0.0 = all interfaces)
  --out DIR              where the key files are written (default: /root/canarchist-keys, mode 700)
  --deliver DEST         copy the key files to the harness when done, e.g.
                         analyst@10.20.0.15:/home/analyst/compensatedanarchist/config/secrets/
  --service NAME         systemd service (default: discovered, usually velociraptor_server)
  --binary PATH          velociraptor binary (default: from the service's ExecStart)
  --config PATH          server.config.yaml (default: from the service's ExecStart)
  --user NAME            user the server runs as (default: the service's User=)
  --no-firewall          do not touch the host firewall
  --no-restart           do not restart the server (new API users only work after a restart)
  --dry-run              show what would be done; change nothing
  -y, --yes              do not ask for confirmation
  -h, --help             this help
EOF
}

HARNESS_IP="" ADMIN=0 NAME="canarchist" API_ADDR="" BIND="" OUT="/root/canarchist-keys" DELIVER=""
SVC="" BIN="" CFG="" SVC_USER="" NO_FW=0 NO_RESTART=0 DRY=0 YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --harness-ip) HARNESS_IP="$2"; shift 2 ;;
    --admin) ADMIN=1; shift ;;
    --name) NAME="$2"; shift 2 ;;
    --api-address) API_ADDR="$2"; shift 2 ;;
    --bind) BIND="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --deliver) DELIVER="$2"; shift 2 ;;
    --service) SVC="$2"; shift 2 ;;
    --binary) BIN="$2"; shift 2 ;;
    --config) CFG="$2"; shift 2 ;;
    --user) SVC_USER="$2"; shift 2 ;;
    --no-firewall) NO_FW=1; shift ;;
    --no-restart) NO_RESTART=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' D=$'\033[2m' X=$'\033[0m'; else B="" G="" Y="" R="" D="" X=""; fi
step() { printf '\n%s== %s%s\n' "$B" "$*" "$X"; }
ok()   { printf '  %sok%s   %s\n' "$G" "$X" "$*"; }
warn() { printf '  %swarn%s %s\n' "$Y" "$X" "$*"; }
info() { printf '  %s%s%s\n' "$D" "$*" "$X"; }
die()  { printf '%serror:%s %s\n' "$R" "$X" "$*" >&2; exit 1; }
confirm() { [ "$YES" = 1 ] && return 0; [ "$DRY" = 1 ] && return 0; read -r -p "  $1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }
run() { if [ "$DRY" = 1 ]; then printf '  %s[dry-run]%s %s\n' "$D" "$X" "$*"; else "$@"; fi; }
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

[ -n "$HARNESS_IP" ] || { usage; die "--harness-ip is required"; }
is_ipv4 "$HARNESS_IP" || die "--harness-ip must be an IPv4 address"
[[ "$NAME" =~ ^[A-Za-z0-9_.-]+$ ]] || die "--name may only contain letters, digits, _ . -"
umask 077
TMP="$(mktemp -d)"
cleanup() { [ -d "$TMP" ] && { find "$TMP" -type f -exec shred -u {} + 2>/dev/null || true; rm -rf "$TMP"; }; }
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------------------------
step "1. Find the Velociraptor installation (read-only)"
if [ -z "$SVC" ]; then
  SVC="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -i velociraptor | grep -vi client | head -1 || true)"
fi
if [ -z "$BIN" ] || [ -z "$CFG" ]; then
  [ -n "$SVC" ] || die "no Velociraptor server service found - pass --service, or --binary and --config"
  argv="$(systemctl show -p ExecStart --value "$SVC" 2>/dev/null | sed -n 's/.*argv\[\]=\([^;]*\);.*/\1/p' | head -1)"
  [ -n "$BIN" ] || BIN="$(awk '{print $1}' <<<"$argv")"
  [ -n "$CFG" ] || CFG="$(sed -n 's/.*--config[= ]\([^ ]*\).*/\1/p' <<<"$argv")"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || die "velociraptor binary not found ('$BIN') - pass --binary"
[ -n "$CFG" ] && [ -f "$CFG" ] || die "server config not found ('$CFG') - pass --config"
if [ -z "$SVC_USER" ]; then SVC_USER="$(systemctl show -p User --value "$SVC" 2>/dev/null || true)"; fi
SVC_USER="${SVC_USER:-root}"
ME="$(id -un)"
if [ "$(id -u)" -ne 0 ] && [ "$SVC_USER" != "$ME" ]; then die "run as root (sudo): the API users must be created as '$SVC_USER'"; fi
as_svc() {
  if [ "$ME" = "$SVC_USER" ]; then "$@"
  elif command -v runuser >/dev/null 2>&1; then runuser -u "$SVC_USER" -- "$@"
  else sudo -u "$SVC_USER" -- "$@"; fi
}
api_get() {  # value of a key inside the top-level API: block of server.config.yaml
  awk -v key="$1" '/^API:/{a=1; next} a && /^[^ \t#]/{a=0} a && $1==key":" {sub(/^[^:]*:[ \t]*/, ""); gsub(/["\047]/, ""); print; exit}' "$CFG"
}
VERSION="$("$BIN" version 2>/dev/null | awk -F': *' '/^version:/{print $2; exit}')"
BIND_CUR="$(api_get bind_address)"
PORT="$(api_get bind_port)"; PORT="${PORT:-8001}"
SCHEME="$(api_get bind_scheme)"
[ "${SCHEME:-tcp}" = "tcp" ] || die "the API listens on bind_scheme '$SCHEME', not tcp - the harness needs tcp; change it by hand"
ROUTE="$(ip -4 route get "$HARNESS_IP" 2>/dev/null | head -1 || true)"
IFACE="$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<<"$ROUTE")"   # the interface that reaches the harness (firewall zone)
[ -n "$API_ADDR" ] || API_ADDR="$(sed -n 's/.* src \([0-9.]*\).*/\1/p' <<<"$ROUTE")"
[ -n "$API_ADDR" ] || die "could not work out this server's address towards $HARNESS_IP - pass --api-address"
[ -n "$BIND" ] || BIND="$API_ADDR"
INV="$NAME" ADM="${NAME}_admin"
ok "Velociraptor ${VERSION:-unknown version}; service ${SVC:-(not managed by systemd)} runs as $SVC_USER"
ok "binary $BIN, config $CFG"
ok "API now listens on ${BIND_CUR:-?}:$PORT"

cat <<EOF

  Plan:
    - back up $CFG
    - create API key '$INV' (investigator,api)$( [ "$ADMIN" = 1 ] && echo " and '$ADM' (administrator,api)") in $OUT
    - API listen address: ${BIND_CUR:-?} -> $BIND (port $PORT)$( [ "$BIND_CUR" = "$BIND" ] && echo " (no change)")
    - allow TCP $PORT from $HARNESS_IP only$( [ "$NO_FW" = 1 ] && echo " (skipped: --no-firewall)")
    - restart ${SVC:-the server} so it loads the new API users$( [ "$NO_RESTART" = 1 ] && echo " (skipped: --no-restart)")
    - point the key files at $API_ADDR:$PORT and verify them with read-only queries
EOF
case "$BIND_CUR" in
  127.*|localhost|::1)
    if [ "$BIND" != "$BIND_CUR" ] && [ "$BIND" != "0.0.0.0" ]; then
      warn "programs on this server that reach the API at $BIND_CUR:$PORT (other API clients, scripts) will stop"
      info "     reaching it. To keep them working, use --bind 0.0.0.0 (the firewall rule still limits who can connect)."
    fi ;;
esac
[ "$DRY" = 1 ] && info "dry run: nothing will be changed"
confirm "Proceed?" || die "aborted - nothing changed"

# ---------------------------------------------------------------------------------------------------------------
step "2. Back up the server config"
BACKUP="$CFG.bak.$(date +%Y%m%d%H%M%S)"
run cp -a "$CFG" "$BACKUP"
ok "backup: $BACKUP"

# ---------------------------------------------------------------------------------------------------------------
step "3. Create the API key(s)"
run install -d -m 700 "$OUT"
[ "$ME" = "$SVC_USER" ] || run chown "$SVC_USER" "$TMP"
make_key() {  # name role
  local n="$1" role="$2" dest="$OUT/$1.api.yaml"
  if [ -e "$dest" ] && ! confirm "$dest exists - issue a new key for '$n' and replace the file?"; then
    warn "kept existing $dest"; return 0
  fi
  run as_svc "$BIN" --config "$CFG" config api_client --name "$n" --role "$role" "$TMP/$n.api.yaml"
  run install -m 600 "$TMP/$n.api.yaml" "$dest"
  run shred -u "$TMP/$n.api.yaml"
  ok "$n ($role) -> $dest"
}
make_key "$INV" "investigator,api"
[ "$ADMIN" = 1 ] && make_key "$ADM" "administrator,api"

# ---------------------------------------------------------------------------------------------------------------
step "4. API listen address"
BIND_CHANGED=0
if [ "$BIND_CUR" = "$BIND" ]; then
  ok "already listening on $BIND"
else
  grep -q '^API:' "$CFG" && [ -n "$BIND_CUR" ] || die "no API: bind_address in $CFG - set it by hand (backup: $BACKUP)"
  if confirm "Change API bind_address from $BIND_CUR to $BIND in $CFG?"; then
    awk -v b="$BIND" '/^API:/{a=1; print; next} a && /^[^ \t#]/{a=0}
      a && $1=="bind_address:" {match($0, /^[ \t]*/); print substr($0, 1, RLENGTH) "bind_address: " b; next} {print}' \
      "$CFG" > "$TMP/server.config.yaml"
    run sh -c 'cat "$1" > "$2"' _ "$TMP/server.config.yaml" "$CFG"   # keeps the file's owner and mode
    [ "$DRY" = 1 ] || [ "$(api_get bind_address)" = "$BIND" ] || die "edit did not apply - restore $BACKUP"
    BIND_CHANGED=1
    ok "bind_address: $BIND"
  else
    warn "left bind_address at $BIND_CUR - the harness cannot connect unless it is reachable"
  fi
fi

# ---------------------------------------------------------------------------------------------------------------
step "5. Firewall: TCP $PORT from $HARNESS_IP only"
FW="none"
if [ "$NO_FW" = 1 ]; then
  warn "skipped (--no-firewall)"; FW="skipped"
elif systemctl is-active -q firewalld 2>/dev/null; then
  # the zone of the interface that reaches the harness; an interface without one is in the default zone
  ZONE=""
  [ -n "$IFACE" ] && ZONE="$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || true)"
  [[ "$ZONE" =~ ^[A-Za-z0-9_.-]+$ ]] || ZONE="$(firewall-cmd --get-default-zone 2>/dev/null || true)"
  [[ "$ZONE" =~ ^[A-Za-z0-9_.-]+$ ]] || die "could not work out the firewalld zone - add the rule by hand, or use --no-firewall"
  if firewall-cmd --zone="$ZONE" --query-port="$PORT/tcp" >/dev/null 2>&1; then
    warn "port $PORT/tcp is already open to every address in zone $ZONE, so a harness-only rule restricts nothing."
    info "     Close it if nothing else needs it: firewall-cmd --permanent --zone=$ZONE --remove-port=$PORT/tcp && firewall-cmd --reload"
  fi
  rule="rule family=\"ipv4\" source address=\"$HARNESS_IP/32\" port port=\"$PORT\" protocol=\"tcp\" accept"
  if confirm "Add firewalld rule to zone $ZONE${IFACE:+ (interface $IFACE)}: $rule ?"; then
    run firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$rule" && run firewall-cmd --reload
    FW="firewalld zone $ZONE: $rule"; ok "$FW"
  fi
elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  if confirm "Add ufw rule: allow from $HARNESS_IP to any port $PORT proto tcp ?"; then
    run ufw allow from "$HARNESS_IP" to any port "$PORT" proto tcp
    FW="ufw: allow from $HARNESS_IP to port $PORT/tcp"; ok "$FW"
  fi
else
  FW="NOT SET - neither firewalld nor ufw is active. Allow TCP $PORT to $API_ADDR from $HARNESS_IP/32 only, in this host's nftables/iptables rules or on the network/hypervisor firewall"
  warn "$FW"
  info "until then any host that can reach $API_ADDR can try the API (it still requires a client cert from this server's CA)"
fi

# ---------------------------------------------------------------------------------------------------------------
step "6. Restart"
RESTARTED="no"
if [ "$NO_RESTART" = 1 ]; then
  warn "skipped (--no-restart): the new API users work only after the server restarts"
elif [ -z "$SVC" ]; then
  warn "not a systemd service - restart the Velociraptor frontend yourself"
elif confirm "Restart $SVC now? (clients reconnect on their own; GUI sessions drop briefly)"; then
  run systemctl restart "$SVC"
  if [ "$DRY" = 0 ]; then
    for _ in $(seq 1 60); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 1; done
    systemctl is-active -q "$SVC" || die "$SVC did not come back - check: journalctl -u $SVC -n 50 (config backup: $BACKUP)"
    ss -ltn 2>/dev/null | grep -q ":$PORT " || warn "nothing listens on port $PORT yet"
  fi
  RESTARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ok "$SVC restarted ($RESTARTED); listening: $(ss -ltn 2>/dev/null | awk -v p=":$PORT" '$4 ~ p"$" {print $4}' | paste -sd' ' -)"
fi

# ---------------------------------------------------------------------------------------------------------------
step "7. Point the keys at $API_ADDR:$PORT and verify"
KEYS=("$OUT/$INV.api.yaml"); [ "$ADMIN" = 1 ] && KEYS+=("$OUT/$ADM.api.yaml")
for k in "${KEYS[@]}"; do
  run sed -i "s|^api_connection_string:.*|api_connection_string: $API_ADDR:$PORT|" "$k"
done
vq() { "$BIN" --api_config "$1" query "$2" --format json 2>"$TMP/err"; }
VERIFIED=()
if [ "$DRY" = 1 ]; then
  info "dry run: skipping verification"
else
  if out="$(vq "$OUT/$INV.api.yaml" "SELECT client_id FROM clients() LIMIT 1")" && [[ "$out" == \[* ]]; then
    ok "$INV: listed clients"; VERIFIED+=("$INV")
  else
    warn "$INV failed: $(tail -2 "$TMP/err" | tr '\n' ' ')"
    [ "$RESTARTED" = "no" ] && info "(expected if the server was not restarted: new API users need a restart)"
  fi
  if [ "$ADMIN" = 1 ]; then
    if out="$(vq "$OUT/$ADM.api.yaml" "SELECT * FROM info()")" && [[ "$out" == \[\{* ]]; then
      ok "$ADM: server info"; VERIFIED+=("$ADM")
    else
      warn "$ADM failed: $(tail -2 "$TMP/err" | tr '\n' ' ')"
    fi
  fi
  info "note: the investigator role may return nothing for info() - that is a permission difference, not a failure"
fi

# ---------------------------------------------------------------------------------------------------------------
step "8. Report for the harness operator (no secrets)"
CLIENTS="[]" ORGS="unknown (needs the admin key)"
if [ "$DRY" = 0 ] && [ ${#VERIFIED[@]} -gt 0 ]; then
  CLIENTS="$(vq "$OUT/$INV.api.yaml" "SELECT client_id, os_info.hostname AS host, os_info.system AS os, last_ip, last_seen_at FROM clients()" || echo "[]")"
  if [ "$ADMIN" = 1 ]; then
    ORGS="$(vq "$OUT/$ADM.api.yaml" "SELECT id, name FROM orgs()" | tr -d '\n ' || echo "?")"
  fi
fi
SUMMARY="$(HARNESS_IP="$HARNESS_IP" API_ADDR="$API_ADDR" python3 - "$CLIENTS" <<'PY' 2>/dev/null || echo "  (python3 not available - client summary skipped)"
import ipaddress, json, os, sys, time
rows = json.loads(sys.argv[1] or "[]")
h = os.environ["HARNESS_IP"]
nets, mine, stale = {}, [], []
for r in rows:
    ip = str(r.get("last_ip") or "").rsplit(":", 1)[0].strip("[]")
    try:
        nets.setdefault(str(ipaddress.ip_network(ip + "/24", strict=False)), []).append(ip)
    except ValueError:
        pass
    if ip == h:
        mine.append(f'{r.get("client_id")} ({r.get("host")})')
    seen = (r.get("last_seen_at") or 0) / 1e6
    if seen and time.time() - seen > 30 * 86400:
        stale.append(f'{r.get("host")} ({r.get("client_id")}, last seen {time.strftime("%Y-%m-%d", time.gmtime(seen))})')
print(f"Clients: {len(rows)} in {', '.join(f'{n} ({len(v)})' for n, v in sorted(nets.items())) or 'no ranges'}")
print(f"Harness workstation ({h}) client: {', '.join(mine) or 'none enrolled'}")
print(f"Stale clients (>30 days): {'; '.join(stale) or 'none'}")
print("")
print("Paste into the harness's config/roe.local.yaml (review it first):")
print("  allowed_targets:")
for n in sorted(nets):
    print(f"    - {n}")
print("  protected_assets:")
for m in mine:
    print(f'    - "{m.split()[0]}"      # the harness workstation itself')
print(f"    - {h}")
print(f"    - {os.environ['API_ADDR']}      # this Velociraptor server")
PY
)"
cat <<EOF

  ------------------------------------------------------------------------------------------------
  Velociraptor version:      ${VERSION:-unknown}
  Service / config:          ${SVC:-n/a} / $CFG (runs as $SVC_USER; backup $BACKUP)
  API address for harness:   $API_ADDR:$PORT   (bind_address ${BIND_CUR:-?} -> $BIND$( [ "$BIND_CHANGED" = 1 ] || echo ", unchanged"))
  Keys created:              $INV (investigator,api)$( [ "$ADMIN" = 1 ] && echo ", $ADM (administrator,api)")
  Key files (root, 600):     ${KEYS[*]}
  Verified:                  ${VERIFIED[*]:-none}
  Firewall:                  $FW
  Restarted:                 $RESTARTED
  Orgs:                      $ORGS
$(sed 's/^/  /' <<<"$SUMMARY")
  ------------------------------------------------------------------------------------------------
EOF

# ---------------------------------------------------------------------------------------------------------------
step "9. Hand the key files to the harness"
if [ -n "$DELIVER" ] && [ "$DRY" = 0 ]; then
  if confirm "Copy ${KEYS[*]} to $DELIVER with scp (you will confirm the harness's host key and log in)?"; then
    scp "${KEYS[@]}" "$DELIVER" && ok "copied to $DELIVER"
    if confirm "Delete the copies on this server now (shred -u)? The server can always issue new keys."; then
      shred -u "${KEYS[@]}" && ok "server-side copies removed"
    fi
  fi
else
  cat <<EOF
  Copy them - never paste them anywhere; they contain a private key:
    scp ${KEYS[*]} <analyst>@$HARNESS_IP:<repo>/config/secrets/
  Then on the harness:  chmod 600 config/secrets/*.api.yaml   and set in config/.env:
    VELO_ENABLED=true
    VELO_API_CONFIG=<repo>/config/secrets/$INV.api.yaml$( [ "$ADMIN" = 1 ] && printf '\n    VELO_ADMIN_ENABLED=true\n    VELO_ADMIN_API_CONFIG=<repo>/config/secrets/%s.api.yaml' "$ADM")
  When the harness's 'canarchist doctor' shows velociraptor connected, delete the copies here: shred -u ${KEYS[*]}
EOF
fi

cat <<EOF

  Rollback, if ever needed:
    cp -a $BACKUP $CFG && systemctl restart ${SVC:-<service>}
    delete the API users $INV$( [ "$ADMIN" = 1 ] && echo " and $ADM") in the GUI (Users), and remove the firewall rule above
    (firewalld: firewall-cmd --permanent --zone=<zone> --remove-rich-rule='<the rule>' && firewall-cmd --reload)
EOF
