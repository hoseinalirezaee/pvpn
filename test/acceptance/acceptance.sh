#!/usr/bin/env bash
# Live acceptance tests for pvpn. Run as root on a disposable Ubuntu host with netplan, networkd, and wireguard-tools.
# It creates real Proton certificates and real WireGuard interfaces. Do not run it on a host you cannot reboot.
#
# Needs: pvpn in PATH, /etc/pvpn/config.yaml, a logged-in session in /var/lib/pvpn, python3, nft, tcpdump,
# and $ACC/protonauth (a small tool that lists API certificates; it only reads).
#
# Usage: acceptance.sh SCENARIO...
#   setup      fixtures: another netplan file, another tunnel (fx0), baseline snapshot
#   dryrun     reconcile --dry-run changes nothing
#   first      first reconcile: 2 groups, 4 interfaces
#   idempotent a second reconcile does nothing
#   restart    systemctl restart keeps the source address (checked on the wire)
#   rotate     rotate key, certificate, and IP: one interface, one group, all
#   iprotate   rotate only the IP (same key and certificate); the new source is checked on the wire
#   rotfail    rotation fails (UDP from the candidate address is blocked) and rolls back
#   replace    group server replacement
#   prune      remove one interface from the config
#   chaos      kill -9 during rotation, then recovery
#   afterboot  checks after a reboot
#   teardown   remove everything and compare with the baseline
#   fixtures-remove
export LC_ALL=C
set -u

export ACC=${ACC:-/root/acc}
export STATE=/var/lib/pvpn
CFG=/etc/pvpn/config.yaml
SUBNET=2a01:4f8:1c1b:a31:
TARGET=2606:4700:4700::1111
mkdir -p "$ACC"
PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); echo "  PASS  $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $*"; }
t()   { local d=$1; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
eq()  { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }
ne()  { if [ "$2" != "$3" ]; then ok "$1"; else bad "$1 (both are '$2')"; fi; }
say() { echo; echo "=== $*"; }

js()      { python3 -c "import json; s=json.load(open('$STATE/state.json')); print($1)"; }
ifaces()  { js "' '.join(sorted(s['interfaces']))"; }
field()   { js "s['interfaces']['$1']['$2']"; }
gfield()  { js "s['groups']['$1']['$2']"; }
members() { js "' '.join(sorted(k for k,v in s['interfaces'].items() if v['group']=='$1'))"; }
sources() { js "'\n'.join(sorted(i['source_ip'] for i in s['interfaces'].values()))"; }
serials() { js "'\n'.join(sorted('serial='+i['cert_serial'] for i in s['interfaces'].values()))"; }

certs_all() {
  "$ACC/protonauth" cert-list -session "$STATE/session.json" 2>&1 | grep -o 'serial=[^ ]* name="[^"]*"' | sort
  rm -f "$STATE/session.json.lock"
}
certs_pvpn() { certs_all | grep 'name="pvpn-'; }
serials_api() { certs_pvpn | sed 's/ name=.*//'; }

snap() {
  {
    echo "## addr6"; ip -6 -br addr show | awk '{print $1, $3, $4}' | sort
    echo "## addr4"; ip -4 -br addr show | awk '{print $1, $3}' | sort
    echo "## rule4"; ip -4 rule | sort
    echo "## rule6"; ip -6 rule | sort
    echo "## route6"; ip -6 route show table all | grep -vE '^(local|multicast|ff00|anycast)' | sed -E 's/ (expires|pref) [^ ]+//g' | sort
    echo "## route4"; ip route show table all | grep -vE '^(local|broadcast)' | sort
    echo "## wg"; wg show interfaces | tr ' ' '\n' | sort
    echo "## netplan"; ls -1 /etc/netplan; sha256sum /etc/netplan/*.yaml 2>/dev/null
    echo "## wgfiles"; ls -1 /etc/wireguard
  } > "$ACC/snap-$1.txt" 2>&1
}

safety_on() {
  systemctl stop pvpn-safety.timer pvpn-safety.service >/dev/null 2>&1
  systemd-run --quiet --unit pvpn-safety --on-active="${1:-900}" "$ACC/restore.sh" >/dev/null 2>&1
}
safety_off() { systemctl stop pvpn-safety.timer pvpn-safety.service >/dev/null 2>&1; }

pvpn_run() { echo "\$ pvpn $*"; pvpn "$@" 2>&1 | sed 's/^/    /'; return "${PIPESTATUS[0]}"; }

hs_age() { local ts; ts=$(wg show "$1" latest-handshakes 2>/dev/null | awk '{print $2}'); [ "${ts:-0}" -gt 0 ] && echo $(($(date +%s) - ts)) || echo 99999; }

add_excludes() { # add exclude entries to the germany group in the config
  python3 - "$CFG" "$@" <<'PY'
import sys
path, items = sys.argv[1], sys.argv[2:]
lines = open(path).read().split("\n")
out = []
for ln in lines:
    out.append(ln)
    if ln.strip() == "exclude:":
        for it in items:
            out.append('        - "%s"' % it)
open(path, "w").write("\n".join(out))
PY
}

# ---- invariants after any complete command ----
consistent() {
  local n src table mark prio conf l
  for n in $(ifaces); do
    src=$(field "$n" source_ip); table=$(field "$n" table); mark=$(field "$n" mark); prio=$(field "$n" priority)
    conf=/etc/wireguard/$n.conf
    eq "$n: file is root:root 0600" "$(stat -c '%a %U:%G' $conf)" "600 root:root"
    eq "$n: file has the managed header" "$(head -1 $conf)" "# managed-by = pvpn"
    eq "$n: exactly one PreUp" "$(grep -c '^PreUp' $conf)" "1"
    eq "$n: no PostDown, DNS, route, or rule commands" "$(grep -cE '^(PostDown|DNS)|ip -6 (route|rule)' $conf)" "0"
    t  "$n: Table = off and SaveConfig = false" bash -c "grep -q '^Table = off' $conf && grep -q '^SaveConfig = false' $conf"
    t  "$n: PreUp restores noprefixroute for $src" grep -qx "PreUp = ip -6 addr change $src/128 dev eth0 noprefixroute preferred_lft 0" $conf
    t  "$n: unit is active" systemctl is-active -q wg-quick@$n
    t  "$n: unit is enabled" systemctl is-enabled -q wg-quick@$n
    t  "$n: drop-in waits for systemd-networkd-wait-online" grep -q 'Requires=systemd-networkd-wait-online.service' /etc/systemd/system/wg-quick@$n.service.d/pvpn.conf
    ne "$n: handshake is fresh (age in seconds, limit 150)" "$([ "$(hs_age $n)" -lt 150 ] && echo fresh || echo "stale $(hs_age $n)")" "stale"
    l=$(ip -6 addr show dev eth0 | grep -A1 "inet6 $src/128")
    t  "$n: source address has noprefixroute" bash -c "echo '$l' | grep -q noprefixroute"
    t  "$n: source address has preferred_lft 0" bash -c "echo '$l' | grep -q 'preferred_lft 0sec'"
    eq "$n: source address is not tentative and has no dadfailed" "$(echo "$l" | grep -cE 'tentative|dadfailed')" "0"
    t  "$n: table $table has default via fe80::1 dev eth0 src $src" bash -c "ip -6 route show table $table | grep -q 'default via fe80::1 dev eth0.* src $src'"
    t  "$n: rule priority $prio fwmark $(printf 0x%x "$mark") lookup $table" bash -c "ip -6 rule | grep -qE '^$prio:.*fwmark $(printf 0x%x "$mark").*lookup $table'"
    t  "$n: netplan file lists $src" grep -q "$src/128" /etc/netplan/90-pvpn.yaml
    eq "$n: live public key equals the state" "$(wg show $n public-key)" "$(field "$n" wg_public_key)"
  done
  eq "private keys are all different" "$(grep -h '^PrivateKey' /etc/wireguard/pvpn-*.conf 2>/dev/null | sort | uniq -d | wc -l)" "0"
  eq "source addresses are all different" "$(sources | uniq -d | wc -l)" "0"
  local g
  for g in $(js "' '.join(sorted(s['groups']))"); do
    eq "group $g: all members use one endpoint" "$(for n in $(members "$g"); do grep '^Endpoint' /etc/wireguard/$n.conf; done | sort -u | wc -l)" "$([ -n "$(members "$g")" ] && echo 1 || echo 0)"
  done
  eq "API certificates named pvpn-* equal the state serials" "$(serials_api)" "$(serials)"
  eq "source addresses on eth0 equal the state" "$(ip -6 -br addr show dev eth0 | tr ' ' '\n' | grep "^$SUBNET" | grep '/128' | sed 's#/128##' | grep -v 'f765:3f06:68a9:c06d' | sort)" "$(sources)"
  eq "journal has no pending operations" "$(js "len(s['pending'])")" "0"
  fixtures_ok
}

fixtures_ok() {
  t  "fixture tunnel fx0 is up (listen port 51999, address 10.99.0.1)" bash -c "[ \"\$(wg show fx0 listen-port)\" = 51999 ] && ip -4 addr show dev fx0 | grep -q 10.99.0.1"
  t  "fixture netplan file: address is on eth0" bash -c "ip -6 addr show dev eth0 | grep -q 'f765:3f06:68a9:c06d'"
  t  "fixture netplan file: table 8000 route and rule are active" bash -c "ip route show table 8000 | grep -q 192.0.2.0/24 && ip rule | grep -q 'fwmark 0x1092 lookup 8000'"
  t  "host IPv6 connectivity" ping -6 -c 1 -W 4 $TARGET
  t  "host IPv4 connectivity" ping -4 -c 1 -W 4 1.1.1.1
  if [ -f "$ACC/defsrc" ]; then
    eq "host default IPv6 source address is unchanged" "$(ip -6 route get $TARGET | grep -o 'src [0-9a-f:]*' | head -1)" "$(cat "$ACC/defsrc")"
  fi
}

# Capture outer IPv6 packets of one interface while a trigger command runs. Prints the source addresses seen.
outer_sources() { # iface seconds trigger...
  local n=$1 secs=$2; shift 2
  local ep; ep=$(grep '^Endpoint' /etc/wireguard/$n.conf | sed -E 's/.*\[(.*)\]:.*/\1/')
  timeout "$secs" tcpdump -n -l -i eth0 "ip6 and udp and dst host $ep and dst port 51820" 2>/dev/null > "$ACC/tcpdump.txt" &
  local pid=$!
  sleep 1; "$@" >/dev/null 2>&1; wait $pid 2>/dev/null
  grep -oE 'IP6 [0-9a-f:]+\.[0-9]+ >' "$ACC/tcpdump.txt" | sed -E 's/IP6 ([0-9a-f:]+)\.[0-9]+ >/\1/' | sort -u
}

# ---------------------------------------------------------------------------

sc_setup() {
  say "setup"
  cat > "$ACC/restore.sh" <<'EOF'
#!/bin/bash
rm -f /etc/netplan/90-pvpn.yaml /etc/netplan/60-fixture.yaml
netplan apply
EOF
  chmod 755 "$ACC/restore.sh"
  [ -x "$ACC/protonauth" ] || { bad "missing $ACC/protonauth"; return; }
  safety_on 1800
  cat > /etc/netplan/60-fixture.yaml <<'EOF'
network:
  version: 2
  ethernets:
    eth0:
      addresses:
        - 2a01:4f8:1c1b:a31:f765:3f06:68a9:c06d/64
      routes:
        - to: 192.0.2.0/24
          via: 172.31.1.1
          table: 8000
      routing-policy:
        - from: 192.0.2.0/24
          table: 8000
          mark: 4242
          priority: 555
EOF
  chmod 600 /etc/netplan/60-fixture.yaml
  netplan apply; sleep 4
  local k1 k2; k1=$(wg genkey); k2=$(wg genkey | wg pubkey)
  ( umask 077; cat > /etc/wireguard/fx0.conf <<EOF
[Interface]
PrivateKey = $k1
Address = 10.99.0.1/32
ListenPort = 51999
Table = off
[Peer]
PublicKey = $k2
AllowedIPs = 10.99.0.2/32
EOF
  )
  systemctl enable --now wg-quick@fx0 >/dev/null 2>&1
  ip -6 route get $TARGET | grep -o 'src [0-9a-f:]*' | head -1 > "$ACC/defsrc"
  echo "  default IPv6 source: $(cat "$ACC/defsrc")"
  fixtures_ok
  snap baseline
  certs_all > "$ACC/certs-baseline.txt"
  echo "  baseline: $(wc -l < "$ACC/certs-baseline.txt") certificates at the API; snapshot: $ACC/snap-baseline.txt"
  safety_off
}

sc_dryrun() {
  say "dryrun"
  safety_on 600
  local a1 a2 s1 s2 c1 c2
  a1=$( { ls -l --time-style=full-iso /etc/netplan /etc/wireguard; ls -la --time-style=full-iso $STATE; ip -6 addr; ip rule; ip -6 rule; wg show; systemctl list-units 'wg-quick@*' --no-legend; } 2>&1 | sha256sum)
  s1=$(sha256sum $STATE/session.json); c1=$(certs_all)
  pvpn_run reconcile --dry-run; eq "dry run exits with 0" "$?" "0"
  a2=$( { ls -l --time-style=full-iso /etc/netplan /etc/wireguard; ls -la --time-style=full-iso $STATE; ip -6 addr; ip rule; ip -6 rule; wg show; systemctl list-units 'wg-quick@*' --no-legend; } 2>&1 | sha256sum)
  s2=$(sha256sum $STATE/session.json); c2=$(certs_all)
  eq "files, addresses, rules, tunnels, and units are unchanged" "$a2" "$a1"
  eq "session file (tokens) is unchanged" "$s2" "$s1"
  eq "API certificates are unchanged" "$c2" "$c1"
  t  "no state file was written" test ! -e "$STATE/state.json"
  t  "no managed netplan file" test ! -e /etc/netplan/90-pvpn.yaml
  safety_off
}

sc_first() {
  say "first reconcile"
  safety_on 900
  local t0 rc; t0=$(date +%s)
  pvpn_run reconcile; rc=$?
  eq "reconcile exits with 0" "$rc" "0"
  echo "  took $(( $(date +%s) - t0 )) s"
  eq "state lists the 4 interfaces" "$(ifaces)" "pvpn-de1 pvpn-de2 pvpn-nl1 pvpn-nl2"
  eq "4 new certificates at the API" "$(certs_pvpn | wc -l)" "4"
  eq "first identifiers are table 5751, mark 22353 (0x5751), priority 101" "$(field pvpn-de1 table)/$(field pvpn-de1 mark)/$(field pvpn-de1 priority)" "5751/22353/101"
  consistent
  snap first
  safety_off
}

sc_idempotent() {
  say "idempotent"
  safety_on 600
  local a b m1 c
  a=$(sha256sum $STATE/state.json /etc/netplan/90-pvpn.yaml /etc/wireguard/pvpn-*.conf | sha256sum)
  m1=$(stat -c %Y /etc/netplan/90-pvpn.yaml)
  pvpn reconcile > "$ACC/idem.txt" 2>&1; eq "second reconcile exits with 0" "$?" "0"
  sed 's/^/    /' "$ACC/idem.txt"
  t  "output says: nothing to do" grep -q 'nothing to do' "$ACC/idem.txt"
  b=$(sha256sum $STATE/state.json /etc/netplan/90-pvpn.yaml /etc/wireguard/pvpn-*.conf | sha256sum)
  eq "state, netplan file, and WireGuard files are unchanged" "$b" "$a"
  eq "netplan file was not rewritten" "$(stat -c %Y /etc/netplan/90-pvpn.yaml)" "$m1"
  eq "no new certificates" "$(certs_pvpn | wc -l)" "4"
  consistent
  safety_off
}

sc_restart() {
  say "restart"
  safety_on 600
  local n=pvpn-de1 src seen other
  src=$(field $n source_ip); other=$(wg show pvpn-nl1 latest-handshakes | awk '{print $2}')
  seen=$(outer_sources $n 25 systemctl restart wg-quick@$n)
  echo "  outer source addresses seen on the wire: $seen"
  t  "outer packets used the saved source address" bash -c "echo '$seen' | grep -qx '$src'"
  eq "no outer packet used a host default address" "$(echo "$seen" | grep -cE 'a31::1$|f765:3f06:68a9:c06d$')" "0"
  eq "every outer source is a managed source address" "$(for a in $seen; do sources | grep -qx "$a" || echo bad; done | wc -l)" "0"
  sleep 3
  eq "source address in state is unchanged" "$(field $n source_ip)" "$src"
  t  "another tunnel kept running (its handshake did not go backwards)" test "$(wg show pvpn-nl1 latest-handshakes | awk '{print $2}')" -ge "$other"
  consistent
  safety_off
}

sc_rotate() {
  say "rotate one interface"
  safety_on 900
  local n=pvpn-de1 oldsrc oldserial oldkey oth rc started1 started2
  oldsrc=$(field $n source_ip); oldserial=$(field $n cert_serial); oldkey=$(field $n wg_public_key)
  oth=$(sha256sum /etc/wireguard/pvpn-de2.conf /etc/wireguard/pvpn-nl1.conf /etc/wireguard/pvpn-nl2.conf | sha256sum)
  started1=$(systemctl show wg-quick@$n -p ActiveEnterTimestampMonotonic)
  pvpn_run rotate --new-key --new-ip --interface $n; rc=$?
  eq "rotate exits with 0" "$rc" "0"
  ne "source address changed" "$(field $n source_ip)" "$oldsrc"
  ne "certificate changed" "$(field $n cert_serial)" "$oldserial"
  ne "key changed" "$(field $n wg_public_key)" "$oldkey"
  eq "old source address is gone from eth0" "$(ip -6 addr show dev eth0 | grep -c "$oldsrc")" "0"
  eq "old certificate is revoked at the API" "$(certs_all | grep -c "serial=$oldserial ")" "0"
  eq "other interfaces were not touched" "$(sha256sum /etc/wireguard/pvpn-de2.conf /etc/wireguard/pvpn-nl1.conf /etc/wireguard/pvpn-nl2.conf | sha256sum)" "$oth"
  started2=$(systemctl show wg-quick@$n -p ActiveEnterTimestampMonotonic)
  eq "unit was updated in place (not restarted)" "$started2" "$started1"
  consistent

  say "rotate one group"
  pvpn_run rotate --new-key --new-ip --group netherlands; eq "rotate --group exits with 0" "$?" "0"
  consistent

  say "rotate all"
  local before; before=$(serials)
  pvpn_run rotate --new-key --new-ip; eq "rotate (all) exits with 0" "$?" "0"
  eq "all certificates changed" "$(comm -12 <(echo "$before") <(serials) | wc -l)" "0"
  pvpn rotate --new-key --group germany --interface pvpn-de1 >/dev/null 2>&1; eq "--group with --interface is refused (exit 2)" "$?" "2"
  pvpn rotate >/dev/null 2>&1; eq "rotate without a flag is refused (exit 2)" "$?" "2"
  pvpn rotate --new-server --interface pvpn-de1 >/dev/null 2>&1; eq "--new-server with --interface is refused (exit 2)" "$?" "2"
  consistent
  safety_off
}

sc_iprotate() {
  say "rotate only the IP"
  safety_on 900
  local n=pvpn-de1 oldsrc oldserial oldkey newsrc seen rc oth
  oldsrc=$(field $n source_ip); oldserial=$(field $n cert_serial); oldkey=$(field $n wg_public_key)
  oth=$(wg show pvpn-nl1 latest-handshakes | awk '{print $2}')
  pvpn_run rotate --new-ip --interface $n; rc=$?
  eq "rotate --new-ip exits with 0" "$rc" "0"
  newsrc=$(field $n source_ip)
  ne "source address changed" "$newsrc" "$oldsrc"
  eq "certificate did not change" "$(field $n cert_serial)" "$oldserial"
  eq "key did not change" "$(field $n wg_public_key)" "$oldkey"
  eq "live key is the saved key" "$(wg show $n public-key)" "$oldkey"
  eq "old source address is gone from eth0" "$(ip -6 addr show dev eth0 | grep -c "$oldsrc")" "0"
  eq "certificate is still at the API" "$(certs_all | grep -c "serial=$oldserial ")" "1"
  eq "WireGuard file has the new source" "$(grep -c "addr change $newsrc/128" /etc/wireguard/$n.conf)" "1"
  # The new source must be used on the wire. A persistent keepalive leaves every 25 s.
  seen=$(outer_sources $n 35 sleep 33)
  echo "  outer source addresses seen on the wire: $seen"
  t  "outer packets used the new source address" bash -c "echo '$seen' | grep -qx '$newsrc'"
  eq "no outer packet used the old source address" "$(echo "$seen" | grep -c "$oldsrc")" "0"
  t  "another tunnel kept running (its handshake did not go backwards)" test "$(wg show pvpn-nl1 latest-handshakes | awk '{print $2}')" -ge "$oth"
  consistent
  safety_off
}

sc_rotfail() {
  say "rotation failure with rollback"
  safety_on 900
  local n=pvpn-nl1 oldsrc oldserial oldkey oldconf oldnp known cand="" i
  oldsrc=$(field $n source_ip); oldserial=$(field $n cert_serial); oldkey=$(field $n wg_public_key)
  oldconf=$(sha256sum /etc/wireguard/$n.conf); oldnp=$(sha256sum /etc/netplan/90-pvpn.yaml)
  known=$(ip -6 -br addr show dev eth0 | tr ' ' '\n' | grep "^$SUBNET" | sed 's#/.*##' | sort)
  nft delete table inet pvpntest >/dev/null 2>&1
  ( pvpn rotate --new-key --new-ip --interface $n > "$ACC/rotfail.txt" 2>&1; echo $? > "$ACC/rotfail.rc" ) &
  local bgpid=$!
  for i in $(seq 1 600); do
    cand=$(comm -13 <(echo "$known") <(ip -6 -br addr show dev eth0 | tr ' ' '\n' | grep "^$SUBNET" | sed 's#/.*##' | sort) | head -1)
    [ -n "$cand" ] && break
    sleep 0.1
  done
  echo "  candidate address seen: ${cand:-none}"
  if [ -n "$cand" ]; then
    nft add table inet pvpntest
    nft add chain inet pvpntest out '{ type filter hook output priority 0; }'
    nft add rule inet pvpntest out ip6 saddr "$cand" meta l4proto udp drop
  fi
  wait $bgpid
  nft delete table inet pvpntest >/dev/null 2>&1
  sed 's/^/    /' "$ACC/rotfail.txt"
  ne "rotation failed (exit code is not 0)" "$(cat "$ACC/rotfail.rc")" "0"
  ne "a candidate address was seen and blocked" "$cand" ""
  eq "state still has the old source, certificate, and key" "$(field $n source_ip)/$(field $n cert_serial)/$(field $n wg_public_key)" "$oldsrc/$oldserial/$oldkey"
  eq "WireGuard file is the old file" "$(sha256sum /etc/wireguard/$n.conf)" "$oldconf"
  eq "netplan file is the old file" "$(sha256sum /etc/netplan/90-pvpn.yaml)" "$oldnp"
  eq "candidate address is gone" "$(ip -6 addr show dev eth0 | grep -c "${cand:-no-candidate}")" "0"
  sleep 3
  consistent
  safety_off
}

sc_replace() {
  say "group server replacement"
  safety_on 900
  local g=germany old dom oldsrc1 oldsrc2 t0 oldserials rc stopmax startmin
  old=$(gfield $g logical); dom=$(gfield $g domain)
  oldsrc1=$(field pvpn-de1 source_ip); oldsrc2=$(field pvpn-de2 source_ip)
  oldserials="$(field pvpn-de1 cert_serial) $(field pvpn-de2 cert_serial)"
  nlsha=$(sha256sum /etc/wireguard/pvpn-nl1.conf)
  cp $CFG "$ACC/config.before-replace"
  add_excludes "$old" "$dom"
  t0=$(date +%s); sleep 1
  pvpn_run reconcile --dry-run | grep -q 'replace-server'; eq "dry run announces replace-server" "$?" "0"
  pvpn_run reconcile; rc=$?
  eq "reconcile exits with 0" "$rc" "0"
  ne "logical server changed" "$(gfield $g logical)" "$old"
  ne "machine changed" "$(gfield $g domain)" "$dom"
  echo "  $old on $dom -> $(gfield $g logical) on $(gfield $g domain)"
  eq "source addresses unchanged" "$(field pvpn-de1 source_ip) $(field pvpn-de2 source_ip)" "$oldsrc1 $oldsrc2"
  local api; api=$(certs_all)
  for s in $oldserials; do eq "old certificate $s revoked" "$(echo "$api" | grep -c "serial=$s ")" "0"; done
  stopmax=$(journalctl -o short-unix --since "@$t0" -u 'wg-quick@pvpn-de*' --no-pager 2>/dev/null | grep -E 'Stopped wg-quick@' | awk '{print $1}' | sort -n | tail -1)
  startmin=$(journalctl -o short-unix --since "@$t0" -u 'wg-quick@pvpn-de*' --no-pager 2>/dev/null | grep -E 'Starting wg-quick@' | awk '{print $1}' | sort -n | head -1)
  echo "  last stop at $stopmax, first start at $startmin"
  t "both old members stopped before the first member started on the new server" bash -c "[ -n '$stopmax' ] && [ -n '$startmin' ] && awk 'BEGIN{exit !($stopmax < $startmin)}'"
  eq "netherlands files did not change" "$(sha256sum /etc/wireguard/pvpn-nl1.conf)" "$nlsha"
  consistent
  cp "$ACC/config.before-replace" $CFG
  safety_off
}

sc_prune() {
  say "prune"
  safety_on 900
  local n=pvpn-nl2 src serial
  src=$(field $n source_ip); serial=$(field $n cert_serial)
  python3 - "$CFG" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read().replace("      - pvpn-nl2\n", "")
open(p, "w").write(s)
PY
  pvpn_run reconcile --dry-run | grep -q 'prune'; eq "dry run announces the prune" "$?" "0"
  pvpn_run reconcile; eq "reconcile exits with 0" "$?" "0"
  t  "unit is stopped" bash -c "! systemctl is-active -q wg-quick@$n"
  t  "unit is disabled" bash -c "! systemctl is-enabled -q wg-quick@$n"
  t  "WireGuard file and drop-in are removed" bash -c "[ ! -e /etc/wireguard/$n.conf ] && [ ! -e /etc/systemd/system/wg-quick@$n.service.d/pvpn.conf ]"
  eq "netplan entry is removed" "$(grep -c "$src" /etc/netplan/90-pvpn.yaml)" "0"
  eq "source address is removed" "$(ip -6 addr show dev eth0 | grep -c "$src")" "0"
  eq "certificate is revoked" "$(certs_all | grep -c "serial=$serial ")" "0"
  eq "interface is gone from the state" "$(ifaces)" "pvpn-de1 pvpn-de2 pvpn-nl1"
  consistent
  safety_off
}

sc_chaos() {
  say "kill -9 during rotation, then recovery"
  safety_on 1500
  local i d rc
  for i in 1 2 3 4; do
    d=$(( (RANDOM % 9) + 1 ))
    timeout -s KILL "$d" pvpn rotate --new-key --new-ip --interface pvpn-de2 >/dev/null 2>&1; rc=$?
    echo "  run $i: killed after ${d}s (rc=$rc); pending=$(js "len(s['pending'])")"
    pvpn reconcile >"$ACC/chaos-$i.txt" 2>&1; echo "    recovery reconcile rc=$?"
  done
  pvpn reconcile >/dev/null 2>&1; eq "final reconcile exits with 0" "$?" "0"
  consistent
  safety_off
}

sc_afterboot() {
  say "after reboot"
  echo "  $(uptime -p)"
  consistent
  local n=pvpn-de1
  t "unit is ordered after systemd-networkd-wait-online" bash -c "systemctl show wg-quick@$n -p After | grep -q systemd-networkd-wait-online.service"
  echo "  critical chain of wg-quick@$n:"; systemd-analyze critical-chain wg-quick@$n.service 2>&1 | sed 's/^/    /' | head -12
  pvpn status 2>&1 | sed 's/^/    /' | head -30
  pvpn reconcile > "$ACC/afterboot.txt" 2>&1; t "reconcile after reboot says: nothing to do" grep -q 'nothing to do' "$ACC/afterboot.txt"
}

sc_teardown() {
  say "teardown"
  safety_on 900
  cp $CFG "$ACC/config.final"
  printf 'version: 1\npaths:\n  state_dir: /var/lib/pvpn\nreconcile:\n  prune: true\ngroups: {}\n' > $CFG
  pvpn_run reconcile; eq "reconcile with no groups exits with 0" "$?" "0"
  eq "no pvpn certificate is left at the API" "$(certs_pvpn | wc -l)" "0"
  eq "API certificate list equals the baseline" "$(certs_all)" "$(cat "$ACC/certs-baseline.txt")"
  t  "no managed netplan file" test ! -e /etc/netplan/90-pvpn.yaml
  eq "no pvpn WireGuard files or drop-ins" "$(ls /etc/wireguard/pvpn-*.conf /etc/systemd/system/wg-quick@pvpn-*.service.d 2>/dev/null | wc -l)" "0"
  eq "state is empty" "$(js "len(s['interfaces'])+len(s['groups'])+len(s['pending'])")" "0"
  fixtures_ok
  snap final
  echo "  differences to the baseline:"; diff "$ACC/snap-baseline.txt" "$ACC/snap-final.txt" | sed 's/^/    /' | head -20
  t "host snapshot equals the baseline" diff -q "$ACC/snap-baseline.txt" "$ACC/snap-final.txt"
  safety_off
}

sc_fixtures_remove() {
  say "remove fixtures"
  systemctl disable --now wg-quick@fx0 >/dev/null 2>&1; rm -f /etc/wireguard/fx0.conf /etc/netplan/60-fixture.yaml; netplan apply
  echo "  fixtures removed"
}

for s in "$@"; do "sc_${s//-/_}"; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
