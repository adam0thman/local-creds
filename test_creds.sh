#!/bin/sh
# Self-check for ./creds against a throwaway index. Run: sh test_creds.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
TD=$(mktemp -d)
trap 'rm -rf "$TD"' EXIT INT TERM

export LOCAL_CREDS_DIR="$TD"
export LOCAL_CREDS_KEY="$TD/key"
age-keygen -o "$LOCAL_CREDS_KEY" 2>/dev/null
grep -i 'public key' "$LOCAL_CREDS_KEY" | sed 's/.*: //' > "$TD/recipients.txt"

cat > "$TD/plain.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-dev-rfc","customer":"acme","env":"dev","kind":"rfc",
  "host":"dev.acme.test","port":null,"user":"TESTER","secret":"s3cr3t p@ss",
  "via":null,"tags":["x"],"fields":{"sid":"D01","client":"100","sysnr":"00"}},
 {"id":"acme-prd-hana","customer":"acme","env":"prd","kind":"hana",
  "host":"hana.acme.test","port":30015,"user":"SYSTEM","secret":"prodpw",
  "via":"acme-prd-bastion","tags":[],"fields":{"sid":"P01"}},
 {"id":"beta-qas-sftp","customer":"beta","env":"qas","kind":"sftp",
  "host":"10.11.12.13","port":22,"user":"edi","secret":"b64:aGVsbG8xMjM=",
  "via":null,"tags":[],"requires":["vpn:example.corp"],"fields":{"sid":"Q77"}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/plain.json"

ok=0
check() { if eval "$2"; then echo "  ok  $1"; ok=$((ok+1)); else echo "  FAIL $1"; exit 1; fi }

echo "creds self-check"

check "find matches by customer+env" \
  '[ "$("$HERE/creds" find acme dev | jq -r ".[0].id")" = "acme-dev-rfc" ]'

check "find never emits the secret" \
  '! "$HERE/creds" find acme | grep -q "s3cr3t"'

check "find narrows on multiple words" \
  '[ "$("$HERE/creds" find acme hana | jq "length")" = "1" ]'

check "exec injects host/user" \
  '[ "$("$HERE/creds" exec acme-dev-rfc -- sh -c "echo \$CREDS_HOST/\$CREDS_USER")" = "dev.acme.test/TESTER" ]'

check "exec injects password with spaces intact" \
  '[ "$("$HERE/creds" exec acme-dev-rfc -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "s3cr3t p@ss" ]'

check "exec flattens fields to CREDS_*" \
  '[ "$("$HERE/creds" exec acme-dev-rfc -- sh -c "echo \$CREDS_CLIENT")" = "100" ]'

check "rfc kind materialises a jco destination file" \
  '"$HERE/creds" exec acme-dev-rfc -- sh -c "grep -q jco.client.passwd \"\$CREDS_JCO_DEST\""'

check "jco destination file is 0600" \
  '[ "$("$HERE/creds" exec acme-dev-rfc -- sh -c "stat -f %Lp \"\$CREDS_JCO_DEST\"")" = "600" ]'

check "jco destination is shredded after exec" \
  '! test -e "$("$HERE/creds" exec acme-dev-rfc -- sh -c "echo \$CREDS_JCO_DIR")"'

check "prod entry refused without CREDS_ALLOW_PROD" \
  '! "$HERE/creds" exec acme-prd-hana -- true 2>/dev/null'

check "prod entry runs with CREDS_ALLOW_PROD=1" \
  'CREDS_ALLOW_PROD=1 "$HERE/creds" exec acme-prd-hana -- true'

check "unknown id fails loudly" \
  '! "$HERE/creds" exec nope -- true 2>/dev/null'

check "sync-ssh emits ProxyJump for via" \
  'HOME="$TD" "$HERE/creds" sync-ssh >/dev/null && grep -q "ProxyJump acme-prd-bastion" "$TD/.ssh/config.d/local-creds"'

check "sync-ssh output contains no secrets" \
  '! grep -qE "s3cr3t|prodpw" "$TD/.ssh/config.d/local-creds"'

check "b64: secret is decoded before injection" \
  '[ "$("$HERE/creds" exec beta-qas-sftp -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "hello123" ]'

check "search finds an entry by IP address" \
  '[ "$("$HERE/creds" find 10.11.12.13 | jq -r ".[0].id")" = "beta-qas-sftp" ]'

check "search finds an entry by SID" \
  '[ "$("$HERE/creds" find q77 | jq -r ".[0].id")" = "beta-qas-sftp" ]'

check "near-miss falls back to suggestions" \
  '[ "$("$HERE/creds" find acme nosuchthing 2>/dev/null | jq "length")" -gt 0 ]'

check "near-miss explains itself on stderr" \
  '"$HERE/creds" find acme nosuchthing 2>&1 >/dev/null | grep -q "closest matches"'

check "total miss lists known customers" \
  '"$HERE/creds" find zzzznope 2>&1 >/dev/null | grep -q "acme, beta"'

check "search matches a requires token" \
  '[ "$("$HERE/creds" find example.corp | jq -r ".[0].id")" = "beta-qas-sftp" ]'

check "exec announces connectivity prerequisites on stderr" \
  '"$HERE/creds" exec beta-qas-sftp -- true 2>&1 >/dev/null | grep -q "requires: vpn:example.corp"'

check "prerequisite notice goes to stderr, not stdout" \
  '! "$HERE/creds" exec beta-qas-sftp -- true 2>/dev/null | grep -q "example.corp"'

# --- ui server: local-only, token-gated ---
# Port 0 = let the OS pick a free one, then read it back from the startup line.
# A hardcoded port collides with any creds ui the user happens to have running.
# Same interpreter resolution as `creds ui` itself (venv with the optional
# extras when present) -- otherwise this harness tests a different code path
# than what actually runs, and extras-dependent probes report "unavailable"
# here while working for real.
uipy="$HOME/.cache/creds/venv/bin/python"
[ -x "$uipy" ] || uipy=python3
CREDS_UI_NO_OPEN=1 LOCAL_CREDS_DIR="$TD" LOCAL_CREDS_KEY="$TD/key" \
  "$uipy" "$HERE/ui_server.py" 0 >"$TD/ui.log" 2>&1 &
uipid=$!
trap 'kill $uipid 2>/dev/null; rm -rf "$TD"' EXIT INT TERM
# 3s was too tight: the venv interpreter imports hdbcli/paramiko at startup, and
# under load that overran the budget and produced an empty token -- a flaky failure
# that looked like a real one. Wait longer, and say WHY if it still does not come up.
i=0
while [ $i -lt 40 ]; do
  grep -q 'creds ui ->' "$TD/ui.log" 2>/dev/null && break
  perl -e 'select undef,undef,undef,0.25'
  i=$((i + 1))
done
grep -q 'creds ui ->' "$TD/ui.log" 2>/dev/null || {
  echo "  ui_server did not start within 10s; its log said:" >&2
  sed 's/^/    /' "$TD/ui.log" >&2
}
uitok=$(sed -n 's/.*?t=\([A-Za-z0-9_-]*\).*/\1/p' "$TD/ui.log" | head -1)
uiport=$(sed -n 's|.*127\.0\.0\.1:\([0-9]*\)/.*|\1|p' "$TD/ui.log" | head -1)

check "ui server starts and prints a token URL" '[ -n "$uitok" ]'

check "ui rejects a request with no token" \
  '[ "$(curl -s -o /dev/null -w %{http_code} "http://127.0.0.1:$uiport/api/index")" = "403" ]'

check "ui rejects a wrong token" \
  '[ "$(curl -s -o /dev/null -w %{http_code} -H "X-Creds-Token: nope" "http://127.0.0.1:$uiport/api/index")" = "403" ]'

check "ui serves the index with a valid token" \
  '[ "$(curl -s -H "X-Creds-Token: $uitok" "http://127.0.0.1:$uiport/api/index" | jq ".entries|length")" = "3" ]'

printf '%s' '{"version":1,"entries":[{"id":"x"},{"id":"x"}]}' > "$TD/dup.json"
printf '%s' '{"version":1,"entries":[{"id":""}]}'            > "$TD/noid.json"
printf '%s' '{"kind":"sftp","host":"127.0.0.1","port":9}'    > "$TD/probe.json"
post() { curl -s -o /dev/null -w '%{http_code}' -X POST -H "X-Creds-Token: $uitok" \
           --data-binary @"$1" "http://127.0.0.1:$uiport$2"; }

check "ui refuses a save with duplicate ids"   '[ "$(post "$TD/dup.json" /api/index)" = "400" ]'
check "ui refuses a save with an empty id"     '[ "$(post "$TD/noid.json" /api/index)" = "400" ]'

check "ui reachability test reports closed ports honestly" \
  'curl -s -X POST -H "X-Creds-Token: $uitok" --data-binary @"$TD/probe.json" \
      "http://127.0.0.1:$uiport/api/test" | jq -e ".ok == false" >/dev/null'

api_test() { curl -s -X POST -H "X-Creds-Token: $uitok" --data-binary @"$1" \
               "http://127.0.0.1:$uiport/api/test"; }

# sapgui still routes mode=auth through icm_auth_test (unchanged); rfc does not
# any more -- see legacy_rfc.json below, which is the actual bug fix.
printf '%s' '{"mode":"auth","entry":{"kind":"sapgui","host":"127.0.0.1","user":"U","secret":"p","fields":{}}}' > "$TD/a1.json"
printf '%s' '{"mode":"auth","entry":{"kind":"hana","host":"127.0.0.1","port":30015,"user":"U","secret":"p"}}' > "$TD/a2.json"
# The over-40-char warning is an ICM/SAP-GUI-BCODE caveat, not a JCo/RFC one --
# JCo genuinely accepts longer passwords (proven empirically elsewhere in this
# project), so this stays on sapgui, which still routes through icm_auth_test.
printf '%s' '{"mode":"auth","entry":{"kind":"sapgui","host":"127.0.0.1","user":"U","fields":{"sysnr":"00","client":"100"},"secret":"0123456789012345678901234567890123456789X"}}' > "$TD/a3.json"
printf '%s' '{"mode":"reach","entry":{"kind":"rfc","host":"127.0.0.1","fields":{"sysnr":"00"}}}' > "$TD/a4.json"
# points at the ui server's own port, so the probe genuinely succeeds
printf '{"mode":"reach","entry":{"kind":"sftp","host":"127.0.0.1","port":%s}}' "$uiport" > "$TD/a5.json"

check "auth test says so when no ICM port is derivable" \
  'api_test "$TD/a1.json" | jq -e ".detail | test(\"no ICM port\")" >/dev/null'

# hdbcli now lives in the creds venv (installed for real HANA logon tests), so
# this asserts a genuine connection attempt rather than "driver missing".
check "hana auth test attempts a real connection when the driver is present" \
  'api_test "$TD/a2.json" | jq -e ".kind == \"hana-auth\" and .ok == false" >/dev/null'

check "auth test notes an over-40 secret without declaring it invalid" \
  'api_test "$TD/a3.json" | jq -e ".notes | any(test(\"longer than SAP\"))" >/dev/null'

check "reach mode never attempts a logon" \
  '[ "$(api_test "$TD/a4.json" | jq -r .kind)" = "tcp" ]'

printf '{"entry":{"kind":"sftp","host":"127.0.0.1"},"protocol":{"type":"tcp","port":%s}}' "$uiport" > "$TD/p1.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"U","secret":"p","fields":{"sysnr":"00"}},"protocol":{"type":"rfc"}}' > "$TD/p2.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"U","secret":"p","fields":{}},"protocol":{"type":"nonsense"}}' > "$TD/p3.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"U","secret":"p","fields":{"sysnr":"00","client":"100"}},"protocol":{"type":"icm-http","port":9,"path":"/sap/bc/ping"}}' > "$TD/p4.json"

check "per-protocol tcp probe works" \
  'api_test "$TD/p1.json" | jq -e ".ok == true and .kind == \"tcp\"" >/dev/null'

# One JCo run (~10s: single-file source is recompiled each time), asserted twice.
rfcout=$(api_test "$TD/p2.json")
check "rfc protocol performs a real JCo logon attempt" \
  '[ "$(printf %s "$rfcout" | jq -r .kind)" = "rfc" ]'
check "rfc failure separates network trouble from bad credentials" \
  'printf %s "$rfcout" | jq -e ".notes | any(test(\"unreachable\"))" >/dev/null'

check "unknown protocol is rejected, not silently passed" \
  'api_test "$TD/p3.json" | jq -e ".ok == false and (.detail | test(\"unknown protocol\"))" >/dev/null'

check "icm-http honours an explicit port override" \
  'api_test "$TD/p4.json" | jq -e ".kind == \"icm-http\" and .ok == false" >/dev/null'

printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","fields":{"sysnr":"07"}},"protocol":{"type":"disp"}}' > "$TD/d1.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","fields":{"sysnr":"07"}},"protocol":{"type":"gateway"}}' > "$TD/d2.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","fields":{"sysnr":"07"}},"protocol":{"type":"msgserver"}}' > "$TD/d3.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","fields":{}},"protocol":{"type":"disp"}}' > "$TD/d4.json"

check "disp derives 32<nn> from sysnr" \
  'api_test "$TD/d1.json" | jq -e ".detail | test(\":3207\")" >/dev/null'
check "gateway derives 33<nn> from sysnr" \
  'api_test "$TD/d2.json" | jq -e ".detail | test(\":3307\")" >/dev/null'
check "msgserver derives 36<nn> from sysnr" \
  'api_test "$TD/d3.json" | jq -e ".detail | test(\":3607\")" >/dev/null'
check "disp without sysnr says what is missing" \
  'api_test "$TD/d4.json" | jq -e ".ok == false and (.detail | test(\"sysnr\"))" >/dev/null'

# --- generic api probe: driven by the entry's own fields, not per-vendor code ---
printf '%s' '{"entry":{"kind":"api","host":"api.example.com","secret":"k",
  "fields":{"base_url":"https://api.example.com/v1","auth_style":"bearer"}},
  "protocol":{"type":"api"}}' > "$TD/api1.json"
printf '%s' '{"entry":{"kind":"api","host":"api.example.com","secret":"k",
  "fields":{"verify_path":"/models","auth_style":"bearer"}},"protocol":{"type":"api"}}' > "$TD/api2.json"
printf '%s' '{"entry":{"kind":"api","host":"api.example.com","secret":"",
  "fields":{"base_url":"https://x/v1","verify_path":"/m","auth_style":"bearer"}},
  "protocol":{"type":"api"}}' > "$TD/api3.json"
printf '{"entry":{"kind":"api","host":"127.0.0.1","secret":"k","fields":{"base_url":"http://127.0.0.1:%s","verify_path":"/api/index","auth_style":"bearer"}},"protocol":{"type":"api"}}' "$uiport" > "$TD/api4.json"

check "api probe demands verify_path" \
  'api_test "$TD/api1.json" | jq -e ".detail | test(\"verify_path\")" >/dev/null'
check "api probe demands base_url" \
  'api_test "$TD/api2.json" | jq -e ".detail | test(\"base_url\")" >/dev/null'
check "api probe refuses an empty secret" \
  'api_test "$TD/api3.json" | jq -e ".detail | test(\"no secret\")" >/dev/null'
check "api probe reports inconclusive when the endpoint ignores the secret" \
  'api_test "$TD/api4.json" | jq -e ".kind | test(\"inconclusive\")" >/dev/null'

check "a successful reach probe still says credentials are unverified" \
  'api_test "$TD/a5.json" | jq -e ".ok == true and (.detail | test(\"NOT verified\"))" >/dev/null'

check "ui binds loopback only" \
  '! netstat -an 2>/dev/null | grep -q "\\*\\.$uiport .*LISTEN"'

# --- durability: snapshots, validation, doctor, restore ---
before=$(ls -1 "$TD/.backups"/creds-*.age 2>/dev/null | wc -l | tr -d ' ')
EDITOR="true" "$HERE/creds" edit >/dev/null
check "a save creates a backup snapshot" \
  '[ "$(ls -1 "$TD/.backups"/creds-*.age 2>/dev/null | wc -l | tr -d " ")" -gt "$before" ]'

check "restore lists snapshots" \
  '"$HERE/creds" restore | grep -q "entries"'

cat > "$TD/dupe-ed.sh" <<'EOS'
#!/bin/sh
python3 - "$1" <<'PY'
import json,sys
i=json.load(open(sys.argv[1])); i["entries"].append(dict(i["entries"][0]))
json.dump(i,open(sys.argv[1],"w"))
PY
EOS
chmod +x "$TD/dupe-ed.sh"
check "edit refuses to save duplicate ids" \
  '! EDITOR="$TD/dupe-ed.sh" "$HERE/creds" edit 2>&1 | grep -q "^saved"'

cat > "$TD/blank-ed.sh" <<'EOS'
#!/bin/sh
python3 - "$1" <<'PY'
import json,sys
i=json.load(open(sys.argv[1])); i["entries"][0]["id"]=""
json.dump(i,open(sys.argv[1],"w"))
PY
EOS
chmod +x "$TD/blank-ed.sh"
check "edit refuses to save an entry with a blank id" \
  '! EDITOR="$TD/blank-ed.sh" "$HERE/creds" edit 2>&1 | grep -q "^saved"'

check "index survives the rejected saves" \
  '[ "$("$HERE/creds" find | jq "length")" = "3" ]'

check "doctor reports a healthy index" \
  '"$HERE/creds" doctor | grep -q "index decrypts"'

check "doctor exits 0 when healthy" '"$HERE/creds" doctor >/dev/null'

check "doctor FAILs on a broken identity" \
  '! LOCAL_CREDS_KEY="$TD/nope.key" "$HERE/creds" doctor >/dev/null 2>&1'

saved=$(pbpaste 2>/dev/null || echo "")
check "copy puts the password on the clipboard" \
  '"$HERE/creds" copy acme-dev-rfc >/dev/null && [ "$(pbpaste)" = "s3cr3t p@ss" ]'
check "copy does not print the password" \
  '! "$HERE/creds" copy acme-dev-rfc | grep -q "s3cr3t"'
printf '%s' "$saved" | pbcopy 2>/dev/null || true

echo "$ok checks passed"

# --- ssh routing: password entries must attempt password auth, not key-only ---
printf '%s' '{"entry":{"kind":"ssh","host":"127.0.0.1","port":9,"user":"u","secret":"pw"},"protocol":{"type":"ssh"}}' > "$TD/ssh_pw.json"
printf '%s' '{"entry":{"kind":"ssh","host":"127.0.0.1","port":9,"user":"u","secret":""},"protocol":{"type":"ssh"}}' > "$TD/ssh_key.json"

check "ssh test routes a password entry to password auth, not key-only" \
  '[ "$(api_test "$TD/ssh_pw.json" | jq -r .kind)" = "ssh-auth (password)" ]'

check "ssh test routes a keyless entry to key auth (unchanged behaviour)" \
  '[ "$(api_test "$TD/ssh_key.json" | jq -r .kind)" = "ssh-auth (key)" ]'

check "ssh password auth actually attempts the network, not a stub pass" \
  'api_test "$TD/ssh_pw.json" | jq -e ".ok == false" >/dev/null'

# --- rfc gateway override: JCo derives sapgw<NN> from SYSNR alone with no way to
# override it on its own, so a mismatched/non-standard gateway needs an explicit
# JCO_GWSERV. Assert against the real JCo error text, which echoes the dialed port. ---
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"u","secret":"p",
  "fields":{"sysnr":"00","client":"100","gwserv":"19999"}},"protocol":{"type":"rfc"}}' > "$TD/gw1.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"u","secret":"p",
  "fields":{"sysnr":"00","client":"100","gwserv":"19999"}},
  "protocol":{"type":"rfc","port":"18888"}}' > "$TD/gw2.json"
printf '%s' '{"entry":{"kind":"rfc","host":"127.0.0.1","user":"u","secret":"p",
  "fields":{"sysnr":"00","client":"100"}},"protocol":{"type":"rfc","port":"3300"}}' > "$TD/gw3.json"

check "rfc gateway override from fields.gwserv is honoured" \
  'api_test "$TD/gw1.json" | jq -e ".detail | test(\"19999\")" >/dev/null'

check "an explicit row port overrides fields.gwserv" \
  'api_test "$TD/gw2.json" | jq -e ".detail | test(\"18888\")" >/dev/null'

check "a row port matching the sysnr convention is not treated as an override" \
  '! api_test "$TD/gw3.json" | jq -e ".notes | any(test(\"gateway override\"))" >/dev/null'

# --- rdp: verdict comes from parsing FreeRDP's ERRCONNECT_* tokens, never exit
# code (confirmed empirically: +auth-only prints "exit status 0" even on a hard
# connection failure). Uses an unreachable host, no real credentials involved. ---
printf '%s' '{"entry":{"kind":"rdp","host":"10.255.255.1","port":3389,"user":"u","secret":"p"},"protocol":{"type":"rdp"}}' > "$TD/rdp1.json"

if command -v xfreerdp >/dev/null 2>&1; then
  check "rdp probe distinguishes a network failure from a credential failure" \
    'api_test "$TD/rdp1.json" | jq -e ".ok == false and (.detail | test(\"network layer, not credentials\"))" >/dev/null'
else
  check "rdp probe reports xfreerdp missing rather than a false pass" \
    'api_test "$TD/rdp1.json" | jq -e ".kind == \"unavailable\"" >/dev/null'
fi

# Static, not a live-process race: confirms the password is built into the
# CREDS_XFREERDP_ARGS env value, never into the argv list subprocess.run() spawns.
check "rdp probe never puts the password into a literal argv list" \
  '! grep -qE "\[\"xfreerdp\".*f\"/p:" "$HERE/ui_server.py"'

check "rdp probe routes credentials through args-from:env, not argv" \
  'grep -q "args-from:env:CREDS_XFREERDP_ARGS" "$HERE/ui_server.py"'

# --- rdp: a post-NLA CONNECT_CANCELLED is auth-only's own success signal, not a
# failure -- confirmed against a real captured trace, not guessed. Static shape
# check: the distinguishing branch must exist and must require BOTH markers. ---
check "rdp probe distinguishes post-NLA cancel (success) from pre-NLA cancel (failure)" \
  'grep -q "ERRCONNECT_CONNECT_CANCELLED. in out and .NLA_STATE_FINAL. in out" "$HERE/ui_server.py"'

# --- "Test login" must use the REAL rfc probe, not the legacy icm_auth_test it
# was left pointing at when the protocols[] system was built. And fields.saprouter
# must work as an alias for fields.router -- it's the more natural name to type. ---
printf '%s' '{"mode":"auth","entry":{"kind":"rfc","host":"127.0.0.1","user":"u","secret":"p","fields":{"sysnr":"00","client":"100"}}}' > "$TD/legacy_rfc.json"
check "top-level 'Test login' calls the real JCo probe for rfc kind, not icm-auth" \
  '[ "$(api_test "$TD/legacy_rfc.json" | jq -r .kind)" = "rfc" ]'

check "fields.saprouter is honoured as an alias for fields.router" \
  'grep -q "f.get(\"router\") or f.get(\"saprouter\")" "$HERE/ui_server.py"'

check "cmd_rfc falls back to CREDS_SAPROUTER when CREDS_ROUTER is unset" \
  'grep -q "CREDS_ROUTER:-\${CREDS_SAPROUTER:-}" "$HERE/creds"'

# ---- landscape graph ------------------------------------------------------

check "graph.py selftest passes (window parsing, BFS, secret containment)" \
  'python3 "$HERE/graph.py" selftest >/dev/null'

# A graph over the throwaway index: two hops, each with its own prerequisite.
cat > "$TD/graphed.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-dev-rfc","customer":"acme","env":"dev","kind":"rfc",
  "host":"dev.acme.test","user":"TESTER","secret":"s3cr3t p@ss","fields":{}}],
 "nodes":[
  {"id":"mac","label":"my mac","type":"client"},
  {"id":"rtr","label":"acme router","type":"saprouter"},
  {"id":"d01","label":"D01","type":"appserver","env":"dev","creds":["acme-dev-rfc"]}],
 "edges":[
  {"from":"mac","to":"rtr","type":"network","port":3299,"requires":["vpn:acme"]},
  {"from":"rtr","to":"d01","type":"rfc","port":3300,"requires":["vpn:acme","acl:jump"]}]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/graphed.json"

check "path walks both hops in order" \
  '[ "$("$HERE/creds" path mac d01 --json | jq -r "[.hops[].to]|join(\",\")")" = "rtr,d01" ]'

check "path accumulates requires across hops, deduped" \
  '[ "$("$HERE/creds" path mac d01 --json | jq -r ".requires|join(\",\")")" = "vpn:acme,acl:jump" ]'

check "path resolves a destination by its attached entry id" \
  '[ "$("$HERE/creds" path mac acme-dev-rfc --json | jq -r ".dst")" = "d01" ]'

check "path never prints a secret" \
  '! "$HERE/creds" path mac d01 --json | grep -q "s3cr3t"'

check "path reports no route rather than inventing one" \
  '! "$HERE/creds" path d01 mac >/dev/null 2>&1'

# A dangling edge is exactly the drift the graph is meant to prevent.
jq '.edges += [{"from":"d01","to":"ghost","type":"network"}]' "$TD/graphed.json" > "$TD/dangling.json"
check "edit refuses to save an edge pointing at a non-existent node" \
  'EDITOR="cp $TD/dangling.json" "$HERE/creds" edit 2>&1 | grep -q "ghost"'

jq '.nodes[2].creds = ["no-such-entry"]' "$TD/graphed.json" > "$TD/badref.json"
check "edit refuses to save a node whose creds ref matches no entry" \
  'EDITOR="cp $TD/badref.json" "$HERE/creds" edit 2>&1 | grep -q "no-such-entry"'

check "an index with no graph at all still validates" \
  'jq "del(.nodes,.edges)" "$TD/graphed.json" > "$TD/nograph.json"; \
   EDITOR="cp $TD/nograph.json" "$HERE/creds" edit >/dev/null 2>&1'

# One box, three ways in: default must stay shortest, --all must show all three.
jq '.edges += [{"from":"rtr","to":"d01","type":"gateway","port":3300},
               {"from":"rtr","to":"d01","type":"ssh","port":22}]' \
   "$TD/graphed.json" > "$TD/multi.json"
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/multi.json"

check "path defaults to a single shortest route" \
  '[ "$("$HERE/creds" path mac d01 --json | jq ".routes == null")" = "true" ]'

check "path --all lists every route into the same node" \
  '[ "$("$HERE/creds" path mac d01 --all --json | jq ".routes|length")" = "3" ]'

check "path --all keeps each route's own port" \
  '"$HERE/creds" path mac d01 --all | grep -q "ssh:22"'

check "gateway/disp/msgserver are accepted edge types" \
  'jq ".edges[0].type = \"msgserver\" | .edges[0].port = 3611" "$TD/graphed.json" > "$TD/mst.json"; \
   EDITOR="cp $TD/mst.json" "$HERE/creds" edit >/dev/null 2>&1'

# ---- logins[]: one system, several (client, user, password) ---------------

cat > "$TD/logins.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-prd-abap-p01","customer":"acme","env":"qas","kind":"abap",
  "host":"p01.acme.test","fields":{"sid":"P01","sysnr":"00"},
  "logins":[
   {"client":"000","user":"DDIC","secret":"ddicpw"},
   {"client":"300","user":"IB_ADAM","secret":"adampw","default":true},
   {"client":"300","user":"SAP*","secret":"starpw"}]},
 {"id":"acme-dev-abap-d01","customer":"acme","env":"dev","kind":"abap",
  "host":"d01.acme.test","user":"FLAT","secret":"flatpw","fields":{"client":"100"}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/logins.json"

check "find never emits a secret from inside logins[]" \
  '! "$HERE/creds" find acme | grep -qE "ddicpw|adampw|starpw"'

check "find matches a user that only exists inside logins[]" \
  '[ "$("$HERE/creds" find acme ib_adam | jq -r ".[0].id")" = "acme-prd-abap-p01" ]'

check "exec picks the login marked default" \
  '[ "$("$HERE/creds" exec acme-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_USER\"")" = "IB_ADAM" ]'

check "--as selects a different user on the same system" \
  '[ "$("$HERE/creds" exec --as "SAP*" acme-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_CLIENT\"")" = "300" ]'

check "--client narrows to that client" \
  '[ "$("$HERE/creds" exec --client 000 acme-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_USER\"")" = "DDIC" ]'

check "the chosen login's password reaches the child, not the entry's" \
  '[ "$("$HERE/creds" exec --client 000 acme-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "ddicpw" ]'

check "an unmatched --as fails loudly and lists what exists" \
  '"$HERE/creds" exec --as NOBODY acme-prd-abap-p01 -- true 2>&1 | grep -q "DDIC"'

check "an entry with no logins[] still works from its flat fields" \
  '[ "$("$HERE/creds" exec acme-dev-abap-d01 -- sh -c "printf %s \"\$CREDS_USER-\$CREDS_CLIENT\"")" = "FLAT-100" ]'

check "a login with no user is refused at save time" \
  'jq ".entries[0].logins[0].user = \"\"" "$TD/logins.json" > "$TD/nouser.json"; \
   EDITOR="cp $TD/nouser.json" "$HERE/creds" edit 2>&1 | grep -q "logins with no user"'

# ---- creds lint -----------------------------------------------------------

cat > "$TD/lint.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-prd-abap-p01","customer":"acme","env":"prd","kind":"abap",
  "host":"p01","fields":{"sid":"P01"},
  "logins":[{"client":"000","user":"DDIC","secret":"topsecretpw"}]},
 {"id":"acme-dev-abap-d01","customer":"acme","env":"qas","kind":"abap",
  "host":"d01","fields":{},"logins":[{"client":"100","user":"U","secret":"x"}]},
 {"id":"acme-10-1-2-3-sapgui","customer":"acme","env":"dev","kind":"sapgui",
  "host":"10.1.2.3","fields":{}},
 {"id":"acme-prd-abap-dupe","customer":"acme","env":"prd","kind":"abap","host":"h",
  "fields":{},"logins":[{"client":"000","user":"A","secret":"1"},
                        {"client":"000","user":"A","secret":"2"}]},
 {"id":"beta-dev-ssh-box","customer":"beta","env":"dev","kind":"ssh","host":"b","fields":{}}
],
 "nodes":[{"id":"acme-p01","customer":"acme","creds":["beta-dev-ssh-box"]}],
 "edges":[]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/lint.json"

check "lint flags an id/env mismatch as an ERROR" \
  '"$HERE/creds" lint 2>&1 | grep -A1 "ERROR acme-dev-abap-d01" | grep -q "one of them is a lie"'

check "lint exits non-zero when there is an ERROR" \
  '! "$HERE/creds" lint >/dev/null 2>&1'

check "lint flags a duplicate login as an ERROR" \
  '"$HERE/creds" lint 2>&1 | grep -q "duplicate login A@000"'

check "lint flags a node borrowing another customer's credential" \
  '"$HERE/creds" lint 2>&1 | grep -q "belongs to customer .beta."'

check "lint warns about an IP embedded in an id" \
  '"$HERE/creds" lint 2>&1 | grep -A1 "acme-10-1-2-3-sapgui" | grep -q "embeds an IP"'

check "lint never prints a secret" \
  '! "$HERE/creds" lint --all 2>&1 | grep -qE "topsecretpw"'

check "lint --customer scopes to one customer" \
  '! "$HERE/creds" lint --customer beta 2>&1 | grep -q "acme-dev-abap-d01"'

check "a conforming entry produces no error or warning" \
  '! "$HERE/creds" lint 2>&1 | grep -qE "(ERROR|WARN) +acme-prd-abap-p01$"'

check "legacy ids are notes, not errors" \
  'jq "{version:1, entries:[{id:\"x-weird-legacy-name\",customer:\"x\",env:\"dev\",kind:\"sapgui\",host:\"h\",fields:{}}]}" -n > "$TD/legacy.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/legacy.json"; \
   "$HERE/creds" lint >/dev/null 2>&1 && "$HERE/creds" lint --all 2>&1 | grep -q "legacy id"'

check "lint warns when requires points at a renamed/missing entry" \
  'jq "{version:1, entries:[{id:\"x-dev-ssh-h\",customer:\"x\",env:\"dev\",kind:\"ssh\",host:\"h\",fields:{},requires:[\"x-gone\",\"internet\",\"vpn:ok\"]}]}" -n > "$TD/req.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/req.json"; \
   "$HERE/creds" lint 2>&1 | grep -q "requires .x-gone. matches no entry id"'

check "lint does not warn about prefixed free-text requires" \
  '! "$HERE/creds" lint 2>&1 | grep -qE "requires .(internet|vpn:ok)."'

check "the ui offers abap and knows it takes logins" \
  'grep -q "const LOGIN_KINDS = \[\"abap\"\]" "$HERE/ui.html" && grep -q "abap.*hana.*ssh" "$HERE/ui.html"'

check "the abap connection grid hides the flat user/secret" \
  'grep -q "usesLogins(e) && (k === \"user\" || k === \"secret\")" "$HERE/ui.html"'

check "a duplicated entry does not inherit its logins passwords" \
  'grep -q "c.logins.map(l => ({ ...l, secret: \"\" }))" "$HERE/ui.html"'

check "the server resolves a login before any probe reads user/secret" \
  'grep -q "ent = with_login(payload.get(\"entry\") or payload, payload.get(\"login\"))" "$HERE/ui_server.py"'

check "with_login prefers the default and falls back to the first" \
  'python3 -c "
import sys; sys.path.insert(0, \"$HERE\")
import ui_server as u
e = {\"user\":\"OLD\",\"secret\":\"old\",\"fields\":{\"client\":\"999\"},\"logins\":[
     {\"client\":\"000\",\"user\":\"A\",\"secret\":\"a\"},
     {\"client\":\"300\",\"user\":\"B\",\"secret\":\"b\",\"default\":True}]}
assert u.with_login(e)[\"user\"] == \"B\", \"default wins\"
assert u.with_login(e)[\"fields\"][\"client\"] == \"300\"
assert u.with_login(e, {\"user\":\"A\"})[\"secret\"] == \"a\", \"selector wins\"
assert u.with_login({\"user\":\"F\",\"secret\":\"f\"})[\"user\"] == \"F\", \"no logins: unchanged\"
"'

# ---- landscape canvas -----------------------------------------------------

check "the server serves /landscape behind the same token" \
  'grep -q "if path == \"/landscape\":" "$HERE/ui_server.py" && \
   sed -n "/if path == .\/landscape.:/,/text\/html/p" "$HERE/ui_server.py" | grep -q "self._auth()"'

check "the canvas never renders a secret into the DOM" \
  '! grep -qE "\.secret|logins\[" "$HERE/landscape.html"'

check "fit refuses to run against a pre-layout rect" \
  'grep -q "r.width < 200 || r.height < 200" "$HERE/landscape.html"'

check "the canvas refuses a creds ref that matches no entry" \
  'grep -q "if (!(idx.entries || \[\]).some(e => e.id === v))" "$HERE/landscape.html"'

check "deleting a node also deletes its edges" \
  'grep -q "idx.edges = edges().filter(e => e.from !== n.id && e.to !== n.id)" "$HERE/landscape.html"'

check "canvas edge types match the ones graph.py accepts" \
  'python3 -c "
import re, sys
sys.path.insert(0, \"$HERE\")
import graph
html = open(\"$HERE/landscape.html\").read()
m = re.search(r\"const EDGE_TYPES = \[(.*?)\]\", html, re.S)
ui = set(re.findall(r\"\\\"([a-z]+)\\\"\", m.group(1)))
assert ui <= graph.EDGE_TYPES, ui - graph.EDGE_TYPES
"'

check "canvas node types match the ones graph.py accepts" \
  'python3 -c "
import re, sys
sys.path.insert(0, \"$HERE\")
import graph
html = open(\"$HERE/landscape.html\").read()
m = re.search(r\"const NODE_TYPES = \[(.*?)\]\", html, re.S)
ui = set(re.findall(r\"\\\"([a-z]+)\\\"\", m.group(1)))
assert ui <= graph.NODE_TYPES, ui - graph.NODE_TYPES
"'

# ---- creds migrate --------------------------------------------------------

cat > "$TD/mig.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-weird-name-sapgui","customer":"acme","env":"prd","kind":"sapgui",
  "host":"p01.acme.test","user":"","secret":"","fields":{"sid":"P01","sysnr":"00"}},
 {"id":"acme-p01-rfc","customer":"acme","env":"prd","kind":"rfc",
  "host":"p01.acme.test","user":"DDIC","secret":"pw1","fields":{"sid":"P01","sysnr":"00","client":"000"}},
 {"id":"acme-clash-a","customer":"acme","env":"dev","kind":"rfc",
  "host":"d01.acme.test","user":"U","secret":"one","fields":{"sid":"D01","sysnr":"00","client":"100"}},
 {"id":"acme-clash-b","customer":"acme","env":"dev","kind":"sapgui",
  "host":"d01.acme.test","user":"U","secret":"two","fields":{"sid":"D01","sysnr":"00","client":"100"}},
 {"id":"acme-nosid-sapgui","customer":"acme","env":"qas","kind":"sapgui",
  "host":"q01.acme.test","user":"","secret":"","fields":{"sysnr":"00"}},
 {"id":"acme-prd-ssh-box-root","customer":"acme","env":"prd","kind":"ssh",
  "host":"1.2.3.4","user":"root","secret":"x","fields":{}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/mig.json"

check "migrate merges an rfc and a sapgui sharing host+sysnr" \
  '"$HERE/creds" migrate --customer acme | grep -q "acme-prd-abap-p01"'

check "migrate refuses to merge when one login has two different passwords" \
  '"$HERE/creds" migrate --customer acme | grep -q "conflicting"'

check "migrate never invents a SID" \
  '"$HERE/creds" migrate --customer acme | grep -q "acme-nosid-sapgui: no SID"'

check "migrate leaves an already-conforming id alone" \
  '! "$HERE/creds" migrate --customer acme | grep -q "acme-prd-ssh-box-root$"'

check "migrate is a dry run unless --apply is given" \
  '"$HERE/creds" migrate --customer acme >/dev/null 2>&1; \
   [ "$("$HERE/creds" find acme p01 rfc | jq length)" = "1" ]'

check "the prod guard still fires on a merged entry (env survived the merge)" \
  '"$HERE/creds" migrate --customer acme --apply >/dev/null 2>&1; \
   "$HERE/creds" exec acme-prd-abap-p01 -- true 2>&1 | grep -q "is PRODUCTION"'

check "a plan containing a collision still applies its usable part" \
  '[ "$("$HERE/creds" find acme abap | jq length)" = "1" ]'

check "migrate --apply keeps the password on the merged login" \
  '[ "$(CREDS_ALLOW_PROD=1 "$HERE/creds" exec acme-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "pw1" ]'

check "migrate --apply left the conflicting pair untouched" \
  '[ "$("$HERE/creds" find acme clash | jq length)" = "2" ]'

check "migrate output never contains a password" \
  '! "$HERE/creds" migrate --customer acme 2>&1 | grep -qE "pw1|one|two"'

check "migrate distinguishes an IP+name collision from two real app servers" \
  'printf "%s" "{\"version\":1,\"entries\":[
   {\"id\":\"z-a\",\"customer\":\"z\",\"env\":\"prd\",\"kind\":\"rfc\",\"host\":\"10.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sid\":\"AAA\",\"sysnr\":\"00\"}},
   {\"id\":\"z-b\",\"customer\":\"z\",\"env\":\"prd\",\"kind\":\"rfc\",\"host\":\"box.example.com\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sid\":\"AAA\",\"sysnr\":\"00\"}},
   {\"id\":\"z-c\",\"customer\":\"z\",\"env\":\"prd\",\"kind\":\"rfc\",\"host\":\"ai01.example.com\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sid\":\"BBB\",\"sysnr\":\"00\"}},
   {\"id\":\"z-d\",\"customer\":\"z\",\"env\":\"prd\",\"kind\":\"rfc\",\"host\":\"ai02.example.com\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sid\":\"BBB\",\"sysnr\":\"00\"}}]}" > "$TD/coll.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/coll.json"; \
   out=$("$HERE/creds" migrate --customer z); \
   printf "%s" "$out" | grep -q "SID AAA.*probably ONE box" && \
   printf "%s" "$out" | grep -q "SID BBB.*SEPARATE app servers"'

check "migrate drops a colliding proposal instead of emitting an unsavable plan" \
  'out=$("$HERE/creds" migrate --customer z); \
   printf "%s" "$out" | grep -q "would be claimed by" && \
   ! printf "%s" "$out" | grep -qE "^  z-[cd]$"'

check "api probe knows the oauth2 client-credentials style" \
  'grep -q "def oauth2_status" "$HERE/ui_server.py" && \
   grep -q "\"grant_type\": \"client_credentials\"" "$HERE/ui_server.py"'

check "oauth2 probe demands a token_url" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"api\",\"host\":\"h\",\"user\":\"cid\",\"secret\":\"s\",
    \"fields\":{\"base_url\":\"https://x.test\",\"verify_path\":\"/p\",\"auth_style\":\"oauth2\"}},
    \"protocol\":{\"type\":\"api\"}}" > "$TD/o1.json"; \
   api_test "$TD/o1.json" | grep -q "token_url"'

check "oauth2 probe demands a client id in the user field" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"api\",\"host\":\"h\",\"user\":\"\",\"secret\":\"s\",
    \"fields\":{\"base_url\":\"https://x.test\",\"verify_path\":\"/p\",\"auth_style\":\"oauth2\",
    \"token_url\":\"https://t.test\"}},\"protocol\":{\"type\":\"api\"}}" > "$TD/o2.json"; \
   api_test "$TD/o2.json" | grep -q "client id"'

check "the editor requires token_url only when auth_style is oauth2" \
  'grep -q "auth_style || \"\").toLowerCase() === \"oauth2\"" "$HERE/ui.html"'

check "lint always surfaces non-conforming ids, even with notes hidden" \
  'printf "%s" "{\"version\":1,\"entries\":[
   {\"id\":\"z-dev-ssh-box\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"ssh\",\"host\":\"h\",\"fields\":{}},
   {\"id\":\"z-99-legacy-name\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"ssh\",\"host\":\"h\",\"fields\":{}}]}" > "$TD/nc.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/nc.json"; \
   "$HERE/creds" lint | grep -q "1/2 id(s) do NOT follow"'

check "a fully conforming customer reports no non-conforming ids" \
  'printf "%s" "{\"version\":1,\"entries\":[
   {\"id\":\"z-dev-ssh-box\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"ssh\",\"host\":\"h\",\"fields\":{}}]}" > "$TD/c.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/c.json"; \
   ! "$HERE/creds" lint | grep -q "do NOT follow"'

# Regression: merging an already-migrated abap entry (logins[]) with a flat one must
# keep BOTH sets of credentials. Reading only the flat fields destroyed them once.
cat > "$TD/keep.json" <<'JSON'
{"version":1,"entries":[
 {"id":"k-prd-abap-p01","customer":"k","env":"prd","kind":"abap","host":"p.test",
  "fields":{"sid":"P01","sysnr":"00"},
  "logins":[{"client":"310","user":"SAP*","secret":"fromlogins","default":true}]},
 {"id":"k-legacy-sapgui","customer":"k","env":"prd","kind":"sapgui","host":"p.test",
  "user":"DDIC","secret":"fromflat","fields":{"sid":"P01","sysnr":"00","client":"000"}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/keep.json"

check "merging keeps a login stored in logins[], not just the flat one" \
  '"$HERE/creds" migrate --customer k --apply >/dev/null 2>&1; \
   [ "$(CREDS_ALLOW_PROD=1 "$HERE/creds" exec --as "SAP*" k-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "fromlogins" ]'

check "merging also keeps the flat-field login" \
  '[ "$(CREDS_ALLOW_PROD=1 "$HERE/creds" exec --as DDIC k-prd-abap-p01 -- sh -c "printf %s \"\$CREDS_PASSWORD\"")" = "fromflat" ]'

check "no login is lost in the merge" \
  '[ "$("$HERE/creds" find k-prd-abap-p01 | jq ".[0].logins|length")" = "2" ]'

# ---- kind: java (NetWeaver Java — PI/PO, Portal, SolMan Java) --------------

check "java reachability uses 5<nn>00, not the ABAP dispatcher port" \
  'printf "%s" "{\"mode\":\"reach\",\"entry\":{\"kind\":\"java\",\"host\":\"127.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sysnr\":\"02\"}}}" > "$TD/j1.json"; \
   api_test "$TD/j1.json" | grep -q "50200"'

check "java-http derives 5<nn>00 from the instance number" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"java\",\"host\":\"127.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sysnr\":\"01\"}},\"protocol\":{\"type\":\"java-http\"}}" > "$TD/j2.json"; \
   api_test "$TD/j2.json" | grep -q "50100"'

check "java-https derives 5<nn>01" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"java\",\"host\":\"127.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sysnr\":\"01\"}},\"protocol\":{\"type\":\"java-https\"}}" > "$TD/j3.json"; \
   api_test "$TD/j3.json" | grep -q "50101"'

check "p4 derives 5<nn>04" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"java\",\"host\":\"127.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sysnr\":\"00\"}},\"protocol\":{\"type\":\"p4\"}}" > "$TD/j4.json"; \
   api_test "$TD/j4.json" | grep -q "50004"'

check "an explicit java-http port overrides the convention" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"java\",\"host\":\"127.0.0.1\",\"user\":\"U\",\"secret\":\"p\",\"fields\":{\"sysnr\":\"00\"}},\"protocol\":{\"type\":\"java-http\",\"port\":51234}}" > "$TD/j5.json"; \
   api_test "$TD/j5.json" | grep -q "51234"'

check "the java kind is known to lint, migrate and the editor alike" \
  'grep -q "\"java\"" "$HERE/lint.py" && grep -q "kind == \"java\"" "$HERE/migrate.py" && \
   grep -q "\"abap\", \"java\"" "$HERE/ui.html"'

# ---- sync-ssh ------------------------------------------------------------
# In jq only null and false are falsy, so select(.user) passed on "" and emitted a
# bare "User" with no argument -- 63 of them, which made ssh reject the whole file
# and broke every ssh on the machine, not just the creds aliases.

cat > "$TD/ssh.json" <<'JSON'
{"version":1,"entries":[
 {"id":"z-prd-ssh-box","customer":"z","env":"prd","kind":"ssh","host":"h1",
  "port":2222,"user":"root","secret":"x","via":"jump.test","fields":{"identity":"~/.ssh/id_x"}},
 {"id":"z-dev-ssh-blank","customer":"z","env":"dev","kind":"ssh","host":"h2",
  "user":"","secret":"","via":"","fields":{"identity":""}},
 {"id":"z-prd-hana-h1-admin","customer":"z","env":"prd","kind":"hana","host":"h3",
  "user":"CUST_ADMIN","secret":"x","fields":{}},
 {"id":"z-prd-abap-p01","customer":"z","env":"prd","kind":"abap","host":"h4",
  "user":"","secret":"","fields":{"sid":"P01"}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/ssh.json"
HOME_BAK=$HOME; export HOME="$TD/home"; mkdir -p "$HOME/.ssh"

check "sync-ssh never emits a keyword without an argument" \
  '"$HERE/creds" sync-ssh >/dev/null 2>&1; \
   ! grep -qE "^[[:space:]]*(User|Port|ProxyJump|IdentityFile|HostName)[[:space:]]*$" \
       "$HOME/.ssh/config.d/local-creds"'

check "the generated config actually parses with ssh" \
  'ssh -F "$HOME/.ssh/config.d/local-creds" -G syntax-check >/dev/null 2>&1'

check "an OS-level kind keeps its User" \
  'awk "/^Host z-prd-ssh-box\$/,/^\$/" "$HOME/.ssh/config.d/local-creds" | grep -q "User root"'

check "an application user never becomes an SSH User" \
  '! awk "/^Host z-prd-hana-h1-admin\$/,/^\$/" "$HOME/.ssh/config.d/local-creds" | grep -q "CUST_ADMIN"'

check "an abap user never becomes an SSH User either" \
  '! awk "/^Host z-prd-abap-p01\$/,/^\$/" "$HOME/.ssh/config.d/local-creds" | grep -qi "^ *User"'

check "empty via/identity emit nothing rather than a bare keyword" \
  'awk "/^Host z-dev-ssh-blank\$/,/^\$/" "$HOME/.ssh/config.d/local-creds" | grep -cE "^ +(ProxyJump|IdentityFile|User)" | grep -q "^0$"'

check "a config that would not parse is never written over the good one" \
  'cp "$HOME/.ssh/config.d/local-creds" "$TD/good"; \
   printf "%s" "{\"version\":1,\"entries\":[{\"id\":\"bad id with spaces\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"ssh\",\"host\":\"h\",\"user\":\"u\",\"secret\":\"s\",\"fields\":{\"identity\":\"a b\nMatch bogusrubbish\"}}]}" > "$TD/bad.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/bad.json"; \
   "$HERE/creds" sync-ssh >/dev/null 2>&1; \
   cmp -s "$TD/good" "$HOME/.ssh/config.d/local-creds"'

export HOME=$HOME_BAK
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/ssh.json"

# A SAProuter route string carries its password inline as /W/<pw>, and it lives in
# `fields`, which find prints in full. Without redaction `creds find` puts a live
# credential into the terminal and the session transcript.
cat > "$TD/router.json" <<'JSON'
{"version":1,"entries":[
 {"id":"r-dev-abap-ecd","customer":"r","env":"dev","kind":"abap","host":"h",
  "secret":"","via":"/H/1.2.3.4/S/3299/W/viapw",
  "requires":["router:/H/1.2.3.4/S/3299/W/reqpw"],
  "fields":{"sid":"ECD","router":"/H/1.2.3.4/S/3299/W/routerpw"},
  "logins":[{"client":"000","user":"DDIC","secret":"loginpw"}]}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/router.json"

check "find redacts a SAProuter route password in fields" \
  '! "$HERE/creds" find r | grep -q routerpw'

check "find redacts one in via and in requires too" \
  '! "$HERE/creds" find r | grep -qE "viapw|reqpw"'

check "the redaction keeps the route readable, only masking the password" \
  '"$HERE/creds" find r | grep -q "/H/1.2.3.4/S/3299/W/\*\*\*"'

check "exec still receives the REAL route, not the masked one" \
  '[ "$("$HERE/creds" exec r-dev-abap-ecd -- sh -c "printf %s \"\$CREDS_ROUTER\"")" = "/H/1.2.3.4/S/3299/W/routerpw" ]'

# /oauth/token is XSUAA's path; SAP Cloud Identity Services uses /oauth2/token.
# Appending blindly turned a correct ".../oauth2/token" into ".../oauth2/token/oauth/token".
check "oauth2 completes a bare origin with /oauth/token" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"api\",\"host\":\"h\",\"user\":\"cid\",\"secret\":\"s\",
    \"fields\":{\"base_url\":\"https://x.invalid\",\"verify_path\":\"/p\",\"auth_style\":\"oauth2\",
    \"token_url\":\"https://uaa.invalid\"}},\"protocol\":{\"type\":\"api\"}}" > "$TD/t1.json"; \
   api_test "$TD/t1.json" | grep -q "token endpoint"'

check "oauth2 respects an explicit token path instead of mangling it" \
  'python3 -c "
import sys, urllib.parse
sys.path.insert(0, \"$HERE\")
import ui_server
src = open(\"$HERE/ui_server.py\").read()
assert \"urllib.parse.urlsplit(turl).path.strip\" in src, \"bare-origin guard missing\"
def complete(u):
    u = u.rstrip(\"/\")
    return u if urllib.parse.urlsplit(u).path.strip(\"/\") else u + \"/oauth/token\"
assert complete(\"https://t.accounts.ondemand.com/oauth2/token\") == \"https://t.accounts.ondemand.com/oauth2/token\"
assert complete(\"https://uaa.example.com\") == \"https://uaa.example.com/oauth/token\"
assert complete(\"https://uaa.example.com/\") == \"https://uaa.example.com/oauth/token\"
assert complete(\"https://uaa.example.com/oauth/token\") == \"https://uaa.example.com/oauth/token\"
"'

check "every login row offers show, copy, Test and Change" \
  'grep -q "class=\"lshow\"" "$HERE/ui.html" && grep -q "class=\"lcopy\"" "$HERE/ui.html" && \
   grep -q "class=\"ltest\"" "$HERE/ui.html" && grep -q "class=\"lpw\"" "$HERE/ui.html"'

check "the flat secret row offers show, copy and Change too" \
  'grep -q "id=\"reveal\"" "$HERE/ui.html" && grep -q "id=\"copypw\"" "$HERE/ui.html" && \
   grep -q "id=\"setpw\"" "$HERE/ui.html"'

check "login passwords render masked, never as plain text" \
  'grep -A2 "class=\"lsec\"" "$HERE/ui.html" | grep -q "webkit-text-security:disc"'

check "the login field handler is scoped to [data-k] so the password field cannot corrupt a login" \
  'grep -q "querySelectorAll(\"input\[data-k\]\")" "$HERE/ui.html"'

check "copy falls back to execCommand when the clipboard API is unavailable" \
  'grep -q "document.execCommand(\"copy\")" "$HERE/ui.html"'

# ---- oauth2-body (Microsoft Entra / Azure AD) -----------------------------
# XSUAA/IAS send client creds as HTTP Basic; Azure AD wants them in the form body,
# with resource= on the v1.0 token endpoint and scope= (rejecting resource) on v2.0.

check "oauth2-body demands a full token_url, not a bare origin" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"api\",\"host\":\"h\",\"user\":\"app\",\"secret\":\"s\",
    \"fields\":{\"base_url\":\"https://graph.invalid\",\"verify_path\":\"/organization\",
    \"auth_style\":\"oauth2-body\",\"token_url\":\"https://login.invalid\",
    \"resource\":\"https://graph.invalid\"}},\"protocol\":{\"type\":\"api\"}}" > "$TD/az1.json"; \
   api_test "$TD/az1.json" | grep -qi "bare origin is ambiguous"'

check "oauth2-body selects the token param by endpoint version (v1 resource / v2 scope)" \
  'grep -q "is_v2 = ." "$HERE/ui_server.py" && \
   grep -q "elif not is_v2 and f.get" "$HERE/ui_server.py" && \
   grep -q "form\[.client_secret.\] = secret" "$HERE/ui_server.py"'

check "the api probe advertises oauth2-body as a style" \
  'grep -q "bearer | header | basic | query | oauth2 | oauth2-body" "$HERE/ui_server.py"'

# ---- kind: vmware (vCenter) ----------------------------------------------
# The control must use a random USERNAME, never a wrong password: vCenter SSO locks
# an account after repeated failures, and Administrator@vsphere.local is the one
# account you cannot afford to lock.

check "vmware probe demands both a user and a password" \
  'printf "%s" "{\"mode\":\"proto\",\"entry\":{\"kind\":\"vmware\",\"host\":\"h\",\"user\":\"\",\"secret\":\"\",\"fields\":{}},\"protocol\":{\"type\":\"vmware\"}}" > "$TD/vc1.json"; \
   api_test "$TD/vc1.json" | grep -q "needs both a user"'

check "vmware control uses a random username, not a wrong password" \
  'grep -A3 "ctl, _ = attempt(" "$HERE/ui_server.py" | grep -q "@vsphere.local" && \
   grep -q "locks accounts after repeated failures" "$HERE/ui_server.py"'

check "vmware verifies TLS by default and names the opt-out on a cert error" \
  'grep -q "verify_tls" "$HERE/ui_server.py" && \
   grep -q "factory self-signed" "$HERE/ui_server.py"'

check "vmware falls back to the 6.5/6.7 session path" \
  'grep -q "/rest/com/vmware/cis/session" "$HERE/ui_server.py"'

# A kind must be known to lint (so it is not warned about), migrate (so it gets an
# identity token) and the editor (so selecting it does not silently blank the field).
# Matches the kind name itself, not the text around it -- adding a neighbouring kind
# must not break this.
kind_registered() {
  grep -q "\"$1\"" "$HERE/lint.py" &&
  grep -q "\"$1\"" "$HERE/migrate.py" &&
  grep -q "\"$1\"" "$HERE/ui.html"
}

check "the vmware kind is registered in lint, migrate and the editor alike" \
  'kind_registered vmware'

check "the webdisp kind is registered in lint, migrate and the editor alike" \
  'kind_registered webdisp'

check "the scc kind is registered in lint, migrate and the editor alike" \
  'kind_registered scc'

check "the suser kind is registered in lint, migrate and the editor alike" \
  'kind_registered suser'

check "an unregistered kind is not silently accepted" \
  '! kind_registered kubernetes'

check "lint warns about a kind the tooling does not know" \
  'printf "%s" "{\"version\":1,\"entries\":[{\"id\":\"z-dev-kubernetes-box\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"kubernetes\",\"host\":\"h\",\"fields\":{}}]}" > "$TD/unk.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/unk.json"; \
   "$HERE/creds" lint | grep -q "kind .kubernetes. is not registered"'

check "lint does not warn about a registered kind" \
  'printf "%s" "{\"version\":1,\"entries\":[{\"id\":\"z-prd-vmware-vc\",\"customer\":\"z\",\"env\":\"prd\",\"kind\":\"vmware\",\"host\":\"h\",\"fields\":{}}]}" > "$TD/kn.json"; \
   age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/kn.json"; \
   ! "$HERE/creds" lint | grep -q "is not registered"'

# ---- fields.url (autofill origin) -----------------------------------------
# url is the ORIGIN a browser page is matched against before a password is filled.
# The rule that earns its keep: plaintext http is fine to a PRIVATE address (most of
# an SAP estate is internal http) but not to a public one. A well-meaning tightening
# to https-only would silently kill autofill for every internal Fiori/PI/cockpit URL,
# so that case is pinned here.
url_lint() {
  printf '%s' "{\"version\":1,\"entries\":[{\"id\":\"z-dev-java-pid\",\"customer\":\"z\",\"env\":\"dev\",\"kind\":\"java\",\"host\":\"h\",\"fields\":{\"url\":\"$1\"}}]}" > "$TD/url.json"
  age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/url.json"
  "$HERE/creds" lint --all 2>&1
}

check "lint accepts plaintext http to a private address" \
  '! url_lint "http://10.70.212.13:50000/dir/start/index.jsp" | grep -q "crosses the open internet"'

check "lint warns about plaintext http to a public host" \
  'url_lint "http://portal.example.com" | grep -q "crosses the open internet"'

check "lint warns about a url with no scheme" \
  'url_lint "portal.example.com/login" | grep -q "never match a page"'

check "lint warns about a non-web url scheme" \
  'url_lint "ssh://box.example.com" | grep -q "is not http(s)"'

check "lint accepts https to a public host" \
  '! url_lint "https://um018.atlassian.net" | grep -qE "(ERROR|WARN) +z-dev-java-pid"'

# ---- creds-nm (browser native messaging host) ------------------------------
# The whole security model is the DOUBLE ORIGIN CHECK: the extension may only ask
# "what fits this origin", and `fill` re-derives the match from the origin instead of
# trusting the id it was handed. Sabotaging that check must break these tests.
cat > "$TD/nm.json" <<'JSON'
{"version":1,"entries":[
 {"id":"acme-dev-java-pi","customer":"acme","env":"dev","kind":"java",
  "host":"10.70.1.1","user":"Administrator","secret":"nmdevpw123",
  "fields":{"url":"http://10.70.1.1:50000/dir/start/index.jsp"}},
 {"id":"acme-prd-api-jira","customer":"acme","env":"prd","kind":"api",
  "host":"x.atlassian.net","user":"bot@acme.test","secret":"nmprodpw456",
  "fields":{"url":"https://x.atlassian.net/rest/api/2"}},
 {"id":"acme-dev-abap-d01","customer":"acme","env":"dev","kind":"abap",
  "host":"d01.acme.test",
  "logins":[{"client":"100","user":"DDIC","secret":"nmloginpw789"},
            {"client":"200","user":"SAPUSER","secret":"nmloginpw200"}],
  "fields":{"url":"https://d01.acme.test"}},
 {"id":"acme-dev-webdisp-ws1","customer":"acme","env":"dev","kind":"webdisp",
  "host":"vip.acme.test","user":"custadmin","secret":"nmwdpw001",
  "fields":{"url":"https://vip.acme.test https://ws1.acme.test:8443"}}
]}
JSON
age -R "$TD/recipients.txt" -o "$TD/creds.age" "$TD/nm.json"
# check() runs its argument through eval, and the shell brace-expands a literal
# {"a":1,"b":2} into two words at the comma -- so the request is built here, from
# plain arguments, and no brace ever reaches eval.
#   nm <cmd> [origin] [id] [user] [client] [confirm]
nm() {
  printf '{"cmd":"%s","origin":"%s","id":"%s","user":"%s","client":"%s","confirm":%s}\n' \
    "$1" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-false}" | "$HERE/creds-nm" --test
}

check "nm ping reports a healthy index" \
  'nm ping | jq -e ".ok and .with_url == 4" >/dev/null'

check "nm matches plaintext http on a private address" \
  '[ "$(nm match http://10.70.1.1:50000 | jq -r ".candidates[0].id")" = "acme-dev-java-pi" ]'

check "nm ignores the path when matching origins" \
  '[ "$(nm match https://x.atlassian.net/browse/ABC-1 | jq -r ".candidates[0].id")" = "acme-prd-api-jira" ]'

check "nm refuses a lookalike domain" \
  '[ "$(nm match https://x.atlassian.net.evil.io | jq ".candidates|length")" = "0" ]'

check "nm refuses a scheme downgrade" \
  '[ "$(nm match http://x.atlassian.net | jq ".candidates|length")" = "0" ]'

check "nm refuses plaintext http to a public host" \
  '[ "$(nm match http://d01.acme.test | jq ".candidates|length")" = "0" ]'

check "nm finds a credential stored in logins[], not just flat fields" \
  '[ "$(nm match https://d01.acme.test | jq -r ".candidates[0].user")" = "DDIC" ]'

# One system, several names: an internal hostname and a public VIP, or a dispatcher
# pair behind one URL. Each origin in fields.url is matched on its own.
check "nm matches the first of several urls on one entry" \
  '[ "$(nm match https://vip.acme.test | jq -r ".candidates[0].id")" = "acme-dev-webdisp-ws1" ]'

check "nm matches a later url, with its own host and port" \
  '[ "$(nm match https://ws1.acme.test:8443 | jq -r ".candidates[0].id")" = "acme-dev-webdisp-ws1" ]'

check "a multi-url entry still refuses an origin it does not list" \
  '[ "$(nm match https://ws9.acme.test:8443 | jq ".candidates|length")" = "0" ]'

check "a port that is not listed does not match" \
  '[ "$(nm match https://ws1.acme.test | jq ".candidates|length")" = "0" ]'

# Paired with the next check: this proves the secret really is reachable, which is what
# stops "match never returns a secret" from passing vacuously.
check "nm fill returns the password for a dev entry" \
  'nm fill http://10.70.1.1:50000 acme-dev-java-pi Administrator | grep -q "nmdevpw123"'

check "nm match never returns a secret" \
  '! nm match http://10.70.1.1:50000 | grep -q "nmdevpw123"'

check "nm fill refuses a production entry without confirm" \
  'nm fill https://x.atlassian.net acme-prd-api-jira bot@acme.test | jq -e ".needs_confirm" >/dev/null'

check "nm fill emits no secret when it refuses production" \
  '! nm fill https://x.atlassian.net acme-prd-api-jira bot@acme.test | grep -q "nmprodpw456"'

check "nm fill allows production once confirmed" \
  'nm fill https://x.atlassian.net acme-prd-api-jira bot@acme.test "" true | grep -q "nmprodpw456"'

# THE check. A caller naming an id that does not belong to the page's origin gets
# nothing -- this is what makes a compromised extension harmless.
check "nm fill refuses an id that does not belong to the origin" \
  '! nm fill http://10.70.1.1:50000 acme-prd-api-jira bot@acme.test "" true | grep -q "nmprodpw456"'

# One system, several accounts: fill must return the account that was ASKED for.
# The origin filter alone cannot catch this -- both logins share an origin.
check "nm fill picks the requested login, not the first on that origin" \
  'nm fill https://d01.acme.test acme-dev-abap-d01 SAPUSER 200 | grep -q "nmloginpw200"'

check "nm fill does not leak a sibling login on the same system" \
  '! nm fill https://d01.acme.test acme-dev-abap-d01 SAPUSER 200 | grep -q "nmloginpw789"'

# Injection is programmatic and gesture-gated: activeTab + scripting, never a
# declarative content script and never a blanket host permission. Losing that means
# the extension is present on every page you visit instead of only when you click it.
# ---- creds browser (playwright, disposable profile) ------------------------
# Covers origin parsing, url precedence, the multi-url split (navigate to ONE of
# several, not the whole string) and the one-attempt logon guard.
check "browser.py pure logic passes its selftest" \
  '"$HERE/browser.py" --selftest >/dev/null 2>&1 || python3 "$HERE/browser.py" --selftest >/dev/null'

check "creds browser without an id prints usage" \
  '"$HERE/creds" browser 2>&1 | grep -q "usage: creds browser"'

# The password reaches browser.py through the environment that creds exec sets up.
# Putting it on the command line would expose it to every process on the box via ps.
check "creds browser never puts the password in a command line" \
  '! grep -n "cmd_browser" -A 5 "$HERE/creds" | grep -qE "CREDS_PASSWORD|\$pw|secret"'

check "browser.py reads the password from the environment, never argv" \
  'grep -q "os.environ.get(\"CREDS_PASSWORD\")" "$HERE/browser.py" && \
   ! grep -qE "argv.*(password|secret)|add_argument.*(password|secret)" "$HERE/browser.py"'

check "browser.py never prints the password" \
  '! grep -nE "print.*(secret|CREDS_PASSWORD)" "$HERE/browser.py"'

# Many SAP accounts lock after three failures. There must be no retry loop.
# Enforced by a guard, not by grepping for loop syntax -- a retry loop can be written
# in more ways than a regex can anticipate, and locking an admin account is expensive.
check "browser.py refuses a second logon attempt in one run" \
  'grep -q "refusing a second logon attempt" "$HERE/browser.py" && \
   grep -q "submit_once(page)" "$HERE/browser.py"'

check "browser.py refuses a cross-origin redirect unless asked" \
  'grep -q "allow-redirect" "$HERE/browser.py" && \
   grep -q "origin_of(landed) not in allowed and not args.allow_redirect" "$HERE/browser.py"'

# Client certs live in the system keychain, not the browser profile: without this the
# "throwaway" browser is still offered the operator's personal SAP Passports, and the
# chooser blocks page load until a human dismisses it.
check "browser.py does not expose the system keychain to the throwaway browser" \
  'grep -q "use-mock-keychain" "$HERE/browser.py"'

check "browser.py uses a disposable in-memory context, never a persistent profile" \
  '! grep -qE "launch_persistent_context\(|user_data_dir *=" "$HERE/browser.py" && \
   grep -q "context.clear_cookies()" "$HERE/browser.py" && \
   grep -q "browser.new_context()" "$HERE/browser.py"'

check "browser.py shares field detection with the extension" \
  'grep -q "extension. / .fill.js" "$HERE/browser.py" || grep -q "\"fill.js\"" "$HERE/browser.py"'

# The browser can read the index and never change it. A write path here would let a
# compromised extension alter entries -- editing stays with `creds edit` / `creds ui`.
check "creds-nm exposes only read-only commands" \
  '[ "$(grep -o "cmd_[a-z]*" "$HERE/creds-nm" | sort -u | tr "\n" " ")" = "cmd_fill cmd_match cmd_ping " ]'

check "creds-nm never re-encrypts or writes the index" \
  '! grep -qE "age., ..-R.|encrypt\(|snapshot\(" "$HERE/creds-nm"'

check "nm rejects an unknown command" \
  'nm frobnicate | jq -e ".ok == false" >/dev/null'

check "the extension registers a keyboard shortcut" \
  'jq -e "._execute_action // .commands._execute_action" "$HERE/extension/manifest.json" >/dev/null'

check "the extension has no host permissions and no declarative content script" \
  '! grep -qE "host_permissions|content_scripts|<all_urls>" "$HERE/extension/manifest.json"'

check "the extension injects only via activeTab + scripting" \
  'jq -e ".permissions | index(\"activeTab\") and index(\"scripting\")" "$HERE/extension/manifest.json" >/dev/null'

check "the field picker passes its unit tests" \
  'node "$HERE/extension/fill.test.js" >/dev/null'

# Autofill must never press the button. A form's action can have changed under it,
# and choosing to log on is the human's call.
check "the injected script never submits a form" \
  '! grep -qE "\.submit\(|requestSubmit|click\(\)" "$HERE/extension/fill.js"'

check "the injected script re-checks the origin inside the page" \
  'grep -q "location.origin !== expectOrigin" "$HERE/extension/fill.js"'

check "the extension manifest pins its id so native messaging keeps working" \
  'jq -e ".key and (.permissions | index(\"nativeMessaging\"))" "$HERE/extension/manifest.json" >/dev/null'
