# `creds` — an encrypted credential index for people who run many systems

One encrypted file holds every system you connect to. Nothing is stored in plaintext,
no command ever prints a password, and connecting to a production system takes a
deliberate extra step.

Built for SAP Basis work across many customer landscapes, but the model is generic:
an entry is *a way to log in to something*, and the tooling around it is vendor-neutral.

```bash
creds find acme qas              # search; secrets stripped from output
creds copy acme-qas-abap-q01     # password -> clipboard, auto-clears
creds exec <id> -- <command>     # run something with CREDS_* injected
creds path my-laptop acme-prd    # route through the landscape + prerequisites
creds lint                       # naming/consistency check
creds ui                         # local web editor, 127.0.0.1, token-gated
```

---

## Contents

- [Why it exists](#why-it-exists)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [First run](#first-run)
- [Daily use](#daily-use)
- [The entry model](#the-entry-model)
- [Naming convention](#naming-convention)
- [Connection tests](#connection-tests)
- [The landscape graph](#the-landscape-graph)
- [Safety model](#safety-model)
- [Multiple machines](#multiple-machines)
- [Files in this repo](#files-in-this-repo)
- [Development](#development)
- [Licence and scope](#licence-and-scope)

---

## Why it exists

If you look after a lot of systems, credentials end up scattered: a spreadsheet here,
a `.txt` next to a project there, some in SAP GUI's own config, some only in your head.
That is bad for security and worse for recall — six months later you cannot remember
whether a password belongs to the dev or the production system.

`creds` puts all of it in **one age-encrypted file** and gives you commands that use
the credentials **without ever showing them to you**.

The *whole file* is encrypted — not just the passwords. Your system list, hostnames and
usernames are confidential too, which matters when the file sits in cloud storage.

---

## How it works

```
  ~/.local-creds/creds.age        the index, age-encrypted    (syncs; safe at rest)
  ~/.config/age/local-creds.key   your private key            (per machine, NEVER syncs)
  creds                           decrypts in memory per command
```

Every command decrypts to memory, does its job, and exits. Plaintext never touches disk.
The one exception is documented and deliberate: an RFC logon needs a JCo destination
*file*, so `creds exec` writes one `0600` in a private temp dir and shreds it on exit.

Secrets reach programs through **environment variables of the child process only** —
never through the command line, because anything on `argv` is visible to every other
process on the machine via `ps`.

---

## Requirements

**Required**

| Tool | Why | Install |
|---|---|---|
| [`age`](https://github.com/FiloSottile/age) | encryption | `brew install age` · `apt install age` |
| `jq` | the index is JSON | `brew install jq` · `apt install jq` |
| `python3` ≥ 3.9 | graph, lint, migrate, web UI | usually present |
| POSIX shell | `creds` is `/bin/sh` | present |

The core is **standard library only** — no `pip install` needed for `creds find`,
`exec`, `copy`, `path`, `lint`, `migrate`, `edit` or `ui`.

**Optional — only for specific connection tests**

| Feature | Needs | Notes |
|---|---|---|
| SSH password login test | `paramiko` | `pip install paramiko` |
| SAP HANA login test | `hdbcli` | `pip install hdbcli` |
| RDP login test | `xfreerdp` | `brew install freerdp` |
| SAP RFC login test | **SAP JCo** + a JRE | see below |
| Encrypted-xlsx import | `msoffcrypto-tool` | optional helper |

Put the optional Python packages in a virtualenv at `~/.cache/creds/venv` (deliberately
*outside* any synced folder — compiled wheels do not travel between machines):

```bash
python3 -m venv ~/.cache/creds/venv
~/.cache/creds/venv/bin/pip install paramiko hdbcli
```

`creds` finds that venv automatically and falls back to plain `python3` when absent.
Override with `CREDS_PYTHON=/path/to/python`.

### SAP JCo is not included

SAP Java Connector is **licensed software and is not redistributable**, so it is not in
this repo. If you want RFC logon tests, download it from the SAP Support Portal
(an S-user is required) and either:

- drop `sapjco3.jar` + `libsapjco3.dylib` (macOS) / `libsapjco3.so` (Linux) into `./lib`, or
- point `CREDS_JCO_LIB` at wherever you keep it.

`creds doctor` reports whether it found a usable copy. Everything else works without it.

---

## Install

```bash
git clone https://github.com/<you>/local-creds.git ~/creds-tool
cd ~/creds-tool

# 1. data directory — keep it where you want it synced
mkdir -p ~/.local-creds

# 2. the command on PATH
mkdir -p ~/.local/bin
ln -s "$PWD/creds" ~/.local/bin/creds        # ensure ~/.local/bin is on your PATH
```

`creds` resolves **code** relative to its own real location (following symlinks) and
**data** from `LOCAL_CREDS_DIR` (default `~/.local-creds`). The two are independent, so
the checkout and the index can live in completely different places.

If you want them together — the simplest setup — make the data dir a symlink to the
checkout and keep the checkout in synced storage:

```bash
ln -s ~/Dropbox/Projects/local-creds ~/.local-creds
```

> **Careful with synced folders.** If your sync client changes its path (e.g. macOS
> Dropbox moving out of `~/Library/CloudStorage`), a stale symlink can *hang* rather
> than fail, and every `creds` command appears to freeze. Re-point the symlinks.

---

## First run

```bash
# generate your private key (per machine, never sync this file)
mkdir -p ~/.config/age
age-keygen -o ~/.config/age/local-creds.key

# record the matching PUBLIC key as a recipient (this file is safe to sync)
grep 'public key' ~/.config/age/local-creds.key | sed 's/.*: //' \
  > ~/.local-creds/recipients.txt

# create an empty index and add your first entry
echo '{"version":1,"entries":[]}' > /tmp/seed.json
EDITOR="cp /tmp/seed.json" creds edit

creds doctor          # verifies key, recipients, schema, tooling
creds ui              # add entries in the browser
```

`creds doctor` is the health check — run it whenever something behaves oddly. It reports
key readability, recipient count, schema validity, backup count, and which optional
tools it can see.

---

## Daily use

```bash
creds find acme qas               # AND-matches id, customer, env, kind, host, user, tags
creds copy <id>                   # password -> clipboard, clears after 45s
creds copy <id> --as SAP* --client 300    # pick one of several logins
creds exec <id> -- <command>      # run with CREDS_* env injected
creds path my-laptop acme-prd     # how do I reach it, and what must be up first
creds lint --customer acme --all  # convention + consistency check
creds sync-ssh                    # regenerate ~/.ssh/config.d/local-creds
creds restore                     # list / roll back pre-save snapshots
```

`find` AND-matches every word, falls back to closest matches, then to a list of known
customers — you are never left with a bare empty result.

**Route passwords are redacted.** A SAProuter string carries its password inline as
`/H/host/S/3299/W/<pw>`. `find` masks any `/W/…` to `/W/***`; `exec` still passes the
real route through.

### `creds exec`

Injects into the child process only:

```
CREDS_ID  CREDS_HOST  CREDS_PORT  CREDS_USER  CREDS_PASSWORD
CREDS_KIND  CREDS_ENV  CREDS_CUSTOMER
CREDS_<FIELD>   one per entry field: CREDS_SID, CREDS_CLIENT, CREDS_SYSNR, …
```

```bash
creds exec acme-dev-hana-h01 -- bash -c \
  'hdbsql -n "$CREDS_HOST:$CREDS_PORT" -u "$CREDS_USER" -p "$CREDS_PASSWORD" "SELECT 1 FROM DUMMY"'
```

Never echo `$CREDS_PASSWORD`, and never put it on a command line — pass it via the
environment, as above.

### SSH

`creds sync-ssh` writes `~/.ssh/config.d/local-creds` so `ssh <entry-id>` and
`ProxyJump` work natively. Add this to the **top** of `~/.ssh/config`:

```
Include config.d/local-creds
```

Only `ssh`/`sftp`/`rdp` entries get a `User` line — an `abap` or `hana` user is an
*application* identity, and writing it as an SSH user would be wrong. The generated file
is validated with `ssh -G` before it replaces the previous one, so a bad generation can
never break every `ssh` on your machine.

---

## The entry model

An entry is one way to log in to one thing.

```json
{
  "id": "acme-prd-abap-p01",
  "customer": "acme",
  "env": "prd",
  "kind": "abap",
  "host": "p01.acme.example",
  "port": null,
  "user": null,
  "secret": "",
  "via": null,
  "tags": ["source:import"],
  "requires": ["vpn:example.corp"],
  "fields": { "sid": "P01", "sysnr": "00" },
  "protocols": [ {"type": "disp", "port": 3200}, {"type": "gateway", "port": 3300} ],
  "logins": [
    {"client": "000", "user": "ADMIN", "secret": "…", "default": true},
    {"client": "300", "user": "SVC_USER", "secret": "…"}
  ]
}
```

| key | meaning |
|---|---|
| `kind` | what it is: `abap` `java` `hana` `ssh` `sftp` `rdp` `bo` `api` `vpn` `vmware` `db` `file` `other` |
| `fields` | free key/value; kind-specific keys like `sid`, `sysnr`, `instance`, `tenant`, `base_url` |
| `protocols` | the ports this thing listens on, each testable independently |
| `logins` | several accounts on one system (see below) |
| `requires` | what must be up first — advisory, printed before `exec` |
| `via` | an SSH jump host |

### `logins` — one system, several accounts

SAP GUI and RFC are two *ports on one system* sharing one `(client, user, password)`.
So they are one entry of `kind: "abap"` — ports in `protocols[]`, accounts in `logins[]`:

```json
"logins": [
  {"client": "000", "user": "ADMIN",    "secret": "…", "default": true},
  {"client": "300", "user": "SVC_USER", "secret": "…"}
]
```

`creds exec` / `creds copy` take `--as <user>` and `--client <nnn>` to choose; with
neither, the `default` login wins. An entry with **no** `logins[]` is treated as a
single login built from the flat `user`/`secret`/`fields.client`, so nothing has to
migrate before it is worth migrating.

---

## Naming convention

```
<customer>-<env>-<kind>-<identity>[-<misc>]
```

**Env leads deliberately** — the environment is then visible in the command you are
about to run, not hidden in a field. Use `all` for things that span environments (VPNs,
routers, bastions).

```
acme-prd-abap-p01            acme-dev-abap-d01
acme-sbx-abap-p01            ← same SID, different env token: a sandbox copy
acme-sbx-ssh-sandboxhost-adminuser
acme-all-vpn-acmecorp
```

`<identity>` depends on the kind, because a SID is not the right identity for everything:

| kind | identity | example |
|---|---|---|
| `abap` / `java` | SID | `acme-prd-abap-p01` |
| `ssh` / `rdp` / `bo` / `vmware` | **hostname** | `acme-prd-ssh-apphost01-root` |
| `hana` | SID + tenant | `acme-prd-hana-h01-tenant1` |
| `api` | service | `acme-prd-api-servicedesk` |

**Never put in an id:** IP addresses (they move, and two aliases of one host read as two
systems), instance numbers (derivable), or imported display text.

The `<env>` token **must** match the `env` field — `creds lint` treats a mismatch as an
error, because an id reading `prd` on a record whose env is `dev` is a *false* safety
signal, which is worse than none.

### `creds lint`

```bash
creds lint                              # errors + warnings, whole index
creds lint --customer acme --all        # one customer, notes included
```

**Errors** (exit 1): env mirror broken · id not prefixed by its customer · duplicate
`(client, user)` in `logins[]` · a graph node borrowing another customer's credential.
**Warnings**: kind mismatch · IP in an id · unregistered kind · a flat secret alongside
`logins[]` · `requires` pointing at a missing entry.
**Notes** (`--all`): legacy ids, entries on no graph node.

The summary always prints how many ids do not follow the convention, even when notes
are hidden — "0 errors" on a set where a third of the ids are wrong reads as clean when
it is not.

### `creds migrate`

Proposes convention ids and merges legacy `rfc`+`sapgui` pairs into one `abap` entry.
**Dry-run by default.**

```bash
creds migrate --customer acme            # show the plan
creds migrate --customer acme --apply    # commit (snapshot taken first)
```

It only does what the data supports: merges strictly on an exact **(host, sysnr)** match,
**refuses** to merge when one `(client, user)` carries two different passwords, never
invents a SID, leaves already-conforming ids alone, and drops colliding proposals rather
than emitting a plan that validation would reject.

---

## Connection tests

Each entry lists **logon methods** in `protocols[]`, tested independently in `creds ui`.
The point is to distinguish *"the network is blocked"* from *"the password is wrong"*.

| type | proves |
|---|---|
| `tcp` `disp` `gateway` `msgserver` | reachability only — credentials **not** verified |
| `icm-http` `icm-https` `odata` | HTTP basic auth against the SAP ICM |
| `rfc` | real SAP logon via JCo |
| `java-http` `java-https` `p4` | NetWeaver Java (`5<nn>00` / `5<nn>01` / `5<nn>04`) |
| `hana` | real HANA logon (SYSTEMDB nameserver `3<nn>13` + `databaseName=`) |
| `ssh` `sftp` | key or password auth |
| `rdp` | NLA/CredSSP handshake via `xfreerdp +auth-only` |
| `bo` | BusinessObjects logon token |
| `api` | vendor-neutral API credential check |
| `vmware` | vCenter session (`POST /api/session`) |

### Every probe is controlled

A test that cannot tell a real secret from a random one proves nothing. Each probe
repeats itself with a **deliberately wrong credential** and reports `INCONCLUSIVE` when
the endpoint answers the same either way.

**Which control depends on whether the account can lock:**

- Stateless API keys → repeat with a **random secret**.
- Accounts that lock (SAP dialog users, AD-backed RDP/SSH, BusinessObjects, vCenter SSO)
  → repeat with a **random username**, never a wrong password for the real account.
  Burning failed-logon attempts against a real admin account is not an acceptable cost
  of testing.

### API auth styles

`fields.auth_style` picks how the secret is presented:

| style | how |
|---|---|
| `bearer` | `Authorization: Bearer <secret>` |
| `header` | custom header named by `fields.auth_header` |
| `basic` | `user:secret` |
| `query` | query parameter named by `fields.auth_param` |
| `oauth2` | client-credentials grant, **HTTP Basic** on the token endpoint |
| `oauth2-body` | client-credentials with the id+secret **in the form body** |

`token_url` may be a bare origin or a full endpoint. A bare origin gets `/oauth/token`
appended; **an explicit path is left alone**, because the path is not universal — some
providers use `/oauth2/token`, and appending blindly would produce
`…/oauth2/token/oauth/token`.

---

## The landscape graph

`requires` on an entry is hand-typed and drifts. The graph makes it *derivable*: draw
the boxes and the hops once, then ask for a route.

```bash
creds path my-laptop acme-prd
creds path my-laptop acme-prd-abap-p01 --json   # a destination can be named by its entry id
creds path my-laptop acme-prd --all             # every route, not just the shortest
```

```
my-laptop -> acme-prd  [PRD]
  my-laptop         --network:3299--> acme-router    # public entry point
  acme-router       --gateway:3300--> acme-prd       # internal name resolved router-side
requires: internet, vpn:example.corp
credentials: acme-prd-abap-p01
NOTE     destination is PRODUCTION -- creds exec needs CREDS_ALLOW_PROD=1
```

Three optional top-level keys sit alongside `entries`; absent means "no graph yet":

```json
"nodes": [{"id":"acme-prd", "label":"P01", "type":"appserver",
           "env":"prd", "creds":["acme-prd-abap-p01"],
           "attrs":{"sid":"P01","sysnr":"00","host":"apphost01"}}],
"edges": [{"from":"acme-router", "to":"acme-prd", "type":"gateway", "port":3300,
           "requires":["vpn:example.corp"],
           "window":{"days":"mon-fri","hours":"08:00-18:00","tz":"Europe/Berlin"}}],
"views": [{"id":"physical","name":"Physical","kind":"physical"}]
```

**Edges are directed** and walked forward only. You draw the direction you connect in,
which is also the direction each hop's hostname is resolved in — a router→server edge
carries the *internal* name, because the router resolves it from inside the network. One
`host` field on an entry cannot express that; two hops can.

**One node per instance, not per box.** Two instances can share a machine with different
instance numbers, hence different ports and different credentials.

`window` marks a hop open only in a change/ACL slot; `creds path` warns outside it.
Dangling edges and `creds` refs matching no entry **block the save**.

### The canvas

`creds ui` also serves **`/landscape`** — an SVG editor for the graph, no dependencies
and no build step. Drag nodes, scroll to zoom, **↝ Link** to draw edges, click to edit
in the side panel, **Tidy** for automatic left-to-right tier layout
(client → router/VPN → app server → database), filter by customer, per-view positions.

---

## Safety model

These are the rules the tool enforces, and the reasoning behind each.

**1. Production entries refuse to run.**
`creds exec` on an `env: prd` entry fails unless the command is prefixed
`CREDS_ALLOW_PROD=1`. The prefix is deliberately an environment assignment so it cannot
be hidden in an alias, and so an agent's allowlist rule for `creds exec` does not cover
it. Unclassified environments default to `prd` — the fail-safe direction.

**2. Secrets never enter output.**
`find` strips `.secret` and `logins[].secret`, and redacts `/W/` route passwords. `copy`
puts the password on the clipboard without displaying it. `lint`, `migrate`, `path` and
`graph` are all secret-free by construction, with tests asserting it.

**3. Secrets never reach `argv`.**
Environment variables for child processes; `/args-from:env:` for `xfreerdp`; a `0600`
temp file, shredded on exit, for JCo. Anything on a command line is world-readable
via `ps`.

**4. Every write is snapshotted.**
Before any save, the current ciphertext is copied to `.backups/` (last 15 kept).
`creds restore` lists and rolls back. Schema validation runs *before* re-encryption, so
a malformed edit is rejected rather than saved.

**5. The web UI is local-only.**
Binds `127.0.0.1` exclusively, requires a per-launch random token, exits after 30
minutes idle.

---

## Multiple machines

The index syncs; the key does not.

1. On the new machine: `age-keygen -o ~/.config/age/local-creds.key`
2. Append its **public** key as a new line in `recipients.txt`
3. On a machine that can already decrypt, re-encrypt to all recipients:
   `EDITOR=true creds edit` (a no-op edit re-encrypts to every recipient)
4. Install the optional venv there if you want the extra tests

To revoke a machine, remove its line from `recipients.txt` and re-encrypt. Rotate any
secret that machine held.

---

## Files in this repo

```
creds               the CLI (POSIX sh)        ui.html          entry editor
graph.py            landscape graph + path    landscape.html   SVG canvas
lint.py             convention checks         ui_server.py     local web server
migrate.py          id + kind migration       *.java           JCo probes (need SAP JCo)
test_creds.sh       172 self-checks           AGENTS.md        instructions for AI agents
```

**Not in this repo, by design:** your `creds.age`, your `recipients.txt`, your keys,
your `.backups/`, and SAP JCo (licensed).

---

## Development

```bash
sh test_creds.sh          # 172 checks, throwaway index, no network
```

The suite creates its own age key and index in a temp dir — it never touches your real
one. It covers secret containment, the production guard, login selection, graph paths,
lint rules, migration guards, ssh-config generation and probe port derivation.

**If you add a `kind`, register it in three places together** — `lint.py`, `migrate.py`
and `ui.html`. A kind the UI does not know shows no selected option in the editor, and
one stray click silently rewrites it. `creds lint` warns about unregistered kinds, and
the suite asserts the vocabularies stay in sync.

Conventions: files under ~800 lines; every non-trivial behaviour gets a check in
`test_creds.sh`; comments explain *why*, especially where something non-obvious was
learned the hard way.

---

## Licence and scope

MIT. See `LICENSE`.

This is a personal tool shared in case it is useful. It is **not** an enterprise secret
manager: there is no audit log, no sharing model, no rotation workflow, and no HSM. It
is a good fit for one practitioner with many systems and a synced folder. If you need
team-wide secret management, use a real secret manager.
