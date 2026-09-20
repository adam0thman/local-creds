# `creds` — an encrypted credential index for people who run many systems

One encrypted file holds every system you connect to. Nothing is stored in plaintext,
no command ever prints a password, and connecting to a production system takes a
deliberate extra step.

Built for SAP Basis work across many customer landscapes, but the model is generic:
an entry is *a way to log in to something*, and the tooling around it is vendor-neutral.

Designed to be safe for an AI coding agent to use on your behalf — see
**[AGENTS.md](AGENTS.md)** for the rules it must follow.

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
- [Browser extension](#browser-extension)
- [Automated logon (`creds browser`)](#automated-logon-creds-browser)
- [Safety model](#safety-model)
- [Multiple machines](#multiple-machines)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Sister projects](#sister-projects)
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
  ~/.local-creds/creds.age        the index, age-encrypted    (safe to sync; optional)
  ~/.config/age/local-creds.key   your private key            (per machine, NEVER sync)
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
git clone https://github.com/adam0thman/local-creds.git ~/creds-tool
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

### Where to keep the index

`creds` does not care how the index gets to your other machines — it only reads
`LOCAL_CREDS_DIR`. Point it at whatever you already use:

```bash
# A: index inside the checkout, checkout in whatever folder you sync
ln -s /path/to/your/synced/folder/local-creds ~/.local-creds

# B: index somewhere else entirely, checkout wherever you like
export LOCAL_CREDS_DIR=/path/to/your/synced/folder/creds-data

# C: no sync at all — single machine, plain local directory
mkdir -p ~/.local-creds        # the default; nothing else to do
```

Any file-sync tool works: iCloud Drive, OneDrive, Dropbox, Google Drive, Nextcloud,
Syncthing, a private git repo, or a USB stick you carry. The index is a single
encrypted file, so it needs no special handling — and because the whole file is
encrypted, a sync provider you do not fully trust is an acceptable place to put it.

Only two things must **not** sync: your private key at
`~/.config/age/local-creds.key`, and the optional Python venv (compiled wheels are
per-machine).

> **If your sync folder ever moves, re-point the symlink.** Sync clients do relocate
> their roots between versions. A symlink pointing into a path that no longer mounts
> can *hang* rather than fail cleanly, and then every `creds` command appears to freeze
> with no error. If that happens, check the symlink first — `readlink ~/.local-creds`
> is safe and does not touch the dead path.

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

## Browser extension

Chrome, Brave, Edge and Chromium. Fills the logon form for the site you are on — or
copies the password if you prefer — so a web logon stops being "find the entry,
`creds copy`, switch window, paste".

### How it talks to the index

The index is age-encrypted and `creds` decrypts only in memory, per command, so an
extension cannot read the file. It goes through a **native messaging host**
(`creds-nm`): Chrome spawns it on demand and kills it when the popup closes. No
daemon, no listening port, no token to leak, and the browser itself enforces which
extension ID may connect.

```
[click toolbar icon]
  popup ──active tab's origin──▶ creds-nm ──▶ decrypt in memory
                                    │         filter on fields.url origin
                                    ▼
                    [{id, user, env}]   ← metadata only, never a secret
  pick one (production asks again) ──▶ creds-nm re-checks the origin ──▶ password
```

The extension can never ask for an entry **by id**. It asks "what fits this origin",
and `fill` re-derives the match from the origin before releasing anything. A
compromised popup still cannot pull an arbitrary credential out of the index.

### Which entries it can find

Those with a `url` in `fields`, holding the origin you log into:

```bash
creds ui          # add: url = https://jira.example.com
creds lint        # warns if it cannot be an origin
```

Matching is exact on scheme, host and port. A path is stored for convenience and
ignored. `sap.example.com` never matches `sap.example.com.evil.io`, and an entry
stored as `https` is not offered on an `http` page.

Plaintext `http` is allowed **only to a private address** — most of an SAP estate is
internal http, and refusing it would make the extension useless for Fiori launchpads,
PI directories and HANA cockpits. To a public host it is refused outright.

### Install

```bash
# 1. load the extension: chrome://extensions → Developer mode → Load unpacked
#    → select the extension/ folder in this repo
# 2. register the native host for every browser you use
./creds-nm --install hghfobjabmappldeanhennjhchbofdoc
# 3. restart the browser
```

`Cmd+Shift+Y` (`Ctrl+Shift+Y` elsewhere) opens it without reaching for the mouse;
rebind at `chrome://extensions/shortcuts`. When exactly one non-production entry
matches, the Fill button takes focus, so the whole logon is shortcut → Enter → Enter.

The ID above is fixed by the `key` in `extension/manifest.json`, so it survives
reloads. If you repack with your own key, pass your own ID instead.

Check it without the browser at all:

```bash
echo '{"cmd":"ping"}' | ./creds-nm --test
```

`creds-nm` runs under the browser, not your shell — no `PATH`, no profile. It finds
`age` at the usual absolute locations; if yours lives elsewhere, `ping` says so.

### Filling

The form is filled, never submitted. Pressing Enter stays your decision: a form's
`action` can have changed under the page, and an autofill that also submits will post
the credential wherever it now points.

Injection is **programmatic and gesture-gated** — `activeTab` plus `scripting`, no
declarative content script and no blanket host permission. The extension has no
presence on any page until the moment you click Fill, and the injected code runs in
Chrome's isolated world, so page scripts can neither see it nor read the argument
carrying the password.

Two cases are refused rather than guessed:

| Page | Why |
|---|---|
| several visible password boxes | a change-password form — filling would type your current password into "new password" |
| no visible password box | nothing to fill; hidden fields are honeypots or leftovers |

The username is taken from `autocomplete="username"` when the form says so, otherwise
the nearest typeable field before the password — which is what the SAP BSP logon
(`sap-user` / `sap-password`) and essentially every classic form look like.

The origin is checked three times before a password moves: when the popup matches,
again against the tab's current URL before the secret is fetched, and once more inside
the page by the injected script. The middle two exist because a tab can navigate while
the popup is open.

### When nothing matches

The popup says so and offers to copy the origin, so adding it to an entry in
`creds ui` is one paste.

It does **not** offer to write the entry for you. `creds-nm` has three commands —
`match`, `fill`, `ping` — and none of them can alter the index; the test suite asserts
that. The browser is the least trustworthy thing with access to this data, so it gets
read-only access and editing stays with `creds edit` and `creds ui`.

### Copying

The Copy button is still there for a form the filler cannot read. Note that clipboards
sync across devices and any running app can read them — filling is the safer path when
it works. Production entries need a second confirmation either way, mirroring
`CREDS_ALLOW_PROD=1` on the CLI.

---

## Automated logon (`creds browser`)

The extension is for your hands. `creds browser` is for a script or an agent: it logs a
**disposable** browser into a system without the password being visible to the caller.

```bash
creds browser <id>                  # open, fill, log on, leave the window up
creds browser <id> --headless       # no window
creds browser <id> --no-submit      # fill only
creds browser <id> --shot out.png   # screenshot the result
```

It runs through `creds exec`, so the production guard, the `requires` notice and the
secret handling are identical to every other command. The password arrives in the
child process's environment and goes straight into the page: never an argument (`argv`
is readable by every process via `ps`), never printed, never returned. An agent can
drive this and still never see the secret.

**Its own profile, and not yours.** Chromium runs against an in-memory context — no
cookie jar on disk, no history, no saved passwords, and none of your real sessions. If
a script misnavigates it is not logged in as you anywhere, and your own browser stays
usable because there is no profile lock to contend with. On close, cookies and web
storage are cleared explicitly as well.

**"Did not submit" is not "wrong password".** If nothing navigated and the page raised
no complaint, that is reported as *no logon attempt was used* — because telling someone
their password failed when the form never went would send them to reset a working one.

**One attempt, ever.** `submit_once()` refuses a second logon in the same run. Many
accounts lock after three failures and some SAP systems after three, so this is a
runtime guard rather than a convention — a retry loop added later raises instead of
locking a real admin account.

**Real logon pages, not toy ones.** Four things a live SAP logon does that a simple
filler gets wrong, all handled:

| What the page does | What happens |
|---|---|
| several SAML redirects | waits for the chain to settle *before* the origin check, so the check judges the page that will actually receive the password |
| a Content Security Policy | fills via CDP rather than an injected `<script>`, which `accounts.sap.com` blocks |
| identity-first logon (user id, then password on the next screen) | answers the first screen and continues — no password is sent, so it costs nothing against lockout |
| a submit button outside its own `<form>` | finds it by the DOM's `.form` property, not by CSS nesting |

**Cross-origin redirects are refused** unless you pass `--allow-redirect`. A logon URL
that bounces to another origin is normal for SAML, and is also how a credential reaches
an identity provider you did not intend.

Field detection is `extension/fill.js` — literally the same code the extension uses, so
there is one implementation and one set of unit tests behind both.

Playwright is optional and not installed for you:

```bash
python3 -m venv ~/.cache/creds/venv
~/.cache/creds/venv/bin/pip install playwright
~/.cache/creds/venv/bin/playwright install chromium
```

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

## Limitations

Read this before adopting it. These are known and stated plainly rather than
discovered later.

### Platform

**macOS is the only tested platform.** Everything below is about what the code
actually calls, not a guess.

| Platform | Status |
|---|---|
| **macOS** | Fully supported and tested |
| **Linux** | Expected to work, **except** `creds copy` and the `keychain:` prefix (see below). Untested end to end. |
| **Windows (native)** | **Does not run.** `creds` is a POSIX `/bin/sh` script; `cmd` and PowerShell cannot execute it. |
| **Windows (WSL2)** | Should behave like Linux. Untested. |
| **Windows (Git Bash / MSYS2)** | Most commands should run; `creds copy` will not. Untested. |

Two calls are macOS-specific:

- `creds copy` uses **`pbcopy` / `pbpaste`**. On Linux, substitute `xclip`/`wl-copy`;
  on WSL, `clip.exe`. The auto-clear step also reads the clipboard back to avoid
  wiping something you copied since, so a replacement needs both directions.
- The optional `keychain:` secret prefix calls **`security find-generic-password`**.
  Inline and `b64:` secrets work everywhere; only that one prefix is macOS-bound.

Everything else — `age`, `jq`, `python3`, the graph, lint, migrate, the web UI and
the probes — is portable.

**If you are running an AI coding agent on Windows** (for example Claude Code, whose
shell tool runs through Git Bash): `creds find`, `exec`, `path`, `lint`, `migrate` and
`doctor` should work, and `creds copy` will not. This combination is **untested** —
if you try it, a report either way is welcome.

### Browser

The web editor masks passwords with the CSS property `-webkit-text-security`,
supported in Chrome, Edge, Safari and **Firefox 128+**. In older Firefox the field
renders **in plaintext**. Use a current browser, or treat the editor as Chromium/Safari
only.

### Concurrency

**Last write wins.** The web UI loads the entire index when the page opens and posts
the entire index on Save. If you edit in the browser while something else (a CLI edit,
another tab, a second machine's sync) changes the index, the later Save silently
overwrites the earlier one. There is no stale-load detection yet.

In practice: save or reload the editor before making changes elsewhere. Snapshots in
`.backups/` mean a clobbered write is recoverable, not lost.

### Scale and scope

- The index is **one file**, decrypted whole into memory per command. Fine for
  hundreds of entries; not designed for tens of thousands.
- **No audit log.** Nothing records who used which credential when.
- **No sharing model.** Adding a machine means adding an age recipient; there are no
  users, groups or per-entry access.
- **No rotation workflow.** Changing a password is a manual edit.
- **Backups are the last 15 saves**, local to the data directory. They are not a
  disaster-recovery plan — if you lose your age key with no other recipient, the index
  is unrecoverable by design.
- **`requires` is advisory.** The tool prints connectivity prerequisites; it does not
  detect or establish a VPN.
- **SAP JCo is not included** (licensed). RFC logon tests are unavailable without it.

### What it is not

This is a personal tool for one practitioner with many systems. It is not an
enterprise secret manager, and it should not be used as one. If you need team-wide
secrets with audit, rotation and revocation, use a product built for that.

---

## Roadmap

Ideas, not commitments. Ordered by how much they would change daily use.

### Not planned: making the extension agent-callable

An agent driving a page cannot type a password — that would put the secret in a tool
call and therefore in a transcript. The tempting fix is `externally_connectable`, so a
page can ask the extension to fill itself.

It is not planned, for two reasons. Chrome will not accept `<all_urls>` or a wildcard
host there — patterns need a real second-level domain — so the manifest would have to
be generated from the index and reloaded whenever an entry is added. And the workable
variant (an extension page driven with a single-use token) needs the `tabs` permission,
which is arbitrary-tab injection: precisely the privilege the extension was built
without.

[`creds browser`](#automated-logon-creds-browser) solves the same problem with no new
trust boundary, so the extension stays minimal. If you find yourself needing the user's
own Chrome for SSO sessions, add a persistent Playwright profile to `creds browser`
rather than widening the extension.

### Browser extension — the harder pages

Filling works on classic forms. Still open: logons inside an `<iframe>` (the injected
script only touches the main frame), SAML flows that bounce to a different origin
mid-logon, and SAPUI5 screens that build their inputs late enough that a click arrives
before the field exists. Each is a real case in an SAP estate; none is solved by
guessing harder.

### Client certificates — record them, do not automate them

Tried and abandoned, deliberately. What was learned is more useful than the feature.

Some SAP systems accept an X.509 client certificate instead of a password — SAP
Passports for the Support Portal, SNC setups, admin UIs behind a smartcard. The
browser shows a chooser: three anonymous S-numbers, pick who you are. Choosing the
wrong customer's identity is exactly the class of mistake this tool exists to prevent.

**Automating the choice is not worth it.** The chooser is a native browser dialog, so
nothing can click it — not Playwright, not a desktop automation tool. The two ways
around it are both bad:

- Chromium's `AutoSelectCertificateForUrls` is an enterprise **policy**, needing a
  managed plist and admin rights, which a personal tool has no business installing.
- Playwright's `client_certificates` wants the certificate **and private key as files**,
  which means exporting the key out of the keychain onto disk. That is a real security
  downgrade — the key stops being protected by the OS — to automate a logon that
  already works with a password.

**What is worth doing, and is done:** the index records which certificate belongs to
which S-User — subject, issuer, serial, expiry, and which store holds it. Public
fields only; the private key is never referenced. An entry with no certificate says so
(`cert:none`), because recording the absence stops someone hunting for one that was
never issued.

That solves the problem a human actually has. The dialog still needs a click, but you
now know which row to click, and `creds` can warn before a certificate expires.

### Smaller things

- **Stale-load detection** in the web UI, so a concurrent Save conflicts loudly
  instead of overwriting (see [Limitations](#limitations)).
- **Clipboard portability** — a `creds copy` that picks `pbcopy`/`xclip`/`wl-copy`/
  `clip.exe` automatically, which also removes the main Linux/WSL gap.
- **Password expiry awareness** — several kinds can report when a credential is due to
  expire; surfacing that in `creds doctor` would turn a surprise into a warning.
- **Graph-driven preflight** — `creds exec` already prints `requires`; it could walk
  the landscape graph and check reachability of each hop before attempting a logon,
  so "VPN is down" is reported as such instead of looking like a bad password.

---

## Sister projects

`creds` answers *"what are the credentials and how do I reach it"*. These public
projects cover the neighbouring problems, and are built to be used alongside it.

| Project | What it does |
|---|---|
| **[sap-gui-control-skill](https://github.com/adam0thman/sap-gui-control-skill)** | Drive SAP GUI for Java on macOS through the Accessibility API — no screenshots, no coordinates, no focus stealing — plus headless RFC for anything that does not need a screen. The natural companion once `creds` has got you logged in. |
| **[sap-basis-ops](https://github.com/adam0thman/sap-basis-ops)** | Claude Code skills for Basis work at the OS and DB layer: start/stop, health triage, housekeeping, transports, kernel and security patching, backup/recovery, and DB-specific commands across HANA, Oracle, ASE, Db2, MaxDB and SQL Server. Cited to help.sap.com. |
| **[sap-cloud-alm-skill](https://github.com/adam0thman/sap-cloud-alm-skill)** | SAP Cloud ALM: the Implementation and Operations APIs, SAP Activate methodology, tenant setup, and automation scripts. Pairs with an `api` entry here holding the OAuth client credentials. |
| **[sap-landscape-dashboard](https://github.com/adam0thman/sap-landscape-dashboard)** | Self-hosted landscape dashboard — card wall per environment, live latency, filesystem and SLD inventory. Where this repo's graph models *how you connect*, that one visualises *how the estate is doing*. |

They share a design stance: prefer the headless path, never guess when the system can
be asked, and say plainly which parts are verified and which are inferred.

---

## Files in this repo

```
creds               the CLI (POSIX sh)        ui.html          entry editor
graph.py            landscape graph + path    landscape.html   SVG canvas
lint.py             convention checks         ui_server.py     local web server
migrate.py          id + kind migration       *.java           JCo probes (need SAP JCo)
creds-nm            native messaging host     extension/       browser extension
browser.py          disposable-browser logon  extension/fill.js  shared form filler
test_creds.sh       211 self-checks           AGENTS.md        instructions for AI agents
```

**Not in this repo, by design:** your `creds.age`, your `recipients.txt`, your keys,
your `.backups/`, and SAP JCo (licensed).

---

## Development

```bash
sh test_creds.sh          # 211 checks, throwaway index, no network
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

**Apache License 2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Free for commercial and non-commercial use, modification and redistribution,
including in closed-source products. In return you must keep the copyright and
licence notice, include the `NOTICE` file, and state any files you changed.

Apache 2.0 rather than MIT for two reasons that matter to this audience: it grants
patent rights explicitly, which enterprise legal review looks for, and its attribution
terms are the more definite of the two.

To be clear about what attribution means here: you must preserve the notices in copies
of the software. You are **not** required to credit this project visibly in your own
product's UI or documentation.

This is a personal tool shared in case it is useful. It is **not** an enterprise secret
manager: there is no audit log, no sharing model, no rotation workflow, and no HSM. It
is a good fit for one practitioner with many systems, on one machine or several. If you
need
team-wide secret management, use a real secret manager.
