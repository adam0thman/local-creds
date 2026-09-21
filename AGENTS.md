# Instructions for AI agents working with `creds`

You are reading this because you are an AI assistant with access to a machine where
this repo is checked out. This file tells you how to use the tool correctly and, more
importantly, **what you must never do with it**.

Read [README.md](README.md) for what the tool is. This file is the operating manual.

Everything below is written as a rule with its reason. The reasons matter: they tell
you how to behave in situations this file did not anticipate.

---

## 1. What this tool holds

An age-encrypted index of real credentials for real production systems. Touching them
carelessly can take down someone's business, lock out admin accounts, or leak secrets
into a chat transcript that syncs to cloud storage.

Act accordingly. When unsure, **ask the human rather than guessing.**

---

## 2. The hard rules

### 2.1 Never print a secret

Do not echo, log, interpolate or otherwise cause a password to appear in:

- your reply text
- a tool call's **output** that you will read
- a command line (`argv` is visible to every process via `ps`)
- any file outside the encrypted index

```bash
# WRONG — the password lands in the transcript
creds exec acme-prd -- sh -c 'echo $CREDS_PASSWORD'
creds exec acme-prd -- mysql -p"$CREDS_PASSWORD"

# RIGHT — the secret stays in the child process's environment
creds exec acme-prd -- sh -c 'mysql --defaults-extra-file=<(printf "[client]\npassword=%s\n" "$CREDS_PASSWORD") …'
creds exec acme-prd -- python3 /path/to/script.py    # script reads os.environ
```

Transcripts are commonly stored on disk and synced to cloud storage. A password you
print is a password that has leaked, even if the human never reads that line.

**Never decrypt the index directly.** No `age -d`, no `cat creds.age`. Use `creds`
commands, whose output is secret-stripped by construction.

### 2.2 Never bypass the production guard on your own initiative

Entries with `env: prd` refuse to run under `creds exec`. Overriding requires prefixing
the command with `CREDS_ALLOW_PROD=1`.

**Only add that prefix when the human has explicitly approved that specific action on
that specific system, in the current conversation.** Never add it pre-emptively, never
add it to "make the command work", and never carry approval from one system to another.

If a command fails the guard, that is the guard *working*. Report it and ask.

### 2.3 Respect account lockout

Many accounts lock after a handful of failed logons — SAP dialog users, AD-backed
RDP/SSH, BusinessObjects, vCenter SSO. Some SAP systems lock after **three**.

- Do not retry a failed logon repeatedly "to see".
- Treat **two attempts per credential per session** as the ceiling unless told otherwise.
- Locking a real admin account is a serious operational incident, not a failed test.

This is also why the built-in probes control with a random *username* rather than a
wrong password for accounts that can lock. If you write a new probe, follow that.

### 2.4 Do not hunt for credentials elsewhere

If a system is not in the index, say so and offer `creds edit` or `creds ui`. Do **not**
go looking through the filesystem, old projects, notes or shell history for passwords.
That is how secrets end up copied into places nobody is tracking.

### 2.5 Ask before destructive or outward-facing actions

Deleting entries, mass renames, `creds migrate --apply`, anything that writes to a
customer system: confirm first. Reads and dry-runs are fine to do on your own.

---

## 3. How to actually use it

### Find out what exists

```bash
creds find <words>...        # AND-matches id, customer, env, kind, host, user, tags
creds find '' | jq -r '.[].id'    # everything
creds doctor                 # health: key, recipients, schema, backups, optional tools
creds lint --customer <name> --all
```

`find` output has secrets stripped — it is safe to read and safe to quote back.

Kinds you will meet: `abap` `java` `hana` `ssh` `sftp` `rdp` `bo` `api` `odata`
`vmware` `vpn` `router` `file`, plus `webdisp` (SAP Web Dispatcher), `scc` (SAP Cloud
Connector) and `suser` (SAP Support Portal account). `rfc`/`sapgui` are legacy and
superseded by `abap`.

### Run something against a system

```bash
creds exec <id> -- <command>
creds exec --as <user> --client <nnn> <id> -- <command>
```

Injected into the child only: `CREDS_ID` `CREDS_HOST` `CREDS_PORT` `CREDS_USER`
`CREDS_PASSWORD` `CREDS_KIND` `CREDS_ENV` `CREDS_CUSTOMER`, plus `CREDS_<FIELD>` for
each entry field (`CREDS_SID`, `CREDS_CLIENT`, `CREDS_SYSNR`, `CREDS_ROUTER`, …).

For SSH work, write a small script that reads `os.environ` and pass it to `creds exec`.
Do not template the password into a shell string.

### Log into a web system without seeing the password

```bash
creds browser <id>                  # open, fill, log on, leave the window up
creds browser <id> --headless       # unattended
creds browser <id> --no-submit      # fill only, no logon attempt, no lockout risk
creds browser <id> --shot out.png   # screenshot the result
creds browser --client <idp> <id>   # pick one of several logins on one system
```

This is **your** path for anything web-based. The password goes from `creds exec`'s
environment straight into the page; you get back "logged on", "rejected" or "did not
submit", never the secret. Start with `--no-submit` on anything you have not tried —
it proves the form was found without spending an attempt.

The browser is disposable: no cookie jar on disk, no history, none of the human's real
sessions, and the system keychain is not exposed to it. Do not add a persistent profile
to "keep me logged in" — that is how an automated run starts acting as the human
somewhere nobody intended.

If it reports **did not submit**, that is not a wrong password. Nothing was sent. Say
so plainly rather than suggesting a password reset.

Note the browser extension in `extension/` is for the *human*, not for you. It needs a
toolbar click by design. You do not need it and must not widen it (see 4.5).

### Understand connectivity before blaming credentials

```bash
creds path <from> <to>          # hops + accumulated prerequisites
creds path <from> <to> --all    # every route
```

`creds exec` prints an entry's `requires` to stderr before running. **If a connection
fails, check those first.** A VPN that is down looks exactly like a wrong password if
you are not paying attention, and "the password must be wrong" is the single most
common wrong conclusion with this tool.

### Edit

```bash
creds ui                                   # browser editor, best for humans
EDITOR="python3 /path/to/script.py" creds edit    # scripted edit, best for you
```

The `creds edit` path gives your script the decrypted JSON as a file argument, then
validates and re-encrypts. A snapshot is taken before every write, so `creds restore`
can undo it.

**Your edit script must never print secrets** — not even to stderr for debugging.
Print ids, usernames and counts instead.

---

## 4. Rules for changing the data

### 4.1 Never invent a SID, hostname, env or port

If you do not know it, leave the field empty, tag the entry `needs:fill` or `check:<what>`,
and say so. A fabricated value that *looks* right is worse than a blank, because nobody
will ever re-check it.

Derive only what is genuinely derivable, and say which is which:

- SAP ABAP instance `nn` → dispatcher `32nn`, gateway `33nn`, message server `36nn`,
  ICM HTTP `80nn`
- SAP NetWeaver Java instance `nn` → HTTP `5nn00`, HTTPS `5nn01`, P4 `5nn04`
- SAP HANA instance `nn` → SYSTEMDB nameserver `3nn13`

### 4.2 Never merge two entries without proof they are one system

The trap: the same machine recorded twice (once by IP, once by hostname) looks identical
to two different machines. Merging wrongly destroys a system's record; *not* merging
merely leaves a duplicate.

Proof means: an exact `(host, sysnr)` match, or `ip a` on the box showing both addresses,
or the human telling you. "Same SID and same instance number" is **not** proof —
a clone (DR copy, sandbox refresh) legitimately has both.

`creds migrate` implements these rules. Prefer it over hand-editing.

### 4.3 Preserve every credential when restructuring

An entry may store logins in `logins[]` **or** in flat `user`/`secret`. Code that reads
only the flat fields silently discards the credentials of a migrated entry. Use
`migrate.logins_of(entry)`, which handles both.

Before any merge, compare secrets for each `(client, user)` pair and **abort on
conflict** — two different passwords for the same pair means they are not the same
account. Never silently pick one.

### 4.4 The env token must mirror the `env` field

Ids are `<customer>-<env>-<kind>-<identity>`. If you change one, change the other in the
same edit. An id reading `prd` on a `dev` record is a *false* safety signal — worse than
no signal, because it invites trust.

When you do not know the environment, default to `prd`. Over-guarding is an
inconvenience; under-guarding is an outage.

### 4.5 Never widen the extension to make automation easier

You cannot type a password into a page — that puts it in a tool call and therefore in a
transcript. Use `creds browser <id>`, which fills the form from the child process's
environment; you see "logged on" or "failed", never the secret.

Do **not** reach for `externally_connectable`, the `tabs` permission, or a content
script to solve this. The extension deliberately has no presence on any page until a
human clicks it, and widening it so an agent can drive it trades a human-gesture
requirement for nothing that `creds browser` does not already give you. The reasoning
is in the README under "Not planned".

### 4.6 `fields.url` is a security boundary, not a bookmark

It is the origin the browser extension and `creds browser` match a page against before
releasing a password. Store `scheme://host[:port]` — a path is kept for convenience and
ignored by matching. Never widen it to a bare domain to "make it match more": exact
origin comparison is what stops `sap.example.com.evil.io` from collecting a credential.

**Several origins go on one entry, whitespace-separated.** One system routinely answers
on more than one name — an internal hostname and a public vanity URL, or a pair behind
a VIP. That is a list, not a reason to duplicate the entry: two entries for one system
means two passwords to rotate and one of them will be missed.

**A federated logon needs the identity provider's origin, not just the portal's.**
`me.sap.com` and `launchpad.support.sap.com` both redirect to `accounts.sap.com`, and
that is where the password is actually typed. An entry listing only the portal matches
nothing on the page that matters. Same for Microsoft (`login.microsoftonline.com`),
Okta and any other SAML or OIDC flow: record where the form lives, not where the
journey starts.

Listing the IdP is also what lets `creds browser` run without `--allow-redirect`, which
turns the cross-origin guard back on — it will still refuse an IdP the entry does not
name, which is the whole point.

Do not invent one. An origin you guessed either never matches (dead weight nobody
re-checks) or points a credential somewhere unintended.

`creds lint` warns about a url it cannot use; `creds-nm` refuses it outright. If you
change one of those rules, change both, and remember the asymmetry — plaintext http is
legitimate to a private address and never to a public one.

### 4.7 Register a new `kind` in three places at once

`lint.py` (KINDS), `migrate.py` (`identity()`), `ui.html` (KINDS, KIND_FIELDS,
`defaultProtocols`). A kind the UI does not know shows no selected option in the editor,
and one stray click silently rewrites it. `creds lint` warns about unregistered kinds.

---

## 5. Rules for changing the code

- **Run `sh test_creds.sh` before and after.** It uses a throwaway index and touches no
  network. 220 checks; keep it at zero failures.
- **Add a check for any non-trivial behaviour you add.** Especially anything touching
  secrets, the production guard, or merging.
- **Verify a test actually fails when the behaviour breaks.** A check like
  `! cmd | grep -q "x"` passes vacuously once `x` no longer exists anywhere. Several
  such tests have been caught in this repo; do not add more.
- **Do not print secrets in tests.** The suite asserts this for existing commands.
- Files stay under ~800 lines. Comments explain *why*.

---

## 6. When something does not work

| Symptom | Likely cause |
|---|---|
| every `creds` command hangs | a stale symlink into a moved/unmounted sync folder — a dead path can block rather than fail |
| `cannot decrypt` | wrong or missing `~/.config/age/local-creds.key`, or this machine is not a recipient |
| RFC test unavailable | SAP JCo not installed — see README, it is licensed and not shipped |
| HANA/SSH test unavailable | optional Python package missing from `~/.cache/creds/venv` |
| connection fails | check `requires` (VPN, router, bastion) **before** suspecting the password |
| a probe says INCONCLUSIVE | the endpoint answered identically to a deliberately wrong credential — it proves nothing, so do not report it as success |

`creds doctor` answers most of these directly. Run it first.

---

## 7. Reporting back to the human

- Say what you verified versus what you assumed. Label inferences as inferences.
- If you guessed a value, say which one and why, and tag the entry.
- If a test was inconclusive, say inconclusive — never round it up to "works".
- If you broke something, say so plainly and state the recovery path
  (`creds restore` lists snapshots).
- Never paste a secret into your summary, including "just the first few characters".
