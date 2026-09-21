#!/usr/bin/env python3
"""Convention checks over the creds index.

The rule that earns its keep is the ENV MIRROR: the env token in an id must equal
the `env` field. Env is in the id so it is visible in the command you are about to
run -- but an id reading `prd` on a record whose env is `dev` (or the reverse) is a
FALSE safety signal, which is worse than no signal. That one is an error; almost
everything else here is advice.

Legacy ids (the ~133 entries imported from SAP GUI display names) are reported once
as INFO rather than failing every rule, so real problems stay visible. Fix those from
the box when you next work that customer, never by reformatting the display text.

SECRETS: stdin carries the decrypted index. Nothing here may print a secret; entries
and logins are referred to by id, user and client only.
"""
import ipaddress
import json
import re
import sys
import urllib.parse

ENVS = {"dev", "qas", "tst", "prd", "sbx", "trn", "all"}
KINDS = {"abap", "java", "ssh", "hana", "rdp", "bo", "api", "vpn", "router", "sftp",
         "vmware", "rfc", "sapgui", "jco", "nco", "odata", "file", "webdisp", "scc", "suser", "web"}
LEGACY_KINDS = {"rfc", "sapgui"}          # superseded by the merged `abap` kind
IPISH = re.compile(r"(^|-)\d{1,3}-\d{1,3}-\d{1,3}(-|$)")

ERROR, WARN, INFO = "ERROR", "WARN", "INFO"


def private_host(h):
    """True when h is definitely NOT on the public internet.

    No DNS lookups: lint must not do network I/O, and an internal name only resolves
    from the right network anyway. Literal private/loopback IPs and dotless or
    .local-style names are what can be decided offline. Everything else is treated as
    public, which is the safe direction -- it costs a warning, never a missed one.
    """
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback
    except ValueError:
        pass
    return "." not in h or h.endswith((".local", ".internal", ".lan", ".corp"))


def check_url(url):
    """Why fields.url is unusable, or None if it is fine.

    `url` is the browser ORIGIN a page is matched against before a password is filled.
    Only scheme://host:port is ever compared -- a path is kept for convenience ("open
    this system") and ignored by matching.
    """
    u = urllib.parse.urlsplit(url if "//" in url else "//" + url)
    if not u.scheme or not u.hostname:
        return (f"url '{url}' has no scheme://host — autofill matches on origin, "
                f"so this can never match a page")
    if u.scheme not in ("http", "https"):
        return f"url scheme '{u.scheme}' is not http(s); autofill only handles web logins"
    try:
        u.port
    except ValueError:
        return f"url '{url}' has a non-numeric port"
    if u.scheme == "http" and not private_host(u.hostname):
        return (f"url is plaintext http to '{u.hostname}', which does not look like a "
                f"private address — a password filled there crosses the open internet. "
                f"Use https, or confirm the host really is internal")
    return None


def lint(index, customer=None, nonconforming=None):
    out = []
    nonconforming = [] if nonconforming is None else nonconforming

    def say(sev, ident, msg):
        out.append((sev, ident, msg))

    entries = index.get("entries") or []
    if customer:
        entries = [e for e in entries if (e.get("customer") or "").lower() == customer]

    entry_ids = {e.get("id") for e in (index.get("entries") or [])}

    for e in entries:
        eid = e.get("id") or "(no id)"
        cust = e.get("customer") or ""
        env = e.get("env") or ""
        kind = e.get("kind") or ""

        if cust != cust.lower() or " " in cust:
            say(WARN, eid, f"customer '{cust}' should be lowercase with no spaces")
        if env and env not in ENVS:
            say(WARN, eid, f"env '{env}' is not one of {', '.join(sorted(ENVS))}")

        if not cust:
            say(WARN, eid, "no customer field, so the id cannot be checked")
        elif not eid.lower().startswith(cust.lower() + "-"):
            say(ERROR, eid, f"id does not start with its customer '{cust}-'")
        else:
            rest = eid[len(cust) + 1:].split("-")
            if rest and rest[0] in ENVS:
                # Conforming enough to check the mirror.
                if rest[0] != env:
                    say(ERROR, eid, f"id says env '{rest[0]}' but the field says "
                                    f"'{env}' -- one of them is a lie")
                if len(rest) > 1 and rest[1] != kind:
                    say(WARN, eid, f"id says kind '{rest[1]}' but the field says '{kind}'")
            else:
                # INFO so 133 imports do not drown the real findings -- but counted
                # separately and always surfaced, because "0 errors, 0 warnings" on a
                # set where a third of the ids do not follow the convention reads as
                # clean when it is not.
                say(INFO, eid, "legacy id: not <customer>-<env>-<kind>-<identity>")
                nonconforming.append(eid)

        if IPISH.search(eid):
            say(WARN, eid, "id embeds an IP address -- IPs move, and aliases of one "
                           "host read as separate systems")
        # A kind the tooling does not know is not cosmetic: the editor's dropdown has
        # no option for it, so opening the entry shows no selection and one stray click
        # silently rewrites the kind. It also gets no probe and no port derivation.
        if kind and kind not in KINDS:
            say(WARN, eid, f"kind '{kind}' is not registered — the editor cannot render "
                           f"it and it has no probe; add it to lint/migrate/ui together")
        if kind in LEGACY_KINDS:
            say(INFO, eid, f"kind '{kind}' is superseded by 'abap' (ports go in "
                           f"protocols[], accounts in logins[])")

        # fields.url -- the origin a browser page is matched against before a password
        # is filled. A bad value is worse than none: it either never matches (dead
        # weight nobody re-checks) or points somewhere a secret must not go.
        # fields.url may list several origins, whitespace-separated -- one system often
        # answers on more than one name. Each is checked on its own.
        for url in str((e.get("fields") or {}).get("url") or "").split():
            why = check_url(url)
            if why:
                say(WARN, eid, why)

        # `requires` is free text (vpn:x, router:/H/..., internet) OR an entry id to
        # jump through. A bare token matching no entry is almost always a rename that
        # was not followed through -- which is how a prerequisite silently disappears.
        for r in e.get("requires") or []:
            if ":" not in r and r not in ("internet",) and r not in entry_ids:
                say(WARN, eid, f"requires '{r}' matches no entry id; if it is free text, "
                               f"prefix it (vpn:…, router:…) or use 'internet'")

        logins = e.get("logins")
        if logins is not None:
            if e.get("secret"):
                say(WARN, eid, "has both a flat secret and logins[] -- two sources of "
                               "truth; move the flat one into logins[]")
            seen, defaults = set(), 0
            for lg in logins if isinstance(logins, list) else []:
                key = (str(lg.get("client") or ""), lg.get("user") or "")
                if key in seen:
                    say(ERROR, eid, f"duplicate login {key[1]}@{key[0] or '-'}")
                seen.add(key)
                defaults += 1 if lg.get("default") else 0
            if defaults > 1:
                say(WARN, eid, f"{defaults} logins marked default; the first wins")
        elif kind == "abap":
            say(INFO, eid, "kind 'abap' with no logins[]; the flat user/secret is used")

    # Graph <-> entry coherence. A node whose credential belongs to another customer
    # is the kind of mix-up that ends with the wrong system being touched.
    by_id = {e.get("id"): e for e in (index.get("entries") or [])}
    for n in index.get("nodes") or []:
        ncust = (n.get("customer") or "").lower()
        if customer and ncust != customer:
            continue
        for c in n.get("creds") or []:
            ent = by_id.get(c)
            if ent is None:
                say(ERROR, n.get("id", "?"), f"creds '{c}' is not an entry id")
            elif ncust and (ent.get("customer") or "").lower() != ncust:
                say(ERROR, n.get("id", "?"),
                    f"creds '{c}' belongs to customer "
                    f"'{ent.get('customer')}', not '{n.get('customer')}'")
        if n.get("env") and n["env"] not in ENVS:
            say(WARN, n.get("id", "?"), f"env '{n['env']}' is not a known environment")

    attached = {c for n in (index.get("nodes") or []) for c in (n.get("creds") or [])}
    for e in entries:
        if e.get("id") not in attached and e.get("id") in entry_ids:
            say(INFO, e.get("id", "?"), "not attached to any landscape node")
    return out


def main(argv):
    customer, show_all = None, False
    args = argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--customer" and i + 1 < len(args):
            customer = args[i + 1].lower(); i += 2
        elif args[i] in ("--all", "-a"):
            show_all = True; i += 1
        else:
            print(f"usage: lint.py [--customer <name>] [--all]  < index.json",
                  file=sys.stderr)
            return 2
    try:
        index = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"creds: index is not valid JSON: {exc}", file=sys.stderr)
        return 2

    nonconforming = []
    found = lint(index, customer, nonconforming)
    counts = {ERROR: 0, WARN: 0, INFO: 0}
    for sev, _, _ in found:
        counts[sev] += 1

    shown = [f for f in found if show_all or f[0] != INFO]
    for sev, ident, msg in sorted(shown, key=lambda f: ({ERROR: 0, WARN: 1, INFO: 2}[f[0]],
                                                        f[1])):
        print(f"  {sev:<5} {ident}\n        {msg}")
    if not shown:
        print("  nothing to report" + ("" if show_all else " (INFO hidden; --all shows it)"))

    scope = f" in {customer}" if customer else ""
    total = len([e for e in (index.get("entries") or [])
                 if not customer or (e.get("customer") or "").lower() == customer])
    print(f"\n{counts[ERROR]} error(s), {counts[WARN]} warning(s), "
          f"{counts[INFO]} note(s){scope}"
          + ("" if show_all else "  --  --all to see notes"))
    if nonconforming:
        print(f"{len(nonconforming)}/{total} id(s) do NOT follow "
              f"<customer>-<env>-<kind>-<identity>:")
        for n in sorted(nonconforming)[:8]:
            print(f"    {n}")
        if len(nonconforming) > 8:
            print(f"    … and {len(nonconforming) - 8} more")
    return 1 if counts[ERROR] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
