#!/usr/bin/env python3
"""Propose convention-compliant ids, and merge rfc+sapgui pairs into `abap` entries.

Dry-run by default. It does only what the DATA supports and refuses to guess:

  * merges strictly on an exact (host, sysnr) match -- two entries on the same host
    and instance number are the same system, whatever their imported names said
  * never merges when one (client, user) pair carries two different passwords
  * never invents a SID; an entry without one is reported as needing the box
  * reports id collisions instead of silently disambiguating them

Everything it cannot decide comes out as a short worklist, which is the point: 133
imported SAP GUI names become a handful of real questions.

SECRETS: passwords are moved field-to-field and compared, never printed.
"""
import json
import re
import sys

import lint as _lint                       # one source of truth for the env vocabulary

ABAPISH = {"rfc", "sapgui", "abap", "jco", "nco"}
IPISH = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def label(host):
    """First DNS label of a hostname; empty for an IP or a blank."""
    host = (host or "").strip()
    if not host or IPISH.match(host):
        return ""
    return re.sub(r"[^a-z0-9]", "", host.split(".")[0].lower())


def slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").lower()).strip("-")


def identity(e, sid):
    """The <identity> token, which depends on the kind (SID is not universal)."""
    kind = e.get("kind")
    f = e.get("fields") or {}
    if kind in ABAPISH:
        return slug(sid)
    if kind == "java":            # NW Java (PI/PO, Portal, SolMan Java): SID, as ABAP
        return slug(sid)
    if kind == "hana":
        return "-".join(x for x in (slug(sid), slug(f.get("tenant"))) if x)
    if kind in ("ssh", "sftp", "rdp", "bo", "vmware"):
        # Host-level access: the machine is the identity, not the SID it happens to run.
        return label(e.get("host")) or slug(sid)
    if kind == "api":
        return slug(f.get("service") or label(e.get("host")))
    return label(e.get("host")) or slug(sid)


def conforms(e, customer):
    """Already <customer>-<env>-<kind>-…, with env and kind agreeing with the record.

    A conforming id is left alone. The generated identity token is a fallback for
    names nobody has curated -- it is worse than a hand-picked one, because a host
    that is an IP yields nothing and a hostname like vpn.example.edu yields "vpn".
    Renaming a good id to a generated one is a downgrade, not a migration.
    """
    parts = (e.get("id") or "").split("-")
    if len(parts) < 4 or parts[0] != customer:
        return False
    kind = "abap" if e.get("kind") in ABAPISH else e.get("kind")
    return (parts[1] in _lint.ENVS and parts[1] == e.get("env")
            and parts[2] == kind and bool(parts[3]))


def logins_of(entry):
    """Every (client, user) -> secret a record holds, however it stores them.

    Mirrors pick_login() in the `creds` script: logins[] when present, otherwise a
    single login synthesised from the flat user/secret/fields.client. Reading only the
    flat fields silently DROPS the credentials of an already-migrated `abap` entry --
    which is data loss, not a naming problem.
    """
    out = {}
    for lg in entry.get("logins") or []:
        user = (lg.get("user") or "").strip()
        if user:
            out[(str(lg.get("client") or ""), user)] = lg.get("secret") or ""
    if out:
        return out
    user = (entry.get("user") or "").strip()
    if user:
        out[(str((entry.get("fields") or {}).get("client") or ""), user)] = \
            entry.get("secret") or ""
    return out


def merge_groups(entries):
    """(host, sysnr) -> [entry]. Only ABAP-ish kinds; only where a host is known."""
    groups = {}
    for e in entries:
        if e.get("kind") not in ABAPISH:
            continue
        host = (e.get("host") or "").strip().lower()
        if not host:
            continue
        key = (host, str((e.get("fields") or {}).get("sysnr") or ""))
        groups.setdefault(key, []).append(e)
    return groups


def plan(index, customer):
    entries = [e for e in index["entries"] if (e.get("customer") or "").lower() == customer]
    merges, renames, blocked, notes = [], [], [], []
    consumed = set()

    for (host, sysnr), members in sorted(merge_groups(entries).items()):
        sids = {(m.get("fields") or {}).get("sid") for m in members} - {None, ""}
        envs = {m.get("env") for m in members} - {None, ""}
        if len(sids) > 1:
            blocked.append(f"{host} sysnr {sysnr or '?'}: members disagree on SID "
                           f"({', '.join(sorted(sids))}) — {', '.join(m['id'] for m in members)}")
            continue
        if not sids:
            blocked.append(f"{host} sysnr {sysnr or '?'}: no SID on any of "
                           f"{', '.join(m['id'] for m in members)} — read it off the box "
                           f"(saphostctrl -function ListInstances)")
            continue
        sid = sids.pop()
        if len(envs) > 1:
            blocked.append(f"{host} ({sid}): members disagree on env "
                           f"({', '.join(sorted(envs))}) — {', '.join(m['id'] for m in members)}")
            continue
        env = envs.pop() if envs else "prd"

        # (client, user) -> secrets. Two secrets for one pair is a real conflict.
        seen = {}
        for m in members:
            for key, secret in logins_of(m).items():
                seen.setdefault(key, set()).add(secret)
        clash = [f"{u}@{c or '-'}" for (c, u), s in seen.items() if len(s) > 1]
        if clash:
            blocked.append(f"{host} ({sid}): {', '.join(clash)} carries conflicting "
                           f"passwords across {', '.join(m['id'] for m in members)}")
            continue

        new_id = f"{customer}-{env}-abap-{slug(sid)}"
        if len(members) > 1 or members[0]["id"] != new_id or members[0].get("kind") != "abap":
            merges.append({"new_id": new_id, "env": env, "sid": sid, "host": host,
                           "sysnr": sysnr, "src": [m["id"] for m in members],
                           "logins": sorted(seen.keys())})
            consumed |= {m["id"] for m in members}

    for e in entries:
        if e["id"] in consumed or conforms(e, customer):
            continue
        sid = (e.get("fields") or {}).get("sid")
        ident = identity(e, sid)
        env = e.get("env") or ""
        if not env:
            blocked.append(f"{e['id']}: no env set")
            continue
        if not ident:
            blocked.append(
                f"{e['id']}: no SID" if e.get("kind") in ABAPISH else
                f"{e['id']}: cannot name it — no SID, and the host "
                f"({e.get('host') or 'none'}) gives no usable label"
                f"{' (it is an IP)' if IPISH.match(e.get('host') or '') else ''}")
            continue
        kind = "abap" if e.get("kind") in ABAPISH else e.get("kind")
        misc = slug(e.get("user")) if kind in ("ssh", "sftp", "rdp") and e.get("user") else ""
        new_id = "-".join(x for x in (customer, env, kind, ident, misc) if x)
        if new_id != e["id"]:
            renames.append({"old": e["id"], "new": new_id})

    # Same SID+sysnr on different host strings is usually one box behind two names.
    by_sid = {}
    for e in entries:
        s = (e.get("fields") or {}).get("sid")
        if s and e.get("kind") in ABAPISH:
            by_sid.setdefault(s, set()).add((e.get("host") or "").lower())
    # Two host strings for one SID mean one of two very different things, and the
    # shape of the strings tells you which. An IP alongside a name is usually the same
    # machine written twice; two distinct names are usually two app servers.
    for s, hosts in sorted(by_sid.items()):
        if len(hosts) <= 1:
            continue
        ips = {h for h in hosts if IPISH.match(h)}
        names = hosts - ips
        joined = ", ".join(sorted(hosts))
        if ips and names:
            notes.append(f"SID {s}: {joined} — an IP and a name for what is probably ONE "
                         f"box. Confirm (ip a on it), point both at one host string, "
                         f"re-run, and they merge")
        elif len(names) > 1:
            notes.append(f"SID {s}: {joined} — distinct hostnames, so probably SEPARATE "
                         f"app servers of one system (SAP names them ...ai01/ai02 for "
                         f"instances, ...cs/ci for central services). Give each a misc "
                         f"token, do not merge")
        else:
            notes.append(f"SID {s}: {joined} — several IPs, no names. Only the box can "
                         f"say whether these are aliases")

    # A colliding proposal must be DROPPED, not merely reported: an entry blocked from
    # merging falls through to the rename branch, where two systems can land on the same
    # id. Leaving them in produced a plan that `validate` rejected wholesale, taking the
    # applicable part of the migration down with it.
    proposed = [m["new_id"] for m in merges] + [r["new"] for r in renames]
    existing = {e["id"] for e in index["entries"]} - consumed - {r["old"] for r in renames}
    unusable = set()
    for nid in sorted(set(proposed)):
        n = proposed.count(nid)
        if n > 1:
            blocked.append(f"'{nid}' would be claimed by {n} different systems — "
                           f"they need distinguishing (app server name, or a misc token)")
            unusable.add(nid)
        elif nid in existing:
            blocked.append(f"'{nid}' already exists as a different entry")
            unusable.add(nid)
    merges = [m for m in merges if m["new_id"] not in unusable]
    renames = [r for r in renames if r["new"] not in unusable]
    return merges, renames, blocked, notes


def apply(index, customer, merges, renames):
    by = {e["id"]: e for e in index["entries"]}
    consumed, new_entries = set(), []
    for m in merges:
        srcs = [by[i] for i in m["src"] if i in by]
        seen, protocols, ptypes = {}, [], set()
        for e in srcs:
            for key, secret in logins_of(e).items():
                seen.setdefault(key, secret)
            for p in e.get("protocols") or []:
                k = (p.get("type"), p.get("port"))
                if k not in ptypes:
                    ptypes.add(k)
                    protocols.append(p)
        logins = [{"client": c, "user": u, "secret": s} for (c, u), s in sorted(seen.items())]
        if logins:
            logins[0]["default"] = True
        fields = {}
        for e in srcs:                       # first non-empty value per key wins
            for k, v in (e.get("fields") or {}).items():
                if k not in fields and str(v or "").strip():
                    fields[k] = v
        fields.pop("client", None)           # client lives on each login now
        new_entries.append({
            "id": m["new_id"], "customer": customer, "env": m["env"], "kind": "abap",
            "host": srcs[0].get("host"), "port": None, "user": None, "secret": "", "via": None,
            "tags": sorted({t for e in srcs for t in (e.get("tags") or [])}),
            "requires": sorted({r for e in srcs for r in (e.get("requires") or [])}),
            "fields": fields, "protocols": protocols, "logins": logins,
        })
        consumed |= {e["id"] for e in srcs}

    ren = {r["old"]: r["new"] for r in renames}
    index["entries"] = [e for e in index["entries"] if e["id"] not in consumed] + new_entries
    for e in index["entries"]:
        if e["id"] in ren:
            e["id"] = ren[e["id"]]
        if e.get("kind") in ABAPISH and e.get("kind") != "abap" and e["id"].split("-")[2:3] == ["abap"]:
            e["kind"] = "abap"

    # Node creds[] must follow, or validation rejects the save.
    remap = dict(ren)
    for m in merges:
        for old in m["src"]:
            remap[old] = m["new_id"]
    for n in index.get("nodes") or []:
        if n.get("creds"):
            n["creds"] = sorted({remap.get(c, c) for c in n["creds"]})
    for e in index["entries"]:
        if e.get("requires"):
            e["requires"] = [remap.get(r, r) for r in e["requires"]]
    return len(new_entries), len(consumed), len(renames)


def report(customer, merges, renames, blocked, notes, applied=False):
    w = sys.stderr if applied else sys.stdout
    verb = "merged" if applied else "would merge"
    print(f"\n{customer}: {verb} {sum(len(m['src']) for m in merges)} entries "
          f"into {len(merges)}, {'renamed' if applied else 'would rename'} {len(renames)}\n", file=w)
    for m in merges:
        print(f"  {' + '.join(m['src'])}\n    -> {m['new_id']}  "
              f"({m['sid']} sysnr {m['sysnr'] or '?'} on {m['host']}, "
              f"{len(m['logins'])} login(s))", file=w)
    for r in renames:
        print(f"  {r['old']}\n    -> {r['new']}", file=w)
    if notes:
        print("\n  worth checking:", file=w)
        for n in notes:
            print(f"    · {n}", file=w)
    if blocked:
        print(f"\n  needs a decision ({len(blocked)}):", file=w)
        for b in blocked:
            print(f"    · {b}", file=w)


def main(argv):
    args = argv[1:]
    customer = do_apply = None
    path = None
    i = 0
    while i < len(args):
        if args[i] == "--customer" and i + 1 < len(args):
            customer = args[i + 1].lower(); i += 2
        elif args[i] == "--apply":
            do_apply = True; i += 1
        elif not args[i].startswith("-"):
            path = args[i]; i += 1
        else:
            print("usage: migrate.py --customer <name> [--apply] [file]", file=sys.stderr)
            return 2
    if not customer:
        print("migrate: --customer is required", file=sys.stderr)
        return 2

    index = json.load(open(path)) if path else json.load(sys.stdin)
    merges, renames, blocked, notes = plan(index, customer)

    if not do_apply:
        report(customer, merges, renames, blocked, notes)
        print("\n  --apply to commit (a snapshot is taken first)\n")
        return 0
    if not path:
        print("migrate: --apply needs the index file (run it through `creds migrate`)",
              file=sys.stderr)
        return 2
    apply(index, customer, merges, renames)
    json.dump(index, open(path, "w"), indent=1)
    report(customer, merges, renames, blocked, notes, applied=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
