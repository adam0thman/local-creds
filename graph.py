#!/usr/bin/env python3
"""Landscape graph over the creds index: nodes, typed edges, and path walking.

The index gains three optional top-level keys alongside `entries`. Absent means
"no graph yet", so every existing index stays valid:

    nodes[]  id, label, type, customer, env, creds[] -> entry ids, attrs{}, pos{}
    edges[]  from, to, type, port, requires[], window{days,hours,tz}, note
    views[]  id, name, kind          (layout only; ignored here)

Why this exists: `requires` on an entry is hand-maintained and drifts. Edges make
it derivable -- walk from where you are to what you want, collect every `requires`
on the way, and that is the real prerequisite list.

Edges are DIRECTED and walked forward only. You draw the direction you connect in
(me -> saprouter -> appserver), which is also the direction a hop's hostname is
resolved in. That distinction is the point: the same box is reached by different
names from different sides, and a single `host` field cannot say so.

SECRETS: stdin carries the fully decrypted index. Nothing here may print a
`secret`. Entries are referenced by id only, never dereferenced.
"""
import json
import sys
from collections import deque
from datetime import datetime

NODE_TYPES = {"appserver", "db", "saprouter", "bastion", "webdisp", "device",
              "network", "cloud", "client", "other"}
# disp/gateway/msgserver deliberately mirror the protocol names the entries and the
# web editor already use, so one instance port means the same thing in both places.
EDGE_TYPES = {"network", "disp", "gateway", "msgserver", "rfc", "jdbc", "ssh",
              "http", "transport", "replication", "other"}

DAYS = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


# --------------------------------------------------------------------------
# time windows  (an edge that is only open during a change window / ACL slot)
# --------------------------------------------------------------------------

def parse_days(spec):
    """'mon-fri' | 'mon,wed' | 'fri-mon' (wraps) -> set of weekday ints."""
    out = set()
    for part in str(spec).lower().replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a not in DAYS or b not in DAYS:
                raise ValueError(f"bad day range {part!r}")
            i, j = DAYS[a], DAYS[b]
            # j < i means the range wraps past Sunday (fri-mon).
            out |= {k % 7 for k in range(i, (j if j >= i else j + 7) + 1)}
        else:
            if part not in DAYS:
                raise ValueError(f"unknown day {part!r}")
            out.add(DAYS[part])
    if not out:
        raise ValueError("empty day spec")
    return out


def _minutes(hhmm):
    h, _, m = str(hhmm).strip().partition(":")
    h, m = int(h), int(m or 0)
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise ValueError(f"bad time {hhmm!r}")
    return h * 60 + m


def parse_hours(spec):
    a, _, b = str(spec).partition("-")
    if not b:
        raise ValueError(f"bad hour range {spec!r}")
    return _minutes(a), _minutes(b)


def window_open(win, now=None):
    """Is this edge's access window open? Raises ValueError on a malformed spec."""
    tz = (win or {}).get("tz")
    if now is None:
        now = datetime.now()
        if tz:
            try:
                from zoneinfo import ZoneInfo
                now = datetime.now(ZoneInfo(tz))
            except Exception as exc:      # unknown tz / no tzdata: say so, don't guess
                raise ValueError(f"timezone {tz!r}: {exc}")
    if now.weekday() not in parse_days(win.get("days", "mon-sun")):
        return False
    start, end = parse_hours(win.get("hours", "00:00-23:59"))
    cur = now.hour * 60 + now.minute
    if start <= end:
        return start <= cur <= end
    return cur >= start or cur <= end     # window running past midnight


def window_text(win):
    return f"{win.get('days', 'mon-sun')} {win.get('hours', '00:00-23:59')}" \
           + (f" {win['tz']}" if win.get("tz") else "")


# --------------------------------------------------------------------------
# graph
# --------------------------------------------------------------------------

def build(index):
    """-> (nodes_by_id, adjacency {node_id: [edge, ...]})."""
    nodes = {n.get("id"): n for n in (index.get("nodes") or []) if n.get("id")}
    adj = {}
    for e in index.get("edges") or []:
        adj.setdefault(e.get("from"), []).append(e)
    return nodes, adj


def resolve(nodes, ref):
    """Accept a node id, an attached entry id, or a label (case-insensitive)."""
    if ref in nodes:
        return ref
    for match in (
        [i for i, n in nodes.items() if ref in (n.get("creds") or [])],
        [i for i, n in nodes.items() if str(n.get("label", "")).lower() == ref.lower()],
    ):
        if len(match) == 1:
            return match[0]
        if len(match) > 1:
            raise LookupError(f"'{ref}' is ambiguous: {', '.join(sorted(match))}")
    raise LookupError(f"no node '{ref}'")


def find_path(nodes, adj, src, dst):
    """Breadth-first, so the result is the fewest-hops route. -> [edge] or None."""
    if src == dst:
        return []
    seen, queue = {src}, deque([(src, [])])
    while queue:
        cur, sofar = queue.popleft()
        for e in adj.get(cur, []):
            nxt = e.get("to")
            if nxt in seen or nxt not in nodes:
                continue
            if nxt == dst:
                return sofar + [e]
            seen.add(nxt)
            queue.append((nxt, sofar + [e]))
    return None


def find_all_paths(nodes, adj, src, dst, max_hops=6, limit=25):
    """Every simple route, shortest first. A box with a dispatcher, a gateway, a
    message server and SSH has four ways in; showing only the first hides three."""
    out = []

    def walk(cur, sofar, seen):
        if len(sofar) >= max_hops or len(out) >= limit:
            return
        for e in adj.get(cur, []):
            nxt = e.get("to")
            if nxt not in nodes or nxt in seen:
                continue
            if nxt == dst:
                out.append(sofar + [e])
                if len(out) >= limit:
                    return
            else:
                walk(nxt, sofar + [e], seen | {nxt})

    walk(src, [], {src})
    return sorted(out, key=len)


def _summarise(hops, now):
    """Accumulate what a single route costs you: prerequisites and shut windows."""
    requires, closed = [], []
    for e in hops:
        for r in e.get("requires") or []:
            if r not in requires:
                requires.append(r)
        win = e.get("window")
        if win:
            try:
                if not window_open(win, now):
                    closed.append(f"{e['from']} -> {e['to']} is only open "
                                  f"{window_text(win)}")
            except ValueError as exc:
                closed.append(f"{e['from']} -> {e['to']} has an unreadable window: {exc}")

    return {"hops": [{"from": e["from"], "to": e["to"],
                      "type": e.get("type", "network"),
                      "port": e.get("port"), "note": e.get("note")} for e in hops],
            "requires": requires, "closed": closed}


def path_report(index, src_ref, dst_ref, now=None, all_routes=False):
    nodes, adj = build(index)
    src, dst = resolve(nodes, src_ref), resolve(nodes, dst_ref)

    found = (find_all_paths(nodes, adj, src, dst) if all_routes
             else ([hops] if (hops := find_path(nodes, adj, src, dst)) is not None else []))
    if not found:
        return {"ok": False, "src": src, "dst": dst,
                "error": f"no route from '{src}' to '{dst}' -- "
                         f"the graph has no edge chain connecting them"}

    node = nodes[dst]
    base = {"ok": True, "src": src, "dst": dst,
            "creds": list(node.get("creds") or []),
            "env": node.get("env", ""), "label": node.get("label", dst)}
    if all_routes:
        base["routes"] = [_summarise(h, now) for h in found]
    else:
        base.update(_summarise(found[0], now))
    return base


def _format_route(route, indent=""):
    out = []
    for h in route["hops"]:
        label = h["type"] + (f":{h['port']}" if h.get("port") else "")
        out.append(f"{indent}  {h['from']:<24} --{label}--> {h['to']}"
                   + (f"   # {h['note']}" if h.get("note") else ""))
    if route["requires"]:
        out.append(f"{indent}  requires: " + ", ".join(route["requires"]))
    for c in route["closed"]:
        out.append(f"{indent}  WARNING  {c}")
    return out


def format_report(rep):
    if not rep.get("ok"):
        return f"creds: {rep['error']}"
    out = [f"{rep['src']} -> {rep['dst']}"
           + (f"  [{rep['env'].upper()}]" if rep.get("env") else "")]
    if "routes" in rep:
        for i, route in enumerate(rep["routes"], 1):
            out.append(f"  route {i} ({len(route['hops'])} hop"
                       f"{'s' if len(route['hops']) != 1 else ''})")
            out += _format_route(route, "  ")
        out.append(f"{len(rep['routes'])} route(s)")
    else:
        out += _format_route(rep)
    if rep["creds"]:
        out.append("credentials: " + ", ".join(rep["creds"]))
    if rep.get("env") == "prd":
        out.append("NOTE     destination is PRODUCTION -- creds exec needs CREDS_ALLOW_PROD=1")
    return "\n".join(out)


# --------------------------------------------------------------------------
# validation  (called from the shell validate() before anything is re-encrypted)
# --------------------------------------------------------------------------

def problems(index):
    """-> list of human-readable problems. Empty means the graph is coherent."""
    out = []
    nodes = index.get("nodes") or []
    edges = index.get("edges") or []
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return ["'nodes' and 'edges' must both be arrays"]

    ids, seen = [], set()
    for i, n in enumerate(nodes):
        nid = n.get("id") if isinstance(n, dict) else None
        if not nid or not isinstance(nid, str):
            out.append(f"node #{i} has a missing or non-string id")
            continue
        if nid in seen:
            out.append(f"duplicate node id: {nid}")
        seen.add(nid)
        ids.append(nid)
        if n.get("type") and n["type"] not in NODE_TYPES:
            out.append(f"WARNING node {nid}: unknown type '{n['type']}'")

    entry_ids = {e.get("id") for e in (index.get("entries") or [])}
    for n in nodes:
        for c in (n.get("creds") or []) if isinstance(n, dict) else []:
            if c not in entry_ids:
                out.append(f"node {n.get('id')}: creds '{c}' is not an entry id")

    for i, e in enumerate(edges):
        if not isinstance(e, dict):
            out.append(f"edge #{i} is not an object")
            continue
        for end in ("from", "to"):
            if e.get(end) not in seen:
                out.append(f"edge #{i} ({e.get('from')}->{e.get('to')}): "
                           f"{end} '{e.get(end)}' is not a node id")
        if e.get("type") and e["type"] not in EDGE_TYPES:
            out.append(f"WARNING edge #{i}: unknown type '{e['type']}'")
        if e.get("window"):
            try:
                parse_days(e["window"].get("days", "mon-sun"))
                parse_hours(e["window"].get("hours", "00:00-23:59"))
            except (ValueError, AttributeError) as exc:
                out.append(f"edge #{i} ({e.get('from')}->{e.get('to')}): bad window -- {exc}")
    return out


# --------------------------------------------------------------------------

def selftest():
    assert parse_days("mon-fri") == {0, 1, 2, 3, 4}
    assert parse_days("fri-mon") == {4, 5, 6, 0}, "range must wrap past Sunday"
    assert parse_days("mon,wed,sun") == {0, 2, 6}
    assert parse_hours("08:00-18:00") == (480, 1080)

    wed_noon = datetime(2026, 8, 26, 12, 0)      # a Wednesday
    assert window_open({"days": "mon-fri", "hours": "08:00-18:00"}, wed_noon)
    assert not window_open({"days": "sat,sun"}, wed_noon)
    assert not window_open({"hours": "18:00-20:00"}, wed_noon)
    # a window that runs past midnight is open on both sides of it
    assert window_open({"hours": "22:00-06:00"}, datetime(2026, 8, 26, 23, 0))
    assert window_open({"hours": "22:00-06:00"}, datetime(2026, 8, 26, 2, 0))
    assert not window_open({"hours": "22:00-06:00"}, wed_noon)

    idx = {
        "entries": [{"id": "x-rfc", "secret": "hunter2"}],
        "nodes": [{"id": "me", "type": "client"},
                  {"id": "rtr", "type": "saprouter"},
                  {"id": "app", "type": "appserver", "creds": ["x-rfc"], "env": "prd"},
                  {"id": "island", "type": "db"}],
        "edges": [{"from": "me", "to": "rtr", "type": "network", "port": 3299,
                   "requires": ["vpn:corp"]},
                  {"from": "rtr", "to": "app", "type": "rfc", "port": 3330,
                   "requires": ["vpn:corp", "acl:jump"]}],
    }
    assert problems(idx) == [], problems(idx)

    rep = path_report(idx, "me", "app")
    assert rep["ok"] and len(rep["hops"]) == 2
    assert rep["requires"] == ["vpn:corp", "acl:jump"], "deduped, order preserved"
    assert rep["creds"] == ["x-rfc"]
    assert not path_report(idx, "me", "island")["ok"], "unreachable must not invent a route"
    assert path_report(idx, "me", "x-rfc")["dst"] == "app", "resolve by attached entry id"
    assert "hunter2" not in format_report(rep), "a secret must never reach the output"

    # edges are directed: app cannot reach me just because me reaches app
    assert not path_report(idx, "app", "me")["ok"]

    # four ways into one box must not be reported as one
    multi = {"entries": [], "nodes": [{"id": "me"}, {"id": "box"}],
             "edges": [{"from": "me", "to": "box", "type": "disp", "port": 3210},
                       {"from": "me", "to": "box", "type": "gateway", "port": 3310},
                       {"from": "me", "to": "box", "type": "ssh", "port": 22}]}
    assert len(path_report(multi, "me", "box")["hops"]) == 1, "default stays shortest"
    assert len(path_report(multi, "me", "box", all_routes=True)["routes"]) == 3
    assert "3310" in format_report(path_report(multi, "me", "box", all_routes=True))

    broken = {"entries": [], "nodes": [{"id": "a"}, {"id": "a"}],
              "edges": [{"from": "a", "to": "ghost"}]}
    assert any("duplicate node id" in p for p in problems(broken))
    assert any("ghost" in p for p in problems(broken))
    print("graph.py selftest ok")


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        selftest()
        return 0
    if len(argv) < 2 or argv[1] not in ("path", "check"):
        print("usage: graph.py {path <from> <to> [--json] | check | selftest}  < index.json",
              file=sys.stderr)
        return 2
    try:
        index = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"creds: index is not valid JSON: {exc}", file=sys.stderr)
        return 2

    if argv[1] == "check":
        found = problems(index)
        for p in found:
            print(p, file=sys.stderr)
        # Warnings are advisory; only hard problems block a save.
        return 1 if any(not p.startswith("WARNING") for p in found) else 0

    if len(argv) < 4:
        print("usage: graph.py path <from> <to> [--json]", file=sys.stderr)
        return 2
    try:
        rep = path_report(index, argv[2], argv[3], all_routes="--all" in argv[4:])
    except LookupError as exc:
        print(f"creds: {exc}", file=sys.stderr)
        known = ", ".join(sorted(build(index)[0])) or "(none yet -- add nodes with creds edit)"
        print(f"known nodes: {known}", file=sys.stderr)
        return 1
    if "--json" in argv[4:]:
        print(json.dumps(rep, indent=2))
    else:
        print(format_report(rep))
    return 0 if rep.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
