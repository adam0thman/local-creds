#!/usr/bin/env python3
"""Local-only editor backend for the creds index. Started by `creds ui`.

Security posture: binds 127.0.0.1 only, requires a per-launch random token on
every request, serves no external resources, and exits after an idle period.
Decryption lives here rather than in a `creds dump` subcommand, so the CLI keeps
its property that no command ever prints a secret.
"""
import datetime, glob, http.server, json, os, re, secrets, shutil, socket, subprocess, sys
import tempfile, threading, time, urllib.parse

DIR = os.environ.get("LOCAL_CREDS_DIR", os.path.expanduser("~/.local-creds"))
ENC = os.path.join(DIR, "creds.age")
RCP = os.path.join(DIR, "recipients.txt")
KEY = os.environ.get("LOCAL_CREDS_KEY", os.path.expanduser("~/.config/age/local-creds.key"))
HERE = os.path.dirname(os.path.abspath(__file__))
HTML = os.path.join(HERE, "ui.html")
LANDSCAPE = os.path.join(HERE, "landscape.html")

TOKEN = secrets.token_urlsafe(24)
IDLE_TIMEOUT = 30 * 60
last_seen = time.time()


def decrypt():
    out = subprocess.run(["age", "-d", "-i", KEY, ENC], capture_output=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.decode()[:200] or "decrypt failed")
    return json.loads(out.stdout)


BACKUPS = os.path.join(DIR, ".backups")
KEEP_BACKUPS = 15


def snapshot():
    """Snapshot the current ciphertext before any overwrite. Same contract as
    `creds edit`, so a save from either surface is recoverable via `creds restore`."""
    if not os.path.exists(ENC):
        return
    os.makedirs(BACKUPS, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    shutil.copy2(ENC, os.path.join(BACKUPS, f"creds-{stamp}.age"))
    snaps = sorted(glob.glob(os.path.join(BACKUPS, "creds-*.age")), reverse=True)
    for old in snaps[KEEP_BACKUPS:]:
        try: os.remove(old)
        except OSError: pass


def encrypt(idx):
    fd, tmp = tempfile.mkstemp(prefix=".creds-", dir=DIR)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(idx, fh, indent=2)
        os.chmod(tmp, 0o600)
        new = ENC + ".new"
        out = subprocess.run(["age", "-R", RCP, "-o", new, tmp], capture_output=True)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.decode()[:200] or "encrypt failed")
        snapshot()
        os.replace(new, ENC)
    finally:
        try: os.remove(tmp)
        except FileNotFoundError: pass


def probe_port(entry):
    """Best guess at the TCP port that proves the service is up."""
    kind, f = entry.get("kind", ""), entry.get("fields") or {}
    if entry.get("port"):
        return int(entry["port"])
    if kind == "java" and str(f.get("sysnr", "")).isdigit():
        return 50000 + int(f["sysnr"]) * 100          # 5<nn>00, the Java HTTP port
    if kind in ("abap", "rfc", "jco", "nco") and str(f.get("sysnr", "")).isdigit():
        return 3200 + int(f["sysnr"])                 # ABAP dispatcher
    if kind == "hana":
        # An explicit tenant port always wins. The fallback assumes the FIRST tenant
        # (3<nn>15); additional tenants get 3<nn>41, 3<nn>44 ... assigned at creation,
        # which no convention can derive -- see the note added in hana_auth_test.
        if str(f.get("tenant_port", "")).isdigit():
            return int(f["tenant_port"])
        inst = str(f.get("instance", "00"))
        return 30015 if inst == "00" else 30000 + int(inst) * 100 + 15
    if kind in ("ssh", "sftp"):
        return 22
    if kind == "sapgui" and str(f.get("sysnr", "")).isdigit():
        return 3200 + int(f["sysnr"])
    return 0


def icm_port(entry):
    """SAP ICM HTTP port. Explicit override wins, else the 80<nn> convention."""
    f = entry.get("fields") or {}
    if str(f.get("icmport", "")).isdigit():
        return int(f["icmport"]), f.get("icmscheme", "http")
    if str(f.get("sysnr", "")).isdigit():
        return 8000 + int(f["sysnr"]), "http"
    return 0, "http"


def tcp_test(host, port, notes):
    if not port:
        return {"ok": False, "kind": "none", "detail": "no port known for this entry", "notes": notes}
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=6):
            ms = int((time.time() - t0) * 1000)
        return {"ok": True, "kind": "tcp",
                "detail": f"TCP {host}:{port} open ({ms} ms) — reachability only, "
                          f"credentials NOT verified", "notes": notes}
    except Exception as exc:
        return {"ok": False, "kind": "tcp",
                "detail": f"TCP {host}:{port} — {type(exc).__name__}: {exc}", "notes": notes}


def ssh_key_test(entry, host, notes):
    """Key/agent auth via the system ssh binary. BatchMode=yes is deliberate here:
    it refuses to fall back to a password prompt, so a pass/fail is unambiguous."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ConnectTimeout=6"]
    if entry.get("via"):
        cmd += ["-J", entry["via"]]
    target = f"{entry.get('user')}@{host}" if entry.get("user") else host
    r = subprocess.run(cmd + [target, "true"], capture_output=True, timeout=25)
    return {"ok": r.returncode == 0, "kind": "ssh-auth (key)",
            "detail": "key auth succeeded — credentials VERIFIED" if r.returncode == 0
                      else (r.stderr.decode().strip().splitlines() or ["failed"])[-1][:160],
            "notes": notes}


def ssh_password_test(entry, host, notes):
    """Password auth via paramiko. The system ssh CLI cannot do this non-interactively
    without sshpass (not present on macOS by default), and BatchMode=yes -- correct
    for key-only bastions -- silently refuses to even ATTEMPT a stored password, which
    is the bug this fixes: it always reported failure for password-based entries
    without ever presenting the password."""
    try:
        import paramiko
    except ImportError:
        return {"ok": False, "kind": "unavailable",
                "detail": "password SSH test needs paramiko: pip install paramiko "
                          "(into the creds venv, ~/.cache/creds/venv)", "notes": notes}
    user, pw = entry.get("user") or "", entry.get("secret") or ""
    if not user or not pw:
        return {"ok": False, "kind": "ssh-auth (password)",
                "detail": "entry has no user and/or password", "notes": notes}

    sock = None
    jump = None
    try:
        if entry.get("via"):
            notes.append(f"tunnelling through {entry['via']} (its own credentials, not this password)")
            jump = paramiko.SSHClient()
            jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            jump.connect(entry["via"], timeout=10, banner_timeout=10, auth_timeout=10)
            transport = jump.get_transport()
            sock = transport.open_channel("direct-tcpip", (host, 22), ("127.0.0.1", 0))

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=22, username=user, password=pw, sock=sock,
                       timeout=10, banner_timeout=10, auth_timeout=10,
                       look_for_keys=False, allow_agent=False)
        client.close()
        return {"ok": True, "kind": "ssh-auth (password)",
                "detail": f"password auth SUCCEEDED as {user} — credentials VERIFIED", "notes": notes}
    except paramiko.AuthenticationException as exc:
        return {"ok": False, "kind": "ssh-auth (password)",
                "detail": f"authentication rejected — {exc}", "notes": notes}
    except Exception as exc:
        return {"ok": False, "kind": "ssh-auth (password)",
                "detail": f"{type(exc).__name__}: {exc}", "notes": notes}
    finally:
        if jump:
            jump.close()


def ssh_test(entry, host, notes):
    """Route to whichever auth the entry actually has. A stored password means the
    account is password-authenticated -- testing key auth against it proves nothing
    and used to report a false failure."""
    if entry.get("secret"):
        return ssh_password_test(entry, host, notes)
    return ssh_key_test(entry, host, notes)


def icm_auth_test(entry, host, notes):
    """Real credential check against the ABAP ICM: /sap/bc/ping with basic auth.

    Needs no SAP SDK, so it works where pyrfc cannot be installed. 200 = valid.
    403 also proves the logon worked (authenticated, just not authorised for ping).
    """
    port, scheme = icm_port(entry)
    if not port:
        return {"ok": False, "kind": "none",
                "detail": "no ICM port known — set fields.icmport (e.g. 8000) or fields.sysnr",
                "notes": notes}
    return http_basic(entry, host, port, scheme, "/sap/bc/ping", notes, "icm-auth")


def hana_auth_test(entry, host, notes):
    """HANA logon.

    Preferred route for a multi-tenant system is the SYSTEMDB nameserver on 3<nn>13
    with databaseName=<tenant>: the nameserver redirects to the tenant. That port is
    derivable from the instance number, whereas tenant SQL ports (3<nn>41, 3<nn>44 …)
    are assigned at tenant-creation time and cannot be computed. Falls back to a
    direct tenant port only when no tenant is named.
    """
    try:
        from hdbcli import dbapi
    except ImportError:
        return {"ok": False, "kind": "unavailable",
                "detail": "HANA logon test needs the SAP driver: pip3 install hdbcli",
                "notes": notes}
    f = entry.get("fields") or {}
    tenant = (f.get("tenant") or "").strip()
    inst = str(f.get("instance", "00"))
    kw, label, port = {}, "hana-auth", probe_port(entry)
    if tenant and inst.isdigit():
        port = 30000 + int(inst) * 100 + 13
        kw["databaseName"] = tenant
        label = "hana-auth (nameserver)"
        notes.append(f"via SYSTEMDB nameserver {port}, redirected to tenant {tenant}")
    try:
        c = dbapi.connect(address=host, port=port, user=entry.get("user"),
                          password=entry.get("secret"), connectTimeout=8000, **kw)
        cur = c.cursor()
        cur.execute("SELECT DATABASE_NAME, SYSTEM_ID, VERSION FROM M_DATABASE")
        db, sid, ver = cur.fetchone()
        c.close()
        return {"ok": True, "kind": label,
                "detail": f"SQL logon SUCCEEDED — tenant {db} on {sid}, HANA {ver} "
                          f"— credentials verified", "notes": notes}
    except Exception as exc:
        msg = str(exc).splitlines()[0][:180]
        if tenant and str(f.get("tenant_port", "")).isdigit():
            notes.append(f"nameserver route failed; a direct tenant port "
                         f"({f['tenant_port']}) is also recorded — not retried automatically")
        return {"ok": False, "kind": label, "detail": msg, "notes": notes}


def http_basic(entry, host, port, scheme, path, notes, label):
    """Basic-auth probe with a built-in control.

    A path can answer 403 (or 200) no matter what you send -- /sap/bc/ping does
    exactly that on some systems, which made an earlier version of this report
    "credentials verified" for passwords that were never checked. So every probe
    is repeated with a random password: if the status does not change, the
    endpoint cannot discriminate and the result is INCONCLUSIVE, not a pass.
    """
    import base64, secrets, ssl, urllib.error, urllib.request
    user, pw = entry.get("user") or "", entry.get("secret") or ""
    if not user or not pw:
        return {"ok": False, "kind": label, "detail": "entry has no user and/or password",
                "notes": notes}
    if len(pw) > 40 and entry.get("kind") in ("rfc", "jco", "nco", "sapgui", "odata"):
        notes.append(f"secret is {len(pw)} chars, longer than SAP's documented 40-char max "
                     f"(HEC/RISE technical users are often issued longer ones)")
    client = (entry.get("fields") or {}).get("client", "")
    sep = "&" if "?" in path else "?"
    url = f"{scheme}://{host}:{port}{path}" + (f"{sep}sap-client={client}" if client else "")
    ctx = ssl._create_unverified_context()
    if scheme == "https":
        notes.append("TLS certificate NOT verified for this probe")

    def status_for(password):
        req = urllib.request.Request(url)
        req.add_header("Authorization", "Basic " +
                       base64.b64encode(f"{user}:{password}".encode("utf-8")).decode())
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                return r.status, ""
        except urllib.error.HTTPError as exc:
            return exc.code, exc.reason
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    real, why = status_for(pw)
    if real is None:
        return {"ok": False, "kind": label, "detail": f"{why} ({url})", "notes": notes}

    control, _ = status_for("x" + secrets.token_urlsafe(24))
    if control == real:
        return {"ok": False, "kind": label + " (inconclusive)",
                "detail": f"HTTP {real} for BOTH the real password and a random one — "
                          f"{path} does not check credentials here, so this proves nothing. "
                          f"Use the rfc method instead.", "notes": notes}

    if real in (200, 403):
        return {"ok": True, "kind": label,
                "detail": f"HTTP {real} (random password gets {control}) — logon SUCCEEDED, "
                          f"credentials verified", "notes": notes}
    if real == 401:
        return {"ok": False, "kind": label,
                "detail": "HTTP 401 — SAP rejected this user/password/client", "notes": notes}
    return {"ok": False, "kind": label, "detail": f"HTTP {real} {why}", "notes": notes}


PROBE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RfcProbe.java")


def find_jco_lib():
    """~/Documents is TCC-protected, so existence is not readability -- test a real read."""
    here = os.path.dirname(os.path.abspath(__file__))
    for d in filter(None, [
            os.environ.get("CREDS_JCO_LIB"),
            os.path.join(here, "lib")]):   # JCo is licensed; see README
        try:
            with open(os.path.join(d, "sapjco3.jar"), "rb") as fh:
                fh.read(1)
            return d
        except OSError:
            continue
    return None


JCO_LIB = find_jco_lib() or ""


def rfc_logon_test(entry, host, notes, proto=None):
    """Real RFC logon via JCo. Parameters go through the environment, never argv,
    because argv is readable by every process on the box via `ps`.

    Gateway port: JCo derives sapgw<NN> = 33<NN> purely from SYSNR and has no way
    to override that on its own. When the real gateway is not on that port, an
    explicit override is required -- checked in this order:
      1. the logon-methods row's own port (an explicit, one-off override you typed)
      2. fields.gwserv (a persistent fact about this system)
    A mismatch here looks identical to a firewalled host (JCO_ERROR_COMMUNICATION),
    so this is worth getting right before assuming the network is at fault.
    """
    jar = os.path.join(JCO_LIB, "sapjco3.jar")
    if not os.path.exists(jar):
        return {"ok": False, "kind": "unavailable",
                "detail": f"sapjco3.jar not found under {JCO_LIB}. Set CREDS_JCO_LIB.",
                "notes": notes}
    f = entry.get("fields") or {}
    row_port = (proto or {}).get("port")
    gwserv = str(row_port) if row_port else str(f.get("gwserv", ""))
    default_gw = 3300 + int(f["sysnr"]) if str(f.get("sysnr", "")).isdigit() else None
    if gwserv and default_gw is not None and gwserv == str(default_gw):
        gwserv = ""       # matches the convention already -- no override needed
    if gwserv:
        notes.append(f"gateway override: dialing port {gwserv} directly"
                     + (" (from the logon-methods row)" if row_port else " (fields.gwserv)"))
    env = dict(os.environ)
    env.update({
        "RFC_HOST": host, "RFC_SYSNR": str(f.get("sysnr", "00")),
        "RFC_CLIENT": str(f.get("client", "")), "RFC_USER": entry.get("user") or "",
        "RFC_PASSWD": entry.get("secret") or "", "RFC_LANG": str(f.get("lang", "EN")),
        "RFC_ROUTER": str(f.get("router") or f.get("saprouter") or ""), "RFC_GWSERV": gwserv,
        "RFC_GWHOST": str(f.get("gwhost", "")),
    })
    if f.get("mode") == "group":                       # load-balanced destination
        env["RFC_MSHOST"] = host
        env["RFC_MSSERV"] = str(f.get("msport", ""))
        env["RFC_GROUP"] = str(f.get("group", ""))
        env["RFC_R3NAME"] = str(f.get("sid", ""))
        notes.append("logging on through the message server using the logon group")
    cmd = ["java", "--enable-native-access=ALL-UNNAMED", "-cp", jar,
           f"-Djava.library.path={JCO_LIB}", PROBE]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=60, env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "kind": "rfc", "detail": "JCo probe timed out (60s)", "notes": notes}
    out = (r.stdout or b"").decode().strip().splitlines()
    line = next((l for l in reversed(out) if l.startswith("{")), "")
    if not line:
        err = (r.stderr or b"").decode().strip().splitlines()
        return {"ok": False, "kind": "rfc",
                "detail": "JCo probe produced no result: " + (err[-1][:200] if err else "no output"),
                "notes": notes}
    try:
        res = json.loads(line)
    except json.JSONDecodeError:
        return {"ok": False, "kind": "rfc", "detail": line[:200], "notes": notes}
    key = res.get("key") or ""
    if "LOGON_FAILURE" in key:
        notes.append("the host answered and RFC negotiated — this is a CREDENTIALS failure, "
                     "not a network one")
    elif "COMMUNICATION" in key:
        notes.append("never got far enough to check credentials — gateway/host unreachable. "
                     "Test the disp and gateway ports first")
    return {"ok": bool(res.get("ok")), "kind": "rfc",
            "detail": (res.get("detail", "") or "")[:400], "notes": notes}


def api_test(entry, proto, notes):
    """Verify an API credential. Vendor-agnostic: the entry's own fields say where
    to call and how to present the secret, so a new vendor is data, not code.

      fields.base_url       https://api.example.com/v1
      fields.verify_path    /user/tokens/verify        (cheapest authenticated GET)
      fields.auth_style     bearer | header | basic | query | oauth2 | oauth2-body
      fields.token_url      OAuth2 token endpoint, for auth_style=oauth2
                            (the service key's uaa.url; /oauth/token is appended
                            when you paste the bare url)
      fields.auth_header    header name for auth_style=header   (e.g. x-api-key)
      fields.auth_param     query name for auth_style=query
      fields.extra_headers  "anthropic-version: 2023-06-01; accept: application/json"

    Like http_basic, every probe is repeated with a random secret: if the endpoint
    answers the same either way it proves nothing and is reported INCONCLUSIVE.
    """
    import secrets as _s, ssl, urllib.error, urllib.parse, urllib.request
    f = entry.get("fields") or {}
    key = entry.get("secret") or ""
    if not key:
        return {"ok": False, "kind": "api", "detail": "entry has no secret to verify",
                "notes": notes}
    base = (proto.get("base_url") or f.get("base_url") or "").rstrip("/")
    if not base:
        return {"ok": False, "kind": "api",
                "detail": "set fields.base_url (e.g. https://api.example.com/v1)", "notes": notes}
    path = proto.get("path") or f.get("verify_path") or ""
    if not path:
        return {"ok": False, "kind": "api",
                "detail": "set fields.verify_path — the cheapest authenticated GET this API offers",
                "notes": notes}
    style = (f.get("auth_style") or "bearer").lower()
    url = base + ("" if path.startswith("/") else "/") + path

    def build(secret):
        u, headers = url, {}
        for pair in (f.get("extra_headers") or "").split(";"):
            if ":" in pair:
                k, _, v = pair.partition(":")
                headers[k.strip()] = v.strip()
        if style == "bearer":
            headers["Authorization"] = "Bearer " + secret
        elif style == "header":
            headers[f.get("auth_header") or "x-api-key"] = secret
        elif style == "basic":
            import base64
            headers["Authorization"] = "Basic " + base64.b64encode(
                f"{entry.get('user') or ''}:{secret}".encode()).decode()
        elif style == "query":
            sep = "&" if "?" in u else "?"
            u = f"{u}{sep}{urllib.parse.quote(f.get('auth_param') or 'key')}={urllib.parse.quote(secret)}"
        else:
            return None, None
        return u, headers

    ctx = ssl.create_default_context()

    def oauth2_status(secret):
        """Client-credentials grant, then one authenticated GET.

        The token endpoint is the real credential check: a wrong client secret is
        rejected there with a clean 401, before the API is touched at all. So a
        failure to get a token IS the verdict, and is returned as such.
        """
        turl = (proto.get("token_url") or f.get("token_url") or "").rstrip("/")
        if not turl:
            return None, ("set fields.token_url — the OAuth2 token endpoint "
                          "(a BTP service key's uaa.url)")
        # Only complete a BARE origin. /oauth/token is XSUAA's path; SAP Cloud Identity
        # Services uses /oauth2/token, and other vendors differ again -- so an explicit
        # path is authoritative. Appending blindly turned a correct
        # ".../oauth2/token" into ".../oauth2/token/oauth/token".
        if not urllib.parse.urlsplit(turl).path.strip("/"):
            if style == "oauth2-body":
                return None, ("Azure/body-auth needs the full token_url (…/oauth2/token "
                              "or …/oauth2/v2.0/token); a bare origin is ambiguous")
            turl = turl.rstrip("/") + "/oauth/token"
        import base64
        cid = entry.get("user") or ""
        if not cid:
            return None, "set the entry's user to the OAuth2 client id"
        # Three vendor dialects of the same grant. The difference is entirely in this
        # one POST: XSUAA/IAS take the client id+secret as HTTP Basic; Azure AD (Entra)
        # wants them in the FORM BODY, plus resource= on the v1.0 endpoint or scope=
        # on v2.0. `oauth2` = Basic (the SAP default); `oauth2-body` = body creds.
        form = {"grant_type": "client_credentials"}
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json"}
        if style == "oauth2-body":
            form["client_id"] = cid
            form["client_secret"] = secret
            # v1.0 wants resource=, v2.0 wants scope= and REJECTS resource. The token
            # URL says which endpoint this is, so send exactly the one that belongs --
            # never both, even when the entry records both for reference.
            is_v2 = "/v2.0/" in turl
            if is_v2 and f.get("scope"):
                form["scope"] = f["scope"]
            elif not is_v2 and f.get("resource"):
                form["resource"] = f["resource"]
            elif f.get("scope"):         # fallback: only a scope was given
                form["scope"] = f["scope"]
        else:
            headers["Authorization"] = "Basic " + base64.b64encode(
                f"{cid}:{secret}".encode()).decode()
        req = urllib.request.Request(
            turl, method="POST",
            data=urllib.parse.urlencode(form).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                token = json.loads(r.read().decode("utf-8", "replace")).get("access_token")
        except urllib.error.HTTPError as exc:
            return exc.code, f"token endpoint: {exc.reason}"
        except Exception as exc:
            return None, f"token endpoint: {type(exc).__name__}: {exc}"
        if not token:
            return None, "token endpoint returned no access_token"

        areq = urllib.request.Request(url, method="GET")
        areq.add_header("Authorization", "Bearer " + token)
        areq.add_header("Accept", "application/json")
        for pair in (f.get("extra_headers") or "").split(";"):
            if ":" in pair:
                k, _, v = pair.partition(":")
                areq.add_header(k.strip(), v.strip())
        try:
            with urllib.request.urlopen(areq, timeout=15, context=ctx) as r:
                return r.status, "token issued"
        except urllib.error.HTTPError as exc:
            return exc.code, f"token issued, but {url} said {exc.reason}"
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def status_for(secret):
        if style in ("oauth2", "oauth2-body"):
            return oauth2_status(secret)
        u, headers = build(secret)
        if u is None:
            return None, f"unknown auth_style '{style}' (bearer|header|basic|query|oauth2|oauth2-body)"
        req = urllib.request.Request(u, method="GET")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=12, context=ctx) as r:
                return r.status, ""
        except urllib.error.HTTPError as exc:
            return exc.code, exc.reason
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    real, why = status_for(key)
    if real is None:
        return {"ok": False, "kind": "api", "detail": f"{why} ({url})", "notes": notes}
    control, _ = status_for("x" + _s.token_urlsafe(24))
    if control == real:
        return {"ok": False, "kind": "api (inconclusive)",
                "detail": f"HTTP {real} for BOTH the real secret and a random one — "
                          f"{path} does not check credentials, so this proves nothing. "
                          f"Point fields.verify_path at an authenticated endpoint.",
                "notes": notes}
    if 200 <= real < 300:
        return {"ok": True, "kind": "api",
                "detail": f"HTTP {real} (random secret gets {control}) — "
                          f"{'client credentials ACCEPTED' if style == 'oauth2' else 'key ACCEPTED'}"
                          f" by {base}" + (f"; {why}" if why else ""),
                "notes": notes}
    if real in (401, 403):
        return {"ok": False, "kind": "api",
                "detail": f"HTTP {real} {why} — the API rejected this key", "notes": notes}
    return {"ok": False, "kind": "api", "detail": f"HTTP {real} {why}", "notes": notes}


def bo_test(entry, proto, notes):
    """SAP BusinessObjects RESTful logon.

    BO does not accept a bearer token: you POST userName/password/auth to
    /biprws/logon/long and it returns an X-SAP-LogonToken. Auth type matters --
    secEnterprise, secLDAP, secWinAD and secSAPR3 are different user stores, and
    the same name may exist in one but not another.

    The control here uses a RANDOM USERNAME rather than a wrong password for the
    real user: BO accounts backed by AD or SAP can lock on repeated failures, and
    a bogus name cannot lock anything that exists.
    """
    import secrets as _s, ssl, urllib.error, urllib.request
    f = entry.get("fields") or {}
    user, pw = entry.get("user") or "", entry.get("secret") or ""
    if not user or not pw:
        return {"ok": False, "kind": "bo", "detail": "entry has no user and/or password",
                "notes": notes}
    base = (proto.get("base_url") or f.get("base_url") or "").rstrip("/")
    if not base:
        return {"ok": False, "kind": "bo",
                "detail": "set fields.base_url (e.g. https://bodev.example.com:8443)", "notes": notes}
    auth = f.get("auth_type") or "secEnterprise"
    if not f.get("auth_type"):
        notes.append("fields.auth_type not set - assuming secEnterprise; "
                     "for an SAP or AD account use secSAPR3 / secWinAD")
    url = base + (proto.get("path") or f.get("verify_path") or "/biprws/logon/long")
    ctx = ssl._create_unverified_context()
    notes.append("TLS certificate NOT verified for this probe")

    def logon(u, p):
        body = ('<attrs xmlns="http://www.sap.com/rws/bip">'
                f'<attr name="userName" type="string">{u}</attr>'
                f'<attr name="password" type="string">{p}</attr>'
                f'<attr name="auth" type="string">{auth}</attr></attrs>').encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/xml")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                return r.status, r.headers.get("X-SAP-LogonToken", "") != "", ""
        except urllib.error.HTTPError as exc:
            return exc.code, False, exc.reason
        except Exception as exc:
            return None, False, f"{type(exc).__name__}: {exc}"

    status, got_token, why = logon(user, pw)
    if status is None:
        return {"ok": False, "kind": "bo", "detail": f"{why} ({url})", "notes": notes}
    if 200 <= status < 300:
        ctl, _, _ = logon("zz" + _s.token_hex(6), _s.token_urlsafe(12))
        if ctl == status:
            return {"ok": False, "kind": "bo (inconclusive)",
                    "detail": f"HTTP {status} for a random username too - this endpoint is not "
                              f"checking credentials", "notes": notes}
        notes.append(f"control: a random username gets HTTP {ctl}")
        return {"ok": True, "kind": "bo",
                "detail": f"HTTP {status} - BO logon SUCCEEDED as {user} ({auth})"
                          + (", logon token issued" if got_token else ""), "notes": notes}
    if status in (401, 403):
        return {"ok": False, "kind": "bo",
                "detail": f"HTTP {status} {why} - BO rejected this user/password under {auth}",
                "notes": notes}
    return {"ok": False, "kind": "bo", "detail": f"HTTP {status} {why}", "notes": notes}


def rdp_test(entry, host, notes):
    """Windows RDP logon via xfreerdp +auth-only (no session, no window, no X server
    needed for this mode -- confirmed by direct testing, see the log line 'Don't
    connect to X.').

    IMPORTANT, verified empirically against a real unreachable host before trusting
    it: xfreerdp's own exit code is NOT reliable for +auth-only -- it printed
    "exit status 0" on a hard connection failure. The verdict has to come from the
    ERRCONNECT_* token in the log text, confirmed present in the installed
    libfreerdp3.dylib via `strings`, not from exit code or from memory of the API.

    No random-secret control (unlike the HTTP/API probes): a Windows/AD account can
    lock after N failures, so this makes exactly one attempt and stops. Any log
    output this does not recognise is reported ambiguous, never a false pass.
    """
    import shutil as _sh
    if not _sh.which("xfreerdp"):
        return {"ok": False, "kind": "unavailable",
                "detail": "RDP logon test needs FreeRDP: brew install freerdp", "notes": notes}
    user, pw = entry.get("user") or "", entry.get("secret") or ""
    if not user or not pw:
        return {"ok": False, "kind": "rdp", "detail": "entry has no user and/or password",
                "notes": notes}
    f = entry.get("fields") or {}
    port = entry.get("port") or 3389
    notes.append("TLS certificate NOT verified for this probe (/cert:ignore) — "
                 "self-signed RDP certs are the norm")

    ACCOUNT = {
        "ERRCONNECT_LOGON_FAILURE": "wrong username or password",
        "ERRCONNECT_AUTHENTICATION_FAILED": "authentication rejected",
        "ERRCONNECT_LOGON_TYPE_NOT_GRANTED": "this user is not allowed to log on this way "
            "(check 'Allow log on through Remote Desktop Services')",
        "ERRCONNECT_ACCOUNT_LOCKED_OUT": "account is LOCKED OUT",
        "ERRCONNECT_ACCOUNT_DISABLED": "account is disabled",
        "ERRCONNECT_ACCOUNT_EXPIRED": "account has expired",
        "ERRCONNECT_ACCOUNT_RESTRICTION": "blocked by an account restriction (logon hours, "
            "workstation restriction, etc.)",
        "ERRCONNECT_PASSWORD_EXPIRED": "password has expired",
        "ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED": "password has certainly expired",
        "ERRCONNECT_PASSWORD_MUST_CHANGE": "password must be changed at next logon",
    }
    NETWORK = {
        "ERRCONNECT_CONNECT_FAILED": "TCP connect failed",
        "ERRCONNECT_CONNECT_TRANSPORT_FAILED": "transport layer failed",
        "ERRCONNECT_TLS_CONNECT_FAILED": "TLS handshake failed",
        "ERRCONNECT_DNS_NAME_NOT_FOUND": "DNS lookup failed",
    }

    # Password goes through /args-from:env:<name>, never argv -- confirmed by
    # testing that the plain /p:<password> form is fully visible to any local
    # process via `ps`, exactly what every other probe in this file avoids.
    args = [f"/v:{host}:{port}", f"/u:{user}", f"/p:{pw}", "/cert:ignore",
            "+auth-only", "/log-level:INFO"]
    if f.get("domain"):
        args.append(f"/d:{f['domain']}")
    env = dict(os.environ)
    env["CREDS_XFREERDP_ARGS"] = "\n".join(args)
    try:
        r = subprocess.run(["xfreerdp", "/args-from:env:CREDS_XFREERDP_ARGS"],
                           capture_output=True, timeout=25, text=True,
                           errors="replace", env=env)
    except subprocess.TimeoutExpired:
        return {"ok": False, "kind": "rdp", "detail": "xfreerdp timed out (25s)", "notes": notes}

    out = (r.stdout or "") + (r.stderr or "")
    for token, why in ACCOUNT.items():
        if token in out:
            return {"ok": False, "kind": "rdp", "detail": f"{token} — {why}", "notes": notes}
    for token, why in NETWORK.items():
        if token in out:
            return {"ok": False, "kind": "rdp",
                    "detail": f"{token} — {why} (network layer, not credentials)", "notes": notes}
    # ERRCONNECT_CONNECT_CANCELLED is +auth-only's OWN way of stopping once auth
    # succeeds: it deliberately aborts right before opening a real session, at
    # CONNECTION_STATE_CAPABILITIES_EXCHANGE_DEMAND_ACTIVE. Confirmed against a
    # real captured trace: NLA completed (NLA_STATE_FINAL), no LOGON_FAILURE
    # anywhere, then MCS/Licensing/Multitransport all proceeded normally before
    # the cancel fired at the capabilities-exchange boundary. If NLA never
    # reaches NLA_STATE_FINAL, the SAME token means the opposite -- cancelled
    # before authentication ever completed -- so both are checked before trusting it.
    if "ERRCONNECT_CONNECT_CANCELLED" in out and "NLA_STATE_FINAL" in out \
            and not any(t in out for t in ACCOUNT):
        return {"ok": True, "kind": "rdp",
                "detail": f"NLA/CredSSP completed (NLA_STATE_FINAL) and the handshake "
                          f"proceeded through Licensing/Multitransport before auth-only's "
                          f"designed stop at capabilities exchange — logon SUCCEEDED as {user}",
                "notes": notes}
    if "ERRCONNECT_" in out or "ERRINFO_" in out:
        stray = next((ln for ln in out.splitlines() if "ERRCONNECT_" in ln or "ERRINFO_" in ln), "")
        return {"ok": False, "kind": "rdp (ambiguous)",
                "detail": f"unrecognised FreeRDP error, not assuming pass or fail: "
                          f"{stray.strip()[:160]}", "notes": notes}
    return {"ok": True, "kind": "rdp",
            "detail": f"no ERRCONNECT_ error in the log — auth-only logon SUCCEEDED as {user} "
                      f"(inferred from absence of error, xfreerdp's own exit code is not reliable "
                      f"here)", "notes": notes}


def with_login(entry, sel=None):
    """Flatten the chosen login onto a COPY of the entry.

    An `abap` entry keeps its accounts in logins[]; every probe below reads the flat
    entry["user"]/["secret"] and fields["client"]. Resolving once here means no probe
    needs to know logins[] exists. Mirrors pick_login() in the `creds` script:
    filter by user/client, prefer the one marked default, else take the first.
    An entry with no logins[] is returned unchanged.
    """
    logins = entry.get("logins") or []
    if not logins:
        return entry
    sel = sel or {}
    want_u, want_c = sel.get("user"), sel.get("client")
    match = [l for l in logins
             if (not want_u or l.get("user") == want_u)
             and (not want_c or str(l.get("client") or "") == str(want_c))]
    if not match:
        return entry
    chosen = next((l for l in match if l.get("default")), match[0])
    out = dict(entry)
    out["user"] = chosen.get("user") or ""
    out["secret"] = chosen.get("secret") or ""
    out["fields"] = {**(entry.get("fields") or {}),
                     "client": str(chosen.get("client") or "")}
    return out


def vmware_test(entry, proto, notes):
    """VMware vCenter logon via the vSphere REST session endpoint.

    POST /api/session with HTTP Basic returns 201 and a session token; 401 means the
    credentials were rejected. /rest/com/vmware/cis/session is the 6.5/6.7 path, tried
    as a fallback so one entry covers both generations.

    The control uses a RANDOM USERNAME, not a wrong password for the real account.
    vCenter SSO locks an account after a few consecutive failures (default 5), and
    Administrator@vsphere.local is precisely the account you cannot afford to lock --
    same reasoning as the BusinessObjects probe.

    TLS is verified by default. A vCenter with the factory self-signed certificate will
    fail here, and that is reported as a certificate problem with the opt-out named,
    rather than silently trusting whatever answers on 443.
    """
    import base64, secrets as _s, ssl, urllib.error, urllib.request
    f = entry.get("fields") or {}
    host = proto.get("host") or entry.get("host") or ""
    port = proto.get("port") or entry.get("port") or 443
    user = entry.get("user") or ""
    pw = entry.get("secret") or ""
    if not user or not pw:
        return {"ok": False, "kind": "vmware",
                "detail": "entry needs both a user (e.g. Administrator@vsphere.local) "
                          "and a password", "notes": notes}

    verify = str(f.get("verify_tls", "true")).strip().lower() not in ("false", "0", "no")
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        notes.append("TLS verification disabled by fields.verify_tls=false")

    paths = [proto.get("path") or f.get("verify_path") or "/api/session",
             "/rest/com/vmware/cis/session"]

    def attempt(u, p, path):
        url = f"https://{host}:{port}{path}"
        req = urllib.request.Request(url, method="POST", data=b"")
        req.add_header("Authorization", "Basic " + base64.b64encode(
            f"{u}:{p}".encode()).decode())
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                return r.status, ""
        except urllib.error.HTTPError as exc:
            return exc.code, exc.reason
        except ssl.SSLCertVerificationError as exc:
            return None, (f"TLS certificate rejected ({exc.verify_message or exc}). "
                          f"vCenter ships a self-signed certificate — set "
                          f"fields.verify_tls=false to accept it deliberately.")
        except Exception as exc:
            return None, f"{type(exc).__name__}: {exc}"

    real, why, used = None, "", ""
    for path in paths:
        real, why = attempt(user, pw, path)
        used = path
        if real is not None and real != 404:
            break
    if real is None:
        return {"ok": False, "kind": "vmware", "detail": f"{why} ({host}:{port})",
                "notes": notes}

    ctl, _ = attempt("zz" + _s.token_hex(6) + "@vsphere.local", _s.token_urlsafe(12), used)
    notes.append("control used a random USERNAME, not a wrong password — vCenter SSO "
                 "locks accounts after repeated failures")
    if ctl == real:
        return {"ok": False, "kind": "vmware (inconclusive)",
                "detail": f"HTTP {real} for both the real user and a random one at "
                          f"{used} — this endpoint is not discriminating, so the "
                          f"result proves nothing", "notes": notes}
    if 200 <= real < 300:
        return {"ok": True, "kind": "vmware",
                "detail": f"HTTP {real} at {used} — session issued, credentials "
                          f"VERIFIED for {user} (random user gets {ctl})", "notes": notes}
    if real in (401, 403):
        return {"ok": False, "kind": "vmware",
                "detail": f"HTTP {real} {why} — vCenter rejected these credentials",
                "notes": notes}
    return {"ok": False, "kind": "vmware", "detail": f"HTTP {real} {why} at {used}",
            "notes": notes}


def test_protocol(entry, proto):
    """Test ONE declared logon method. Each result says what it actually proved."""
    t = (proto or {}).get("type", "tcp")
    host = proto.get("host") or entry.get("host") or ""
    f = entry.get("fields") or {}
    notes = []
    if not host:
        return {"ok": False, "kind": t, "detail": "entry has no host"}
    if entry.get("via"):
        notes.append(f"reached via {entry['via']}; only ssh/sftp traverse it")
    if entry.get("requires"):
        notes.append("requires: " + ", ".join(entry["requires"]))

    def port_or(default):
        p = proto.get("port")
        return int(p) if str(p).isdigit() else default

    sysnr = int(f["sysnr"]) if str(f.get("sysnr", "")).isdigit() else None

    # The three ports every ABAP stack exposes, derived from the instance number.
    if t == "disp":
        if sysnr is None and not proto.get("port"):
            return {"ok": False, "kind": t, "detail": "needs fields.sysnr or an explicit port",
                    "notes": notes}
        return tcp_test(host, port_or(3200 + (sysnr or 0)), notes)
    if t == "gateway":
        if sysnr is None and not proto.get("port"):
            return {"ok": False, "kind": t, "detail": "needs fields.sysnr or an explicit port",
                    "notes": notes}
        return tcp_test(host, port_or(3300 + (sysnr or 0)), notes)
    if t == "msgserver":
        default = int(f["msport"]) if str(f.get("msport", "")).isdigit() else (
            3600 + sysnr if sysnr is not None else 0)
        if not default and not proto.get("port"):
            return {"ok": False, "kind": t,
                    "detail": "needs fields.msport, fields.sysnr, or an explicit port",
                    "notes": notes}
        # On a distributed system the message server runs on the ASCS/CI host, not
        # on this app server -- a refusal here is normal, not a fault.
        res = tcp_test(proto.get("host") or f.get("mshost") or host, port_or(default), notes)
        if not res.get("ok") and not (proto.get("host") or f.get("mshost")):
            res.setdefault("notes", []).append(
                "message server is usually on the ASCS/CI host, not this app server — "
                "set fields.mshost (or the row's host) if this is a distributed system")
        return res
    if t == "tcp":
        return tcp_test(host, port_or(probe_port(entry)), notes)
    if t in ("java-http", "java-https"):
        nn = sysnr if sysnr is not None else 0
        default = (50000 if t == "java-http" else 50001) + nn * 100
        return http_basic(entry, host, port_or(default),
                          "http" if t == "java-http" else "https",
                          proto.get("path") or f.get("verify_path") or "/nwa", notes, t)
    if t == "p4":
        nn = sysnr if sysnr is not None else 0
        return tcp_test(host, port_or(50004 + nn * 100), notes)
    if t == "icm-http":
        return http_basic(entry, host, port_or(8000 + sysnr if sysnr is not None else 0),
                          "http", proto.get("path") or "/sap/bc/ping", notes, "icm-http")
    if t == "icm-https":
        return http_basic(entry, host, port_or(44300 + sysnr if sysnr is not None else 0),
                          "https", proto.get("path") or "/sap/bc/ping", notes, "icm-https")
    if t == "odata":
        return http_basic(entry, host, port_or(44300 + sysnr if sysnr is not None else 443),
                          proto.get("scheme") or "https",
                          proto.get("path") or "/sap/opu/odata/sap/", notes, "odata")
    if t == "api":
        return api_test(entry, proto, notes)
    if t == "vmware":
        return vmware_test(entry, proto, notes)
    if t == "rdp":
        return rdp_test(entry, host, notes)
    if t == "bo":
        return bo_test(entry, proto, notes)
    if t in ("ssh", "sftp"):
        return ssh_test(entry, host, notes)
    if t == "hana":
        return hana_auth_test(entry, host, notes)
    if t == "rfc":
        return rfc_logon_test(entry, host, notes, proto)
    return {"ok": False, "kind": t, "detail": f"unknown protocol '{t}'", "notes": notes}


def test_entry(entry, mode="reach"):
    """mode 'reach' = TCP only. mode 'auth' = real logon where that is possible.

    Every result states plainly whether credentials were actually verified.
    """
    host = entry.get("host", "")
    kind = entry.get("kind", "")
    notes = []
    if not host:
        return {"ok": False, "kind": "none", "detail": "entry has no host"}
    if (entry.get("fields") or {}).get("mode") == "group":
        notes.append("load-balanced entry: testing the message server, not an app server")
    if entry.get("via"):
        notes.append(f"reached via {entry['via']}; this probe does NOT traverse the bastion")
    if entry.get("requires"):
        notes.append("requires: " + ", ".join(entry["requires"]))

    if mode != "auth":
        return tcp_test(host, probe_port(entry), notes)

    if kind in ("ssh", "sftp"):
        return ssh_test(entry, host, notes)
    if kind == "hana":
        return hana_auth_test(entry, host, notes)
    if kind in ("abap", "rfc", "jco", "nco"):
        return rfc_logon_test(entry, host, notes)
    if kind == "vmware":
        return vmware_test(entry, {"port": entry.get("port") or 443}, notes)
    if kind == "java":
        f = entry.get("fields") or {}
        nn = int(f["sysnr"]) if str(f.get("sysnr", "")).isdigit() else 0
        return http_basic(entry, host, 50000 + nn * 100, "http",
                          f.get("verify_path") or "/nwa", notes, "java-auth")
    if kind in ("sapgui", "odata"):
        return icm_auth_test(entry, host, notes)
    notes.append(f"no logon test implemented for kind '{kind}' — fell back to reachability")
    return tcp_test(host, probe_port(entry), notes)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _auth(self):
        global last_seen
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        tok = self.headers.get("X-Creds-Token") or (q.get("t") or [""])[0]
        if not secrets.compare_digest(tok, TOKEN):
            self._send(403, {"error": "bad or missing token"})
            return False
        last_seen = time.time()
        return True

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "script-src 'unsafe-inline'; connect-src 'self'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/index.html"):
            if not self._auth():
                return
            with open(HTML, "rb") as fh:
                page = fh.read().replace(b"__TOKEN__", TOKEN.encode())
            return self._send(200, page, "text/html; charset=utf-8")
        if path == "/landscape":
            if not self._auth():
                return
            with open(LANDSCAPE, "rb") as fh:
                page = fh.read().replace(b"__TOKEN__", TOKEN.encode())
            return self._send(200, page, "text/html; charset=utf-8")
        if path == "/api/index":
            if not self._auth():
                return
            try:
                return self._send(200, decrypt())
            except Exception as exc:
                return self._send(500, {"error": str(exc)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError as exc:
            return self._send(400, {"error": f"bad JSON: {exc}"})

        if path == "/api/index":
            if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
                return self._send(400, {"error": "expected {version, entries: []}"})
            ids = [e.get("id") for e in payload["entries"]]
            if any(not i for i in ids):
                return self._send(400, {"error": "every entry needs a non-empty id"})
            dup = {i for i in ids if ids.count(i) > 1}
            if dup:
                return self._send(400, {"error": "duplicate ids: " + ", ".join(sorted(dup))})
            try:
                encrypt(payload)
                return self._send(200, {"ok": True, "count": len(payload["entries"])})
            except Exception as exc:
                return self._send(500, {"error": str(exc)})

        if path == "/api/test":
            try:
                ent = with_login(payload.get("entry") or payload, payload.get("login"))
                if payload.get("protocol"):
                    return self._send(200, test_protocol(ent, payload["protocol"]))
                return self._send(200, test_entry(ent, payload.get("mode", "reach")))
            except subprocess.TimeoutExpired:
                return self._send(200, {"ok": False, "kind": "timeout", "detail": "timed out"})
            except Exception as exc:
                return self._send(200, {"ok": False, "kind": "error", "detail": str(exc)})

        if path == "/api/quit":
            threading.Timer(0.3, lambda: os._exit(0)).start()
            return self._send(200, {"ok": True})

        self._send(404, {"error": "not found"})


def reaper():
    while True:
        time.sleep(30)
        if time.time() - last_seen > IDLE_TIMEOUT:
            os._exit(0)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{srv.server_port}/?t={TOKEN}"
    threading.Thread(target=reaper, daemon=True).start()
    print(f"creds ui -> {url}")
    print(f"(127.0.0.1 only, token-gated, exits after {IDLE_TIMEOUT // 60} min idle)")
    sys.stdout.flush()
    if os.environ.get("CREDS_UI_NO_OPEN") != "1":
        subprocess.run(["open", url], check=False)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
