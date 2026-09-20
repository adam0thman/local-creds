#!/usr/bin/env python3
"""Log a browser into a system from the index, without the password passing through
anything that records it.

Run through `creds browser <id>`, which is `creds exec` underneath: the password
arrives in this process's environment and goes straight into the page. It is never an
argument (argv is world-readable via ps), never printed, and never returned to the
caller -- so an agent can drive this and still never see the secret.

Its own profile, and not yours. Chromium runs against a context that exists only in
memory: no cookie jar on disk, no history, no saved passwords, and none of your real
sessions. If a script misnavigates it is not logged in as you anywhere. On close the
cookies and web storage are cleared explicitly as well -- belt and braces, because
"nothing was persisted" is a claim worth making true twice.

ONE ATTEMPT. Many accounts lock after three failures and some SAP systems after
three; there is deliberately no retry loop here. A failed logon is reported, not
re-tried. See AGENTS.md section 2.3.

Field detection is extension/fill.js -- the same code the browser extension uses, so
there is one implementation and one set of unit tests for both.
"""
import argparse
import json
import os
import pathlib
import sys
import urllib.parse

HERE = pathlib.Path(__file__).resolve().parent
FILL_JS = HERE / "extension" / "fill.js"

INSTALL = """playwright is not installed. It is optional and heavyweight, so creds
does not pull it in for you:

    python3 -m venv ~/.cache/creds/venv       # if you have not already
    ~/.cache/creds/venv/bin/pip install playwright
    ~/.cache/creds/venv/bin/playwright install chromium
"""


def origin_of(url):
    """(scheme, host, port) -- the same comparison creds-nm makes. Path is ignored."""
    if not url:
        return None
    s = urllib.parse.urlsplit(url.strip() if "//" in url else "//" + url.strip())
    if not s.scheme or not s.hostname or s.scheme not in ("http", "https"):
        return None
    try:
        port = s.port
    except ValueError:
        return None
    return (s.scheme.lower(), s.hostname.lower(), port or (443 if s.scheme == "https" else 80))


def target_url(args):
    """Where to go: the argument, else the entry's url, else build one from host."""
    if args.url:
        return args.url
    url = os.environ.get("CREDS_URL")
    if url:
        return url
    host = os.environ.get("CREDS_HOST")
    port = os.environ.get("CREDS_PORT")
    if not host:
        return None
    return f"http://{host}:{port}" if port else f"https://{host}"


_submitted = False


def submit_once(page):
    """Press Enter to log on -- at most once per run.

    Many accounts lock after three failed logons, some SAP systems after three. A
    retry loop added here later would lock a real admin account, so this refuses
    loudly instead of trusting that nobody ever wraps it in a `for`.
    """
    global _submitted
    if _submitted:
        raise RuntimeError("refusing a second logon attempt in one run "
                           "(repeated failures lock accounts)")
    _submitted = True
    page.keyboard.press("Enter")


def selftest():
    """Pure logic, checkable without playwright or a network."""
    assert origin_of("https://a.example.com/x/y") == ("https", "a.example.com", 443)
    assert origin_of("http://10.0.0.1:50000/dir") == ("http", "10.0.0.1", 50000)
    # Default ports are normalised, so https://h and https://h:443 are one origin.
    assert origin_of("https://h") == origin_of("https://h:443")
    assert origin_of("ssh://h") is None, "only http(s) is fillable"
    assert origin_of("h:notaport") is None
    assert origin_of("") is None and origin_of(None) is None
    # A lookalike is a different origin, exactly as in creds-nm.
    assert origin_of("https://sap.example.com") != origin_of("https://sap.example.com.evil.io")

    class A:
        url = None
    os.environ.pop("CREDS_URL", None)
    os.environ["CREDS_HOST"] = "h.example.com"
    os.environ.pop("CREDS_PORT", None)
    assert target_url(A) == "https://h.example.com"
    os.environ["CREDS_PORT"] = "50000"
    assert target_url(A) == "http://h.example.com:50000"
    os.environ["CREDS_URL"] = "https://explicit.example.com/login"
    assert target_url(A) == "https://explicit.example.com/login", "fields.url wins over host"
    A.url = "https://argument.example.com"
    assert target_url(A) == "https://argument.example.com", "an argument wins over both"
    for k in ("CREDS_URL", "CREDS_HOST", "CREDS_PORT"):
        os.environ.pop(k, None)
    # A second logon attempt must be refused, however it is reached.
    class _KB:
        def __init__(self): self.n = 0
        def press(self, _): self.n += 1

    class _P:
        def __init__(self): self.keyboard = _KB()

    global _submitted
    _submitted = False
    page = _P()
    submit_once(page)
    assert page.keyboard.n == 1
    for _ in range(2):                      # exactly what a retry loop would do
        try:
            submit_once(page)
            raise AssertionError("a second logon attempt must raise")
        except RuntimeError:
            pass
    assert page.keyboard.n == 1, "no second key press may reach the page"
    _submitted = False

    print("  browser.py: selftest passed")
    return 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    ap = argparse.ArgumentParser(prog="creds browser", add_help=True)
    ap.add_argument("url", nargs="?", help="override the entry's url")
    ap.add_argument("--headless", action="store_true", help="no window (automation)")
    ap.add_argument("--no-submit", action="store_true",
                    help="fill the form but do not log on")
    ap.add_argument("--allow-redirect", action="store_true",
                    help="permit filling after a cross-origin redirect (SAML/IdP)")
    ap.add_argument("--shot", metavar="PATH", help="save a screenshot of the result")
    ap.add_argument("--keep-open", action="store_true",
                    help="leave the window up until Enter is pressed")
    args = ap.parse_args(argv[1:])

    secret = os.environ.get("CREDS_PASSWORD")
    user = os.environ.get("CREDS_USER") or ""
    ident = os.environ.get("CREDS_ID") or "?"
    if not secret:
        print("creds browser: no password on this entry", file=sys.stderr)
        return 2

    url = target_url(args)
    if not url:
        print("creds browser: entry has no url and no host -- add fields.url",
              file=sys.stderr)
        return 2
    expect = origin_of(url)
    if not expect:
        print(f"creds browser: {url!r} is not an http(s) url", file=sys.stderr)
        return 2
    expect_origin = f"{expect[0]}://{expect[1]}" + (
        "" if expect[2] in (80, 443) else f":{expect[2]}")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print(INSTALL, file=sys.stderr)
        return 3

    print(f"creds browser: {ident} -> {url}", file=sys.stderr)
    if os.environ.get("CREDS_ENV") == "prd":
        print("creds browser: PRODUCTION system", file=sys.stderr)

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=args.headless)
        # No storage_state and no user_data_dir: this context is in-memory only.
        context = browser.new_context()
        page = context.new_page()
        rc = 1
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=45000)

            landed = page.evaluate("location.origin")
            if landed != expect_origin and not args.allow_redirect:
                # A redirect to another origin is normal for SAML -- and is also how a
                # credential ends up at an identity provider you did not intend. Opt in.
                print(f"creds browser: refused -- {url} redirected to {landed}.\n"
                      f"  Re-run with --allow-redirect if that is the expected IdP.",
                      file=sys.stderr)
                return 4

            # One implementation of field detection, shared with the extension.
            page.add_script_tag(content=FILL_JS.read_text())
            result = page.evaluate(
                "([u, s, o]) => window.__creds_fill(u, s, o)",
                [user, secret, landed])

            if not result.get("ok"):
                print(f"creds browser: could not fill -- {result.get('reason')}",
                      file=sys.stderr)
                rc = 5
            elif args.no_submit:
                print("creds browser: filled, not submitted", file=sys.stderr)
                rc = 0
            else:
                # fill.js never submits, by design. Submitting is a separate, deliberate
                # act here -- and it happens exactly once.
                submit_once(page)
                page.wait_for_load_state("networkidle", timeout=45000)
                still_asking = page.evaluate(
                    "!!document.querySelector('input[type=password]')")
                title = page.title()
                if still_asking:
                    print(f"creds browser: logon appears to have FAILED "
                          f"(password field still present) -- {title}", file=sys.stderr)
                    print("  Not retrying: repeated failures lock accounts.",
                          file=sys.stderr)
                    rc = 6
                else:
                    print(f"creds browser: logged on -- {title}", file=sys.stderr)
                    rc = 0

            if args.shot:
                page.screenshot(path=args.shot, full_page=True)
                print(f"creds browser: screenshot -> {args.shot}", file=sys.stderr)
            if args.keep_open and not args.headless:
                print("creds browser: window open; press Enter to close and wipe.",
                      file=sys.stderr)
                try:
                    input()
                except (EOFError, KeyboardInterrupt):
                    pass
            return rc
        finally:
            # Asked for explicitly: leave nothing behind on close. The in-memory context
            # already dies with the process; this makes it true even if a future change
            # introduces a persistent profile.
            for wipe in ("localStorage.clear()", "sessionStorage.clear()"):
                try:
                    page.evaluate(wipe)
                except Exception:
                    pass
            try:
                context.clear_cookies()
            except Exception:
                pass
            context.close()
            browser.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
