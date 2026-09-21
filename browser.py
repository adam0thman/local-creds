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


def urls_of_env():
    """Every origin in CREDS_URL. fields.url may list several, whitespace-separated."""
    return (os.environ.get("CREDS_URL") or "").split()


def choose_idp(page, scope):
    """Click the identity provider named by `scope` on a chooser page.

    BTP puts an "or sign in with:" page in front of anything wired to more than one
    identity provider -- no form, just links. Matching on the link's href as well as
    its text matters: SAP labels its own one "Default Identity Provider", which names
    no host at all, while the href says accounts.sap.com.

    Clicking a chooser sends no credential, so this cannot cost a lockout attempt.
    Returns the chosen link's text, or None.
    """
    if not scope:
        return None
    return page.evaluate("""(scope) => {
      const want = scope.toLowerCase();
      const links = Array.from(document.querySelectorAll('a[href], button'))
        .filter(a => a.offsetParent);
      const hit = links.find(a =>
        (a.innerText || '').toLowerCase().includes(want) ||
        (a.getAttribute('href') || '').toLowerCase().includes(want));
      if (!hit) return null;
      const label = (hit.innerText || hit.getAttribute('href') || '').trim().slice(0, 60);
      hit.click();
      return label;
    }""", scope)


def settle(page, PWTimeout):
    """Wait for a redirect chain to finish and a password box to appear, if it will.

    Two waits, both best-effort: networkidle for the SAML hops, then the password
    field itself for pages that render it with JavaScript afterwards. A timeout is not
    an error here -- absence is reported properly by the field picker.
    """
    for wait in (lambda: page.wait_for_load_state("networkidle", timeout=30000),
                 lambda: page.wait_for_selector("input[type=password]",
                                                state="visible", timeout=20000)):
        try:
            wait()
        except PWTimeout:
            pass


def probe(page, expr, PWTimeout, default=None):
    """Evaluate something on the page, tolerating a navigation still in flight.

    Submitting a logon form navigates, and an evaluate that lands mid-navigation throws
    "Execution context was destroyed". That is not an answer about the logon -- it is
    the verification step falling over -- so retry rather than report a verdict nobody
    checked.
    """
    for _ in range(3):
        try:
            return page.evaluate(expr)
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10000)
            except PWTimeout:
                pass
    return default


def url_origin_str(url):
    """"scheme://host[:port]" for a url, or the url itself if it will not parse."""
    o = origin_of(url)
    if not o:
        return url
    return f"{o[0]}://{o[1]}" + ("" if o[2] in (80, 443) else f":{o[2]}")


def target_url(args):
    """Where to go: the argument, else the FIRST entry url, else built from host.

    An entry may list several origins -- a public vanity name and an internal one, or a
    pair behind a VIP. Only one can be navigated to, so the first wins and the rest stay
    valid destinations for the origin check below.
    """
    if args.url:
        return args.url
    urls = urls_of_env()
    if urls:
        return urls[0]
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
    # Prefer the form's OWN submit button. A UI5 identity-first page (SAP ID is one)
    # ignores Enter entirely, and a form that never submitted looks exactly like a
    # rejected password if you only check whether the password box is still there.
    clicked = _click_submit(page)
    if not clicked:
        page.keyboard.press("Enter")
    return clicked


def _click_submit(page):
    """Click the logon form's submit control. Separated so submit_once stays readable."""
    try:
        return page.evaluate("""() => {
      const pw = document.querySelector('input[type=password]');
      // Do NOT scope the search to the form's subtree. HTML5 lets a submit button sit
      // anywhere and bind to its form by the `form` attribute -- SAP ID's "Continue"
      // is outside <form id=logOnForm> exactly so. The DOM's .form property resolves
      // that association whatever the nesting, which a CSS descendant selector cannot.
      const btns = Array.from(
          document.querySelectorAll('button[type=submit], input[type=submit]'))
        .filter(b => b.offsetParent && !b.disabled);
      const btn = (pw && btns.find(b => b.form && b.form === pw.form)) || btns[0];
      if (!btn) return false;
      btn.click();
      return true;
    }""")
    except Exception:
        return False


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
    # Several origins on one entry: navigate to the first, accept any of them.
    os.environ["CREDS_URL"] = "https://me.example.com https://launchpad.example.com"
    assert target_url(A) == "https://me.example.com", "must not navigate to the whole list"
    assert len(urls_of_env()) == 2
    assert origin_of(target_url(A)) == ("https", "me.example.com", 443)
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
        def evaluate(self, _): return False       # no button -> falls back to Enter

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
    # Landing on ANY origin the entry lists is fine -- following a link from the public
    # name to the internal one is not a redirect to somewhere unintended.
    allowed = {o for o in (origin_of(u) for u in ([url] + urls_of_env())) if o}

    try:
        from playwright.sync_api import sync_playwright
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        print(INSTALL, file=sys.stderr)
        return 3

    print(f"creds browser: {ident} -> {url}", file=sys.stderr)
    if os.environ.get("CREDS_ENV") == "prd":
        print("creds browser: PRODUCTION system", file=sys.stderr)

    with sync_playwright() as pw:
        # --use-mock-keychain swaps the macOS Keychain for an empty one. Without it a
        # site asking for a client certificate (accounts.sap.com does) pops a chooser
        # listing the SAP Passports installed on this machine, which blocks page load
        # until a human dismisses it -- and by then every wait below has expired.
        #
        # It also closes a real hole in the isolation this command claims: certificates
        # live in the system keychain, not the browser profile, so a "throwaway" browser
        # would otherwise still be offered the operator's personal certs.
        browser = pw.chromium.launch(headless=args.headless,
                                     args=["--use-mock-keychain"])
        # No storage_state and no user_data_dir: this context is in-memory only.
        context = browser.new_context()
        page = context.new_page()
        rc = 1
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=45000)

            # SAML and IdP flows are several redirects deep and domcontentloaded fires
            # on the FIRST hop. Settling matters twice over: an injected script does not
            # survive the next navigation, and -- the security half -- the origin check
            # below must judge the page that will actually receive the password, not an
            # intermediate one it happened to bounce through.
            settle(page, PWTimeout)
            landed = page.evaluate("location.origin")
            if landed != url_origin_str(url):
                print(f"creds browser: followed a redirect to {landed}", file=sys.stderr)
            if origin_of(landed) not in allowed and not args.allow_redirect:
                # A redirect to another origin is normal for SAML -- and is also how a
                # credential ends up at an identity provider you did not intend. Opt in.
                print(f"creds browser: refused -- {url} redirected to {landed}.\n"
                      f"  Re-run with --allow-redirect if that is the expected IdP.",
                      file=sys.stderr)
                return 4

            # One implementation of field detection, shared with the extension.
            #
            # NOT add_script_tag: a real logon page worth protecting sets a Content
            # Security Policy, and accounts.sap.com blocks injected inline scripts
            # outright. page.evaluate goes through CDP, which CSP does not govern.
            # Wrapped in an arrow function so Playwright calls it rather than trying
            # to interpret the file's own leading IIFE.
            def inject():
                page.evaluate("() => {\n" + FILL_JS.read_text() + "\n}")

            # A late redirect can still destroy the context mid-injection; one retry
            # after re-settling is enough, and failing loudly beats filling blind.
            try:
                inject()
            except Exception:
                try:
                    page.wait_for_load_state("networkidle", timeout=15000)
                except PWTimeout:
                    pass
                landed = page.evaluate("location.origin")
                if origin_of(landed) not in allowed and not args.allow_redirect:
                    print(f"creds browser: refused -- ended on {landed}", file=sys.stderr)
                    return 4
                inject()
            result = page.evaluate(
                "([u, s, o]) => window.__creds_fill(u, s, o)",
                [user, secret, landed])

            if result.get("ok") and result.get("step") == "username":
                # fill.js put the user id in. Advancing to the password screen sends NO
                # password, so it is not a logon attempt and must not consume the
                # one-attempt guard -- hence _click_submit directly, not submit_once.
                print("creds browser: identity-first logon -- entering the user id",
                      file=sys.stderr)
                if not _click_submit(page):
                    page.keyboard.press("Enter")
                settle(page, PWTimeout)
                landed = probe(page, "location.origin", PWTimeout, landed)
                if origin_of(landed) not in allowed and not args.allow_redirect:
                    print(f"creds browser: refused -- ended on {landed}", file=sys.stderr)
                    return 4
                inject()
                result = page.evaluate(
                    "([u, s, o]) => window.__creds_fill(u, s, o)",
                    [user, secret, landed])
                if result.get("ok") and result.get("step") == "username":
                    print("creds browser: the password screen never appeared",
                          file=sys.stderr)
                    return 5

            if not result.get("ok") and result.get("reason") == "no-password-field":
                # No form at all may mean an identity-provider chooser rather than a
                # page we cannot handle. Which one to pick is the login's scope --
                # `creds exec --client <idp>` -- so this never guesses.
                chosen = choose_idp(page, os.environ.get("CREDS_CLIENT"))
                if chosen:
                    print(f"creds browser: identity provider -- {chosen}",
                          file=sys.stderr)
                    settle(page, PWTimeout)
                    landed = probe(page, "location.origin", PWTimeout, landed)
                    if origin_of(landed) not in allowed and not args.allow_redirect:
                        print(f"creds browser: refused -- ended on {landed}",
                              file=sys.stderr)
                        return 4
                    inject()
                    result = page.evaluate(
                        "([u, s, o]) => window.__creds_fill(u, s, o)",
                        [user, secret, landed])
                    if result.get("ok") and result.get("step") == "username":
                        print("creds browser: identity-first logon -- entering the user id",
                              file=sys.stderr)
                        if not _click_submit(page):
                            page.keyboard.press("Enter")
                        settle(page, PWTimeout)
                        landed = probe(page, "location.origin", PWTimeout, landed)
                        if origin_of(landed) not in allowed and not args.allow_redirect:
                            print(f"creds browser: refused -- ended on {landed}",
                                  file=sys.stderr)
                            return 4
                        inject()
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
                before = page.url
                before_origin = page.evaluate("location.origin")
                submit_once(page)
                # A successful logon leaves the identity provider and then renders an
                # application, which takes longer than the redirect itself. Screenshot
                # and verdict must both wait for that, or a working logon is reported
                # as unreadable and photographed half-painted.
                try:
                    page.wait_for_function(
                        "o => location.origin !== o || !document.querySelector("
                        "'input[type=password]')", arg=before_origin, timeout=45000)
                except PWTimeout:
                    pass
                for settle_step in (
                        lambda: page.wait_for_load_state("networkidle", timeout=45000),
                        lambda: page.wait_for_load_state("load", timeout=20000)):
                    try:
                        settle_step()
                    except PWTimeout:
                        pass
                still_asking = probe(
                    page, "!!document.querySelector('input[type=password]')", PWTimeout)
                # An error the page itself shows is the only positive evidence that a
                # credential was rejected.
                complaint = probe(page, """() => {
                  const el = document.querySelector(
                    '[role=alert], .sapMMessageStrip, .errorMessage, [class*=error i]');
                  return el && el.offsetParent ? (el.innerText || '').trim().slice(0, 200) : '';
                }""", PWTimeout, "")
                title = page.title()
                if still_asking is None:
                    print("creds browser: submitted, but the result could not be read "
                          "-- check the screenshot; an attempt WAS used", file=sys.stderr)
                    rc = 8
                elif still_asking and not complaint and page.url == before:
                    # Nothing moved and nothing complained: the form never went. Saying
                    # "wrong password" here would send someone to reset a working one.
                    print("creds browser: the form did not submit -- no request was "
                          "made, so NO logon attempt was used", file=sys.stderr)
                    rc = 7
                elif still_asking:
                    print(f"creds browser: logon REJECTED -- "
                          f"{complaint or title or 'still on the logon page'}",
                          file=sys.stderr)
                    print("  Not retrying: repeated failures lock accounts.",
                          file=sys.stderr)
                    rc = 6
                else:
                    where = probe(page, "location.href", PWTimeout, "") or page.url
                    print(f"creds browser: logged on -- {title or '(no title)'}",
                          file=sys.stderr)
                    print(f"  landed on {where[:110]}", file=sys.stderr)
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
