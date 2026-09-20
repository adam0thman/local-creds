// The popup. Looks up what fits the page you are on, then fills or copies.
//
// Injection happens only here, only on a click, only into the tab in front: there is
// no declarative content script and no host permission, so this extension has no
// presence on any page until you ask for one.
//
// The origin comes from chrome.tabs, which the browser supplies. A page cannot set it,
// and it is re-checked twice more before a secret moves: once here against the tab's
// current URL, and once inside the page by fill.js.

const HOST = "com.local_creds.nm";
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const ask = req => new Promise((resolve, reject) =>
  chrome.runtime.sendNativeMessage(HOST, req, r =>
    chrome.runtime.lastError ? reject(new Error(chrome.runtime.lastError.message))
                             : resolve(r)));

/** Toolbar click is the user gesture that makes activeTab yield a URL. */
async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  try { return { id: tab.id, origin: new URL(tab.url).origin }; }
  catch { return { id: tab?.id, origin: null }; }
}

const FILL_REASONS = {
  "no-password-field": "no password box on this page",
  "multiple-password-fields": "several password boxes — looks like a change-password form",
  "origin-changed": "the page navigated away; nothing was filled",
};

function setupHelp(msg) {
  return `<p class="err">${esc(msg)}</p>
    <p class="empty">Is the native host installed?<br>
    <code>./creds-nm --install ${esc(chrome.runtime.id)}</code><br>
    then restart the browser.</p>`;
}

/** Fetch the secret, but only after re-confirming the tab is still where it was. */
async function secretFor(hit, origin, confirmed) {
  const now = await activeTab();
  if (now.origin !== origin) {
    return { ok: false, error: "the page navigated away — nothing was sent" };
  }
  return ask({ cmd: "fill", origin, id: hit.id, user: hit.user,
               client: hit.client, confirm: confirmed });
}

async function doFill(hit, origin, confirmed) {
  const r = await secretFor(hit, origin, confirmed);
  if (!r.ok) return r;
  const tab = await activeTab();
  // fill.js defines window.__creds_fill in the ISOLATED world, so page scripts can
  // neither see the function nor read the argument carrying the password.
  await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["fill.js"] });
  const [res] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: (u, s, o) => window.__creds_fill(u, s, o),
    args: [r.user || "", r.secret, origin],
  });
  const out = res?.result || { ok: false, reason: "no-result" };
  return out.ok ? { ok: true, filledUser: out.filledUser }
                : { ok: false, error: FILL_REASONS[out.reason] || out.reason };
}

async function doCopy(hit, origin, confirmed) {
  const r = await secretFor(hit, origin, confirmed);
  if (!r.ok) return r;
  await navigator.clipboard.writeText(r.secret);
  return { ok: true, copied: true };
}

function row(hit, origin) {
  const el = document.createElement("div");
  el.className = "hit";
  el.innerHTML = `
    <div class="id">${esc(hit.id)}<span class="env${hit.prod ? " prod" : ""}">${esc(hit.env || "?")}</span></div>
    <div class="who">${esc(hit.user)}${hit.client ? " · client " + esc(hit.client) : ""}</div>
    ${hit.prod ? `<p class="warn">⚠ PRODUCTION</p>` : ""}
    <div class="btns"><button data-act="fill" class="primary">Fill</button>
                      <button data-act="copy">Copy</button></div>
    <p class="note" hidden></p>`;

  const note = el.querySelector(".note");
  el.querySelectorAll("button").forEach(btn => {
    btn.onclick = async () => {
      const filling = btn.dataset.act === "fill";
      // Production gets its own explicit yes, mirroring CREDS_ALLOW_PROD=1 on the CLI.
      if (hit.prod && !confirm(
        `${filling ? "Fill" : "Copy"} the PRODUCTION password for ${hit.id}?`)) return;

      el.querySelectorAll("button").forEach(b => b.disabled = true);
      note.hidden = false;
      note.className = "note";
      note.textContent = "…";
      try {
        const r = filling ? await doFill(hit, origin, hit.prod)
                          : await doCopy(hit, origin, hit.prod);
        if (!r.ok) {
          note.className = "note err";
          note.textContent = r.error || "failed";
        } else if (filling) {
          note.textContent = r.filledUser
            ? "Filled username and password. Not submitted — press Enter yourself."
            : "Filled the password. Not submitted — press Enter yourself.";
        } else {
          // Clipboards sync across devices and any app can read them. Say so.
          note.textContent = "On your clipboard until you copy something else.";
        }
      } catch (e) {
        note.className = "note err";
        note.textContent = /Cannot access|chrome:\/\//.test(e.message)
          ? "the browser blocks extensions on this page" : e.message;
      }
      el.querySelectorAll("button").forEach(b => b.disabled = false);
    };
  });
  return el;
}

(async () => {
  const { origin } = await activeTab();
  $("#origin").textContent = origin || "(no page)";
  if (!origin) { $("#out").innerHTML = `<p class="empty">Open a site first.</p>`; return; }

  let r;
  try {
    r = await ask({ cmd: "match", origin });
  } catch (e) {
    $("#out").innerHTML = setupHelp(e.message);
    return;
  }
  if (!r || !r.ok) { $("#out").innerHTML = setupHelp(r?.error || "lookup failed"); return; }

  if (!r.candidates.length) {
    const health = await ask({ cmd: "ping" }).catch(() => null);
    // "Nothing matches" and "the index is unreadable" look identical otherwise.
    if (health && !health.ok) { $("#out").innerHTML = setupHelp(health.problems.join("; ")); return; }
    // Deliberately NOT offering to write the entry from here: creds-nm stays
    // read-only, so a compromised extension can never alter the index. Copying the
    // origin into `creds ui` is one paste.
    $("#out").innerHTML = `
      <p class="empty">Nothing stored for this origin.
      ${health ? esc(health.with_url) : "?"} entries carry a <code>url</code>.</p>
      <p class="empty">Add it in <code>creds ui</code> as
      <code>fields.url</code>:</p>
      <div class="btns"><button id="copyorigin">Copy origin</button></div>`;
    $("#copyorigin").onclick = async ev => {
      await navigator.clipboard.writeText(origin);
      ev.target.textContent = "copied ✓";
    };
    return;
  }
  r.candidates.forEach(h => $("#out").appendChild(row(h, origin)));
  // Opened by keyboard, one obvious answer: Enter should finish the job. Only when
  // there is exactly one non-production match -- anything else is the human's choice.
  if (r.candidates.length === 1 && !r.candidates[0].prod) {
    $("#out").querySelector("button[data-act=fill]").focus();
  }
})();
