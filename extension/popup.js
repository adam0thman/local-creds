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
  "no-password-field": "no password box on this page, and no user id box either",
  "multiple-password-fields": "several password boxes — looks like a change-password form",
  "origin-changed": "the page navigated away; nothing was filled",
};

/** Words a row is matched against when filtering. */
const hay = h => [h.id, h.user, h.customer, h.env, h.kind].join(" ").toLowerCase();

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
  return out.ok ? { ok: true, filledUser: out.filledUser, step: out.step }
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
  el.dataset.hay = hay(hit);
  el.innerHTML = `
    <div class="id">${esc(hit.id)}<span class="env${hit.prod ? " prod" : ""}">${esc(hit.env || "?")}</span></div>
    <div class="who">${esc(hit.user)}${hit.client ? " · client " + esc(hit.client) : ""}</div>
    ${hit.prod ? `<p class="warn">⚠ PRODUCTION</p>` : ""}
    <div class="btns"><button data-act="fill" class="primary">Fill</button>
                      <button data-act="user">Copy user</button>
                      <button data-act="pw">Copy password</button></div>
    <p class="note" hidden></p>`;

  const note = el.querySelector(".note");
  const say = (text, bad) => {
    note.hidden = false;
    note.className = bad ? "note err" : "note";
    note.textContent = text;
  };

  el.querySelectorAll("button").forEach(btn => {
    btn.onclick = async () => {
      const act = btn.dataset.act;

      // The user id is not a secret and is already in hand -- no host call, no
      // production confirmation, nothing to leak.
      if (act === "user") {
        await navigator.clipboard.writeText(hit.user || "");
        say(`Copied ${hit.user}`);
        return;
      }

      // Production gets its own explicit yes, mirroring CREDS_ALLOW_PROD=1 on the CLI.
      if (hit.prod && !confirm(
        `${act === "fill" ? "Fill" : "Copy"} the PRODUCTION password for ${hit.id}?`)) return;

      el.querySelectorAll("button").forEach(b => b.disabled = true);
      say("…");
      try {
        const r = act === "fill" ? await doFill(hit, origin, hit.prod)
                                 : await doCopy(hit, origin, hit.prod);
        if (!r.ok) {
          say(r.error || "failed", true);
        } else if (act !== "fill") {
          // Clipboards sync across devices and any app can read them. Say so.
          say("On your clipboard until you copy something else.");
        } else if (r.step === "username") {
          // Identity-first page: this screen only wants the user id.
          say("Filled the user id. Press Continue, then Fill again for the password.");
        } else {
          say(r.filledUser
            ? "Filled username and password. Not submitted — press Enter yourself."
            : "Filled the password. Not submitted — press Enter yourself.");
        }
      } catch (e) {
        say(/Cannot access|chrome:\/\//.test(e.message)
          ? "the browser blocks extensions on this page" : e.message, true);
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

  // A shared identity provider can match every S-User you own. Scrolling a list of
  // thirty to find one customer is worse than the terminal this replaces, so filter.
  if (r.candidates.length > 3) {
    const box = document.createElement("input");
    box.type = "search";
    box.id = "filter";
    box.placeholder = `filter ${r.candidates.length} matches — customer, id, user…`;
    box.autocomplete = "off";
    box.spellcheck = false;
    box.setAttribute("aria-label", "Filter matches");
    $("#out").prepend(box);
    const rows = [...$("#out").querySelectorAll(".hit")];
    box.oninput = () => {
      const terms = box.value.toLowerCase().split(/\s+/).filter(Boolean);
      let shown = 0;
      rows.forEach(el => {
        const hit = terms.every(t => el.dataset.hay.includes(t));
        el.hidden = !hit;
        if (hit) shown++;
      });
      $("#count").textContent = terms.length ? `${shown} of ${rows.length}` : "";
      // Filtered to one: Enter should finish the job without reaching for the mouse.
      if (shown === 1) rows.find(el => !el.hidden).querySelector("button").focus();
    };
    box.focus();
  } else if (r.candidates.length === 1 && !r.candidates[0].prod) {
    // One obvious answer and nothing production: Enter finishes it.
    $("#out").querySelector("button[data-act=fill]").focus();
  }
})();
