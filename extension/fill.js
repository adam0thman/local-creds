// Runs INSIDE the page, injected on a user gesture only -- there is no declarative
// content script and no host permission, so this code does not exist on any page
// until the moment you click Fill.
//
// It never submits. Choosing to log on stays a human action: an autofill that also
// submits will happily post a credential to whatever the form's action has become.
(function () {
  "use strict";

  // Inputs a human could actually type into. An invisible or disabled field is either
  // a honeypot or a leftover, and filling one is how a password ends up somewhere the
  // user cannot see.
  const TEXTY = ["text", "email", "tel", "", undefined, null];

  /**
   * Which field is the username and which is the password.
   *
   * Pure, so it can be unit-tested without a DOM (see fill.test.js). Takes plain
   * descriptors: {type, name, id, autocomplete, visible, disabled, readOnly}.
   * Returns {ok:true, userIdx, pwIdx} with indices into the ORIGINAL array, or
   * {ok:false, reason}.
   */
  function pickFields(inputs) {
    const usable = [];
    inputs.forEach((f, i) => {
      if (f && f.visible && !f.disabled && !f.readOnly) usable.push({ f, i });
    });

    const pws = usable.filter(u => u.f.type === "password");
    if (!pws.length) return { ok: false, reason: "no-password-field" };
    // Two visible password boxes means a change-password or registration form. Which
    // one is "the" password is a guess, and guessing wrong types the current password
    // into a "new password" box -- so refuse and let the human do it.
    if (pws.length > 1) return { ok: false, reason: "multiple-password-fields" };

    const pw = pws[0];

    // A form that says which field is the username is more trustworthy than position.
    const hinted = usable.find(u =>
      String(u.f.autocomplete || "").toLowerCase() === "username");
    if (hinted) return { ok: true, userIdx: hinted.i, pwIdx: pw.i };

    // Otherwise: the nearest typeable field BEFORE the password. Works for the SAP
    // BSP logon (sap-user / sap-password) and for essentially every classic form.
    const before = usable.filter(u => u.i < pw.i && TEXTY.includes(u.f.type));
    return {
      ok: true,
      userIdx: before.length ? before[before.length - 1].i : -1,
      pwIdx: pw.i,
    };
  }

  /**
   * Index of the field that wants a user id, when there is no password box at all.
   *
   * Identity-first logons (SAP ID, Microsoft, Okta) ask who you are on one screen and
   * for your password on the next. Pure, so it is unit-tested with the rest.
   */
  function pickUserOnly(inputs) {
    const usable = [];
    inputs.forEach((f, i) => {
      if (f && f.visible && !f.disabled && !f.readOnly && TEXTY.includes(f.type))
        usable.push({ f, i });
    });
    if (!usable.length) return -1;
    const hinted = usable.find(u =>
      ["username", "email"].includes(String(u.f.autocomplete || "").toLowerCase()));
    return hinted ? hinted.i : usable[0].i;
  }

  /**
   * What to do with this page, decided from field descriptors alone.
   *
   * Pure on purpose. This is the branch that decides between "type the password",
   * "this is the user id screen of an identity-first logon" and "refuse" -- and
   * getting it wrong made Fill look broken on every SAP ID page. A decision that
   * matters that much should not be reachable only through a real DOM.
   */
  function plan(inputs, user) {
    const pick = pickFields(inputs);
    if (pick.ok) return { action: "password", userIdx: pick.userIdx, pwIdx: pick.pwIdx };
    if (pick.reason === "no-password-field" && user) {
      const ui = pickUserOnly(inputs);
      if (ui >= 0) return { action: "username", userIdx: ui };
    }
    return { action: "refuse", reason: pick.reason };
  }

  // Assigning .value directly does not tell React, Angular or UI5 anything -- their
  // state stays empty and the form submits blank. Going through the native setter and
  // then firing the events they listen for is what makes the value real.
  function setValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function describe(el) {
    return {
      type: (el.type || "").toLowerCase(),
      name: el.name, id: el.id,
      autocomplete: el.getAttribute("autocomplete"),
      // offsetParent is null for display:none and for anything not laid out.
      visible: !!(el.offsetParent || el.getClientRects().length),
      disabled: el.disabled, readOnly: el.readOnly,
    };
  }

  function fill(user, secret, expectOrigin) {
    // Last line of defence. The tab can navigate between the popup reading its URL and
    // this code running; if it did, the page under us is not the one the credential was
    // matched against.
    if (location.origin !== expectOrigin) {
      return { ok: false, reason: "origin-changed", actual: location.origin };
    }
    const els = Array.from(document.querySelectorAll("input"));
    const what = plan(els.map(describe), user);

    if (what.action === "refuse") return { ok: false, reason: what.reason };

    if (what.action === "username") {
      // Sends no password, so it cannot cost a lockout attempt.
      setValue(els[what.userIdx], user);
      els[what.userIdx].focus();
      return { ok: true, step: "username", filledUser: true, submitted: false };
    }

    setValue(els[what.pwIdx], secret);
    let filledUser = false;
    if (what.userIdx >= 0 && user) {
      setValue(els[what.userIdx], user);
      filledUser = true;
    }
    els[what.pwIdx].focus();
    return { ok: true, step: "password", filledUser, submitted: false };
  }

  if (typeof window !== "undefined") window.__creds_fill = fill;
  if (typeof module !== "undefined") module.exports = { pickFields, pickUserOnly, plan };
})();
