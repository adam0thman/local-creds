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
    const pick = pickFields(els.map(describe));
    if (!pick.ok) return pick;

    setValue(els[pick.pwIdx], secret);
    let filledUser = false;
    if (pick.userIdx >= 0 && user) {
      setValue(els[pick.userIdx], user);
      filledUser = true;
    }
    els[pick.pwIdx].focus();
    return { ok: true, filledUser, submitted: false };
  }

  if (typeof window !== "undefined") window.__creds_fill = fill;
  if (typeof module !== "undefined") module.exports = { pickFields };
})();
