// Unit tests for the field picker. No DOM, no browser: pickFields takes plain
// descriptors precisely so the fiddly part can be checked here.
//   node extension/fill.test.js
const assert = require("assert");
const { pickFields, pickUserOnly, plan } = require("./fill.js");

const f = o => Object.assign({ type: "text", visible: true, disabled: false, readOnly: false }, o);
let n = 0;
const t = (name, fn) => { fn(); n++; };

t("classic form: username is the field before the password", () => {
  const r = pickFields([f({ name: "u" }), f({ type: "password", name: "p" })]);
  assert.deepStrictEqual(r, { ok: true, userIdx: 0, pwIdx: 1 });
});

t("SAP BSP logon (sap-user / sap-password)", () => {
  const r = pickFields([f({ name: "sap-client" }), f({ name: "sap-user" }),
                        f({ type: "password", name: "sap-password" })]);
  assert.strictEqual(r.userIdx, 1, "nearest typeable field before the password wins");
});

t("autocomplete=username beats position", () => {
  const r = pickFields([f({ name: "search" }), f({ name: "u", autocomplete: "username" }),
                        f({ type: "hidden" }), f({ type: "password" })]);
  assert.strictEqual(r.userIdx, 1);
});

t("hidden and disabled fields are never chosen", () => {
  const r = pickFields([f({ name: "honeypot", visible: false }),
                        f({ name: "locked", disabled: true }),
                        f({ name: "real" }), f({ type: "password" })]);
  assert.strictEqual(r.userIdx, 2);
});

t("an invisible password field is not fillable", () => {
  const r = pickFields([f({ name: "u" }), f({ type: "password", visible: false })]);
  assert.deepStrictEqual(r, { ok: false, reason: "no-password-field" });
});

t("a change-password form is refused, not guessed", () => {
  // Filling here would type the CURRENT password into a "new password" box.
  const r = pickFields([f({ type: "password", name: "old" }),
                        f({ type: "password", name: "new" }),
                        f({ type: "password", name: "confirm" })]);
  assert.deepStrictEqual(r, { ok: false, reason: "multiple-password-fields" });
});

t("a page with no password field is refused", () => {
  assert.deepStrictEqual(pickFields([f({ name: "q" })]),
                         { ok: false, reason: "no-password-field" });
});

t("password with no preceding text field still fills the password", () => {
  const r = pickFields([f({ type: "password" })]);
  assert.deepStrictEqual(r, { ok: true, userIdx: -1, pwIdx: 0 });
});

t("indices refer to the original array, not the filtered one", () => {
  const r = pickFields([f({ visible: false }), f({ visible: false }),
                        f({ name: "u" }), f({ type: "password" })]);
  assert.deepStrictEqual(r, { ok: true, userIdx: 2, pwIdx: 3 });
});

t("a text field AFTER the password is not mistaken for the username", () => {
  const r = pickFields([f({ type: "password" }), f({ name: "captcha" })]);
  assert.strictEqual(r.userIdx, -1);
});

// --- identity-first: the SAP ID / Microsoft / Okta first screen -----------------
t("picks the user id box when there is no password box yet", () => {
  assert.strictEqual(pickUserOnly([f({ name: "j_username" })]), 0);
});

t("prefers an autocomplete=username hint over position", () => {
  assert.strictEqual(pickUserOnly(
    [f({ name: "search" }), f({ name: "u", autocomplete: "username" })]), 1);
});

t("accepts autocomplete=email too", () => {
  assert.strictEqual(pickUserOnly(
    [f({ name: "q" }), f({ name: "e", autocomplete: "email" })]), 1);
});

t("skips hidden and disabled boxes on the identity screen", () => {
  assert.strictEqual(pickUserOnly(
    [f({ visible: false }), f({ disabled: true }), f({ name: "real" })]), 2);
});

t("never offers a password box as the user id box", () => {
  assert.strictEqual(pickUserOnly([f({ type: "password" })]), -1);
});

t("says so when there is nothing typeable at all", () => {
  assert.strictEqual(pickUserOnly([f({ type: "checkbox" }), f({ type: "hidden" })]), -1);
});

// --- plan(): the branch that decides what Fill actually does --------------------
t("a normal logon form plans a password fill", () => {
  const r = plan([f({ name: "u" }), f({ type: "password" })], "S1");
  assert.deepStrictEqual(r, { action: "password", userIdx: 0, pwIdx: 1 });
});

t("the SAP ID first screen plans a username fill, not a refusal", () => {
  // This is the case that made Fill look broken: a user id box, no password box.
  const r = plan([f({ name: "j_username" })], "S0020967337");
  assert.deepStrictEqual(r, { action: "username", userIdx: 0 });
});

t("no user to type means the identity screen is refused, not half-filled", () => {
  const r = plan([f({ name: "j_username" })], "");
  assert.strictEqual(r.action, "refuse");
});

t("a change-password form is still refused, user id or not", () => {
  const r = plan([f({ name: "u" }), f({ type: "password" }), f({ type: "password" })], "S1");
  assert.deepStrictEqual(r, { action: "refuse", reason: "multiple-password-fields" });
});

t("a page with nothing typeable is refused", () => {
  assert.strictEqual(plan([f({ type: "checkbox" })], "S1").action, "refuse");
});

t("a password box present means password, never the username step", () => {
  const r = plan([f({ name: "u" }), f({ type: "password" })], "S1");
  assert.strictEqual(r.action, "password", "must not regress to the identity screen");
});

console.log(`  fill.js: ${n} unit tests passed`);
