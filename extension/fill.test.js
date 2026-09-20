// Unit tests for the field picker. No DOM, no browser: pickFields takes plain
// descriptors precisely so the fiddly part can be checked here.
//   node extension/fill.test.js
const assert = require("assert");
const { pickFields } = require("./fill.js");

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

console.log(`  fill.js: ${n} unit tests passed`);
