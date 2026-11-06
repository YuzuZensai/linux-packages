const assert = require("node:assert/strict");
const addon = require("/opt/eda/resources/app.asar.unpacked/node_modules/velopack/lib/native/velopack_nodeffi_linux_x64_gnu.node");

addon.js_appbuilder_run(() => {}, null, null, false);
assert.throws(
  () => addon.js_new_update_manager(
    JSON.stringify({ kind: "http", url: "https://example.invalid/", options: {} }),
    "",
    null,
  ),
  /not properly installed/,
  "Native packages must leave updates to the package manager",
);
console.log("Installed Eda native startup passed; AppImage self-updates are disabled.");
