// Probe spawned by forensic-normalize-tz.test.js under a controlled TZ to prove the
// timestamp normalizers read naive (zone-less) strings as UTC regardless of host TZ.
// Args: timestamp strings. Output: JSON { tz, results: { input: { backend, renderer } } }.
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const backend = require("../../electron/utils/forensic-normalize");

// Load the ESM renderer mirror by stripping `export` and exec'ing in a vm sandbox —
// same technique as forensic-normalize.test.js, so both copies are covered.
function loadRendererMirror() {
  const src = fs.readFileSync(
    path.join(__dirname, "..", "..", "src", "utils", "forensic-normalize.js"),
    "utf8",
  );
  const munged = src.replace(/^export\s+function\s+/gm, "function ");
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(munged + "\n;globalThis.normalizeTimestamp = normalizeTimestamp;", ctx);
  return ctx.normalizeTimestamp;
}

const rendererNT = loadRendererMirror();
const results = {};
for (const input of process.argv.slice(2)) {
  results[input] = { backend: backend.normalizeTimestamp(input), renderer: rendererNT(input) };
}
process.stdout.write(JSON.stringify({ tz: process.env.TZ || null, results }));
