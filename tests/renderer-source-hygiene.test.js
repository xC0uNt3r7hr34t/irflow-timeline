/**
 * Guards against the two ways an upstream merge silently breaks the renderer.
 *
 * Both are invisible to `vite build`, so the first symptom is a crash or a doubled modal in front
 * of an examiner: a reference to a local the other side of the merge deleted (the row context menu
 * lost `hasExplicitMultiSelection` this way), and a modal left rendering inline in App.jsx after
 * upstream extracted it into its own component (`usnAnalysis`, `ransomware`, `heatmap`, `ads`,
 * `timestomping` were all mounted twice).
 */

"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const SRC_DIR = path.join(__dirname, "..", "src");
const APP_JSX = path.join(SRC_DIR, "App.jsx");

/** Browser/runtime globals the renderer legitimately reaches for. */
const ALLOWED_GLOBALS = new Set([
  "window", "document", "navigator", "location", "history", "screen", "self", "globalThis",
  "console", "performance", "requestAnimationFrame", "cancelAnimationFrame",
  "setTimeout", "clearTimeout", "setInterval", "clearInterval", "queueMicrotask",
  "fetch", "Headers", "Request", "Response", "AbortController", "URL", "URLSearchParams",
  "Blob", "File", "FileReader", "FormData", "Image", "Audio", "Worker", "MessageChannel",
  "IntersectionObserver", "ResizeObserver", "MutationObserver", "CustomEvent", "Event",
  "DOMParser", "XMLSerializer", "XMLHttpRequest", "TextEncoder", "TextDecoder", "structuredClone",
  "requestIdleCallback", "cancelIdleCallback",
  "localStorage", "sessionStorage", "indexedDB", "crypto", "matchMedia", "getComputedStyle",
  "alert", "prompt", "atob", "btoa", "SVGElement", "HTMLElement", "Node", "Element",
  "Object", "Array", "String", "Number", "Boolean", "Symbol", "BigInt", "Math", "JSON", "Date",
  "RegExp", "Map", "Set", "WeakMap", "WeakSet", "Promise", "Proxy", "Reflect", "Intl",
  "Error", "TypeError", "RangeError", "SyntaxError", "EvalError", "ReferenceError",
  "Function", "Infinity", "NaN", "undefined", "isNaN", "isFinite", "parseInt", "parseFloat",
  "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI",
  "ArrayBuffer", "SharedArrayBuffer", "DataView", "Uint8Array", "Uint16Array", "Uint32Array",
  "Int8Array", "Int16Array", "Int32Array", "Float32Array", "Float64Array", "BigInt64Array",
  "process", "React",
]);

function listSourceFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listSourceFiles(full));
    else if (/\.jsx?$/.test(entry.name)) out.push(full);
  }
  return out.sort();
}

function loadBabel() {
  try {
    const parser = require("@babel/parser");
    const traverseModule = require("@babel/traverse");
    return { parser, traverse: traverseModule.default || traverseModule };
  } catch {
    return null;
  }
}

test("no renderer source references an undefined identifier", (t) => {
  const babel = loadBabel();
  if (!babel) {
    t.skip("@babel/parser is not installed in this environment");
    return;
  }

  const offenders = [];
  for (const file of listSourceFiles(SRC_DIR)) {
    const code = fs.readFileSync(file, "utf8");
    const ast = babel.parser.parse(code, {
      sourceType: "module",
      plugins: ["jsx", "classProperties", "optionalChaining", "nullishCoalescingOperator"],
    });

    babel.traverse(ast, {
      ReferencedIdentifier(refPath) {
        const name = refPath.node.name;
        if (ALLOWED_GLOBALS.has(name)) return;
        if (refPath.scope.hasBinding(name, { noGlobals: true })) return;
        offenders.push(`${path.relative(SRC_DIR, file)}:${refPath.node.loc?.start.line} — ${name}`);
      },
    });
  }

  assert.deepEqual(offenders, [], `undefined identifiers in renderer sources:\n${offenders.join("\n")}`);
});

test("a modal type is rendered either inline or as a component, never both", () => {
  const app = fs.readFileSync(APP_JSX, "utf8");

  const inline = new Set();
  for (const m of app.matchAll(/\{modal\?\.type === "([A-Za-z]+)"[^\n]*\(\(\) => \{/g)) inline.add(m[1]);

  const component = new Set();
  for (const m of app.matchAll(/\{modal\?\.type === "([A-Za-z]+)"[^\n]*<([A-Z]\w+)/g)) component.add(m[1]);

  const both = [...inline].filter((type) => component.has(type)).sort();
  assert.deepEqual(both, [], `these modals render twice — drop the stale inline copy: ${both.join(", ")}`);
});
