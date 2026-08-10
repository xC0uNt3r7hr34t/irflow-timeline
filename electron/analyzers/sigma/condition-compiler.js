/**
 * sigma/condition-compiler.js — Sigma Condition to JS Predicate Compiler
 *
 * Compiles a Sigma rule's detection block (named groups + condition string)
 * into a JavaScript predicate function: (resolve, row) => boolean
 *
 * Where `resolve(fieldName, row)` returns the field value from the row.
 */

const { safeRegexTester } = require("../../utils/safe-regex");

/**
 * Parse an IPv4 CIDR notation into { network: number, mask: number }.
 * Returns null for invalid input.
 */
function _parseCIDR(cidr) {
  const m = String(cidr).match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (!m) return null;
  const parts = m[1].split(".").map(Number);
  if (parts.some(p => p < 0 || p > 255)) return null;
  const prefix = parseInt(m[2], 10);
  if (prefix < 0 || prefix > 32) return null;
  const ip = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { network: (ip & mask) >>> 0, mask };
}

/**
 * Parse an IPv4 address string to a 32-bit unsigned integer.
 * Returns null for invalid input.
 */
function _parseIPv4(ip) {
  const parts = String(ip).trim().split(".").map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Encode a string to base64 (ASCII-safe).
 */
function _toBase64(str) {
  return Buffer.from(str, "utf8").toString("base64");
}

/**
 * Generate base64offset variants for a search value.
 * base64offset accounts for the three possible alignment offsets in base64 encoding.
 * When a string appears at an arbitrary byte offset within a base64-encoded blob,
 * it can produce three different base64 substring patterns depending on the
 * offset mod 3. We generate all three and strip the unreliable boundary characters.
 */
function _base64OffsetVariants(str) {
  // Compute padding/trim from the UTF-8 BYTE length and build the padded value in byte
  // space. Mixing str.length (UTF-16 code units) with byte-based base64 encoding mis-trimmed
  // every variant for multi-byte search values, so |base64offset rules with a non-ASCII
  // literal (whose byte length isn't 3-aligned) silently never matched.
  const bytes = Buffer.from(str, "utf8");
  const variants = [];
  for (let offset = 0; offset < 3; offset++) {
    const tailPad = (3 - (offset + bytes.length) % 3) % 3;
    const padded = Buffer.concat([Buffer.alloc(offset), bytes, Buffer.alloc(tailPad)]);
    const encoded = padded.toString("base64");
    // The first ceil(offset*4/3) chars and last ceil(tailPad*4/3) chars are influenced
    // by the padding bytes. Strip them to get the stable substring.
    const leadChars = offset === 0 ? 0 : offset === 1 ? 2 : 3;
    const trailChars = tailPad === 0 ? 0 : tailPad === 1 ? 2 : 3;
    const trimmed = encoded.slice(leadChars, encoded.length - trailChars).replace(/=+$/, "");
    if (trimmed) variants.push(trimmed);
  }
  return [...new Set(variants)];
}

// Regex metacharacters that must be escaped when a Sigma literal is embedded in a regex.
const _RE_META = /[.*+?^${}()|[\]\\]/g;

// Convert a Sigma search value into a regex source fragment, honoring Sigma escaping:
//   *  -> .*  (any run of characters)     \*  -> literal *
//   ?  -> .   (any single character)      \?  -> literal ?
//   \\ -> literal \                       lone \ -> literal \
// Returns { source, hasWildcard }; hasWildcard is true only for an UNescaped * or ?.
function _sigmaToRegexSource(sv) {
  let out = "";
  let hasWildcard = false;
  for (let i = 0; i < sv.length; i++) {
    const c = sv[i];
    if (c === "\\") {
      const next = sv[i + 1];
      if (next === "*" || next === "?" || next === "\\") {
        out += next.replace(_RE_META, "\\$&"); // escaped wildcard/backslash → literal
        i++;
      } else {
        out += "\\\\"; // lone backslash → literal backslash
      }
    } else if (c === "*") {
      out += ".*"; hasWildcard = true;
    } else if (c === "?") {
      out += "."; hasWildcard = true;
    } else {
      out += c.replace(_RE_META, "\\$&");
    }
  }
  return { source: out, hasWildcard };
}

// Unescape a wildcard-free Sigma literal for plain (non-regex) string matching:
// \* \? \\ -> * ? \ ; lone backslashes are preserved.
function _unescapeSigmaLiteral(sv) {
  let out = "";
  for (let i = 0; i < sv.length; i++) {
    if (sv[i] === "\\" && (sv[i + 1] === "*" || sv[i + 1] === "?" || sv[i + 1] === "\\")) {
      out += sv[i + 1]; i++;
    } else {
      out += sv[i];
    }
  }
  return out;
}

// Build a single-argument matcher (fv) => boolean for a search value + text mode
// ("exact" | "contains" | "startswith" | "endswith"). Values containing * / ? compile
// to an anchored, case-insensitive regex; plain values use fast string ops. Previously
// * and ? were matched as literal characters, so rules like
// `Image|endswith: '*\powershell.exe'` never matched — silent false negatives.
function _buildTextMatcher(sv, mode) {
  const { source, hasWildcard } = _sigmaToRegexSource(sv);
  if (!hasWildcard) {
    const lit = _unescapeSigmaLiteral(sv).toLowerCase();
    if (mode === "startswith") return (fv) => fv.toLowerCase().startsWith(lit);
    if (mode === "endswith") return (fv) => fv.toLowerCase().endsWith(lit);
    if (mode === "contains") return (fv) => fv.toLowerCase().includes(lit);
    return (fv) => fv.toLowerCase() === lit; // exact
  }
  let pattern;
  if (mode === "startswith") pattern = "^" + source;
  else if (mode === "endswith") pattern = source + "$";
  else if (mode === "contains") pattern = source;
  else pattern = "^" + source + "$"; // exact — full-field match
  // 's' (dotAll) so * / ? span newlines in multi-line fields (e.g. CommandLine).
  // Route through the ReDoS-safe compiler: it bounds per-field input length and
  // rejects pathological patterns. (Sigma wildcards expand to group-free `.*`/`.`,
  // so the nested-quantifier guard never fires here — this is a defensive input cap.)
  const test = safeRegexTester(pattern, "is");
  return test ? (fv) => test(fv) : () => false;
}

// Wrap _buildTextMatcher with a per-search-value cache so each distinct value's regex
// is compiled once at rule-compile time, not once per scanned row.
function _memoTextMatchFn(mode) {
  const cache = new Map();
  return (fv, sv) => {
    let m = cache.get(sv);
    if (m === undefined) { m = _buildTextMatcher(sv, mode); cache.set(sv, m); }
    return m(fv);
  };
}

/**
 * Apply a Sigma value modifier to produce a match function.
 * @param {string} fieldName - Original field name (may have modifiers: "Image|endswith")
 * @returns {{ field: string, matchFn: (fieldValue: string, searchValue: string) => boolean, allRequired: boolean }}
 */
function parseFieldModifiers(fieldName) {
  const parts = fieldName.split("|");
  const field = parts[0];
  const mods = parts.slice(1).map(m => m.toLowerCase());

  let allRequired = false; // |all modifier requires ALL values to match
  let matchFn;
  let isFieldRef = false;

  if (mods.includes("all")) allRequired = true;

  // Determine encoding transform: base64, base64offset, wide/utf16 modify the search
  // value before comparison. These are independent of the match type (contains, etc.).
  const hasBase64Offset = mods.includes("base64offset");
  const hasBase64 = mods.includes("base64");
  const hasWide = mods.includes("wide") || mods.includes("utf16le") || mods.includes("utf16");

  // Build a search-value transform based on encoding modifiers.
  // Returns an array of encoded variants of the search value.
  let encodeSv;
  if (hasBase64Offset) {
    encodeSv = (sv) => _base64OffsetVariants(sv);
  } else if (hasBase64) {
    encodeSv = (sv) => [_toBase64(sv)];
  } else if (hasWide) {
    // UTF-16LE: null-byte interleaved. Also include plain value as fallback.
    encodeSv = (sv) => {
      const wide = sv.split("").join("\x00") + "\x00";
      return [wide, sv];
    };
  } else {
    encodeSv = null; // no encoding transform
  }

  // base64/base64offset/wide always use binary-safe "includes" matching
  // (case-sensitive for encoded data), regardless of other modifiers
  if (encodeSv && !mods.includes("re") && !mods.includes("cidr")) {
    // Determine the text match operation (default: contains for encoded values)
    let textMatch;
    if (mods.includes("endswith")) {
      textMatch = (fv, encoded) => fv.endsWith(encoded);
    } else if (mods.includes("startswith")) {
      textMatch = (fv, encoded) => fv.startsWith(encoded);
    } else {
      // |contains or default — encoded values use "includes"
      textMatch = (fv, encoded) => fv.includes(encoded);
    }
    matchFn = (fv, sv) => {
      const variants = encodeSv(sv);
      return variants.some(v => textMatch(fv, v));
    };
  } else if (mods.includes("endswith")) {
    matchFn = _memoTextMatchFn("endswith");
  } else if (mods.includes("startswith")) {
    matchFn = _memoTextMatchFn("startswith");
  } else if (mods.includes("contains")) {
    matchFn = _memoTextMatchFn("contains");
  } else if (mods.includes("re")) {
    // Compile each distinct pattern once (was recompiling on every scanned row).
    // Sigma rules are downloaded from public/3rd-party repos or user-imported, so the
    // |re pattern is UNTRUSTED — route it through the ReDoS-safe compiler. A rejected
    // (unsafe/invalid) pattern becomes a never-match tester.
    const reCache = new Map();
    matchFn = (fv, sv) => {
      let tester = reCache.get(sv);
      if (tester === undefined) {
        tester = safeRegexTester(sv, "i"); // (value) => boolean, or null if rejected
        reCache.set(sv, tester);
      }
      return tester ? tester(fv) : false;
    };
  } else if (mods.includes("cidr")) {
    matchFn = (fv, sv) => {
      const cidr = _parseCIDR(sv);
      if (!cidr) return false;
      const ip = _parseIPv4(fv);
      if (ip === null) return false;
      return ((ip & cidr.mask) >>> 0) === cidr.network;
    };
  } else if (mods.includes("exists")) {
    // |exists: true means field must exist; false means field must not exist
    matchFn = null; // handled separately
  } else if (mods.includes("gt") || mods.includes("gte") || mods.includes("lt") || mods.includes("lte")) {
    // Numeric comparison modifiers
    const op = mods.includes("gt") ? "gt" : mods.includes("gte") ? "gte" : mods.includes("lt") ? "lt" : "lte";
    matchFn = (fv, sv) => {
      const a = parseFloat(fv);
      const b = parseFloat(sv);
      if (isNaN(a) || isNaN(b)) return false;
      if (op === "gt") return a > b;
      if (op === "gte") return a >= b;
      if (op === "lt") return a < b;
      return a <= b; // lte
    };
  } else if (mods.includes("fieldref")) {
    // |fieldref: value is another field name, not a literal
    isFieldRef = true;
    matchFn = (fv, sv) => fv.toLowerCase() === sv.toLowerCase();
  } else {
    // Exact match (case-insensitive), with * / ? wildcard support.
    matchFn = _memoTextMatchFn("exact");
  }

  // |windash: expand - to / for command-line flags
  const windash = mods.includes("windash");

  return { field, matchFn, allRequired, windash, hasExists: mods.includes("exists"), isFieldRef };
}

/**
 * Compile a single detection group (e.g., `selection`, `filter_main`) into a predicate.
 * A group is an AND of field conditions. Multiple values per field = OR (unless |all).
 *
 * @param {object} group - Detection group: { "Image|endswith": "\\cmd.exe", "CommandLine|contains": ["whoami", "net user"] }
 * @returns {Function} (resolve, row) => boolean
 */
function compileGroup(group) {
  if (!group || typeof group !== "object") return () => true;

  // Handle list-of-maps (OR of multiple condition sets) — rare but valid in Sigma
  if (Array.isArray(group)) {
    const subPredicates = group.map(g => compileGroup(g));
    return (resolve, row) => subPredicates.some(p => p(resolve, row));
  }

  const fieldPredicates = [];

  for (const [rawField, rawValues] of Object.entries(group)) {
    const { field, matchFn, allRequired, windash, hasExists, isFieldRef } = parseFieldModifiers(rawField);

    if (hasExists) {
      // |exists modifier: check if field is present/absent
      const expectExists = rawValues === true || rawValues === "true";
      fieldPredicates.push((resolve, row) => {
        const v = resolve(field, row);
        return expectExists ? (v !== undefined && v !== "") : (v === undefined || v === "");
      });
      continue;
    }

    // |fieldref: values are field names, resolved at match time
    if (isFieldRef) {
      let refFields = Array.isArray(rawValues) ? rawValues : [rawValues];
      refFields = refFields.map(v => v === null ? "" : String(v));
      fieldPredicates.push((resolve, row) => {
        const fv = resolve(field, row);
        if (fv === undefined || fv === "") return false;
        return refFields.some(ref => {
          const rv = resolve(ref, row);
          if (rv === undefined || rv === "") return false;
          return matchFn(fv, rv);
        });
      });
      continue;
    }

    // Normalize values to array
    let values = Array.isArray(rawValues) ? rawValues : [rawValues];
    values = values.map(v => v === null ? "" : String(v));

    // |windash expansion: for each value, also add variant with - replaced by /
    if (windash) {
      const expanded = [];
      for (const v of values) {
        expanded.push(v);
        if (v.includes("-")) expanded.push(v.replace(/-/g, "/"));
        if (v.includes("/")) expanded.push(v.replace(/\//g, "-"));
      }
      values = [...new Set(expanded)];
    }

    if (allRequired) {
      // ALL values must match (AND)
      fieldPredicates.push((resolve, row) => {
        const fv = resolve(field, row);
        if (fv === undefined || fv === "") return false;
        return values.every(sv => matchFn(fv, sv));
      });
    } else {
      // ANY value matches (OR)
      fieldPredicates.push((resolve, row) => {
        const fv = resolve(field, row);
        if (fv === undefined || fv === "") {
          // Check if any search value is empty string (match against missing)
          return values.some(sv => sv === "");
        }
        return values.some(sv => matchFn(fv, sv));
      });
    }
  }

  // All field conditions must match (AND within a group)
  return (resolve, row) => fieldPredicates.every(p => p(resolve, row));
}

/**
 * Parse a Sigma condition string and compile into a predicate.
 *
 * Supports: `selection`, `selection and not filter`, `1 of selection*`,
 * `all of them`, `selection1 or selection2`, parenthesized expressions.
 *
 * @param {string} condition - Condition string from the rule
 * @param {object} detection - Detection block with all named groups
 * @returns {Function} (resolve, row) => boolean
 */
function compileCondition(condition, detection) {
  if (!condition) return () => false;

  // Pre-compile all named groups
  const groupPredicates = {};
  for (const [name, group] of Object.entries(detection)) {
    if (name === "condition" || name === "timeframe") continue;
    groupPredicates[name] = compileGroup(group);
  }

  // Tokenize the condition string
  const tokens = tokenize(condition);

  // Parse into an AST and compile
  const ast = parseExpr(tokens, 0, groupPredicates, detection);
  return ast.fn;
}

/**
 * Tokenize a condition string into words and operators.
 */
function tokenize(condition) {
  const tokens = [];
  let i = 0;
  const s = condition.trim();

  while (i < s.length) {
    // Skip whitespace
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;

    // Parentheses
    if (s[i] === "(") { tokens.push({ type: "LPAREN" }); i++; continue; }
    if (s[i] === ")") { tokens.push({ type: "RPAREN" }); i++; continue; }

    // Words (keywords and identifiers)
    let word = "";
    while (i < s.length && /[^\s()]+/.test(s[i])) {
      word += s[i]; i++;
      // Handle pipe in "1 of selection*" patterns
      if (s[i] === "|") break;
    }

    if (word === "and") tokens.push({ type: "AND" });
    else if (word === "or") tokens.push({ type: "OR" });
    else if (word === "not") tokens.push({ type: "NOT" });
    else if (word === "1") tokens.push({ type: "NUM", value: 1 });
    else if (word === "all") tokens.push({ type: "ALL" });
    else if (word === "of") tokens.push({ type: "OF" });
    else if (word === "them") tokens.push({ type: "THEM" });
    else if (/^\d+$/.test(word)) tokens.push({ type: "NUM", value: parseInt(word) });
    else tokens.push({ type: "IDENT", value: word });
  }

  return tokens;
}

/**
 * Recursive descent parser for Sigma condition expressions.
 * Two precedence tiers: `and` binds tighter than `or` (per the Sigma spec), so
 * `a or b and c` parses as `a or (b and c)`. A single flat level would have
 * (incorrectly) evaluated it left-to-right as `(a or b) and c`.
 * Returns { fn: (resolve, row) => boolean, pos: number }.
 */
function parseExpr(tokens, pos, groupPredicates, detection) {
  // OR tier (lowest precedence)
  let left = parseAndExpr(tokens, pos, groupPredicates, detection);
  pos = left.pos;
  while (tokens[pos]?.type === "OR") {
    pos++;
    const right = parseAndExpr(tokens, pos, groupPredicates, detection);
    pos = right.pos;
    const leftFn = left.fn, rightFn = right.fn;
    left = { fn: (resolve, row) => leftFn(resolve, row) || rightFn(resolve, row), pos };
  }
  return left;
}

function parseAndExpr(tokens, pos, groupPredicates, detection) {
  // AND tier (binds tighter than OR)
  let left = parseTerm(tokens, pos, groupPredicates, detection);
  pos = left.pos;
  while (tokens[pos]?.type === "AND") {
    pos++;
    const right = parseTerm(tokens, pos, groupPredicates, detection);
    pos = right.pos;
    const leftFn = left.fn, rightFn = right.fn;
    left = { fn: (resolve, row) => leftFn(resolve, row) && rightFn(resolve, row), pos };
  }
  return left;
}

function parseTerm(tokens, pos, groupPredicates, detection) {
  if (pos >= tokens.length) return { fn: () => false, pos };

  const tok = tokens[pos];

  // NOT
  if (tok.type === "NOT") {
    const inner = parseTerm(tokens, pos + 1, groupPredicates, detection);
    const innerFn = inner.fn;
    return { fn: (resolve, row) => !innerFn(resolve, row), pos: inner.pos };
  }

  // Parenthesized expression
  if (tok.type === "LPAREN") {
    const inner = parseExpr(tokens, pos + 1, groupPredicates, detection);
    let endPos = inner.pos;
    if (tokens[endPos]?.type === "RPAREN") endPos++;
    return { fn: inner.fn, pos: endPos };
  }

  // "1 of selection*" / "all of them" / "1 of them"
  if ((tok.type === "NUM" || tok.type === "ALL") && tokens[pos + 1]?.type === "OF") {
    const count = tok.type === "ALL" ? Infinity : tok.value;
    pos += 2; // skip "of"
    let matchNames;
    if (tokens[pos]?.type === "THEM") {
      // "all of them" — all detection groups
      matchNames = Object.keys(groupPredicates);
      pos++;
    } else if (tokens[pos]?.type === "IDENT") {
      // "1 of selection*" — wildcard match
      const pattern = tokens[pos].value;
      pos++;
      if (pattern.endsWith("*")) {
        const prefix = pattern.slice(0, -1);
        matchNames = Object.keys(groupPredicates).filter(n => n.startsWith(prefix));
      } else {
        matchNames = [pattern];
      }
    } else {
      matchNames = Object.keys(groupPredicates);
    }

    const fns = matchNames.map(n => groupPredicates[n]).filter(Boolean);
    const requiredCount = count === Infinity ? fns.length : count;
    return {
      fn: (resolve, row) => {
        let matched = 0;
        for (const f of fns) {
          if (f(resolve, row)) { matched++; if (matched >= requiredCount) return true; }
        }
        return false;
      },
      pos,
    };
  }

  // Simple identifier reference
  if (tok.type === "IDENT") {
    const name = tok.value;
    const predFn = groupPredicates[name] || (() => false);
    return { fn: predFn, pos: pos + 1 };
  }

  // Fallback
  return { fn: () => false, pos: pos + 1 };
}

/**
 * Compile a complete Sigma rule's detection block into a single predicate.
 *
 * @param {object} detection - The rule's `detection` block (groups + condition)
 * @returns {Function} (resolve, row) => boolean
 */
function compileDetection(detection) {
  if (!detection || !detection.condition) return () => false;

  const conditions = Array.isArray(detection.condition) ? detection.condition : [detection.condition];

  // Multiple conditions = OR
  const predicates = conditions.map(c => compileCondition(c, detection));
  if (predicates.length === 1) return predicates[0];
  return (resolve, row) => predicates.some(p => p(resolve, row));
}

module.exports = { compileDetection, compileGroup, compileCondition, parseFieldModifiers };
