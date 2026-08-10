"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { AI_DETECTION_RULES } = require("../electron/analyzers/ai-history/detection-rules");
const {
  analyzeAiHistory,
  analyzeAiHistoryRows,
  findMatchesInText,
  compileRules,
  COMPILED_RULES,
} = require("../electron/analyzers/ai-history/index");
const {
  luhnValid,
  creditCardLikely,
  ibanValid,
  shannonEntropy,
  isPlaceholderValue,
  isKnownExampleValue,
  isFilesystemPathLike,
  redactValue,
  fingerprint,
} = require("../electron/analyzers/ai-history/validators");

const row = (text, extra = {}) => ({ recordId: "1", role: "user", tool: "Claude Code", timestamp: "2026-01-01 00:00:00", text, ...extra });
const ruleIds = (text, role = "user", rules = COMPILED_RULES) => findMatchesInText(text, role, rules).map((h) => h.rule.id);
const join = (...parts) => parts.join("");
const AWS_KEY = join("AK", "IA7X2H4Q9Z8M1N3P5R");
const GCP_KEY = join("AI", "zaSyB1234567890abcdefghijklmnopqrstuv");
const GITHUB_KEY = join("gh", "p_Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3I2");
const GITHUB_KEY_2 = join("gh", "p_A1B2C3D4E5F6G7H8I9J0K1L2M3N4P5Q6R7S8");
const GITHUB_FINE_GRAINED = join("github_", "pat_11ABCDEFG0aBcDeFgHiJkL_1234567890abcdefghijklmnopqrstuvwxyz");
const GITLAB_KEY = join("gl", "pat-aB3dE5gH7jK9mN2pQ4rS");
const OPENAI_KEY = join("sk-proj-Qw7Er9Ty2Ui4Op6As8Df", "T3BlbkFJ", "Gh1Jk3Lm5Nz7Xc9Vb0Xy4Za");
const OPENAI_EXAMPLE_KEY = join("sk-proj-aaaaaaaaaaaaaaaaaaaa", "T3BlbkFJ", "bbbbbbbbbbbbbbbbbbbb");
const ANTHROPIC_KEY = join("sk-", "ant-api03-abcdefghijklmnopqrstuvwxyz0123456789");
const STRIPE_LIVE_KEY = join("sk_", "live_abcdefghijklmnopqrstuvwx");
const SLACK_KEY = join("xo", "xb-123456789012-Z9y8X7w6V5u4T3s2R1q0");
const SLACK_EXAMPLE_KEY = join("xo", "xb-123456789012-abcdefghijklmnopqrst");
const pemMarker = (kind, end = false) => join("-----", end ? "END" : "BEGIN", " ", kind ? `${kind} ` : "", "PRIVATE KEY-----");

// ───────────────────────── ReDoS-gate regression ─────────────────────────
test("every catalog rule survives the compileSafeRegex ReDoS gate (none dropped)", () => {
  const compiled = compileRules(AI_DETECTION_RULES);
  assert.equal(compiled.length, AI_DETECTION_RULES.length,
    `dropped rules: ${AI_DETECTION_RULES.filter((r) => !compiled.find((c) => c.id === r.id)).map((r) => r.id).join(", ")}`);
});

test("rule ids are unique", () => {
  const ids = AI_DETECTION_RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

// ───────────────────────── Named-provider positives ──────────────────────
test("detects named provider keys / tokens / private keys", () => {
  const cases = [
    [AWS_KEY, "aws-access-key"],
    [`here is my key ${GCP_KEY} end`, "gcp-api-key"],
    [GITHUB_KEY, "github-pat"],
    [GITHUB_FINE_GRAINED, "github-fine-grained"],
    [GITLAB_KEY, "gitlab-pat"],
    [OPENAI_KEY, "openai-key"],
    [ANTHROPIC_KEY, "anthropic-key"],
    [STRIPE_LIVE_KEY, "stripe-live-key"],
    [SLACK_KEY, "slack-token"],
    ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_-x", "jwt"],
    [join(pemMarker("OPENSSH"), "\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n", pemMarker("OPENSSH", true)), "pem-private-key"],
    [join(pemMarker("RSA"), "\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n", pemMarker("RSA", true)), "pem-private-key"],
  ];
  for (const [text, id] of cases) {
    assert.ok(ruleIds(text).includes(id), `expected ${id} for: ${text.slice(0, 30)}`);
  }
});

test("detects generic credential assignments and creds-in-URL", () => {
  assert.ok(ruleIds('password = "S3cr3t!Hunter2pass"').includes("generic-secret-assignment"));
  assert.ok(ruleIds('api_key: "x8F2k9Lm4Qp7Zt1Wv6Rn"').includes("generic-secret-assignment"));
  assert.ok(ruleIds("mongodb://admin:Sup3rSecretPwd99@db.internal:27017").includes("url-basic-auth"));
  assert.ok(ruleIds('Authorization: Bearer abcDEF1234567890ghIJKL').includes("auth-bearer-basic"));
});

test("reports multiple same-rule secrets in one row", () => {
  const first = GITHUB_KEY;
  const second = GITHUB_KEY_2;
  const { findings, summary } = analyzeAiHistoryRows([row(`first ${first} then ${second}`)], { mode: "quick", salt: "fixed" });
  const gh = findings.filter((f) => f.ruleId === "github-pat");
  assert.equal(gh.length, 2);
  assert.deepEqual(new Set(gh.map((f) => f.match)), new Set([first, second]));
  assert.equal(summary.uniqueSecrets, 2);
});

test("private-key detection captures full PEM blocks for multiline reveal", () => {
  const pem = [
    pemMarker("RSA"),
    "MIIEowIBAAKCAQEAx8mE4n7VZ0p2YhU3tFh7q6Hk9nA4bC5dE6fG7hI8jK9l",
    "mN0oP1qR2sT3uV4wX5yZ6aB7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX8y",
    pemMarker("RSA", true),
  ].join("\n");
  const { findings } = analyzeAiHistoryRows([row(`stored private_key: ${pem}`)], { mode: "quick", salt: "fixed" });
  const hit = findings.find((f) => f.ruleId === "pem-private-key");
  assert.ok(hit);
  assert.ok(hit.match.includes(pemMarker("RSA")));
  assert.ok(hit.match.includes(pemMarker("RSA", true)));
  assert.ok(hit.match.includes("\n"));
});

test("private-key detection captures escaped newline PEM blocks", () => {
  const escapedPem = join("config private_key=\\\"", pemMarker(""), "\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n", pemMarker("", true), "\\\"");
  const { findings } = analyzeAiHistoryRows([row(escapedPem)], { mode: "quick", salt: "fixed" });
  const hit = findings.find((f) => f.ruleId === "pem-private-key");
  assert.ok(hit);
  assert.ok(hit.match.includes(pemMarker("")));
  assert.ok(hit.match.includes(pemMarker("", true)));
});

test("private-key detection expands JSON-escaped partial PEM bodies", () => {
  const partialPem = String.raw`{\"private_key\":\"${pemMarker("")}\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\nMIICWwIBAAKBgQC9c1exampleBodyLine==\",\"private_key_id\":\"abc123\"}`;
  const { findings } = analyzeAiHistoryRows([row(partialPem)], { mode: "quick", salt: "fixed" });
  const hit = findings.find((f) => f.ruleId === "pem-private-key");
  assert.ok(hit);
  assert.ok(hit.match.includes(pemMarker("")));
  assert.ok(hit.match.includes("MIIEvgIBADANBgkqhkiG9w0BAQEFAASC"));
  assert.ok(hit.match.includes("MIICWwIBAAKBgQC9c1exampleBodyLine=="));
  assert.ok(!hit.match.includes("private_key_id"));
  assert.ok(hit.match.length > pemMarker("").length);
});

test("private-key detection expands double-escaped partial PEM bodies", () => {
  const partialPem = String.raw`{\\\"private_key\\\":\\\"${pemMarker("")}\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\\nMIICWwIBAAKBgQC9c1exampleBodyLine==\\\",\\\"private_key_id\\\":\\\"abc123\\\"}`;
  const { findings } = analyzeAiHistoryRows([row(partialPem)], { mode: "quick", salt: "fixed" });
  const hit = findings.find((f) => f.ruleId === "pem-private-key");
  assert.ok(hit);
  assert.ok(hit.match.includes("MIIEvgIBADANBgkqhkiG9w0BAQEFAASC"));
  assert.ok(hit.match.includes("MIICWwIBAAKBgQC9c1exampleBodyLine=="));
  assert.ok(!hit.match.includes("private_key_id"));
});

test("private-key detection ignores tiny PEM example fragments", () => {
  const partialPem = String.raw`{\"private_key\":\"${pemMarker("RSA")}\nMIIEvg\",\"private_key_id\":\"abc123\"}`;
  const result = analyzeAiHistoryRows([row(partialPem)], { mode: "quick", salt: "fixed" });
  assert.equal(result.findings.some((f) => f.ruleId === "pem-private-key"), false);
});

test("private-key detection ignores marker-only prose", () => {
  const result = analyzeAiHistoryRows([
    row(`Real PEM ("${pemMarker("RSA")}") will not match a quoted placeholder.`),
  ], { mode: "quick", salt: "fixed" });
  assert.equal(result.findings.some((f) => f.ruleId === "pem-private-key"), false);
});

// ───────────────────────── False positives ───────────────────────────────
test("does NOT flag prose mentioning credential concepts", () => {
  for (const text of [
    "I forgot my password again and had to reset it",
    "Use a strong password and rotate your token regularly",
    "the api key should be stored in an environment variable",
  ]) {
    assert.deepEqual(ruleIds(text), [], `false positive on: ${text}`);
  }
});

test("drops documentation placeholders", () => {
  assert.deepEqual(ruleIds('api_key = "your_api_key_here"'), []);
  assert.deepEqual(ruleIds('password: "<your-password>"'), []);
  assert.deepEqual(ruleIds('secret = "${SECRET_KEY}"'), []);
  assert.deepEqual(ruleIds('password = "xxxxxxxx"'), []);
});

test("drops known vendor documentation examples", () => {
  const awsExample = join("AK", "IAIOSFODNN7EXAMPLE");
  assert.ok(isKnownExampleValue(awsExample));
  assert.deepEqual(ruleIds(awsExample), []);
  assert.deepEqual(ruleIds(OPENAI_EXAMPLE_KEY), []);
  assert.deepEqual(ruleIds(SLACK_EXAMPLE_KEY), []);
});

test("generic credential assignment requires a stronger secret-shaped value", () => {
  assert.deepEqual(ruleIds('password = "password123"'), []);
  assert.deepEqual(ruleIds('api_key = "abcdefghijkl"'), []);
  assert.ok(ruleIds('client_secret = "N9v!xL2pQ7zR4tY8mK3s"').includes("generic-secret-assignment"));
});

// ───────────────────────── Validators ────────────────────────────────────
test("luhnValid accepts a valid card and rejects an invalid one", () => {
  assert.ok(luhnValid("4242 4242 4242 4242"));   // Stripe test Visa
  assert.ok(!luhnValid("4242 4242 4242 4241"));
});

test("creditCardLikely rejects all-zero and non-card grouped numeric artifacts", () => {
  assert.ok(creditCardLikely("4242 4242 4242 4242"));
  assert.ok(!creditCardLikely("00000000-0000-000"));
  assert.ok(!creditCardLikely("0000 0000 0000 0000"));
});

test("ibanValid checks mod-97", () => {
  assert.ok(ibanValid("GB82 WEST 1234 5698 7654 32"));
  assert.ok(!ibanValid("GB00 WEST 1234 5698 7654 32"));
});

test("shannonEntropy ranks random higher than repetitive", () => {
  assert.ok(shannonEntropy("aaaaaaaaaaaaaaaa") < 1);
  assert.ok(shannonEntropy("aB3$xK9-zQ2!mP7&") > 3);
});

test("isPlaceholderValue flags obvious placeholders, not real secrets", () => {
  assert.ok(isPlaceholderValue("your_api_key"));
  assert.ok(isPlaceholderValue("xxxxxxxx"));
  assert.ok(isPlaceholderValue("<token>"));
  assert.ok(!isPlaceholderValue("x8F2k9Lm4Qp7Zt1Wv6Rn"));
});

test("isFilesystemPathLike identifies local paths before entropy scoring", () => {
  assert.ok(isFilesystemPathLike("/Users/dfir/Downloads/shouldve_paid_the_ransom_UDEMY_SHINYHUNTERS/supabase_project_downloads/dropbox_tuktuk_c2_files"));
  assert.ok(isFilesystemPathLike("C:/Users/dfir/AppData/Roaming/Cursor/User/state.vscdb"));
  assert.ok(!isFilesystemPathLike("N9vXl2pQ7zR4tY8mK3sA1bC2dE3fG4h"));
});

// ───────────────────────── Quick vs Deep (PII gating) ─────────────────────
test("PII fires only in Deep mode", () => {
  const rows = [row("contact me at jane.doe@acmecorp.io about card 4242 4242 4242 4242")];
  const quick = analyzeAiHistoryRows(rows, { mode: "quick" });
  assert.equal(quick.findings.filter((f) => f.category === "pii").length, 0);
  const deep = analyzeAiHistoryRows(rows, { mode: "deep" });
  const ids = deep.findings.map((f) => f.ruleId);
  assert.ok(ids.includes("pii-email"));
  assert.ok(ids.includes("pii-credit-card"));
});

test("Deep phone detection requires nearby phone context", () => {
  assert.equal(analyzeAiHistoryRows([row("build number 15551234567 completed")], { mode: "deep" }).findings.some((f) => f.ruleId === "pii-phone"), false);
  assert.equal(analyzeAiHistoryRows([row("call my mobile +1 555 123 4567")], { mode: "deep" }).findings.some((f) => f.ruleId === "pii-phone"), true);
});

test("Deep credit-card detection rejects all-zero UUID-like numeric artifacts", () => {
  const result = analyzeAiHistoryRows([row("00000000-0000-000")], { mode: "deep" });
  assert.equal(result.findings.some((f) => f.ruleId === "pii-credit-card"), false);
});

test("Deep entropy detection ignores directory paths", () => {
  const result = analyzeAiHistoryRows([
    row("/Users/dfir/Downloads/shouldve_paid_the_ransom_UDEMY_SHINYHUNTERS/supabase_project_downloads/dropbox_tuktuk_c2_files"),
  ], { mode: "deep" });
  assert.equal(result.findings.some((f) => f.ruleId === "high-entropy"), false);
});

test("confidence tiers use verified, likely, suspicious, informational", () => {
  const rows = [
    row(GITHUB_KEY),
    row('client_secret = "N9v!xL2pQ7zR4tY8mK3s"'),
    row("contact jane.doe@acmecorp.io"),
    row("card 4012 8888 8888 1881"),
  ];
  const { summary } = analyzeAiHistoryRows(rows, { mode: "deep", salt: "fixed" });
  assert.ok(summary.byConfidence.likely >= 1);
  assert.ok(summary.byConfidence.suspicious >= 1);
  assert.ok(summary.byConfidence.informational >= 1);
  assert.ok(summary.byConfidence.verified >= 1);
});

test("Stripe test keys and public test cards are downgraded", () => {
  const { findings } = analyzeAiHistoryRows([
    row("stripe sk_test_N9vXl2pQ7zR4tY8mK3sA"),
    row("card 4242 4242 4242 4242"),
  ], { mode: "deep", salt: "fixed" });
  const stripe = findings.find((f) => f.ruleId === "stripe-test-key");
  const card = findings.find((f) => f.ruleId === "pii-credit-card");
  assert.equal(stripe.severity, "low");
  assert.equal(stripe.confidence, "informational");
  assert.equal(card.severity, "low");
  assert.equal(card.confidence, "informational");
});

// ───────────────────────── Redaction / fingerprint / direction ───────────
test("findings redact by default, expose match in-memory, and tag leak direction", () => {
  const { findings } = analyzeAiHistoryRows([row(GITHUB_KEY)], { mode: "quick", salt: "t" });
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.ruleId, "github-pat");
  assert.match(f.redacted, /ghp_.*•.*\(\d+ chars\)/);
  assert.ok(!f.snippet.includes(GITHUB_KEY), "snippet must mask the secret");
  assert.equal(f.match, GITHUB_KEY); // cleartext for per-row reveal
  assert.equal(f.leakDirection, "user→service");
  assert.equal(f.fingerprint, fingerprint(GITHUB_KEY, "t"));
});

test("provided scan salt keeps incident fingerprints stable across rescans", () => {
  const a = analyzeAiHistoryRows([row(GITHUB_KEY)], { mode: "quick", salt: "tab-salt" });
  const b = analyzeAiHistoryRows([row(GITHUB_KEY)], { mode: "quick", salt: "tab-salt" });
  const c = analyzeAiHistoryRows([row(GITHUB_KEY)], { mode: "quick", salt: "other-tab-salt" });
  assert.equal(a.findings[0].fingerprint, b.findings[0].fingerprint);
  assert.notEqual(a.findings[0].fingerprint, c.findings[0].fingerprint);
});

test("assistant-role leak is tagged service→user", () => {
  const { findings } = analyzeAiHistoryRows([row(STRIPE_LIVE_KEY, { role: "assistant" })], { mode: "quick" });
  assert.equal(findings[0].leakDirection, "service→user");
});

test("summary rolls up severity, categories and unique secrets", () => {
  const rows = [
    row(AWS_KEY),
    row(STRIPE_LIVE_KEY),
    row(AWS_KEY), // same secret again → 2 findings, 1 unique fingerprint
  ];
  const { summary } = analyzeAiHistoryRows(rows, { mode: "quick", salt: "fixed" });
  assert.equal(summary.total, 3);
  assert.equal(summary.bySeverity.critical, 1); // stripe live
  assert.equal(summary.bySeverity.high, 2);      // 2x aws
  assert.equal(summary.uniqueSecrets, 2);        // aws (dup) + stripe
});

// ───────────────────────── DB-entry coverage / streaming ────────────────
function fakeAiMeta(records) {
  return {
    colMap: {
      Summary: "c0",
      FullText: "c1",
      RecordId: "c2",
      Role: "c3",
      Tool: "c4",
      Timestamp: "c5",
      SessionId: "c6",
      SourceFile: "c7",
      Workspace: "c8",
      MessageId: "c9",
    },
    db: {
      prepare(sql) {
        if (/SELECT COUNT\(\*\)/.test(sql)) return { get: () => ({ n: records.length }) };
        return {
          iterate: function* iterate() {
            for (const rec of records) yield rec;
          },
        };
      },
    },
  };
}

test("analyzeAiHistory reports FullText coverage from the actual FullText column", () => {
  const meta = fakeAiMeta([
    { c0: `preview with ${AWS_KEY}`, c1: "", c2: "1", c3: "user", c4: "Claude Code", c5: "2026-01-01 00:00:00" },
  ]);
  const result = analyzeAiHistory(meta, { mode: "quick", salt: "fixed" });
  assert.equal(result.summary.total, 1);
  assert.equal(result.fullTextAvailable, false);
  assert.equal(result.rowsWithFullText, 0);
  assert.equal(result.rowsSummaryOnly, 1);
  assert.ok(result.maxScannedChars > 0);
});

test("analyzeAiHistory streams rows and scans FullText before Summary", () => {
  const meta = fakeAiMeta([
    { c0: "summary only", c1: `full body ${GITHUB_KEY}`, c2: "7", c3: "user", c4: "Claude Code", c5: "2026-01-01 00:00:00" },
    { c0: `preview with ${STRIPE_LIVE_KEY}`, c1: "", c2: "8", c3: "assistant", c4: "ChatGPT", c5: "2026-01-01 00:00:01" },
  ]);
  const progress = [];
  const result = analyzeAiHistory(meta, { mode: "quick", salt: "fixed", progressCb: (p) => progress.push(p) });
  assert.equal(result.summary.total, 2);
  assert.equal(result.fullTextAvailable, true);
  assert.equal(result.rowsWithFullText, 1);
  assert.equal(result.rowsSummaryOnly, 1);
  assert.deepEqual(result.findings.map((f) => f.recordId).sort(), ["7", "8"]);
  assert.deepEqual(progress.at(-1), { phase: "ai-secrets", processed: 2, total: 2 });
});
