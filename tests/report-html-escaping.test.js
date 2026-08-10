// Regression test for HTML injection via report tag colors (release review L4).
//
// buildReportHtml escapes tag NAMES via esc() but interpolated tag COLORS raw into
// style="" attributes. tagColors arrives over IPC and can come from a restored .tle
// session file (hand-editable), so a value like `red"><img ...>` broke out of the
// attribute and injected markup into the generated standalone report (self-XSS). Fix
// validates each color against a strict hex pattern, falling back to the default.

const test = require("node:test");
const assert = require("node:assert/strict");
const { buildReportHtml } = require("../electron/ipc/export-handlers");

const baseData = {
  headers: ["ts", "msg"],
  totalRows: 1,
  tagCount: 1,
  taggedRowCount: 1,
  bookmarkCount: 0,
  bookmarkedRows: [],
  tsRange: null,
  tagSummary: [{ tag: "Evil", cnt: 1 }],
  taggedGroups: { Evil: [] },
};

test("buildReportHtml neutralizes a malicious tag color (no attribute breakout)", () => {
  const malicious = 'red"><img src=x onerror=alert(document.location)>';
  const html = buildReportHtml(baseData, "case.csv", { Evil: malicious });
  assert.ok(!html.includes("<img src=x onerror"), "must not inject an <img> tag");
  assert.ok(!html.includes('onerror=alert'), "must not emit the onerror payload");
  assert.ok(html.includes("#8b949e"), "a rejected color must fall back to the default");
});

test("buildReportHtml preserves a valid hex tag color", () => {
  const html = buildReportHtml(
    { ...baseData, tagSummary: [{ tag: "Good", cnt: 2 }], taggedGroups: { Good: [] } },
    "case.csv",
    { Good: "#E85D2A" }
  );
  assert.ok(html.includes("#E85D2A"), "a valid hex color should be kept verbatim");
});

test("buildReportHtml still escapes the tag name itself", () => {
  const html = buildReportHtml(
    { ...baseData, tagSummary: [{ tag: '<script>x</script>', cnt: 1 }], taggedGroups: {} },
    "case.csv",
    {}
  );
  assert.ok(!html.includes("<script>x</script>"), "tag name must be HTML-escaped");
  assert.ok(html.includes("&lt;script&gt;"), "tag name should appear escaped");
});
