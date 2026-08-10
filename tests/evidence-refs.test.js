const assert = require("node:assert/strict");
const test = require("node:test");

test("collectEvidenceRefs deduplicates direct and fallback row references", async () => {
  const { collectEvidenceRefs, groupEvidenceRefs } = await import("../src/utils/evidence-refs.js");
  const refs = collectEvidenceRefs({
    evidenceRefs: [{ tabId: "tab-a", rowId: 7 }, { tabId: "tab-a", rowId: 7 }],
    itemRowids: [8, "9", "bad", 0],
  }, { fallbackTabId: "tab-main" });

  assert.deepEqual(refs, [
    { tabId: "tab-a", rowId: 7 },
    { tabId: "tab-main", rowId: 8 },
    { tabId: "tab-main", rowId: 9 },
  ]);

  const grouped = groupEvidenceRefs(refs);
  assert.deepEqual([...grouped.values()], [
    { tabId: "tab-a", rowIds: [7] },
    { tabId: "tab-main", rowIds: [8, 9] },
  ]);
});

test("collectEvidenceRefs walks findings and incidents referenced by result objects", async () => {
  const { collectEvidenceRefs } = await import("../src/utils/evidence-refs.js");
  const findings = [
    { id: "f1", evidenceRefs: [{ tabId: "tab-a", rowId: 11 }] },
    { id: "f2", events: [{ evidenceRefs: [{ tabId: "tab-b", rowId: 22 }] }] },
  ];
  const incidents = [
    { id: "i1", findingIds: ["f1", "f2"], evidenceRefs: [{ tabId: "tab-c", rowId: 33 }] },
  ];

  const refs = collectEvidenceRefs(
    { incidentIds: ["i1"], findingIds: ["f1"] },
    { relatedFindings: findings, relatedIncidents: incidents, fallbackTabId: "tab-main" },
  );

  assert.deepEqual(refs, [
    { tabId: "tab-a", rowId: 11 },
    { tabId: "tab-c", rowId: 33 },
    { tabId: "tab-b", rowId: 22 },
  ]);
});
