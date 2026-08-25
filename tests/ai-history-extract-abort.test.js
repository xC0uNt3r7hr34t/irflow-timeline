"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  createAiHistoryExtractAbortToken,
  requestAiHistoryExtractAbort,
  AiHistoryExtractAbortedError,
} = require("../electron/parsers/ai-history/extract-abort");

test("per-job abort tokens are independent", () => {
  const a = createAiHistoryExtractAbortToken("job-a");
  const b = createAiHistoryExtractAbortToken("job-b");

  requestAiHistoryExtractAbort("job-a");

  assert.throws(() => a.checkAbort(), AiHistoryExtractAbortedError);
  assert.doesNotThrow(() => b.checkAbort());

  a.dispose();
  b.dispose();
});

test("requestAiHistoryExtractAbort without jobId cancels all tokens", () => {
  const a = createAiHistoryExtractAbortToken();
  const b = createAiHistoryExtractAbortToken();
  requestAiHistoryExtractAbort();
  assert.throws(() => a.checkAbort(), AiHistoryExtractAbortedError);
  assert.throws(() => b.checkAbort(), AiHistoryExtractAbortedError);
  a.dispose();
  b.dispose();
});
