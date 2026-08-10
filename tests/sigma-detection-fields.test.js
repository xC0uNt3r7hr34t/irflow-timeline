const test = require("node:test");
const assert = require("node:assert/strict");
const { collectDetectionFields } = require("../electron/analyzers/sigma/detection-fields");

test("collectDetectionFields gathers selection keys and fieldref targets", () => {
  const fields = collectDetectionFields({
    selection: {
      "Image|endswith": "\\cmd.exe",
      "CommandLine|contains": "whoami",
      "TargetObject|fieldref": "Details",
    },
    filter: { EventID: "4688" },
    condition: "selection and not filter",
  });
  assert.ok(fields.has("Image"));
  assert.ok(fields.has("CommandLine"));
  assert.ok(fields.has("TargetObject"));
  assert.ok(fields.has("Details"));
  assert.ok(fields.has("EventID"));
  assert.equal(fields.has("condition"), false);
});
