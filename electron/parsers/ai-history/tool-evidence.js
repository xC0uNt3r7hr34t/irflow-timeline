/**
 * ai-history/tool-evidence.js — preserve structured AI tool-call evidence.
 *
 * Tool calls are commonly embedded in a larger assistant message. A row therefore keeps the
 * analyst-friendly command/description alongside the complete serialized input. For a row with
 * multiple tool calls, JSON arrays preserve call and argument boundaries without inventing shell
 * quoting that was not present in the source artifact.
 */

const TOOL_COMMAND_KEYS = ["command", "cmd", "shell_command", "shellCommand", "script"];
const TOOL_DESCRIPTION_KEYS = ["description", "explanation", "purpose"];

function parseJsonInput(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function serializeEvidenceValue(value) {
  if (value == null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function ownValue(obj, keys) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return undefined;
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, key) && obj[key] != null) return obj[key];
  }
  return undefined;
}

function toolInputCommand(input) {
  const parsed = parseJsonInput(input);
  return ownValue(parsed, TOOL_COMMAND_KEYS);
}

function toolInputDescription(input) {
  const parsed = parseJsonInput(input);
  return ownValue(parsed, TOOL_DESCRIPTION_KEYS);
}

function combineValues(values) {
  const present = values.filter((value) => value != null && serializeEvidenceValue(value) !== "");
  if (!present.length) return "";
  if (present.length === 1) return serializeEvidenceValue(present[0]);
  return serializeEvidenceValue(present);
}

/**
 * Build fields accepted by makeRow() from normalized `{ name, input }` calls.
 */
function buildToolEvidence(calls) {
  const valid = (Array.isArray(calls) ? calls : [])
    .filter((call) => call && typeof call === "object" && call.name)
    .map((call) => ({
      name: String(call.name),
      input: call.input,
    }));

  if (!valid.length) {
    return { toolName: "", toolCommand: "", toolInput: "", toolDescription: "" };
  }

  const toolNames = [...new Set(valid.map((call) => call.name))].join(", ");
  const commands = valid.map((call) => toolInputCommand(call.input));
  const descriptions = valid.map((call) => toolInputDescription(call.input));

  let toolInput = "";
  if (valid.length === 1) {
    toolInput = serializeEvidenceValue(valid[0].input);
  } else {
    toolInput = serializeEvidenceValue(valid.map((call) => ({
      name: call.name,
      input: parseJsonInput(call.input),
    })));
  }

  return {
    toolName: toolNames,
    toolCommand: combineValues(commands),
    toolInput,
    toolDescription: combineValues(descriptions),
  };
}

module.exports = {
  parseJsonInput,
  serializeEvidenceValue,
  toolInputCommand,
  toolInputDescription,
  buildToolEvidence,
};
