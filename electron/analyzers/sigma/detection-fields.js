/**
 * Collect Sigma field names referenced in a rule detection block (for SELECT narrowing).
 */

const { parseFieldModifiers } = require("./condition-compiler");

function collectFromGroup(group, fields) {
  if (!group || typeof group !== "object") return;
  if (Array.isArray(group)) {
    for (const item of group) collectFromGroup(item, fields);
    return;
  }
  for (const [rawField, rawValues] of Object.entries(group)) {
    const { field, isFieldRef } = parseFieldModifiers(rawField);
    if (field) fields.add(field);
    if (isFieldRef) {
      const vals = Array.isArray(rawValues) ? rawValues : [rawValues];
      for (const v of vals) {
        if (v != null && String(v).trim()) fields.add(String(v).trim());
      }
    }
  }
}

/**
 * @param {object} detection - Rule `detection` block
 * @returns {Set<string>} Sigma field names used in selections (not condition keys)
 */
function collectDetectionFields(detection) {
  const fields = new Set();
  if (!detection || typeof detection !== "object") return fields;
  for (const [key, val] of Object.entries(detection)) {
    if (key === "condition") continue;
    collectFromGroup(val, fields);
  }
  return fields;
}

module.exports = { collectDetectionFields };
