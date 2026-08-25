const fs = require("fs");
const path = require("path");

const DEFAULT_NOISY_RULES = [
  {
    id: "d372ec1b-8c88-6601-d01f-30886bc7ccc4",
    title: "NotPetya Ransomware Activity",
    comment: "NotPetya Ransomware Activity - noisy in broad enterprise hunts",
  },
];

function getRulesConfigDirForBin(binPath) {
  if (!binPath) return null;
  return path.join(path.dirname(binPath), "rules", "config");
}

function ensureDefaultNoisyRules(binPath, options = {}) {
  const configDir = options.configDir || getRulesConfigDirForBin(binPath);
  if (!configDir) return { updated: false, path: null, added: [] };
  try {
    fs.mkdirSync(configDir, { recursive: true });
  } catch {
    return { updated: false, path: path.join(configDir, "noisy_rules.txt"), added: [] };
  }

  const noisyPath = path.join(configDir, "noisy_rules.txt");
  let current = "";
  try {
    current = fs.existsSync(noisyPath) ? fs.readFileSync(noisyPath, "utf8") : "";
  } catch {
    return { updated: false, path: noisyPath, added: [] };
  }

  const existingIds = new Set();
  for (const line of current.split(/\r?\n/)) {
    const match = line.match(/^\s*([0-9a-f]{8}-[0-9a-f-]{27,})/i);
    if (match) existingIds.add(match[1].toLowerCase());
  }

  const additions = DEFAULT_NOISY_RULES.filter((rule) => !existingIds.has(rule.id.toLowerCase()));
  if (additions.length === 0) return { updated: false, path: noisyPath, added: [] };

  const prefix = current && !current.endsWith("\n") ? "\n" : "";
  const lines = additions.map((rule) => `${rule.id} # ${rule.comment}`);
  try {
    fs.appendFileSync(noisyPath, `${prefix}${lines.join("\n")}\n`, "utf8");
  } catch {
    return { updated: false, path: noisyPath, added: [] };
  }
  return { updated: true, path: noisyPath, added: additions.map((rule) => rule.id) };
}

module.exports = {
  DEFAULT_NOISY_RULES,
  ensureDefaultNoisyRules,
  getRulesConfigDirForBin,
};
