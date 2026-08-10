const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULT_LEVELS = ["critical", "high", "medium", "low", "informational"];
const LEVEL_RANK = ["informational", "low", "medium", "high", "critical"];
const STATUS_LIST = ["stable", "test", "experimental"];

function createScanOutputPaths(outputMode = "csv") {
  const ts = Date.now();
  const tmpOutput = path.join(os.tmpdir(), `tle-hayabusa-${ts}.csv`);
  const tmpHtmlReport = path.join(os.tmpdir(), `tle-hayabusa-report-${ts}.html`);
  const outputExt = outputMode === "csv" ? ".csv" : ".jsonl";
  const actualOutput = outputMode !== "csv" ? tmpOutput.replace(".csv", outputExt) : tmpOutput;
  return { tmpOutput, tmpHtmlReport, actualOutput };
}

function buildScanCommand({ dirPath, options = {}, outputPaths, warnings = [] }) {
  const levels = Array.isArray(options.levels) && options.levels.length > 0 ? options.levels : DEFAULT_LEVELS;
  const selectedStatuses = Array.isArray(options.statuses) && options.statuses.length > 0
    ? options.statuses.filter((status) => STATUS_LIST.includes(status))
    : STATUS_LIST;

  let minLevel = LEVEL_RANK.find((level) => levels.includes(level)) || "informational";
  const raiseMinLevel = (floor) => {
    if (LEVEL_RANK.indexOf(minLevel) < LEVEL_RANK.indexOf(floor)) minLevel = floor;
  };
  let statusFilter = selectedStatuses.length < STATUS_LIST.length ? selectedStatuses : null;

  const outputMode = options.outputMode || "csv";
  const subcommand = outputMode === "json" || outputMode === "jsonl" ? "json-timeline" : "csv-timeline";
  const profile = options.profile || "verbose";

  const args = [
    subcommand,
    "-d", dirPath,
    "-o", outputPaths.actualOutput,
    "-p", profile,
    "--no-wizard",
    "-q",
    "-H", outputPaths.tmpHtmlReport,
  ];

  if (outputMode === "jsonl") args.push("--jsonl-output");

  const ruleSet = options.ruleSet || "all";
  if (ruleSet === "core") {
    raiseMinLevel("high");
    statusFilter = statusFilter || ["stable", "test"];
  } else if (ruleSet === "core+") {
    raiseMinLevel("medium");
    statusFilter = statusFilter || ["stable", "test"];
  } else if (ruleSet === "core++") {
    raiseMinLevel("medium");
  } else if (ruleSet === "et") {
    args.push("--include-tag", "detection.emerging_threats");
  } else if (ruleSet === "th") {
    args.push("--include-tag", "detection.threat_hunting");
  }

  args.push("-m", minLevel);
  if (statusFilter?.length > 0) {
    for (const status of statusFilter) args.push("--include-status", status);
  }

  if (options.recoverRecords) args.push("-x");
  if (options.timelineStart) args.push("--timeline-start", options.timelineStart);
  if (options.timelineEnd) args.push("--timeline-end", options.timelineEnd);
  if (options.utc) args.push("-U");
  if (options.provenRules) args.push("-P");
  if (options.enableNoisy) args.push("-n");
  if (options.enableDeprecated) args.push("-D");
  if (options.enableUnsupported) args.push("-u");
  if (options.eidFilter) args.push("-E");
  if (options.includeTags?.length > 0) args.push("--include-tag", ...options.includeTags);
  if (options.excludeTags?.length > 0) args.push("--exclude-tag", ...options.excludeTags);
  if (options.includeComputers?.length > 0) args.push("--include-computer", ...options.includeComputers);
  if (options.excludeComputers?.length > 0) args.push("--exclude-computer", ...options.excludeComputers);
  if (options.includeEids?.length > 0) args.push("--include-eid", ...options.includeEids);
  if (options.excludeEids?.length > 0) args.push("--exclude-eid", ...options.excludeEids);
  if (options.enableAllRules) args.push("-A");
  if (options.scanAllEvtxFiles) args.push("-a");
  if (options.rulesPath) args.push("-r", options.rulesPath);
  if (options.rulesConfig) args.push("-c", options.rulesConfig);

  if (options.geoIpDir) {
    try {
      const mmdbFiles = fs.readdirSync(options.geoIpDir).filter((file) => file.endsWith(".mmdb"));
      if (mmdbFiles.length > 0) {
        args.push("-G", options.geoIpDir);
      } else {
        warnings.push(`GeoIP skipped: no .mmdb files found in ${options.geoIpDir}. Download MaxMind GeoLite2 databases first.`);
      }
    } catch {
      warnings.push(`GeoIP skipped: cannot read directory ${options.geoIpDir}`);
    }
  }

  return {
    args,
    outputMode,
    profile,
    levels,
    selectedStatuses,
    minLevel,
    statusFilter,
    subcommand,
  };
}

function buildGenericCommand(subcommand, dirPath, outputPath, extraArgs = []) {
  return [subcommand, "-d", dirPath, "-o", outputPath, "-q", ...extraArgs];
}

function getAvailableProfiles() {
  return [
    { id: "minimal", label: "Minimal", desc: "Timestamp + Rule + Level + Computer" },
    { id: "standard", label: "Standard", desc: "Minimal + Channel + EventID + RecordID" },
    { id: "verbose", label: "Verbose", desc: "Standard + Details + ExtraFieldInfo + MitreTags (default)" },
    { id: "all-field-info", label: "All Fields", desc: "All event fields in one column" },
    { id: "all-field-info-verbose", label: "All Fields Verbose", desc: "Verbose + all event fields" },
    { id: "super-verbose", label: "Super Verbose", desc: "Everything including RuleFile/RuleID" },
    { id: "timesketch-minimal", label: "Timesketch Minimal", desc: "Timesketch-compatible minimal" },
    { id: "timesketch-verbose", label: "Timesketch Verbose", desc: "Timesketch-compatible verbose" },
  ];
}

module.exports = {
  createScanOutputPaths,
  buildScanCommand,
  buildGenericCommand,
  getAvailableProfiles,
};
