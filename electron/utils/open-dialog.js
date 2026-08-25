/**
 * Native open-dialog defaults.
 *
 * showHiddenFiles reveals dot-directories (e.g. ~/.claude) on macOS.
 *
 * Platform rule (Electron): on Windows and Linux an open dialog cannot be both a file
 * selector and a directory selector. Passing ["openFile", "openDirectory"] there shows a
 * FOLDER picker and drops `filters` entirely, so the analyst can neither pick a file nor
 * choose a file type. Only macOS supports the combined dialog. Callers that legitimately
 * accept either therefore declare which side wins off-macOS via `prefer`, and expose a
 * separate folder entry point so directory ingest stays reachable.
 */

const FILE_PROPERTY = "openFile";
const DIRECTORY_PROPERTY = "openDirectory";

function withShowHiddenFiles(properties) {
  const list = Array.isArray(properties) ? [...properties] : ["openFile"];
  if (!list.includes("showHiddenFiles")) list.push("showHiddenFiles");
  return list;
}

/**
 * Drop the unsupported half of a file+directory dialog on Windows/Linux.
 * @param {string[]} properties
 * @param {{ platform?: string, prefer?: "file"|"directory" }} opts
 */
function resolveSelectionProperties(properties, { platform = process.platform, prefer = "file" } = {}) {
  const list = Array.isArray(properties) ? [...properties] : ["openFile"];
  if (platform === "darwin") return list;
  if (!list.includes(FILE_PROPERTY) || !list.includes(DIRECTORY_PROPERTY)) return list;
  const dropped = prefer === "directory" ? FILE_PROPERTY : DIRECTORY_PROPERTY;
  return list.filter((property) => property !== dropped);
}

function canSelectFiles(properties) {
  return Array.isArray(properties) && properties.includes(FILE_PROPERTY);
}

/**
 * Guarantee an escape hatch in the file-type dropdown. Without a wildcard entry a narrow
 * filter list hides everything else, which reads as "the dialog won't let me pick my file".
 */
function withAllFilesFilter(filters, properties) {
  if (!Array.isArray(filters) || filters.length === 0) return filters;
  if (!canSelectFiles(properties)) return filters;
  if (filters.some((filter) => (filter?.extensions || []).includes("*"))) return filters;
  return [...filters, { name: "All Files", extensions: ["*"] }];
}

/**
 * Options for dialog.showOpenDialog with hidden files enabled and platform-legal
 * file/directory properties.
 *
 * @param {object} options standard showOpenDialog options, plus:
 *   `prefer` — "file" (default) or "directory": which selection mode survives on
 *   Windows/Linux when both were requested. Stripped before reaching Electron.
 */
function openDialogOptions(options = {}) {
  const { prefer = "file", ...rest } = options;
  const resolved = resolveSelectionProperties(rest.properties, { prefer });
  return {
    ...rest,
    filters: withAllFilesFilter(rest.filters, resolved),
    properties: withShowHiddenFiles(resolved),
  };
}

module.exports = {
  withShowHiddenFiles,
  openDialogOptions,
  resolveSelectionProperties,
  withAllFilesFilter,
};
