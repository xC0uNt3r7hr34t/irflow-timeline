/**
 * Native open-dialog defaults. showHiddenFiles reveals dot-directories (e.g. ~/.claude) on macOS.
 */

function withShowHiddenFiles(properties) {
  const list = Array.isArray(properties) ? [...properties] : ["openFile"];
  if (!list.includes("showHiddenFiles")) list.push("showHiddenFiles");
  return list;
}

/** Options for dialog.showOpenDialog with hidden files enabled. */
function openDialogOptions(options = {}) {
  return {
    ...options,
    properties: withShowHiddenFiles(options.properties),
  };
}

module.exports = { withShowHiddenFiles, openDialogOptions };
