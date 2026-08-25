const fsp = require("fs/promises");
const path = require("path");

const OUTPUT_IMAGE_RE = /\.(?:bmp|png|jpe?g)$/i;

function classifyOutputImage(filePath) {
  const base = path.basename(filePath);
  if (/(?:collage|aggregate|contact[-_ ]?sheet|bitmap)$/i.test(base.replace(/\.[^.]+$/, ""))) {
    return "collage";
  }
  return "tile";
}

function extractTileIndex(filePath) {
  const base = path.basename(filePath).replace(/\.[^.]+$/, "");
  const match = base.match(/(?:^|[_-])(\d{1,8})$/) || base.match(/^(\d{1,8})$/);
  return match ? Number(match[1]) : null;
}

async function walkOutputDirectory(dirPath, state, rootDir) {
  let entries;
  try {
    entries = await fsp.readdir(dirPath, { withFileTypes: true });
  } catch (err) {
    state.warnings.push(`Could not read output directory ${dirPath}: ${err.message}`);
    return;
  }

  for (const entry of entries) {
    const childPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      await walkOutputDirectory(childPath, state, rootDir);
      continue;
    }
    if (!entry.isFile() || !OUTPUT_IMAGE_RE.test(entry.name)) continue;
    const st = await fsp.stat(childPath);
    const kind = classifyOutputImage(childPath);
    const image = {
      path: childPath,
      relativePath: path.relative(rootDir, childPath),
      name: entry.name,
      kind,
      tileIndex: kind === "tile" ? extractTileIndex(childPath) : null,
      size: st.size,
      mtimeMs: st.mtimeMs,
      modifiedAt: st.mtime.toISOString(),
    };
    state.images.push(image);
  }
}

function summarizeOutputImages(images) {
  const summary = {
    imageCount: images.length,
    tileCount: 0,
    collageCount: 0,
    totalBytes: 0,
    folders: [],
  };
  const folders = new Set();
  for (const image of images) {
    if (image.kind === "collage") summary.collageCount += 1;
    else summary.tileCount += 1;
    summary.totalBytes += Number(image.size) || 0;
    folders.add(path.dirname(image.relativePath || image.path));
  }
  summary.folders = [...folders].sort((a, b) => a.localeCompare(b));
  return summary;
}

async function parseExtractionOutput(outputDir) {
  const state = { images: [], warnings: [] };
  try {
    const st = await fsp.stat(outputDir);
    if (!st.isDirectory()) {
      return {
        outputDir,
        images: [],
        summary: summarizeOutputImages([]),
        warnings: [`Output path is not a directory: ${outputDir}`],
      };
    }
  } catch {
    return {
      outputDir,
      images: [],
      summary: summarizeOutputImages([]),
      warnings: [`Output directory does not exist: ${outputDir}`],
    };
  }

  await walkOutputDirectory(outputDir, state, outputDir);
  state.images.sort((a, b) => a.relativePath.localeCompare(b.relativePath));
  return {
    outputDir,
    images: state.images,
    summary: summarizeOutputImages(state.images),
    warnings: state.warnings,
  };
}

module.exports = {
  OUTPUT_IMAGE_RE,
  classifyOutputImage,
  extractTileIndex,
  summarizeOutputImages,
  parseExtractionOutput,
};
