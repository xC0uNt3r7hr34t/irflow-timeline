const fs = require("fs");
const path = require("path");
const { executeAppBuilderAsJson } = require("app-builder-lib/out/util/appBuilder");

async function main() {
  const inputPath = process.argv[2] ? path.resolve(process.argv[2]) : "";
  const outputPath = process.argv[3] ? path.resolve(process.argv[3]) : "";

  if (!inputPath || !outputPath) {
    throw new Error("Usage: node scripts/generate-blockmap.js <input> <output>");
  }
  if (!fs.statSync(inputPath).isFile()) {
    throw new Error(`Input is not a file: ${inputPath}`);
  }

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.rmSync(outputPath, { force: true });

  const updateInfo = await executeAppBuilderAsJson([
    "blockmap",
    "--input",
    inputPath,
    "--output",
    outputPath,
  ]);

  if (!fs.statSync(outputPath).isFile()) {
    throw new Error(`Blockmap was not created: ${outputPath}`);
  }

  process.stdout.write(`${JSON.stringify(updateInfo)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
