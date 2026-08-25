---
description: Recover and package Windows RDP Bitmap Cache artifacts with the IRFlow Timeline bmc-tools integration.
---

# RDP Bitmap Cache

IRFlow Timeline includes an RDP Bitmap Cache workflow for recovering visual remnants from Windows user profile cache files.

The feature wraps ANSSI-FR `bmc-tools` and is intended for lateral movement and hands-on-keyboard review where screenshots are unavailable but RDP cache artifacts may still reveal remote desktop activity.

## Supported Artifacts

The scanner looks for:

- `bcache*.bmc`
- `cache????.bin`

These files are commonly found under Windows user profile paths such as:

```text
Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache
```

You can select one cache file or a parent directory. Directory scanning is recursive and symlinks are skipped by default.

## Opening

- **Menu:** **Tools → Platforms → Windows → RDP Bitmap Cache**

## Workflow

1. Open **Tools → Platforms → Windows → RDP Bitmap Cache**.
2. Select a cache source file or folder.
3. Confirm the preflight summary: cache file count, size, detected profiles, and cache directories.
4. Select `bmc-tools` if the bundled copy is unavailable.
5. Click **Extract Images**.
6. Review recovered collages and tiles in the image preview.
7. Export an evidence package for reporting or handoff.

![RDP Bitmap Cache modal showing selected cache-bin source files (Cache0000.bin, Cache0001.bin), extraction options (Include old tiles, Generate collage, Collage width, Verbose log), an Extraction complete panel with snapshot hash plus Copy Summary and Export Evidence Package buttons, and a Recovered Image Preview with a reconstructed collage, SHA-256 hash, and a thumbnail grid of recovered tiles](/dfir-tips/RDP-Bitmap-Cache-Results.png)

The extraction panel shows a snapshot hash and image count, and the preview separates **collages** (reconstructed full-cache mosaics) from individual **tiles**. Select any thumbnail to see its size, SHA-256, and **Copy Path** / **Open Image** actions, or use **Open Output Folder** to browse all recovered bitmaps on disk.

## Evidence Package

After extraction, click **Export Evidence Package** to create an app-managed package folder containing:

- `manifest.json` with extraction metadata, source paths, command line, and hashes
- `input-files.csv` with source cache file metadata and SHA-256 hashes
- `output-images.csv` with recovered image metadata and SHA-256 hashes
- `images/` with copied recovered bitmap output
- `bmc-tools-command.txt` when an exact command line was recorded
- `README.txt` describing the package contents

The original source cache files are not copied into the package. Their paths and hashes are preserved in the manifest and CSV inventory.

## Build Notes

Release builds run:

```bash
npm run bundle:tools
```

This bundles both Hayabusa and `bmc-tools`. To refresh only `bmc-tools`, run:

```bash
npm run bundle:bmc-tools
```

You can pin a specific branch, tag, or commit:

```bash
npm run bundle:bmc-tools -- 5a4cad32be78b3b874aeec910cb478e04ba3501e
```

## Analyst Notes

Bitmap cache output should be treated as recovered visual fragments, not a complete screen recording. Use it as supporting evidence alongside logon, RDP, process, and network telemetry.
