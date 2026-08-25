const fs = require("fs");
const fsp = require("fs/promises");
const path = require("path");
const zlib = require("zlib");

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const BI_RGB = 0;
const BI_BITFIELDS = 3;

let crcTable = null;

function getCrcTable() {
  if (crcTable) return crcTable;
  crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[n] = c >>> 0;
  }
  return crcTable;
}

function crc32(buffers) {
  const table = getCrcTable();
  let c = 0xffffffff;
  for (const buffer of buffers) {
    for (let i = 0; i < buffer.length; i += 1) {
      c = table[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data = Buffer.alloc(0)) {
  const typeBuffer = Buffer.from(type, "ascii");
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  typeBuffer.copy(out, 4);
  data.copy(out, 8);
  out.writeUInt32BE(crc32([typeBuffer, data]), 8 + data.length);
  return out;
}

function encodePngRgba(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const rowBytes = width * 4;
  const scanlines = Buffer.alloc((rowBytes + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const destOffset = y * (rowBytes + 1);
    scanlines[destOffset] = 0;
    rgba.copy(scanlines, destOffset + 1, y * rowBytes, (y + 1) * rowBytes);
  }

  return Buffer.concat([
    PNG_SIGNATURE,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", zlib.deflateSync(scanlines)),
    pngChunk("IEND"),
  ]);
}

function trailingZeroBits(value) {
  if (!value) return 0;
  let count = 0;
  let v = value >>> 0;
  while ((v & 1) === 0) {
    count += 1;
    v >>>= 1;
  }
  return count;
}

function bitCount(value) {
  let count = 0;
  let v = value >>> 0;
  while (v) {
    count += v & 1;
    v >>>= 1;
  }
  return count;
}

function maskReader(mask) {
  if (!mask) return () => null;
  const shift = trailingZeroBits(mask);
  const bits = bitCount(mask);
  const max = (2 ** bits) - 1;
  return (pixel) => {
    const raw = (pixel & mask) >>> shift;
    return bits === 8 ? raw : Math.round((raw / max) * 255);
  };
}

function readBmpMetadata(buffer) {
  if (buffer.length < 54 || buffer.toString("ascii", 0, 2) !== "BM") {
    throw new Error("Not a BMP file.");
  }
  const pixelOffset = buffer.readUInt32LE(10);
  const dibSize = buffer.readUInt32LE(14);
  if (dibSize < 40) throw new Error(`Unsupported BMP DIB header size: ${dibSize}`);

  const width = buffer.readInt32LE(18);
  const signedHeight = buffer.readInt32LE(22);
  const height = Math.abs(signedHeight);
  const topDown = signedHeight < 0;
  const planes = buffer.readUInt16LE(26);
  const bitsPerPixel = buffer.readUInt16LE(28);
  const compression = buffer.readUInt32LE(30);
  if (planes !== 1 || width <= 0 || height <= 0) throw new Error("Unsupported BMP dimensions.");
  if (![24, 32].includes(bitsPerPixel)) throw new Error(`Unsupported BMP bit depth: ${bitsPerPixel}`);
  if (![BI_RGB, BI_BITFIELDS].includes(compression)) throw new Error(`Unsupported BMP compression: ${compression}`);

  let masks = null;
  if (compression === BI_BITFIELDS && bitsPerPixel === 32) {
    const maskOffset = 14 + 40;
    masks = {
      red: buffer.readUInt32LE(maskOffset),
      green: buffer.readUInt32LE(maskOffset + 4),
      blue: buffer.readUInt32LE(maskOffset + 8),
      alpha: dibSize >= 56 ? buffer.readUInt32LE(maskOffset + 12) : 0,
    };
  }

  return {
    pixelOffset,
    dibSize,
    width,
    height,
    topDown,
    bitsPerPixel,
    compression,
    rowStride: Math.floor((bitsPerPixel * width + 31) / 32) * 4,
    masks,
  };
}

function decodeBmpToRgba(buffer, options = {}) {
  const meta = readBmpMetadata(buffer);
  const maxDimension = Number.isFinite(options.maxDimension) ? Math.floor(options.maxDimension) : 2048;
  const scale = maxDimension > 0 ? Math.min(1, maxDimension / Math.max(meta.width, meta.height)) : 1;
  const outWidth = Math.max(1, Math.round(meta.width * scale));
  const outHeight = Math.max(1, Math.round(meta.height * scale));
  const rgba = Buffer.alloc(outWidth * outHeight * 4);

  const readRed = maskReader(meta.masks?.red || 0x00ff0000);
  const readGreen = maskReader(meta.masks?.green || 0x0000ff00);
  const readBlue = maskReader(meta.masks?.blue || 0x000000ff);
  const readAlpha = maskReader(meta.masks?.alpha || 0);

  for (let y = 0; y < outHeight; y += 1) {
    const sourceY = Math.min(meta.height - 1, Math.floor(y / scale));
    const bmpY = meta.topDown ? sourceY : meta.height - 1 - sourceY;
    const rowOffset = meta.pixelOffset + bmpY * meta.rowStride;
    for (let x = 0; x < outWidth; x += 1) {
      const sourceX = Math.min(meta.width - 1, Math.floor(x / scale));
      const sourceOffset = rowOffset + Math.floor((sourceX * meta.bitsPerPixel) / 8);
      const destOffset = (y * outWidth + x) * 4;
      if (meta.bitsPerPixel === 24) {
        rgba[destOffset] = buffer[sourceOffset + 2] || 0;
        rgba[destOffset + 1] = buffer[sourceOffset + 1] || 0;
        rgba[destOffset + 2] = buffer[sourceOffset] || 0;
        rgba[destOffset + 3] = 255;
      } else {
        // Assemble the 32-bit little-endian pixel byte-wise instead of buffer.readUInt32LE,
        // which throws RangeError on a truncated/corrupt BMP when sourceOffset+4 runs past
        // the buffer. RDP bitmap-cache tiles come from bmc-tools output and may be malformed;
        // out-of-range bytes degrade to 0 here, mirroring the 24-bpp path above.
        const pixel = (
          (buffer[sourceOffset] || 0) |
          ((buffer[sourceOffset + 1] || 0) << 8) |
          ((buffer[sourceOffset + 2] || 0) << 16) |
          ((buffer[sourceOffset + 3] || 0) << 24)
        ) >>> 0;
        rgba[destOffset] = readRed(pixel) ?? 0;
        rgba[destOffset + 1] = readGreen(pixel) ?? 0;
        rgba[destOffset + 2] = readBlue(pixel) ?? 0;
        rgba[destOffset + 3] = readAlpha(pixel) ?? 255;
      }
    }
  }

  return {
    width: outWidth,
    height: outHeight,
    sourceWidth: meta.width,
    sourceHeight: meta.height,
    scaled: outWidth !== meta.width || outHeight !== meta.height,
    rgba,
  };
}

async function convertBmpToPng(inputPath, outputPath, options = {}) {
  const buffer = await fsp.readFile(inputPath);
  const decoded = decodeBmpToRgba(buffer, options);
  const png = encodePngRgba(decoded.width, decoded.height, decoded.rgba);
  await fsp.mkdir(path.dirname(outputPath), { recursive: true });
  await fsp.writeFile(outputPath, png);
  const st = await fsp.stat(outputPath);
  return {
    outputPath,
    width: decoded.width,
    height: decoded.height,
    sourceWidth: decoded.sourceWidth,
    sourceHeight: decoded.sourceHeight,
    scaled: decoded.scaled,
    size: st.size,
  };
}

module.exports = {
  PNG_SIGNATURE,
  convertBmpToPng,
  decodeBmpToRgba,
  encodePngRgba,
  readBmpMetadata,
};
