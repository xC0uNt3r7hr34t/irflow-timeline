/**
 * Read one top-level plist key without requiring macOS `plutil`.
 *
 * Computer History identity artifacts are Apple plists (XML or binary). Examiners on Windows/Linux
 * still need to parse them from a collected home directory. Whole-file JSON conversion is avoided
 * because `<data>` blobs make `plutil -convert json` fail; key-at-a-time extraction does not.
 */

"use strict";

const MAX_PLIST_BYTES = 32 * 1024 * 1024;

function decodeXmlEntities(value) {
  return String(value)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/&amp;/g, "&");
}

function valueFromXmlFragment(rest) {
  const m = rest.match(
    /^(?:<string>([\s\S]*?)<\/string>|<integer>(-?\d+)<\/integer>|<real>(-?[\d.eE+-]+)<\/real>|<true\s*\/>|<false\s*\/>|<data>([\s\S]*?)<\/data>|<date>([\s\S]*?)<\/date>)/i,
  );
  if (!m) return null;
  if (m[0].toLowerCase().startsWith("<true")) return "true";
  if (m[0].toLowerCase().startsWith("<false")) return "false";
  if (m[1] != null) return decodeXmlEntities(m[1]);
  if (m[2] != null) return m[2];
  if (m[3] != null) return m[3];
  if (m[4] != null) return m[4].replace(/\s+/g, "");
  if (m[5] != null) return decodeXmlEntities(m[5]);
  return null;
}

function readXmlPlistKey(xml, key) {
  const needle = `<key>${key}</key>`;
  let from = 0;
  while (from < xml.length) {
    const i = xml.indexOf(needle, from);
    if (i < 0) return null;
    const rest = xml.slice(i + needle.length).replace(/^\s+/, "");
    const value = valueFromXmlFragment(rest);
    if (value != null) return value;
    from = i + needle.length;
  }
  return null;
}

function readSizedInt(buf, offset, size) {
  if (size === 1) return buf[offset];
  if (size === 2) return buf.readUInt16BE(offset);
  if (size === 4) return buf.readUInt32BE(offset);
  if (size === 8) {
    const v = buf.readBigUInt64BE(offset);
    const n = Number(v);
    if (!Number.isSafeInteger(n)) throw new Error("plist offset exceeds safe integer");
    return n;
  }
  throw new Error("unsupported plist integer size");
}

function parseBplistObject(buf, offsetTable, objectRefSize, index, seen) {
  if (seen.has(index)) return null;
  seen.add(index);
  const objOff = offsetTable[index];
  const marker = buf[objOff];
  const type = marker >> 4;
  let extra = marker & 0x0f;
  let cursor = objOff + 1;

  const readLength = () => {
    if (extra !== 0x0f) return extra;
    const lenMarker = buf[cursor++];
    const lenBytes = 1 << (lenMarker & 0x0f);
    const len = readSizedInt(buf, cursor, lenBytes);
    cursor += lenBytes;
    return len;
  };

  if (marker === 0x00) return null;
  if (marker === 0x08) return "false";
  if (marker === 0x09) return "true";

  if (type === 0x1) {
    const size = 1 << extra;
    if (size === 1) return String(buf.readInt8(cursor));
    if (size === 2) return String(buf.readInt16BE(cursor));
    if (size === 4) return String(buf.readInt32BE(cursor));
    if (size === 8) return buf.readBigInt64BE(cursor).toString();
    return null;
  }

  if (type === 0x2) {
    const size = 1 << extra;
    if (size === 4) return String(buf.readFloatBE(cursor));
    if (size === 8) return String(buf.readDoubleBE(cursor));
    return null;
  }

  if (type === 0x3) {
    return buf.slice(cursor, cursor + 8).toString("hex");
  }

  if (type === 0x4) {
    const len = readLength();
    return buf.slice(cursor, cursor + len).toString("base64");
  }

  if (type === 0x5) {
    const len = readLength();
    return buf.slice(cursor, cursor + len).toString("ascii");
  }

  if (type === 0x6) {
    const len = readLength();
    const raw = buf.slice(cursor, cursor + len * 2);
    const swapped = Buffer.allocUnsafe(raw.length);
    for (let i = 0; i + 1 < raw.length; i += 2) {
      swapped[i] = raw[i + 1];
      swapped[i + 1] = raw[i];
    }
    return swapped.toString("utf16le");
  }

  if (type === 0xa) {
    const len = readLength();
    const refs = [];
    for (let i = 0; i < len; i++) {
      refs.push(readSizedInt(buf, cursor + i * objectRefSize, objectRefSize));
    }
    return refs.map((ref) => parseBplistObject(buf, offsetTable, objectRefSize, ref, new Set(seen)));
  }

  if (type === 0xd) {
    const len = readLength();
    const dict = Object.create(null);
    for (let i = 0; i < len; i++) {
      const keyRef = readSizedInt(buf, cursor + i * objectRefSize, objectRefSize);
      const valRef = readSizedInt(buf, cursor + (len + i) * objectRefSize, objectRefSize);
      const k = parseBplistObject(buf, offsetTable, objectRefSize, keyRef, new Set(seen));
      dict[String(k)] = parseBplistObject(buf, offsetTable, objectRefSize, valRef, new Set(seen));
    }
    return dict;
  }

  return null;
}

function readBplistKey(buf, key) {
  if (buf.length < 40 || buf.slice(0, 8).toString("ascii") !== "bplist00") return null;
  const trailer = buf.subarray(buf.length - 32);
  const offsetIntSize = trailer[6];
  const objectRefSize = trailer[7];
  const numObjects = Number(trailer.readBigUInt64BE(8));
  const topObject = Number(trailer.readBigUInt64BE(16));
  const offsetTableOffset = Number(trailer.readBigUInt64BE(24));
  if (!Number.isSafeInteger(numObjects) || numObjects <= 0 || numObjects > 1_000_000) return null;
  if (offsetIntSize < 1 || objectRefSize < 1) return null;

  const offsetTable = [];
  for (let i = 0; i < numObjects; i++) {
    offsetTable.push(readSizedInt(buf, offsetTableOffset + i * offsetIntSize, offsetIntSize));
  }
  const top = parseBplistObject(buf, offsetTable, objectRefSize, topObject, new Set());
  if (!top || typeof top !== "object" || Array.isArray(top)) return null;
  if (!Object.prototype.hasOwnProperty.call(top, key)) return null;
  const value = top[key];
  if (value == null) return null;
  if (typeof value === "string") return value;
  return String(value);
}

function readPlistKeyFromBuffer(buf, key) {
  if (!Buffer.isBuffer(buf) || !key) return null;
  if (buf.length > MAX_PLIST_BYTES) return null;
  if (buf.slice(0, 8).toString("ascii") === "bplist00") {
    try { return readBplistKey(buf, key); } catch { return null; }
  }
  const xml = buf.toString("utf8");
  if (!xml.includes("<plist")) return null;
  try { return readXmlPlistKey(xml, key); } catch { return null; }
}

module.exports = {
  readPlistKeyFromBuffer,
  readXmlPlistKey,
};
