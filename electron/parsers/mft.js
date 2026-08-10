const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { dbg } = require("../logger");
const { BATCH_SIZE_DEFAULT } = require("./csv");

const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch

const MFT_COLUMNS = [
  "EntryNumber", "SequenceNumber", "InUse", "ParentEntryNumber", "ParentSequenceNumber",
  "ParentPath", "FileName", "Extension", "FileSize", "ReferenceCount", "ReparseTarget",
  "IsDirectory", "HasAds", "IsAds", "SI<FN", "uSecZeros", "Copied", "SiFlags", "NameType",
  "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
  "LastRecordChange0x10", "LastRecordChange0x30", "LastAccess0x10", "LastAccess0x30",
  "UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "ObjectIdFileDroid",
  "LoggedUtilStream", "ZoneIdContents", "AdsStreamCount", "AdsStreams",
];

// FILETIME epoch: 100ns intervals between 1601-01-01 and 1970-01-01
const FT_EPOCH_DIFF = 116444736000000000n;

const SI_FLAG_NAMES = [
  [0x0001, "ReadOnly"], [0x0002, "Hidden"], [0x0004, "System"],
  [0x0010, "Directory"], [0x0020, "Archive"], [0x0040, "Device"], [0x0080, "Normal"],
  [0x0100, "Temporary"], [0x0200, "SparseFile"], [0x0400, "ReparsePoint"],
  [0x0800, "Compressed"], [0x1000, "Offline"], [0x2000, "NotContentIndexed"],
  [0x4000, "Encrypted"], [0x8000, "IntegrityStream"],
  [0x10000, "Virtual"], [0x20000, "NoScrubData"],
  [0x40000, "RecallOnOpen"], [0x400000, "RecallOnDataAccess"],
  [0x10000000, "IsIndexView"],
];

const FN_NAMESPACE_NAMES = ["Posix", "Windows", "Dos", "DosWindows"];

/**
 * Check if a file is a raw $MFT binary by reading the first 4 bytes
 */
function isMftFile(filePath) {
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const buf = Buffer.alloc(4);
    const bytesRead = fs.readSync(fd, buf, 0, 4, 0);
    if (bytesRead < 4) return false;
    // "FILE" = 0x46 0x49 0x4C 0x45
    return buf[0] === 0x46 && buf[1] === 0x49 && buf[2] === 0x4C && buf[3] === 0x45;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
}

/**
 * Convert Windows FILETIME (BigInt, 100ns since 1601) to ISO-like string
 * Output format: "2024-07-03 10:05:28.2583360" (matches MFTECmd)
 */
function filetimeToIso(ft) {
  if (ft === 0n || ft < FT_EPOCH_DIFF) return "";
  const ticks = ft - FT_EPOCH_DIFF;
  const ms = Number(ticks / 10000n);
  const d = new Date(ms);
  if (isNaN(d.getTime())) return "";
  // Build 7-digit fractional seconds (100ns precision)
  // Use slice instead of padStart to avoid per-call string allocations
  const frac = ("0000000" + Number(ticks % 10000000n)).slice(-7);
  const yyyy = d.getUTCFullYear();
  const mo = ("0" + (d.getUTCMonth() + 1)).slice(-2);
  const dd = ("0" + d.getUTCDate()).slice(-2);
  const hh = ("0" + d.getUTCHours()).slice(-2);
  const mi = ("0" + d.getUTCMinutes()).slice(-2);
  const ss = ("0" + d.getUTCSeconds()).slice(-2);
  return yyyy + "-" + mo + "-" + dd + " " + hh + ":" + mi + ":" + ss + "." + frac;
}

/** Check if FILETIME sub-second portion is exactly zero (timestomping indicator) */
function ftHasZeroUsec(ft) {
  return ft !== 0n && (ft % 10000000n === 0n);
}

/** Decode SiFlags bitmask to pipe-separated string */
function flagsToString(flags) {
  if (!flags) return "None";
  const parts = [];
  for (const [mask, name] of SI_FLAG_NAMES) {
    if (flags & mask) parts.push(name);
  }
  return parts.length > 0 ? parts.join("|") : "None";
}

/** Extract file extension from filename */
function mftGetExtension(filename) {
  if (!filename) return "";
  const dot = filename.lastIndexOf(".");
  if (dot <= 0 || dot === filename.length - 1) return "";
  return filename.substring(dot);
}

/**
 * Apply fixup array — restore last 2 bytes of each 512-byte sector
 * Critical for MFT record integrity
 */
function applyFixup(buf, fixupOffset, fixupCount) {
  if (fixupCount <= 1 || fixupOffset < 4 || fixupOffset + fixupCount * 2 > buf.length) return;
  for (let i = 1; i < fixupCount; i++) {
    const sectorEnd = i * 512 - 2;
    const srcOff = fixupOffset + i * 2;
    if (sectorEnd + 2 > buf.length || srcOff + 2 > buf.length) break;
    const replacement = buf.readUInt16LE(srcOff);
    buf.writeUInt16LE(replacement, sectorEnd);
  }
}

/**
 * Parse $STANDARD_INFORMATION attribute (type 0x10) — always resident
 */
function parseSI(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 48 || s + 48 > buf.length) return null;
  return {
    created:     buf.readBigUInt64LE(s),
    modified:    buf.readBigUInt64LE(s + 8),
    mftModified: buf.readBigUInt64LE(s + 16),
    accessed:    buf.readBigUInt64LE(s + 24),
    fileFlags:   buf.readUInt32LE(s + 32),
    securityId:  contentSize >= 56 && s + 56 <= buf.length ? buf.readUInt32LE(s + 52) : 0,
    usn:         contentSize >= 72 && s + 72 <= buf.length ? buf.readBigUInt64LE(s + 64) : 0n,
  };
}

/**
 * Parse $FILE_NAME attribute (type 0x30) — always resident
 */
function parseFN(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 66 || s + 66 > buf.length) return null;

  const parentRefLow = buf.readUInt32LE(s);
  const parentRefHigh = buf.readUInt16LE(s + 4);
  const parentEntry = parentRefLow + parentRefHigh * 0x100000000;
  const parentSeqNum = buf.readUInt16LE(s + 6);

  const nameLen = buf[s + 64];
  const namespace = buf[s + 65];
  const fnEnd = s + 66 + nameLen * 2;
  if (fnEnd > buf.length) return null;
  const filename = buf.toString("utf16le", s + 66, fnEnd);

  return {
    parentEntry,
    parentSeqNum,
    created:     buf.readBigUInt64LE(s + 8),
    modified:    buf.readBigUInt64LE(s + 16),
    mftModified: buf.readBigUInt64LE(s + 24),
    accessed:    buf.readBigUInt64LE(s + 32),
    realSize:    buf.readBigUInt64LE(s + 48),
    namespace,
    filename,
  };
}

/**
 * Parse $OBJECT_ID attribute (type 0x40) — extract file GUID
 */
function parseObjectId(buf, attrPos) {
  const contentSize = buf.readUInt32LE(attrPos + 16);
  const contentOffset = buf.readUInt16LE(attrPos + 20);
  const s = attrPos + contentOffset;
  if (contentSize < 16 || s + 16 > buf.length) return "";
  // Format as GUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
  const hex = buf.toString("hex", s, s + 16);
  return `${hex.slice(6,8)}${hex.slice(4,6)}${hex.slice(2,4)}${hex.slice(0,2)}-${hex.slice(10,12)}${hex.slice(8,10)}-${hex.slice(14,16)}${hex.slice(12,14)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

/**
 * Walk all attributes in an MFT record
 */
function parseAttributes(buf, offset, header) {
  const rec = {
    ...header,
    si: null,
    fn: null,
    hasAds: false,
    isAds: false,
    zoneId: "",
    adsStreams: null, // lazily-allocated list of non-Zone named $DATA streams ({name,size,exec})
    objectId: "",
    loggedUtilStream: "",
    reparseTarget: "",
    refCount: 0,
    dataSize: -1n, // Real file size from $DATA attribute (-1 = not found)
  };

  let pos = offset;
  let dataAttrCount = 0;
  let fnBest = null;
  let fnDos = null;
  let fnLinkCount = 0; // Count distinct non-DOS names (hard links)

  while (pos + 8 <= buf.length) {
    const attrType = buf.readUInt32LE(pos);
    if (attrType === 0xFFFFFFFF || attrType === 0) break;
    const attrLen = buf.readUInt32LE(pos + 4);
    if (attrLen < 16 || pos + attrLen > buf.length) break;

    const nonResident = buf[pos + 8];
    const nameLen = buf[pos + 9];
    const nameOffset = buf.readUInt16LE(pos + 10);

    try {
      if (attrType === 0x10 && !nonResident) {
        rec.si = parseSI(buf, pos);
      } else if (attrType === 0x30 && !nonResident) {
        const fn = parseFN(buf, pos);
        if (fn) {
          // Count non-DOS names as hard link references (DOS is companion, not separate link)
          if (fn.namespace !== 2) fnLinkCount++;
          if (fn.namespace === 2) {
            // DOS (8.3 short name) — lowest priority
            fnDos = fn;
          } else if (fn.namespace === 3) {
            // DosWindows (combined) — highest priority
            fnBest = fn;
          } else if (fn.namespace === 1) {
            // Win32 (long name) — high priority, don't override DosWindows
            if (!fnBest || fnBest.namespace !== 3) fnBest = fn;
          } else {
            // POSIX (0) — fallback only
            if (!fnBest) fnBest = fn;
          }
        }
      } else if (attrType === 0x40 && !nonResident) {
        rec.objectId = parseObjectId(buf, pos);
      } else if (attrType === 0x80) {
        dataAttrCount++;
        if (nameLen === 0) {
          // Primary (unnamed) $DATA — extract real file size
          if (nonResident) {
            // Non-resident: real size at offset 48 from attribute start
            if (pos + 56 <= buf.length) rec.dataSize = buf.readBigUInt64LE(pos + 48);
          } else {
            // Resident: content size at offset 16 from attribute start
            rec.dataSize = BigInt(buf.readUInt32LE(pos + 16));
          }
        } else {
          rec.hasAds = true;
          // Decode the stream NAME for resident AND non-resident streams (the name lives in the
          // attribute header either way).
          let attrName = "";
          if (pos + nameOffset + nameLen * 2 <= buf.length) {
            attrName = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
          }
          if (attrName === "Zone.Identifier") {
            if (!nonResident) {
              const cSize = buf.readUInt32LE(pos + 16);
              const cOff = buf.readUInt16LE(pos + 20);
              if (cSize > 0 && cSize < 2048 && pos + cOff + cSize <= buf.length) {
                rec.zoneId = buf.toString("utf8", pos + cOff, pos + cOff + cSize).trim();
              }
            }
          } else if (attrName) {
            // Non-Zone named $DATA stream — capture name + size so the ADS Analyzer can enumerate
            // alternate streams (T1564.004) from a raw $MFT instead of only flagging HasAds. For
            // resident streams, sniff the first two bytes for the PE 'MZ' signature (a hidden EXE).
            let streamSize = -1n;
            let execContent = false;
            if (nonResident) {
              if (pos + 56 <= buf.length) streamSize = buf.readBigUInt64LE(pos + 48);
            } else {
              const cSize = buf.readUInt32LE(pos + 16);
              streamSize = BigInt(cSize);
              const cOff = buf.readUInt16LE(pos + 20);
              // Sniff the PE 'MZ' magic, bounded to BOTH the buffer and this attribute (cOff is
              // relative to the attribute start) so a corrupt offset can't read into the next attr.
              if (cSize >= 2 && cOff + 2 <= attrLen && pos + cOff + 2 <= buf.length && buf[pos + cOff] === 0x4D && buf[pos + cOff + 1] === 0x5A) execContent = true;
            }
            if (!rec.adsStreams) rec.adsStreams = [];
            rec.adsStreams.push({ name: attrName, size: streamSize, exec: execContent });
          }
        }
        if (dataAttrCount > 1) rec.hasAds = true;
      } else if (attrType === 0xC0 && !nonResident && nameLen > 0 && pos + nameOffset + nameLen * 2 <= buf.length) {
        // $LOGGED_UTILITY_STREAM
        rec.loggedUtilStream = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
      } else if (attrType === 0xC0 && !nonResident && nameLen === 0) {
        // Reparse point data is in 0xC0 in some cases, but typically from $REPARSE_POINT
      }
    } catch {
      // Skip corrupt attribute
    }

    pos += attrLen;
  }

  rec.fn = fnBest || fnDos || null;
  // Use non-DOS link count; fall back to 1 if only a DOS name exists
  rec.refCount = fnLinkCount > 0 ? fnLinkCount : (fnDos ? 1 : 0);
  return rec;
}

/**
 * Parse a single 1024-byte MFT record.
 * Returns { type: "base", rec } for base records, or
 * { type: "ext", baseEntry, fnAttrs } for extension records with $FILE_NAME attrs.
 */
function parseMftRecord(buf, recordIndex) {
  if (buf.length < 48) return null;
  if (buf[0] !== 0x46 || buf[1] !== 0x49 || buf[2] !== 0x4C || buf[3] !== 0x45) return null;

  const fixupOffset = buf.readUInt16LE(4);
  const fixupCount = buf.readUInt16LE(6);
  const attrOffset = buf.readUInt16LE(20);
  const baseRefLow = buf.readUInt32LE(32);
  const baseRefHigh = buf.readUInt16LE(36);

  applyFixup(buf, fixupOffset, fixupCount);
  if (attrOffset < 48 || attrOffset >= buf.length) return null;

  // Extension record — extract $FILE_NAME attrs for merging into base record
  if (baseRefLow !== 0 || baseRefHigh !== 0) {
    const baseEntry = baseRefLow + baseRefHigh * 0x100000000;
    const fnAttrs = [];
    let pos = attrOffset;
    while (pos + 8 <= buf.length) {
      const aType = buf.readUInt32LE(pos);
      if (aType === 0xFFFFFFFF || aType === 0) break;
      const aLen = buf.readUInt32LE(pos + 4);
      if (aLen < 16 || pos + aLen > buf.length) break;
      if (aType === 0x30 && !buf[pos + 8]) {
        try { const fn = parseFN(buf, pos); if (fn) fnAttrs.push(fn); } catch {}
      }
      pos += aLen;
    }
    return fnAttrs.length > 0 ? { type: "ext", baseEntry, fnAttrs } : null;
  }

  // Base record
  const lsn = buf.readBigUInt64LE(8);
  const seqNum = buf.readUInt16LE(16);
  const flags = buf.readUInt16LE(22);
  let entryNumber = buf.readUInt32LE(44);
  if (entryNumber === 0 && recordIndex > 0) entryNumber = recordIndex;

  return { type: "base", rec: parseAttributes(buf, attrOffset, {
    entryNumber, seqNum, lsn,
    inUse: (flags & 0x01) !== 0,
    isDirectory: (flags & 0x02) !== 0,
  }) };
}

// Upper bound on memoized parent paths. The cache stores one full path string per distinct
// parent directory; on a 30GB+ $MFT (tens of millions of records, millions of directories)
// an unbounded cache of deep path strings can grow into the GBs and OOM the import worker.
// The cache is a pure optimization over the immutable dirMap, so evicting entries only costs
// some recomputation — never correctness.
const PATH_CACHE_MAX = 1_000_000;

/**
 * Resolve full parent path by walking the directory map
 */
function resolveParentPath(entryNumber, dirMap, pathCache) {
  const cached = pathCache.get(entryNumber);
  if (cached !== undefined) return cached;

  const parts = [];
  let current = entryNumber;
  const visited = new Set();

  while (current !== undefined && current !== 5) { // Entry 5 = root "."
    if (visited.has(current)) { parts.unshift("[ORPHAN]"); break; }
    visited.add(current);
    const entry = dirMap.get(current);
    if (!entry) { parts.unshift("[ORPHAN]"); break; }
    parts.unshift(entry.name);
    current = entry.parentEntry;
  }

  const resolved = parts.length > 0 ? ".\\" + parts.join("\\") : ".";

  // Bound the cache: evict oldest inserted entries (Map preserves insertion order) once the
  // cap is reached, keeping the root (entry 5) pinned. FIFO keeps the hot path a single get.
  if (pathCache.size >= PATH_CACHE_MAX) {
    let toEvict = pathCache.size - PATH_CACHE_MAX + 1;
    for (const k of pathCache.keys()) {
      if (k === 5) continue; // keep root pinned
      pathCache.delete(k);
      if (--toEvict <= 0) break;
    }
  }

  pathCache.set(entryNumber, resolved);
  return resolved;
}

/**
 * Build a row array matching MFT_COLUMNS order from a parsed record
 */
function buildMftRow(rec, dirMap, pathCache) {
  const fn = rec.fn;
  const si = rec.si;
  const parentPath = fn ? resolveParentPath(fn.parentEntry, dirMap, pathCache) : "";

  // Non-Zone ADS streams: pipe-joined "<flag>name(size)" (first 8). The flag is ALWAYS exactly one
  // leading char ('!' = resident PE/MZ content, '.' = not) so it can never be forged by a stream
  // name that itself begins with '!'. '|' is illegal in NTFS stream names, so it is a safe delimiter.
  const adsList = rec.adsStreams || [];
  const adsStreamsStr = adsList.slice(0, 8)
    .map((s) => `${s.exec ? "!" : "."}${s.name}(${s.size >= 0n ? s.size.toString() : "?"})`)
    .join("|");

  // SI<FN: True if any SI timestamp is earlier than corresponding FN timestamp
  let siFn = "False";
  if (si && fn) {
    if (si.created < fn.created || si.modified < fn.modified ||
        si.mftModified < fn.mftModified || si.accessed < fn.accessed) {
      siFn = "True";
    }
  }

  // uSecZeros: True if any SI timestamp has zero sub-second component
  let uSecZeros = "False";
  if (si) {
    if (ftHasZeroUsec(si.created) || ftHasZeroUsec(si.modified) ||
        ftHasZeroUsec(si.mftModified) || ftHasZeroUsec(si.accessed)) {
      uSecZeros = "True";
    }
  }

  // Copied: True if SI Created > SI Modified
  const copied = si && si.created > si.modified ? "True" : "False";

  // File size: prefer $DATA real size, fall back to $FILE_NAME realSize
  const fileSize = rec.dataSize >= 0n ? rec.dataSize : (fn ? fn.realSize : 0n);

  return [
    String(rec.entryNumber),                              // EntryNumber
    String(rec.seqNum),                                   // SequenceNumber
    rec.inUse ? "True" : "False",                         // InUse
    fn ? String(fn.parentEntry) : "",                     // ParentEntryNumber
    fn ? String(fn.parentSeqNum) : "",                    // ParentSequenceNumber
    parentPath,                                           // ParentPath
    fn ? fn.filename : "",                                // FileName
    fn ? mftGetExtension(fn.filename) : "",               // Extension
    String(fileSize),                                       // FileSize
    String(rec.refCount),                                 // ReferenceCount
    rec.reparseTarget,                                    // ReparseTarget
    rec.isDirectory ? "True" : "False",                   // IsDirectory
    rec.hasAds ? "True" : "False",                        // HasAds
    rec.isAds ? "True" : "False",                         // IsAds
    siFn,                                                 // SI<FN
    uSecZeros,                                            // uSecZeros
    copied,                                               // Copied
    si ? flagsToString(si.fileFlags) : "",                // SiFlags
    fn ? (FN_NAMESPACE_NAMES[fn.namespace] || String(fn.namespace)) : "", // NameType
    si ? filetimeToIso(si.created) : "",                  // Created0x10
    fn ? filetimeToIso(fn.created) : "",                  // Created0x30
    si ? filetimeToIso(si.modified) : "",                 // LastModified0x10
    fn ? filetimeToIso(fn.modified) : "",                 // LastModified0x30
    si ? filetimeToIso(si.mftModified) : "",              // LastRecordChange0x10
    fn ? filetimeToIso(fn.mftModified) : "",              // LastRecordChange0x30
    si ? filetimeToIso(si.accessed) : "",                 // LastAccess0x10
    fn ? filetimeToIso(fn.accessed) : "",                 // LastAccess0x30
    si ? String(si.usn) : "",                             // UpdateSequenceNumber
    String(rec.lsn),                                      // LogfileSequenceNumber
    si ? String(si.securityId) : "",                      // SecurityId
    rec.objectId,                                         // ObjectIdFileDroid
    rec.loggedUtilStream,                                 // LoggedUtilStream
    rec.zoneId,                                           // ZoneIdContents
    adsList.length ? String(adsList.length) : "",        // AdsStreamCount
    adsStreamsStr,                                        // AdsStreams ("[!]name(size)" pipe-joined; '!' = resident MZ/PE content)
  ];
}

/**
 * Parse raw $MFT binary file — memory-efficient two-pass architecture
 * Pass 1: Read file, build directory map + extension FN map (directories only ~5-10% of entries)
 * Pass 2: Re-read file from disk, parse each record, resolve paths, insert into SQLite
 *
 * Previous approach stored ALL parsed records in memory (~500 bytes each),
 * which for a 30GB MFT (29M records) = ~15GB heap → OOM crash.
 * New approach re-reads the file from disk in Pass 2 instead.
 */
async function parseMftFile(filePath, tabId, db, onProgress) {
  const RECORD_SIZE = 1024;
  const CHUNK_RECORDS = 4096; // Read 4MB at a time
  let fileSize, fd;
  try {
    fileSize = fs.statSync(filePath).size;
    fd = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot open MFT file: ${e.message}`);
  }
  const totalRecords = Math.floor(fileSize / RECORD_SIZE);

  dbg("MFT", `parseMftFile start`, { filePath, fileSize, totalRecords });

  // Fixed schema — no discovery phase needed
  const headers = [...MFT_COLUMNS];
  const colCount = headers.length;
  db.createTab(tabId, headers);

  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  const chunkBuf = Buffer.alloc(RECORD_SIZE * CHUNK_RECORDS);
  const dirMap = new Map();
  const extFnMap = new Map(); // extension record FN attrs keyed by base entry number
  // dosOnlyEntries: track base records that only have DOS-namespace FN (namespace=2)
  // so Pass 2 can apply extension FN merge without re-scanning all records
  const dosOnlyEntries = new Set();
  let recordsRead = 0;
  let lastYield = Date.now();

  // ── Pass 1: Build directory map + collect extension FN attrs ──
  // Only stores directory entries (~5-10% of all records) + extension FN attrs.
  // Does NOT store parsed base records — saves ~12-17GB on 30GB files.
  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const recBuf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        const recordIndex = Math.floor(offset / RECORD_SIZE) + i;

        try {
          const parsed = parseMftRecord(recBuf, recordIndex);
          if (!parsed) continue;
          if (parsed.type === "base") {
            const rec = parsed.rec;
            if (rec.isDirectory && rec.fn) {
              dirMap.set(rec.entryNumber, {
                parentEntry: rec.fn.parentEntry,
                name: rec.fn.filename,
              });
            }
            // Track entries with DOS-only FN for extension merge
            if (!rec.fn || rec.fn.namespace === 2) {
              dosOnlyEntries.add(rec.entryNumber);
            }
          } else if (parsed.type === "ext") {
            // Only keep extension attrs for entries that need them
            let arr = extFnMap.get(parsed.baseEntry);
            if (!arr) { arr = []; extFnMap.set(parsed.baseEntry, arr); }
            for (const fn of parsed.fnAttrs) arr.push(fn);
          }
        } catch {
          // Skip corrupt record
        }
        recordsRead++;
      }

      // Progress (Pass 1 = 0-40%) + event loop yield
      const now = Date.now();
      if (now - lastYield >= 200) {
        lastYield = now;
        if (onProgress) onProgress(recordsRead, Math.floor(offset * 0.4), fileSize);
        await new Promise((r) => setImmediate(r));
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  dbg("MFT", `Pass 1 complete`, { recordsRead, dirMapSize: dirMap.size, extEntries: extFnMap.size, dosOnly: dosOnlyEntries.size });

  // ── Pre-merge extension FN attrs into dirMap ──
  // Apply extension FN fixes to dirMap before Pass 2 so path resolution is correct
  let extMerged = 0;
  if (extFnMap.size > 0) {
    for (const [entryNum, extFns] of extFnMap) {
      if (!dosOnlyEntries.has(entryNum)) continue;
      let best = null;
      for (const fn of extFns) {
        if (fn.namespace === 3) { best = fn; break; }
        if (fn.namespace === 1 && (!best || best.namespace === 0)) best = fn;
        if (fn.namespace === 0 && !best) best = fn;
      }
      if (best) {
        // Update dirMap if this entry is a directory
        const existing = dirMap.get(entryNum);
        if (existing) {
          dirMap.set(entryNum, { parentEntry: best.parentEntry, name: best.filename });
        }
        extMerged++;
      }
    }
    dbg("MFT", `Extension FN pre-merge for dirMap`, { extEntries: extFnMap.size, merged: extMerged });
  }

  // ── Pass 2: Re-read file, parse records, resolve paths, insert into SQLite ──
  // Re-reads from disk instead of holding all records in memory.
  // Cost: ~30-60s extra parse time for 30GB. Savings: ~12-17GB heap.
  const pathCache = new Map();
  pathCache.set(5, "."); // Entry 5 = root directory

  let batch = [];
  let rowCount = 0;
  lastYield = Date.now();

  let fd2;
  try {
    fd2 = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot re-open MFT file for Pass 2: ${e.message}`);
  }

  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd2, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const recBuf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        const recordIndex = Math.floor(offset / RECORD_SIZE) + i;

        try {
          const parsed = parseMftRecord(recBuf, recordIndex);
          if (!parsed || parsed.type !== "base") continue;
          const rec = parsed.rec;

          // Apply extension FN merge for DOS-only entries
          if (dosOnlyEntries.has(rec.entryNumber)) {
            const extFns = extFnMap.get(rec.entryNumber);
            if (extFns) {
              let best = null;
              for (const fn of extFns) {
                if (fn.namespace === 3) { best = fn; break; }
                if (fn.namespace === 1 && (!best || best.namespace === 0)) best = fn;
                if (fn.namespace === 0 && !best) best = fn;
              }
              if (best) {
                rec.fn = best;
                if (rec.refCount === 0 && best.namespace !== 2) rec.refCount = 1;
              }
            }
          }

          batch.push(buildMftRow(rec, dirMap, pathCache));
          rowCount++;

          if (batch.length >= batchSize) {
            db.insertBatchArrays(tabId, batch);
            batch = [];
            const now = Date.now();
            if (now - lastYield >= 200) {
              lastYield = now;
              // Pass 2 = 40-100%
              if (onProgress) onProgress(rowCount, Math.floor(fileSize * 0.4 + (offset / fileSize) * fileSize * 0.6), fileSize);
              await new Promise((r) => setImmediate(r));
            }
          }
        } catch {
          // Skip corrupt record
        }
      }
    }
  } finally {
    fs.closeSync(fd2);
  }

  // Final batch
  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
    batch = [];
  }

  // Cleanup
  dirMap.clear();
  extFnMap.clear();
  dosOnlyEntries.clear();
  pathCache.clear();
  batch = null;

  if (onProgress) onProgress(rowCount, fileSize, fileSize);
  const result = db.finalizeImport(tabId);

  const mem = process.memoryUsage();
  dbg("MFT", `parseMftFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: "raw-mft",
  };
}

/**
 * Extract all resident $DATA content from a raw $MFT file.
 * Writes each resident file to outputDir/Resident/ using MFTECmd naming.
 */
async function extractResidentData(mftPath, outputDir, progressCb) {
  const RECORD_SIZE = 1024;
  const CHUNK_RECORDS = 1024;
  const fileSize = fs.statSync(mftPath).size;
  const totalRecords = Math.floor(fileSize / RECORD_SIZE);
  const residentDir = path.join(outputDir, "Resident");
  fs.mkdirSync(residentDir, { recursive: true });

  const fd = fs.openSync(mftPath, "r");
  const chunkBuf = Buffer.alloc(RECORD_SIZE * CHUNK_RECORDS);
  let extractedCount = 0;
  let skippedErrors = 0;
  let recordsProcessed = 0;
  let lastYield = Date.now();

  // Sanitize filename for filesystem safety
  const sanitize = (name) => name.replace(/[/\\:*?"<>|\x00]/g, "_");

  try {
    for (let offset = 0; offset < fileSize; offset += RECORD_SIZE * CHUNK_RECORDS) {
      const bytesToRead = Math.min(RECORD_SIZE * CHUNK_RECORDS, fileSize - offset);
      const bytesRead = fs.readSync(fd, chunkBuf, 0, bytesToRead, offset);
      const recordsInChunk = Math.floor(bytesRead / RECORD_SIZE);

      for (let i = 0; i < recordsInChunk; i++) {
        const recStart = i * RECORD_SIZE;
        const buf = chunkBuf.subarray(recStart, recStart + RECORD_SIZE);
        recordsProcessed++;

        try {
          // Validate FILE signature
          if (buf[0] !== 0x46 || buf[1] !== 0x49 || buf[2] !== 0x4C || buf[3] !== 0x45) continue;

          const fixupOffset = buf.readUInt16LE(4);
          const fixupCount = buf.readUInt16LE(6);
          const attrOffset = buf.readUInt16LE(20);
          applyFixup(buf, fixupOffset, fixupCount);
          if (attrOffset < 48 || attrOffset >= buf.length) continue;

          const recordIndex = Math.floor(offset / RECORD_SIZE) + i;
          let entryNumber = buf.readUInt32LE(44);
          if (entryNumber === 0 && recordIndex > 0) entryNumber = recordIndex;
          const seqNum = buf.readUInt16LE(16);

          // Check if extension record
          const baseRefLow = buf.readUInt32LE(32);
          const baseRefHigh = buf.readUInt16LE(36);
          const isExtension = baseRefLow !== 0 || baseRefHigh !== 0;
          const baseEntry = isExtension ? baseRefLow + baseRefHigh * 0x100000000 : entryNumber;

          // Walk attributes — collect best filename + resident $DATA content
          let fnBest = null, fnDos = null;
          const residentData = []; // { content: Buffer, streamName: string|null }

          let pos = attrOffset;
          while (pos + 8 <= buf.length) {
            const attrType = buf.readUInt32LE(pos);
            if (attrType === 0xFFFFFFFF || attrType === 0) break;
            const attrLen = buf.readUInt32LE(pos + 4);
            if (attrLen < 16 || pos + attrLen > buf.length) break;

            const nonResident = buf[pos + 8];
            const nameLen = buf[pos + 9];
            const nameOffset = buf.readUInt16LE(pos + 10);

            if (attrType === 0x30 && !nonResident) {
              // $FILE_NAME — use same namespace priority
              try {
                const fn = parseFN(buf, pos);
                if (fn) {
                  if (fn.namespace === 2) fnDos = fn;
                  else if (fn.namespace === 3) fnBest = fn;
                  else if (fn.namespace === 1) { if (!fnBest || fnBest.namespace !== 3) fnBest = fn; }
                  else { if (!fnBest) fnBest = fn; }
                }
              } catch {}
            } else if (attrType === 0x80 && !nonResident) {
              // Resident $DATA — extract content
              try {
                const contentSize = buf.readUInt32LE(pos + 16);
                const contentOffset = buf.readUInt16LE(pos + 20);
                const dataStart = pos + contentOffset;
                if (contentSize > 0 && dataStart + contentSize <= buf.length) {
                  let streamName = null;
                  if (nameLen > 0 && pos + nameOffset + nameLen * 2 <= buf.length) {
                    streamName = buf.toString("utf16le", pos + nameOffset, pos + nameOffset + nameLen * 2);
                  }
                  residentData.push({
                    content: Buffer.from(buf.subarray(dataStart, dataStart + contentSize)),
                    streamName,
                  });
                }
              } catch {}
            }

            pos += attrLen;
          }

          // Write extracted resident data files
          if (residentData.length > 0) {
            const fn = fnBest || fnDos;
            const baseName = sanitize(fn ? fn.filename : "unknown");
            const entry = isExtension ? baseEntry : entryNumber;

            for (const rd of residentData) {
              let outName;
              if (rd.streamName) {
                outName = `${entry}-${seqNum}_${baseName}_${sanitize(rd.streamName)}`;
              } else {
                outName = `${entry}-${seqNum}_${baseName}`;
              }
              // Use original extension if present, otherwise append .bin
              if (!path.extname(outName)) outName += ".bin";
              fs.writeFileSync(path.join(residentDir, outName), rd.content);
              extractedCount++;
            }
          }
        } catch {
          skippedErrors++;
        }

        // Progress + event loop yield
        const now = Date.now();
        if (now - lastYield >= 200) {
          lastYield = now;
          if (progressCb) progressCb(recordsProcessed, totalRecords);
          await new Promise((r) => setImmediate(r));
        }
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  return { extractedCount, totalRecords, outputDir: residentDir, skippedErrors };
}

module.exports = { isMftFile, parseMftFile, extractResidentData, parseMftRecord, buildMftRow, MFT_COLUMNS };
