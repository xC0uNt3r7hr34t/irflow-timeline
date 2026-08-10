const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const { dbg } = require("../logger");
const { BATCH_SIZE_DEFAULT } = require("./csv");

const BATCH_SIZE_MAX_BYTES = 100 * 1024 * 1024; // ~100MB target max per batch

// FILETIME epoch: 100ns intervals between 1601-01-01 and 1970-01-01
const FT_EPOCH_DIFF = 116444736000000000n;

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

/** Extract file extension from filename */
function mftGetExtension(filename) {
  if (!filename) return "";
  const dot = filename.lastIndexOf(".");
  if (dot <= 0 || dot === filename.length - 1) return "";
  return filename.substring(dot);
}

const USN_COLUMNS = [
  "Name", "Extension", "EntryNumber", "SequenceNumber",
  "ParentEntryNumber", "ParentSequenceNumber", "ParentPath",
  "UpdateSequenceNumber", "UpdateTimestamp", "UpdateReasons",
  "FileAttributes", "SourceInfo", "OffsetToData", "SourceFile",
];

// USN_SOURCE_* flags (the SourceInfo field). A NON-zero value means the change was driven by
// the OS/replication subsystem rather than a user/process — the cleanest false-positive
// discriminator for destructive-looking bursts (defrag, TxF, FRS/DFSR). Empty = user-driven.
const USN_SOURCE_INFO_FLAGS = [
  [0x00000001, "DataManagement"],               // USN_SOURCE_DATA_MANAGEMENT (defrag, ScanDisk, system)
  [0x00000002, "AuxiliaryData"],                // USN_SOURCE_AUXILIARY_DATA
  [0x00000004, "ReplicationManagement"],        // USN_SOURCE_REPLICATION_MANAGEMENT (FRS/DFSR)
  [0x00000008, "ClientReplicationManagement"],  // USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT
];

const USN_REASON_FLAGS = [
  [0x00000001, "DataOverwrite"],
  [0x00000002, "DataExtend"],
  [0x00000004, "DataTruncation"],
  [0x00000010, "NamedDataOverwrite"],
  [0x00000020, "NamedDataExtend"],
  [0x00000040, "NamedDataTruncation"],
  [0x00000100, "FileCreate"],
  [0x00000200, "FileDelete"],
  [0x00000400, "EaChange"],
  [0x00000800, "SecurityChange"],
  [0x00001000, "RenameOldName"],
  [0x00002000, "RenameNewName"],
  [0x00004000, "IndexableChange"],
  [0x00008000, "BasicInfoChange"],
  [0x00010000, "HardLinkChange"],
  [0x00020000, "CompressionChange"],
  [0x00040000, "EncryptionChange"],
  [0x00080000, "ObjectIdChange"],
  [0x00100000, "ReparsePointChange"],
  [0x00200000, "StreamChange"],
  [0x00400000, "TransactedChange"],
  [0x00800000, "IntegrityChange"],
  [0x01000000, "DesiredStorageClassChange"],
  [0x80000000, "Close"],
];

const USN_ATTR_FLAGS = [
  [0x0001, "ReadOnly"], [0x0002, "Hidden"], [0x0004, "System"],
  [0x0010, "Directory"], [0x0020, "Archive"], [0x0040, "Device"],
  [0x0080, "Normal"], [0x0100, "Temporary"], [0x0200, "SparseFile"],
  [0x0400, "ReparsePoint"], [0x0800, "Compressed"], [0x1000, "Offline"],
  [0x2000, "NotContentIndexed"], [0x4000, "Encrypted"],
];

/** Decode USN reason bitmask to pipe-separated string */
function usnReasonToString(reason) {
  const parts = [];
  for (const [mask, name] of USN_REASON_FLAGS) {
    if (reason & mask) parts.push(name);
  }
  return parts.join("|") || String(reason);
}

/** Decode USN SourceInfo bitmask to pipe-separated string ("" = user-driven change) */
function usnSourceInfoToString(sourceInfo) {
  if (!sourceInfo) return "";
  const parts = [];
  for (const [mask, name] of USN_SOURCE_INFO_FLAGS) {
    if (sourceInfo & mask) parts.push(name);
  }
  return parts.join("|") || "";
}

/** Decode file attributes bitmask to pipe-separated string */
function usnAttrsToString(attrs) {
  const parts = [];
  for (const [mask, name] of USN_ATTR_FLAGS) {
    if (attrs & mask) parts.push(name);
  }
  return parts.join("|") || "";
}

/**
 * Check if a file is a raw $J (USN Journal) by filename patterns
 */
function isUsnJrnlFile(filePath) {
  const base = path.basename(filePath).toUpperCase();
  // Common names: $UsnJrnl%3A$J, $UsnJrnl:$J, $J
  if (base.includes("USNJRNL") || base === "$J") return true;
  // Also check parent directory for $Extend
  const dir = path.basename(path.dirname(filePath)).toUpperCase();
  if (dir.includes("EXTEND") && base.startsWith("$")) return true;
  return false;
}

/**
 * Parse raw $J (USN Journal) binary file
 * USN_RECORD_V2: variable-length records, may start with null padding
 */
async function parseUsnJrnlFile(filePath, tabId, db, onProgress) {
  let fileSize, fd;
  try {
    fileSize = fs.statSync(filePath).size;
    fd = fs.openSync(filePath, "r");
  } catch (e) {
    throw new Error(`Cannot open USN Journal file: ${e.message}`);
  }
  dbg("USN", `parseUsnJrnlFile start`, { filePath, fileSize });

  const headers = [...USN_COLUMNS];
  const colCount = headers.length;
  db.createTab(tabId, headers);

  const batchSize = Math.max(5000, Math.min(BATCH_SIZE_DEFAULT, Math.floor(BATCH_SIZE_MAX_BYTES / (colCount * 80))));
  const sourceFile = filePath;

  const READ_CHUNK = 4 * 1024 * 1024; // Read 4MB at a time
  const chunkBuf = Buffer.alloc(READ_CHUNK + 4096); // Extra space for record spanning chunk boundary
  let batch = [];
  let rowCount = 0;
  let lastYield = Date.now();
  let fileReadPos = 0; // Next byte to read from the file
  let carryOver = 0;   // Bytes carried from previous chunk (already at chunkBuf[0..carryOver-1])
  let isFirstChunk = true;

  try {
    while (fileReadPos < fileSize || carryOver > 0) {
      const bytesToRead = Math.min(READ_CHUNK + 4096 - carryOver, fileSize - fileReadPos);
      if (bytesToRead <= 0 && carryOver === 0) break;

      // Read new data after carry-over bytes
      const bytesRead = fs.readSync(fd, chunkBuf, carryOver, Math.max(0, bytesToRead), fileReadPos);
      if (bytesRead === 0 && carryOver === 0) break; // EOF with no pending data
      fileReadPos += bytesRead;
      const available = carryOver + bytesRead;
      if (available < 60) break; // Minimum USN_RECORD_V2 size

      // chunkBuf[0] corresponds to this file position
      const chunkBase = fileReadPos - available;
      let pos = 0;

      if (isFirstChunk) {
        isFirstChunk = false;
        // Skip initial null padding (sparse file region)
        while (pos + 8 <= available) {
          if (chunkBuf.readBigUInt64LE(pos) !== 0n) break;
          pos += 8;
        }
        if (pos > 0) {
          dbg("USN", `Skipped sparse region`, { nullBytes: pos });
        }
      }

      // Parse records from this chunk
      while (pos + 60 <= available) {
        // Skip null padding between records
        if (chunkBuf.readUInt32LE(pos) === 0) {
          pos += 8; // Align to 8-byte boundary
          continue;
        }

        const recLen = chunkBuf.readUInt32LE(pos);
        // Sanity: USN_RECORD_V2 min=60, max reasonable ~4096
        if (recLen < 60 || recLen > 4096) {
          pos += 8;
          continue;
        }

        // Need full record in buffer
        if (pos + recLen > available) break; // Will carry over

        const majorVer = chunkBuf.readUInt16LE(pos + 4);

        if (majorVer === 2) {
          // USN_RECORD_V2
          const entryLo = chunkBuf.readUInt32LE(pos + 8);
          const entryHi = chunkBuf.readUInt16LE(pos + 12);
          const entryNum = entryLo + entryHi * 0x100000000;
          const seqNum = chunkBuf.readUInt16LE(pos + 14);

          const parentLo = chunkBuf.readUInt32LE(pos + 16);
          const parentHi = chunkBuf.readUInt16LE(pos + 20);
          const parentEntry = parentLo + parentHi * 0x100000000;
          const parentSeq = chunkBuf.readUInt16LE(pos + 22);

          const usn = chunkBuf.readBigUInt64LE(pos + 24);
          const timestamp = chunkBuf.readBigUInt64LE(pos + 32);
          const reason = chunkBuf.readUInt32LE(pos + 40);
          const sourceInfo = chunkBuf.readUInt32LE(pos + 44); // SourceInfo (system/replication vs user)
          const fileAttrs = chunkBuf.readUInt32LE(pos + 52);
          const nameLen = chunkBuf.readUInt16LE(pos + 56);
          const nameOff = chunkBuf.readUInt16LE(pos + 58);

          let filename = "";
          if (nameLen > 0 && pos + nameOff + nameLen <= available) {
            filename = chunkBuf.toString("utf16le", pos + nameOff, pos + nameOff + nameLen);
          }

          const ext = mftGetExtension(filename);
          const dataOffset = chunkBase + pos;

          batch.push([
            filename,                                    // Name
            ext,                                         // Extension
            String(entryNum),                            // EntryNumber
            String(seqNum),                              // SequenceNumber
            String(parentEntry),                         // ParentEntryNumber
            String(parentSeq),                           // ParentSequenceNumber
            "",                                          // ParentPath (needs $MFT)
            String(usn),                                 // UpdateSequenceNumber
            filetimeToIso(timestamp),                    // UpdateTimestamp
            usnReasonToString(reason),                   // UpdateReasons
            usnAttrsToString(fileAttrs),                 // FileAttributes
            usnSourceInfoToString(sourceInfo),           // SourceInfo
            String(dataOffset),                          // OffsetToData
            sourceFile,                                  // SourceFile
          ]);
          rowCount++;
        } else if (majorVer === 3) {
          // USN_RECORD_V3 — 128-bit file references (16 bytes each)
          if (recLen < 76 || pos + 76 > available) { pos += Math.max(recLen, 8); continue; }
          const entryLo = chunkBuf.readUInt32LE(pos + 8);
          const seqNum = chunkBuf.readUInt16LE(pos + 14);
          const parentLo = chunkBuf.readUInt32LE(pos + 24);
          const parentSeq = chunkBuf.readUInt16LE(pos + 30);

          const usn = chunkBuf.readBigUInt64LE(pos + 40);
          const timestamp = chunkBuf.readBigUInt64LE(pos + 48);
          const reason = chunkBuf.readUInt32LE(pos + 56);
          const sourceInfo = chunkBuf.readUInt32LE(pos + 60); // SourceInfo (V3 layout)
          const fileAttrs = chunkBuf.readUInt32LE(pos + 68);
          const nameLen = chunkBuf.readUInt16LE(pos + 72);
          const nameOff = chunkBuf.readUInt16LE(pos + 74);

          let filename = "";
          if (nameLen > 0 && pos + nameOff + nameLen <= available) {
            filename = chunkBuf.toString("utf16le", pos + nameOff, pos + nameOff + nameLen);
          }

          const ext = mftGetExtension(filename);
          const dataOffset = chunkBase + pos;

          batch.push([
            filename, ext, String(entryLo), String(seqNum),
            String(parentLo), String(parentSeq), "",
            String(usn), filetimeToIso(timestamp),
            usnReasonToString(reason), usnAttrsToString(fileAttrs),
            usnSourceInfoToString(sourceInfo),
            String(dataOffset), sourceFile,
          ]);
          rowCount++;
        }
        // else: unknown version, skip

        pos += recLen;
        // Align to 8-byte boundary
        if (pos % 8 !== 0) pos += 8 - (pos % 8);
      }

      // Flush batch
      if (batch.length >= batchSize) {
        db.insertBatchArrays(tabId, batch);
        batch = [];
      }

      // Carry remaining bytes to next iteration
      if (pos < available) {
        const remaining = available - pos;
        chunkBuf.copy(chunkBuf, 0, pos, pos + remaining);
        carryOver = remaining;
      } else {
        carryOver = 0;
      }

      // EOF with unprocessable carry-over — break to avoid infinite loop
      if (bytesRead === 0) break;

      // Progress + yield
      const now = Date.now();
      if (now - lastYield >= 200) {
        lastYield = now;
        if (onProgress) onProgress(rowCount, fileReadPos, fileSize);
        await new Promise((r) => setImmediate(r));
      }
    }
  } finally {
    fs.closeSync(fd);
  }

  // Final batch
  if (batch.length > 0) {
    db.insertBatchArrays(tabId, batch);
    batch = [];
  }

  if (onProgress) onProgress(rowCount, fileSize, fileSize);
  const result = db.finalizeImport(tabId);

  const mem = process.memoryUsage();
  dbg("USN", `parseUsnJrnlFile done`, { rowCount, heapUsedMB: Math.round(mem.heapUsed / 1048576), rssMB: Math.round(mem.rss / 1048576) });

  return {
    headers,
    rowCount: result.rowCount,
    tsColumns: result.tsColumns,
    numericColumns: result.numericColumns,
    sourceFormat: "raw-usnjrnl",
  };
}

module.exports = { isUsnJrnlFile, parseUsnJrnlFile, usnSourceInfoToString, usnReasonToString };
