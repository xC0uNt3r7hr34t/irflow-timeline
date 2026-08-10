const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");

const TimelineDB = require("../electron/db");
const {
  FIXED_FIELDS,
  buildPlasoMessage,
  extractEvtxChannel,
  formatEpochMicroseconds,
  formatPlasoDateTime,
  normalizePlasoValue,
  parsePlasoBlob,
  parsePlasoFile,
} = require("../electron/parsers/plaso");

test("Plaso FILETIME decorators become canonical UTC timestamps", () => {
  const value = {
    __class_name__: "Filetime",
    __type__: "DateTimeValues",
    timestamp: "132116226764533490",
  };
  assert.equal(formatPlasoDateTime(value), "2019-08-30 07:11:16.453349");
  assert.equal(normalizePlasoValue(value), "2019-08-30 07:11:16.453349");
});

test("Plaso date-time classes present in supplied images normalize correctly", () => {
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "PosixTimeInNanoseconds",
      __type__: "DateTimeValues",
      timestamp: "1780307980893475300",
    }),
    "2026-06-01 09:59:40.893475"
  );
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "WebKitTime",
      __type__: "DateTimeValues",
      timestamp: "13423569929871700",
    }),
    "2026-05-18 09:25:29.871700"
  );
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "FATDateTime",
      __type__: "DateTimeValues",
      fat_date_time: 1963285687,
    }),
    "2026-05-23 14:40:10.000000"
  );
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "TimeElementsInMicroseconds",
      __type__: "DateTimeValues",
      time_elements_tuple: [2023, 12, 13, 5, 49, 1, 123456],
      time_zone_offset: 60,
    }),
    "2023-12-13 04:49:01.123456"
  );
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "Systemtime",
      __type__: "DateTimeValues",
      system_time_tuple: [2026, 4, 4, 9, 16, 56, 21, 634],
    }),
    "2026-04-09 16:56:21.634000"
  );
  assert.equal(
    formatPlasoDateTime({
      __class_name__: "NotSet",
      __type__: "DateTimeValues",
      string: "Not set",
    }),
    ""
  );
});

test("Plaso blob parsing preserves unsafe timestamp integers before conversion", () => {
  const serialized = Buffer.from(
    '{"creation_time":{"__class_name__":"Filetime","__type__":"DateTimeValues","timestamp":132116226764533490}}'
  );
  const parsed = parsePlasoBlob(zlib.deflateSync(serialized), true);
  assert.equal(parsed.creation_time.timestamp, "132116226764533490");
  assert.equal(normalizePlasoValue(parsed.creation_time), "2019-08-30 07:11:16.453349");
});

test("EVTX XML becomes a readable named body and exposes its channel", () => {
  const xmlString = `<Event>
    <System><Channel>Security</Channel></System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-5-18</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="CommandLine">cmd.exe /c whoami &amp;&amp; hostname</Data>
    </EventData>
  </Event>`;
  assert.equal(extractEvtxChannel(xmlString), "Security");
  assert.equal(
    buildPlasoMessage({ xml_string: xmlString, strings: ["unlabelled fallback"] }),
    [
      "SubjectUserSid=S-1-5-18",
      "NewProcessName=C:\\Windows\\System32\\cmd.exe",
      "CommandLine=cmd.exe /c whoami && hostname",
    ].join("\n")
  );
});

test("Plaso core fields do not depend on heterogeneous schema sampling", () => {
  for (const field of [
    "datetime",
    "message",
    "event_identifier",
    "source_name",
    "computer_name",
    "channel",
    "creation_time",
    "written_time",
    "xml_string",
    "extra_fields",
  ]) {
    assert.ok(FIXED_FIELDS.includes(field), `missing stable Plaso field: ${field}`);
  }
});

test("Plaso import keeps EVTX bodies and date-range capable timestamps", async (t) => {
  let Database;
  try {
    Database = require("better-sqlite3");
    const probe = new Database(":memory:");
    probe.close();
  } catch (err) {
    if (err?.code === "ERR_DLOPEN_FAILED") {
      t.skip("better-sqlite3 native module is not built for this Node runtime");
      return;
    }
    throw err;
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "tle-plaso-test-"));
  const sourcePath = path.join(tempDir, "fixture.plaso");
  t.after(() => fs.rmSync(tempDir, { recursive: true, force: true }));

  const source = new Database(sourcePath);
  source.exec(`
    CREATE TABLE metadata (key TEXT, value TEXT);
    CREATE TABLE event_data (
      _identifier INTEGER PRIMARY KEY AUTOINCREMENT,
      _data BLOB
    );
    CREATE TABLE event (
      _identifier INTEGER PRIMARY KEY AUTOINCREMENT,
      _event_data_identifier TEXT,
      date_time TEXT,
      timestamp INTEGER,
      timestamp_desc TEXT
    );
  `);
  source.prepare("INSERT INTO metadata (key, value) VALUES (?, ?)").run("format_version", "20230327");
  source.prepare("INSERT INTO metadata (key, value) VALUES (?, ?)").run("compression_format", "zlib");

  const eventData = {
    __type__: "AttributeContainer",
    __container_type__: "event_data",
    _parser_chain: "winevtx",
    data_type: "windows:evtx:record",
    creation_time: {
      __class_name__: "Filetime",
      __type__: "DateTimeValues",
      timestamp: 132116226764533490,
    },
    written_time: {
      __class_name__: "Filetime",
      __type__: "DateTimeValues",
      timestamp: 132116226764533490,
    },
    computer_name: "HOST-01",
    event_identifier: 4688,
    record_number: 42,
    source_name: "Microsoft-Windows-Security-Auditing",
    strings: ["S-1-5-18", "cmd.exe"],
    xml_string: `<Event>
      <System><Channel>Security</Channel></System>
      <EventData>
        <Data Name="SubjectUserSid">S-1-5-18</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      </EventData>
    </Event>`,
    uncommon_late_field: "retained",
  };
  const insertData = source.prepare("INSERT INTO event_data (_data) VALUES (?)");
  const dataInfo = insertData.run(zlib.deflateSync(Buffer.from(JSON.stringify(eventData))));
  source.prepare(`
    INSERT INTO event (
      _event_data_identifier, date_time, timestamp, timestamp_desc
    ) VALUES (?, ?, ?, ?)
  `).run(
    `event_data.${dataInfo.lastInsertRowid}`,
    JSON.stringify(eventData.creation_time),
    1567149076453349,
    "Written Time"
  );
  source.prepare(`
    INSERT INTO event (
      _event_data_identifier, date_time, timestamp, timestamp_desc
    ) VALUES (?, ?, ?, ?)
  `).run(
    `event_data.${dataInfo.lastInsertRowid}`,
    JSON.stringify({
      __class_name__: "NotSet",
      __type__: "DateTimeValues",
      string: "Not set",
    }),
    0,
    "Not a time"
  );
  source.close();

  const target = new TimelineDB();
  target._dbPathHint = path.join(tempDir, "timeline.sqlite");
  try {
    const result = await parsePlasoFile(sourcePath, "plaso-tab", target);
    assert.equal(result.rowCount, 2);
    assert.ok(result.tsColumns.includes("datetime"));
    assert.ok(result.tsColumns.includes("creation_time"));

    const queried = target.queryRows("plaso-tab", {
      offset: 0,
      limit: 10,
      dateRangeFilters: {
        datetime: {
          from: "2019-08-30T07:11:00",
          to: "2019-08-30T07:12:00",
        },
      },
    });
    assert.equal(queried.totalFiltered, 1);
    const row = queried.rows[0];
    assert.equal(row.datetime, "2019-08-30 07:11:16.453349");
    assert.equal(row.creation_time, "2019-08-30 07:11:16.453349");
    assert.equal(row.channel, "Security");
    assert.match(row.message, /NewProcessName=C:\\Windows\\System32\\cmd\.exe/);
    assert.doesNotMatch(row.creation_time, /__class_name__/);

    const allRows = target.queryRows("plaso-tab", { offset: 0, limit: 10 });
    assert.equal(allRows.rows.find((candidate) => candidate.timestamp_desc === "Not a time")?.datetime, "");
  } finally {
    target.closeAll();
  }
});

test("normalized Plaso microseconds preserve canonical lexical range ordering", () => {
  assert.equal(formatEpochMicroseconds("1567149076453349"), "2019-08-30 07:11:16.453349");
  assert.ok(
    formatEpochMicroseconds("1567149076453349") >= "2019-08-30T07:11:00".replace("T", " ")
  );
});

test("date-range filters canonicalize UI and forensic timestamp separators", () => {
  const whereConditions = [];
  const params = [];
  TimelineDB.prototype._applyDateRangeFilters(
    {
      datetime: {
        from: "2019-08-30T07:11:00",
        to: "2019-08-30T07:12:00",
      },
    },
    {
      colMap: { datetime: "c0" },
      tsColumns: new Set(["datetime"]),
    },
    whereConditions,
    params
  );
  assert.deepEqual(whereConditions, [
    "sort_datetime(c0) >= sort_datetime(?)",
    "sort_datetime(c0) <= sort_datetime(?)",
  ]);
  assert.deepEqual(params, [
    "2019-08-30T07:11:00",
    "2019-08-30T07:12:00",
  ]);
});
