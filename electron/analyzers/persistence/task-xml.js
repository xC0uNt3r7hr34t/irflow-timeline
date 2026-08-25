/**
 * analyzers/persistence/task-xml.js — Task Scheduler XML → structured task
 *
 * A registered scheduled task is a file under `Windows\System32\Tasks\<path>`, and that
 * file states outright what the analyzer currently tries to infer from event text: the
 * command, the arguments, whether it runs hidden, whether it runs elevated, whether the
 * action is a COM handler, and what triggers it.
 *
 * Today those flags come from scraping the fragments Task Scheduler happens to echo into
 * an event payload (index.js "deep task XML semantics"), which is why findings carry
 * `_taskXmlPartial`. Reading the definition itself is not an approximation of that — it is
 * the source those events are derived from, and it covers every registered task, including
 * ones that never fired during the log window.
 *
 * Deliberately not a general XML parser: the schema is fixed and the input is untrusted, so
 * extraction is index-based scanning with no backtracking regex anywhere.
 */

const TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task";

/**
 * Decode a task file to text. Windows writes these UTF-16LE with a BOM; KAPE copies them
 * byte-for-byte, and some tools rewrite them as UTF-8.
 */
function decodeTaskXml(buf) {
  if (!buf || buf.length === 0) return "";
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b.length >= 2 && b[0] === 0xff && b[1] === 0xfe) return b.subarray(2).toString("utf16le");
  if (b.length >= 2 && b[0] === 0xfe && b[1] === 0xff) return b.subarray(2).swap16().toString("utf16le");
  if (b.length >= 3 && b[0] === 0xef && b[1] === 0xbb && b[2] === 0xbf) return b.subarray(3).toString("utf8");
  // No BOM. A UTF-16LE ASCII payload has a NUL in every other byte; UTF-8 has none early on.
  const probe = b.subarray(0, Math.min(64, b.length));
  let nulls = 0;
  for (const byte of probe) if (byte === 0) nulls++;
  if (nulls > probe.length / 4) return b.toString("utf16le");
  return b.toString("utf8");
}

const XML_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
function unescapeXml(s) {
  if (!s || s.indexOf("&") === -1) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    const amp = s.indexOf("&", i);
    if (amp === -1) { out += s.slice(i); break; }
    out += s.slice(i, amp);
    const semi = s.indexOf(";", amp);
    // A bare "&" or a runaway entity: emit it literally rather than swallowing the rest.
    if (semi === -1 || semi - amp > 12) { out += "&"; i = amp + 1; continue; }
    const ent = s.slice(amp + 1, semi);
    if (ent[0] === "#") {
      const code = ent[1] === "x" || ent[1] === "X" ? parseInt(ent.slice(2), 16) : parseInt(ent.slice(1), 10);
      out += Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    } else if (XML_ENTITIES[ent] !== undefined) {
      out += XML_ENTITIES[ent];
    } else {
      out += s.slice(amp, semi + 1); // unknown entity — keep it visible
    }
    i = semi + 1;
  }
  return out;
}

// Strip an optional namespace prefix so <t:Command> matches "Command".
const _localName = (tagBody) => {
  const name = tagBody.split(/[\s/>]/, 1)[0];
  const colon = name.lastIndexOf(":");
  return colon === -1 ? name : name.slice(colon + 1);
};

/**
 * Collect the inner text of every `<name>` element, in document order.
 * Index-based: no regex, so no catastrophic backtracking on a hostile file.
 */
function collectTags(xml, name, { limit = 200 } = {}) {
  const out = [];
  if (!xml) return out;
  const lower = xml.toLowerCase();
  const want = name.toLowerCase();
  let i = 0;
  while (out.length < limit) {
    const open = lower.indexOf("<" + want, i);
    if (open === -1) break;
    const tagEnd = xml.indexOf(">", open);
    if (tagEnd === -1) break;
    const body = xml.slice(open + 1, tagEnd);
    // Reject a longer tag that merely starts with the same letters (<Command> vs <CommandLine>).
    if (_localName(body).toLowerCase() !== want) { i = open + 1; continue; }
    if (body.endsWith("/")) { out.push(""); i = tagEnd + 1; continue; } // self-closing
    const close = lower.indexOf("</" + want, tagEnd);
    if (close === -1) break;
    out.push(unescapeXml(xml.slice(tagEnd + 1, close)).trim());
    i = close + 1;
  }
  return out;
}

const firstTag = (xml, name) => {
  const all = collectTags(xml, name, { limit: 1 });
  return all.length > 0 ? all[0] : "";
};

/** Slice out one element including its children, so triggers/actions can be scoped. */
function sectionOf(xml, name) {
  if (!xml) return "";
  const lower = xml.toLowerCase();
  const want = name.toLowerCase();
  const open = lower.indexOf("<" + want);
  if (open === -1) return "";
  const tagEnd = xml.indexOf(">", open);
  if (tagEnd === -1) return "";
  const close = lower.indexOf("</" + want, tagEnd);
  if (close === -1) return "";
  return xml.slice(tagEnd + 1, close);
}

// Trigger element -> the short name the analyzer's scoring already understands.
const TRIGGER_KINDS = [
  ["BootTrigger", "boot"],
  ["LogonTrigger", "logon"],
  ["RegistrationTrigger", "registration"],
  ["TimeTrigger", "time"],
  ["CalendarTrigger", "calendar"],
  ["IdleTrigger", "idle"],
  ["EventTrigger", "event"],
  ["SessionStateChangeTrigger", "session"],
];

const _isTrue = (v) => /^(?:true|1)$/i.test(String(v || "").trim());

/**
 * Parse one task definition.
 *
 * @param buf          file contents
 * @param taskName     the task's path, derived from its location under Tasks\ (the file
 *                     name IS the task name; the XML's <URI> is a cross-check that is
 *                     frequently absent)
 * @returns a structured task, or null when the file is not a task definition
 */
function parseTaskXml(buf, { taskName = "" } = {}) {
  const xml = decodeTaskXml(buf);
  if (!xml || xml.toLowerCase().indexOf("<task") === -1) return null;

  const reg = sectionOf(xml, "RegistrationInfo");
  const settings = sectionOf(xml, "Settings");
  const principals = sectionOf(xml, "Principals");
  const triggersXml = sectionOf(xml, "Triggers");
  const actionsXml = sectionOf(xml, "Actions");

  const uri = firstTag(reg, "URI") || firstTag(xml, "URI");
  const name = taskName || uri || "";

  // Exec actions: a task may register several. Keep them all; the first is the headline.
  const commands = collectTags(actionsXml, "Command", { limit: 32 });
  const argsList = collectTags(actionsXml, "Arguments", { limit: 32 });
  const workingDirs = collectTags(actionsXml, "WorkingDirectory", { limit: 32 });
  const actions = commands.map((cmd, i) => ({
    command: cmd,
    arguments: argsList[i] || "",
    workingDirectory: workingDirs[i] || "",
  }));

  // COM handler actions run in-process via a CLSID — no image path to inspect, which is
  // exactly why they are used for stealth.
  const comHandlers = collectTags(actionsXml, "ClassId", { limit: 32 });

  const triggers = [];
  for (const [tag, kind] of TRIGGER_KINDS) {
    if (triggersXml.toLowerCase().indexOf("<" + tag.toLowerCase()) !== -1) triggers.push(kind);
  }

  const runLevel = firstTag(principals, "RunLevel");
  const principal = firstTag(principals, "UserId") || firstTag(principals, "GroupId");
  const enabledRaw = firstTag(settings, "Enabled");

  return {
    taskName: name,
    uri,
    author: firstTag(reg, "Author"),
    description: firstTag(reg, "Description"),
    registrationDate: firstTag(reg, "Date"),
    actions,
    command: actions[0]?.command || "",
    arguments: actions[0]?.arguments || "",
    comHandlers,
    hasComHandler: comHandlers.length > 0 || actionsXml.toLowerCase().indexOf("<comhandler") !== -1,
    hidden: _isTrue(firstTag(settings, "Hidden")),
    // An absent <Enabled> means enabled — the default is true.
    enabled: enabledRaw === "" ? true : _isTrue(enabledRaw),
    runLevel,
    elevated: /highest/i.test(runLevel || ""),
    principal,
    logonType: firstTag(principals, "LogonType"),
    triggers,
    // Version 1.0 tasks (XP-era) have no <Task> namespace; worth knowing when triaging.
    schemaVersion: (/<Task[^>]*\sversion="([^"]{1,16})"/i.exec(xml) || [])[1] || "",
    hasTaskNamespace: xml.indexOf(TASK_NS) !== -1,
  };
}

/**
 * Task path from a file's location under `...\Windows\System32\Tasks\`.
 * The folder structure IS the task path: `Tasks\Microsoft\Windows\Defrag\ScheduledDefrag`
 * is the task `\Microsoft\Windows\Defrag\ScheduledDefrag`.
 */
function taskNameFromPath(filePath) {
  const norm = String(filePath || "").replace(/\\/g, "/");
  const m = /\/Windows\/System32\/Tasks\/(.+)$/i.exec(norm);
  if (!m) return "";
  return "\\" + m[1].split("/").filter(Boolean).join("\\");
}

module.exports = {
  parseTaskXml,
  decodeTaskXml,
  unescapeXml,
  collectTags,
  taskNameFromPath,
  TRIGGER_KINDS,
};
