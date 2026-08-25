// Tests for the trigram-FTS5 default-search optimization (release review M5).
//
// The default global search regressed from an indexed FTS5 lookup to a full-table
// concat-LIKE scan (while still building an unused FTS index every import). M5 rebuilds
// data_fts with the FTS5 trigram tokenizer (substring MATCH) and restores an indexed
// prefilter in _applySearch: the trigram MATCH narrows candidate rows, and the existing
// LIKE conditions re-confirm exact semantics. The prefilter must be a SUPERSET of the
// LIKE result so results are identical — just faster on large datasets.
//
// Needs a live SQLite binding; skipped under a Node runtime without the native module
// built (CI rebuilds it). Run after `npm rebuild better-sqlite3`.

const test = require("node:test");
const assert = require("node:assert/strict");

let Database = null;
try { Database = require("better-sqlite3"); } catch { /* native module not built */ }
const HAVE_SQLITE = (() => {
  if (!Database) return false;
  try { const d = new Database(":memory:"); d.close(); return true; } catch { return false; }
})();

const proto = require("../electron/db/query-store");

test("trigram FTS prefilter: substring search is correct AND result-equivalent to pure LIKE",
  { skip: HAVE_SQLITE ? false : "better-sqlite3 native module not built for this runtime" },
  () => {
    const db = new Database(":memory:");
    db.exec("CREATE TABLE data (c0 TEXT, c1 TEXT)");
    const rows = [
      [1, "crackb4ckd00r detected", "HOST-A"],
      [2, "clean process started", "WORKSTATION01"],
      [3, "powershell -enc foobar", "HOST-A"],
      [4, "net use server share", "DC01"],
    ];
    const ins = db.prepare("INSERT INTO data(rowid,c0,c1) VALUES (?,?,?)");
    for (const r of rows) ins.run(...r);
    db.exec("CREATE VIRTUAL TABLE data_fts USING fts5(c0,c1,content=data,content_rowid=rowid,tokenize='trigram')");
    db.exec("INSERT INTO data_fts(rowid,c0,c1) SELECT rowid,c0,c1 FROM data");

    const headers = ["Message", "Computer"];
    const safeCols = [{ original: "Message", safe: "c0" }, { original: "Computer", safe: "c1" }];
    const colMap = { Message: "c0", Computer: "c1" };

    const run = (term, mode, cond, ftsReady) => {
      const meta = { safeCols, colMap, headers, ftsReady };
      const wc = [], params = [];
      proto._applySearch(term, mode, meta, wc, params, cond);
      const sql = `SELECT rowid FROM data${wc.length ? " WHERE " + wc.join(" AND ") : ""}`;
      const ids = db.prepare(sql).all(...params).map((r) => r.rowid).sort((a, b) => a - b);
      return { ids, usedFts: /data_fts MATCH/.test(wc.join(" ")) };
    };

    // Run with the index ready (uses the prefilter) and without (pure LIKE); the
    // prefilter must never change the result set.
    const bothWays = (term, mode, cond) => {
      const withFts = run(term, mode, cond, true);
      const withoutFts = run(term, mode, cond, false);
      assert.deepEqual(withFts.ids, withoutFts.ids,
        `FTS prefilter changed results for "${term}" (${mode}/${cond}): ${JSON.stringify(withFts.ids)} vs ${JSON.stringify(withoutFts.ids)}`);
      return withFts;
    };

    // issue #8: a substring embedded in a larger token must match (default mixed mode)
    let r = bothWays("b4ckd00r", "mixed", "contains");
    assert.deepEqual(r.ids, [1], "b4ckd00r must match crackb4ckd00r");
    assert.ok(r.usedFts, "ready index → prefilter used");

    // exact mode, substring containing a space and a regex/FTS special char
    r = bothWays("powershell -enc", "exact", "contains");
    assert.deepEqual(r.ids, [3]);
    assert.ok(r.usedFts);

    // AND mode — all terms required
    r = bothWays("clean process", "and", "contains");
    assert.deepEqual(r.ids, [2]);
    assert.ok(r.usedFts);

    // OR mode — superset prefilter only when every term is >=3 chars
    r = bothWays("powershell server", "or", "contains");
    assert.deepEqual(r.ids, [3, 4]);
    assert.ok(r.usedFts);

    // mixed with exclusion — "host" required, "crack" excluded
    r = bothWays("host -crack", "mixed", "contains");
    assert.deepEqual(r.ids, [3], "rows with 'host' but not 'crack'");
    assert.ok(r.usedFts, "the required 'host' term drives the prefilter; -crack stays LIKE-only");

    // column-qualified Col:value
    r = bothWays("Computer:host", "mixed", "contains");
    assert.deepEqual(r.ids, [1, 3]);
    assert.ok(r.usedFts);

    // term <3 chars cannot be trigram-indexed → must fall back to LIKE (no prefilter)
    r = bothWays("en", "mixed", "contains");
    assert.deepEqual(r.ids, [3], "'en' substring (in -enc) via LIKE");
    assert.equal(r.usedFts, false, "<3-char terms must not use the trigram prefilter");

    // no-match sanity
    r = bothWays("zzzqqq", "mixed", "contains");
    assert.deepEqual(r.ids, []);

    db.close();
  });
