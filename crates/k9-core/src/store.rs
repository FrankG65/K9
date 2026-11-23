//! SQLite store for detections, remembered decisions, quarantine entries,
//! the event log, the notification queue and schedule bookkeeping.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::model::{Action, Decision, Detection, DetectionStatus, Finding, Kind, QuarantineEntry, Severity};

fn details_json(f: &Finding) -> Option<String> {
    f.details.as_ref().map(|d| d.to_string())
}
use crate::now_string;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    engine      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'offen',
    action      TEXT,
    kind        TEXT NOT NULL DEFAULT 'datei',
    details     TEXT,
    UNIQUE(path, sha256, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);
CREATE TABLE IF NOT EXISTS decisions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    action      TEXT NOT NULL,
    decided_at  TEXT NOT NULL,
    note        TEXT,
    UNIQUE(sha256, rule_id)
);
CREATE TABLE IF NOT EXISTS quarantine (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id   INTEGER,
    original_path  TEXT NOT NULL,
    stored_file    TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    size           INTEGER NOT NULL,
    threat_name    TEXT NOT NULL,
    xor_key        BLOB NOT NULL,
    sddl           TEXT,
    quarantined_at TEXT NOT NULL,
    restored_at    TEXT
);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    level   TEXT NOT NULL,
    message TEXT NOT NULL
);
"#;

/// Bookkeeping that stays in the user's database (no security relevance).
const LOCAL_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS notification_queue (
    detection_id INTEGER PRIMARY KEY,
    queued_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_cache (
    path   TEXT PRIMARY KEY,
    size   INTEGER NOT NULL,
    mtime  INTEGER NOT NULL,
    state  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS window_queue (
    detection_id INTEGER PRIMARY KEY,
    not_before   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS schedule_runs (
    key      TEXT PRIMARY KEY,
    last_run TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fund_puffer (
    seq   INTEGER PRIMARY KEY,
    funde TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dienst_ausgang (
    nr         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL UNIQUE,
    schluessel TEXT NOT NULL UNIQUE,
    nachricht  TEXT NOT NULL
);
"#;

/// Tables that belong to the Windows service when it is installed.
const SHARED_TABLES: [&str; 5] = ["detections", "decisions", "quarantine", "events", "disabled_autostart"];

const DISABLED_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS disabled_autostart (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id INTEGER NOT NULL,
    label        TEXT NOT NULL,
    backup       TEXT NOT NULL,
    disabled_at  TEXT NOT NULL,
    restored_at  TEXT
);
"#;

pub struct Store {
    conn: Connection,
    /// The service's database is attached read-only; changes go through the service.
    remote: bool,
}

/// Adds columns introduced after step 1 to existing databases.
///
/// In one write transaction: "is the column there?" and "add it" must not be separated.
/// Without it two programs opening a new database at the same moment both saw the column
/// missing, and the second one failed with "duplicate column name: signatur" (found by the
/// test below on 22.11.2026, about one run in five).
fn migrate(conn: &Connection) -> Result<()> {
    // An up-to-date database (the normal case) needs no write lock at all.
    if conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? >= 3 {
        return Ok(());
    }
    conn.execute_batch("BEGIN IMMEDIATE")?;
    match migrate_steps(conn) {
        Ok(()) => Ok(conn.execute_batch("COMMIT")?),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

fn migrate_steps(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(detections)")?;
    let cols: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
    if !cols.iter().any(|c| c == "kind") {
        conn.execute_batch("ALTER TABLE detections ADD COLUMN kind TEXT NOT NULL DEFAULT 'datei'; ALTER TABLE detections ADD COLUMN details TEXT;")?;
    }
    // v2: process findings use a narrow fingerprint (rule + parent + command line).
    // Older process allowances were keyed by the program file alone (too broad) -> removed.
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 2 {
        let removed = conn.execute("DELETE FROM decisions WHERE rule_id LIKE 'PROZESS%'", [])?;
        if removed > 0 {
            conn.execute(
                "INSERT INTO events (ts, level, message) VALUES (?1, 'warnung', ?2)",
                params![now_string(), format!("{removed} zu breite Prozess-Freigabe(n) aus älterer Version entfernt – der Fall wird bei Bedarf neu gefragt")],
            )?;
        }
        conn.pragma_update(None, "user_version", 2)?;
    }
    // v3: decisions signed by the Windows service.
    if version < 3 {
        let mut stmt = conn.prepare("PRAGMA table_info(decisions)")?;
        let cols: Vec<String> = stmt.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<_>>()?;
        drop(stmt);
        if !cols.iter().any(|c| c == "signatur") {
            conn.execute_batch("ALTER TABLE decisions ADD COLUMN signatur TEXT;")?;
        }
        conn.pragma_update(None, "user_version", 3)?;
    }
    Ok(())
}

/// Result of registering a finding without a remembered decision.
#[derive(Debug)]
pub enum Upsert {
    /// First time seen (or re-opened after a revoked decision): notify.
    New(Detection),
    /// Already waiting for a decision: do not notify again.
    AlreadyPending(Detection),
}

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct Counts {
    pub pending: i64,
    pub decisions: i64,
    pub quarantined: i64,
    pub detections_total: i64,
}

/// "database is locked"/"busy": another connection is in the way right now.
fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if matches!(f.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked))
}

impl Store {
    /// Opens the database. With the Windows service, findings, decisions,
    /// quarantine list, events and disabled autostarts live in its own
    /// database `%ProgramData%\K9\geschuetzt.db`: the service opens
    /// only that one; agent and k9 attach it read-only.
    pub fn open(path: &Path) -> Result<Self> {
        if crate::schutz::in_service() {
            return Self::open_protected(&crate::schutz::protected_db_path());
        }
        match crate::schutz::protected_db() {
            Some(p) => Self::open_attached(path, &p),
            None => {
                let conn = Connection::open(path).with_context(|| format!("Datenbank {} kann nicht geöffnet werden", path.display()))?;
                Self::init(conn)
            }
        }
    }

    /// Opens the same database file a second time (for tests of concurrent access).
    #[cfg(test)]
    fn open_file(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // Agent and CLI may access the DB at the same time.
        conn.busy_timeout(Duration::from_secs(10))?;
        // The file may be changed by any program of the user: no trusted schema.
        let _ = conn.pragma_update(None, "trusted_schema", "OFF");
        // A brand-new database is switched to WAL by the first connection. SQLite refuses that
        // at once ("database is locked", without waiting for the busy timeout) while another
        // thread has the file open – at the very first start several parts of the agent open
        // it together, and a dashboard request in that moment got an error. So: try again.
        let setup = |conn: &Connection| -> rusqlite::Result<()> {
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.execute_batch(SCHEMA)?;
            conn.execute_batch(DISABLED_SCHEMA)?;
            conn.execute_batch(LOCAL_SCHEMA)
        };
        let mut tries = 0;
        loop {
            match setup(&conn) {
                Ok(()) => break,
                Err(e) if tries < 50 && is_busy(&e) => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => return Err(e.into()),
            }
        }
        migrate(&conn)?;
        Ok(Self { conn, remote: false })
    }

    /// The service's database (service process). Opened with SYSTEM rights;
    /// the journal stays in memory, so later writes need no new files in the
    /// protected folder (the request threads act with the user's rights).
    pub fn open_protected(path: &Path) -> Result<Self> {
        let conn = crate::schutz::as_system(|| Connection::open(path))
            .with_context(|| format!("Geschützte Datenbank {} nicht verfügbar", path.display()))?;
        conn.busy_timeout(Duration::from_secs(10))?;
        let _ = conn.pragma_update(None, "trusted_schema", "OFF");
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(DISABLED_SCHEMA)?;
        conn.execute_batch(LOCAL_SCHEMA)?;
        migrate(&conn)?;
        Ok(Self { conn, remote: false })
    }

    /// The service's database opened by the elevated `k9 dienst aktualisieren` while the
    /// service is stopped (administrators may write the protected folder; no SYSTEM token).
    pub fn open_protected_admin(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("Geschützte Datenbank {} nicht verfügbar", path.display()))?;
        conn.busy_timeout(Duration::from_secs(10))?;
        let _ = conn.pragma_update(None, "trusted_schema", "OFF");
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(SCHEMA)?;
        conn.execute_batch(DISABLED_SCHEMA)?;
        conn.execute_batch(LOCAL_SCHEMA)?;
        migrate(&conn)?;
        Ok(Self { conn, remote: false })
    }

    /// Agent/k9 with the service: own bookkeeping locally, the service's
    /// tables attached read-only (unqualified names resolve to them because
    /// the old local copies are renamed to `alt_*`).
    pub fn open_attached(path: &Path, protected: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("Datenbank {} kann nicht geöffnet werden", path.display()))?;
        conn.busy_timeout(Duration::from_secs(10))?;
        let _ = conn.pragma_update(None, "trusted_schema", "OFF");
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(LOCAL_SCHEMA)?;
        for t in SHARED_TABLES {
            let exists: bool = conn
                .query_row("SELECT COUNT(*) FROM main.sqlite_master WHERE type = 'table' AND name = ?1", [t], |r| r.get::<_, i64>(0))
                .map(|n| n > 0)?;
            if exists {
                conn.execute_batch(&format!("DROP TABLE IF EXISTS main.alt_{t}; ALTER TABLE main.{t} RENAME TO alt_{t};"))?;
            }
        }
        let uri = format!("file:{}?mode=ro", protected.display().to_string().replace('\\', "/"));
        conn.execute("ATTACH DATABASE ?1 AS g", [uri]).with_context(|| format!("{} nicht lesbar", protected.display()))?;
        Ok(Self { conn, remote: true })
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    /// After the move to K9: quarantine files lie below the new protected folder.
    pub fn rewrite_quarantine_paths(&self, old: &Path, new: &Path) -> Result<usize> {
        let rows: Vec<(i64, String)> = {
            let mut st = self.conn.prepare("SELECT id, stored_file FROM quarantine")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            r
        };
        let mut n = 0;
        for (id, path) in rows {
            if let Some(p) = crate::umzug::rewrite(&path, old, new) {
                self.conn.execute("UPDATE quarantine SET stored_file = ?1 WHERE id = ?2", params![p, id])?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Stored files of all quarantine entries that are not restored (for the health check).
    pub fn quarantine_files(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT stored_file FROM quarantine WHERE restored_at IS NULL")?;
        let r = st.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        Ok(r)
    }

    pub fn meta_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)", params![key, value])?;
        Ok(())
    }

    /// Service: keeps a finding for the agent until it was delivered (survives a
    /// restart). False if the same finding (`key`) is already waiting. At most
    /// `max` entries are kept, the oldest go first.
    pub fn outbox_add(&self, token: &str, key: &str, message: &str, max: usize) -> Result<bool> {
        let added = self.conn.execute(
            "INSERT OR IGNORE INTO dienst_ausgang (token, schluessel, nachricht) VALUES (?1, ?2, ?3)",
            params![token, key, message],
        )? == 1;
        self.conn.execute(
            "DELETE FROM dienst_ausgang WHERE nr NOT IN (SELECT nr FROM dienst_ausgang ORDER BY nr DESC LIMIT ?1)",
            params![max as i64],
        )?;
        Ok(added)
    }

    /// Delivered to the agent: no longer kept.
    pub fn outbox_remove(&self, token: &str) -> Result<()> {
        self.conn.execute("DELETE FROM dienst_ausgang WHERE token = ?1", [token])?;
        Ok(())
    }

    /// Waiting findings in the order they were reported.
    pub fn outbox_all(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT nachricht FROM dienst_ausgang ORDER BY nr")?;
        let rows = st.query_map([], |r| r.get(0))?.collect::<std::result::Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    /// Service: one-time takeover of findings, decisions, quarantine list,
    /// events and disabled autostarts from the user's database. The caller
    /// acts with the user's rights (the user file is opened with them).
    pub fn import_user_db(&self, user_db: &Path) -> Result<usize> {
        const TABLES: [(&str, &str); 5] = [
            ("detections", "id, path, sha256, rule_id, threat_name, category, severity, engine, first_seen, last_seen, status, action, kind, details"),
            ("decisions", "id, sha256, rule_id, threat_name, action, decided_at, note, signatur"),
            ("quarantine", "id, detection_id, original_path, stored_file, sha256, size, threat_name, xor_key, sddl, quarantined_at, restored_at"),
            ("events", "id, ts, level, message"),
            ("disabled_autostart", "id, detection_id, label, backup, disabled_at, restored_at"),
        ];
        if !user_db.is_file() {
            return Ok(0);
        }
        self.conn.execute("ATTACH DATABASE ?1 AS u", [user_db.display().to_string()])?;
        let result = (|| -> Result<usize> {
            let mut n = 0;
            for (t, cols) in TABLES {
                // The agent renames its copies to alt_* as soon as the service database exists.
                let src = [t.to_string(), format!("alt_{t}")].into_iter().find(|name| {
                    self.conn
                        .query_row("SELECT COUNT(*) FROM u.sqlite_master WHERE type = 'table' AND name = ?1", [name], |r| r.get::<_, i64>(0))
                        .is_ok_and(|c| c > 0)
                });
                let Some(src) = src else { continue };
                let src_cols: Vec<String> = {
                    let mut stmt = self.conn.prepare(&format!("PRAGMA u.table_info({src})"))?;
                    let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
                    rows.collect::<rusqlite::Result<_>>()?
                };
                let select: Vec<String> =
                    cols.split(", ").map(|c| if src_cols.iter().any(|s| s == c) { c.to_string() } else { "NULL".to_string() }).collect();
                let filter = if t == "events" { " WHERE id > (SELECT COALESCE(MAX(id), 0) - 5000 FROM u.".to_string() + &src + ")" } else { String::new() };
                n += self.conn.execute(&format!("INSERT OR IGNORE INTO main.{t} ({cols}) SELECT {} FROM u.{src}{filter}", select.join(", ")), [])?;
            }
            Ok(n)
        })();
        let _ = self.conn.execute("DETACH DATABASE u", []);
        result
    }

    /// Creates the protected database (service only, with SYSTEM rights).
    pub fn create_protected(path: &Path) -> Result<()> {
        let c = Connection::open(path)?;
        c.pragma_update(None, "journal_mode", "DELETE")?;
        c.execute_batch(SCHEMA)?;
        c.execute_batch(DISABLED_SCHEMA)?;
        c.execute_batch(LOCAL_SCHEMA)?;
        migrate(&c)?;
        Ok(())
    }

    /// True if the Windows service keeps findings and decisions (this process may only read them).
    pub fn is_remote(&self) -> bool {
        self.remote
    }

    fn with_sec<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        f(&self.conn)
    }

    fn write_sec<R>(&self, f: impl FnOnce(&Connection) -> Result<R>) -> Result<R> {
        if self.remote {
            bail!("Nur der Windows-Dienst darf Entscheidungen und die Quarantäne-Liste ändern");
        }
        self.with_sec(f)
    }

    // ---------------------------------------------------------------- detections

    fn detection_from_row(row: &Row<'_>) -> rusqlite::Result<Detection> {
        let action: Option<String> = row.get("action")?;
        Ok(Detection {
            id: row.get("id")?,
            path: row.get("path")?,
            sha256: row.get("sha256")?,
            rule_id: row.get("rule_id")?,
            threat_name: row.get("threat_name")?,
            category: row.get("category")?,
            severity: Severity::parse(&row.get::<_, String>("severity")?),
            engine: row.get("engine")?,
            first_seen: row.get("first_seen")?,
            last_seen: row.get("last_seen")?,
            status: DetectionStatus::parse(&row.get::<_, String>("status")?),
            action: action.and_then(|a| a.parse().ok()),
            kind: Kind::parse(&row.get::<_, String>("kind")?),
            details: row.get::<_, Option<String>>("details")?.and_then(|d| serde_json::from_str(&d).ok()),
        })
    }

    fn find_detection(&self, f: &Finding) -> Result<Option<Detection>> {
        let path = f.path.to_string_lossy();
        Ok(self
            .conn
            .query_row(
                "SELECT * FROM detections WHERE path = ?1 AND sha256 = ?2 AND rule_id = ?3",
                params![path, f.sha256, f.rule_id],
                Self::detection_from_row,
            )
            .optional()?)
    }

    /// Registers a finding that has no remembered decision.
    pub fn upsert_pending(&self, f: &Finding) -> Result<Upsert> {
        let now = now_string();
        if let Some(existing) = self.find_detection(f)? {
            if existing.status == DetectionStatus::Offen {
                self.conn.execute("UPDATE detections SET last_seen = ?1, details = ?2 WHERE id = ?3", params![now, details_json(f), existing.id])?;
                return Ok(Upsert::AlreadyPending(self.detection(existing.id)?.context("Erkennung verschwunden")?));
            }
            // A decision existed earlier but was revoked: ask again.
            self.conn.execute(
                "UPDATE detections SET last_seen = ?1, status = 'offen', action = NULL WHERE id = ?2",
                params![now, existing.id],
            )?;
            return Ok(Upsert::New(self.detection(existing.id)?.context("Erkennung verschwunden")?));
        }
        self.conn.execute(
            "INSERT INTO detections (path, sha256, rule_id, threat_name, category, severity, engine, first_seen, last_seen, status, kind, details)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'offen', ?9, ?10)",
            params![
                f.path.to_string_lossy(),
                f.sha256,
                f.rule_id,
                f.threat_name,
                f.category,
                f.severity.as_str(),
                f.engine,
                now,
                f.kind.as_str(),
                details_json(f)
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        Ok(Upsert::New(self.detection(id)?.context("Erkennung verschwunden")?))
    }

    /// Records a finding for which a remembered decision was applied silently.
    pub fn record_automatic(&self, f: &Finding, action: Action) -> Result<Detection> {
        let now = now_string();
        let id = match self.find_detection(f)? {
            Some(existing) => {
                self.conn.execute(
                    "UPDATE detections SET last_seen = ?1, status = 'automatisch', action = ?2 WHERE id = ?3",
                    params![now, action.as_str(), existing.id],
                )?;
                existing.id
            }
            None => {
                self.conn.execute(
                    "INSERT INTO detections (path, sha256, rule_id, threat_name, category, severity, engine, first_seen, last_seen, status, action, kind, details)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'automatisch', ?9, ?10, ?11)",
                    params![
                        f.path.to_string_lossy(),
                        f.sha256,
                        f.rule_id,
                        f.threat_name,
                        f.category,
                        f.severity.as_str(),
                        f.engine,
                        now,
                        action.as_str(),
                        f.kind.as_str(),
                        details_json(f)
                    ],
                )?;
                self.conn.last_insert_rowid()
            }
        };
        self.detection(id)?.context("Erkennung verschwunden")
    }

    pub fn detection(&self, id: i64) -> Result<Option<Detection>> {
        Ok(self
            .conn
            .query_row("SELECT * FROM detections WHERE id = ?1", [id], Self::detection_from_row)
            .optional()?)
    }

    pub fn pending_detections(&self) -> Result<Vec<Detection>> {
        self.query_detections("SELECT * FROM detections WHERE status = 'offen' ORDER BY id", [])
    }

    /// Latest detections of any status (newest first).
    pub fn recent_detections(&self, limit: i64) -> Result<Vec<Detection>> {
        self.query_detections("SELECT * FROM detections ORDER BY last_seen DESC, id DESC LIMIT ?1", [limit])
    }

    fn query_detections<P: rusqlite::Params>(&self, sql: &str, p: P) -> Result<Vec<Detection>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(p, Self::detection_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// New details for an open finding (e.g. corrected manufacturer of a driver).
    pub fn update_details(&self, id: i64, details: &serde_json::Value) -> Result<()> {
        self.conn.execute("UPDATE detections SET details = ?1 WHERE id = ?2 AND status = 'offen'", params![details.to_string(), id])?;
        Ok(())
    }

    pub fn mark_detection(&self, id: i64, status: DetectionStatus, action: Option<Action>) -> Result<()> {
        self.conn.execute(
            "UPDATE detections SET status = ?1, action = ?2 WHERE id = ?3",
            params![status.as_str(), action.map(Action::as_str), id],
        )?;
        Ok(())
    }

    /// Other pending detections with the same fingerprint (e.g. copies at other paths).
    pub fn pending_with_fingerprint(&self, sha256: &str, rule_id: &str) -> Result<Vec<Detection>> {
        self.query_detections(
            "SELECT * FROM detections WHERE status = 'offen' AND sha256 = ?1 AND rule_id = ?2 ORDER BY id",
            params![sha256, rule_id],
        )
    }

    // ----------------------------------------------------------------- decisions

    fn decision_from_row(row: &Row<'_>) -> rusqlite::Result<Decision> {
        let action: String = row.get("action")?;
        Ok(Decision {
            id: row.get("id")?,
            sha256: row.get("sha256")?,
            rule_id: row.get("rule_id")?,
            threat_name: row.get("threat_name")?,
            action: action.parse().unwrap_or(Action::Quarantaene),
            decided_at: row.get("decided_at")?,
            note: row.get("note")?,
            signature: row.get("signatur").unwrap_or(None),
        })
    }

    pub fn decision_by_id(&self, id: i64) -> Result<Option<Decision>> {
        self.with_sec(|c| Ok(c.query_row("SELECT * FROM decisions WHERE id = ?1", [id], Self::decision_from_row).optional()?))
    }

    /// Signature of the Windows service for a decision.
    pub fn set_decision_signature(&self, id: i64, signature: &str) -> Result<()> {
        self.write_sec(|c| {
            c.execute("UPDATE decisions SET signatur = ?1 WHERE id = ?2", params![signature, id])?;
            Ok(())
        })
    }

    pub fn find_decision(&self, sha256: &str, rule_id: &str) -> Result<Option<Decision>> {
        self.with_sec(|c| {
            Ok(c.query_row("SELECT * FROM decisions WHERE sha256 = ?1 AND rule_id = ?2", params![sha256, rule_id], Self::decision_from_row)
                .optional()?)
        })
    }

    /// Remembers a decision. With the Windows service it is stored and signed
    /// there; releases need the user's confirmation in the service's window.
    pub fn set_decision(&self, sha256: &str, rule_id: &str, threat_name: &str, action: Action, note: Option<&str>) -> Result<Decision> {
        if self.remote {
            crate::dienst::request_save_decision(sha256, rule_id, threat_name, action, note)?;
            return self.find_decision(sha256, rule_id)?.context("Entscheidung verschwunden");
        }
        self.write_sec(|c| {
            c.execute(
                "INSERT INTO decisions (sha256, rule_id, threat_name, action, decided_at, note) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(sha256, rule_id) DO UPDATE SET action = excluded.action, decided_at = excluded.decided_at,
                     note = excluded.note, threat_name = excluded.threat_name, signatur = NULL",
                params![sha256, rule_id, threat_name, action.as_str(), now_string(), note],
            )?;
            Ok(())
        })?;
        self.find_decision(sha256, rule_id)?.context("Entscheidung verschwunden")
    }

    pub fn list_decisions(&self) -> Result<Vec<Decision>> {
        self.with_sec(|c| {
            let mut stmt = c.prepare("SELECT * FROM decisions ORDER BY decided_at DESC, id DESC")?;
            let rows = stmt.query_map([], Self::decision_from_row)?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Removes a remembered decision; the next identical detection is reported again.
    pub fn revoke_decision(&self, id: i64) -> Result<Option<Decision>> {
        let d = self.decision_by_id(id)?;
        if d.is_some() {
            if self.remote {
                crate::dienst::request_revoke(Some(id), None)?;
            } else {
                self.write_sec(|c| Ok(c.execute("DELETE FROM decisions WHERE id = ?1", [id])?))?;
            }
        }
        Ok(d)
    }

    pub fn revoke_decision_by_fingerprint(&self, sha256: &str, rule_id: &str) -> Result<bool> {
        if self.remote {
            let exists = self.find_decision(sha256, rule_id)?.is_some();
            if exists {
                crate::dienst::request_revoke(None, Some((sha256, rule_id)))?;
            }
            return Ok(exists);
        }
        self.write_sec(|c| Ok(c.execute("DELETE FROM decisions WHERE sha256 = ?1 AND rule_id = ?2", params![sha256, rule_id])? > 0))
    }

    // ---------------------------------------------------------------- quarantine

    fn quarantine_from_row(row: &Row<'_>) -> rusqlite::Result<QuarantineEntry> {
        Ok(QuarantineEntry {
            id: row.get("id")?,
            detection_id: row.get("detection_id")?,
            original_path: row.get("original_path")?,
            stored_file: row.get("stored_file")?,
            sha256: row.get("sha256")?,
            size: row.get::<_, i64>("size")? as u64,
            threat_name: row.get("threat_name")?,
            quarantined_at: row.get("quarantined_at")?,
            restored_at: row.get("restored_at")?,
            key: row.get("xor_key")?,
            sddl: row.get("sddl")?,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_quarantine(
        &self,
        detection_id: Option<i64>,
        original_path: &str,
        stored_file: &str,
        sha256: &str,
        size: u64,
        threat_name: &str,
        key: &[u8],
        sddl: Option<&str>,
    ) -> Result<i64> {
        self.write_sec(|c| {
            c.execute(
                "INSERT INTO quarantine (detection_id, original_path, stored_file, sha256, size, threat_name, xor_key, sddl, quarantined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![detection_id, original_path, stored_file, sha256, size as i64, threat_name, key, sddl, now_string()],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn quarantine_entry(&self, id: i64) -> Result<Option<QuarantineEntry>> {
        self.with_sec(|c| Ok(c.query_row("SELECT * FROM quarantine WHERE id = ?1", [id], Self::quarantine_from_row).optional()?))
    }

    /// Entries currently in quarantine (not restored).
    pub fn list_quarantine(&self) -> Result<Vec<QuarantineEntry>> {
        self.with_sec(|c| {
            let mut stmt = c.prepare("SELECT * FROM quarantine WHERE restored_at IS NULL ORDER BY id DESC")?;
            let rows = stmt.query_map([], Self::quarantine_from_row)?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        })
    }

    /// Quarantine entries of the user's own database (for the one-time takeover).
    pub fn list_user_quarantine(&self) -> Result<Vec<QuarantineEntry>> {
        let mut stmt = self.conn.prepare("SELECT * FROM quarantine WHERE restored_at IS NULL ORDER BY id")?;
        let rows = stmt.query_map([], Self::quarantine_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Decisions of the user's own database (for the one-time takeover).
    pub fn list_user_decisions(&self) -> Result<Vec<Decision>> {
        let mut stmt = self.conn.prepare("SELECT * FROM decisions ORDER BY id")?;
        let rows = stmt.query_map([], Self::decision_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Takeover into the protected database (service): keeps id, signature and
    /// all fields. Returns the number of rows copied.
    pub fn import_protected(&self, decisions: &[Decision], quarantine: &[QuarantineEntry]) -> Result<usize> {
        self.write_sec(|c| {
            let mut n = 0;
            for d in decisions {
                n += c.execute(
                    "INSERT OR IGNORE INTO decisions (id, sha256, rule_id, threat_name, action, decided_at, note, signatur) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![d.id, d.sha256, d.rule_id, d.threat_name, d.action.as_str(), d.decided_at, d.note, d.signature],
                )?;
            }
            for q in quarantine {
                n += c.execute(
                    "INSERT OR IGNORE INTO quarantine (id, detection_id, original_path, stored_file, sha256, size, threat_name, xor_key, sddl, quarantined_at)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![q.id, q.detection_id, q.original_path, q.stored_file, q.sha256, q.size as i64, q.threat_name, q.key, q.sddl, q.quarantined_at],
                )?;
            }
            Ok(n)
        })
    }

    /// New location of a quarantined file (migration into the protected folder).
    pub fn set_quarantine_file(&self, id: i64, stored_file: &str) -> Result<()> {
        self.write_sec(|c| {
            c.execute("UPDATE quarantine SET stored_file = ?1 WHERE id = ?2", params![stored_file, id])?;
            Ok(())
        })
    }

    pub fn mark_restored(&self, id: i64) -> Result<()> {
        self.write_sec(|c| {
            c.execute("UPDATE quarantine SET restored_at = ?1 WHERE id = ?2", params![now_string(), id])?;
            Ok(())
        })
    }

    // -------------------------------------------------------------------- events

    pub fn log_event(&self, level: &str, message: &str) -> Result<()> {
        if self.remote {
            // The log belongs to the service; without it the entry goes to the agent log only.
            if let Err(e) = crate::dienst::request_event(level, message) {
                tracing::info!("[{level}] {message} (Dienst nicht erreichbar: {e:#})");
            }
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO events (ts, level, message) VALUES (?1, ?2, ?3)",
            params![now_string(), level, message],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: i64) -> Result<Vec<(String, String, String)>> {
        let mut stmt = self.conn.prepare("SELECT ts, level, message FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // -------------------------------------------------------- notification queue

    pub fn enqueue_notification(&self, detection_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO notification_queue (detection_id, queued_at) VALUES (?1, ?2)",
            params![detection_id, now_string()],
        )?;
        Ok(())
    }

    pub fn queued_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM notification_queue", [], |r| r.get(0))?)
    }

    /// Removes all queued notifications and returns the detections that are still pending.
    pub fn take_queued(&self) -> Result<Vec<Detection>> {
        let tx = self.conn.unchecked_transaction()?;
        let ids: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT detection_id FROM notification_queue ORDER BY queued_at")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        tx.execute("DELETE FROM notification_queue", [])?;
        tx.commit()?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(d) = self.detection(id)? {
                if d.status == DetectionStatus::Offen {
                    out.push(d);
                }
            }
        }
        Ok(out)
    }

    // ------------------------------------------------- disabled autostarts

    pub fn insert_disabled(&self, detection_id: i64, label: &str, backup: &serde_json::Value) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO disabled_autostart (detection_id, label, backup, disabled_at) VALUES (?1, ?2, ?3, ?4)",
            params![detection_id, label, backup.to_string(), now_string()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// (id, label, disabled_at) of currently disabled entries.
    pub fn list_disabled(&self) -> Result<Vec<(i64, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, label, disabled_at FROM disabled_autostart WHERE restored_at IS NULL ORDER BY id DESC")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// (detection_id, label, backup) of a still disabled entry.
    pub fn disabled_entry(&self, id: i64) -> Result<Option<(i64, String, serde_json::Value)>> {
        let row: Option<(i64, String, String)> = self
            .conn
            .query_row(
                "SELECT detection_id, label, backup FROM disabled_autostart WHERE id = ?1 AND restored_at IS NULL",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(row.map(|(d, l, b)| (d, l, serde_json::from_str(&b).unwrap_or_default())))
    }

    pub fn mark_reenabled(&self, id: i64) -> Result<()> {
        self.conn.execute("UPDATE disabled_autostart SET restored_at = ?1 WHERE id = ?2", params![now_string(), id])?;
        Ok(())
    }

    // --------------------------------------------------------- scan cache

    /// True if the file was scanned clean with the same signature state.
    pub fn cache_is_clean(&self, path: &str, size: u64, mtime: i64, state: &str) -> Result<bool> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM file_cache WHERE path = ?1 AND size = ?2 AND mtime = ?3 AND state = ?4",
                params![path, size as i64, mtime, state],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Stores clean results in one transaction.
    pub fn cache_store_clean(&self, entries: &[(String, u64, i64)], state: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO file_cache (path, size, mtime, state) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(path) DO UPDATE SET size = excluded.size, mtime = excluded.mtime, state = excluded.state",
            )?;
            for (p, s, m) in entries {
                stmt.execute(params![p, *s as i64, m, state])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn cache_clear(&self) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM file_cache", [])?)
    }

    // ------------------------------------------------------- window queue

    /// Queues a detection for the notification window. With `replace`, an
    /// existing entry gets the new time (e.g. "ask again at the next scan").
    pub fn enqueue_window(&self, detection_id: i64, not_before: &str, replace: bool) -> Result<()> {
        let sql = if replace {
            "INSERT INTO window_queue (detection_id, not_before) VALUES (?1, ?2)
             ON CONFLICT(detection_id) DO UPDATE SET not_before = excluded.not_before"
        } else {
            "INSERT OR IGNORE INTO window_queue (detection_id, not_before) VALUES (?1, ?2)"
        };
        self.conn.execute(sql, params![detection_id, not_before])?;
        Ok(())
    }

    /// Next pending detection whose window is due, plus how many further
    /// windows are waiting. Entries of already decided detections are dropped.
    pub fn next_window(&self, now: &str) -> Result<Option<(Detection, usize)>> {
        self.conn.execute(
            "DELETE FROM window_queue WHERE detection_id NOT IN (SELECT id FROM detections WHERE status = 'offen')",
            [],
        )?;
        let ids: Vec<i64> = {
            let mut stmt = self
                .conn
                .prepare("SELECT detection_id FROM window_queue WHERE not_before <= ?1 ORDER BY not_before, detection_id")?;
            let rows = stmt.query_map([now], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let Some(first) = ids.first() else { return Ok(None) };
        let total: i64 = self.conn.query_row("SELECT COUNT(*) FROM window_queue", [], |r| r.get(0))?;
        Ok(self.detection(*first)?.map(|d| (d, (total - 1).max(0) as usize)))
    }

    pub fn remove_window(&self, detection_id: i64) -> Result<()> {
        self.conn.execute("DELETE FROM window_queue WHERE detection_id = ?1", [detection_id])?;
        Ok(())
    }

    pub fn window_queue_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM window_queue", [], |r| r.get(0))?)
    }

    // ------------------------------------------------------------ schedule runs

    pub fn last_run(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT last_run FROM schedule_runs WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_last_run(&self, key: &str, ts: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO schedule_runs (key, last_run) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET last_run = excluded.last_run",
            params![key, ts],
        )?;
        Ok(())
    }

    // ------------------------------------------------- findings for the service

    /// Next sequence number for findings sent to the service (the service
    /// notices gaps, e.g. buffered findings deleted by another program).
    pub fn next_seq(&self) -> Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        let cur: i64 = tx
            .query_row("SELECT value FROM meta WHERE key = 'fund_seq'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        tx.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('fund_seq', ?1)", [(cur + 1).to_string()])?;
        tx.commit()?;
        Ok(cur + 1)
    }

    /// Keeps findings the service could not take (JSON of the wire findings).
    pub fn buffer_findings(&self, seq: i64, json: &str) -> Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO fund_puffer (seq, funde) VALUES (?1, ?2)", params![seq, json])?;
        Ok(())
    }

    pub fn buffered_findings(&self) -> Result<Vec<(i64, String)>> {
        let mut stmt = self.conn.prepare("SELECT seq, funde FROM fund_puffer ORDER BY seq")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn remove_buffered(&self, seq: i64) -> Result<()> {
        self.conn.execute("DELETE FROM fund_puffer WHERE seq = ?1", [seq])?;
        Ok(())
    }

    /// Service side: the last sequence number received; returns the gap
    /// (number of missing messages) for `seq`.
    pub fn check_seq(&self, seq: i64) -> Result<i64> {
        let last: i64 = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'fund_seq_empfangen'", [], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if seq > last {
            self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('fund_seq_empfangen', ?1)", [seq.to_string()])?;
        }
        Ok(if last > 0 && seq > last + 1 { seq - last - 1 } else { 0 })
    }

    // -------------------------------------------------------------------- status

    pub fn counts(&self) -> Result<Counts> {
        let one = |sql: &str| -> Result<i64> { Ok(self.conn.query_row(sql, [], |r| r.get(0))?) };
        Ok(Counts {
            pending: one("SELECT COUNT(*) FROM detections WHERE status = 'offen'")?,
            decisions: self.with_sec(|c| Ok(c.query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get(0))?))?,
            quarantined: self.with_sec(|c| Ok(c.query_row("SELECT COUNT(*) FROM quarantine WHERE restored_at IS NULL", [], |r| r.get(0))?))?,
            detections_total: one("SELECT COUNT(*) FROM detections")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_database_can_be_opened_by_many_threads_at_once() {
        // The first open switches the file to WAL; others opening at the same moment used to
        // fail with "database is locked" (seen in the end-to-end test on 20.11.2026).
        for round in 0..5 {
            let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
            let db = dir.path().join(format!("neu{round}.db"));
            let threads: Vec<_> = (0..12)
                .map(|_| {
                    let db = db.clone();
                    std::thread::spawn(move || Store::open_file(&db).and_then(|s| s.counts().map(|_| ())).map_err(|e| format!("{e:#}")))
                })
                .collect();
            for t in threads {
                assert_eq!(t.join().unwrap(), Ok(()));
            }
        }
    }

    #[test]
    fn service_outbox_survives_reopen_without_duplicates() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let db = dir.path().join("geschuetzt.db");
        Store::create_protected(&db).unwrap();
        {
            let s = Store::open_protected(&db).unwrap();
            assert!(s.outbox_add("t1", "R|a|x", "eins", 3).unwrap());
            assert!(!s.outbox_add("t2", "R|a|x", "doppelt", 3).unwrap(), "derselbe Fund wartet schon");
            assert!(s.outbox_add("t3", "R|b|y", "zwei", 3).unwrap());
        }
        // After a restart: still there, in order.
        let s = Store::open_protected(&db).unwrap();
        assert_eq!(s.outbox_all().unwrap(), vec!["eins", "zwei"]);
        s.outbox_remove("t1").unwrap();
        assert_eq!(s.outbox_all().unwrap(), vec!["zwei"]);
        // Delivered findings may be reported again; the oldest go first beyond the limit.
        assert!(s.outbox_add("t4", "R|a|x", "eins neu", 2).unwrap());
        assert!(s.outbox_add("t5", "R|c|z", "drei", 2).unwrap());
        assert_eq!(s.outbox_all().unwrap(), vec!["eins neu", "drei"]);
    }

    #[test]
    fn service_database_is_read_only_for_the_agent_and_takes_over_old_data() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let user_db = dir.path().join("benutzer.db");
        let prot_db = dir.path().join("geschuetzt.db");
        // Old state: everything in the user's database.
        let old = Store::open(&user_db).unwrap();
        let f = finding("C:\\x\\alt.exe");
        let Upsert::New(det) = old.upsert_pending(&f).unwrap() else { panic!() };
        old.set_decision(&"cd".repeat(32), "R2", "alt", Action::Freigabe, None).unwrap();
        old.log_event("info", "alter Eintrag").unwrap();
        drop(old);
        // The service creates its database and takes the data over once.
        let svc = Store::open_protected(&prot_db).unwrap();
        assert!(svc.import_user_db(&user_db).unwrap() >= 3);
        assert_eq!(svc.detection(det.id).unwrap().unwrap().path, det.path);
        assert_eq!(svc.list_decisions().unwrap().len(), 1);
        // The agent attaches it read-only: reads work, its old copies are renamed.
        let agent = Store::open_attached(&user_db, &prot_db).unwrap();
        assert!(agent.is_remote());
        assert_eq!(agent.pending_detections().unwrap().len(), 1);
        assert_eq!(agent.list_decisions().unwrap().len(), 1);
        // Writing directly is impossible – a program cannot hide or allow anything there.
        assert!(agent.mark_detection(det.id, DetectionStatus::Entschieden, Some(Action::Freigabe)).is_err());
        assert!(agent.upsert_pending(&finding("C:\\x\\neu.exe")).is_err());
        // Local bookkeeping still works.
        agent.enqueue_window(det.id, "2000-01-01 00:00:00", true).unwrap();
        assert_eq!(agent.next_window("2999-01-01 00:00:00").unwrap().map(|(d, _)| d.id), Some(det.id));
        // A second takeover after the rename finds the alt_* tables (nothing lost, nothing doubled).
        assert_eq!(svc.import_user_db(&user_db).unwrap(), 0);
    }

    #[test]
    fn sequence_gaps_are_detected() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.check_seq(1).unwrap(), 0);
        assert_eq!(s.check_seq(2).unwrap(), 0);
        assert_eq!(s.check_seq(2).unwrap(), 0, "Wiederholung ist keine Lücke");
        assert_eq!(s.check_seq(5).unwrap(), 2, "3 und 4 fehlen");
        assert_eq!(s.next_seq().unwrap(), 1);
        assert_eq!(s.next_seq().unwrap(), 2);
        s.buffer_findings(2, "[]").unwrap();
        assert_eq!(s.buffered_findings().unwrap().len(), 1);
        s.remove_buffered(2).unwrap();
        assert!(s.buffered_findings().unwrap().is_empty());
    }

    #[test]
    fn migration_keeps_existing_decisions() {
        let dir = tempfile::tempdir_in(crate::test_tmp()).unwrap();
        let db = dir.path().join("alt.db");
        {
            // Database of the previous version (no signature column, user_version 2).
            let c = rusqlite::Connection::open(&db).unwrap();
            c.execute_batch(
                "CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL, rule_id TEXT NOT NULL,
                 threat_name TEXT NOT NULL, action TEXT NOT NULL, decided_at TEXT NOT NULL, note TEXT, UNIQUE(sha256, rule_id));
                 INSERT INTO decisions (sha256, rule_id, threat_name, action, decided_at) VALUES ('aa', 'R', 'alt', 'freigabe', 'gestern');
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }
        let s = Store::open(&db).unwrap();
        let list = s.list_decisions().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].action, Action::Freigabe);
        assert!(list[0].signature.is_none());
        s.set_decision_signature(list[0].id, "00").unwrap();
        assert_eq!(s.decision_by_id(list[0].id).unwrap().unwrap().signature.as_deref(), Some("00"));
    }

    fn finding(path: &str) -> Finding {
        Finding {
            path: path.into(),
            sha256: "ab".repeat(32),
            size: 3,
            rule_id: "VS-TEST-0001".into(),
            threat_name: "Test".into(),
            category: "Test".into(),
            severity: Severity::Niedrig,
            engine: "muster".into(),
            kind: crate::model::Kind::Datei,
            details: None,
        }
    }

    #[test]
    fn pending_is_reported_once() {
        let s = Store::open_in_memory().unwrap();
        let f = finding("C:\\a.txt");
        assert!(matches!(s.upsert_pending(&f).unwrap(), Upsert::New(_)));
        assert!(matches!(s.upsert_pending(&f).unwrap(), Upsert::AlreadyPending(_)));
        assert_eq!(s.pending_detections().unwrap().len(), 1);
    }

    #[test]
    fn decision_roundtrip_and_revoke() {
        let s = Store::open_in_memory().unwrap();
        let f = finding("C:\\a.txt");
        let Upsert::New(d) = s.upsert_pending(&f).unwrap() else { panic!() };
        let dec = s.set_decision(&f.sha256, &f.rule_id, &f.threat_name, Action::Freigabe, Some("bekannt")).unwrap();
        s.mark_detection(d.id, DetectionStatus::Entschieden, Some(Action::Freigabe)).unwrap();
        assert_eq!(s.find_decision(&f.sha256, &f.rule_id).unwrap().unwrap().action, Action::Freigabe);
        // Updating keeps one row per fingerprint.
        s.set_decision(&f.sha256, &f.rule_id, &f.threat_name, Action::Quarantaene, None).unwrap();
        assert_eq!(s.list_decisions().unwrap().len(), 1);
        assert!(s.revoke_decision(dec.id).unwrap().is_some());
        assert!(s.find_decision(&f.sha256, &f.rule_id).unwrap().is_none());
        // After revoking, the same finding is reported again.
        assert!(matches!(s.upsert_pending(&f).unwrap(), Upsert::New(_)));
    }

    #[test]
    fn window_queue_respects_time_and_status() {
        let s = Store::open_in_memory().unwrap();
        let Upsert::New(a) = s.upsert_pending(&finding("C:\\a")).unwrap() else { panic!() };
        let Upsert::New(b) = s.upsert_pending(&finding("C:\\b")).unwrap() else { panic!() };
        s.enqueue_window(a.id, "2026-11-13 10:00:00", false).unwrap();
        s.enqueue_window(b.id, "2026-11-13 12:00:00", false).unwrap();
        // Only a is due; b counts as waiting.
        let (d, more) = s.next_window("2026-11-13 11:00:00").unwrap().unwrap();
        assert_eq!((d.id, more), (a.id, 1));
        // "Später": a moves behind; without replace an existing entry is kept.
        s.enqueue_window(a.id, "2026-11-13 13:00:00", true).unwrap();
        s.enqueue_window(a.id, "2026-11-13 09:00:00", false).unwrap();
        assert!(s.next_window("2026-11-13 11:00:00").unwrap().is_none());
        assert_eq!(s.next_window("2026-11-13 12:30:00").unwrap().unwrap().0.id, b.id);
        // Decided elsewhere (e.g. dashboard) -> dropped from the queue.
        s.mark_detection(b.id, DetectionStatus::Entschieden, Some(Action::Freigabe)).unwrap();
        let (d, more) = s.next_window("2026-11-13 14:00:00").unwrap().unwrap();
        assert_eq!((d.id, more), (a.id, 0));
        s.remove_window(a.id).unwrap();
        assert_eq!(s.window_queue_count().unwrap(), 0);
    }

    /// Developer maintenance: remove a detection created by a faulty rule.
    /// VS_DB=<db> VS_DEL=<id> cargo test -p k9-core --lib remove_detection -- --ignored
    #[test]
    #[ignore]
    fn remove_detection() {
        let s = Store::open(Path::new(&std::env::var("VS_DB").unwrap())).unwrap();
        let id: i64 = std::env::var("VS_DEL").unwrap().parse().unwrap();
        for sql in ["DELETE FROM window_queue WHERE detection_id = ?1", "DELETE FROM notification_queue WHERE detection_id = ?1", "DELETE FROM detections WHERE id = ?1"] {
            s.conn.execute(sql, [id]).unwrap();
        }
        eprintln!("offen: {}, Fensterwarteschlange: {}", s.counts().unwrap().pending, s.window_queue_count().unwrap());
    }

    /// Developer helper: inserts a demo process finding with a long command line.
    /// VS_DB=<db> cargo test -p k9-core --lib insert_demo_finding -- --ignored
    #[test]
    #[ignore]
    fn insert_demo_finding() {
        let s = Store::open(Path::new(&std::env::var("VS_DB").unwrap())).unwrap();
        let cmd = format!("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"$s = '{}'; Invoke-Expression $s\"", r"Get-ChildItem C:\Beispiel\Ordner\mit\langem\Pfad; ".repeat(12));
        let f = Finding {
            path: "Prozess powershell.exe (PID 4711), gestartet von cmd.exe".into(),
            sha256: "cd".repeat(32),
            size: 0,
            rule_id: "PROZESSARGUMENTE:powershell.exe".into(),
            threat_name: "powershell.exe mit verdächtigen Argumenten (invoke-expression)".into(),
            category: "Verdächtiges Verhalten".into(),
            severity: Severity::Hoch,
            engine: "echtzeit".into(),
            kind: Kind::Prozess,
            details: Some(serde_json::json!({ "pid": 4711, "ziel": r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe", "befehl": cmd, "hinweis": "Nichts wurde beendet." })),
        };
        s.upsert_pending(&f).unwrap();
    }

    #[test]
    fn queue_returns_only_pending() {
        let s = Store::open_in_memory().unwrap();
        let Upsert::New(a) = s.upsert_pending(&finding("C:\\a")).unwrap() else { panic!() };
        let Upsert::New(b) = s.upsert_pending(&finding("C:\\b")).unwrap() else { panic!() };
        s.enqueue_notification(a.id).unwrap();
        s.enqueue_notification(b.id).unwrap();
        s.enqueue_notification(b.id).unwrap();
        s.mark_detection(a.id, DetectionStatus::Entschieden, Some(Action::Freigabe)).unwrap();
        let q = s.take_queued().unwrap();
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].id, b.id);
        assert_eq!(s.queued_count().unwrap(), 0);
    }
}
