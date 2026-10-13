//! Private stores (architecture §6 "Personal" and §5 prompt-budget Core).
//!
//! `PrivateStore` is one SQLite database under a mode-0700 directory that is
//! never inside a worktree: the Personal data root when a user config
//! exists, otherwise `${XDG_STATE_HOME:-~/.local/state}/kinbase`. It holds
//! raw private provenance under retention, session runs, candidates,
//! decisions, receipts, and the serialized prompt-budget shard. No shared
//! process ever receives its path.

use crate::error::ContractError;
use crate::model::{Atom, Observation};
use crate::paths;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const PRIVATE_SCHEMA_VERSION: i64 = 3;
pub const RAW_RETENTION_SECONDS: i64 = 24 * 60 * 60;
pub const CANDIDATE_LIFETIME_SECONDS: i64 = 15 * 60;
pub const PROMPT_WINDOW_SECONDS: i64 = 60 * 60;
pub const PROMPT_WINDOW_LIMIT: i64 = 4;
pub const CONSECUTIVE_LIMIT: i64 = 3;
pub const REISSUE_LOCK_SECONDS: i64 = 24 * 60 * 60;
/// How long a retrieval stays in the query log. The log is the future
/// compiler's specification, not a history: it had no bound at all.
pub const QUERY_LOG_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
/// The most query-log entries a status report carries (the newest).
pub const QUERY_LOG_REPORT_LIMIT: i64 = 200;

pub struct PrivateStore {
    pub root: PathBuf,
    pub connection: Connection,
    pub kind: &'static str,
}

pub fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| paths::home_dir().join(".local").join("state"))
        .join("kinbase")
}

/// The `logged_at` before which a query-log entry has expired at `now`,
/// in the log's own format.
fn query_log_cutoff(now: &str) -> String {
    crate::time::parse_rfc3339_millis(now)
        .map(|instant| {
            crate::time::format_rfc3339_millis(
                instant - chrono::Duration::seconds(QUERY_LOG_RETENTION_SECONDS),
            )
        })
        .unwrap_or_default()
}

fn sqlite_error(context: &str) -> impl Fn(rusqlite::Error) -> ContractError + '_ {
    move |error| ContractError::internal(format!("{context}: {error}"))
}

/// Parse the `record` column of each row, skipping any row that is not a
/// readable `T`. One unreadable row must not make the whole ledger unreadable,
/// the disposition `all_observations` already takes: five empty observation
/// rows once hid 1,292 good ones, and eight empty `query_log` rows later hid
/// every `status` report behind `RUN_INTEGRITY_FAILED`.
fn parse_rows<T: serde::de::DeserializeOwned>(
    context: &str,
    rows: impl Iterator<Item = rusqlite::Result<String>>,
) -> Result<Vec<T>, ContractError> {
    let mut output = Vec::new();
    let mut skipped = crate::output::Skipped::default();
    for (position, row) in rows.enumerate() {
        let text = row.map_err(sqlite_error("row"))?;
        match serde_json::from_str::<T>(&text) {
            Ok(value) => output.push(value),
            Err(_) => skipped.push(
                position,
                text.len(),
                match crate::output::unreadable_reason(text.as_bytes()) {
                    "outside the canonical data model" => "not a record of this ledger",
                    reason => reason,
                },
            ),
        }
    }
    skipped.report(context);
    Ok(output)
}

/// The character class Kindex accepts for a host session identifier. A prompt
/// or decision sentence has spaces and never passes.
fn is_host_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 200
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '@' | '/' | '-'))
}

/// The canonical text of a record bound for the private ledger, or a refusal.
/// `canonical_text` yields "" for a record outside the canonical data model
/// (and `value_of` yields null for one that does not serialise); either was
/// written over the row and read back as nothing.
fn canonical_record(record: &Value) -> Result<String, ContractError> {
    crate::json::try_canonical_text(record).map_err(|error| {
        ContractError::internal(format!("record violates the canonical data model: {error}"))
    })
}

fn canonical_model<T: serde::Serialize>(value: &T) -> Result<String, ContractError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ContractError::internal(format!("record is not serialisable: {error}")))?;
    canonical_record(&value)
}

impl PrivateStore {
    /// Open the Personal store under `data_root` (mode 0700 enforced).
    pub fn open_personal(data_root: &Path) -> Result<Self, ContractError> {
        paths::ensure_private_dir(data_root, "Personal data root")?;
        Self::open_at(data_root, "kinbase-personal.sqlite3", "personal")
    }

    /// Open the host-wide Core store (prompt budget, session runs in
    /// Codebase-only mode).
    pub fn open_core() -> Result<Self, ContractError> {
        let root = state_dir();
        paths::ensure_private_dir(&root, "Kinbase state directory")?;
        Self::open_at(&root, "core.sqlite3", "core")
    }

    /// Whether the host-wide Core store exists yet. A diagnostic that finds
    /// none reports an empty store instead of creating one.
    pub fn core_exists() -> bool {
        state_dir().join("core.sqlite3").is_file()
    }

    /// An empty store in memory: the shape of every report when no durable
    /// store exists, without writing one.
    pub fn open_memory(kind: &'static str) -> Result<Self, ContractError> {
        let connection = Connection::open_in_memory()
            .map_err(|error| ContractError::internal(format!("open memory store: {error}")))?;
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(sqlite_error("pragma"))?;
        let store = Self {
            root: state_dir(),
            connection,
            kind,
        };
        store.migrate()?;
        Ok(store)
    }

    fn open_at(root: &Path, file: &str, kind: &'static str) -> Result<Self, ContractError> {
        let path = root.join(file);
        paths::reject_symlink(&path, "private store")?;
        let connection = Connection::open(&path).map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("private store cannot be opened ({error})"),
                format!(
                    "Make {} writable by the current user; no partial schema was created.",
                    root.display()
                ),
            )
        })?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sqlite_error("busy timeout"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
            )
            .map_err(sqlite_error("pragma"))?;
        let store = Self {
            root: root.to_path_buf(),
            connection,
            kind,
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), ContractError> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS observations(
                    observation_id TEXT PRIMARY KEY, source_kind TEXT NOT NULL, source_identity TEXT NOT NULL,
                    native_id TEXT NOT NULL, content_digest TEXT NOT NULL, record TEXT NOT NULL,
                    observed_at TEXT NOT NULL, lifecycle TEXT NOT NULL);
                 CREATE INDEX IF NOT EXISTS observations_source ON observations(source_identity, native_id);
                 CREATE TABLE IF NOT EXISTS bodies(
                    content_digest TEXT PRIMARY KEY, bytes BLOB NOT NULL, stored_at TEXT NOT NULL,
                    retention_until TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS atoms(
                    atom_id TEXT PRIMARY KEY, observation_id TEXT NOT NULL, record TEXT NOT NULL,
                    created_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS personal_facts(
                    fact_id TEXT PRIMARY KEY, logical_key TEXT NOT NULL, record TEXT NOT NULL,
                    created_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS sessions(
                    session_id TEXT PRIMARY KEY, host TEXT NOT NULL, repository_id TEXT,
                    started_at TEXT NOT NULL, ended_at TEXT, status TEXT NOT NULL, record TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS session_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, observed_at TEXT NOT NULL, record TEXT NOT NULL,
                    UNIQUE(session_id, event_id));
                 CREATE TABLE IF NOT EXISTS candidates(
                    candidate_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, destination TEXT NOT NULL,
                    payload_digest TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS decisions(
                    receipt_id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL, destination TEXT NOT NULL,
                    decision TEXT NOT NULL, digest TEXT NOT NULL, record TEXT NOT NULL, decided_at TEXT NOT NULL,
                    UNIQUE(candidate_id, destination));
                 CREATE TABLE IF NOT EXISTS destination_receipts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, candidate_id TEXT NOT NULL, destination TEXT NOT NULL,
                    status TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS prompt_reservations(
                    reservation_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL,
                    destination TEXT NOT NULL, candidate_id TEXT NOT NULL, content_digest TEXT NOT NULL,
                    reserved_at TEXT NOT NULL, expires_at TEXT NOT NULL, display_token TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS reissue_locks(
                    principal_id TEXT NOT NULL, destination TEXT NOT NULL, content_digest TEXT NOT NULL,
                    lock_window TEXT NOT NULL, locked_at TEXT NOT NULL, source_revision TEXT NOT NULL,
                    UNIQUE(principal_id, destination, content_digest, lock_window));
                 CREATE TABLE IF NOT EXISTS consecutive(
                    principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL, count INTEGER NOT NULL,
                    last_reset_event TEXT, updated_at TEXT NOT NULL,
                    PRIMARY KEY(principal_id, host_instance_id));
                 CREATE TABLE IF NOT EXISTS resets(
                    reset_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, host_instance_id TEXT NOT NULL,
                    after_event_id TEXT NOT NULL, reason_code TEXT NOT NULL, reset_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS budget_metrics(name TEXT PRIMARY KEY, count INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS reminders(
                    reminder_id TEXT PRIMARY KEY, record TEXT NOT NULL, due_at TEXT NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS checkpoints(
                    source_identity TEXT PRIMARY KEY, record TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS query_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, record TEXT NOT NULL, logged_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS private_unknowns(
                    unknown_id TEXT PRIMARY KEY, record TEXT NOT NULL, status TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS shard_observations(
                    observed_at TEXT PRIMARY KEY, record TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS quarantine(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, record TEXT NOT NULL, recorded_at TEXT NOT NULL);",
            )
            .map_err(sqlite_error("private schema"))?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![PRIVATE_SCHEMA_VERSION.to_string()],
            )
            .map_err(sqlite_error("schema version"))?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, ContractError> {
        self.connection
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sqlite_error("meta read"))
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(sqlite_error("meta write"))
    }

    pub fn audit(&self, kind: &str, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO audit(kind, record, recorded_at) VALUES (?1, ?2, ?3)",
                params![
                    kind,
                    canonical_record(record)?,
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("audit"))
    }

    // ----- observations and bodies -----

    pub fn store_body(&self, bytes: &[u8], now: &str) -> Result<String, ContractError> {
        let digest = crate::hash::sha256_bytes(bytes);
        let retention_until = crate::time::plus_seconds(now, RAW_RETENTION_SECONDS)
            .map_err(ContractError::internal)?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO bodies(content_digest, bytes, stored_at, retention_until) VALUES (?1, ?2, ?3, ?4)",
                params![digest, bytes, now, retention_until],
            )
            .map_err(sqlite_error("store body"))?;
        Ok(format!("sha256:{digest}"))
    }

    pub fn body(&self, content_digest: &str) -> Result<Option<Vec<u8>>, ContractError> {
        self.connection
            .query_row(
                "SELECT bytes FROM bodies WHERE content_digest=?1",
                params![content_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read body"))
    }

    /// Garbage-collect raw bodies past their retention clock. Returns the
    /// count removed; observations keep their digests (evidence tombstones).
    pub fn expire_bodies(&self, now: &str) -> Result<usize, ContractError> {
        self.connection
            .execute(
                "DELETE FROM bodies WHERE retention_until <= ?1",
                params![now],
            )
            .map_err(sqlite_error("expire bodies"))
    }

    pub fn observation(&self, observation_id: &str) -> Result<Option<Observation>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM observations WHERE observation_id=?1",
                params![observation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read observation"))?;
        record
            .map(|text| {
                serde_json::from_str(&text)
                    .map_err(|error| ContractError::internal(crate::json::serde_error_text(&error)))
            })
            .transpose()
    }

    pub fn insert_observation(&self, observation: &Observation) -> Result<bool, ContractError> {
        // `value_of` yields Null and `canonical_text` yields "" when serialisation
        // fails, so a failure here used to be written into the ledger as an empty
        // record and discovered much later as an unreadable row. Five of 1,297
        // observations in one deployment's corpus were lost that way. Refuse instead: an
        // observation that cannot be serialised is a defect to surface, never a
        // blank to store.
        let value = serde_json::to_value(observation).map_err(|error| {
            ContractError::internal(format!(
                "observation {} is not serialisable: {error}",
                observation.observation_id
            ))
        })?;
        let record = crate::json::try_canonical_bytes(&value)
            .map_err(|error| {
                ContractError::internal(format!(
                    "observation {} violates the canonical data model: {error}",
                    observation.observation_id
                ))
            })
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|error| {
                    ContractError::internal(format!(
                        "observation {} canonical bytes are not UTF-8: {error}",
                        observation.observation_id
                    ))
                })
            })?;
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO observations(observation_id, source_kind, source_identity, native_id, content_digest, record, observed_at, lifecycle)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    observation.observation_id,
                    observation.source_kind,
                    observation.source_identity,
                    observation.native_id,
                    observation.content_digest,
                    record,
                    observation.observed_at,
                    observation.lifecycle
                ],
            )
            .map_err(sqlite_error("insert observation"))?;
        Ok(inserted == 1)
    }

    /// Retire the previous observation for a changed native source. The old
    /// row remains as history with a superseded lifecycle, and the explicit
    /// disposition transition is recorded for `status --json`.
    pub fn supersede_observation(
        &self,
        observation_id: &str,
        from_disposition: &str,
        to_disposition: &str,
        new_observation_id: &str,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE observations SET lifecycle='superseded' WHERE observation_id=?1 AND lifecycle != 'superseded'",
                params![observation_id],
            )
            .map_err(sqlite_error("supersede observation"))?;
        self.audit(
            "disposition-change",
            &json!({
                "observation_id": observation_id,
                "new_observation_id": new_observation_id,
                "from_disposition": from_disposition,
                "to_disposition": to_disposition,
                "observed_at": now
            }),
        )
    }

    /// Replace the stored record of an existing observation (mutable
    /// provenance such as lifecycle, revision or adapter attributes). The
    /// observation identity and content digest never change.
    pub fn update_observation(&self, observation: &Observation) -> Result<bool, ContractError> {
        let record = canonical_model(observation)?;
        let updated = self
            .connection
            .execute(
                "UPDATE observations SET record=?2, lifecycle=?3, observed_at=?4 WHERE observation_id=?1",
                params![
                    observation.observation_id,
                    record,
                    observation.lifecycle,
                    observation.observed_at
                ],
            )
            .map_err(sqlite_error("update observation"))?;
        Ok(updated == 1)
    }

    /// Move an observation recorded under an older identity of its source to
    /// the source's current identity. The observation id is kept, so every
    /// receipt and atom that names it still resolves.
    pub fn rekey_observation(&self, observation: &Observation) -> Result<(), ContractError> {
        let value = serde_json::to_value(observation).map_err(|error| {
            ContractError::internal(format!("observation is not serialisable: {error}"))
        })?;
        let record = crate::json::try_canonical_text(&value).map_err(|error| {
            ContractError::internal(format!(
                "observation violates the canonical data model: {error}"
            ))
        })?;
        self.connection
            .execute(
                "UPDATE observations SET source_identity=?2, record=?3, lifecycle=?4 WHERE observation_id=?1",
                params![
                    observation.observation_id,
                    observation.source_identity,
                    record,
                    observation.lifecycle
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("rekey observation"))
    }

    /// Every observation in the ledger in admission order (the ledger's own
    /// opaque cursor), with the lifecycle column and cursor attached.
    pub fn all_observations(&self) -> Result<Vec<Observation>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record, lifecycle, rowid FROM observations ORDER BY rowid")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        let mut skipped = crate::output::Skipped::default();
        for (position, row) in rows.enumerate() {
            let (text, lifecycle, cursor) = row.map_err(sqlite_error("row"))?;
            // One unreadable row must not make the whole ledger unreadable. A
            // corrupt observation is quarantined by being skipped -- the rest of a
            // company's corpus stays usable, which is the same disposition this
            // product takes everywhere else it meets bytes it cannot trust. Failing
            // the entire read instead meant five empty rows out of 1,297 hid every
            // other observation from every caller. The skip is counted and
            // reported, as every sibling reader's is.
            let Ok(mut observation) = serde_json::from_str::<Observation>(&text) else {
                skipped.push(
                    position,
                    text.len(),
                    crate::output::unreadable_reason(text.as_bytes()),
                );
                continue;
            };
            observation.lifecycle = lifecycle;
            observation.cursor = Some(cursor.max(0) as u64);
            output.push(observation);
        }
        skipped.report("observations");
        Ok(output)
    }

    /// The ledger's current admission cursor (highest rowid), 0 when empty.
    pub fn observation_cursor(&self) -> Result<u64, ContractError> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(rowid), 0) FROM observations",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error("cursor"))?;
        Ok(value.max(0) as u64)
    }

    pub fn observations_for_source(
        &self,
        source_identity: &str,
    ) -> Result<Vec<Observation>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record, lifecycle FROM observations WHERE source_identity=?1 ORDER BY observed_at, observation_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![source_identity], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        let mut skipped = crate::output::Skipped::default();
        for (position, row) in rows.enumerate() {
            let (text, lifecycle) = row.map_err(sqlite_error("row"))?;
            // Same disposition as `all_observations`: skip, and say so.
            let mut observation: Observation = match serde_json::from_str(&text) {
                Ok(observation) => observation,
                Err(_) => {
                    skipped.push(position, text.len(), "not a readable observation");
                    continue;
                }
            };
            observation.lifecycle = lifecycle;
            output.push(observation);
        }
        skipped.report("observations_for_source");
        Ok(output)
    }

    pub fn observation_count(&self) -> Result<i64, ContractError> {
        self.connection
            .query_row("SELECT COUNT(*) FROM observations", [], |row| row.get(0))
            .map_err(sqlite_error("count"))
    }

    pub fn insert_atom(&self, atom: &Atom, now: &str) -> Result<bool, ContractError> {
        let record = canonical_model(atom)?;
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO atoms(atom_id, observation_id, record, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![atom.atom_id, atom.observation_id, record, now],
            )
            .map_err(sqlite_error("insert atom"))?;
        Ok(inserted == 1)
    }

    pub fn atoms(&self) -> Result<Vec<Atom>, ContractError> {
        self.records("SELECT record FROM atoms ORDER BY created_at, atom_id")
    }

    pub fn atoms_for_session(&self, session_id: &str) -> Result<Vec<Atom>, ContractError> {
        let source_identity = format!("session:{session_id}");
        let mut statement = self
            .connection
            .prepare(
                "SELECT a.record FROM atoms a JOIN observations o ON o.observation_id = a.observation_id
                 WHERE o.source_identity = ?1 ORDER BY a.created_at, a.atom_id",
            )
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![source_identity], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        parse_rows("atoms_for_session", rows)
    }

    fn records<T: serde::de::DeserializeOwned>(&self, sql: &str) -> Result<Vec<T>, ContractError> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        parse_rows(sql, rows)
    }

    pub fn values(
        &self,
        sql: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(args, |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        parse_rows(sql, rows)
    }

    // ----- personal facts -----

    pub fn upsert_personal_fact(&self, fact: &Value, now: &str) -> Result<bool, ContractError> {
        let fact_id = crate::json::get_str(fact, "fact_id")
            .unwrap_or_default()
            .to_owned();
        let logical_key = crate::json::get_str(fact, "logical_key")
            .unwrap_or_default()
            .to_owned();
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO personal_facts(fact_id, logical_key, record, created_at, status) VALUES (?1, ?2, ?3, ?4, 'current')",
                params![fact_id, logical_key, canonical_record(fact)?, now],
            )
            .map_err(sqlite_error("personal fact"))?;
        Ok(inserted == 1)
    }

    pub fn personal_facts(&self) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM personal_facts WHERE status='current' ORDER BY created_at, fact_id",
            &[],
        )
    }

    // ----- sessions -----

    pub fn insert_session(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO sessions(session_id, host, repository_id, started_at, status, record) VALUES (?1, ?2, ?3, ?4, 'started', ?5)",
                params![
                    crate::json::get_str(record, "session_id").unwrap_or_default(),
                    crate::json::get_str(record, "host").unwrap_or_default(),
                    crate::json::get_str(record, "repository_id"),
                    crate::json::get_str(record, "started_at").unwrap_or_default(),
                    canonical_record(record)?
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("insert session"))
    }

    pub fn session(&self, session_id: &str) -> Result<Option<Value>, ContractError> {
        let row: Option<(String, String, Option<String>)> = self
            .connection
            .query_row(
                "SELECT record, status, ended_at FROM sessions WHERE session_id=?1",
                params![session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sqlite_error("read session"))?;
        Ok(row.map(|(record, status, ended_at)| {
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["status"] = Value::String(status);
            value["ended_at"] = ended_at.map(Value::String).unwrap_or(Value::Null);
            value
        }))
    }

    pub fn end_session(&self, session_id: &str, now: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE sessions SET status='ended', ended_at=?2 WHERE session_id=?1",
                params![session_id, now],
            )
            .map(|_| ())
            .map_err(sqlite_error("end session"))
    }

    pub fn insert_session_event(
        &self,
        session_id: &str,
        event_id: &str,
        event_type: &str,
        record: &Value,
        now: &str,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO session_events(session_id, event_id, event_type, observed_at, record) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![session_id, event_id, event_type, now, canonical_record(record)?],
            )
            .map_err(sqlite_error("insert session event"))?;
        Ok(inserted == 1)
    }

    pub fn session_events(&self, session_id: &str) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM session_events WHERE session_id=?1 ORDER BY id",
            &[&session_id],
        )
    }

    pub fn session_event_exists(
        &self,
        event_id: &str,
        event_type: &str,
    ) -> Result<bool, ContractError> {
        let count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM session_events WHERE event_id=?1 AND event_type=?2",
                params![event_id, event_type],
                |row| row.get(0),
            )
            .map_err(sqlite_error("event exists"))?;
        Ok(count > 0)
    }

    // ----- candidates and decisions -----

    pub fn insert_candidate(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO candidates(candidate_id, session_id, destination, payload_digest, record, created_at, expires_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
                params![
                    crate::json::get_str(record, "candidate_id").unwrap_or_default(),
                    crate::json::get_str(record, "session_id").unwrap_or_default(),
                    crate::json::get_str(record, "destination").unwrap_or_default(),
                    crate::json::get_str(record, "payload_digest").unwrap_or_default(),
                    canonical_record(record)?,
                    crate::json::get_str(record, "created_at").unwrap_or_default(),
                    crate::json::get_str(record, "expires_at").unwrap_or_default(),
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("insert candidate"))
    }

    pub fn candidate(&self, candidate_id: &str) -> Result<Option<Value>, ContractError> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT record, status FROM candidates WHERE candidate_id=?1",
                params![candidate_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("read candidate"))?;
        Ok(row.map(|(record, status)| {
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["status"] = Value::String(status);
            value
        }))
    }

    pub fn set_candidate_status(
        &self,
        candidate_id: &str,
        status: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE candidates SET status=?2 WHERE candidate_id=?1",
                params![candidate_id, status],
            )
            .map(|_| ())
            .map_err(sqlite_error("candidate status"))
    }

    pub fn candidates_for_session(&self, session_id: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record, status FROM candidates WHERE session_id=?1 ORDER BY created_at, candidate_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![session_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let (record, status) = row.map_err(sqlite_error("row"))?;
            let mut value: Value = serde_json::from_str(&record)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            value["status"] = Value::String(status);
            output.push(value);
        }
        Ok(output)
    }

    pub fn decision(
        &self,
        candidate_id: &str,
        destination: &str,
    ) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM decisions WHERE candidate_id=?1 AND destination=?2",
                params![candidate_id, destination],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read decision"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn any_decision(&self, candidate_id: &str) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM decisions WHERE candidate_id=?1 ORDER BY decided_at LIMIT 1",
                params![candidate_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("read decision"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn insert_decision(&self, record: &Value) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO decisions(receipt_id, candidate_id, destination, decision, digest, record, decided_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    crate::json::get_str(record, "receipt_id").unwrap_or_default(),
                    crate::json::get_str(record, "candidate_id").unwrap_or_default(),
                    crate::json::get_str(record, "destination").unwrap_or_default(),
                    crate::json::get_str(record, "decision").unwrap_or_default(),
                    crate::json::get_str(record, "digest").unwrap_or_default(),
                    canonical_record(record)?,
                    crate::json::get_str(record, "decided_at").unwrap_or_default(),
                ],
            )
            .map_err(sqlite_error("insert decision"))?;
        Ok(inserted == 1)
    }

    pub fn insert_destination_receipt(
        &self,
        candidate_id: &str,
        destination: &str,
        status: &str,
        record: &Value,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO destination_receipts(candidate_id, destination, status, record, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![candidate_id, destination, status, canonical_record(record)?, crate::time::now_rfc3339_millis()],
            )
            .map(|_| ())
            .map_err(sqlite_error("destination receipt"))
    }

    pub fn destination_receipts(&self, candidate_id: &str) -> Result<Vec<Value>, ContractError> {
        self.values(
            "SELECT record FROM destination_receipts WHERE candidate_id=?1 ORDER BY id",
            &[&candidate_id],
        )
    }

    pub fn recent_decision_digests(
        &self,
        principal_destination: &str,
    ) -> Result<Vec<String>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT digest FROM decisions WHERE destination=?1 AND decision IN ('reject','defer') ORDER BY decided_at DESC LIMIT 200")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![principal_destination], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    // ----- prompt budget core (architecture §5) -----

    /// One `BEGIN IMMEDIATE` transaction that checks reissue eligibility,
    /// inserts the unique reissue lock, reserves one of four sliding-hour
    /// slots, increments the consecutive count, and issues a single-use
    /// display token. Returns the reservation record or the typed refusal.
    /// `reissue_trusted` says whether a byte-change reissue is eligible
    /// (authority-trusted source revision).
    pub fn reserve_prompt_slot(
        &mut self,
        principal_id: &str,
        host_instance_id: &str,
        destination: &str,
        candidate_id: &str,
        content_digest: &str,
        source_revision: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let window_start = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        // Existing live reservation for this candidate is returned as-is
        // (idempotent render of the same item).
        let existing: Option<String> = transaction
            .query_row(
                "SELECT record FROM (SELECT reservation_id, candidate_id, expires_at, display_token, status,
                     json_object('reservation_id', reservation_id, 'candidate_id', candidate_id, 'display_token', display_token,
                                 'reserved_at', reserved_at, 'expires_at', expires_at, 'status', status, 'destination', destination) AS record
                     FROM prompt_reservations)
                 WHERE candidate_id=?1 AND expires_at > ?2 AND status='reserved'",
                params![candidate_id, now],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("existing reservation"))?;
        if let Some(record) = existing {
            transaction.commit().map_err(sqlite_error("commit"))?;
            let mut value: Value = serde_json::from_str(&record).unwrap_or(Value::Null);
            value["reused"] = Value::Bool(true);
            return Ok(value);
        }
        // Reissue eligibility: a rejected/deferred/expired content digest
        // cannot be reissued for 24 hours unless its source revision or
        // rendered bytes changed.
        let lock_window = &now[..10];
        let prior_lock: Option<(String, String)> = transaction
            .query_row(
                "SELECT locked_at, source_revision FROM reissue_locks WHERE principal_id=?1 AND destination=?2 AND content_digest=?3 ORDER BY locked_at DESC LIMIT 1",
                params![principal_id, destination, content_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("reissue lock read"))?;
        if let Some((locked_at, locked_revision)) = prior_lock {
            let age = crate::time::seconds_between(&locked_at, now).unwrap_or(0);
            if age < REISSUE_LOCK_SECONDS && locked_revision == source_revision {
                self_bump(&transaction, "suppressed")?;
                transaction.commit().map_err(sqlite_error("commit"))?;
                return Err(ContractError::limit(
                    "this content digest was decided within the last 24 hours and its source revision is unchanged",
                    json!({"refused_count": 1, "omitted_count": 1, "lock_age_seconds": age, "lock_seconds": REISSUE_LOCK_SECONDS}),
                ));
            }
        }
        // Four total cross-destination slots in the sliding hour; crash or
        // abandonment never releases a slot, it expires on the same clock.
        let reserved_in_window: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM prompt_reservations WHERE principal_id=?1 AND host_instance_id=?2 AND reserved_at > ?3",
                params![principal_id, host_instance_id, window_start],
                |row| row.get(0),
            )
            .map_err(sqlite_error("window count"))?;
        if reserved_in_window >= PROMPT_WINDOW_LIMIT {
            self_bump(&transaction, "suppressed")?;
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "four shared approval opportunities are already reserved in the sliding hour for this principal and host instance",
                json!({"refused_count": 1, "omitted_count": 1, "reserved_in_window": reserved_in_window, "window_seconds": PROMPT_WINDOW_SECONDS, "ceiling": PROMPT_WINDOW_LIMIT}),
            ));
        }
        let consecutive: i64 = transaction
            .query_row(
                "SELECT count FROM consecutive WHERE principal_id=?1 AND host_instance_id=?2",
                params![principal_id, host_instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("consecutive read"))?
            .unwrap_or(0);
        if consecutive >= CONSECUTIVE_LIMIT {
            self_bump(&transaction, "suppressed")?;
            // The suppressed opportunity itself breaks the consecutive run,
            // allowing a fourth non-consecutive slot within the hourly cap.
            transaction
                .execute(
                    "UPDATE consecutive SET count=0, updated_at=?3 WHERE principal_id=?1 AND host_instance_id=?2",
                    params![principal_id, host_instance_id, now],
                )
                .map_err(sqlite_error("reset consecutive after suppression"))?;
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "three consecutive shared prompts were surfaced without returning to the primary task",
                json!({"refused_count": 1, "omitted_count": 1, "consecutive": consecutive, "ceiling": CONSECUTIVE_LIMIT}),
            ));
        }
        let reservation_id = crate::crypto::random_id("resv");
        let display_token = crate::crypto::random_token();
        let expires_at = crate::time::plus_seconds(now, PROMPT_WINDOW_SECONDS)
            .map_err(ContractError::internal)?;
        transaction
            .execute(
                "INSERT INTO prompt_reservations(reservation_id, principal_id, host_instance_id, destination, candidate_id, content_digest, reserved_at, expires_at, display_token, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'reserved')",
                params![reservation_id, principal_id, host_instance_id, destination, candidate_id, content_digest, now, expires_at, display_token],
            )
            .map_err(sqlite_error("reserve"))?;
        transaction
            .execute(
                "INSERT INTO consecutive(principal_id, host_instance_id, count, updated_at) VALUES (?1, ?2, 1, ?3)
                 ON CONFLICT(principal_id, host_instance_id) DO UPDATE SET count=count+1, updated_at=excluded.updated_at",
                params![principal_id, host_instance_id, now],
            )
            .map_err(sqlite_error("consecutive"))?;
        // The digest lock is a fact about a digest that reached a human, so it
        // is taken in the same transaction as the slot it reached them in. A
        // proposal the budget refused was never put to anyone and never
        // decided, so it must stay reissuable.
        transaction
            .execute(
                "INSERT OR IGNORE INTO reissue_locks(principal_id, destination, content_digest, lock_window, locked_at, source_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![principal_id, destination, content_digest, lock_window, now, source_revision],
            )
            .map_err(sqlite_error("reissue lock insert"))?;
        self_bump(&transaction, "reserved")?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "reservation_id": reservation_id,
            "candidate_id": candidate_id,
            "destination": destination,
            "display_token": display_token,
            "reserved_at": now,
            "expires_at": expires_at,
            "status": "reserved",
            "reserved_in_window": reserved_in_window + 1,
            "consecutive": consecutive + 1,
            "reused": false
        }))
    }

    /// Mark a reservation rendered/decided (metrics only; never releases the slot).
    pub fn mark_reservation(&self, candidate_id: &str, status: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE prompt_reservations SET status=?2 WHERE candidate_id=?1 AND status='reserved'",
                params![candidate_id, status],
            )
            .map_err(sqlite_error("mark reservation"))?;
        self.bump(status)
    }

    pub fn bump(&self, name: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO budget_metrics(name, count) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET count=count+1",
                params![name],
            )
            .map(|_| ())
            .map_err(sqlite_error("metric"))
    }

    /// One `BEGIN IMMEDIATE` reissue eligibility transaction. A digest is locked
    /// for 24 hours unless the trusted source revision changed.
    pub fn reserve_reissue(
        &mut self,
        principal_id: &str,
        destination: &str,
        content_digest: &str,
        source_revision: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let lock_window = &now[..10];
        let prior_lock: Option<(String, String)> = transaction
            .query_row(
                "SELECT locked_at, source_revision FROM reissue_locks WHERE principal_id=?1 AND destination=?2 AND content_digest=?3 ORDER BY locked_at DESC LIMIT 1",
                params![principal_id, destination, content_digest],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sqlite_error("reissue lock read"))?;
        if let Some((locked_at, locked_revision)) = prior_lock {
            let age = crate::time::seconds_between(&locked_at, now).unwrap_or(0);
            if age < REISSUE_LOCK_SECONDS && locked_revision == source_revision {
                self_bump(&transaction, "suppressed")?;
                transaction.commit().map_err(sqlite_error("commit"))?;
                return Err(ContractError::limit(
                    "candidate source bytes and revision are unchanged within 24 hours",
                    json!({"refused_count": 1, "omitted_count": 1, "lock_age_seconds": age, "lock_seconds": REISSUE_LOCK_SECONDS}),
                ));
            }
        }
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO reissue_locks(principal_id, destination, content_digest, lock_window, locked_at, source_revision) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![principal_id, destination, content_digest, lock_window, now, source_revision],
            )
            .map_err(sqlite_error("reissue lock insert"))?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "transaction": "BEGIN IMMEDIATE",
            "committed": true,
            "lock_inserted": inserted == 1,
            "at": now
        }))
    }

    /// Consecutive-counter reset: only after a real primary-task event and at
    /// most once per hour. The hourly ceiling is untouched.
    pub fn reset_consecutive(
        &mut self,
        principal_id: &str,
        host_instance_id: &str,
        after_event_id: &str,
        reason_code: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(sqlite_error("begin immediate"))?;
        let event_exists: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM session_events WHERE event_id=?1 AND event_type IN ('primary-task','UserPromptSubmit','user_prompt_submit','prompt')",
                params![after_event_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error("event lookup"))?;
        if event_exists == 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "no recorded primary-task event matches the supplied event id",
                "Record a real new primary-task event (a host prompt) before resetting the consecutive counter.",
            ));
        }
        let already_used: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM resets WHERE after_event_id=?1",
                params![after_event_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error("reset lookup"))?;
        if already_used > 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "this primary-task event already authorized a reset",
                json!({"refused_count": 1, "omitted_count": 1}),
            ));
        }
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let hour_ago = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        let recent: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM resets WHERE principal_id=?1 AND host_instance_id=?2 AND reset_at > ?3",
                params![principal_id, host_instance_id, hour_ago],
                |row| row.get(0),
            )
            .map_err(sqlite_error("recent resets"))?;
        if recent > 0 {
            transaction.commit().map_err(sqlite_error("commit"))?;
            return Err(ContractError::limit(
                "consecutive-counter reset is limited to once per hour; the hourly ceiling never resets",
                json!({"refused_count": 1, "omitted_count": 1, "cooldown_seconds": PROMPT_WINDOW_SECONDS}),
            ));
        }
        let reset_id = crate::crypto::random_id("reset");
        transaction
            .execute(
                "INSERT INTO resets(reset_id, principal_id, host_instance_id, after_event_id, reason_code, reset_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![reset_id, principal_id, host_instance_id, after_event_id, reason_code, now],
            )
            .map_err(sqlite_error("insert reset"))?;
        transaction
            .execute(
                "INSERT INTO consecutive(principal_id, host_instance_id, count, last_reset_event, updated_at) VALUES (?1, ?2, 0, ?3, ?4)
                 ON CONFLICT(principal_id, host_instance_id) DO UPDATE SET count=0, last_reset_event=excluded.last_reset_event, updated_at=excluded.updated_at",
                params![principal_id, host_instance_id, after_event_id, now],
            )
            .map_err(sqlite_error("reset consecutive"))?;
        transaction.commit().map_err(sqlite_error("commit"))?;
        Ok(json!({
            "reset_id": reset_id,
            "after_primary_event": after_event_id,
            "reason_code": reason_code,
            "reset_at": now,
            "scope": "consecutive-counter-only",
            "hourly_ceiling_reset": false
        }))
    }

    /// Budget shard summary for `doctor`.
    pub fn budget_shard(
        &self,
        principal_id: &str,
        host_instance_id: &str,
        now: &str,
    ) -> Result<Value, ContractError> {
        let now_dt = crate::time::parse_rfc3339_millis(now).map_err(ContractError::internal)?;
        let window_start = crate::time::format_rfc3339_millis(
            now_dt - chrono::Duration::seconds(PROMPT_WINDOW_SECONDS),
        );
        let reserved_in_window: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM prompt_reservations WHERE principal_id=?1 AND host_instance_id=?2 AND reserved_at > ?3",
                params![principal_id, host_instance_id, window_start],
                |row| row.get(0),
            )
            .map_err(sqlite_error("window count"))?;
        let consecutive: i64 = self
            .connection
            .query_row(
                "SELECT count FROM consecutive WHERE principal_id=?1 AND host_instance_id=?2",
                params![principal_id, host_instance_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("consecutive"))?
            .unwrap_or(0);
        let mut metrics = serde_json::Map::new();
        let mut statement = self
            .connection
            .prepare("SELECT name, count FROM budget_metrics ORDER BY name")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        for row in rows {
            let (name, count) = row.map_err(sqlite_error("row"))?;
            metrics.insert(name, Value::from(count));
        }
        for name in [
            "reserved",
            "rendered",
            "decided",
            "expired",
            "suppressed",
            "delivery_loss",
        ] {
            metrics.entry(name).or_insert(Value::from(0));
        }
        Ok(json!({
            "principal_id": principal_id,
            "host_instance_id": host_instance_id,
            "window_seconds": PROMPT_WINDOW_SECONDS,
            "total_limit": PROMPT_WINDOW_LIMIT,
            "consecutive_limit": CONSECUTIVE_LIMIT,
            "reserved_in_window": reserved_in_window,
            "consumed_in_window": reserved_in_window,
            "consecutive": consecutive,
            "metrics": metrics,
            "global_cross_machine_total_known": false,
            "warning": "no global cross-machine prompt total is known; this shard covers exactly one (principal_id, host_instance_id)"
        }))
    }

    pub fn record_shard_observation(&self, record: &Value, now: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO shard_observations(observed_at, record) VALUES (?1, ?2)",
                params![now, canonical_record(record)?],
            )
            .map(|_| ())
            .map_err(sqlite_error("shard observation"))
    }

    /// Expire candidates and count delivery losses (reservations that were
    /// never rendered before expiry).
    pub fn sweep(&self, now: &str) -> Result<Value, ContractError> {
        let expired_candidates = self
            .connection
            .execute(
                "UPDATE candidates SET status='expired' WHERE status='pending' AND expires_at <= ?1",
                params![now],
            )
            .map_err(sqlite_error("expire candidates"))?;
        let lost = self
            .connection
            .execute(
                "UPDATE prompt_reservations SET status='delivery_loss' WHERE status='reserved' AND expires_at <= ?1",
                params![now],
            )
            .map_err(sqlite_error("delivery loss"))?;
        for _ in 0..expired_candidates {
            self.bump("expired")?;
        }
        for _ in 0..lost {
            self.bump("delivery_loss")?;
        }
        let bodies = self.expire_bodies(now)?;
        let queries = self
            .connection
            .execute(
                "DELETE FROM query_log WHERE logged_at <= ?1",
                params![query_log_cutoff(now)],
            )
            .map_err(sqlite_error("expire query log"))?;
        Ok(
            json!({"expired_candidates": expired_candidates, "delivery_loss": lost, "expired_bodies": bodies, "expired_queries": queries}),
        )
    }

    /// What `sweep` would change at `now`, changing nothing: `doctor` reports
    /// this, and the transitions happen on the session write path.
    pub fn sweep_due(&self, now: &str) -> Result<Value, ContractError> {
        let count = |sql: &str| -> Result<i64, ContractError> {
            let counted: rusqlite::Result<i64> =
                self.connection
                    .query_row(sql, params![now], |row| row.get(0));
            counted.map_err(sqlite_error("sweep preview"))
        };
        let due_queries: rusqlite::Result<i64> = self.connection.query_row(
            "SELECT COUNT(*) FROM query_log WHERE logged_at <= ?1",
            params![query_log_cutoff(now)],
            |row| row.get(0),
        );
        let due_queries = due_queries.map_err(sqlite_error("sweep preview"))?;
        Ok(json!({
            "applied": false,
            "due_candidate_expiries": count(
                "SELECT COUNT(*) FROM candidates WHERE status='pending' AND expires_at <= ?1"
            )?,
            "due_delivery_losses": count(
                "SELECT COUNT(*) FROM prompt_reservations WHERE status='reserved' AND expires_at <= ?1"
            )?,
            "due_body_expiries": count("SELECT COUNT(*) FROM bodies WHERE retention_until <= ?1")?,
            "due_query_expiries": due_queries
        }))
    }

    // ----- checkpoints, query log, reminders, unknowns -----

    pub fn checkpoint(&self, source_identity: &str) -> Result<Option<Value>, ContractError> {
        let record: Option<String> = self
            .connection
            .query_row(
                "SELECT record FROM checkpoints WHERE source_identity=?1",
                params![source_identity],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("checkpoint"))?;
        Ok(record.and_then(|text| serde_json::from_str(&text).ok()))
    }

    pub fn set_checkpoint(
        &self,
        source_identity: &str,
        record: &Value,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO checkpoints(source_identity, record, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(source_identity) DO UPDATE SET record=excluded.record, updated_at=excluded.updated_at",
                params![source_identity, canonical_record(record)?, now],
            )
            .map(|_| ())
            .map_err(sqlite_error("set checkpoint"))
    }

    pub fn log_query(&self, session_id: Option<&str>, record: &Value) -> Result<(), ContractError> {
        // `canonical_text` yields "" when the record fails the canonical text
        // rule, and a blank row is unreadable to every later reader: eight of
        // them in one Personal store hid every `status` report. Refuse, as
        // `insert_observation` does, and bound the session column to a host
        // identifier so free text cannot land there again.
        if let Some(session) = session_id {
            if !is_host_identifier(session) {
                return Err(ContractError::invariant(
                    "query log session_id must be a bounded host identifier",
                ));
            }
        }
        let record = crate::json::try_canonical_bytes(record)
            .map_err(|error| {
                ContractError::internal(format!("query record is not serialisable: {error}"))
            })
            .and_then(|bytes| {
                String::from_utf8(bytes)
                    .map_err(|_| ContractError::internal("query record is not UTF-8"))
            })?;
        self.connection
            .execute(
                "INSERT INTO query_log(session_id, record, logged_at) VALUES (?1, ?2, ?3)",
                params![session_id, record, crate::time::now_rfc3339_millis()],
            )
            .map(|_| ())
            .map_err(sqlite_error("query log"))
    }

    pub fn query_log(&self, session_id: Option<&str>) -> Result<Vec<Value>, ContractError> {
        match session_id {
            Some(session) => self.values(
                "SELECT record FROM query_log WHERE session_id=?1 ORDER BY id",
                &[&session],
            ),
            None => self.values("SELECT record FROM query_log ORDER BY id", &[]),
        }
    }

    /// The newest `limit` query-log entries, oldest first, and how many the
    /// log holds: a report carries a window and says so, rather than
    /// reading the whole log on every status.
    pub fn recent_query_log(&self, limit: i64) -> Result<(Vec<Value>, i64), ContractError> {
        let records = self.values(
            "SELECT record FROM (SELECT id, record FROM query_log ORDER BY id DESC LIMIT ?1) ORDER BY id",
            &[&limit],
        )?;
        let total: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM query_log", [], |row| row.get(0))
            .map_err(sqlite_error("count query log"))?;
        Ok((records, total))
    }

    pub fn insert_reminder(&self, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO reminders(reminder_id, record, due_at, status) VALUES (?1, ?2, ?3, 'pending')",
                params![
                    crate::json::get_str(record, "reminder_id").unwrap_or_default(),
                    canonical_record(record)?,
                    crate::json::get_str(record, "due_at").unwrap_or_default(),
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("reminder"))
    }

    pub fn upsert_private_unknown(
        &self,
        unknown_id: &str,
        record: &Value,
        status: &str,
        now: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO private_unknowns(unknown_id, record, status, updated_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(unknown_id) DO UPDATE SET record=excluded.record, status=excluded.status, updated_at=excluded.updated_at",
                params![unknown_id, canonical_record(record)?, status, now],
            )
            .map(|_| ())
            .map_err(sqlite_error("private unknown"))
    }

    pub fn private_unknowns(&self) -> Result<Vec<Value>, ContractError> {
        self.values("SELECT record FROM private_unknowns WHERE status <> 'closed' ORDER BY updated_at, unknown_id", &[])
    }

    pub fn quarantine(&self, kind: &str, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO quarantine(kind, record, recorded_at) VALUES (?1, ?2, ?3)",
                params![
                    kind,
                    // Quarantine holds what failed the canonical rule, so it
                    // keeps an escaped rendering rather than refusing.
                    crate::output::single_line(record),
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("quarantine"))
    }

    pub fn quarantine_count(&self, kind: &str) -> Result<i64, ContractError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM quarantine WHERE kind=?1",
                params![kind],
                |row| row.get(0),
            )
            .map_err(sqlite_error("quarantine count"))
    }
}

fn self_bump(transaction: &rusqlite::Transaction<'_>, name: &str) -> Result<(), ContractError> {
    transaction
        .execute(
            "INSERT INTO budget_metrics(name, count) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET count=count+1",
            params![name],
        )
        .map(|_| ())
        .map_err(sqlite_error("metric"))
}

#[cfg(test)]
mod sweep_tests {
    use super::*;

    #[test]
    fn a_preview_changes_nothing_and_the_sweep_applies_it() {
        let store = PrivateStore::open_memory("core").expect("store");
        store
            .insert_candidate(&json!({
                "candidate_id": "cand_1",
                "session_id": "s-1",
                "destination": "company",
                "payload_digest": "0".repeat(64),
                "created_at": "2026-09-01T00:00:00.000Z",
                "expires_at": "2026-09-01T00:15:00.000Z"
            }))
            .expect("candidate");
        store
            .store_body(b"raw", "2026-09-01T00:00:00.000Z")
            .expect("body");
        let now = "2026-09-17T00:00:00.000Z";
        for _ in 0..2 {
            let due = store.sweep_due(now).expect("preview");
            assert_eq!(due["due_candidate_expiries"], 1, "{due}");
            assert_eq!(due["due_body_expiries"], 1, "{due}");
            assert_eq!(due["applied"], false);
        }
        let applied = store.sweep(now).expect("sweep");
        assert_eq!(applied["expired_candidates"], 1, "{applied}");
        assert_eq!(applied["expired_bodies"], 1, "{applied}");
        assert_eq!(
            store.sweep_due(now).expect("preview")["due_candidate_expiries"],
            0
        );
    }

    #[test]
    fn the_query_log_keeps_thirty_days_and_a_report_reads_a_window() {
        let store = PrivateStore::open_memory("core").expect("store");
        for index in 0..5 {
            store
                .log_query(Some("s-1"), &json!({"query": format!("q{index}")}))
                .expect("log");
        }
        // Two entries logged long ago.
        store
            .connection
            .execute(
                "UPDATE query_log SET logged_at='2026-01-01T00:00:00.000Z' WHERE id <= 2",
                [],
            )
            .expect("age");
        let (window, total) = store.recent_query_log(2).expect("window");
        assert_eq!(total, 5);
        assert_eq!(window, vec![json!({"query": "q3"}), json!({"query": "q4"})]);

        let now = crate::time::now_rfc3339_millis();
        assert_eq!(
            store.sweep_due(&now).expect("preview")["due_query_expiries"],
            2
        );
        assert_eq!(store.sweep(&now).expect("sweep")["expired_queries"], 2);
        let (window, total) = store.recent_query_log(10).expect("window");
        assert_eq!(total, 3);
        assert_eq!(window.first(), Some(&json!({"query": "q2"})));
    }
}
