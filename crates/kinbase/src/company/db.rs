//! `kinbased` SQLite state (architecture §6 "Company / Kinbase"): an
//! append-only event table with a monotonic cursor, authority registry,
//! directory, questions/answers/Unknowns, consumed nonces, tokens with
//! first-use client-key binding, throttles, certificates, manifest
//! observations, fact version history, and append-only usage rows.

use crate::error::ContractError;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

pub const COMPANY_SCHEMA_VERSION: i64 = 2;

pub fn sqlite_error(context: &str) -> impl Fn(rusqlite::Error) -> ContractError + '_ {
    move |error| ContractError::internal(format!("{context}: {error}"))
}

/// The three outcome columns of a usage breakdown: requests, succeeded and
/// failed. A refusal is a 4xx and is what remains; a 5xx is the service
/// failing, counted apart so a maintenance fault does not read as callers
/// being turned away.
const USAGE_OUTCOMES: &str =
    "COUNT(*), COALESCE(SUM(status < 400), 0), COALESCE(SUM(status >= 500), 0)";

/// `(requests, succeeded, refused, failed)` from the `USAGE_OUTCOMES`
/// columns starting at `first`.
fn usage_outcomes(row: &rusqlite::Row<'_>, first: usize) -> rusqlite::Result<(i64, i64, i64, i64)> {
    let requests: i64 = row.get(first)?;
    let succeeded: i64 = row.get(first + 1)?;
    let failed: i64 = row.get(first + 2)?;
    Ok((requests, succeeded, requests - succeeded - failed, failed))
}

pub struct CompanyDb {
    pub connection: Connection,
}

/// Read-time annotations these readers attach to a stored certificate. They are
/// not covered by the root signature, so any path that hands a certificate to a
/// client for installation must strip them first: `unsigned_bytes` removes only
/// `signature`, so a surviving annotation lands in the verification preimage and
/// the signature fails.
pub const CERTIFICATE_ANNOTATIONS: [&str; 3] = ["discovery_hint", "certificate_digest", "status"];

/// Return the certificate exactly as it was signed.
pub fn signed_certificate(document: &Value) -> Value {
    let mut pristine = document.clone();
    if let Some(map) = pristine.as_object_mut() {
        for key in CERTIFICATE_ANNOTATIONS {
            map.remove(key);
        }
    }
    pristine
}

impl CompanyDb {
    /// Opens and brings the schema up to date. Startup path: it creates the
    /// directory, fixes the mode and runs the migration, so a request never has
    /// to. Tests use it for the same reason.
    pub fn open(path: &Path) -> Result<Self, ContractError> {
        // The directory has to exist before the connection is opened, not after.
        if let Some(parent) = path.parent() {
            crate::paths::ensure_dir(parent, "Company SQLite directory")?;
        }
        let db = Self::connect(path)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        db.migrate()?;
        Ok(db)
    }

    /// Opens a connection to a database the startup path has already migrated.
    ///
    /// This is what a request uses. `open` chmods the file and runs `migrate`,
    /// and `migrate` is two `INSERT OR IGNORE` statements, so calling it per
    /// request meant every unauthenticated connection took two write
    /// transactions against a ten second busy timeout before anyone checked a
    /// credential. The symlink check stays: it is a stat, and the file being
    /// swapped underneath a running service is exactly what it exists to catch.
    pub fn connect(path: &Path) -> Result<Self, ContractError> {
        crate::paths::reject_symlink(path, "Company SQLite")?;
        let connection = Connection::open(path).map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("Company SQLite cannot be opened ({error})"),
                format!(
                    "Make {} writable by the service user; no partial schema was created.",
                    path.display()
                ),
            )
        })?;
        connection
            .busy_timeout(std::time::Duration::from_secs(10))
            .map_err(sqlite_error("busy timeout"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
            )
            .map_err(sqlite_error("pragma"))?;
        Ok(Self { connection })
    }

    /// Opens a connection that cannot write, for a reader running beside the
    /// service against whatever file the config names. `connect` would switch
    /// a foreign file's journal mode before anyone checked what it was.
    pub fn connect_read_only(path: &Path) -> Result<Self, ContractError> {
        crate::paths::reject_symlink(path, "Company SQLite")?;
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("Company SQLite cannot be opened ({error})"),
                format!("Make {} readable by this user.", path.display()),
            )
        })?;
        connection
            .busy_timeout(std::time::Duration::from_secs(10))
            .map_err(sqlite_error("busy timeout"))?;
        Ok(Self { connection })
    }

    /// Idempotent schema creation/migration (Validator ruling R-2).
    pub fn migrate(&self) -> Result<(), ContractError> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS events(
                    cursor INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
                    message_type TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL,
                    signer TEXT NOT NULL, verification TEXT NOT NULL, recorded_at TEXT NOT NULL,
                    source_identity TEXT);
                 CREATE TRIGGER IF NOT EXISTS events_immutable_update BEFORE UPDATE ON events
                    BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
                 CREATE TRIGGER IF NOT EXISTS events_immutable_delete BEFORE DELETE ON events
                    BEGIN SELECT RAISE(ABORT, 'events are immutable'); END;
                 CREATE TABLE IF NOT EXISTS tokens(
                    token_digest TEXT PRIMARY KEY, role TEXT NOT NULL, scopes TEXT NOT NULL,
                    authority_scopes TEXT NOT NULL, principal_id TEXT NOT NULL, bound_client_key TEXT,
                    created_at TEXT NOT NULL, retired_at TEXT);
                 CREATE TABLE IF NOT EXISTS token_client_keys(
                    token_digest TEXT NOT NULL, client_key TEXT NOT NULL, first_used_at TEXT NOT NULL,
                    PRIMARY KEY(token_digest, client_key));
                 CREATE TABLE IF NOT EXISTS registry(
                    authority_id TEXT NOT NULL, scope TEXT NOT NULL, public_key TEXT NOT NULL,
                    channel TEXT NOT NULL, capabilities TEXT NOT NULL, status TEXT NOT NULL,
                    cursor INTEGER NOT NULL, document TEXT NOT NULL, PRIMARY KEY(authority_id, scope));
                 CREATE TABLE IF NOT EXISTS directory(
                    authority_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, contact TEXT NOT NULL,
                    retention_until TEXT NOT NULL, updated_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS questions(
                    question_id TEXT PRIMARY KEY, unknown_id TEXT, authority_id TEXT NOT NULL,
                    scope TEXT NOT NULL, question_kind TEXT NOT NULL, document TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, response_due_at TEXT NOT NULL,
                    asked_by TEXT NOT NULL, delivery TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS answers(
                    answer_id TEXT PRIMARY KEY, question_id TEXT NOT NULL, authority_id TEXT NOT NULL,
                    scope TEXT NOT NULL, document TEXT NOT NULL, cursor INTEGER NOT NULL, answered_at TEXT NOT NULL,
                    supersedes TEXT);
                 CREATE TABLE IF NOT EXISTS unknowns(
                    unknown_id TEXT PRIMARY KEY, document TEXT NOT NULL, status TEXT NOT NULL,
                    owner_identity TEXT NOT NULL, scope TEXT NOT NULL, response_due_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL, kind TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS nonces(
                    destination TEXT NOT NULL, nonce TEXT NOT NULL, payload_digest TEXT NOT NULL,
                    client_key TEXT NOT NULL, authority_scope TEXT NOT NULL, receipt TEXT NOT NULL,
                    consumed_at TEXT NOT NULL, expires_at TEXT NOT NULL, PRIMARY KEY(destination, nonce));
                 CREATE TABLE IF NOT EXISTS request_nonces(
                    client_key TEXT NOT NULL, nonce TEXT NOT NULL, expires_at TEXT NOT NULL,
                    PRIMARY KEY(client_key, nonce));
                 CREATE TABLE IF NOT EXISTS auth_failures(minute INTEGER PRIMARY KEY, count INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS auth_failure_subjects(
                    minute INTEGER NOT NULL, subject TEXT NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(minute, subject));
                 CREATE TABLE IF NOT EXISTS request_rate(
                    client_key TEXT NOT NULL, minute INTEGER NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(client_key, minute));
                 CREATE TABLE IF NOT EXISTS read_volume(
                    principal_key TEXT NOT NULL, hour INTEGER NOT NULL, count INTEGER NOT NULL,
                    bytes INTEGER NOT NULL, PRIMARY KEY(principal_key, hour));
                 CREATE TABLE IF NOT EXISTS certificates(
                    repository_uuid TEXT PRIMARY KEY, document TEXT NOT NULL, hint TEXT,
                    digest TEXT NOT NULL, issued_at TEXT NOT NULL, status TEXT NOT NULL,
                    lineage_parent TEXT, cursor INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS manifest_observations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, repository_uuid TEXT NOT NULL, branch TEXT NOT NULL,
                    revision TEXT NOT NULL, event_count INTEGER NOT NULL, merkle_root TEXT NOT NULL,
                    event_digests TEXT NOT NULL, observed_at TEXT NOT NULL, fresh_until TEXT NOT NULL,
                    document TEXT NOT NULL, status TEXT NOT NULL, cursor INTEGER NOT NULL);
                 CREATE UNIQUE INDEX IF NOT EXISTS manifest_observation_lineage
                    ON manifest_observations(repository_uuid, branch, revision);
                 CREATE TABLE IF NOT EXISTS fact_versions(
                    fact_id TEXT NOT NULL, version INTEGER NOT NULL, semantic_digest TEXT NOT NULL,
                    digest_alg_version TEXT NOT NULL, event_id TEXT NOT NULL, cursor INTEGER NOT NULL,
                    retained INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(fact_id, version));
                 CREATE TABLE IF NOT EXISTS steward_queue(
                    event_id TEXT PRIMARY KEY, document TEXT NOT NULL, approval TEXT NOT NULL,
                    status TEXT NOT NULL, queued_at TEXT NOT NULL, submitted_by TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS relaxations(
                    relaxation_id TEXT PRIMARY KEY, repository_uuid TEXT NOT NULL, fact_id TEXT NOT NULL,
                    fact_version TEXT NOT NULL, requested_class TEXT NOT NULL, expires_at TEXT NOT NULL,
                    document TEXT NOT NULL, cursor INTEGER NOT NULL, status TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, record TEXT NOT NULL,
                    recorded_at TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS metrics(name TEXT PRIMARY KEY, count INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS authority_calls(
                    task_id TEXT NOT NULL, arm TEXT NOT NULL, seed TEXT NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(task_id, arm, seed));
                 CREATE TABLE IF NOT EXISTS usage_events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, recorded_at TEXT NOT NULL,
                    principal_id TEXT NOT NULL, client TEXT NOT NULL, token_role TEXT NOT NULL,
                    action TEXT NOT NULL, target TEXT NOT NULL, status INTEGER NOT NULL,
                    error_code TEXT, duration_ms INTEGER NOT NULL);
                 CREATE INDEX IF NOT EXISTS usage_events_recorded_at ON usage_events(recorded_at);
                 CREATE TRIGGER IF NOT EXISTS usage_events_immutable_update BEFORE UPDATE ON usage_events
                    BEGIN SELECT RAISE(ABORT, 'usage records are append-only'); END;
                 CREATE TRIGGER IF NOT EXISTS usage_events_immutable_delete BEFORE DELETE ON usage_events
                    WHEN OLD.recorded_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')
                    BEGIN SELECT RAISE(ABORT, 'usage records younger than a day are append-only'); END;",
            )
            .map_err(sqlite_error("company schema"))?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?1)",
                params![COMPANY_SCHEMA_VERSION.to_string()],
            )
            .map_err(sqlite_error("schema version"))?;
        self.connection
            .execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES ('revocation_cursor', '0')",
                [],
            )
            .map_err(sqlite_error("revocation cursor"))?;
        Ok(())
    }

    /// Whether the store holds a table named `name`.
    pub fn has_table(&self, name: &str) -> Result<bool, ContractError> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                params![name],
                |row| row.get(0),
            )
            .map_err(sqlite_error("schema lookup"))
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, ContractError> {
        self.connection
            .query_row("SELECT value FROM meta WHERE key=?1", params![key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(sqlite_error("meta"))
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map(|_| ())
            .map_err(sqlite_error("set meta"))
    }

    /// Current change cursor: the highest event cursor (0 when empty).
    pub fn cursor(&self) -> Result<i64, ContractError> {
        self.connection
            .query_row("SELECT COALESCE(MAX(cursor), 0) FROM events", [], |row| {
                row.get(0)
            })
            .map_err(sqlite_error("cursor"))
    }

    pub fn revocation_cursor(&self) -> Result<String, ContractError> {
        Ok(self
            .meta("revocation_cursor")?
            .unwrap_or_else(|| "0".to_owned()))
    }

    pub fn append_event(
        &self,
        event_id: &str,
        message_type: &str,
        kind: &str,
        payload: &Value,
        signer: &str,
        verification: &str,
        source_identity: Option<&str>,
    ) -> Result<Option<i64>, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO events(event_id, message_type, kind, payload, signer, verification, recorded_at, source_identity)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event_id,
                    message_type,
                    kind,
                    crate::json::record_text(payload)?,
                    signer,
                    verification,
                    crate::time::now_rfc3339_millis(),
                    source_identity
                ],
            )
            .map_err(sqlite_error("append event"))?;
        if inserted == 0 {
            return Ok(None);
        }
        Ok(Some(self.connection.last_insert_rowid()))
    }

    pub fn event_cursor(&self, event_id: &str) -> Result<Option<i64>, ContractError> {
        self.connection
            .query_row(
                "SELECT cursor FROM events WHERE event_id=?1",
                params![event_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("event cursor"))
    }

    pub fn events_of_kind(&self, kind: &str) -> Result<Vec<(i64, Value, String)>, ContractError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT cursor, payload, verification FROM events WHERE kind=?1 ORDER BY cursor",
            )
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![kind], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let (cursor, payload, verification) = row.map_err(sqlite_error("row"))?;
            let value: Value = serde_json::from_str(&payload)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            output.push((cursor, value, verification));
        }
        Ok(output)
    }

    /// The events at these cursors, parsed as `events_of_kind` parses them:
    /// a snapshot window loads only the rows it sends.
    pub fn events_at(&self, cursors: &[i64]) -> Result<Vec<(i64, Value, String)>, ContractError> {
        if cursors.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = vec!["?"; cursors.len()].join(",");
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT cursor, payload, verification FROM events WHERE cursor IN ({placeholders})"
            ))
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(rusqlite::params_from_iter(cursors.iter()), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let (cursor, payload, verification) = row.map_err(sqlite_error("row"))?;
            let value: Value = serde_json::from_str(&payload)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            output.push((cursor, value, verification));
        }
        Ok(output)
    }

    pub fn events_of_message_type(
        &self,
        message_type: &str,
    ) -> Result<Vec<(i64, Value, String)>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT cursor, payload, verification FROM events WHERE message_type=?1 ORDER BY cursor")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![message_type], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let (cursor, payload, verification) = row.map_err(sqlite_error("row"))?;
            let value: Value = serde_json::from_str(&payload)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            output.push((cursor, value, verification));
        }
        Ok(output)
    }

    pub fn all_events(&self, since: i64, limit: i64) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT cursor, event_id, message_type, kind, payload, verification, recorded_at FROM events WHERE cursor > ?1 ORDER BY cursor LIMIT ?2")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![since, limit], |row| {
                Ok(json!({
                    "cursor": row.get::<_, i64>(0)?.to_string(),
                    "event_id": row.get::<_, String>(1)?,
                    "message_type": row.get::<_, String>(2)?,
                    "kind": row.get::<_, String>(3)?,
                    "payload": serde_json::from_str::<Value>(&row.get::<_, String>(4)?).unwrap_or(Value::Null),
                    "verification": row.get::<_, String>(5)?,
                    "recorded_at": row.get::<_, String>(6)?
                }))
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    // ----- tokens -----

    pub fn register_token(
        &self,
        token: &str,
        role: &str,
        scopes: &[&str],
        authority_scopes: &[String],
        principal_id: &str,
    ) -> Result<(), ContractError> {
        let digest = crate::hash::sha256_text(token);
        let scopes_json = serde_json::to_string(scopes).unwrap_or_default();
        let authority_json = serde_json::to_string(authority_scopes).unwrap_or_default();
        self.connection
            .execute(
                "INSERT INTO tokens(token_digest, role, scopes, authority_scopes, principal_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(token_digest) DO UPDATE SET role=excluded.role, scopes=excluded.scopes,
                    authority_scopes=excluded.authority_scopes, principal_id=excluded.principal_id, retired_at=NULL",
                params![digest, role, scopes_json, authority_json, principal_id, crate::time::now_rfc3339_millis()],
            )
            .map(|_| ())
            .map_err(sqlite_error("register token"))
    }

    /// Retire every live token of `role` except the digest named, so the
    /// token now in a role's file is the only one that role accepts.
    pub fn retire_other_tokens(
        &self,
        role: &str,
        keep_token: &str,
    ) -> Result<usize, ContractError> {
        let keep = crate::hash::sha256_text(keep_token);
        self.connection
            .execute(
                "UPDATE tokens SET retired_at=?3 WHERE role=?1 AND token_digest<>?2 AND retired_at IS NULL",
                params![role, keep, crate::time::now_rfc3339_millis()],
            )
            .map_err(sqlite_error("retire tokens"))
    }

    pub fn retire_tokens_with_role(&self, role: &str) -> Result<usize, ContractError> {
        self.connection
            .execute(
                "UPDATE tokens SET retired_at=?2 WHERE role=?1 AND retired_at IS NULL",
                params![role, crate::time::now_rfc3339_millis()],
            )
            .map_err(sqlite_error("retire tokens"))
    }

    pub fn token(&self, token: &str) -> Result<Option<TokenRow>, ContractError> {
        let digest = crate::hash::sha256_text(token);
        self.connection
            .query_row(
                "SELECT role, scopes, authority_scopes, principal_id, bound_client_key FROM tokens WHERE token_digest=?1 AND retired_at IS NULL",
                params![digest],
                |row| {
                    Ok(TokenRow {
                        digest: digest.clone(),
                        role: row.get(0)?,
                        scopes: serde_json::from_str(&row.get::<_, String>(1)?).unwrap_or_default(),
                        authority_scopes: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                        principal_id: row.get(3)?,
                        bound_client_key: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(sqlite_error("token"))
    }

    /// First-use binding (Validator ruling R-4): bind on first successful
    /// authentication; refuse a different key afterwards.
    pub fn bind_token_key(
        &self,
        token_digest: &str,
        client_key: &str,
    ) -> Result<bool, ContractError> {
        let existing: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT bound_client_key FROM tokens WHERE token_digest=?1",
                params![token_digest],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("token binding"))?;
        match existing {
            None => Ok(false),
            Some(Some(bound)) => Ok(crate::crypto::constant_time_equal(
                bound.as_bytes(),
                client_key.as_bytes(),
            )),
            Some(None) => {
                self.connection
                    .execute(
                        "UPDATE tokens SET bound_client_key=?2 WHERE token_digest=?1 AND bound_client_key IS NULL",
                        params![token_digest, client_key],
                    )
                    .map_err(sqlite_error("bind token"))?;
                Ok(true)
            }
        }
    }

    /// R-17: record each successful `(token, client key)` pair for audit.
    /// Several keys may use one token; read ceilings are keyed by pair.
    pub fn record_token_client_pair(
        &self,
        token_digest: &str,
        client_key: &str,
        now: &str,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO token_client_keys(token_digest, client_key, first_used_at) VALUES (?1, ?2, ?3)",
                params![token_digest, client_key, now],
            )
            .map_err(sqlite_error("token client pair"))?;
        if inserted == 1 {
            let record = json!({"kind": "token-client-pair", "token_digest": token_digest, "client_key": client_key, "first_used_at": now});
            self.connection
                .execute(
                    "INSERT INTO audit(kind, record, recorded_at) VALUES ('token-client-pair', ?1, ?2)",
                    params![crate::json::record_text(&record)?, now],
                )
                .map_err(sqlite_error("token client audit"))?;
        }
        Ok(inserted == 1)
    }

    pub fn token_client_key_count(&self, token_digest: &str) -> Result<i64, ContractError> {
        self.connection
            .query_row(
                "SELECT COUNT(*) FROM token_client_keys WHERE token_digest=?1",
                params![token_digest],
                |row| row.get(0),
            )
            .map_err(sqlite_error("token client count"))
    }

    // ----- throttles -----

    /// Failed authentications this minute for one subject: a presented
    /// token's digest, or `unauthenticated` for a request presenting none
    /// the service holds.
    pub fn auth_failures(&self, minute: i64, subject: &str) -> Result<i64, ContractError> {
        Ok(self
            .connection
            .query_row(
                "SELECT count FROM auth_failure_subjects WHERE minute=?1 AND subject=?2",
                params![minute, subject],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("auth failures"))?
            .unwrap_or(0))
    }

    pub fn record_auth_failure(&self, minute: i64, subject: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "DELETE FROM auth_failure_subjects WHERE minute < ?1",
                params![minute - 1],
            )
            .map_err(sqlite_error("prune auth failures"))?;
        self.connection
            .execute(
                "INSERT INTO auth_failure_subjects(minute, subject, count) VALUES (?1, ?2, 1)
                 ON CONFLICT(minute, subject) DO UPDATE SET count=count+1",
                params![minute, subject],
            )
            .map(|_| ())
            .map_err(sqlite_error("auth failure"))
    }

    pub fn bump_request_rate(&self, client_key: &str, minute: i64) -> Result<i64, ContractError> {
        self.connection
            .execute(
                "INSERT INTO request_rate(client_key, minute, count) VALUES (?1, ?2, 1) ON CONFLICT(client_key, minute) DO UPDATE SET count=count+1",
                params![client_key, minute],
            )
            .map_err(sqlite_error("request rate"))?;
        self.connection
            .query_row(
                "SELECT count FROM request_rate WHERE client_key=?1 AND minute=?2",
                params![client_key, minute],
                |row| row.get(0),
            )
            .map_err(sqlite_error("request rate read"))
    }

    pub fn add_read_volume(
        &self,
        principal_key: &str,
        hour: i64,
        count: i64,
        bytes: i64,
    ) -> Result<(i64, i64), ContractError> {
        self.connection
            .execute(
                "INSERT INTO read_volume(principal_key, hour, count, bytes) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(principal_key, hour) DO UPDATE SET count=count+excluded.count, bytes=bytes+excluded.bytes",
                params![principal_key, hour, count, bytes],
            )
            .map_err(sqlite_error("read volume"))?;
        self.connection
            .query_row(
                "SELECT count, bytes FROM read_volume WHERE principal_key=?1 AND hour=?2",
                params![principal_key, hour],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error("read volume read"))
    }

    pub fn consume_request_nonce(
        &self,
        client_key: &str,
        nonce: &str,
        expires_at: &str,
        now: &str,
    ) -> Result<bool, ContractError> {
        self.connection
            .execute(
                "DELETE FROM request_nonces WHERE expires_at <= ?1",
                params![now],
            )
            .map_err(sqlite_error("prune request nonces"))?;
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO request_nonces(client_key, nonce, expires_at) VALUES (?1, ?2, ?3)",
                params![client_key, nonce, expires_at],
            )
            .map_err(sqlite_error("request nonce"))?;
        Ok(inserted == 1)
    }

    // ----- registry / directory -----

    pub fn upsert_registry_entry(&self, entry: &Value, cursor: i64) -> Result<(), ContractError> {
        let capabilities = entry
            .get("capabilities")
            .map(|value| serde_json::to_string(value).unwrap_or_default())
            .unwrap_or_else(|| "[]".to_owned());
        self.connection
            .execute(
                "INSERT INTO registry(authority_id, scope, public_key, channel, capabilities, status, cursor, document)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(authority_id, scope) DO UPDATE SET public_key=excluded.public_key, channel=excluded.channel,
                    capabilities=excluded.capabilities, status=excluded.status, cursor=excluded.cursor, document=excluded.document",
                params![
                    crate::json::get_str(entry, "authority_id").unwrap_or_default(),
                    crate::json::get_str(entry, "scope").unwrap_or_default(),
                    crate::json::get_str(entry, "public_key").unwrap_or_default(),
                    crate::json::get_str(entry, "channel").unwrap_or("inbox"),
                    capabilities,
                    crate::json::get_str(entry, "status").unwrap_or("active"),
                    cursor,
                    crate::json::record_text(entry)?
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("registry upsert"))
    }

    /// R-10: an entry absent from a republished registry is revoked at the
    /// cursor of that publication; a later publication that lists it again
    /// re-activates it through the ordinary upsert.
    pub fn mark_registry_entry_revoked(
        &self,
        authority_id: &str,
        scope: &str,
        cursor: i64,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE registry SET status='revoked', cursor=?3 WHERE authority_id=?1 AND scope=?2",
                params![authority_id, scope, cursor],
            )
            .map(|_| ())
            .map_err(sqlite_error("registry revoke"))
    }

    pub fn registry_entries(&self) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT authority_id, scope, public_key, channel, capabilities, status, cursor FROM registry ORDER BY authority_id, scope")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok(json!({
                    "authority_id": row.get::<_, String>(0)?,
                    "scope": row.get::<_, String>(1)?,
                    "public_key": row.get::<_, String>(2)?,
                    "channel": row.get::<_, String>(3)?,
                    "capabilities": serde_json::from_str::<Value>(&row.get::<_, String>(4)?).unwrap_or(Value::Array(Vec::new())),
                    "status": row.get::<_, String>(5)?,
                    "cursor": row.get::<_, i64>(6)?.to_string()
                }))
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn upsert_directory(
        &self,
        authority_id: &str,
        display_name: &str,
        contact: &str,
        retention_until: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO directory(authority_id, display_name, contact, retention_until, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(authority_id) DO UPDATE SET display_name=excluded.display_name, contact=excluded.contact,
                    retention_until=excluded.retention_until, updated_at=excluded.updated_at",
                params![authority_id, display_name, contact, retention_until, crate::time::now_rfc3339_millis()],
            )
            .map(|_| ())
            .map_err(sqlite_error("directory"))
    }

    pub fn directory(&self, authority_id: &str, now: &str) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT display_name, contact, retention_until FROM directory WHERE authority_id=?1 AND retention_until > ?2",
                params![authority_id, now],
                |row| {
                    Ok(json!({
                        "authority_id": authority_id,
                        "display_name": row.get::<_, String>(0)?,
                        "contact": row.get::<_, String>(1)?,
                        "retention_until": row.get::<_, String>(2)?
                    }))
                },
            )
            .optional()
            .map_err(sqlite_error("directory read"))
    }

    // ----- questions / answers / unknowns -----

    pub fn insert_question(
        &self,
        document: &Value,
        asked_by: &str,
        delivery: &Value,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO questions(question_id, unknown_id, authority_id, scope, question_kind, document, status, created_at, response_due_at, asked_by, delivery)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'queued', ?7, ?8, ?9, ?10)",
                params![
                    crate::json::get_str(document, "question_id").unwrap_or_default(),
                    crate::json::get_str(document, "unknown_id"),
                    crate::json::get_str(document, "authority_id").unwrap_or_default(),
                    crate::json::get_str(document, "authority_scope").unwrap_or_default(),
                    crate::json::get_str(document, "question_kind").unwrap_or("general"),
                    crate::json::record_text(document)?,
                    crate::json::get_str(document, "created_at").unwrap_or_default(),
                    crate::json::get_str(document, "response_due_at").unwrap_or_default(),
                    asked_by,
                    crate::json::record_text(delivery)?
                ],
            )
            .map_err(sqlite_error("insert question"))?;
        Ok(inserted == 1)
    }

    pub fn question(&self, question_id: &str) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT document, status, delivery FROM questions WHERE question_id=?1",
                params![question_id],
                |row| {
                    let mut document: Value =
                        serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                    document["status"] = Value::String(row.get::<_, String>(1)?);
                    document["delivery"] =
                        serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or(Value::Null);
                    Ok(document)
                },
            )
            .optional()
            .map_err(sqlite_error("question"))
    }

    pub fn questions(&self, authority_id: Option<&str>) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT document, status, delivery FROM questions WHERE (?1 IS NULL OR authority_id=?1) ORDER BY created_at, question_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![authority_id], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["status"] = Value::String(row.get::<_, String>(1)?);
                document["delivery"] =
                    serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or(Value::Null);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn set_question_status(
        &self,
        question_id: &str,
        status: &str,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE questions SET status=?2 WHERE question_id=?1",
                params![question_id, status],
            )
            .map(|_| ())
            .map_err(sqlite_error("question status"))
    }

    pub fn insert_answer(
        &self,
        document: &Value,
        cursor: i64,
        supersedes: Option<&str>,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO answers(answer_id, question_id, authority_id, scope, document, cursor, answered_at, supersedes)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    crate::json::get_str(document, "answer_id").unwrap_or_default(),
                    crate::json::get_str(document, "question_id").unwrap_or_default(),
                    crate::json::get_str(document, "authority_id").unwrap_or_default(),
                    crate::json::get_str(document, "authority_scope").unwrap_or_default(),
                    crate::json::record_text(document)?,
                    cursor,
                    crate::json::get_str(document, "answered_at").unwrap_or_default(),
                    supersedes
                ],
            )
            .map_err(sqlite_error("insert answer"))?;
        Ok(inserted == 1)
    }

    pub fn answers_for_question(&self, question_id: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT document, cursor, supersedes FROM answers WHERE question_id=?1 ORDER BY cursor")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![question_id], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["cursor"] = Value::String(row.get::<_, i64>(1)?.to_string());
                document["supersedes"] = row
                    .get::<_, Option<String>>(2)?
                    .map(Value::String)
                    .unwrap_or(Value::Null);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn upsert_unknown(&self, document: &Value, kind: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO unknowns(unknown_id, document, status, owner_identity, scope, response_due_at, updated_at, kind)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(unknown_id) DO UPDATE SET document=excluded.document, status=excluded.status,
                    owner_identity=excluded.owner_identity, response_due_at=excluded.response_due_at, updated_at=excluded.updated_at",
                params![
                    crate::json::get_str(document, "fact_id").or(crate::json::get_str(document, "unknown_id")).unwrap_or_default(),
                    crate::json::record_text(document)?,
                    crate::json::get_str(document, "status").unwrap_or("open"),
                    crate::json::get_str(document, "owner_identity").unwrap_or_default(),
                    crate::json::get_str(document, "scope").unwrap_or_default(),
                    crate::json::get_str(document, "response_due_at").unwrap_or_default(),
                    crate::time::now_rfc3339_millis(),
                    kind
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("upsert unknown"))
    }

    pub fn unknowns(&self, status: Option<&str>) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT document, status, kind FROM unknowns WHERE (?1 IS NULL OR status=?1) ORDER BY updated_at, unknown_id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![status], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["status"] = Value::String(row.get::<_, String>(1)?);
                document["kind"] = Value::String(row.get::<_, String>(2)?);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn unknown(&self, unknown_id: &str) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT document, status FROM unknowns WHERE unknown_id=?1",
                params![unknown_id],
                |row| {
                    let mut document: Value =
                        serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                    document["status"] = Value::String(row.get::<_, String>(1)?);
                    Ok(document)
                },
            )
            .optional()
            .map_err(sqlite_error("unknown"))
    }

    // ----- nonces (destination-owned retry records) -----

    pub fn nonce_record(
        &self,
        destination: &str,
        nonce: &str,
    ) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT payload_digest, client_key, authority_scope, receipt, consumed_at, expires_at FROM nonces WHERE destination=?1 AND nonce=?2",
                params![destination, nonce],
                |row| {
                    Ok(json!({
                        "payload_digest": row.get::<_, String>(0)?,
                        "client_key": row.get::<_, String>(1)?,
                        "authority_scope": row.get::<_, String>(2)?,
                        "receipt": serde_json::from_str::<Value>(&row.get::<_, String>(3)?).unwrap_or(Value::Null),
                        "consumed_at": row.get::<_, String>(4)?,
                        "expires_at": row.get::<_, String>(5)?
                    }))
                },
            )
            .optional()
            .map_err(sqlite_error("nonce"))
    }

    pub fn prune_nonces(&self, now: &str) -> Result<usize, ContractError> {
        self.connection
            .execute("DELETE FROM nonces WHERE expires_at <= ?1", params![now])
            .map_err(sqlite_error("prune nonces"))
    }

    // ----- certificates -----

    pub fn upsert_certificate(
        &self,
        document: &Value,
        hint: Option<&str>,
        cursor: i64,
    ) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO certificates(repository_uuid, document, hint, digest, issued_at, status, lineage_parent, cursor)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6, ?7)
                 ON CONFLICT(repository_uuid) DO UPDATE SET document=excluded.document, hint=COALESCE(excluded.hint, certificates.hint),
                    digest=excluded.digest, issued_at=excluded.issued_at, status='active', lineage_parent=excluded.lineage_parent, cursor=excluded.cursor",
                params![
                    crate::json::get_str(document, "repository_uuid").unwrap_or_default(),
                    crate::json::record_text(document)?,
                    hint,
                    crate::json::digest(document),
                    crate::json::get_str(document, "issued_at").unwrap_or_default(),
                    crate::json::get_str(document, "lineage_parent_uuid"),
                    cursor
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("certificate"))
    }

    pub fn certificate(&self, repository_uuid: &str) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT document, hint, digest, status FROM certificates WHERE repository_uuid=?1",
                params![repository_uuid],
                |row| {
                    let mut document: Value =
                        serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                    document["discovery_hint"] = row
                        .get::<_, Option<String>>(1)?
                        .map(Value::String)
                        .unwrap_or(Value::Null);
                    document["certificate_digest"] = Value::String(row.get::<_, String>(2)?);
                    document["status"] = Value::String(row.get::<_, String>(3)?);
                    Ok(document)
                },
            )
            .optional()
            .map_err(sqlite_error("certificate read"))
    }

    pub fn certificates_for_hint(&self, hint: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT document, digest FROM certificates WHERE hint=?1 AND status='active' ORDER BY cursor DESC")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![hint], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["certificate_digest"] = Value::String(row.get::<_, String>(1)?);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn all_certificates(&self) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT document, hint, digest, status FROM certificates ORDER BY repository_uuid",
            )
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["discovery_hint"] = row
                    .get::<_, Option<String>>(1)?
                    .map(Value::String)
                    .unwrap_or(Value::Null);
                document["certificate_digest"] = Value::String(row.get::<_, String>(2)?);
                document["status"] = Value::String(row.get::<_, String>(3)?);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    // ----- manifest observations -----

    pub fn latest_manifest_observation(
        &self,
        repository_uuid: &str,
        branch: &str,
    ) -> Result<Option<Value>, ContractError> {
        self.connection
            .query_row(
                "SELECT document, status, event_count, event_digests, fresh_until, id FROM manifest_observations
                 WHERE repository_uuid=?1 AND branch=?2 ORDER BY id DESC LIMIT 1",
                params![repository_uuid, branch],
                |row| {
                    let mut document: Value = serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                    document["status"] = Value::String(row.get::<_, String>(1)?);
                    document["event_count"] = Value::from(row.get::<_, i64>(2)?);
                    document["event_digests"] = serde_json::from_str(&row.get::<_, String>(3)?).unwrap_or(Value::Array(Vec::new()));
                    document["fresh_until"] = Value::String(row.get::<_, String>(4)?);
                    document["observation_id"] = Value::from(row.get::<_, i64>(5)?);
                    Ok(document)
                },
            )
            .optional()
            .map_err(sqlite_error("manifest observation"))
    }

    pub fn insert_manifest_observation(
        &self,
        document: &Value,
        cursor: i64,
    ) -> Result<i64, ContractError> {
        self.connection
            .execute(
                "INSERT INTO manifest_observations(repository_uuid, branch, revision, event_count, merkle_root, event_digests, observed_at, fresh_until, document, status, cursor)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'current', ?10)",
                params![
                    crate::json::get_str(document, "repository_uuid").unwrap_or_default(),
                    crate::json::get_str(document, "branch").unwrap_or_default(),
                    crate::json::get_str(document, "observed_default_branch_revision").unwrap_or_default(),
                    crate::json::get_u64(document, "event_count").unwrap_or(0) as i64,
                    crate::json::get_str(document, "merkle_root").unwrap_or_default(),
                    serde_json::to_string(document.get("event_digests").unwrap_or(&Value::Array(Vec::new()))).unwrap_or_default(),
                    crate::json::get_str(document, "observed_at").unwrap_or_default(),
                    crate::json::get_str(document, "fresh_until").unwrap_or_default(),
                    crate::json::record_text(document)?,
                    cursor
                ],
            )
            .map_err(|error| {
                if matches!(
                    &error,
                    rusqlite::Error::SqliteFailure(code, _) if code.code == rusqlite::ErrorCode::ConstraintViolation
                ) {
                    return ContractError::integrity(
                        "DIGEST_MISMATCH",
                        "manifest lineage head is already observed for this repository and branch",
                        "Return the existing observation; a lineage head cannot be admitted twice.",
                    );
                }
                sqlite_error("manifest observation insert")(error)
            })?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn expire_manifest_observations(&self, now: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT id, repository_uuid, branch, fresh_until FROM manifest_observations WHERE status='current' AND fresh_until <= ?1")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![now], |row| {
                Ok(json!({"observation_id": row.get::<_, i64>(0)?, "repository_uuid": row.get::<_, String>(1)?, "branch": row.get::<_, String>(2)?, "fresh_until": row.get::<_, String>(3)?}))
            })
            .map_err(sqlite_error("query"))?;
        let expired: Vec<Value> = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))?;
        for item in &expired {
            self.connection
                .execute(
                    "UPDATE manifest_observations SET status='historical' WHERE id=?1",
                    params![
                        item.get("observation_id")
                            .and_then(Value::as_i64)
                            .unwrap_or(0)
                    ],
                )
                .map_err(sqlite_error("retire observation"))?;
        }
        Ok(expired)
    }

    // ----- fact versions -----

    pub fn record_fact_version(
        &self,
        fact_id: &str,
        semantic_digest: &str,
        event_id: &str,
        cursor: i64,
    ) -> Result<i64, ContractError> {
        let next: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM fact_versions WHERE fact_id=?1",
                params![fact_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error("version"))?;
        self.connection
            .execute(
                "INSERT INTO fact_versions(fact_id, version, semantic_digest, digest_alg_version, event_id, cursor) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![fact_id, next, semantic_digest, crate::model::DIGEST_ALG_VERSION, event_id, cursor],
            )
            .map_err(sqlite_error("fact version"))?;
        Ok(next)
    }

    /// Row count, newest cursor and retained count of the fact-version index.
    /// Rows are written after their event is appended, so the event cursor
    /// alone does not say whether a version row has landed; `retained` is
    /// published in snapshots, so a change to it must change the mark too.
    pub fn fact_versions_mark(&self) -> Result<(i64, i64, i64), ContractError> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(cursor), 0), COALESCE(SUM(retained), 0) FROM fact_versions",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(sqlite_error("fact versions mark"))
    }

    /// Row count and newest id of one kind of audit record. Audit rows are
    /// insert-only and append no event.
    pub fn audit_mark(&self, kind: &str) -> Result<(i64, i64), ContractError> {
        self.connection
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(id), 0) FROM audit WHERE kind=?1",
                params![kind],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error("audit mark"))
    }

    pub fn fact_versions(&self, fact_id: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT version, semantic_digest, digest_alg_version, event_id, cursor, retained FROM fact_versions WHERE fact_id=?1 ORDER BY version")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![fact_id], |row| {
                Ok(json!({
                    "version": row.get::<_, i64>(0)?.to_string(),
                    "semantic_content_digest": row.get::<_, String>(1)?,
                    "digest_alg_version": row.get::<_, String>(2)?,
                    "event_id": row.get::<_, String>(3)?,
                    "cursor": row.get::<_, i64>(4)?.to_string(),
                    "retained": row.get::<_, i64>(5)? == 1
                }))
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    // ----- steward queue, relaxations, audit, metrics -----

    pub fn queue_for_steward(
        &self,
        event_id: &str,
        document: &Value,
        approval: &Value,
        submitted_by: &str,
    ) -> Result<bool, ContractError> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO steward_queue(event_id, document, approval, status, queued_at, submitted_by) VALUES (?1, ?2, ?3, 'pending-steward-review', ?4, ?5)",
                params![event_id, crate::json::record_text(document)?, crate::json::record_text(approval)?, crate::time::now_rfc3339_millis(), submitted_by],
            )
            .map_err(sqlite_error("steward queue"))?;
        Ok(inserted == 1)
    }

    pub fn resolve_steward_queue(&self, event_id: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "UPDATE steward_queue SET status='admitted' WHERE event_id=?1 AND status='pending-steward-review'",
                params![event_id],
            )
            .map(|_| ())
            .map_err(sqlite_error("steward queue resolution"))
    }

    pub fn steward_queue(&self) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT event_id, status, queued_at, submitted_by FROM steward_queue ORDER BY queued_at")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok(json!({"event_id": row.get::<_, String>(0)?, "status": row.get::<_, String>(1)?, "queued_at": row.get::<_, String>(2)?, "submitted_by": row.get::<_, String>(3)?}))
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn insert_relaxation(&self, document: &Value, cursor: i64) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO relaxations(relaxation_id, repository_uuid, fact_id, fact_version, requested_class, expires_at, document, cursor, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')",
                params![
                    crate::json::get_str(document, "event_id").unwrap_or_default(),
                    crate::json::get_str(document, "repository_id").unwrap_or_default(),
                    crate::json::get_str(document, "relaxed_fact_id").unwrap_or_default(),
                    crate::json::get_str(document, "relaxed_fact_version").unwrap_or("current"),
                    crate::json::get_str(document, "relaxed_class").unwrap_or("advisory"),
                    crate::json::get_str(document, "effective_until").unwrap_or_default(),
                    crate::json::record_text(document)?,
                    cursor
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("relaxation"))
    }

    pub fn relaxations(&self) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT document, expires_at, status FROM relaxations ORDER BY cursor")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                let mut document: Value =
                    serde_json::from_str(&row.get::<_, String>(0)?).unwrap_or(Value::Null);
                document["expires_at"] = Value::String(row.get::<_, String>(1)?);
                document["status"] = Value::String(row.get::<_, String>(2)?);
                Ok(document)
            })
            .map_err(sqlite_error("query"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("rows"))
    }

    pub fn audit(&self, kind: &str, record: &Value) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO audit(kind, record, recorded_at) VALUES (?1, ?2, ?3)",
                params![
                    kind,
                    crate::json::record_text(record)?,
                    crate::time::now_rfc3339_millis()
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("audit"))
    }

    /// Audit records of one kind, oldest first.
    pub fn audit_records(&self, kind: &str) -> Result<Vec<Value>, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM audit WHERE kind=?1 ORDER BY id")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map(params![kind], |row| row.get::<_, String>(0))
            .map_err(sqlite_error("query"))?;
        let mut output = Vec::new();
        for row in rows {
            let text = row.map_err(sqlite_error("row"))?;
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                output.push(value);
            }
        }
        Ok(output)
    }

    pub fn bump(&self, name: &str) -> Result<(), ContractError> {
        self.connection
            .execute(
                "INSERT INTO metrics(name, count) VALUES (?1, 1) ON CONFLICT(name) DO UPDATE SET count=count+1",
                params![name],
            )
            .map(|_| ())
            .map_err(sqlite_error("metric"))
    }

    pub fn metrics(&self) -> Result<Value, ContractError> {
        let mut statement = self
            .connection
            .prepare("SELECT name, count FROM metrics ORDER BY name")
            .map_err(sqlite_error("prepare"))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(sqlite_error("query"))?;
        let mut map = serde_json::Map::new();
        for row in rows {
            let (name, count) = row.map_err(sqlite_error("row"))?;
            map.insert(name, Value::from(count));
        }
        Ok(Value::Object(map))
    }

    // ----- usage -----

    /// Append one usage row (`crate::usage`). Every string is refused unless
    /// it meets the canonical text rule; a writer never stores a folded or
    /// empty stand-in.
    ///
    /// The row commits with `synchronous=NORMAL`: in WAL mode that is a page
    /// write rather than a disk flush, and a request already pays three FULL
    /// commits for its nonce, client pair and rate counter. A usage row lost
    /// to a power cut costs a count, never an authority or a receipt, so it
    /// does not get to double the request's flush cost.
    pub fn append_usage(&self, event: &crate::usage::UsageEvent) -> Result<(), ContractError> {
        for (field, value) in [
            ("recorded_at", event.recorded_at.as_str()),
            ("principal_id", event.principal_id.as_str()),
            ("client", event.client.as_str()),
            ("token_role", event.token_role.as_str()),
            ("action", event.action),
            ("target", event.target),
            (
                "error_code",
                event.error_code.as_deref().unwrap_or_default(),
            ),
        ] {
            crate::json::validate_text(value).map_err(|reason| {
                ContractError::invariant(format!("usage {field} breaks the text rule ({reason})"))
            })?;
        }
        self.connection
            .execute_batch("PRAGMA synchronous=NORMAL")
            .map_err(sqlite_error("usage synchronous"))?;
        let inserted = self
            .connection
            .execute(
                "INSERT INTO usage_events(recorded_at, principal_id, client, token_role, action, target, status, error_code, duration_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    event.recorded_at,
                    event.principal_id,
                    event.client,
                    event.token_role,
                    event.action,
                    event.target,
                    event.status,
                    event.error_code,
                    i64::try_from(event.duration_ms).unwrap_or(i64::MAX)
                ],
            )
            .map(|_| ())
            .map_err(sqlite_error("usage"));
        // The connection may serve another write; it goes back to FULL even
        // when the insert failed. A failed restore is reported on its own:
        // folded into the result it turned a row that was stored into a
        // `usage-record-failed` report.
        if let Err(error) = self
            .connection
            .execute_batch("PRAGMA synchronous=FULL")
            .map_err(sqlite_error("usage synchronous"))
        {
            crate::output::diagnostic(
                "usage-synchronous-restore-failed",
                json!({"code": error.code}),
            );
        }
        inserted
    }

    /// Deletes up to a thousand usage rows recorded before `before`, oldest
    /// first, once the oldest was recorded before `due`. The check is one
    /// index read, so a store with nothing due takes no write lock, and the
    /// batch bounds how long a backlog holds it.
    pub fn prune_usage(&self, before: &str, due: &str) -> Result<usize, ContractError> {
        let oldest: Option<String> = self
            .connection
            .query_row("SELECT MIN(recorded_at) FROM usage_events", [], |row| {
                row.get(0)
            })
            .map_err(sqlite_error("usage prune"))?;
        if oldest.is_none_or(|oldest| oldest.as_str() >= due) {
            return Ok(0);
        }
        self.connection
            .execute(
                "DELETE FROM usage_events WHERE id IN (
                    SELECT id FROM usage_events WHERE recorded_at < ?1 ORDER BY recorded_at LIMIT 1000)",
                params![before],
            )
            .map_err(sqlite_error("usage prune"))
    }

    /// Aggregates over the usage rows inside `window`, one query per
    /// breakdown so the counting happens in SQLite rather than in memory.
    ///
    /// The queries share one read transaction. The service keeps appending
    /// while a report runs, and without a shared WAL snapshot a row committed
    /// between the totals and a breakdown showed up in one and not the other.
    pub fn usage_summary(
        &self,
        window: &crate::usage::Window,
        bucket: crate::usage::Bucket,
    ) -> Result<crate::usage::Summary, ContractError> {
        self.connection
            .execute_batch("BEGIN")
            .map_err(sqlite_error("usage snapshot"))?;
        let summary = self.usage_summary_in_snapshot(window, bucket);
        // Nothing was written, so ending the snapshot either way is the same.
        let ended = self
            .connection
            .execute_batch(if summary.is_ok() {
                "COMMIT"
            } else {
                "ROLLBACK"
            })
            .map_err(sqlite_error("usage snapshot"));
        let summary = summary?;
        ended?;
        Ok(summary)
    }

    fn usage_summary_in_snapshot(
        &self,
        window: &crate::usage::Window,
        bucket: crate::usage::Bucket,
    ) -> Result<crate::usage::Summary, ContractError> {
        // Only the bounds the window has go into the query: `?1 IS NULL OR
        // recorded_at >= ?1` kept SQLite off the recorded_at index, so even a
        // narrow window scanned all history once per breakdown.
        let mut bounds = Vec::new();
        let mut values = Vec::new();
        for (operator, value) in [(">=", &window.since), ("<", &window.until)] {
            if let Some(value) = value {
                values.push(value.as_str());
                bounds.push(format!("recorded_at {operator} ?{}", values.len()));
            }
        }
        let from = if bounds.is_empty() {
            "FROM usage_events".to_owned()
        } else {
            format!("FROM usage_events WHERE {}", bounds.join(" AND "))
        };
        let bound = || rusqlite::params_from_iter(values.iter());
        let totals = self
            .connection
            .query_row(
                &format!(
                    "SELECT {USAGE_OUTCOMES}, COUNT(DISTINCT principal_id), COUNT(DISTINCT client),
                            MIN(recorded_at), MAX(recorded_at)
                     {from}"
                ),
                bound(),
                |row| {
                    let (requests, succeeded, refused, failed) = usage_outcomes(row, 0)?;
                    Ok(json!({
                        "requests": requests,
                        "succeeded": succeeded,
                        "refused": refused,
                        "failed": failed,
                        "principals": row.get::<_, i64>(3)?,
                        "clients": row.get::<_, i64>(4)?,
                        "first_at": row.get::<_, Option<String>>(5)?,
                        "last_at": row.get::<_, Option<String>>(6)?
                    }))
                },
            )
            .map_err(sqlite_error("usage totals"))?;

        let mut actions_by_principal: BTreeMap<String, serde_json::Map<String, Value>> =
            BTreeMap::new();
        for (principal, action, count) in self.usage_rows(
            &format!(
                "SELECT principal_id, action, COUNT(*) {from}
                 GROUP BY principal_id, action"
            ),
            bound(),
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )? {
            actions_by_principal
                .entry(principal)
                .or_default()
                .insert(action, Value::from(count));
        }
        let by_principal = self
            .usage_rows(
                &format!(
                    "SELECT principal_id, {USAGE_OUTCOMES}, COUNT(DISTINCT client),
                        MIN(recorded_at), MAX(recorded_at)
                 {from}
                 GROUP BY principal_id ORDER BY COUNT(*) DESC, principal_id"
                ),
                bound(),
                |row| {
                    let (requests, succeeded, refused, failed) = usage_outcomes(row, 1)?;
                    Ok(json!({
                        "principal_id": row.get::<_, String>(0)?,
                        "requests": requests,
                        "succeeded": succeeded,
                        "refused": refused,
                        "failed": failed,
                        "clients": row.get::<_, i64>(4)?,
                        "first_at": row.get::<_, String>(5)?,
                        "last_at": row.get::<_, String>(6)?
                    }))
                },
            )?
            .into_iter()
            .map(|mut row| {
                let principal = row["principal_id"].as_str().unwrap_or_default().to_owned();
                row["actions"] =
                    Value::Object(actions_by_principal.remove(&principal).unwrap_or_default());
                row
            })
            .collect();
        let by_client = self.usage_rows(
            &format!(
                "SELECT principal_id, client, token_role, COUNT(*), MAX(recorded_at)
                 {from}
                 GROUP BY principal_id, client, token_role ORDER BY COUNT(*) DESC, principal_id, client"
            ),
            bound(),
            |row| {
                Ok(json!({
                    "principal_id": row.get::<_, String>(0)?,
                    "client": row.get::<_, String>(1)?,
                    "token_role": row.get::<_, String>(2)?,
                    "requests": row.get::<_, i64>(3)?,
                    "last_at": row.get::<_, String>(4)?
                }))
            },
        )?;
        // Rounded, not truncated: integer division showed most fast actions
        // as 0 ms.
        let by_action = self.usage_rows(
            &format!(
                "SELECT action, {USAGE_OUTCOMES}, COUNT(DISTINCT principal_id),
                        CAST(ROUND(AVG(duration_ms)) AS INTEGER)
                 {from}
                 GROUP BY action ORDER BY COUNT(*) DESC, action"
            ),
            bound(),
            |row| {
                let (requests, succeeded, refused, failed) = usage_outcomes(row, 1)?;
                Ok(json!({
                    "action": row.get::<_, String>(0)?,
                    "requests": requests,
                    "succeeded": succeeded,
                    "refused": refused,
                    "failed": failed,
                    "principals": row.get::<_, i64>(4)?,
                    "mean_duration_ms": row.get::<_, i64>(5)?
                }))
            },
        )?;
        // The prefix length comes from the closed `Bucket`, never the caller.
        let by_window = self.usage_rows(
            &format!(
                "SELECT substr(recorded_at, 1, {}) AS bucket, {USAGE_OUTCOMES},
                        COUNT(DISTINCT principal_id)
                 {from}
                 GROUP BY bucket ORDER BY bucket",
                bucket.prefix_len()
            ),
            bound(),
            |row| {
                let (requests, succeeded, refused, failed) = usage_outcomes(row, 1)?;
                Ok(json!({
                    "window": row.get::<_, String>(0)?,
                    "requests": requests,
                    "succeeded": succeeded,
                    "refused": refused,
                    "failed": failed,
                    "principals": row.get::<_, i64>(4)?
                }))
            },
        )?;
        Ok(crate::usage::Summary {
            totals,
            by_principal,
            by_client,
            by_action,
            by_window,
        })
    }

    fn usage_rows<T>(
        &self,
        sql: &str,
        parameters: impl rusqlite::Params,
        map: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    ) -> Result<Vec<T>, ContractError> {
        let mut statement = self
            .connection
            .prepare(sql)
            .map_err(sqlite_error("prepare usage"))?;
        let rows = statement
            .query_map(parameters, map)
            .map_err(sqlite_error("query usage"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error("usage rows"))
    }

    pub fn authority_call_count(
        &self,
        task_id: &str,
        arm: &str,
        seed: &str,
    ) -> Result<i64, ContractError> {
        Ok(self
            .connection
            .query_row(
                "SELECT count FROM authority_calls WHERE task_id=?1 AND arm=?2 AND seed=?3",
                params![task_id, arm, seed],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error("authority calls"))?
            .unwrap_or(0))
    }

    pub fn bump_authority_call(
        &self,
        task_id: &str,
        arm: &str,
        seed: &str,
    ) -> Result<i64, ContractError> {
        self.connection
            .execute(
                "INSERT INTO authority_calls(task_id, arm, seed, count) VALUES (?1, ?2, ?3, 1) ON CONFLICT(task_id, arm, seed) DO UPDATE SET count=count+1",
                params![task_id, arm, seed],
            )
            .map_err(sqlite_error("authority call"))?;
        self.authority_call_count(task_id, arm, seed)
    }
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub digest: String,
    pub role: String,
    pub scopes: Vec<String>,
    pub authority_scopes: Vec<String>,
    pub principal_id: String,
    pub bound_client_key: Option<String>,
}

impl TokenRow {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|granted| granted == scope)
    }
    /// Exact canonical byte equality; missing or empty sets grant nothing.
    pub fn authority_scope_allows(&self, scope: &str) -> bool {
        self.authority_scopes.iter().any(|granted| granted == scope)
    }
}

#[cfg(test)]
mod open_vs_connect {
    use super::*;

    /// `open` is the startup path and has to create the directory it is handed.
    /// An earlier revision of the split connected before creating it, which
    /// fails on a first install and on nothing else.
    #[test]
    fn open_creates_a_directory_that_does_not_exist_yet() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("nested").join("deeper").join("company.sqlite3");
        assert!(!path.parent().unwrap().exists());
        CompanyDb::open(&path).expect("open must create the directory it is given");
        assert!(path.exists(), "no database was created");
    }

    /// `connect` is the request path: it must not migrate, so it cannot write.
    #[test]
    fn connect_does_not_create_a_schema() {
        let temp = tempfile::TempDir::new().unwrap();
        let path = temp.path().join("company.sqlite3");
        let db = CompanyDb::connect(&path).expect("connect opens a fresh file");
        let tables: i64 = db
            .connection
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "connect migrated the schema; it must not write");
    }
}
