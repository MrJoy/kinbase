//! A persisted identity index over the Personal ledgers that hold entities.
//!
//! The ledger is the authority; this index is a projection of it that any
//! process can rebuild. It answers two questions without reading the ledger:
//! whether a record with this identity is already there, and where the
//! records with a given tag (a session, a source) are. A hook is a fresh
//! process, so the in-memory line index in `store` reads the whole ledger on
//! every append: the observe worker spent 83% of a prompt's 0.71 s hashing
//! 276 MB of `observations.jsonl`, and every Stop streamed the same file to
//! find one session's lines.
//!
//! A record's identity is the value of its key fields only. Timestamps,
//! nonces and classifier output are not identity: a record that differs from
//! one already there only in them is the same record seen again, and appending
//! it is a no-op (the first copy stands).
//!
//! The index follows the ledger, never the reverse. It records how far into
//! the ledger it has read (with the device, inode and last bytes, so a
//! rewrite is told from an append) and reads only what was appended since. A
//! line written by a process that died before indexing it is picked up by
//! the next reader; a rewritten ledger, or an index of another version, is
//! rebuilt from the start. Deleting the index file loses nothing.
//!
//! The index narrows; the ledger decides. Nothing acts on an answer from the
//! index until the ledger confirms it: a duplicate is suppressed only after
//! the line the index points at is read back and carries the same identity,
//! and a tagged read keeps only lines that sit whole at their offsets and
//! carry the tag. An answer the ledger does not confirm (a rewrite the cursor
//! could not tell from an append, a cursor that outlived a crash the ledger's
//! tail did not) rebuilds the index, says so, and asks again.

use crate::error::ContractError;
use crate::hash::sha256_raw;
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};
use serde_json::{Map, Value};
use std::fs;
use std::io::{BufRead as _, Seek as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::Path;

const INDEX_FILE: &str = ".ledger-index.sqlite3";
/// Bumped whenever a spec or the key derivation changes: an index written
/// under another version is rebuilt rather than trusted.
const INDEX_VERSION: i64 = 2;
const TAIL_BYTES: u64 = 64;

/// What identifies a ledger's records and what readers look them up by.
pub struct Spec {
    /// The fields whose values, together, are the record's identity.
    key: &'static [&'static str],
    /// The fields a reader selects records by.
    tags: &'static [&'static str],
}

const SPECS: &[(&str, Spec)] = &[
    (
        "observations.jsonl",
        Spec {
            key: &["observation_id"],
            tags: &["source_identity"],
        },
    ),
    (
        "session-events.jsonl",
        Spec {
            key: &["session_id", "event_id"],
            tags: &["session_id"],
        },
    ),
    (
        "atoms.jsonl",
        Spec {
            key: &["atom_id"],
            tags: &["observation_id"],
        },
    ),
    (
        "candidates.jsonl",
        Spec {
            key: &["candidate_id"],
            tags: &["session_id"],
        },
    ),
];

/// The spec of an indexed ledger, by file name.
pub fn spec_for(path: &Path) -> Option<&'static Spec> {
    let name = path.file_name()?.to_str()?;
    SPECS
        .iter()
        .find(|(file, _)| *file == name)
        .map(|(_, spec)| spec)
}

fn sqlite_error(context: &str) -> impl Fn(rusqlite::Error) -> ContractError + '_ {
    move |error| ContractError::internal(format!("ledger index {context}: {error}"))
}

/// The identity of `record`: its key fields' values. A record missing a key
/// field (or holding a non-string there) is identified by its whole line, the
/// only identity it has.
fn identity(spec: &Spec, record: &Map<String, Value>, line: &[u8]) -> [u8; 32] {
    let mut text = String::from("key");
    for field in spec.key {
        match record.get(*field) {
            Some(value @ Value::String(_)) => {
                text.push('\0');
                text.push_str(&crate::json::jcs_text(value));
            }
            _ => {
                let mut bytes = b"line\0".to_vec();
                bytes.extend_from_slice(line);
                return sha256_raw(&bytes);
            }
        }
    }
    sha256_raw(text.as_bytes())
}

fn tag(field: &str, value: &str) -> [u8; 32] {
    sha256_raw(format!("{field}\0{value}").as_bytes())
}

fn read_tail(file: &fs::File, length: u64) -> Vec<u8> {
    let start = length.saturating_sub(TAIL_BYTES);
    let mut tail = vec![0u8; (length - start) as usize];
    if file.read_exact_at(&mut tail, start).is_err() {
        tail.clear();
    }
    tail
}

fn open(ledger: &Path) -> Result<rusqlite::Connection, ContractError> {
    let path = ledger
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(INDEX_FILE);
    let connection = rusqlite::Connection::open(&path).map_err(sqlite_error("open"))?;
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(sqlite_error("busy timeout"))?;
    // A projection: losing the last commits to a crash costs a re-read of the
    // ledger's tail, never a record, so it is not synced on every commit.
    let schema: i64 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sqlite_error("schema version"))?;
    if schema != INDEX_VERSION {
        connection
            .execute_batch(&format!(
                "DROP TABLE IF EXISTS cursor; DROP TABLE IF EXISTS keys; DROP TABLE IF EXISTS tags;
                 PRAGMA user_version = {INDEX_VERSION};"
            ))
            .map_err(sqlite_error("schema reset"))?;
    }
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS cursor(
                 ledger TEXT PRIMARY KEY, version INTEGER NOT NULL, device INTEGER NOT NULL,
                 inode INTEGER NOT NULL, length INTEGER NOT NULL, tail BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS keys(
                 ledger TEXT NOT NULL, key BLOB NOT NULL, offset INTEGER NOT NULL,
                 length INTEGER NOT NULL, PRIMARY KEY(ledger, key)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS tags(
                 ledger TEXT NOT NULL, tag BLOB NOT NULL, offset INTEGER NOT NULL,
                 length INTEGER NOT NULL, PRIMARY KEY(ledger, tag, offset)) WITHOUT ROWID;",
        )
        .map_err(sqlite_error("schema"))?;
    for suffix in ["-wal", "-shm"] {
        let mut side = path.clone().into_os_string();
        side.push(suffix);
        let _ = fs::set_permissions(&side, fs::Permissions::from_mode(0o600));
    }
    Ok(connection)
}

fn ledger_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Index `record` (the line at `offset`, `length` bytes long).
fn insert(
    tx: &rusqlite::Transaction<'_>,
    ledger: &str,
    spec: &Spec,
    record: &Map<String, Value>,
    line: &[u8],
    offset: u64,
) -> Result<(), ContractError> {
    tx.prepare_cached(
        "INSERT OR IGNORE INTO keys(ledger, key, offset, length) VALUES (?1, ?2, ?3, ?4)",
    )
    .and_then(|mut statement| {
        statement.execute(params![
            ledger,
            &identity(spec, record, line)[..],
            offset as i64,
            line.len() as i64
        ])
    })
    .map_err(sqlite_error("insert key"))?;
    for field in spec.tags {
        let Some(value) = record.get(*field).and_then(Value::as_str) else {
            continue;
        };
        tx.prepare_cached(
            "INSERT OR IGNORE INTO tags(ledger, tag, offset, length) VALUES (?1, ?2, ?3, ?4)",
        )
        .and_then(|mut statement| {
            statement.execute(params![
                ledger,
                &tag(field, value)[..],
                offset as i64,
                line.len() as i64
            ])
        })
        .map_err(sqlite_error("insert tag"))?;
    }
    Ok(())
}

/// Tag an unreadable line by the string each tag field is spelled with in
/// its bytes (`"field":"value"`, as the canonical writer writes it).
fn insert_unreadable(
    tx: &rusqlite::Transaction<'_>,
    ledger: &str,
    spec: &Spec,
    line: &[u8],
    offset: u64,
) -> Result<(), ContractError> {
    for field in spec.tags {
        for value in spelled_strings(line, field) {
            tx.prepare_cached(
                "INSERT OR IGNORE INTO tags(ledger, tag, offset, length) VALUES (?1, ?2, ?3, ?4)",
            )
            .and_then(|mut statement| {
                statement.execute(params![
                    ledger,
                    &tag(field, &value)[..],
                    offset as i64,
                    line.len() as i64
                ])
            })
            .map_err(sqlite_error("insert tag"))?;
        }
    }
    Ok(())
}

/// Every JSON string written right after a `"field":` in `line` and there
/// whole: wherever a marker scan of the line would have found the field.
fn spelled_strings(line: &[u8], field: &str) -> Vec<String> {
    let key = format!(
        "{}:",
        crate::json::jcs_text(&Value::String(field.to_owned()))
    );
    let mut values = Vec::new();
    let mut from = 0;
    while let Some(found) = crate::store::bytes_find(&line[from..], key.as_bytes()) {
        let start = from + found + key.len();
        from = start;
        if line.get(start) != Some(&b'"') {
            continue;
        }
        let mut end = start + 1;
        while end < line.len() && line[end] != b'"' {
            end += if line[end] == b'\\' { 2 } else { 1 };
        }
        if let Some(value) = line
            .get(start..=end)
            .and_then(|text| serde_json::from_slice(text).ok())
        {
            values.push(value);
        }
    }
    values
}

/// The line at `offset`, `length` bytes long, when the ledger holds a whole
/// line there: one that starts the file or follows a newline, and ends in one.
fn line_at(file: &fs::File, offset: u64, length: u64) -> Option<Vec<u8>> {
    let start = offset.checked_sub(1);
    let mut bytes = vec![0u8; length as usize + 1 + usize::from(start.is_some())];
    file.read_exact_at(&mut bytes, start.unwrap_or(offset))
        .ok()?;
    if start.is_some() && bytes.remove(0) != b'\n' {
        return None;
    }
    (bytes.pop() == Some(b'\n')).then_some(bytes)
}

/// Whether `line` carries `field` = one of `values`: as a parsed record, or,
/// for a line that does not parse, as its bytes spell it.
fn carries(line: &[u8], field: &str, values: &[&str]) -> bool {
    match serde_json::from_slice::<Map<String, Value>>(line) {
        Ok(record) => record
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| values.contains(&value)),
        Err(_) => spelled_strings(line, field)
            .iter()
            .any(|value| values.contains(&value.as_str())),
    }
}

/// The index gave an answer the ledger does not confirm: forget the ledger
/// and read it again from the start. Recovered, with a signal.
fn rebuild(
    tx: &rusqlite::Transaction<'_>,
    ledger: &str,
    spec: &Spec,
    file: &fs::File,
) -> Result<(), ContractError> {
    for table in ["keys", "tags", "cursor"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE ledger = ?1"),
            params![ledger],
        )
        .map_err(sqlite_error("reset"))?;
    }
    crate::output::diagnostic(
        "ledger-index-rebuilt",
        serde_json::json!({
            "ledger": ledger,
            "reason": "an index answer was not confirmed by the ledger",
            "effect": "the ledger is indexed again from the start"
        }),
    );
    catch_up(tx, ledger, spec, file)
}

fn set_cursor(
    tx: &rusqlite::Transaction<'_>,
    ledger: &str,
    file: &fs::File,
    length: u64,
) -> Result<(), ContractError> {
    let metadata = file
        .metadata()
        .map_err(|error| ContractError::io("inspect ledger", error))?;
    tx.execute(
        "INSERT INTO cursor(ledger, version, device, inode, length, tail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(ledger) DO UPDATE SET version = ?2, device = ?3, inode = ?4, length = ?5, tail = ?6",
        params![
            ledger,
            INDEX_VERSION,
            metadata.dev() as i64,
            metadata.ino() as i64,
            length as i64,
            read_tail(file, length)
        ],
    )
    .map_err(sqlite_error("cursor"))?;
    Ok(())
}

/// Bring the index up to the ledger's last whole line: read only what was
/// appended since the cursor, or everything when the ledger was rewritten or
/// the index is of another version. An unterminated last line is left for a
/// later reader, since its writer may still be writing it.
fn catch_up(
    tx: &rusqlite::Transaction<'_>,
    ledger: &str,
    spec: &Spec,
    file: &fs::File,
) -> Result<(), ContractError> {
    let metadata = file
        .metadata()
        .map_err(|error| ContractError::io("inspect ledger", error))?;
    let cursor: Option<(i64, i64, i64, i64, Vec<u8>)> = tx
        .query_row(
            "SELECT version, device, inode, length, tail FROM cursor WHERE ledger = ?1",
            params![ledger],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error("read cursor"))?;
    let current = cursor.and_then(|(version, device, inode, length, tail)| {
        (version == INDEX_VERSION
            && device == metadata.dev() as i64
            && inode == metadata.ino() as i64
            && (length as u64) <= metadata.len()
            && read_tail(file, length as u64) == tail)
            .then_some(length as u64)
    });
    let start = match current {
        Some(length) if length == metadata.len() => return Ok(()),
        Some(length) => length,
        None => {
            for table in ["keys", "tags"] {
                tx.execute(
                    &format!("DELETE FROM {table} WHERE ledger = ?1"),
                    params![ledger],
                )
                .map_err(sqlite_error("reset"))?;
            }
            0
        }
    };
    let mut reader = std::io::BufReader::new(file);
    reader
        .seek(std::io::SeekFrom::Start(start))
        .map_err(|error| ContractError::io("read ledger", error))?;
    let mut offset = start;
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| ContractError::io("read ledger", error))?;
        if read == 0 || buffer.last() != Some(&b'\n') {
            break;
        }
        let line = buffer[..buffer.len() - 1]
            .strip_suffix(b"\r")
            .unwrap_or(&buffer[..buffer.len() - 1]);
        match serde_json::from_slice::<Map<String, Value>>(line) {
            Ok(record) => insert(tx, ledger, spec, &record, line, offset)?,
            // An unreadable line is no record's identity, but it may be one
            // of a reader's records cut short. It is tagged by the values
            // its bytes spell for the tag fields, as a marker scan of the
            // ledger would have kept it, so the reader that asks for them
            // gets it, fails to parse it and reports it: skipped with a
            // signal, never silently absent.
            Err(_) => insert_unreadable(tx, ledger, spec, line, offset)?,
        }
        offset += read as u64;
    }
    set_cursor(tx, ledger, file, offset)
}

/// What `append` did with a record.
pub enum Appended {
    /// A record with the same identity is already in the ledger.
    Present,
    /// The record was written.
    Written,
}

/// Append `canonical` to the ledger open (and exclusively locked) as `file`
/// unless a record with its identity is already there. `write` writes the
/// line and returns the offset its record starts at. An error returned before
/// `write` ran leaves the ledger untouched, so the caller may append another
/// way; once the line is written, a failure to index it is reported and left
/// for the next reader to catch up.
pub fn append(
    path: &Path,
    file: &fs::File,
    spec: &Spec,
    canonical: &str,
    write: impl FnOnce() -> Result<u64, ContractError>,
) -> Result<Appended, ContractError> {
    let record = serde_json::from_str::<Map<String, Value>>(canonical)
        .map_err(|error| ContractError::internal(format!("record is not an object: {error}")))?;
    let ledger = ledger_name(path);
    let mut connection = open(path)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error("begin"))?;
    catch_up(&tx, &ledger, spec, file)?;
    let key = identity(spec, &record, canonical.as_bytes());
    let lookup = || {
        tx.query_row(
            "SELECT offset, length FROM keys WHERE ledger = ?1 AND key = ?2",
            params![ledger, &key[..]],
            |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64)),
        )
        .optional()
        .map_err(sqlite_error("lookup"))
    };
    // A duplicate is suppressed only on the ledger's word: the line the index
    // points at must be there, whole, with this identity.
    let confirmed = |(offset, length): (u64, u64)| {
        line_at(file, offset, length).is_some_and(|line| {
            serde_json::from_slice::<Map<String, Value>>(&line)
                .is_ok_and(|stored| identity(spec, &stored, &line) == key)
        })
    };
    let mut present = lookup()?;
    if present.is_some_and(|span| !confirmed(span)) {
        rebuild(&tx, &ledger, spec, file)?;
        present = lookup()?.filter(|span| confirmed(*span));
    }
    if present.is_some() {
        // Keep what the catch-up read, so the next process need not.
        tx.commit().map_err(sqlite_error("commit"))?;
        return Ok(Appended::Present);
    }
    let offset = write()?;
    let indexed = (|| {
        insert(&tx, &ledger, spec, &record, canonical.as_bytes(), offset)?;
        let length = file
            .metadata()
            .map_err(|error| ContractError::io("inspect ledger", error))?
            .len();
        set_cursor(&tx, &ledger, file, length)?;
        tx.commit().map_err(sqlite_error("commit"))
    })();
    if let Err(error) = indexed {
        unavailable(&ledger, &error, "the next reader indexes the written line");
    }
    Ok(Appended::Written)
}

/// The lines of the ledger at `path` tagged `field` = one of `values`, in
/// ledger order. `None` when the ledger is not indexed by `field`.
pub fn read_tagged(
    path: &Path,
    field: &str,
    values: &[&str],
) -> Result<Option<Vec<Vec<u8>>>, ContractError> {
    let Some(spec) = spec_for(path).filter(|spec| spec.tags.contains(&field)) else {
        return Ok(None);
    };
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Some(Vec::new())),
        Err(error) => return Err(ContractError::io("open ledger", error)),
    };
    // Shared with other readers, excluded from a writer mid-line.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 {
        return Err(ContractError::io(
            "lock ledger",
            std::io::Error::last_os_error(),
        ));
    }
    let ledger = ledger_name(path);
    let mut connection = open(path)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error("begin"))?;
    catch_up(&tx, &ledger, spec, &file)?;
    // Each line the index names is read back and kept only if the ledger
    // holds it whole there with the tag; one that is not rebuilds the index.
    let tagged = || -> Result<Option<Vec<Vec<u8>>>, ContractError> {
        let mut spans = Vec::new();
        let mut statement = tx
            .prepare_cached("SELECT offset, length FROM tags WHERE ledger = ?1 AND tag = ?2")
            .map_err(sqlite_error("prepare"))?;
        for value in values {
            let rows = statement
                .query_map(params![ledger, &tag(field, value)[..]], |row| {
                    Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
                })
                .map_err(sqlite_error("select"))?;
            for row in rows {
                spans.push(row.map_err(sqlite_error("row"))?);
            }
        }
        spans.sort_unstable();
        spans.dedup();
        let mut lines = Vec::with_capacity(spans.len());
        for (offset, length) in spans {
            match line_at(&file, offset, length).filter(|line| carries(line, field, values)) {
                Some(line) => lines.push(line),
                None => return Ok(None),
            }
        }
        Ok(Some(lines))
    };
    let lines = match tagged()? {
        Some(lines) => lines,
        None => {
            rebuild(&tx, &ledger, spec, &file)?;
            tagged()?.ok_or_else(|| {
                ContractError::internal("ledger index disagrees with a ledger it just read")
            })?
        }
    };
    tx.commit().map_err(sqlite_error("commit"))?;
    Ok(Some(lines))
}

/// The index could not answer; the caller falls back to the ledger itself.
/// Recovered, never silent.
pub fn unavailable(ledger: &str, error: &ContractError, effect: &str) {
    crate::output::diagnostic(
        "ledger-index-unavailable",
        serde_json::json!({"ledger": ledger, "code": error.code, "message": error.message, "effect": effect}),
    );
}

#[cfg(test)]
mod tests {
    use super::read_tagged;
    use serde_json::{Value, json};
    use std::fs;
    use std::io::Write as _;
    use std::path::Path;

    fn observation(id: &str, session: &str, observed_at: &str) -> Value {
        json!({
            "observation_id": id,
            "source_identity": format!("session:{session}"),
            "observed_at": observed_at,
            "statement": "Retries stop after five attempts."
        })
    }

    fn ids(path: &Path, session: &str) -> Vec<String> {
        read_tagged(path, "source_identity", &[&format!("session:{session}")])
            .expect("read")
            .expect("indexed")
            .iter()
            .map(|line| {
                let record: Value = serde_json::from_slice(line).expect("record");
                record["observation_id"].as_str().expect("id").to_owned()
            })
            .collect()
    }

    fn line_count(path: &Path) -> usize {
        fs::read_to_string(path).expect("ledger").lines().count()
    }

    fn ledger() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("observations.jsonl");
        (temp, path)
    }

    #[test]
    fn a_record_seen_again_with_a_new_timestamp_is_not_appended() {
        let (_temp, path) = ledger();
        crate::store::append_jsonl(
            &path,
            &observation("obs_a", "s1", "2026-10-14T00:00:00.000Z"),
        )
        .expect("first");
        crate::store::append_jsonl(
            &path,
            &observation("obs_a", "s1", "2026-10-14T01:00:00.000Z"),
        )
        .expect("again");
        assert_eq!(line_count(&path), 1);
        assert!(
            fs::read_to_string(&path)
                .expect("ledger")
                .contains("00:00:00.000Z")
        );
    }

    #[test]
    fn a_deleted_index_is_rebuilt_from_the_ledger() {
        let (temp, path) = ledger();
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t1")).expect("first");
        fs::remove_file(temp.path().join(super::INDEX_FILE)).expect("remove index");
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t2")).expect("again");
        assert_eq!(line_count(&path), 1);
        assert_eq!(ids(&path, "s1"), ["obs_a"]);
    }

    #[test]
    fn a_line_written_around_the_index_is_found_and_not_duplicated() {
        let (_temp, path) = ledger();
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t1")).expect("first");
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        writeln!(
            file,
            "{}",
            crate::json::jcs_text(&observation("obs_b", "s2", "t1"))
        )
        .expect("raw");
        drop(file);
        assert_eq!(ids(&path, "s2"), ["obs_b"]);
        crate::store::append_jsonl(&path, &observation("obs_b", "s2", "t2")).expect("again");
        assert_eq!(line_count(&path), 2);
    }

    #[test]
    fn tagged_records_come_back_in_ledger_order_and_only_their_own() {
        let (_temp, path) = ledger();
        for (id, session) in [("obs_a", "s1"), ("obs_b", "s2"), ("obs_c", "s1")] {
            crate::store::append_jsonl(&path, &observation(id, session, "t")).expect("append");
        }
        assert_eq!(ids(&path, "s1"), ["obs_a", "obs_c"]);
        assert_eq!(ids(&path, "s3"), Vec::<String>::new());
    }

    #[test]
    fn a_rewritten_ledger_is_indexed_again() {
        let (temp, path) = ledger();
        for id in ["obs_a", "obs_b"] {
            crate::store::append_jsonl(&path, &observation(id, "s1", "t")).expect("append");
        }
        // A compaction: a new file renamed over the old one.
        let staged = temp.path().join("observations.jsonl.new");
        fs::write(
            &staged,
            format!(
                "{}\n",
                crate::json::jcs_text(&observation("obs_b", "s1", "t"))
            ),
        )
        .expect("stage");
        fs::rename(&staged, &path).expect("rename");
        assert_eq!(ids(&path, "s1"), ["obs_b"]);
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t")).expect("append");
        assert_eq!(ids(&path, "s1"), ["obs_b", "obs_a"]);
    }

    #[test]
    fn a_rewrite_the_cursor_cannot_see_is_caught_by_the_ledger() {
        // Same inode, same length, same last bytes: the cursor takes it for
        // the ledger it read. The index's answers must still be checked
        // against the ledger before anything acts on them.
        let (_temp, path) = ledger();
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t")).expect("a");
        crate::store::append_jsonl(&path, &observation("obs_b", "s1", "t")).expect("b");
        let text = fs::read_to_string(&path).expect("ledger");
        let rewritten = text.replacen(
            &crate::json::jcs_text(&observation("obs_a", "s1", "t")),
            &crate::json::jcs_text(&observation("obs_c", "s2", "t")),
            1,
        );
        assert_eq!(rewritten.len(), text.len());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.write_all(rewritten.as_bytes())
            .expect("rewrite in place");
        drop(file);

        assert_eq!(
            ids(&path, "s1"),
            ["obs_b"],
            "obs_a is no longer in the ledger"
        );
        assert_eq!(ids(&path, "s2"), ["obs_c"]);
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t")).expect("a again");
        assert_eq!(
            line_count(&path),
            3,
            "obs_a was not suppressed on the index's word"
        );
        assert_eq!(ids(&path, "s1"), ["obs_b", "obs_a"]);
    }

    #[test]
    fn a_torn_last_line_is_terminated_and_never_indexed() {
        let (_temp, path) = ledger();
        fs::write(&path, b"{\"observation_id\":\"obs_torn\"").expect("torn");
        crate::store::append_jsonl(&path, &observation("obs_a", "s1", "t")).expect("append");
        assert_eq!(line_count(&path), 2);
        assert_eq!(ids(&path, "s1"), ["obs_a"]);
    }

    #[test]
    fn a_ledger_not_indexed_by_the_field_is_not_answered() {
        let (temp, path) = ledger();
        assert!(
            read_tagged(&path, "statement", &["x"])
                .expect("read")
                .is_none()
        );
        let other = temp.path().join("apologies.jsonl");
        assert!(
            read_tagged(&other, "session_id", &["x"])
                .expect("read")
                .is_none()
        );
    }
}
