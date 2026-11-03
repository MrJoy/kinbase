//! Compatibility facade for the completed command surface.
//!
//! The command modules operate on the three physical roots. Personal is the
//! configured Personal data root; Company is the configured private Company
//! cache root; Codebase is the repository `.kin/`. No root is accepted from
//! a product-specific environment variable.

use crate::error::ContractError;
use crate::hash::{is_sha256, sha256_bytes, sha256_text};
use crate::json::{canonical_text, parse_strict_object};
use crate::model::FactEvent;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead as _, Read as _, Seek as _, Write};
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub fn store_root(store: crate::StoreKind, repo: &Path) -> PathBuf {
    match store {
        crate::StoreKind::Personal => crate::config::load_user_config()
            .ok()
            .flatten()
            .map(|config| config.personal.data_root)
            .unwrap_or_else(|| crate::private::state_dir().join("codebase-personal")),
        crate::StoreKind::Company => match crate::config::load_user_config().ok().flatten() {
            Some(config) => match (config.company, config.companies.is_empty()) {
                (Some(company), _) => company.cache_root,
                (None, true) => crate::private::state_dir().join("company-cache"),
                // Several Companies, none selected for this repository: one
                // shared fallback would carry local Company answers from one
                // organization's repository into another's.
                (None, false) => crate::private::state_dir()
                    .join("company-unselected")
                    .join(unselected_namespace(repo)),
            },
            None => crate::private::state_dir().join("company-cache"),
        },
        crate::StoreKind::Codebase => repo.join(".kin"),
    }
}

/// The fallback Company store a repository no Company claims writes to. The
/// path alone is not the repository: a checkout deleted and recloned at the
/// same path is another one. The certified UUID, when there is one, and the
/// device and inode of the Git common directory tell them apart, since a
/// new clone has a new `.git`.
fn unselected_namespace(repo: &Path) -> String {
    let (root, identity) = match crate::codebase::Repository::discover(repo) {
        Ok(repository) => {
            let git = fs::metadata(&repository.common_dir)
                .map(|metadata| format!("{}:{}", metadata.dev(), metadata.ino()))
                .unwrap_or_default();
            let uuid = repository.uuid_hint().unwrap_or_default().to_owned();
            (repository.root, format!("{uuid}\0{git}"))
        }
        Err(_) => (repo.to_path_buf(), String::new()),
    };
    let root = root.canonicalize().unwrap_or(root);
    sha256_text(&format!("{}\0{identity}", root.to_string_lossy()))[..16].to_owned()
}

pub fn ensure_store_root(store: crate::StoreKind, repo: &Path) -> Result<PathBuf, ContractError> {
    let root = store_root(store, repo);
    crate::paths::ensure_private_dir(&root, "physical store root")?;
    Ok(root)
}

pub fn append_record(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    value: &Value,
) -> Result<(), ContractError> {
    let root = ensure_store_root(store, repo)?;
    append_jsonl(&root.join(filename), value)
}

/// `append_record` for a ledger no replay can rebuild (decisions, receipts,
/// apologies, abandonments): the file and its directory are synced before
/// the call returns.
pub fn append_record_durable(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    value: &Value,
) -> Result<(), ContractError> {
    let root = ensure_store_root(store, repo)?;
    append_jsonl_with(&root.join(filename), value, Append { durable: true })
}

/// Every readable record of `filename`. An unreadable line is skipped and
/// reported, never allowed to hide the rest of the ledger.
pub fn read_records(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl_where(&root.join(filename), |_| true)
}

/// Every record of `filename`, for a reader that decides whether something
/// already happened (a receipt, an apology, an abandonment, a
/// classification). A line it cannot read may be the very record that says
/// it did, so an unreadable line refuses the decision instead of reading as
/// absent and letting the step run twice.
pub fn read_records_complete(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<Vec<Value>, ContractError> {
    read_records_complete_where(store, repo, filename, |_| true)
}

/// `read_records_complete` for the lines `keep` accepts, read by stream: one
/// candidate's receipts out of every candidate's. A line `keep` passes over
/// is still parsed (and dropped, so nothing is materialised): one that is
/// not a JSON object may be the very record the caller is looking for, and
/// refuses the decision as an unreadable kept line does. Callers keep lines
/// by the value they look for, not a `"key":value` spelling, so a record
/// written with other spacing is still found.
pub fn read_records_complete_where(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    let (records, skipped) = read_jsonl_counted_checked(&root.join(filename), keep, true)?;
    if skipped.total() == 0 {
        return Ok(records);
    }
    let lines = skipped
        .positions()
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    Err(ContractError::integrity(
        "DIGEST_MISMATCH",
        format!(
            "{filename} has {} unreadable line(s) (line {lines}); whether this step already happened cannot be decided",
            skipped.total()
        ),
        format!(
            "Move the named line(s) of {filename} aside and rerun; nothing was repeated or admitted."
        ),
    ))
}

/// The records of `filename` whose raw canonical line satisfies `keep`, read
/// by stream. A ledger holds every session's records and one host event
/// wants one session's: the caller passes a marker only that session's
/// canonical lines can contain, only those lines are parsed, and the exact
/// filter still runs on the parsed record. Nothing else is materialised, so
/// the cost is a scan of the file rather than a parse of it. A line that is
/// not the caller's is never parsed and never decoded, so it cannot hide the
/// caller's; a kept line that cannot be read is skipped and reported, the
/// disposition every ledger reader here takes. A ledger that was never
/// written holds no records.
pub fn read_records_where(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let root = store_root(store, repo);
    read_jsonl_where(&root.join(filename), keep)
}

/// The records of `filename` whose `field` holds one of `values`, in ledger
/// order, looked up in the ledger's identity index (`ledger_index`) rather
/// than by scanning it. A ledger not indexed by `field`, or an index that
/// cannot answer, is streamed with `fallback` instead, a line predicate the
/// caller's exact filter refines either way. Kept lines are parsed and
/// reported as `read_records_where` does, except that a skipped line's
/// `position` counts the kept lines, since the index does not number the
/// ledger's.
pub fn read_records_tagged(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
    field: &str,
    values: &[&str],
    fallback: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    let path = store_root(store, repo).join(filename);
    match crate::ledger_index::read_tagged(&path, field, values) {
        Ok(Some(lines)) => {
            let mut skipped = crate::output::Skipped::default();
            let mut output = Vec::with_capacity(lines.len());
            for (position, line) in lines.iter().enumerate() {
                match parse_strict_object(line) {
                    Ok(map) => output.push(Value::Object(map)),
                    Err(_) => skipped.push(
                        position + 1,
                        line.len(),
                        crate::output::unreadable_reason(line),
                    ),
                }
            }
            skipped.report(filename);
            Ok(output)
        }
        Ok(None) => read_jsonl_where(&path, fallback),
        Err(error) => {
            crate::ledger_index::unavailable(filename, &error, "streamed the ledger instead");
            read_jsonl_where(&path, fallback)
        }
    }
}

/// Where `needle` first occurs in `haystack`, for marker checks on raw
/// ledger bytes. A line is small and a marker starts with a quote, so a
/// first-byte scan with an early-exit compare is enough, and nothing is
/// decoded to find out whether a line is the caller's.
pub fn bytes_find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }
    let last_start = haystack.len() - needle.len();
    let mut start = 0;
    while let Some(offset) = haystack[start..=last_start]
        .iter()
        .position(|&byte| byte == needle[0])
    {
        let at = start + offset;
        if &haystack[at..at + needle.len()] == needle {
            return Some(at);
        }
        start = at + 1;
    }
    None
}

pub fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    bytes_find(haystack, needle).is_some()
}

/// A line without its terminator.
fn trim_line(buffer: &[u8]) -> &[u8] {
    let line = buffer.strip_suffix(b"\n").unwrap_or(buffer);
    line.strip_suffix(b"\r").unwrap_or(line)
}

pub fn read_jsonl_where(
    path: &Path,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<Vec<Value>, ContractError> {
    Ok(read_jsonl_counted(path, keep)?.0)
}

fn read_jsonl_counted(
    path: &Path,
    keep: impl Fn(&[u8]) -> bool,
) -> Result<(Vec<Value>, crate::output::Skipped), ContractError> {
    read_jsonl_counted_checked(path, keep, false)
}

/// Whether a line is one JSON object, parsed without keeping it.
fn is_json_object(line: &[u8]) -> bool {
    line.first() == Some(&b'{') && serde_json::from_slice::<serde::de::IgnoredAny>(line).is_ok()
}

fn read_jsonl_counted_checked(
    path: &Path,
    keep: impl Fn(&[u8]) -> bool,
    check_unkept: bool,
) -> Result<(Vec<Value>, crate::output::Skipped), ContractError> {
    let mut skipped = crate::output::Skipped::default();
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((Vec::new(), skipped));
        }
        Err(error) => return Err(ContractError::io("read JSONL", error)),
    };
    // The signal names the ledger, never its directory.
    let ledger = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = Vec::new();
    let mut output = Vec::new();
    let mut position = 0usize;
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| ContractError::io("read JSONL", error))?;
        if read == 0 {
            break;
        }
        position += 1;
        // The predicate sees raw bytes: a foreign line is neither decoded nor
        // copied, however large or broken it is, and a kept one that is not
        // UTF-8 is reported rather than decoded.
        let line = trim_line(&buffer);
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if !keep(line) {
            if check_unkept && !is_json_object(line) {
                skipped.push(position, line.len(), "not a whole record");
            }
            continue;
        }
        let Ok(text) = std::str::from_utf8(line) else {
            skipped.push(position, line.len(), "invalid UTF-8");
            continue;
        };
        match parse_strict_object(text.as_bytes()) {
            Ok(map) => output.push(Value::Object(map)),
            Err(_) => skipped.push(
                position,
                text.len(),
                crate::output::unreadable_reason(text.as_bytes()),
            ),
        }
    }
    skipped.report(&ledger);
    Ok((output, skipped))
}

/// The lines this process has already seen in each ledger, as digests, and
/// how far into the file it has read. An append checks for its line against
/// the index and reads only what other writers appended since; scanning the
/// whole ledger on every append made a batch of appends quadratic (and
/// materialising it had cost 1.6 GB per append on a 275 MB file).
struct LineIndex {
    device: u64,
    inode: u64,
    length: u64,
    /// Change time when `length` was last read up to, and the bytes just
    /// before it: a rewrite in place keeps the inode (and may keep the
    /// length), and only these tell it from another writer's append.
    changed: (i64, i64),
    tail: Vec<u8>,
    lines: HashSet<[u8; 32]>,
}

/// The bytes a line index remembers from the end of what it has read.
const INDEX_TAIL_BYTES: u64 = 64;

fn read_tail(file: &fs::File, length: u64) -> Vec<u8> {
    let start = length.saturating_sub(INDEX_TAIL_BYTES);
    let mut tail = vec![0u8; (length - start) as usize];
    if file.read_exact_at(&mut tail, start).is_err() {
        tail.clear();
    }
    tail
}

fn line_indexes() -> &'static Mutex<HashMap<std::path::PathBuf, LineIndex>> {
    static INDEXES: OnceLock<Mutex<HashMap<std::path::PathBuf, LineIndex>>> = OnceLock::new();
    INDEXES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether `canonical` already appears as a whole line of the ledger open
/// (and exclusively locked) as `file`. Anything but an append since the
/// index was built (a replacement, a truncation, a rewrite in place) reads
/// the ledger again from the start.
fn line_present(file: &fs::File, path: &Path, canonical: &[u8]) -> Result<bool, ContractError> {
    let metadata = file
        .metadata()
        .map_err(|error| ContractError::io("inspect JSONL", error))?;
    let changed = (metadata.ctime(), metadata.ctime_nsec());
    let fresh = || LineIndex {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: 0,
        changed: (0, 0),
        tail: Vec::new(),
        lines: HashSet::new(),
    };
    let mut indexes = line_indexes()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let index = indexes.entry(path.to_path_buf()).or_insert_with(fresh);
    let rewritten = index.device != metadata.dev()
        || index.inode != metadata.ino()
        || index.length > metadata.len()
        || (index.length == metadata.len() && index.changed != changed)
        || (index.length < metadata.len() && read_tail(file, index.length) != index.tail);
    if rewritten {
        *index = fresh();
    }
    if index.length < metadata.len() {
        let mut reader = std::io::BufReader::new(file);
        reader
            .seek(std::io::SeekFrom::Start(index.length))
            .map_err(|error| ContractError::io("read JSONL", error))?;
        let mut reader = reader.take(metadata.len() - index.length);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            let read = reader
                .read_until(b'\n', &mut buffer)
                .map_err(|error| ContractError::io("read JSONL", error))?;
            if read == 0 {
                break;
            }
            index
                .lines
                .insert(crate::hash::sha256_raw(trim_line(&buffer)));
        }
        index.length = metadata.len();
        index.tail = read_tail(file, index.length);
    }
    index.changed = changed;
    Ok(index.lines.contains(&crate::hash::sha256_raw(canonical)))
}

/// Record a line this process just appended (still holding the ledger's
/// lock), so the next append need not read it back.
fn line_appended(file: &fs::File, path: &Path, canonical: &[u8]) {
    let Ok(metadata) = file.metadata() else {
        return;
    };
    let mut indexes = line_indexes()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = indexes.get_mut(path) {
        index.lines.insert(crate::hash::sha256_raw(canonical));
        index.length = metadata.len();
        index.changed = (metadata.ctime(), metadata.ctime_nsec());
        index.tail = read_tail(file, index.length);
    }
}

pub fn append_jsonl(path: &Path, value: &Value) -> Result<(), ContractError> {
    append_jsonl_with(path, value, Append { durable: false })
}

/// How `append_jsonl_with` appends: whether it returns only once the line is
/// on disk.
struct Append {
    durable: bool,
}

fn append_jsonl_with(
    path: &Path,
    value: &Value,
    Append { durable }: Append,
) -> Result<(), ContractError> {
    if let Some(parent) = path.parent() {
        crate::paths::ensure_private_dir(parent, "record directory")?;
    }
    // `canonical_text` yields "" for a record that fails the canonical rule,
    // and the empty line it appended was skipped on read: a silent drop, the
    // same shape that lost observations and blanked query_log. Refuse instead.
    let canonical = crate::json::try_canonical_bytes(value)
        .map_err(|error| ContractError::internal(format!("record is not canonical: {error}")))
        .and_then(|bytes| {
            String::from_utf8(bytes).map_err(|_| ContractError::internal("record is not UTF-8"))
        })?;
    let file = open_locked_ledger(path)?;
    // A ledger of entities is checked by identity against its persisted index
    // (`ledger_index`), which reads only what was appended since it last
    // looked; the whole-line check below reads the whole ledger in every
    // fresh process and misses a record seen again with a new timestamp.
    if let Some(spec) = crate::ledger_index::spec_for(path) {
        let ledger = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let unchecked = match crate::ledger_index::append(path, &file, spec, &canonical, || {
            write_line(&file, path, canonical.as_bytes())
        }) {
            Ok(crate::ledger_index::Appended::Present | crate::ledger_index::Appended::Written) => {
                false
            }
            Ok(crate::ledger_index::Appended::Behind) => {
                crate::ledger_index::behind(&ledger);
                true
            }
            Err(error) => {
                crate::ledger_index::unavailable(
                    &ledger,
                    &error,
                    "appended without the duplicate check; the dream pass removes a duplicate",
                );
                true
            }
        };
        // Nothing was written yet. Without the index, append unchecked: a
        // duplicate is harmless and the dream pass compacts it, and reading
        // the whole ledger to look for one is the cost the index removes.
        if unchecked {
            write_line(&file, path, canonical.as_bytes())?;
        }
        if durable {
            sync_ledger(&file, path)?;
        }
        return Ok(());
    }
    if line_present(&file, path, canonical.as_bytes())? {
        // An earlier attempt may have written the line and failed to sync it;
        // a durable append returns only once the line is on disk.
        if durable {
            sync_ledger(&file, path)?;
        }
        return Ok(());
    }
    write_line(&file, path, canonical.as_bytes())?;
    line_appended(&file, path, canonical.as_bytes());
    if durable {
        sync_ledger(&file, path)?;
    }
    Ok(())
}

/// The ledger at `path`, open for append and exclusively locked. Ledgers are
/// private: created owner-only whatever the umask, and an existing one
/// readable by others is narrowed. One writer at a time from the duplicate
/// check to the write: two hooks appending the same record otherwise both
/// find it absent. Released when the file closes.
///
/// The dream pass replaces a ledger with its compacted copy while holding the
/// lock; a writer that opened the old file and waited for the lock would
/// then append to a file no longer at `path`. So the locked file must still
/// be the one at `path`, or it is opened again.
pub(crate) fn open_locked_ledger(path: &Path) -> Result<fs::File, ContractError> {
    for _ in 0..16 {
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| ContractError::io("append JSONL", error))?;
        let metadata = file
            .metadata()
            .map_err(|error| ContractError::io("inspect JSONL", error))?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(mode & 0o700))
                .map_err(|error| ContractError::io("narrow JSONL mode", error))?;
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(ContractError::io(
                "lock JSONL",
                std::io::Error::last_os_error(),
            ));
        }
        let current = fs::metadata(path).ok();
        if current.is_some_and(|current| {
            current.dev() == metadata.dev() && current.ino() == metadata.ino()
        }) {
            return Ok(file);
        }
    }
    Err(ContractError::internal(format!(
        "{} kept being replaced while it was being locked",
        path.display()
    )))
}

/// Append `canonical` as one line of the locked ledger `file`; returns the
/// offset the record starts at.
fn write_line(mut file: &fs::File, path: &Path, canonical: &[u8]) -> Result<u64, ContractError> {
    // A write cut short (a full disk, a crash before the page cache reached
    // the disk) leaves a last line with no terminator. Appending straight
    // after it glued the new record onto the torn one and both read back as
    // one unreadable line; terminating the torn line first loses only it.
    let length = file
        .metadata()
        .map_err(|error| ContractError::io("inspect JSONL", error))?
        .len();
    let mut line = Vec::with_capacity(canonical.len() + 2);
    if length > 0 {
        let mut last = [0u8; 1];
        file.read_exact_at(&mut last, length - 1)
            .map_err(|error| ContractError::io("inspect JSONL", error))?;
        if last[0] != b'\n' {
            line.push(b'\n');
            crate::output::diagnostic(
                "torn-ledger-tail",
                json!({"ledger": path.file_name().map(|name| name.to_string_lossy().into_owned()), "bytes": length}),
            );
        }
    }
    let offset = length + line.len() as u64;
    line.extend_from_slice(canonical);
    line.push(b'\n');
    file.write_all(&line)
        .map_err(|error| ContractError::io("write JSONL", error))?;
    Ok(offset)
}

fn sync_ledger(file: &fs::File, path: &Path) -> Result<(), ContractError> {
    file.sync_all()
        .map_err(|error| ContractError::io("sync JSONL", error))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| ContractError::io("sync JSONL directory", error))?;
    }
    Ok(())
}

/// Sync a ledger whose record a caller found already present, so a decision
/// read back from it is on disk before the caller acts on it.
pub fn sync_record(
    store: crate::StoreKind,
    repo: &Path,
    filename: &str,
) -> Result<(), ContractError> {
    let path = store_root(store, repo).join(filename);
    match fs::File::open(&path) {
        Ok(file) => sync_ledger(&file, &path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ContractError::io("open JSONL", error)),
    }
}

pub fn write_private_body(root: &Path, bytes: &[u8]) -> Result<String, ContractError> {
    let digest = sha256_bytes(bytes);
    let directory = root.join("bodies");
    crate::paths::ensure_private_dir(&directory, "private body store")?;
    let path = directory.join(&digest);
    if !path.exists() {
        crate::paths::write_atomic(&path, bytes, 0o600, false)?;
    }
    Ok(format!("sha256:{digest}"))
}

pub fn write_content_addressed_event(
    root: &Path,
    event: &FactEvent,
) -> Result<(PathBuf, String), ContractError> {
    // An event that fails the canonical rule is refused, never written as
    // the marker record the infallible helper returns.
    let canonical = crate::json::try_canonical_text(&event.document()).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!("event is not canonical: {error}"),
            "Quarantine the event; it was not written.",
        )
    })?;
    let digest = sha256_text(&canonical);
    if !is_sha256(&digest) {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "event digest is malformed",
            "Quarantine the event.",
        ));
    }
    let relative = crate::paths::sharded_relative(&digest)?;
    let destination = root.join("events").join(&relative);
    if let Some(parent) = destination.parent() {
        crate::paths::ensure_dir(parent, "event store")?;
    }
    crate::paths::write_atomic(&destination, canonical.as_bytes(), 0o644, true)?;
    Ok((destination, digest))
}

/// Every readable event under `root/events`. A file that cannot be read as
/// an event is skipped and reported: one leftover or damaged file used to
/// fail the whole read, and callers took that for an empty store.
pub fn read_events(root: &Path) -> Result<Vec<FactEvent>, ContractError> {
    let events_root = root.join("events");
    let mut files = Vec::new();
    collect_files(&events_root, &mut files)?;
    let mut skipped = crate::output::Skipped::default();
    let mut texts = Vec::new();
    for path in files {
        let name = path
            .strip_prefix(&events_root)
            .unwrap_or(&path)
            .to_string_lossy()
            .into_owned();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                skipped.push_file(&name, 0, "unreadable file");
                continue;
            }
        };
        // The parser enforces the same bound; checking first keeps an
        // oversized file from being decoded at all.
        if bytes.len() > crate::model::MAX_EVENT_BYTES {
            skipped.push_file(&name, bytes.len(), "event exceeds the size bound");
            continue;
        }
        texts.push((String::from_utf8_lossy(&bytes).into_owned(), name));
    }
    texts.sort();
    let mut events = Vec::with_capacity(texts.len());
    for (text, name) in texts {
        match FactEvent::parse(text.as_bytes()) {
            Ok(event) => events.push(event),
            Err(_) => skipped.push_file(
                &name,
                text.len(),
                match crate::output::unreadable_reason(text.as_bytes()) {
                    "outside the canonical data model" => "not a fact event",
                    reason => reason,
                },
            ),
        }
    }
    skipped.report("events");
    Ok(events)
}

pub fn event_canonical_text(event: &FactEvent) -> String {
    let mut value = event.document();
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    canonical_text(&value)
}

pub fn verify_event_signature(event: &FactEvent, public_key: &Path) -> Result<bool, ContractError> {
    let key = crate::crypto::PublicKey::load(public_key, "event signing public key")?;
    let message = event_canonical_text(event);
    Ok(key.verify("fact-event", message.as_bytes(), &event.signature))
}

pub fn parse_event(bytes: &[u8]) -> Result<FactEvent, ContractError> {
    FactEvent::parse(bytes).map_err(|error| {
        ContractError::integrity("DIGEST_MISMATCH", error, "Quarantine the malformed event.")
    })
}

pub fn manifest_placeholder() -> Value {
    json!({"schema":"kinbase-manifest/1"})
}

/// Event files under `path`: `.json` files only, never a `write_atomic`
/// temporary (`.tmp-*`) a crash left behind.
fn collect_files(path: &Path, output: &mut Vec<PathBuf>) -> Result<(), ContractError> {
    if path.is_dir() {
        let mut children = fs::read_dir(path)
            .map_err(|error| ContractError::io("walk event store", error))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| ContractError::io("walk event store", error))?;
        children.sort();
        for child in children {
            collect_files(&child, output)?;
        }
    } else if path.is_file() {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default();
        if !name.starts_with(".tmp-") && name.ends_with(".json") {
            output.push(path.to_path_buf());
        }
    }
    Ok(())
}

#[cfg(test)]
mod unselected_namespace_tests {
    use super::unselected_namespace;
    use std::path::Path;
    use std::process::Command;

    fn git_init(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn a_checkout_replaced_at_the_same_path_gets_its_own_store() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("checkout");
        git_init(&repo);
        let first = unselected_namespace(&repo);
        assert_eq!(unselected_namespace(&repo), first, "not stable");
        std::fs::rename(&repo, temp.path().join("old")).unwrap();
        git_init(&repo);
        assert_ne!(
            unselected_namespace(&repo),
            first,
            "the replacement checkout inherited the previous repository's store"
        );
    }
}

#[cfg(test)]
mod append_tests {
    use super::*;

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .expect("ledger")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn repeated_appends_are_deduplicated_across_other_writers() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("records.jsonl");
        for index in 0..3 {
            append_jsonl(&path, &json!({"n": index})).expect("append");
        }
        append_jsonl(&path, &json!({"n": 1})).expect("repeat");
        // Another writer appends a line this process has not seen.
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .and_then(|mut file| file.write_all(b"{\"n\":7}\n"))
            .expect("foreign append");
        append_jsonl(&path, &json!({"n": 7})).expect("seen through the tail");
        append_jsonl(&path, &json!({"n": 8})).expect("new");
        assert_eq!(
            lines(&path),
            [
                "{\"n\":0}",
                "{\"n\":1}",
                "{\"n\":2}",
                "{\"n\":7}",
                "{\"n\":8}"
            ]
        );

        // A ledger replaced under the same name is indexed again.
        fs::write(&path, b"{\"n\":1}\n").expect("replace");
        append_jsonl(&path, &json!({"n": 0})).expect("after replace");
        append_jsonl(&path, &json!({"n": 1})).expect("present after replace");
        assert_eq!(lines(&path), ["{\"n\":1}", "{\"n\":0}"]);
    }

    #[test]
    fn ledgers_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("fresh.jsonl");
        append_jsonl(&path, &json!({"n": 1})).expect("append");
        let mode = |path: &Path| fs::metadata(path).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);

        let wide = dir.path().join("wide.jsonl");
        fs::write(&wide, b"").expect("create");
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o644)).expect("widen");
        append_jsonl(&wide, &json!({"n": 1})).expect("append");
        assert_eq!(mode(&wide), 0o600);
    }

    #[test]
    fn a_marked_complete_read_refuses_a_torn_line_it_skips() {
        let repo = tempfile::tempdir().expect("repo");
        let root = ensure_store_root(crate::StoreKind::Codebase, repo.path()).expect("root");
        fs::write(
            root.join("decisions.jsonl"),
            b"{\"candidate_id\":\"a\",\"state\":\"committed\"}\n{\"candidate_id\":\"b\",\"state\":\"comm\n{\"candidate_id\":\"a\",\"state\":\"refused\"}\n",
        )
        .expect("ledger");
        let marker = b"\"candidate_id\":\"a\"";
        let keep = |line: &[u8]| bytes_contain(line, marker);
        // The tolerant reader keeps a's records; the complete one refuses,
        // since the torn line could have been a's.
        let tolerant = read_records_where(
            crate::StoreKind::Codebase,
            repo.path(),
            "decisions.jsonl",
            keep,
        )
        .expect("tolerant");
        assert_eq!(tolerant.len(), 2);
        let error = read_records_complete_where(
            crate::StoreKind::Codebase,
            repo.path(),
            "decisions.jsonl",
            keep,
        )
        .expect_err("a torn line refuses the decision");
        assert_eq!(error.code, "DIGEST_MISMATCH");

        fs::write(
            root.join("decisions.jsonl"),
            b"{\"candidate_id\":\"a\",\"state\":\"committed\"}\n{\"candidate_id\":\"b\",\"state\":\"x\"}\n",
        )
        .expect("ledger");
        let complete = read_records_complete_where(
            crate::StoreKind::Codebase,
            repo.path(),
            "decisions.jsonl",
            keep,
        )
        .expect("whole lines");
        assert_eq!(
            complete,
            vec![json!({"candidate_id": "a", "state": "committed"})]
        );
    }

    #[test]
    fn a_complete_read_finds_a_spaced_record_and_refuses_braced_garbage() {
        let repo = tempfile::tempdir().expect("repo");
        let root = ensure_store_root(crate::StoreKind::Codebase, repo.path()).expect("root");
        let value = b"\"a\"";
        let keep = |line: &[u8]| bytes_contain(line, value);
        fs::write(
            root.join("decisions.jsonl"),
            b"{\"candidate_id\": \"a\", \"state\": \"committed\"}\n{\"candidate_id\":\"b\"}\n",
        )
        .expect("ledger");
        let found = read_records_complete_where(
            crate::StoreKind::Codebase,
            repo.path(),
            "decisions.jsonl",
            keep,
        )
        .expect("read");
        assert_eq!(
            found,
            vec![json!({"candidate_id": "a", "state": "committed"})]
        );

        fs::write(
            root.join("decisions.jsonl"),
            b"{\"candidate_id\":\"b\"}\n{garbage that is braced}\n",
        )
        .expect("ledger");
        let error = read_records_complete_where(
            crate::StoreKind::Codebase,
            repo.path(),
            "decisions.jsonl",
            keep,
        )
        .expect_err("a malformed row refuses");
        assert_eq!(error.code, "DIGEST_MISMATCH");
    }

    #[test]
    fn a_rewrite_in_place_is_indexed_again() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("records.jsonl");
        append_jsonl(&path, &json!({"n": 1})).expect("append");
        append_jsonl(&path, &json!({"n": 2})).expect("append");
        // Same inode, same length: {"n":2} becomes {"n":3}.
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.write_all_at(b"{\"n\":3}\n", 8).expect("rewrite");
        drop(file);
        append_jsonl(&path, &json!({"n": 2})).expect("restored");
        assert_eq!(lines(&path), ["{\"n\":1}", "{\"n\":3}", "{\"n\":2}"]);

        // A rewrite that also grows the file is not taken for an append.
        fs::write(&path, b"{\"n\":9}\n{\"n\":8}\n{\"n\":7}\n{\"n\":6}\n").expect("grow");
        append_jsonl(&path, &json!({"n": 1})).expect("restored");
        assert_eq!(lines(&path).last().map(String::as_str), Some("{\"n\":1}"));
    }

    #[test]
    fn an_invalid_event_is_refused_not_written() {
        let dir = tempfile::tempdir().expect("dir");
        let key = crate::crypto::PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let document = key
            .sign_document(
                "fact-event",
                &json!({
                    "schema": crate::model::EVENT_SCHEMA,
                    "event_id": "evt_invalid_write",
                    "store_kind": "company",
                    "authority_id": "architect",
                    "authority_scope": "architecture:scheduling",
                    "fact_id": "fact_invalid_write",
                    "logical_key": "architecture:scheduling",
                    "atom_kind": "constraint",
                    "scope": "architecture:scheduling",
                    "statement": "The scheduler must bound queue wait time.",
                    "evidence_refs": [],
                    "asserted_at": now,
                    "effective_from": now,
                    "disposition": "accepted",
                    "distortion": {"trigger": "deadline", "loss_if_absent": 8000, "rationale": "test"},
                    "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
                    "company_refs": [], "authority_snapshot_cursor": "0", "confidence": 8000,
                    "unresolved_uncertainty": null
                }),
            )
            .expect("sign");
        let mut event = FactEvent::parse(&crate::json::canonical_bytes(&document)).expect("event");
        event.statement = "bidi \u{202e} override".to_owned();
        event.raw = None;
        let error = write_content_addressed_event(dir.path(), &event).expect_err("refused");
        assert_eq!(error.code, "DIGEST_MISMATCH");
        assert!(!dir.path().join("events").exists());
    }
}
