//! The dream pass: the Personal store's maintenance, off the hook path.
//!
//! A hook does the least it can and leaves the rest here. A dream compacts
//! the entity ledgers by identity (the first record with an identity stands;
//! a later copy that differs only in a timestamp, nonce or confidence is the
//! same record seen again), re-encodes checkpoints in the current form
//! (receipts settled by an earlier checkpoint of the session are counted, not
//! listed again; checkpoints that decided nothing, or what an earlier one did,
//! are dropped), and brings the ledger index fully up to date.
//!
//! It runs detached, at most one at a time (a lease on `.dream.lock`), and at
//! most once a day unless asked (`kinbase dream --force`). SessionEnd starts
//! it when it is due. A ledger is copied without its lock, then its lock is
//! taken only to copy what was appended meanwhile and swap the copy in; a
//! writer that waited on the old file finds it replaced and opens the new
//! one (`store::open_locked_ledger`). Each replaced ledger is kept beside it
//! as `<ledger>.pre-dream-<unix seconds>` until a dream finds it a week old,
//! and an unreadable line is kept as it is: a dream never discards what it
//! cannot read.

use crate::error::ContractError;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead as _, Seek as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::io::AsRawFd as _;
use std::path::{Path, PathBuf};

const LEASE_FILE: &str = ".dream.lock";
const STATE_FILE: &str = ".dream-state.json";
/// A replaced ledger is kept as `<ledger>.pre-dream-<unix seconds>`.
const BACKUP_SUFFIX: &str = ".pre-dream-";
/// A dream is due once a day.
const INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
/// A replaced ledger is kept this long.
const BACKUP_RETENTION: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// The ledgers a dream compacts, in order.
const LEDGERS: &[&str] = &[
    "observations.jsonl",
    "session-events.jsonl",
    "atoms.jsonl",
    "candidates.jsonl",
    "session-checkpoints.jsonl",
];

/// Whether a dream is due in the Personal store at `root`: none has
/// finished within the interval. One `stat`, so SessionEnd can ask.
pub fn due(root: &Path) -> bool {
    fs::metadata(root.join(STATE_FILE))
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_none_or(|elapsed| elapsed >= INTERVAL)
}

/// Start a detached dream for `root` when one is due. Never waits for it.
pub fn start_if_due(root: &Path) {
    use std::os::unix::process::CommandExt as _;
    if !due(root) {
        return;
    }
    let Ok(program) = std::env::current_exe() else {
        return;
    };
    let _ = std::process::Command::new(program)
        .args(["dream", "--json"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn();
}

/// Dream over the Personal store at `root`. `force` dreams even when one is
/// not due.
pub fn dream(root: &Path, force: bool) -> Result<Value, ContractError> {
    crate::paths::ensure_private_dir(root, "physical store root")?;
    let lease = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(root.join(LEASE_FILE))
        .map_err(|error| ContractError::io("open dream lease", error))?;
    if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Ok(json!({"status": "busy"}));
    }
    if !force && !due(root) {
        return Ok(json!({"status": "not_due"}));
    }
    let started = std::time::Instant::now();
    let removed_backups = remove_old_backups(root);
    let mut ledgers = Vec::new();
    for name in LEDGERS {
        let path = root.join(name);
        let mut report = compact(&path)?;
        crate::ledger_index::refresh(&path)?;
        report["ledger"] = json!(name);
        ledgers.push(report);
    }
    // The indexes ingest derives through, built here rather than by the first
    // ingest after an upgrade.
    let cohort_indexes = crate::private::PrivateStore::open_personal(root)
        .and_then(|store| store.ensure_cohort_indexes())
        .map_or_else(|error| json!(error.code), |()| json!("ready"));
    let result = json!({
        "status": "dreamed",
        "cohort_indexes": cohort_indexes,
        "finished_at": crate::time::now_rfc3339_millis(),
        "milliseconds": started.elapsed().as_millis() as u64,
        "ledgers": ledgers,
        "removed_backups": removed_backups
    });
    crate::paths::write_atomic(
        &root.join(STATE_FILE),
        crate::json::canonical_text(&result).as_bytes(),
        0o600,
        false,
    )?;
    Ok(result)
}

fn remove_old_backups(root: &Path) -> Vec<String> {
    let now = unix_seconds();
    let mut removed = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return removed;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stamp) = LEDGERS.iter().find_map(|ledger| {
            name.strip_prefix(&format!("{ledger}{BACKUP_SUFFIX}"))
                .and_then(|stamp| stamp.parse::<u64>().ok())
        }) else {
            continue;
        };
        if now.saturating_sub(stamp) >= BACKUP_RETENTION.as_secs()
            && fs::remove_file(entry.path()).is_ok()
        {
            removed.push(name);
        }
    }
    removed.sort();
    removed
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// What a dream keeps of a ledger, line by line, carrying what it has seen.
struct Filter {
    spec: &'static crate::ledger_index::Spec,
    checkpoints: bool,
    seen: HashSet<[u8; 32]>,
    /// Per session, the receipts an earlier checkpoint listed as settled.
    settled: HashMap<String, HashSet<String>>,
    dropped: u64,
    reencoded: u64,
}

impl Filter {
    /// The line to keep in place of `line`, or `None` to drop it.
    fn keep(&mut self, line: &[u8]) -> Option<Vec<u8>> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let Ok(mut record) = serde_json::from_slice::<Map<String, Value>>(line) else {
            // A dream never discards what it cannot read.
            return Some(line.to_vec());
        };
        let mut line = line.to_vec();
        if self.checkpoints {
            let original = record.clone();
            if !self.reencode_checkpoint(&mut record) {
                self.dropped += 1;
                return None;
            }
            match crate::json::try_canonical_bytes(&Value::Object(record.clone())) {
                Ok(reencoded) if reencoded != line => {
                    line = reencoded;
                    self.reencoded += 1;
                }
                Ok(_) => {}
                // Kept as written: a dream never discards what it cannot
                // write back.
                Err(_) => record = original,
            }
        }
        if !self
            .seen
            .insert(crate::ledger_index::identity(self.spec, &record, &line))
        {
            self.dropped += 1;
            return None;
        }
        Some(line)
    }

    /// Put a checkpoint in the current form: settled receipts an earlier
    /// checkpoint of the session listed are counted, not listed, and the id
    /// is the digest of what it decided. False when it decided nothing.
    fn reencode_checkpoint(&mut self, record: &mut Map<String, Value>) -> bool {
        let session = record
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let settled = self.settled.entry(session).or_default();
        let mut counted = record
            .get("admissions_settled")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let admissions = record
            .get("admissions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut kept = Vec::with_capacity(admissions.len());
        for admission in admissions {
            let receipt = admission
                .get("receipt_id")
                .and_then(Value::as_str)
                .filter(|_| crate::session::admission_settled(&admission));
            match receipt {
                Some(receipt) if settled.contains(receipt) => counted += 1,
                Some(receipt) => {
                    settled.insert(receipt.to_owned());
                    kept.push(admission);
                }
                None => kept.push(admission),
            }
        }
        record.insert("admissions".to_owned(), Value::Array(kept));
        record.insert("admissions_settled".to_owned(), json!(counted));
        let decision = crate::session::checkpoint_decision(&Value::Object(record.clone()));
        if crate::session::checkpoint_is_empty(&decision) {
            return false;
        }
        record.insert(
            "checkpoint_id".to_owned(),
            json!(crate::session::checkpoint_id(&decision)),
        );
        true
    }
}

/// Copy the whole lines of `source` from `start` to its end through
/// `filter` into `out`; returns where the copy stopped (after the last whole
/// line) and how many lines it read.
fn copy_lines(
    source: &fs::File,
    start: u64,
    filter: &mut Filter,
    out: &mut impl std::io::Write,
) -> Result<(u64, u64), ContractError> {
    let mut reader = std::io::BufReader::new(source);
    reader
        .seek(std::io::SeekFrom::Start(start))
        .map_err(|error| ContractError::io("read ledger", error))?;
    let mut offset = start;
    let mut lines = 0;
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = reader
            .read_until(b'\n', &mut buffer)
            .map_err(|error| ContractError::io("read ledger", error))?;
        if read == 0 || buffer.last() != Some(&b'\n') {
            break;
        }
        lines += 1;
        offset += read as u64;
        if let Some(kept) = filter.keep(&buffer[..buffer.len() - 1]) {
            out.write_all(&kept)
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|error| ContractError::io("write compacted ledger", error))?;
        }
    }
    Ok((offset, lines))
}

/// Compact one ledger in place; reports what it read and kept.
fn compact(path: &Path) -> Result<Value, ContractError> {
    let Some(spec) = crate::ledger_index::spec_for(path) else {
        return Ok(json!({"status": "not_indexed"}));
    };
    let source = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"status": "absent"}));
        }
        Err(error) => return Err(ContractError::io("open ledger", error)),
    };
    let identity = source
        .metadata()
        .map_err(|error| ContractError::io("inspect ledger", error))?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let staged: PathBuf = path.with_file_name(format!(".{name}.dream-{}", std::process::id()));
    let mut filter = Filter {
        spec,
        checkpoints: name == "session-checkpoints.jsonl",
        seen: HashSet::new(),
        settled: HashMap::new(),
        dropped: 0,
        reencoded: 0,
    };
    let mut out = std::io::BufWriter::new(
        fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&staged)
            .map_err(|error| ContractError::io("stage compacted ledger", error))?,
    );
    let outcome = (|| {
        // Most of the ledger, without its lock: writers keep appending.
        let (copied, mut lines) = copy_lines(&source, 0, &mut filter, &mut out)?;
        // Then the lock, only for what they appended meanwhile and the swap.
        let locked = crate::store::open_locked_ledger(path)?;
        let current = locked
            .metadata()
            .map_err(|error| ContractError::io("inspect ledger", error))?;
        if (current.dev(), current.ino()) != (identity.dev(), identity.ino()) {
            return Err(ContractError::internal(format!(
                "{name} was replaced while it was being compacted"
            )));
        }
        let (end, tail) = copy_lines(&locked, copied, &mut filter, &mut out)?;
        lines += tail;
        // A torn last line (its writer is gone: the lock is ours) is kept.
        let mut torn = Vec::new();
        {
            use std::io::Read as _;
            let mut rest = &locked;
            rest.seek(std::io::SeekFrom::Start(end))
                .map_err(|error| ContractError::io("read ledger", error))?;
            rest.read_to_end(&mut torn)
                .map_err(|error| ContractError::io("read ledger", error))?;
        }
        if !torn.is_empty() {
            out.write_all(&torn)
                .and_then(|()| out.write_all(b"\n"))
                .map_err(|error| ContractError::io("write compacted ledger", error))?;
        }
        let file = out
            .into_inner()
            .map_err(|error| ContractError::io("write compacted ledger", error.into_error()))?;
        let bytes_before = current.len();
        let bytes_after = file
            .metadata()
            .map_err(|error| ContractError::io("inspect compacted ledger", error))?
            .len();
        let mut report = json!({
            "lines_read": lines,
            "dropped": filter.dropped,
            "reencoded": filter.reencoded,
            "bytes_before": bytes_before,
            "bytes_after": bytes_after
        });
        if filter.dropped == 0 && filter.reencoded == 0 {
            report["status"] = json!("unchanged");
            return Ok(report);
        }
        file.sync_all()
            .map_err(|error| ContractError::io("sync compacted ledger", error))?;
        // The replaced ledger stays reachable before anything replaces it;
        // each dream keeps its own generation.
        let backup_name = format!("{name}{BACKUP_SUFFIX}{}", unix_seconds());
        let backup = path.with_file_name(&backup_name);
        if !backup.exists() {
            fs::hard_link(path, &backup)
                .map_err(|error| ContractError::io("keep the replaced ledger", error))?;
        }
        fs::rename(&staged, path)
            .map_err(|error| ContractError::io("swap in the compacted ledger", error))?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| ContractError::io("sync ledger directory", error))?;
        }
        report["status"] = json!("compacted");
        report["backup"] = json!(backup_name);
        drop(locked);
        Ok(report)
    })();
    let _ = fs::remove_file(&staged);
    outcome
}

#[cfg(test)]
mod tests {
    use super::dream as dream_once;
    use serde_json::{Value, json};
    use std::fs;
    use std::io::Write as _;
    use std::path::Path;

    /// A dream, waited for while another holds the lease: a test thread that
    /// forks a child holds an inherited copy of the lease's lock until the
    /// child execs.
    fn dream(root: &Path, force: bool) -> Result<Value, crate::error::ContractError> {
        for _ in 0..200 {
            let result = dream_once(root, force)?;
            if result["status"] != "busy" {
                return Ok(result);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        dream_once(root, force)
    }

    fn write_lines(path: &Path, records: &[Value]) {
        let mut text = String::new();
        for record in records {
            text.push_str(&crate::json::canonical_text(record));
            text.push('\n');
        }
        fs::write(path, text).expect("ledger");
    }

    fn records(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .expect("ledger")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap_or(Value::String(line.to_owned())))
            .collect()
    }

    #[test]
    fn a_dream_keeps_the_first_copy_of_each_identity_and_every_unreadable_line() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("observations.jsonl");
        let observation = |id: &str, at: &str| json!({"observation_id": id, "source_identity": "session:s1", "observed_at": at});
        write_lines(
            &path,
            &[
                observation("obs_a", "t1"),
                observation("obs_b", "t1"),
                observation("obs_a", "t2"),
            ],
        );
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open");
        file.write_all(b"{\"observation_id\":\"obs_torn\"\n")
            .expect("unreadable");
        drop(file);

        let report = dream(temp.path(), true).expect("dream");
        assert_eq!(report["status"], "dreamed", "{report}");
        let kept = records(&path);
        assert_eq!(kept.len(), 3, "{kept:?}");
        assert_eq!(kept[0], observation("obs_a", "t1"));
        assert_eq!(kept[1], observation("obs_b", "t1"));
        assert_eq!(
            kept[2],
            Value::String("{\"observation_id\":\"obs_torn\"".to_owned())
        );
        let backup = report["ledgers"][0]["backup"].as_str().expect("backup");
        assert_eq!(
            records(&temp.path().join(backup)).len(),
            4,
            "the replaced ledger is kept"
        );
        // The index follows the compacted ledger.
        let lines = crate::ledger_index::read_tagged(&path, "source_identity", &["session:s1"])
            .expect("read")
            .expect("indexed");
        assert_eq!(lines.len(), 2, "the unreadable line spells no source");

        let again = dream(temp.path(), true).expect("dream again");
        assert_eq!(again["ledgers"][0]["status"], "unchanged", "{again}");
        assert_eq!(
            dream(temp.path(), false).expect("not due")["status"],
            "not_due"
        );
    }

    #[test]
    fn a_dream_puts_checkpoints_in_the_current_form() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("session-checkpoints.jsonl");
        let receipt = |id: &str| {
            json!({"candidate_id": format!("cand_{id}"), "receipt_id": format!("receipt_{id}"),
                   "state": "committed", "destination": "personal"})
        };
        let held = json!({"candidate_id": "cand_h", "destination": "company", "state": "held",
                          "reason": "no store"});
        let checkpoint = |id: &str, admissions: Vec<Value>, held_count: u64| {
            json!({"session_id": "s1", "checkpoint_id": id, "checkpointed_at": id,
                   "admissions": admissions, "admission_failures": 0,
                   "admissions_held": held_count, "personal_fact_count": 0,
                   "sweep": {"expired_bodies": 0}, "observation_count": 1})
        };
        write_lines(
            &path,
            &[
                checkpoint("checkpoint_1", vec![receipt("a")], 0),
                // Lists a again, settled earlier: counted, not listed.
                checkpoint("checkpoint_2", vec![receipt("a"), receipt("b")], 0),
                // Decided nothing new: dropped.
                checkpoint("checkpoint_3", vec![receipt("a"), receipt("b")], 0),
                checkpoint("checkpoint_4", vec![held.clone()], 1),
                // The same hold again: the same checkpoint.
                checkpoint("checkpoint_5", vec![held.clone()], 1),
            ],
        );
        dream(temp.path(), true).expect("dream");
        let kept = records(&path);
        assert_eq!(kept.len(), 3, "{kept:?}");
        assert_eq!(kept[0]["admissions"], json!([receipt("a")]));
        assert_eq!(kept[1]["admissions"], json!([receipt("b")]));
        assert_eq!(kept[1]["admissions_settled"], 1);
        assert_eq!(kept[2]["admissions"], json!([held]));
        for record in &kept {
            let decision = crate::session::checkpoint_decision(record);
            assert_eq!(
                record["checkpoint_id"],
                crate::session::checkpoint_id(&decision)
            );
        }
    }

    #[test]
    fn a_writer_waiting_on_the_old_ledger_appends_to_the_new_one() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("atoms.jsonl");
        write_lines(&path, &[json!({"atom_id": "atom_a"})]);
        let held = crate::store::open_locked_ledger(&path).expect("lock");
        let writer = {
            let path = path.clone();
            std::thread::spawn(move || {
                crate::store::append_jsonl(&path, &json!({"atom_id": "atom_b"})).expect("append")
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Swap a new ledger in while the writer waits on the old one's lock.
        let staged = temp.path().join("atoms.jsonl.new");
        write_lines(&staged, &[json!({"atom_id": "atom_a"})]);
        fs::rename(&staged, &path).expect("swap");
        drop(held);
        writer.join().expect("writer");
        let kept = records(&path);
        assert_eq!(
            kept,
            [json!({"atom_id": "atom_a"}), json!({"atom_id": "atom_b"})]
        );
    }
}
