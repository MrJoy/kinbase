//! The Personal store's Kindex (product.md: Personal is Kindex).
//!
//! Host transcripts are Personal by provenance. Kinbase keeps them in its
//! private journal, and with `[personal] kindex_executable` configured it also
//! hands what the ingest scan read of each transcript to the Kindex graph at
//! the Personal root, where `kinbase recall` answers the principal's own
//! questions from it. Only the launcher and Personal worker hold the Personal
//! root, so both steps run there. Nothing Kindex reads or returns enters a
//! shared store, a projection or a host hook.
//!
//! The hand-off exports the scan's records, so the scan's bounds apply (a
//! transcript over the per-file bound is skipped, a directory over its budget
//! is refused) and nothing is read twice. Each transcript is kept for its
//! retention: a `.retention` sidecar's `private_retention_seconds`, else
//! `[personal] kindex_retention_seconds`, else the private raw-session default,
//! counted from the transcript's last change. Kindex is told when each
//! conversation expires, and a ledger under the Personal root records what was
//! handed over, so a conversation past its retention, or whose transcript is
//! gone from a source that is ingested again, is retracted from Kindex with
//! everything Kindex derived from it.
//!
//! Kindex runs under the classifier's executable rules: an absolute regular
//! file owned by the effective user, no group/other write anywhere up its
//! directory chain, its pinned SHA-256 rechecked through the descriptor that
//! is executed, and a scrubbed environment plus only the variables the
//! configuration names. The Personal root is checked (not a symlink, owned by
//! the effective user, mode 0700) before every invocation.

use crate::config::PersonalKindexConfig;
use crate::error::ContractError;
use crate::lifecycle::SourceRecord;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The directory Kindex keeps the Personal graph in, inside the Personal root.
const KINDEX_DIR: &str = "personal-kindex";
/// Written into that directory when Kinbase creates it. Kindex is only ever
/// given a directory Kinbase made for it, never one another Kindex process (a
/// daemon or its cron, with their own config) may already use.
const KINDEX_MARKER: &str = ".kinbase-personal-kindex";
const HANDOFF_DIR: &str = ".kinbase-handoff";
const LEDGER_FILE: &str = "conversations.json";
const LEDGER_LOCK: &str = "conversations.lock";
const LEDGER_LIMIT: usize = 64 * 1024 * 1024;

/// One transcript line (Claude Code or Codex JSON Lines) as a Kindex message,
/// with the line's timestamp. `None` for a line with no message text.
fn transcript_message(map: &Map<String, Value>) -> Option<(Value, Option<String>)> {
    let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
    if matches!(kind, "stop" | "session_end") {
        return None;
    }
    let body: &Map<String, Value> = if kind == "response_item" {
        map.get("payload").and_then(Value::as_object)?
    } else {
        map.get("message").and_then(Value::as_object).unwrap_or(map)
    };
    let content = crate::lifecycle::content_text(body).filter(|t| !t.trim().is_empty())?;
    let role = body
        .get("role")
        .and_then(Value::as_str)
        .filter(|role| !role.is_empty())
        .unwrap_or(if kind.is_empty() { "user" } else { kind });
    let mut message = json!({ "role": role, "content": content });
    if let Some(name) = body.get("name").and_then(Value::as_str) {
        message["name"] = json!(name);
    }
    let timestamp = map
        .get("timestamp")
        .or_else(|| map.get("ts"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some((message, timestamp))
}

/// The host's own session id on a transcript line, when it carries one.
fn native_session_id(map: &Map<String, Value>) -> Option<String> {
    map.get("sessionId")
        .or_else(|| map.get("session_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .map(str::to_owned)
}

fn day_of(timestamp: &str) -> Option<String> {
    let day = timestamp.get(..10)?;
    chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
        .ok()
        .map(|_| day.to_owned())
}

fn day_of_seconds(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(|time| time.date_naive().to_string())
        .unwrap_or_default()
}

/// A transcript's lines as Kindex conversations, one per calendar day its
/// messages carry: a session resumed on later days keeps each message under
/// its own date instead of the session's first. A message without a timestamp
/// joins the day before it (or the first day). Each conversation's id is
/// `{base}#{day}`, or `{base}#undated` when no line has a date.
pub fn transcript_segments<'a>(base: &str, lines: impl IntoIterator<Item = &'a str>) -> Vec<Value> {
    // (day, its first timestamp, its messages), in order of first appearance.
    let mut days: Vec<(String, Option<String>, Vec<Value>)> = Vec::new();
    let mut current: Option<usize> = None;
    let mut lead: Vec<Value> = Vec::new();
    for line in lines {
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some((message, timestamp)) = transcript_message(&map) else {
            continue;
        };
        match timestamp.as_deref().and_then(day_of) {
            Some(day) => {
                let index = match days.iter().position(|(known, _, _)| *known == day) {
                    Some(index) => index,
                    None => {
                        days.push((day, timestamp.clone(), Vec::new()));
                        days.len() - 1
                    }
                };
                // Lines before the first dated one belong to its day.
                days[index].2.append(&mut lead);
                days[index].2.push(message);
                current = Some(index);
            }
            None => match current {
                Some(index) => days[index].2.push(message),
                None => lead.push(message),
            },
        }
    }
    let mut segments: Vec<Value> = days
        .into_iter()
        .map(|(day, first, messages)| json!({"id": format!("{base}#{day}"), "date": first, "messages": messages}))
        .collect();
    if segments.is_empty() && !lead.is_empty() {
        segments
            .push(json!({"id": format!("{base}#undated"), "date": Value::Null, "messages": lead}));
    }
    segments.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    segments
}

/// What the ledger keeps for one handed-off transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEntry {
    /// The transcript file, canonical.
    path: String,
    /// Unix seconds past which it is retracted.
    deadline: i64,
    /// The Kindex conversation ids it was handed over as.
    segments: Vec<String>,
}

/// What earlier hand-offs sent, and which scan settled each source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ledger {
    /// Handed-off transcripts, by conversation base.
    conversations: BTreeMap<String, LedgerEntry>,
    /// For each source handed off (canonical), when the newest scan of it
    /// began (Unix nanoseconds). That scan settled every transcript under it,
    /// listed or not, so a scan begun earlier saw an older state of any of
    /// them and neither imports, restores nor retracts one.
    #[serde(default)]
    sources: BTreeMap<String, i128>,
}

/// What one hand-off sends to Kindex and the ledger it leaves.
#[derive(Debug, Default)]
struct Plan {
    entries: Vec<Value>,
    ledger: Ledger,
    conversations: usize,
    transcripts: usize,
    expired: usize,
    removed: usize,
    /// Transcripts a later scan has already handed over, left as they are.
    stale: usize,
}

/// A path's canonical form. A path that no longer exists takes its nearest
/// existing ancestor's, so a removed transcript or source still matches what
/// was recorded while it existed.
fn canonical(path: &Path) -> PathBuf {
    if let Ok(path) = std::fs::canonicalize(path) {
        return path;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            canonical(parent).join(name)
        }
        _ => std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// The conversation identity of one transcript: the host's session id (the
/// file name when the transcript has none) and a digest of the transcript's
/// canonical path, so equal file names in different directories, or a session
/// id reused by another host, never share a conversation.
fn conversation_base(path: &Path, session: Option<&str>) -> String {
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.trim_end_matches(".jsonl"))
        .unwrap_or("transcript");
    let digest = crate::hash::sha256_text(&path.to_string_lossy());
    format!("{}@{}", session.unwrap_or(stem), &digest[..16])
}

fn retract(entries: &mut Vec<Value>, segments: &[String]) {
    entries.extend(
        segments
            .iter()
            .map(|id| json!({ "id": id, "retracted": true })),
    );
}

/// Plans a hand-off of `records` (one scan of `source`, begun at
/// `scan_started`), given what the ledger says earlier hand-offs sent.
/// `present` is every transcript file the scan listed and `read` every one it
/// read in full, canonical.
#[allow(clippy::too_many_arguments)]
fn plan(
    default_retention: i64,
    records: &[SourceRecord],
    source: &Path,
    present: &BTreeSet<PathBuf>,
    read: &BTreeSet<PathBuf>,
    scan_started: i128,
    mut ledger: Ledger,
    now: i64,
) -> Plan {
    let mut out = Plan::default();
    // A transcript under a source a scan begun after this one has settled is
    // left as that scan left it, present or not: this one saw an older state.
    let settled = ledger.sources.clone();
    let newer = |path: &Path| {
        settled
            .iter()
            .any(|(source, started)| *started > scan_started && path.starts_with(source))
    };
    let mut stale: BTreeSet<String> = BTreeSet::new();
    let mut by_file: BTreeMap<
        PathBuf,
        (
            std::sync::Arc<crate::lifecycle::TranscriptOrigin>,
            Vec<&SourceRecord>,
        ),
    > = BTreeMap::new();
    for record in records {
        let Some(origin) = &record.transcript else {
            continue;
        };
        if record.disposition == "terminal" {
            continue;
        }
        by_file
            .entry(canonical(&origin.path))
            .or_insert_with(|| (origin.clone(), Vec::new()))
            .1
            .push(record);
    }
    let mut handled: BTreeSet<String> = BTreeSet::new();
    for (path, (origin, file_records)) in &by_file {
        let key = path.to_string_lossy().into_owned();
        let lines: Vec<String> = file_records
            .iter()
            .map(|record| String::from_utf8_lossy(&record.content).into_owned())
            .collect();
        let session = lines.iter().find_map(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| value.as_object().and_then(native_session_id))
        });
        let base = conversation_base(path, session.as_deref());
        handled.insert(base.clone());
        if newer(path) {
            stale.insert(key);
            continue;
        }
        let retention = origin
            .declared_retention_seconds
            .unwrap_or(default_retention);
        let deadline = origin.modified.unwrap_or(now).saturating_add(retention);
        // Kindex expires by calendar day, so it is told the deadline's day; the
        // ledger keeps the exact deadline, and `recall` and every hand-off
        // retract a conversation once it passes.
        let expires = day_of_seconds(deadline);
        let previous = ledger.conversations.remove(&base);
        if deadline <= now {
            out.expired += 1;
            if let Some(previous) = previous {
                retract(&mut out.entries, &previous.segments);
            }
            continue;
        }
        let mut segments = transcript_segments(&base, lines.iter().map(String::as_str));
        if segments.is_empty() {
            if let Some(previous) = previous {
                retract(&mut out.entries, &previous.segments);
            }
            continue;
        }
        let ids: Vec<String> = segments
            .iter()
            .filter_map(|segment| segment["id"].as_str().map(str::to_owned))
            .collect();
        if let Some(previous) = previous {
            let gone: Vec<String> = previous
                .segments
                .into_iter()
                .filter(|id| !ids.contains(id))
                .collect();
            retract(&mut out.entries, &gone);
        }
        for segment in &mut segments {
            segment["expires"] = json!(expires);
        }
        out.conversations += segments.len();
        out.transcripts += 1;
        out.entries.extend(segments);
        ledger.conversations.insert(
            base,
            LedgerEntry {
                path: key,
                deadline,
                segments: ids,
            },
        );
    }
    // Earlier hand-offs: past retention, or their transcript is gone from
    // this source.
    let scope = canonical(source);
    let mut kept = BTreeMap::new();
    for (base, entry) in std::mem::take(&mut ledger.conversations) {
        if handled.contains(&base) {
            kept.insert(base, entry);
            continue;
        }
        let path = PathBuf::from(&entry.path);
        if entry.deadline <= now {
            out.expired += 1;
            retract(&mut out.entries, &entry.segments);
        } else if !path.starts_with(&scope) {
            kept.insert(base, entry);
        } else if newer(&path) {
            stale.insert(entry.path.clone());
            kept.insert(base, entry);
        } else if !present.contains(&path) || read.contains(&path) {
            // Gone from the source, or read by this scan and no longer holding
            // this conversation (emptied, or now another session).
            out.removed += 1;
            retract(&mut out.entries, &entry.segments);
        } else {
            kept.insert(base, entry);
        }
    }
    ledger.conversations = kept;
    let generation = ledger
        .sources
        .entry(scope.to_string_lossy().into_owned())
        .or_insert(scan_started);
    *generation = (*generation).max(scan_started);
    out.stale = stale.len();
    out.ledger = ledger;
    out
}

/// The Personal root, checked before Kindex is given it: not a symlink (a
/// trailing separator would resolve one), created if missing, owned by the
/// effective user and mode 0700. Returns its canonical path.
pub(crate) fn protect_root(data_root: &Path) -> Result<PathBuf, ContractError> {
    use std::os::unix::fs::MetadataExt;
    let root: PathBuf = data_root.components().collect();
    crate::paths::ensure_private_dir(&root, "Personal data root")?;
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| ContractError::unreadable("Personal data root", &error))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != euid {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "Personal data root is not a directory owned by the current user",
            "Point [personal] data_root at a directory you own; it is kept at mode 0700.",
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "Personal data root is readable or writable by others",
            format!("Run `chmod 0700 {}` and retry.", root.display()),
        ));
    }
    std::fs::canonicalize(&root)
        .map_err(|error| ContractError::unreadable("Personal data root", &error))
}

/// The Personal Kindex directory under the (protected) Personal root, created
/// by Kinbase with its marker; an existing directory without the marker is
/// refused, as is a graph an earlier build kept in the Personal root itself.
/// Returns its canonical path.
pub(crate) fn kindex_root(data_root: &Path) -> Result<PathBuf, ContractError> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let personal = protect_root(data_root)?;
    if std::fs::symlink_metadata(personal.join(HANDOFF_DIR)).is_ok() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "the Personal root holds a Personal Kindex graph from an earlier build, outside its own directory",
            format!(
                "Remove that graph (the Kindex files and {HANDOFF_DIR} in {}) and retry; Kinbase now keeps it in {KINDEX_DIR}/.",
                personal.display()
            ),
        ));
    }
    let root = personal.join(KINDEX_DIR);
    if std::fs::symlink_metadata(&root).is_err() {
        // Made under another name and moved into place whole, so a concurrent
        // run never sees the directory without its marker.
        let fresh = personal.join(format!(".{KINDEX_DIR}-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&fresh)
            .map_err(|error| ContractError::io("Personal Kindex directory", error))?;
        crate::paths::write_atomic(&fresh.join(KINDEX_MARKER), b"kinbase\n", 0o600, false)?;
        if std::fs::rename(&fresh, &root).is_err() {
            let _ = std::fs::remove_dir_all(&fresh);
        }
    }
    let refused = || {
        ContractError::refused(
            "CONFIG_INVARIANT",
            format!("{} was not created by Kinbase", root.display()),
            format!(
                "Kinbase gives Kindex only a directory it made, so no other Kindex process works on the Personal graph; move {} aside and retry.",
                root.display()
            ),
        )
    };
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| ContractError::unreadable("Personal Kindex directory", &error))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != euid {
        return Err(refused());
    }
    if !std::fs::symlink_metadata(root.join(KINDEX_MARKER)).is_ok_and(|marker| marker.is_file()) {
        return Err(refused());
    }
    if metadata.mode() & 0o077 != 0 {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| ContractError::io("Personal Kindex directory", error))?;
    }
    Ok(root)
}

/// Removes what an interrupted run left in the hand-off directory. Staging
/// directories are made only while the ledger is locked, as it is when this
/// runs, so none is in use; a per-run file (config, team knowledge) is removed
/// once it is older than any Kindex run lasts.
fn sweep(dir: &Path, cfg: &PersonalKindexConfig) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let limit = std::time::Duration::from_secs(cfg.timeout_seconds.saturating_add(60));
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == LEDGER_FILE || name == LEDGER_LOCK {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        } else if metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > limit)
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// The hand-off directory under the Personal root, private and not a symlink.
fn handoff_dir(root: &Path) -> Result<PathBuf, ContractError> {
    let dir = root.join(HANDOFF_DIR);
    crate::paths::ensure_private_dir(&dir, "Kindex hand-off directory")?;
    Ok(dir)
}

fn load_ledger(dir: &Path) -> Result<Ledger, ContractError> {
    let path = dir.join(LEDGER_FILE);
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(Ledger::default());
    }
    let bytes = crate::paths::read_bounded(&path, LEDGER_LIMIT, "Kindex hand-off ledger")?;
    if let Ok(ledger) = serde_json::from_slice::<Ledger>(&bytes) {
        return Ok(ledger);
    }
    // A ledger written before scans were recorded holds only conversations.
    serde_json::from_slice::<BTreeMap<String, LedgerEntry>>(&bytes).map(|conversations| Ledger {
        conversations,
        ..Ledger::default()
    }).map_err(|error| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            format!("Kindex hand-off ledger is unreadable ({error})"),
            "Restore or remove the ledger under the Personal root's .kinbase-handoff directory.",
        )
    })
}

fn save_ledger(dir: &Path, ledger: &Ledger) -> Result<(), ContractError> {
    let bytes =
        serde_json::to_vec(ledger).map_err(|error| ContractError::internal(error.to_string()))?;
    crate::paths::write_atomic(&dir.join(LEDGER_FILE), &bytes, 0o600, false).map(|_| ())
}

/// The sections of a Kindex config Kinbase checks and passes on. Kindex's
/// others (channels, reminders, agents, profiles and the rest) are refused:
/// what they would reach is not checked.
const CONFIG_SECTIONS: [&str; 5] = ["llm", "embedding", "ask", "conversations", "budget"];
const LLM_KEYS: [&str; 7] = [
    "enabled",
    "provider",
    "model",
    "api_key_env",
    "cache_control",
    "codebook_min_weight",
    "tier2_max_tokens",
];
const EMBEDDING_KEYS: [&str; 11] = [
    "provider",
    "model",
    "api_key_env",
    "dimensions",
    "strategy",
    "chunk_chars",
    "chunk_overlap_chars",
    "max_group_chunks",
    "reindex_max_jobs",
    "reindex_max_queue",
    "drain_time_budget",
];
/// The providers Kindex calls over the network, for its LLM and embeddings.
const LLM_PROVIDERS: [&str; 2] = ["anthropic", "openai"];
const EMBEDDING_PROVIDERS: [&str; 3] = ["voyage", "openai", "gemini"];

fn config_refused(message: impl Into<String>) -> ContractError {
    ContractError::refused(
        "CONFIG_INVARIANT",
        message,
        "Fix the Kindex config named by [personal] kindex_config; nothing was sent to Kindex.",
    )
}

/// One section of the config (created empty when absent), with only `keys`.
fn config_section<'a>(
    sections: &'a mut serde_json::Map<String, Value>,
    name: &str,
    keys: &[&str],
) -> Result<&'a mut serde_json::Map<String, Value>, ContractError> {
    let Some(section) = sections
        .entry(name)
        .or_insert_with(|| json!({}))
        .as_object_mut()
    else {
        return Err(config_refused(format!(
            "kindex_config `{name}` must be an object"
        )));
    };
    if let Some(key) = section.keys().find(|key| !keys.contains(&key.as_str())) {
        return Err(config_refused(format!(
            "kindex_config sets `{name}.{key}`, which Kinbase does not check"
        )));
    }
    Ok(section)
}

/// A string setting; any other type is refused, since Kindex might read it
/// differently.
fn config_text(
    section: &serde_json::Map<String, Value>,
    name: &str,
    key: &str,
) -> Result<Option<String>, ContractError> {
    match section.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(config_refused(format!(
            "kindex_config `{name}.{key}` must be a string"
        ))),
    }
}

/// Resolves the config every Kindex run is given: `kindex_config` (JSON;
/// Kindex reads JSON as YAML) or, without one, an empty one. Embeddings stay
/// local unless a provider is named. Returns it and the off-machine
/// processors it names: the LLM when enabled (`kin digest`, `kin ask`) and the
/// embedding provider unless local (`kin digest` embeds what it stores,
/// `kin ask` the question). Anything Kindex might read differently is refused.
/// A processor a resolved config names: its provider, model and the variable
/// Kindex reads its key from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Processor {
    provider: String,
    model: String,
    key_env: String,
}

/// The variable a processor's key is read from: named, one variable, ending in
/// `_API_KEY`, so it is the credential that identifies the account.
fn key_env(section: &serde_json::Map<String, Value>, name: &str) -> Result<String, ContractError> {
    config_text(section, name, "api_key_env")?
        .filter(|key| {
            key.len() > "_API_KEY".len()
                && key.ends_with("_API_KEY")
                && key
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        })
        .ok_or_else(|| {
            config_refused(format!(
                "kindex_config `{name}.api_key_env` must name the one variable, ending in _API_KEY, that holds the account's key"
            ))
        })
}

fn resolve_config(cfg: &PersonalKindexConfig) -> Result<(Value, Vec<Processor>), ContractError> {
    let mut config: Value = match &cfg.config {
        None => json!({}),
        Some(path) => {
            let bytes = crate::paths::read_bounded(path, 1024 * 1024, "Kindex config")?;
            serde_json::from_slice(&bytes).map_err(|_| {
                config_refused(
                    "kindex_config is not JSON, so what Kindex would send Personal text to cannot be checked",
                )
            })?
        }
    };
    let Some(sections) = config.as_object_mut() else {
        return Err(config_refused("kindex_config must be a JSON object"));
    };
    if let Some(key) = sections
        .keys()
        .find(|key| !CONFIG_SECTIONS.contains(&key.as_str()))
    {
        return Err(config_refused(format!(
            "kindex_config sets `{key}`; Kinbase passes Kindex only {}",
            CONFIG_SECTIONS.join(", ")
        )));
    }
    for name in ["ask", "conversations", "budget"] {
        if sections
            .get(name)
            .is_some_and(|section| !section.is_object())
        {
            return Err(config_refused(format!(
                "kindex_config `{name}` must be an object"
            )));
        }
    }
    let mut processors = Vec::new();
    let llm = config_section(sections, "llm", &LLM_KEYS)?;
    let enabled = match llm.get("enabled") {
        None => false,
        Some(Value::Bool(enabled)) => *enabled,
        // Kindex would read "true" or 1 as true.
        Some(_) => {
            return Err(config_refused(
                "kindex_config `llm.enabled` must be true or false",
            ));
        }
    };
    let provider = config_text(llm, "llm", "provider")?;
    let model = config_text(llm, "llm", "model")?;
    config_text(llm, "llm", "api_key_env")?;
    if enabled {
        // Named, not left to Kindex's defaults: the processor authorized is
        // the one used.
        let (Some(provider), Some(model)) =
            (provider, model.filter(|model| !model.trim().is_empty()))
        else {
            return Err(config_refused(
                "kindex_config enables the LLM without naming `llm.provider` and `llm.model`",
            ));
        };
        if !LLM_PROVIDERS.contains(&provider.as_str()) {
            return Err(config_refused(format!(
                "kindex_config `llm.provider` is `{provider}`; it must be {}",
                LLM_PROVIDERS.join(" or ")
            )));
        }
        processors.push(Processor {
            key_env: key_env(llm, "llm")?,
            provider,
            model,
        });
    }
    let embedding = config_section(sections, "embedding", &EMBEDDING_KEYS)?;
    let model = config_text(embedding, "embedding", "model")?;
    config_text(embedding, "embedding", "api_key_env")?;
    config_text(embedding, "embedding", "strategy")?;
    match config_text(embedding, "embedding", "provider")?.as_deref() {
        // Unnamed, embeddings stay local (Kindex's own default is Voyage).
        None => {
            embedding.insert("provider".to_owned(), json!("local"));
        }
        Some("local") => {}
        Some(provider) if EMBEDDING_PROVIDERS.contains(&provider) => {
            let Some(model) = model.filter(|model| !model.trim().is_empty()) else {
                return Err(config_refused(format!(
                    "kindex_config names the `{provider}` embedding provider without `embedding.model`"
                )));
            };
            processors.push(Processor {
                provider: provider.to_owned(),
                model,
                key_env: key_env(embedding, "embedding")?,
            });
        }
        Some(provider) => {
            return Err(config_refused(format!(
                "kindex_config `embedding.provider` is `{provider}`; it must be local, {}",
                EMBEDDING_PROVIDERS.join(", ")
            )));
        }
    }
    Ok((config, processors))
}

/// The resolved Kindex config of one hand-off or recall, written under the
/// hand-off directory for it alone (and removed after), and the processors it
/// names. Every Kindex run is passed exactly this file, so Kindex loads no
/// global, project or profile config.
struct Setup {
    config: PathBuf,
    processors: Vec<Processor>,
    /// The config enables Kindex's LLM, so `kin digest` has work to do.
    llm: bool,
}

/// What an authorized run is given and reports: the processors' credentials
/// (Kindex's only environment) and, for the receipt, each processor.
struct Authorized {
    env: Vec<(String, String)>,
    processors: Vec<Value>,
}

/// A credential from Kinbase's environment (in tests, from a per-thread map).
fn credential(name: &str) -> Option<String> {
    #[cfg(test)]
    if let Some(value) = tests::CREDENTIALS.with(|map| map.borrow().get(name).cloned()) {
        return Some(value);
    }
    std::env::var(name).ok()
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.config);
    }
}

fn setup(cfg: &PersonalKindexConfig, dir: &Path) -> Result<Setup, ContractError> {
    let (config, processors) = resolve_config(cfg)?;
    let bytes =
        serde_json::to_vec(&config).map_err(|error| ContractError::internal(error.to_string()))?;
    let path = dir.join(format!("kindex-config-{}.json", uuid::Uuid::new_v4()));
    crate::paths::write_atomic(&path, &bytes, 0o600, false)?;
    Ok(Setup {
        config: path,
        llm: config["llm"]["enabled"] == json!(true),
        processors,
    })
}

impl Setup {
    /// Refuses, before any Personal byte reaches Kindex for a model call,
    /// unless every processor the config names is explicitly authorized in
    /// `[personal] kindex_processors`: the same provider, model and key
    /// variable, and a key whose SHA-256 is the authorized account's.
    fn authorize(&self, cfg: &PersonalKindexConfig) -> Result<Authorized, ContractError> {
        let mut authorized = Authorized {
            env: Vec::new(),
            processors: Vec::new(),
        };
        for processor in &self.processors {
            let named = format!("{}:{}", processor.provider, processor.model);
            let unauthorized = |why: &str| {
                ContractError::integrity(
                    "PROCESSOR_UNAUTHORIZED",
                    format!("Kindex would send Personal-store text to `{named}`, {why}"),
                    format!(
                        "Add a [[personal.kindex_processors]] entry for `{named}` (provider, model, key_env, key_sha256, retention) only if that provider, account and retention mode are authorized for historical Personal data, or configure Kindex to run locally; nothing was sent."
                    ),
                )
            };
            let Some(grant) = cfg.processors.iter().find(|grant| {
                grant.provider == processor.provider
                    && grant.model == processor.model
                    && grant.key_env == processor.key_env
            }) else {
                return Err(unauthorized(
                    "which no [[personal.kindex_processors]] entry authorizes with that key variable",
                ));
            };
            let Some(key) = credential(&processor.key_env) else {
                return Err(unauthorized(&format!(
                    "but {} is not set",
                    processor.key_env
                )));
            };
            if crate::hash::sha256_text(&key) != grant.key_sha256 {
                return Err(unauthorized(&format!(
                    "but {} holds the key of an account other than the authorized one",
                    processor.key_env
                )));
            }
            if !authorized
                .env
                .iter()
                .any(|(name, _)| *name == processor.key_env)
            {
                authorized.env.push((processor.key_env.clone(), key));
            }
            authorized.processors.push(json!({
                "provider": processor.provider,
                "model": processor.model,
                "account": &grant.key_sha256[..16],
                "retention": grant.retention,
            }));
        }
        Ok(authorized)
    }
}

/// Runs Kindex with `env` (an authorized run's credentials; nothing else of
/// Kinbase's environment) and `input` on its standard input.
fn run(
    cfg: &PersonalKindexConfig,
    args: Vec<String>,
    env: &[(String, String)],
    input: &[u8],
) -> Result<Vec<u8>, ContractError> {
    crate::sandbox::run_verified_executable_with_env(
        &cfg.executable,
        &cfg.executable_sha256,
        &args,
        env,
        input,
        std::time::Duration::from_secs(cfg.timeout_seconds),
    )
    .map_err(|mut error| {
        error.message = format!("Personal Kindex: {}", error.message);
        error
    })
}

fn common_args(root: &Path, setup: &Setup) -> Vec<String> {
    vec![
        "--data-dir".to_owned(),
        root.to_string_lossy().into_owned(),
        "--config".to_owned(),
        setup.config.to_string_lossy().into_owned(),
    ]
}

/// Sends `entries` (conversations and retractions) to Kindex through a private
/// staging directory under the hand-off directory, removed afterwards.
fn ingest(
    cfg: &PersonalKindexConfig,
    root: &Path,
    dir: &Path,
    setup: &Setup,
    entries: &[Value],
) -> Result<(), ContractError> {
    let staging = dir.join(uuid::Uuid::new_v4().to_string());
    crate::paths::ensure_private_dir(&staging, "Kindex hand-off staging")?;
    let result = (|| {
        for (index, entry) in entries.iter().enumerate() {
            let bytes = serde_json::to_vec(entry)
                .map_err(|error| ContractError::internal(error.to_string()))?;
            crate::paths::write_atomic(
                &staging.join(format!("{index:06}.json")),
                &bytes,
                0o600,
                false,
            )?;
        }
        // Every staged entry is sent: without a limit Kindex caps an ingest at
        // 50 conversations, and the ledger records the whole batch as delivered.
        let mut args = vec![
            "ingest".to_owned(),
            "conversations".to_owned(),
            "--limit".to_owned(),
            "0".to_owned(),
            "--directory".to_owned(),
        ];
        args.push(staging.to_string_lossy().into_owned());
        args.extend(common_args(root, setup));
        // Storing makes no model call, so Kindex is given no credential.
        run(cfg, args, &[], &[]).map(|_| ())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result
}

fn seconds(now: &str) -> Result<i64, ContractError> {
    crate::time::parse_rfc3339_millis(now)
        .map(|time| time.timestamp())
        .map_err(ContractError::invariant)
}

/// Hands one scan of host transcripts at `source` to the Personal Kindex graph
/// (and digests them when configured), and retracts what is past retention or
/// gone from the source. Returns a receipt.
pub fn hand_off(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    source: &Path,
    scan: &crate::lifecycle::SourceScan,
    now: &str,
) -> Result<Value, ContractError> {
    let now = seconds(now)?;
    // What the scan itself listed and read: the files as they are now may have
    // changed since, and another hand-off may already have sent the change.
    let Some(seen) = &scan.transcripts else {
        return Err(ContractError::internal(
            "a transcript hand-off needs what its scan listed and read",
        ));
    };
    let root = kindex_root(data_root)?;
    let dir = handoff_dir(&root)?;
    let setup = setup(cfg, &dir)?;
    let _lock = crate::paths::lock_file(&dir.join(LEDGER_LOCK), "Kindex hand-off ledger lock")?;
    sweep(&dir, cfg);
    let ledger = load_ledger(&dir)?;
    let present: BTreeSet<PathBuf> = seen.listed.iter().map(|path| canonical(path)).collect();
    let read: BTreeSet<PathBuf> = seen.read.iter().map(|path| canonical(path)).collect();
    let default_retention = cfg
        .retention_seconds
        .unwrap_or(crate::lifecycle::PRIVATE_RAW_RETENTION_SECONDS);
    let plan = plan(
        default_retention,
        &scan.records,
        source,
        &present,
        &read,
        seen.started_at_nanos,
        ledger,
        now,
    );
    let mut receipt = json!({
        "conversations": plan.conversations,
        "transcripts": plan.transcripts,
        "retracted_expired": plan.expired,
        "retracted_removed": plan.removed,
        "stale": plan.stale,
        "digested": false,
        "embedded": false
    });
    if plan.entries.is_empty() {
        save_ledger(&dir, &plan.ledger)?;
        return Ok(receipt);
    }
    // Storing the conversations is local to the Personal root; the digest
    // sends them to a model, so it runs only for an authorized processor.
    ingest(cfg, &root, &dir, &setup, &plan.entries)?;
    save_ledger(&dir, &plan.ledger)?;
    if cfg.digest && plan.conversations > 0 {
        match setup.authorize(cfg) {
            // `kin digest` needs the LLM: without one it stops before doing
            // anything, embeddings included. With only an embedding provider,
            // its queue is drained on its own. With neither, nothing runs.
            Ok(authorized) if setup.llm || !authorized.processors.is_empty() => {
                let mut args = if setup.llm {
                    vec!["digest".to_owned()]
                } else {
                    vec!["embed".to_owned(), "drain".to_owned()]
                };
                args.extend(common_args(&root, &setup));
                run(cfg, args, &authorized.env, &[])?;
                receipt["digested"] = json!(setup.llm);
                receipt["embedded"] = json!(true);
                receipt["processors"] = json!(authorized.processors);
            }
            Ok(_) => {}
            Err(refused) => {
                receipt["digest_refused"] =
                    crate::output::error_document(&refused)["error"].clone();
            }
        }
    }
    Ok(receipt)
}

/// Retracts the conversations whose retention has passed. Returns how many.
fn purge_expired(
    cfg: &PersonalKindexConfig,
    root: &Path,
    dir: &Path,
    setup: &Setup,
    now: i64,
) -> Result<usize, ContractError> {
    let _lock = crate::paths::lock_file(&dir.join(LEDGER_LOCK), "Kindex hand-off ledger lock")?;
    sweep(dir, cfg);
    let mut ledger = load_ledger(dir)?;
    let (due, kept): (BTreeMap<_, _>, BTreeMap<_, _>) = std::mem::take(&mut ledger.conversations)
        .into_iter()
        .partition(|(_, entry)| entry.deadline <= now);
    if due.is_empty() {
        return Ok(0);
    }
    let mut entries = Vec::new();
    for entry in due.values() {
        retract(&mut entries, &entry.segments);
    }
    ingest(cfg, root, dir, setup, &entries)?;
    ledger.conversations = kept;
    save_ledger(dir, &ledger)?;
    Ok(due.len())
}

/// Answers the principal's question from the Personal Kindex graph, with
/// `team` (shared knowledge a projection released for the question, one item
/// per line, annotated) alongside it. Shared facts may flow into the Personal
/// side; nothing flows back. Conversations past their retention are retracted
/// first.
/// A recall's answer and what was sent for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Recalled {
    pub answer: String,
    /// The off-machine processors the answer could use, each with its account
    /// (the key's SHA-256, abbreviated) and retention mode (empty: local only).
    pub processors: Vec<Value>,
    /// SHA-256 of what was handed to Kindex for this purpose: the question and
    /// the team knowledge lines.
    pub sent_sha256: String,
}

pub fn recall(
    cfg: &PersonalKindexConfig,
    data_root: &Path,
    question: &str,
    as_of: Option<&str>,
    team: &[String],
    now: &str,
) -> Result<Recalled, ContractError> {
    let root = kindex_root(data_root)?;
    let dir = handoff_dir(&root)?;
    let setup = setup(cfg, &dir)?;
    // Retention is honoured whatever the processor: retractions carry no text.
    purge_expired(cfg, &root, &dir, &setup, seconds(now)?)?;
    let authorized = setup.authorize(cfg)?;
    let mut args = vec!["ask".to_owned()];
    args.extend(common_args(&root, &setup));
    if let Some(as_of) = as_of {
        args.push("--as-of".to_owned());
        args.push(as_of.to_owned());
    }
    let team_file =
        (!team.is_empty()).then(|| dir.join(format!("team-{}.txt", uuid::Uuid::new_v4())));
    if let Some(path) = &team_file {
        let lines: Vec<String> = team
            .iter()
            .map(|item| item.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        crate::paths::write_atomic(path, lines.join("\n").as_bytes(), 0o600, false)?;
        args.push("--context-file".to_owned());
        args.push(path.to_string_lossy().into_owned());
    }
    // The question goes on standard input (`-`), never on the command line,
    // where the process list would show it.
    args.push("--".to_owned());
    args.push("-".to_owned());
    let out = run(cfg, args, &authorized.env, question.as_bytes());
    if let Some(path) = &team_file {
        let _ = std::fs::remove_file(path);
    }
    let mut sent = question.to_owned();
    for item in team {
        sent.push('\n');
        sent.push_str(item);
    }
    Ok(Recalled {
        answer: String::from_utf8_lossy(&out?).trim().to_owned(),
        processors: authorized.processors,
        sent_sha256: crate::hash::sha256_text(&sent),
    })
}

/// The shared knowledge a projection releases to recall, and what recall
/// reports about it. A withheld projection releases no statements, only a
/// note that team guidance is blocked; a released statement keeps the
/// governance it carries (role, kind, store, standing, provenance, the paths
/// it governs), and a degraded authority snapshot is stated.
#[derive(Debug, Default, PartialEq)]
pub struct TeamKnowledge {
    pub items: Vec<String>,
    pub facts: usize,
    pub report: Value,
}

pub fn team_knowledge(result: &Value, statements: &BTreeMap<String, String>) -> TeamKnowledge {
    let state = result["projection_state"].as_str().unwrap_or("projected");
    let policy = result["degraded_policy"].as_str().unwrap_or_default();
    let refresh = &result["brief"]["authority_refresh"];
    let mut report = json!({
        "projection_state": state,
        "degraded_policy": policy,
        "authority_refresh": refresh["status"].as_str().unwrap_or("unknown"),
    });
    if state == "withheld" {
        report["facts"] = json!(0);
        return TeamKnowledge {
            items: vec![
                "Team guidance for this question is withheld: an open question or a degraded safety \
                 dependency blocks the shared projection. Answer from the user's own conversations \
                 and say that team guidance is pending."
                    .to_owned(),
            ],
            facts: 0,
            report,
        };
    }
    let mut items = Vec::new();
    if refresh["status"].as_str() == Some("withheld") {
        items.push(format!(
            "The team knowledge below comes from a cached authority snapshot; the refresh was withheld ({}). \
             It may be out of date.",
            refresh["code"].as_str().unwrap_or("unavailable")
        ));
    }
    if policy == "reversible_sandbox_only_experiment" {
        items.push(
            "Team knowledge is degraded for this question: treat it as guidance for reversible \
             experiments only."
                .to_owned(),
        );
    }
    let mut facts = 0;
    for selected in result["selected"].as_array().into_iter().flatten() {
        let Some(statement) = selected["fact_id"]
            .as_str()
            .and_then(|id| statements.get(id))
        else {
            continue;
        };
        let mut notes = vec![
            selected["role"]
                .as_str()
                .unwrap_or("fact")
                .replace('_', " "),
            format!(
                "{} {}",
                selected["store_kind"].as_str().unwrap_or("shared"),
                selected["atom_kind"].as_str().unwrap_or("fact")
            ),
            format!(
                "standing: {}",
                selected["standing"].as_str().unwrap_or("unknown")
            ),
            format!(
                "provenance: {}",
                selected["provenance"].as_str().unwrap_or("unknown")
            ),
        ];
        let governs: Vec<&str> = selected["governs_paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        if !governs.is_empty() {
            notes.push(format!("governs: {}", governs.join(", ")));
        }
        items.push(format!("[{}] {statement}", notes.join("; ")));
        facts += 1;
    }
    report["facts"] = json!(facts);
    TeamKnowledge {
        items,
        facts,
        report,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthorizedProcessor;
    use crate::lifecycle::TranscriptOrigin;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    const NOW: i64 = 1_791_000_000; // 2026-10-03

    thread_local! {
        /// Credentials `credential` returns in this test's thread, instead of
        /// the process environment.
        pub(super) static CREDENTIALS: std::cell::RefCell<BTreeMap<String, String>> =
            const { std::cell::RefCell::new(BTreeMap::new()) };
    }

    fn set_credential(name: &str, value: &str) {
        CREDENTIALS.with(|map| map.borrow_mut().insert(name.to_owned(), value.to_owned()));
    }

    /// Where Kindex keeps the graph under the Personal root `root`.
    fn graph(root: &Path) -> PathBuf {
        root.join(KINDEX_DIR)
    }

    fn segments(base: &str, lines: &[&str]) -> Vec<Value> {
        transcript_segments(base, lines.iter().copied())
    }

    #[test]
    fn claude_and_codex_lines_become_messages() {
        let lines = [
            r#"{"type":"user","timestamp":"2024-03-10T09:00:00.000Z","message":{"role":"user","content":"I bought a red kayak."}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Nice!"}]}}"#,
            r#"{"type":"response_item","payload":{"role":"user","name":"Caroline","content":[{"type":"input_text","text":"Hi Mel"}]}}"#,
            r#"not json"#,
            r#"{"type":"stop"}"#,
        ];
        let out = segments("s1", &lines);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "s1#2024-03-10");
        assert_eq!(out[0]["date"], "2024-03-10T09:00:00.000Z");
        let messages = out[0]["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages[0],
            json!({"role": "user", "content": "I bought a red kayak."})
        );
        assert_eq!(messages[1]["content"], "Nice!");
        assert_eq!(
            messages[2],
            json!({"role": "user", "content": "Hi Mel", "name": "Caroline"})
        );
    }

    #[test]
    fn a_transcript_without_text_is_no_conversation() {
        assert!(segments("s", &[r#"{"type":"stop"}"#]).is_empty());
    }

    #[test]
    fn a_resumed_session_keeps_each_message_under_its_own_date() {
        let lines = [
            r#"{"type":"user","message":{"role":"user","content":"before any date"}}"#,
            r#"{"type":"user","timestamp":"2024-03-10T23:50:00.000Z","message":{"role":"user","content":"day one"}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":"reply on day one"}}"#,
            r#"{"type":"user","timestamp":"2024-03-12T08:00:00.000Z","message":{"role":"user","content":"resumed on day three"}}"#,
            r#"{"type":"assistant","timestamp":"2024-03-12T08:00:05.000Z","message":{"role":"assistant","content":"reply on day three"}}"#,
        ];
        let out = segments("s", &lines);
        assert_eq!(
            out.iter()
                .map(|s| s["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["s#2024-03-10", "s#2024-03-12"]
        );
        let contents = |i: usize| -> Vec<String> {
            out[i]["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m["content"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            contents(0),
            ["before any date", "day one", "reply on day one"]
        );
        assert_eq!(contents(1), ["resumed on day three", "reply on day three"]);
        assert_eq!(out[1]["date"], "2024-03-12T08:00:00.000Z");
    }

    #[test]
    fn an_undated_transcript_is_one_undated_conversation() {
        let out = segments(
            "s",
            &[r#"{"type":"user","message":{"role":"user","content":"hi"}}"#],
        );
        assert_eq!(out[0]["id"], "s#undated");
        assert_eq!(out[0]["date"], Value::Null);
    }

    fn record(path: &Path, line: &str, modified: i64, declared: Option<i64>) -> SourceRecord {
        let mut record = SourceRecord::new("n", "u");
        record.content = line.as_bytes().to_vec();
        record.transcript = Some(Arc::new(TranscriptOrigin {
            path: path.to_path_buf(),
            modified: Some(modified),
            declared_retention_seconds: declared,
        }));
        record
    }

    const LINE: &str = r#"{"type":"user","sessionId":"sess-1","timestamp":"2026-10-03T09:00:00.000Z","message":{"role":"user","content":"hello"}}"#;

    #[test]
    fn identical_file_names_in_different_directories_are_different_conversations() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a/s.jsonl"), dir.path().join("b/s.jsonl"));
        for path in [&a, &b] {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, LINE).unwrap();
        }
        let records = vec![record(&a, LINE, NOW, None), record(&b, LINE, NOW, None)];
        let present = [canonical(&a), canonical(&b)].into_iter().collect();
        let out = plan(
            86_400,
            &records,
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            Ledger::default(),
            NOW,
        );
        let ids: BTreeSet<&str> = out
            .entries
            .iter()
            .filter_map(|e| e["id"].as_str())
            .collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.iter().all(|id| id.starts_with("sess-1@")));
        assert_eq!(out.ledger.conversations.len(), 2);
    }

    #[test]
    fn conversations_carry_their_retention_and_expired_ones_are_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present = [canonical(&path)].into_iter().collect();
        // Kept for 30 days from its last change: Kindex is told the deadline's day.
        let fresh = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            Ledger::default(),
            NOW,
        );
        assert_eq!(
            fresh.entries[0]["expires"],
            day_of_seconds(NOW + 30 * 86_400)
        );
        // A sidecar's declared retention wins over the configured one.
        let declared = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, Some(3 * 86_400))],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            Ledger::default(),
            NOW,
        );
        assert_eq!(
            declared.entries[0]["expires"],
            day_of_seconds(NOW + 3 * 86_400)
        );
        // Later, past retention: the same transcript is retracted, not resent.
        let later = NOW + 31 * 86_400;
        let expired = plan(
            30 * 86_400,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            fresh.ledger.clone(),
            later,
        );
        assert_eq!(expired.expired, 1);
        assert_eq!(
            expired.entries,
            vec![json!({"id": fresh.entries[0]["id"], "retracted": true})]
        );
        assert!(expired.ledger.conversations.is_empty());
        // Past retention with no transcript in the scan at all: retracted too.
        let swept = plan(
            30 * 86_400,
            &[],
            Path::new("/elsewhere"),
            &BTreeSet::new(),
            &BTreeSet::new(),
            0,
            fresh.ledger,
            later,
        );
        assert_eq!(swept.expired, 1);
        assert_eq!(swept.entries[0]["retracted"], true);
    }

    #[test]
    fn a_transcript_gone_from_its_source_is_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present: BTreeSet<PathBuf> = [canonical(&path)].into_iter().collect();
        let first = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            Ledger::default(),
            NOW,
        );
        // Ingesting another source leaves it alone.
        let other = plan(
            86_400 * 30,
            &[],
            Path::new("/elsewhere"),
            &BTreeSet::new(),
            &BTreeSet::new(),
            0,
            first.ledger.clone(),
            NOW,
        );
        assert!(other.entries.is_empty() && other.ledger.conversations.len() == 1);
        // The same source without it: retracted.
        let gone = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            0,
            first.ledger,
            NOW,
        );
        assert_eq!(gone.removed, 1);
        assert_eq!(gone.entries[0]["retracted"], true);
    }

    #[test]
    fn a_day_no_longer_in_the_transcript_is_retracted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let mut ledger = Ledger::default();
        let base = conversation_base(&canonical(&path), Some("sess-1"));
        std::fs::write(&path, LINE).unwrap();
        ledger.conversations.insert(
            base.clone(),
            LedgerEntry {
                path: canonical(&path).to_string_lossy().into_owned(),
                deadline: NOW + 86_400 * 30,
                segments: vec![format!("{base}#2026-09-01"), format!("{base}#2026-10-03")],
            },
        );
        let present = [canonical(&path)].into_iter().collect();
        let out = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            ledger,
            NOW,
        );
        assert!(
            out.entries
                .contains(&json!({"id": format!("{base}#2026-09-01"), "retracted": true}))
        );
        assert!(
            out.entries
                .iter()
                .any(|e| e["id"] == format!("{base}#2026-10-03") && e["messages"].is_array())
        );
    }

    #[test]
    fn an_oversized_transcript_is_never_read_or_exported() {
        // The scan skips a transcript over the per-file bound, so it yields no
        // records, and the hand-off exports only the scan's records.
        let dir = tempfile::tempdir().unwrap();
        let line = format!("{LINE}\n");
        std::fs::write(
            dir.path().join("big.jsonl"),
            line.repeat(1024 * 1024 / line.len() + 2),
        )
        .unwrap();
        std::fs::write(dir.path().join("small.jsonl"), &line).unwrap();
        let scan = crate::lifecycle::scan_transcripts(
            "claude_jsonl",
            dir.path(),
            "2026-10-03T09:00:00.000Z",
        )
        .unwrap();
        assert_eq!(scan.skipped.values().sum::<usize>(), 1);
        assert!(!scan.records.is_empty());
        assert!(
            scan.records.iter().all(|r| r
                .transcript
                .as_ref()
                .unwrap()
                .path
                .ends_with("small.jsonl"))
        );
        let present = [
            canonical(&dir.path().join("small.jsonl")),
            canonical(&dir.path().join("big.jsonl")),
        ]
        .into_iter()
        .collect();
        let out = plan(
            86_400,
            &scan.records,
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            Ledger::default(),
            NOW,
        );
        assert_eq!(out.transcripts, 1);
        assert!(
            out.ledger
                .conversations
                .values()
                .all(|entry| entry.path.ends_with("small.jsonl"))
        );
    }

    #[test]
    fn the_personal_root_is_created_private() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("personal");
        let canonical_root = protect_root(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&canonical_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn a_permissive_personal_root_is_tightened() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("personal");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        protect_root(&root).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_symlinked_personal_root_is_refused_with_or_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("personal");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(protect_root(&link).is_err());
        let mut trailing = link.into_os_string();
        trailing.push("/");
        assert!(protect_root(Path::new(&trailing)).is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn kindex_gets_only_a_directory_kinbase_made() {
        let dir = tempfile::tempdir().unwrap();
        let personal = dir.path().join("personal");
        let root = kindex_root(&personal).unwrap();
        assert_eq!(root, protect_root(&personal).unwrap().join(KINDEX_DIR));
        assert!(root.join(KINDEX_MARKER).is_file());
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(kindex_root(&personal).unwrap(), root);
        // A directory Kinbase did not make (another Kindex's data directory).
        let other = dir.path().join("other");
        std::fs::create_dir_all(other.join(KINDEX_DIR)).unwrap();
        std::fs::write(other.join(KINDEX_DIR).join("kindex.db"), "").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(kindex_root(&other).unwrap_err().code, "CONFIG_INVARIANT");
        // A graph an earlier build kept in the Personal root itself.
        let earlier = dir.path().join("earlier");
        std::fs::create_dir_all(earlier.join(HANDOFF_DIR)).unwrap();
        std::fs::set_permissions(&earlier, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(kindex_root(&earlier).unwrap_err().code, "CONFIG_INVARIANT");
    }

    #[test]
    fn an_interrupted_run_leaves_nothing_past_the_next_one() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(30 * 86_400));
        let root = base.path().join("personal");
        let dir = handoff_dir(&kindex_root(&root).unwrap()).unwrap();
        // A staging directory a killed hand-off left, and an old per-run file.
        let staging = dir.join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("000000.json"), "{}").unwrap();
        let old = dir.join("team-old.txt");
        std::fs::write(&old, "x").unwrap();
        let long_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3_600);
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let fresh = dir.join("team-fresh.txt");
        std::fs::write(&fresh, "x").unwrap();
        recall(
            &cfg,
            &root,
            "anything?",
            None,
            &[],
            &crate::time::now_rfc3339_millis(),
        )
        .unwrap();
        assert!(!staging.exists() && !old.exists());
        assert!(
            fresh.exists(),
            "a file a concurrent run may still use was removed"
        );
    }

    #[test]
    fn a_symlinked_handoff_directory_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let root = protect_root(&dir.path().join("personal")).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(HANDOFF_DIR)).unwrap();
        assert!(handoff_dir(&root).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    fn selected(fact_id: &str) -> Value {
        json!({"fact_id": fact_id, "role": "ratified_ruling", "store_kind": "company", "atom_kind": "decision",
               "standing": "ratified", "provenance": "human", "governs_paths": ["src/pay"]})
    }

    #[test]
    fn a_withheld_projection_releases_no_statements() {
        let result = json!({"projection_state": "withheld", "degraded_policy": "block_dependent_decision",
                            "selected": [selected("f1")], "brief": {"authority_refresh": {"status": "ok"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert_eq!(team.facts, 0);
        assert!(
            team.items
                .iter()
                .all(|item| !item.contains("ledger service"))
        );
        assert!(team.items[0].contains("withheld"));
        assert_eq!(team.report["projection_state"], "withheld");
    }

    #[test]
    fn released_statements_keep_their_governance() {
        let result = json!({"projection_state": "projected", "degraded_policy": "block_dependent_decision",
                            "selected": [selected("f1")], "brief": {"authority_refresh": {"status": "ok"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert_eq!(team.facts, 1);
        assert_eq!(
            team.items,
            [
                "[ratified ruling; company decision; standing: ratified; provenance: human; governs: src/pay] Use the ledger service."
            ]
        );
    }

    #[test]
    fn a_degraded_projection_says_so() {
        let result = json!({"projection_state": "projected", "degraded_policy": "reversible_sandbox_only_experiment",
                            "selected": [selected("f1")],
                            "brief": {"authority_refresh": {"status": "withheld", "code": "CACHE_EXPIRED"}}});
        let statements = BTreeMap::from([("f1".to_owned(), "Use the ledger service.".to_owned())]);
        let team = team_knowledge(&result, &statements);
        assert!(
            team.items[0].contains("cached authority snapshot")
                && team.items[0].contains("CACHE_EXPIRED")
        );
        assert!(team.items[1].contains("reversible experiments only"));
        assert_eq!(team.facts, 1);
        assert_eq!(team.report["authority_refresh"], "withheld");
    }

    /// A directory whose whole ancestry the executable rules accept.
    fn verified_base() -> PathBuf {
        [
            std::env::var_os("KINBASE_TEST_VERIFIED_DIR").map(PathBuf::from),
            Some(std::env::temp_dir()),
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
        ]
        .into_iter()
        .flatten()
        .filter_map(|dir| dir.canonicalize().ok())
        .find(|dir| {
            dir.ancestors().all(|ancestor| {
                std::fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    ancestor == Path::new("/")
                        || (!metadata.file_type().is_symlink()
                            && metadata.permissions().mode() & 0o022 == 0)
                })
            })
        })
        .expect("a directory the executable rules accept")
    }

    /// A pinned fake `kin`: `ingest` copies the staged conversations to
    /// `<data-dir>/received/`, `digest` is counted, `ask` prints its context
    /// file. Each run copies the config it is given to `<data-dir>/config.<command>`.
    fn fake_kindex(dir: &Path, retention_seconds: Option<i64>) -> PersonalKindexConfig {
        let body = concat!(
            "#!/bin/sh\n",
            "command=$1; root=; config=; context=; previous=\n",
            "for arg in \"$@\"; do case \"$previous\" in --data-dir) root=$arg ;; --config) config=$arg ;; --context-file) context=$arg ;; esac; previous=$arg; done\n",
            "[ -n \"$root\" ] && [ -f \"$config\" ] || exit 8\n",
            "cp \"$config\" \"$root/config.$command\" && printf '%s\\n' \"$@\" > \"$root/argv.$command\" && env > \"$root/env.$command\"\n",
            "case \"$command\" in\n",
            "ingest) [ \"$3 $4\" = \"--limit 0\" ] || exit 9; mkdir -p \"$root/received\" && cp \"$6\"/*.json \"$root/received/\" && ls -ld \"$6\" > \"$root/staging-mode\" ;;\n",
            "digest) echo digest >> \"$root/digests\" ;;\n",
            "embed) echo \"$2\" >> \"$root/embeds\" ;;\n",
            "ask) cat > \"$root/question\"; if [ -n \"$context\" ]; then cat \"$context\"; fi ;;\n",
            "esac\n",
        );
        let executable = dir.join("kin");
        std::fs::write(&executable, body).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        PersonalKindexConfig {
            executable,
            executable_sha256: crate::hash::sha256_bytes(body.as_bytes()),
            config: None,
            timeout_seconds: 30,
            digest: true,
            retention_seconds,
            processors: Vec::new(),
            team_knowledge: true,
        }
    }

    fn received(root: &Path) -> Vec<Value> {
        let root = graph(root);
        let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("received"))
            .map(|dir| dir.flatten().map(|entry| entry.path()).collect())
            .unwrap_or_default();
        files.sort();
        let out = files
            .iter()
            .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
            .collect();
        let _ = std::fs::remove_dir_all(root.join("received"));
        out
    }

    #[test]
    fn hand_off_sends_the_scan_protects_the_root_and_retracts_past_retention() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(2 * 86_400));
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("s.jsonl"), LINE).unwrap();
        let root = base.path().join("personal");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let now = crate::time::now_rfc3339_millis();
        let scan = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();

        let receipt = hand_off(&cfg, &root, &source, &scan, &now).unwrap();
        assert_eq!(receipt["conversations"], 1, "{receipt}");
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let sent = received(&root);
        assert_eq!(sent.len(), 1);
        assert!(sent[0]["id"].as_str().unwrap().starts_with("sess-1@"));
        assert!(sent[0]["expires"].is_string());
        assert!(
            std::fs::read_to_string(graph(&root).join("staging-mode"))
                .unwrap()
                .starts_with("drwx------")
        );
        // No LLM is configured, so there is nothing to digest and nothing runs.
        assert_eq!(receipt["digested"], false, "{receipt}");
        assert!(!graph(&root).join("digests").exists());
        let ledger = std::fs::metadata(graph(&root).join(HANDOFF_DIR).join(LEDGER_FILE)).unwrap();
        assert_eq!(ledger.permissions().mode() & 0o777, 0o600);

        // Three days later the transcript is past its retention: recall
        // retracts it from Kindex before it answers.
        let later =
            crate::time::format_rfc3339_millis(chrono::Utc::now() + chrono::Duration::days(3));
        recall(&cfg, &root, "what did I say?", None, &[], &later).unwrap();
        let retracted = received(&root);
        assert_eq!(
            retracted,
            vec![json!({"id": sent[0]["id"], "retracted": true})]
        );
        assert!(
            load_ledger(&graph(&root).join(HANDOFF_DIR))
                .unwrap()
                .conversations
                .is_empty()
        );
    }

    #[test]
    fn recall_passes_team_knowledge_through_a_private_file() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), None);
        let root = base.path().join("personal");
        let answer = recall(
            &cfg,
            &root,
            "why the ledger?",
            None,
            &["[ratified ruling] Use the\nledger.".to_owned()],
            &crate::time::now_rfc3339_millis(),
        )
        .unwrap()
        .answer;
        assert_eq!(answer, "[ratified ruling] Use the ledger.");
        // Nothing is left behind but the (empty) ledger lock.
        let leftovers: Vec<_> = std::fs::read_dir(graph(&root).join(HANDOFF_DIR))
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name() != LEDGER_LOCK)
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn an_emptied_transcript_is_retracted_and_an_oversized_one_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present: BTreeSet<PathBuf> = [canonical(&path)].into_iter().collect();
        let first = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &present,
            0,
            Ledger::default(),
            NOW,
        );
        // Truncated to nothing: still present, read, and no records.
        std::fs::write(&path, "").unwrap();
        let emptied = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &present,
            &present,
            0,
            first.ledger.clone(),
            NOW,
        );
        assert_eq!(emptied.removed, 1);
        assert_eq!(emptied.entries[0]["retracted"], true);
        // Grown past the per-file bound: present but not read, so its earlier
        // conversation stands.
        let oversized = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &present,
            &BTreeSet::new(),
            0,
            first.ledger,
            NOW,
        );
        assert!(oversized.entries.is_empty() && oversized.ledger.conversations.len() == 1);
    }

    #[test]
    fn a_transcript_inside_its_retention_is_sent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let present: BTreeSet<PathBuf> = [canonical(&path)].into_iter().collect();
        // Default 24-hour retention, changed 20 hours ago: kept, expiring on
        // its deadline's day.
        let twenty_hours_ago = NOW - 20 * 3600;
        let out = plan(
            86_400,
            &[record(&path, LINE, twenty_hours_ago, None)],
            dir.path(),
            &present,
            &present,
            0,
            Ledger::default(),
            NOW,
        );
        assert_eq!(out.transcripts, 1, "{:?}", out.entries);
        assert_eq!(
            out.entries[0]["expires"],
            day_of_seconds(twenty_hours_ago + 86_400)
        );
        // A one-hour retention on a fresh transcript is sent too.
        let short = plan(
            3600,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &present,
            &present,
            0,
            Ledger::default(),
            NOW,
        );
        assert_eq!(short.transcripts, 1);
    }

    #[test]
    fn concurrent_hand_offs_keep_each_others_ledger_entries() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(30 * 86_400));
        let root = base.path().join("personal");
        let now = crate::time::now_rfc3339_millis();
        let sources: Vec<PathBuf> = (0..6)
            .map(|i| {
                let source = base.path().join(format!("source-{i}"));
                std::fs::create_dir(&source).unwrap();
                std::fs::write(
                    source.join("s.jsonl"),
                    LINE.replace("sess-1", &format!("sess-{i}")),
                )
                .unwrap();
                source
            })
            .collect();
        std::thread::scope(|scope| {
            for source in &sources {
                let (cfg, root, now) = (&cfg, &root, &now);
                scope.spawn(move || {
                    let scan =
                        crate::lifecycle::scan_transcripts("claude_jsonl", source, now).unwrap();
                    hand_off(cfg, root, source, &scan, now).unwrap();
                });
            }
        });
        let ledger = load_ledger(&graph(&root).join(HANDOFF_DIR)).unwrap();
        assert_eq!(
            ledger.conversations.len(),
            6,
            "{:?}",
            ledger.conversations.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_older_scan_never_undoes_a_newer_hand_off() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let file: BTreeSet<PathBuf> = [canonical(&path)].into_iter().collect();
        let newer = i128::from(NOW) * 1_000_000_000;
        let older = newer - 1_000;
        // The newer scan read the transcript with content and handed it over.
        let handed = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &file,
            &file,
            newer,
            Ledger::default(),
            NOW,
        );
        assert_eq!(handed.transcripts, 1);
        // An older scan that read the same file empty runs afterwards: it must not
        // retract what the newer scan sent.
        let late_empty = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &file,
            &file,
            older,
            handed.ledger.clone(),
            NOW,
        );
        assert!(late_empty.entries.is_empty(), "{:?}", late_empty.entries);
        assert_eq!(late_empty.stale, 1);
        assert_eq!(late_empty.ledger, handed.ledger);
        // Nor resend the older content it read.
        let old_line = LINE.replace("hello", "an earlier version");
        let late_old = plan(
            86_400 * 30,
            &[record(&path, &old_line, NOW, None)],
            dir.path(),
            &file,
            &file,
            older,
            handed.ledger.clone(),
            NOW,
        );
        assert!(late_old.entries.is_empty() && late_old.stale == 1);
        // Nor call it gone because the file was not there yet when it listed.
        let late_unlisted = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            older,
            handed.ledger.clone(),
            NOW,
        );
        assert!(late_unlisted.entries.is_empty());
        // A scan at least as recent does retract an emptied transcript.
        let fresh_empty = plan(
            86_400 * 30,
            &[],
            dir.path(),
            &file,
            &file,
            newer + 1,
            handed.ledger,
            NOW,
        );
        assert_eq!(fresh_empty.removed, 1);
        assert!(fresh_empty.ledger.conversations.is_empty());
        // The retraction outlives the entry: a scan begun before it, which read
        // the transcript with content, restores nothing.
        let resurrected = plan(
            86_400 * 30,
            &[record(&path, LINE, NOW, None)],
            dir.path(),
            &file,
            &file,
            newer,
            fresh_empty.ledger.clone(),
            NOW,
        );
        assert!(resurrected.entries.is_empty(), "{:?}", resurrected.entries);
        assert_eq!(resurrected.stale, 1);
        // A transcript never handed over: a newer scan found the source
        // without it, so an older scan that read it imports nothing.
        let other = tempfile::tempdir().unwrap();
        let sub = other.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let deleted = sub.join("deleted.jsonl");
        std::fs::write(&deleted, LINE).unwrap();
        let read: BTreeSet<PathBuf> = [canonical(&deleted)].into_iter().collect();
        let absent = plan(
            86_400 * 30,
            &[],
            other.path(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            newer,
            Ledger::default(),
            NOW,
        );
        assert!(absent.entries.is_empty());
        let first_import = plan(
            86_400 * 30,
            &[record(&deleted, LINE, NOW, None)],
            other.path(),
            &read,
            &read,
            older,
            absent.ledger.clone(),
            NOW,
        );
        assert!(
            first_import.entries.is_empty(),
            "{:?}",
            first_import.entries
        );
        assert_eq!(first_import.stale, 1);
        // A scan of a source inside the newer scan's is older there too.
        let nested = plan(
            86_400 * 30,
            &[record(&deleted, LINE, NOW, None)],
            &sub,
            &read,
            &read,
            older,
            absent.ledger,
            NOW,
        );
        assert!(nested.entries.is_empty() && nested.stale == 1);
    }

    #[test]
    fn the_hand_off_reconciles_against_what_the_scan_saw() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(30 * 86_400));
        let root = base.path().join("personal");
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        let path = source.join("s.jsonl");
        std::fs::write(&path, "").unwrap();
        let now = crate::time::now_rfc3339_millis();
        // An early scan reads the transcript empty...
        let early = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        // ...a later scan reads it with content and hands it over first...
        std::fs::write(&path, LINE).unwrap();
        let later = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        hand_off(&cfg, &root, &source, &later, &now).unwrap();
        // ...then the early scan's hand-off runs: nothing it saw is newer.
        let receipt = hand_off(&cfg, &root, &source, &early, &now).unwrap();
        assert_eq!(receipt["retracted_removed"], 0, "{receipt}");
        assert_eq!(
            load_ledger(&graph(&root).join(HANDOFF_DIR))
                .unwrap()
                .conversations
                .len(),
            1
        );
        received(&root);

        // The reverse: a scan reads the transcript with content, the
        // transcript is emptied, and a later scan's hand-off retracts it first.
        let with_content =
            crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        std::fs::write(&path, "").unwrap();
        let emptied = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        let receipt = hand_off(&cfg, &root, &source, &emptied, &now).unwrap();
        assert_eq!(receipt["retracted_removed"], 1, "{receipt}");
        received(&root);
        // The earlier scan's hand-off restores none of the deleted text.
        let receipt = hand_off(&cfg, &root, &source, &with_content, &now).unwrap();
        assert_eq!(receipt["conversations"], 0, "{receipt}");
        assert_eq!(receipt["stale"], 1, "{receipt}");
        assert!(received(&root).is_empty());
        assert!(
            load_ledger(&graph(&root).join(HANDOFF_DIR))
                .unwrap()
                .conversations
                .is_empty()
        );
    }

    #[test]
    fn a_transcript_deleted_before_its_first_hand_off_stays_out() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(30 * 86_400));
        let root = base.path().join("personal");
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        let path = source.join("s.jsonl");
        std::fs::write(&path, LINE).unwrap();
        let now = crate::time::now_rfc3339_millis();
        // A scans the transcript, never handed over before; it is deleted; B
        // scans the source without it and hands off first.
        let a = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        std::fs::remove_file(&path).unwrap();
        let b = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        hand_off(&cfg, &root, &source, &b, &now).unwrap();
        // A's hand-off imports none of the deleted text.
        let receipt = hand_off(&cfg, &root, &source, &a, &now).unwrap();
        assert_eq!(receipt["conversations"], 0, "{receipt}");
        assert_eq!(receipt["stale"], 1, "{receipt}");
        assert!(received(&root).is_empty());
    }

    #[test]
    fn a_source_that_is_gone_retracts_what_it_handed_off() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), Some(30 * 86_400));
        let root = base.path().join("personal");
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("s.jsonl"), LINE).unwrap();
        let now = crate::time::now_rfc3339_millis();
        let scan = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        hand_off(&cfg, &root, &source, &scan, &now).unwrap();
        received(&root);
        std::fs::remove_dir_all(&source).unwrap();
        // What ingest passes for a source that is no longer there.
        let gone = crate::lifecycle::SourceScan {
            transcripts: Some(crate::lifecycle::TranscriptScan::begin()),
            ..crate::lifecycle::SourceScan::default()
        };
        let receipt = hand_off(&cfg, &root, &source, &gone, &now).unwrap();
        assert_eq!(receipt["retracted_removed"], 1, "{receipt}");
        assert_eq!(received(&root).len(), 1);
        // A scan without what it listed and read is refused, not guessed at.
        let unrecorded = crate::lifecycle::SourceScan::default();
        assert!(hand_off(&cfg, &root, &source, &unrecorded, &now).is_err());
    }

    fn with(
        cfg: &PersonalKindexConfig,
        config: Option<&Path>,
        processors: &[AuthorizedProcessor],
    ) -> PersonalKindexConfig {
        PersonalKindexConfig {
            config: config.map(Path::to_path_buf),
            processors: processors.to_vec(),
            ..cfg.clone()
        }
    }

    /// An authorization of `provider:model` for the account whose key is `key`.
    fn grant(provider: &str, model: &str, key_env: &str, key: &str) -> AuthorizedProcessor {
        AuthorizedProcessor {
            provider: provider.to_owned(),
            model: model.to_owned(),
            key_env: key_env.to_owned(),
            key_sha256: crate::hash::sha256_text(key),
            retention: "zero-data-retention".to_owned(),
        }
    }

    fn authorize(cfg: &PersonalKindexConfig) -> Result<Vec<Value>, ContractError> {
        let dir = tempfile::tempdir().unwrap();
        setup(cfg, dir.path())?
            .authorize(cfg)
            .map(|authorized| authorized.processors)
    }

    /// The resolved config of `config` (JSON text), and its processors as
    /// `provider:model@key_env`.
    fn resolved(base: &Path, config: &str) -> Result<(Value, Vec<String>), ContractError> {
        let path = base.join(format!("kin-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, config).unwrap();
        resolve_config(&with(&fake_kindex(base, None), Some(&path), &[])).map(
            |(config, processors)| {
                let named = processors
                    .iter()
                    .map(|p| format!("{}:{}@{}", p.provider, p.model, p.key_env))
                    .collect();
                (config, named)
            },
        )
    }

    #[test]
    fn the_processors_kindex_would_use_are_read_from_its_config() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let cfg = fake_kindex(base.path(), None);
        // No config: no LLM, and embeddings local (Kindex's own default is
        // Voyage), whatever credentials are passed.
        let (config, processors) = resolve_config(&with(&cfg, None, &[])).unwrap();
        assert!(processors.is_empty());
        assert_eq!(config["embedding"]["provider"], "local");
        assert_eq!(
            resolved(base.path(), r#"{"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna", "api_key_env": "OPENAI_API_KEY"},
                                      "embedding": {"provider": "openai", "model": "text-embedding-3-small", "api_key_env": "OPENAI_API_KEY"}}"#)
                .unwrap()
                .1,
            ["openai:gpt-6-luna@OPENAI_API_KEY", "openai:text-embedding-3-small@OPENAI_API_KEY"]
        );
        assert_eq!(
            resolved(
                base.path(),
                r#"{"embedding": {"provider": "voyage", "model": "voyage-3.5", "api_key_env": "VOYAGE_API_KEY"}}"#
            )
            .unwrap()
            .1,
            ["voyage:voyage-3.5@VOYAGE_API_KEY"]
        );
        assert!(
            resolved(
                base.path(),
                r#"{"llm": {"enabled": false}, "embedding": {"provider": "local"}}"#
            )
            .unwrap()
            .1
            .is_empty()
        );
        // Whatever Kindex might read differently from Kinbase is refused.
        for config in [
            "llm:\n  enabled: true\n",
            r#"["llm"]"#,
            r#"{"llm": {"enabled": "true", "provider": "openai", "model": "gpt-6-luna"}}"#,
            r#"{"llm": {"enabled": 1, "provider": "openai", "model": "gpt-6-luna"}}"#,
            r#"{"llm": {"enabled": true}}"#,
            r#"{"llm": {"enabled": true, "provider": "OpenAI", "model": "gpt-6-luna"}}"#,
            r#"{"llm": {"enabled": true, "provider": "openai", "model": 6}}"#,
            // The key variable is named, one variable, a credential: it is the
            // account the processor is authorized for.
            r#"{"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna"}}"#,
            r#"{"llm": {"enabled": true, "provider": "anthropic", "model": "claude-haiku-4-5", "api_key_env": "HOME"}}"#,
            r#"{"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna", "api_key_env": "A_API_KEY,B_API_KEY"}}"#,
            r#"{"embedding": {"provider": "voyage", "model": "voyage-3.5"}}"#,
            r#"{"llm": {"base_url": "https://example.invalid"}}"#,
            r#"{"embedding": {"provider": "none"}}"#,
            r#"{"embedding": {"provider": "voyage"}}"#,
            r#"{"embedding": {"provider": 1}}"#,
            r#"{"profiles": {"work": {"llm": {"enabled": true}}}}"#,
            r#"{"default_profile": "work"}"#,
            r#"{"channels": {"slack": {"enabled": true}}}"#,
            r#"{"ask": 3}"#,
        ] {
            assert_eq!(
                resolved(base.path(), config).unwrap_err().code,
                "CONFIG_INVARIANT",
                "{config}"
            );
        }
    }

    #[test]
    fn the_receipt_says_what_ran_after_a_hand_off() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let fake = fake_kindex(base.path(), Some(30 * 86_400));
        set_credential("UNIT_VOYAGE_API_KEY", "pa-embedding-account");
        set_credential("UNIT_OPENAI_API_KEY", "sk-llm-account");
        let embedder = grant(
            "voyage",
            "voyage-3.5",
            "UNIT_VOYAGE_API_KEY",
            "pa-embedding-account",
        );
        let llm = grant(
            "openai",
            "gpt-6-luna",
            "UNIT_OPENAI_API_KEY",
            "sk-llm-account",
        );
        let cases = [
            // Embeddings only: `kin digest` would stop at once, so the queue is
            // drained on its own and nothing is called digested.
            (
                r#"{"embedding": {"provider": "voyage", "model": "voyage-3.5", "api_key_env": "UNIT_VOYAGE_API_KEY"}}"#,
                vec![embedder.clone()],
                (false, true, None, Some("drain\n")),
            ),
            // An LLM: `kin digest`, which drains the queue too.
            (
                r#"{"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna", "api_key_env": "UNIT_OPENAI_API_KEY"},
                    "embedding": {"provider": "voyage", "model": "voyage-3.5", "api_key_env": "UNIT_VOYAGE_API_KEY"}}"#,
                vec![llm, embedder],
                (true, true, Some("digest\n"), None),
            ),
        ];
        for (index, (config, grants, (digested, embedded, digests, embeds))) in
            cases.into_iter().enumerate()
        {
            let path = base.path().join(format!("kin-{index}.json"));
            std::fs::write(&path, config).unwrap();
            let cfg = with(&fake, Some(&path), &grants);
            let root = base.path().join(format!("personal-{index}"));
            let source = base.path().join(format!("transcripts-{index}"));
            std::fs::create_dir(&source).unwrap();
            std::fs::write(source.join("s.jsonl"), LINE).unwrap();
            let now = crate::time::now_rfc3339_millis();
            let scan = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
            let receipt = hand_off(&cfg, &root, &source, &scan, &now).unwrap();
            assert_eq!(receipt["digested"], digested, "{receipt}");
            assert_eq!(receipt["embedded"], embedded, "{receipt}");
            assert_eq!(
                receipt["processors"].as_array().unwrap().len(),
                grants.len(),
                "{receipt}"
            );
            let read = |name: &str| std::fs::read_to_string(graph(&root).join(name)).ok();
            assert_eq!(read("digests").as_deref(), digests, "{receipt}");
            assert_eq!(read("embeds").as_deref(), embeds, "{receipt}");
        }
    }

    #[test]
    fn personal_text_reaches_only_an_authorized_processor() {
        let base = tempfile::TempDir::new_in(verified_base()).unwrap();
        let fake = fake_kindex(base.path(), Some(30 * 86_400));
        let config = base.path().join("kin.json");
        std::fs::write(
            &config,
            r#"{"llm": {"enabled": true, "provider": "openai", "model": "gpt-6-luna", "api_key_env": "UNIT_OPENAI_API_KEY"},
                "embedding": {"provider": "local"}}"#,
        )
        .unwrap();
        set_credential("UNIT_OPENAI_API_KEY", "sk-authorized-account");
        let unauthorized = with(&fake, Some(&config), &[]);
        let authorized = with(
            &fake,
            Some(&config),
            &[grant(
                "openai",
                "gpt-6-luna",
                "UNIT_OPENAI_API_KEY",
                "sk-authorized-account",
            )],
        );
        assert_eq!(
            authorize(&unauthorized).unwrap_err().code,
            "PROCESSOR_UNAUTHORIZED"
        );
        assert_eq!(
            authorize(&authorized).unwrap(),
            [json!({"provider": "openai", "model": "gpt-6-luna",
                    "account": &crate::hash::sha256_text("sk-authorized-account")[..16],
                    "retention": "zero-data-retention"})]
        );
        // The authorization is for one account: another key, another model or
        // another key variable is not covered.
        for other in [
            grant(
                "openai",
                "gpt-6-luna",
                "UNIT_OPENAI_API_KEY",
                "sk-another-account",
            ),
            grant(
                "openai",
                "gpt-6-sol",
                "UNIT_OPENAI_API_KEY",
                "sk-authorized-account",
            ),
            grant(
                "openai",
                "gpt-6-luna",
                "OTHER_OPENAI_API_KEY",
                "sk-authorized-account",
            ),
        ] {
            assert_eq!(
                authorize(&with(&fake, Some(&config), &[other]))
                    .unwrap_err()
                    .code,
                "PROCESSOR_UNAUTHORIZED"
            );
        }

        // Hand-off: the conversations are stored (local); the digest is refused.
        let root = base.path().join("personal");
        let source = base.path().join("transcripts");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("s.jsonl"), LINE).unwrap();
        let now = crate::time::now_rfc3339_millis();
        let scan = crate::lifecycle::scan_transcripts("claude_jsonl", &source, &now).unwrap();
        let receipt = hand_off(&unauthorized, &root, &source, &scan, &now).unwrap();
        assert_eq!(receipt["conversations"], 1);
        assert_eq!(receipt["digested"], false);
        assert_eq!(receipt["digest_refused"]["code"], "PROCESSOR_UNAUTHORIZED");
        assert!(!graph(&root).join("digests").exists(), "the digest ran");
        assert_eq!(received(&root).len(), 1);

        // Recall: refused before the question is handed to Kindex.
        let refused = recall(&unauthorized, &root, "what did I say?", None, &[], &now).unwrap_err();
        assert_eq!(refused.code, "PROCESSOR_UNAUTHORIZED");
        let answered = recall(&authorized, &root, "what did I say?", None, &[], &now).unwrap();
        assert_eq!(answered.processors[0]["model"], "gpt-6-luna");
        // The question reached Kindex on standard input, not the command line,
        // and Kindex was given the authorized credential and no other.
        assert_eq!(
            std::fs::read_to_string(graph(&root).join("question")).unwrap(),
            "what did I say?"
        );
        assert!(
            !std::fs::read_to_string(graph(&root).join("argv.ask"))
                .unwrap()
                .contains("what did I say")
        );
        let env = std::fs::read_to_string(graph(&root).join("env.ask")).unwrap();
        assert!(
            env.contains("UNIT_OPENAI_API_KEY=sk-authorized-account"),
            "{env}"
        );
        let stored = std::fs::read_to_string(graph(&root).join("env.ingest")).unwrap();
        assert!(
            !stored.contains("API_KEY"),
            "storing was given a credential: {stored}"
        );
        assert_eq!(
            answered.sent_sha256,
            crate::hash::sha256_text("what did I say?")
        );
        // Every Kindex run was given exactly the checked config, and nothing
        // of it is left behind.
        let (checked, _) = resolve_config(&authorized).unwrap();
        for command in ["ingest", "ask"] {
            let given: Value = serde_json::from_slice(
                &std::fs::read(graph(&root).join(format!("config.{command}"))).unwrap(),
            )
            .unwrap();
            assert_eq!(given, checked, "{command}");
        }
        assert!(
            std::fs::read_dir(graph(&root).join(HANDOFF_DIR))
                .unwrap()
                .flatten()
                .all(|entry| !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("kindex-config"))
        );
    }
}
