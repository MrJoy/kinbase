//! Source adapter lifecycle (architecture §4): `scan(source) -> native
//! units and records`, and the pure projection that turns the observation
//! ledger into derived facts and owned Unknowns.
//!
//! The observation ledger (private store) is the only authority for what an
//! adapter observed; derived facts are a pure function of that ledger, the
//! authority snapshot and `as_of`. Adapters never assert facts themselves and
//! never write shared events; the projection is recomputed on every read so
//! recency, Git topology and authority state can change a derivation without
//! rewriting history.

use crate::codebase::{Repository, git, git_ok};
use crate::error::ContractError;
use crate::hash::sha256_bytes;
use crate::model::Observation;
use crate::time::parse_rfc3339_millis;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub(crate) const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_DIRECTORY_BYTES: usize = 128 * 1024 * 1024;
/// Default private raw-session retention in proof roots (verification
/// "Operational limits": 24 hours).
pub const PRIVATE_RAW_RETENTION_SECONDS: i64 = 24 * 3600;

// ==========================================================================
// Native units and records
// ==========================================================================

/// One native record inside one native unit (a transcript file, a source
/// file, a commit, a ref, an export object, a Kindex node, a signed answer).
#[derive(Debug, Clone)]
pub struct SourceRecord {
    pub native_id: String,
    pub unit_id: String,
    pub logical_key: String,
    pub statement: String,
    pub atom_kind: String,
    pub disposition: String,
    /// Bytes whose digest is the observation's content identity.
    pub content: Vec<u8>,
    pub scope: String,
    pub confidence: u16,
    pub asserted_at: Option<String>,
    pub effective_from: Option<String>,
    pub effective_until: Option<String>,
    pub receipt_observed_at: Option<String>,
    pub receipt_expires_at: Option<String>,
    pub environment_id: Option<String>,
    pub owner_id: Option<String>,
    pub signer: Option<String>,
    pub parents: Vec<String>,
    pub attributes: Map<String, Value>,
    pub origin: String,
    /// One of `crate::model::PROVENANCE`; caps the standing any fact derived
    /// from this record may reach. Defaults to `unknown`, which is the honest
    /// answer for evidence that carries no authorship marker at all.
    pub provenance: String,
    /// Spans of code this record is about, taken from a diff rather than guessed.
    pub anchors: Vec<crate::model::CodeAnchor>,
    /// Paths this record rules over, when it is a record that rules at all.
    pub governs_paths: Vec<String>,
    pub revision: Option<String>,
    pub branch: Option<String>,
    pub raw_expired: bool,
    /// Set for `.kin/events` FactEvents: the reducer owns those facts.
    pub reducer_owned: bool,
    /// Present in the newest snapshot of a snapshot-style export.
    pub present: bool,
    /// The transcript a host-transcript record was read from. Not recorded
    /// in the journal; the Personal Kindex hand-off groups and dates by it.
    pub transcript: Option<std::sync::Arc<TranscriptOrigin>>,
}

/// A transcript file as one scan read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptOrigin {
    pub path: PathBuf,
    /// Last modification, in Unix seconds: the start of its retention clock.
    pub modified: Option<i64>,
    /// `private_retention_seconds` from the transcript's `.retention` sidecar.
    pub declared_retention_seconds: Option<i64>,
}

impl SourceRecord {
    pub fn new(native_id: impl Into<String>, unit_id: impl Into<String>) -> Self {
        Self {
            native_id: native_id.into(),
            unit_id: unit_id.into(),
            logical_key: String::new(),
            statement: String::new(),
            atom_kind: "claim".to_owned(),
            disposition: "current".to_owned(),
            content: Vec::new(),
            scope: "repository".to_owned(),
            confidence: 7_000,
            asserted_at: None,
            effective_from: None,
            effective_until: None,
            receipt_observed_at: None,
            receipt_expires_at: None,
            environment_id: None,
            owner_id: None,
            signer: None,
            parents: Vec::new(),
            attributes: Map::new(),
            origin: "merged-default".to_owned(),
            provenance: "unknown".to_owned(),
            anchors: Vec::new(),
            governs_paths: Vec::new(),
            revision: None,
            branch: None,
            raw_expired: false,
            reducer_owned: false,
            present: true,
            transcript: None,
        }
    }

    pub fn content_digest(&self) -> String {
        sha256_bytes(&self.content)
    }
}

/// Everything one adapter scan produced.
#[derive(Debug, Default)]
pub struct SourceScan {
    pub records: Vec<SourceRecord>,
    pub unit_ids: BTreeSet<String>,
    pub source_digest: String,
    /// Shallow or sparse view of the repository, when the scan could tell.
    pub narrowed_view: Option<String>,
    pub bytes_read: usize,
    /// Native input the adapter could not read, by reason. Reported with the
    /// ingest receipt; never silently dropped.
    pub skipped: BTreeMap<String, usize>,
    /// Non-blank lines an export adapter examined.
    pub export_lines: usize,
    /// Identities the source still holds that this (windowed) scan did not
    /// emit, with the origin class they would carry now. One whose recorded
    /// origin still matches is not retired: leaving the window is not
    /// leaving the source.
    pub present_elsewhere: BTreeMap<String, String>,
    /// Where the next page of a windowed source starts, when there is one.
    pub next_checkpoint: Option<String>,
    /// For host transcripts: what this scan saw, and when it began, so a
    /// hand-off reconciles against the scan itself rather than the files as
    /// they are by the time it runs.
    pub transcripts: Option<TranscriptScan>,
}

/// The transcript files one scan listed and read, and when it started.
#[derive(Debug, Default, Clone)]
pub struct TranscriptScan {
    /// Wall-clock nanoseconds since the Unix epoch at the start of the scan.
    pub started_at_nanos: i128,
    /// Every transcript file the scan listed, read or skipped.
    pub listed: Vec<PathBuf>,
    /// The transcript files it read in full (an oversized one is not read).
    pub read: Vec<PathBuf>,
}

impl TranscriptScan {
    /// A scan beginning now, having listed and read nothing yet.
    pub fn begin() -> Self {
        TranscriptScan {
            started_at_nanos: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos() as i128)
                .unwrap_or(0),
            ..TranscriptScan::default()
        }
    }
}

impl SourceScan {
    pub fn skip(&mut self, reason: impl Into<String>) {
        *self.skipped.entry(reason.into()).or_insert(0) += 1;
    }
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::refused(
        "CONFIG_INVARIANT",
        format!(
            "source is unavailable or escapes the repository ({})",
            error.kind()
        ),
        "Pass a source contained by the repository.",
    )
    .with_detail(json!({"omitted_count": 1}))
}

fn limit(message: &str) -> ContractError {
    ContractError::limit(message, json!({"omitted_count": 1}))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ContractError> {
    let metadata = std::fs::metadata(path).map_err(io_error)?;
    if metadata.len() as usize > MAX_FILE_BYTES {
        return Err(ContractError::new(
            "LIMIT_EXCEEDED",
            format!("source file exceeds the {MAX_FILE_BYTES}-byte bound"),
            "Split the source into bounded adapter batches.",
            false,
            crate::error::ExitCode::Refused,
        )
        .with_detail(json!({"omitted_count": 1})));
    }
    std::fs::read(path).map_err(io_error)
}

fn file_mtime(path: &Path) -> Option<i64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
}

/// Regular files under `directory`, sorted, refusing symlinks that escape.
pub fn regular_files(directory: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let root = directory.canonicalize().map_err(io_error)?;
    let mut output = Vec::new();
    collect(directory, &root, &mut output)?;
    output.sort();
    Ok(output)
}

fn collect(directory: &Path, root: &Path, output: &mut Vec<PathBuf>) -> Result<(), ContractError> {
    let mut children = std::fs::read_dir(directory)
        .map_err(io_error)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error)?;
    children.sort();
    for child in children {
        let metadata = std::fs::symlink_metadata(&child).map_err(io_error)?;
        if metadata.file_type().is_symlink() {
            let target = child.canonicalize().map_err(io_error)?;
            if !target.starts_with(root) {
                return Err(ContractError::refused(
                    "CONFIG_INVARIANT",
                    "directory source contains a symlink that escapes the source root",
                    "Remove the escaping symlink or pass only contained regular files.",
                )
                .with_detail(json!({"omitted_count": 1})));
            }
            continue;
        }
        if metadata.is_dir() {
            if child.file_name().and_then(|name| name.to_str()) == Some(".git") {
                continue;
            }
            collect(&child, root, output)?;
        } else if metadata.is_file() {
            output.push(child);
        }
    }
    Ok(())
}

fn relative_to(repo_root: &Path, path: &Path) -> String {
    let canonical_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    canonical
        .strip_prefix(&canonical_root)
        .map(|rel| rel.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

/// Human-readable text in ledger records rejects C0/C1 controls
/// (architecture §3); native statements are folded onto one line.
pub fn clean_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_space = false;
    for character in value.chars() {
        let code = character as u32;
        // Noncharacters carry nothing and are dropped; every other character
        // the canonical rule rejects separates words. A private list here
        // drifted from the rule once (U+061C) and aborted ingest mid-batch.
        if (0xfdd0..=0xfdef).contains(&code) || (code & 0xfffe) == 0xfffe {
            continue;
        }
        if crate::json::breaks_text_rule(character) || character.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        out.push(character);
        last_space = false;
    }
    out.trim().to_owned()
}

pub fn clean_value(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(clean_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(clean_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (clean_text(key), clean_value(value)))
                .collect(),
        ),
        Value::Number(number) if number.is_f64() => Value::String(number.to_string()),
        other => other.clone(),
    }
}

fn finish(scan: &mut SourceScan) {
    for record in &mut scan.records {
        record.statement = bounded_statement(&clean_text(&record.statement));
        let cleaned = clean_value(&Value::Object(record.attributes.clone()));
        if let Value::Object(map) = cleaned {
            record.attributes = map;
        }
    }
    let mut digests: Vec<String> = scan
        .records
        .iter()
        .map(|record| format!("{}:{}", record.native_id, record.content_digest()))
        .collect();
    digests.sort();
    scan.source_digest = sha256_bytes(digests.join("\n").as_bytes());
}

/// Scan one adapter source into native units and records.
pub fn scan(
    source_kind: &str,
    source: &Path,
    repo: &Repository,
    now: &str,
    checkpoint: Option<&str>,
) -> Result<SourceScan, ContractError> {
    let mut scan = match source_kind {
        "codex_jsonl" | "claude_jsonl" => scan_transcripts(source_kind, source, now)?,
        "repo_code" => scan_repo_code(source, repo)?,
        "repo_symbols" => scan_repo_symbols(source, repo)?,
        "repo_tests" | "runtime_evidence" => scan_envelopes(source_kind, source, repo)?,
        "git_history" => scan_git_history(repo, checkpoint)?,
        "docs_adr" => scan_docs_adr(source, repo)?,
        "issue_tracker" => scan_issue_tracker(source, repo)?,
        "pull_request" => scan_pull_request(source, repo)?,
        "chat_thread" => scan_chat_thread(source, repo)?,
        "document" => scan_document(source, repo)?,
        "github_export" => scan_github_export(source, repo)?,
        "kindex" => scan_kindex(source, repo)?,
        "authority_answer" => scan_answers(source, repo)?,
        other => {
            return Err(ContractError::invariant(format!(
                "unsupported source kind: {other}"
            )));
        }
    };
    if scan.narrowed_view.is_none() {
        if repo.is_shallow() {
            scan.narrowed_view = Some("shallow clone: history is truncated".to_owned());
        } else if repo.is_sparse_checkout() {
            scan.narrowed_view = Some("sparse checkout: the tree is a partial view".to_owned());
        }
    }
    if let Some(reason) = scan.narrowed_view.clone() {
        for record in &mut scan.records {
            record
                .attributes
                .insert("narrowed_view".to_owned(), json!(reason));
        }
    }
    finish(&mut scan);
    Ok(scan)
}

fn check_budget(scan: &mut SourceScan, bytes: usize) -> Result<(), ContractError> {
    scan.bytes_read += bytes;
    if scan.bytes_read > MAX_DIRECTORY_BYTES {
        return Err(limit("directory source exceeds the 128 MiB bound"));
    }
    Ok(())
}

pub(crate) fn source_files(source: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let metadata = std::fs::symlink_metadata(source).map_err(io_error)?;
    if metadata.file_type().is_symlink() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "source symlink traversal is refused",
            "Pass the regular file or directory target directly.",
        )
        .with_detail(json!({"omitted_count": 1})));
    }
    if metadata.is_file() {
        return Ok(vec![source.to_path_buf()]);
    }
    if metadata.is_dir() {
        return regular_files(source);
    }
    Err(ContractError::refused(
        "CONFIG_INVARIANT",
        "source is neither a regular file nor a directory",
        "Pass a regular file or directory.",
    )
    .with_detail(json!({"omitted_count": 1})))
}

// --------------------------------------------------------------------------
// codex_jsonl / claude_jsonl
// --------------------------------------------------------------------------

pub(crate) fn content_text(map: &Map<String, Value>) -> Option<String> {
    if let Some(Value::String(text)) = map.get("text") {
        return Some(text.clone());
    }
    // Claude Code writes a typed prompt as a plain string.
    if let Some(Value::String(text)) = map.get("content") {
        if !text.trim().is_empty() {
            return Some(text.clone());
        }
    }
    if let Some(Value::Array(parts)) = map.get("content") {
        let text = parts
            .iter()
            .filter_map(|part| part.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" ");
        if !text.trim().is_empty() {
            return Some(text);
        }
    }
    None
}

fn time_string(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| parse_rfc3339_millis(value).is_ok())
        .map(str::to_owned)
}

fn session_lineage(stem: &str) -> Option<String> {
    let (base, suffix) = stem.rsplit_once("-r")?;
    (!suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) && !base.is_empty())
        .then(|| base.to_owned())
}

pub(crate) fn scan_transcripts(
    source_kind: &str,
    source: &Path,
    now: &str,
) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let now_seconds = parse_rfc3339_millis(now)
        .map(|value| value.timestamp())
        .unwrap_or(0);
    let mut seen = TranscriptScan::begin();
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let stem = name.trim_end_matches(".jsonl").to_owned();
        seen.listed.push(path.clone());
        // One long session is not a reason to read none of the others.
        if std::fs::metadata(&path).map_err(io_error)?.len() as usize > MAX_FILE_BYTES {
            scan.skip(format!(
                "{source_kind}: transcript exceeds the {MAX_FILE_BYTES}-byte bound"
            ));
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        seen.read.push(path.clone());
        scan.unit_ids.insert(stem.clone());
        // Private raw retention: a sidecar may declare the retention that
        // applies to this transcript; the default is the proof-root bound.
        let sidecar = path.with_file_name(format!("{name}.retention"));
        let declared_retention = std::fs::read_to_string(&sidecar)
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|value| {
                value
                    .get("private_retention_seconds")
                    .and_then(Value::as_i64)
            });
        let retention = declared_retention.unwrap_or(PRIVATE_RAW_RETENTION_SECONDS);
        let modified = file_mtime(&path);
        let raw_expired = modified
            .map(|mtime| now_seconds - mtime > retention)
            .unwrap_or(false);
        let origin = std::sync::Arc::new(TranscriptOrigin {
            path: path.clone(),
            modified,
            declared_retention_seconds: declared_retention,
        });
        let lineage = session_lineage(&stem);
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            // A live session's last line may still be being written.
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                scan.skip(format!("{source_kind}: line is not JSON"));
                continue;
            };
            let Some(map) = value.as_object() else {
                continue;
            };
            let kind = map.get("type").and_then(Value::as_str).unwrap_or_default();
            let terminal = matches!(kind, "stop" | "session_end");
            let statement = if terminal {
                None
            } else if kind == "response_item" {
                map.get("payload")
                    .and_then(Value::as_object)
                    .and_then(content_text)
            } else {
                map.get("message")
                    .and_then(Value::as_object)
                    .and_then(content_text)
                    .or_else(|| content_text(map))
            };
            let record_id = map
                .get("id")
                .or_else(|| map.get("uuid"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    if terminal {
                        "end".to_owned()
                    } else {
                        format!("line:{}", index + 1)
                    }
                });
            if !terminal
                && statement
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .is_empty()
            {
                continue;
            }
            let native_id = format!("{stem}/{record_id}");
            let mut record = SourceRecord::new(&native_id, &stem);
            record.logical_key = format!("{source_kind}:{native_id}");
            record.statement = statement
                .clone()
                .unwrap_or_else(|| "[session ended]".to_owned());
            record.atom_kind = if terminal { "observation" } else { "claim" }.to_owned();
            record.disposition = if terminal { "terminal" } else { "current" }.to_owned();
            record.content = line.as_bytes().to_vec();
            record.scope = "host-session".to_owned();
            record.confidence = 6_000;
            record.asserted_at = time_string(
                map.get("timestamp")
                    .or_else(|| map.get("ts"))
                    .and_then(Value::as_str),
            );
            record.origin = "personal-host".to_owned();
            record.raw_expired = raw_expired;
            record.transcript = Some(origin.clone());
            if let Some(parent) = &lineage {
                record
                    .attributes
                    .insert("resumed_from".to_owned(), json!(parent));
            }
            if map.get("edited") == Some(&Value::Bool(true)) {
                record.attributes.insert("edited".to_owned(), json!(true));
            }
            // Neither host puts the role at the top level.
            let role = map
                .get("role")
                .or_else(|| map.get("message").and_then(|message| message.get("role")))
                .or_else(|| map.get("payload").and_then(|payload| payload.get("role")))
                .cloned()
                .unwrap_or(Value::Null);
            record.attributes.insert("role".to_owned(), role);
            scan.records.push(record);
        }
    }
    scan.transcripts = Some(seen);
    Ok(scan)
}

// --------------------------------------------------------------------------
// Repository files: repo_code and docs_adr (worktree plus divergent heads)
// --------------------------------------------------------------------------

fn declarations(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        let is_python = trimmed.starts_with("def ") || trimmed.starts_with("class ");
        let is_typescript = [
            "export function ",
            "function ",
            "const ",
            "export const ",
            "interface ",
            "type ",
            "export type ",
            "export interface ",
        ]
        .iter()
        .any(|prefix| trimmed.starts_with(prefix));
        if is_python || is_typescript {
            let mut name = trimmed.to_owned();
            if let Some(index) = name.find(|c: char| c == '(' || c == ':' || c == '=' || c == '{') {
                name.truncate(index);
            }
            names.push(name.trim().to_owned());
        }
    }
    names
}

fn code_statement(relpath: &str, text: &str) -> String {
    let names = declarations(text);
    if names.is_empty() {
        format!("{relpath} ({} lines)", text.lines().count())
    } else {
        format!("{relpath} declares: {}", names.join("; "))
    }
}

/// Local branches whose heads are not part of the default lineage, with the
/// files under `relative_dir` that differ from the default branch.
fn divergent_heads(
    repo: &Repository,
    relative_dir: &str,
) -> Vec<(String, String, Vec<(String, Vec<u8>)>)> {
    let default = repo.default_branch();
    let Ok(refs) = git(
        &repo.root,
        &[
            "for-each-ref",
            "--format=%(refname:short)%00%(objectname)",
            "refs/heads",
        ],
    ) else {
        return Vec::new();
    };
    let mut output = Vec::new();
    for line in refs.lines() {
        let Some((branch, head)) = line.split_once('\0') else {
            continue;
        };
        if branch == default || branch.is_empty() {
            continue;
        }
        if git_ok(&repo.root, &["merge-base", "--is-ancestor", head, &default]) {
            continue;
        }
        let Ok(listing) = git(
            &repo.root,
            &["ls-tree", "-r", "--name-only", head, "--", relative_dir],
        ) else {
            continue;
        };
        let mut files = Vec::new();
        for path in listing.lines().map(str::trim).filter(|p| !p.is_empty()) {
            let branch_blob = git(&repo.root, &["rev-parse", &format!("{head}:{path}")]).ok();
            let default_blob = git(&repo.root, &["rev-parse", &format!("{default}:{path}")]).ok();
            if branch_blob.is_some() && branch_blob == default_blob {
                continue;
            }
            let Ok(content) = git(&repo.root, &["show", &format!("{head}:{path}")]) else {
                continue;
            };
            files.push((path.to_owned(), content.into_bytes()));
        }
        output.push((branch.to_owned(), head.to_owned(), files));
    }
    output
}

/// The commit that last touched a path: the path's source revision, which
/// moves only when the path changes (never with unrelated commits).
/// Last commit to touch each tracked path, in one walk.
///
/// `path_revision` spawns a `git log` per file. A survey of a service with 477
/// source files therefore spawned 477 subprocesses and took minutes, which
/// across a 32-repository estate is hours of process startup and nothing else.
/// One `--name-only` walk answers the same question for every file at once.
fn revisions_by_path(repo: &Repository) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let Ok(log) = git(
        &repo.root,
        &["log", "--name-only", "--format=%x01%H", "-8000"],
    ) else {
        return map;
    };
    let mut current: Option<String> = None;
    for line in log.lines() {
        if let Some(sha) = line.strip_prefix('\u{1}') {
            current = Some(sha.trim().to_owned());
            continue;
        }
        let path = line.trim();
        if path.is_empty() || path.starts_with('"') {
            continue;
        }
        if let Some(sha) = &current {
            // First mention wins: the log walks newest first, so the first
            // commit naming a path is the last commit to have touched it.
            map.entry(path.to_owned()).or_insert_with(|| sha.clone());
        }
    }
    map
}

fn path_revision(repo: &Repository, relpath: &str) -> Option<String> {
    git(&repo.root, &["log", "-1", "--format=%H", "--", relpath])
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
        .or_else(|| repo.revision().ok())
}

/// One record per exported declaration, keyed on the *symbol* rather than the
/// file it lives in.
///
/// Every other bulk adapter gives each observation a unique logical key --
/// `git_history:commit:<sha>`, `repo_code:<path>` -- so two facts never contest
/// the same key, no conflict is ever detected, and the ruling loop cannot fire
/// on ingested evidence at all. one deployment's corpus of 83,655 facts produced zero questions.
/// A symbol name is a subject that several definitions can genuinely disagree
/// about, and disagreement is what the reducer needs to see before it can ask a
/// human which definition is current. Measured across seven services of one deployment:
/// `Db` is defined six times in five shapes, `ObservabilityLayer` seven times
/// in seven shapes. That is the founder's "which of the five ways do I
/// emulate, or is it none of them" as data rather than as a complaint.
fn scan_repo_symbols(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let mut skipped_oversize = 0usize;
    let revisions = revisions_by_path(repo);
    let fallback_revision = repo.revision().ok();
    // Read once, count, then emit. Counting in a separate pass re-read every
    // file and opened a window in which the two passes could disagree about a
    // file that changed between them.
    #[allow(clippy::type_complexity)]
    let mut found: Vec<(
        String,
        &'static str,
        String,
        usize,
        usize,
        String,
        Option<String>,
    )> = Vec::new();
    let mut occurrences: BTreeMap<String, usize> = BTreeMap::new();
    // Git's tracked set, not the filesystem. Walking the working tree meant
    // enumerating `node_modules` -- 8,072 of payment's 8,550 TypeScript files
    // belong to dependencies -- before filtering any of it out, and the scan
    // timed out before reaching the repository's own 477. Untracked files are
    // not part of what the repository has committed to anyway.
    for path in tracked_source_files(repo, source)? {
        let relpath = relative_to(&repo.root, &path);
        if !is_source_language(&relpath)
            || is_vendored_path(&relpath)
            || is_generated_path(&relpath)
            || is_test_path(&relpath)
        {
            continue;
        }
        // A survey skips what it cannot read; it does not refuse the survey.
        // One generated schema over the per-file bound would otherwise abort the
        // scan and leave the repository with no symbols at all -- the same shape
        // as the commit walk that refused 148,004 commits and ingested none.
        let Ok(bytes) = read_bounded(&path) else {
            skipped_oversize += 1;
            continue;
        };
        check_budget(&mut scan, bytes.len())?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let lines: Vec<&str> = text.lines().collect();
        let revision = revisions
            .get(&relpath)
            .cloned()
            .or_else(|| fallback_revision.clone());
        for (index, line) in lines.iter().enumerate() {
            let Some((kind, name)) = exported_declaration(line) else {
                continue;
            };
            let start = index + 1;
            let (end, shape) = declaration_shape(&lines, index);
            *occurrences.entry(name.clone()).or_insert(0) += 1;
            found.push((
                relpath.clone(),
                kind,
                name,
                start,
                end,
                shape,
                revision.clone(),
            ));
        }
    }
    // A name that appears in many files of one repository is that repository's
    // idiom, not an argument: fifty-four files exporting `Props`, or every
    // route exporting `GET` and `metadata`, is a framework requiring a name,
    // and reporting it as fifty-four competing definitions buries the handful
    // of real disagreements under convention. Conflict is a few definitions
    // that differ, not many that conform.
    {
        for (relpath, kind, name, start, end, shape, revision) in found {
            let native_id = format!("symbol:{relpath}:{start}:{name}");
            let mut record = SourceRecord::new(&native_id, &relpath);
            // Shared on purpose -- this is the one key in the system that several
            // records are meant to land on -- but only when sharing it means
            // something. See `convention_threshold`.
            record.logical_key =
                if occurrences.get(&name).copied().unwrap_or(0) > CONVENTION_THRESHOLD {
                    format!("symbol:{kind}:{name}@{relpath}")
                } else {
                    format!("symbol:{kind}:{name}")
                };
            record.atom_kind = "interface".to_owned();
            record.statement = bounded_statement(&format!(
                "{kind} {name} is defined at {relpath}:{start} with shape {shape}"
            ));
            // The shape, not the file bytes: re-reading an unchanged declaration
            // must be the same observation even if the file around it moved.
            record.content = shape.as_bytes().to_vec();
            record.origin = repo.origin_trust(&repo.root.join(&relpath));
            record.revision = revision.clone();
            record.branch = repo.branch().ok();
            record.confidence = 7_000;
            record.anchors = vec![crate::model::CodeAnchor {
                path: relpath.clone(),
                line_start: start as u32,
                line_end: end as u32,
                revision: revision.clone(),
                span_sha256: Some(shape.clone()),
            }];
            record
                .attributes
                .insert("symbol_kind".to_owned(), json!(kind));
            record.attributes.insert("symbol".to_owned(), json!(name));
            record.attributes.insert("shape".to_owned(), json!(shape));
            scan.unit_ids.insert(native_id);
            scan.records.push(record);
        }
    }
    if skipped_oversize > 0 {
        crate::output::diagnostic(
            "symbols-file-skipped",
            json!({
                "code": "LIMIT_EXCEEDED",
                "message": format!(
                    "{skipped_oversize} source file(s) exceed the per-file bound and were not scanned for symbols"
                ),
                "remediation": "Read those files directly; every other file in the repository was scanned.",
                "retryable": false,
                "evidence_id": "err_symbols_oversize",
                "omitted_count": skipped_oversize
            }),
        );
    }
    Ok(scan)
}

/// Above this many definitions of one name in one repository, the name is a
/// convention rather than a contested subject and each definition gets its own
/// key. Chosen from the data: real duplications in one deployment run two to eight
/// (`Db` eight, `ObservabilityLayer` seven), while conventions run to fifty.
const CONVENTION_THRESHOLD: usize = 8;

/// Files git tracks under `source`, falling back to a filesystem walk when the
/// repository has no git index to ask.
fn tracked_source_files(repo: &Repository, source: &Path) -> Result<Vec<PathBuf>, ContractError> {
    let Ok(listing) = git(&repo.root, &["ls-files", "-z"]) else {
        return source_files(source);
    };
    let mut paths: Vec<PathBuf> = listing
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| repo.root.join(entry))
        .filter(|path| path.starts_with(source) && path.is_file())
        .collect();
    if paths.is_empty() {
        return source_files(source);
    }
    paths.sort();
    Ok(paths)
}

/// Dependencies and build output, which are somebody else's code.
///
/// `node_modules` holds thousands of `.ts` files, and counting a library's
/// exports as this repository's own would drown every real symbol and make
/// every common name look contested by vendored copies of itself.
fn is_vendored_path(relpath: &str) -> bool {
    const VENDORED: [&str; 9] = [
        "node_modules/",
        "target/",
        ".venv/",
        "venv/",
        "site-packages/",
        ".next/",
        "build/",
        "coverage/",
        ".cache/",
    ];
    VENDORED
        .iter()
        .any(|marker| relpath.starts_with(marker.trim_end_matches('/')) || relpath.contains(marker))
}

/// Languages whose declarations this adapter can read. Anything else is skipped
/// rather than guessed at: a wrong symbol is worse than a missing one.
fn is_source_language(relpath: &str) -> bool {
    [".ts", ".tsx", ".js", ".jsx", ".rs", ".py", ".go"]
        .iter()
        .any(|extension| relpath.ends_with(extension))
        && !relpath.ends_with(".d.ts")
}

/// A test declares fixtures, not house style, and counting them as competing
/// definitions would make every helper look contested.
fn is_test_path(relpath: &str) -> bool {
    relpath.contains("__tests__")
        || relpath.contains("/test/")
        || relpath.contains("/tests/")
        || relpath.ends_with(".spec.ts")
        || relpath.ends_with(".test.ts")
        || relpath.ends_with("_test.go")
        || relpath.starts_with("test_")
}

/// `(kind, name)` for a line that exports a declaration, in the handful of
/// forms that are unambiguous from one line. Deliberately conservative: a
/// pattern that needs a parser to read correctly is not matched at all.
fn exported_declaration(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim_start();
    const FORMS: [(&str, &str); 14] = [
        ("export async function ", "function"),
        ("export function ", "function"),
        ("export class ", "class"),
        ("export interface ", "interface"),
        ("export type ", "type"),
        ("export const ", "const"),
        ("export enum ", "enum"),
        ("pub async fn ", "function"),
        ("pub fn ", "function"),
        ("pub struct ", "struct"),
        ("pub enum ", "enum"),
        ("pub trait ", "trait"),
        ("def ", "function"),
        ("class ", "class"),
    ];
    for (prefix, kind) in FORMS {
        let Some(rest) = trimmed.strip_prefix(prefix) else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect();
        // A leading underscore is a deliberate "do not use me"; a one-character
        // name carries no subject anyone could rule on.
        if name.len() < 2 || name.starts_with('_') {
            return None;
        }
        return Some((kind, name));
    }
    None
}

/// The declaration's extent and a digest of its normalised text.
///
/// Normalisation strips comments and collapses whitespace, so two services that
/// copied the same implementation and then reformatted it still agree. That
/// agreement is the whole signal: five identical copies mean the pattern is
/// settled, six copies in six shapes mean nobody has decided.
fn declaration_shape(lines: &[&str], start_index: usize) -> (usize, String) {
    const MAX_DECLARATION_LINES: usize = 200;
    let mut depth: i32 = 0;
    let mut seen_open = false;
    let mut end = start_index;
    let mut body = String::new();
    for (offset, line) in lines[start_index..]
        .iter()
        .take(MAX_DECLARATION_LINES)
        .enumerate()
    {
        body.push_str(line);
        body.push(' ');
        end = start_index + offset;
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if line.contains('{') {
            seen_open = true;
        }
        if seen_open && depth <= 0 {
            break;
        }
        // A declaration with no block at all ends at its terminator.
        if !seen_open && (line.trim_end().ends_with(';') || line.trim_end().ends_with(',')) {
            break;
        }
    }
    let mut normalised = String::with_capacity(body.len());
    let mut last_was_space = false;
    for character in strip_line_comments(&body).chars() {
        if character.is_whitespace() {
            if !last_was_space && !normalised.is_empty() {
                normalised.push(' ');
            }
            last_was_space = true;
        } else {
            normalised.push(character);
            last_was_space = false;
        }
    }
    (
        end + 1,
        crate::hash::sha256_text(normalised.trim())[..16].to_owned(),
    )
}

fn strip_line_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '/' && chars.peek() == Some(&'/') {
            for next in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            continue;
        }
        out.push(character);
    }
    out
}

fn scan_repo_code(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        let relpath = relative_to(&repo.root, &path);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let mut record = SourceRecord::new(&relpath, &relpath);
        record.logical_key = format!("repo_code:{relpath}");
        record.statement = bounded_statement(&code_statement(&relpath, &text));
        record.content = bytes;
        record.origin = repo.origin_trust(&path);
        record.revision = path_revision(repo, &relpath);
        record.branch = repo.branch().ok();
        record
            .attributes
            .insert("declarations".to_owned(), json!(declarations(&text)));
        scan.unit_ids.insert(relpath.clone());
        scan.records.push(record);
    }
    let relative_dir = relative_to(&repo.root, source);
    for (branch, head, files) in divergent_heads(repo, &relative_dir) {
        for (path, content) in files {
            let native_id = format!("{path}@{branch}");
            let text = String::from_utf8_lossy(&content).into_owned();
            let mut record = SourceRecord::new(&native_id, &native_id);
            record.logical_key = format!("repo_code:{path}");
            record.statement = bounded_statement(&code_statement(&path, &text));
            record.content = content;
            record.origin = "unreviewed-branch".to_owned();
            record.revision = Some(head.clone());
            record.branch = Some(branch.clone());
            record
                .attributes
                .insert("declarations".to_owned(), json!(declarations(&text)));
            scan.unit_ids.insert(native_id);
            scan.records.push(record);
        }
    }
    Ok(scan)
}

struct AdrDocument {
    number: String,
    title: String,
    status: String,
    supersedes: Option<String>,
    body: String,
}

fn parse_adr(text: &str) -> Result<AdrDocument, String> {
    let normalized = text
        .trim_start_matches('\u{feff}')
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let rest = normalized.trim_start();
    let Some(after_front) = rest.strip_prefix("---\n") else {
        return Err("ADR Markdown must begin with YAML front matter".to_owned());
    };
    let Some(end) = after_front.find("\n---") else {
        return Err("ADR Markdown front matter is not closed".to_owned());
    };
    let front = &after_front[..end];
    let body = after_front[end + 4..].trim().to_owned();
    let mut number = None;
    let mut title = String::new();
    let mut status = "proposed".to_owned();
    let mut supersedes = None;
    for line in front.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.trim() {
                "adr" => number = Some(value.to_owned()),
                "title" => title = value.to_owned(),
                "status" => status = value.to_lowercase(),
                "supersedes" => supersedes = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    let number = number.ok_or_else(|| "ADR front matter must name adr".to_owned())?;
    if title.is_empty() {
        return Err("ADR front matter must name title".to_owned());
    }
    Ok(AdrDocument {
        number,
        title,
        status,
        supersedes,
        body,
    })
}

fn adr_record(native_id: &str, relpath: &str, bytes: Vec<u8>) -> Result<SourceRecord, String> {
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let adr = parse_adr(&text)?;
    let stem = Path::new(relpath)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(relpath)
        .to_owned();
    let mut record = SourceRecord::new(native_id, native_id);
    record.logical_key = format!("docs_adr:{stem}");
    record.statement = bounded_statement(&format!("# {}\n{}", adr.title, adr.body));
    record.atom_kind = "decision".to_owned();
    record.disposition = match adr.status.as_str() {
        "accepted" => "accepted",
        "proposed" => "proposed",
        "rejected" => "rejected",
        "superseded" => "superseded",
        _ => "proposed",
    }
    .to_owned();
    record.content = bytes;
    record
        .attributes
        .insert("adr".to_owned(), json!(adr.number));
    record
        .attributes
        .insert("status".to_owned(), json!(adr.status));
    if let Some(supersedes) = adr.supersedes {
        record
            .attributes
            .insert("supersedes".to_owned(), json!(supersedes));
    }
    Ok(record)
}

fn scan_docs_adr(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let mut parsed_any = false;
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !(name.ends_with(".md") || name.ends_with(".rst") || name.ends_with(".txt")) {
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        let relpath = relative_to(&repo.root, &path);
        let mut record = adr_record(&relpath, &relpath, bytes).map_err(|message| {
            ContractError::new(
                "CONFIG_INVARIANT",
                message,
                "Use a valid native source envelope.",
                false,
                crate::error::ExitCode::Refused,
            )
        })?;
        parsed_any = true;
        record.origin = repo.origin_trust(&path);
        record.revision = path_revision(repo, &relpath);
        record.branch = repo.branch().ok();
        scan.unit_ids.insert(relpath.clone());
        scan.records.push(record);
    }
    let relative_dir = relative_to(&repo.root, source);
    for (branch, head, files) in divergent_heads(repo, &relative_dir) {
        for (path, content) in files {
            if !(path.ends_with(".md") || path.ends_with(".rst") || path.ends_with(".txt")) {
                continue;
            }
            let native_id = format!("{path}@{branch}");
            let Ok(mut record) = adr_record(&native_id, &path, content) else {
                continue;
            };
            record.origin = "unreviewed-branch".to_owned();
            record.revision = Some(head.clone());
            record.branch = Some(branch.clone());
            scan.unit_ids.insert(native_id);
            scan.records.push(record);
        }
    }
    if !parsed_any && scan.records.is_empty() {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "ADR Markdown must begin with YAML front matter",
            "Use a valid native source envelope.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    Ok(scan)
}

// --------------------------------------------------------------------------
// Command-result envelopes: repo_tests and runtime_evidence
// --------------------------------------------------------------------------

fn scan_envelopes(
    source_kind: &str,
    source: &Path,
    repo: &Repository,
) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let mut envelope_count = 0usize;
    for path in source_files(source)? {
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        let Ok(value) = crate::json::parse_strict_value(&bytes) else {
            continue;
        };
        let Some(map) = value.as_object() else {
            continue;
        };
        let is_envelope = map.get("schema").and_then(Value::as_str)
            == Some("kinbase-command-result/1")
            || map.get("command").is_some_and(Value::is_array)
            || map.get("stdout").is_some_and(Value::is_string);
        if !is_envelope {
            continue;
        }
        envelope_count += 1;
        let relpath = relative_to(&repo.root, &path);
        let command = map
            .get("command")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        let exit_code = map.get("exit_code").and_then(Value::as_i64).unwrap_or(0);
        let stdout = map
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let environment = map
            .get("environment_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let owner = map
            .get("environment_owner")
            .or_else(|| map.get("owner_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let observed_at = time_string(map.get("observed_at").and_then(Value::as_str));
        // Keyed on the repository path: two `result.json` files in different
        // directories are two runs, not one amended twice.
        let mut record = SourceRecord::new(&relpath, &relpath);
        record.logical_key = match &environment {
            Some(environment) => format!("{source_kind}:{environment}:{command}"),
            None => format!("{source_kind}:{command}"),
        };
        record.statement = if source_kind == "repo_tests" {
            format!("{command} -> exit {exit_code}: {}", stdout.trim())
        } else {
            format!(
                "{command} in {}: {}",
                environment.as_deref().unwrap_or("unregistered environment"),
                stdout.trim()
            )
        };
        record.atom_kind = "observation".to_owned();
        record.disposition = if source_kind == "repo_tests" {
            if exit_code == 0 { "passed" } else { "failed" }.to_owned()
        } else {
            "observed".to_owned()
        };
        record.content = bytes;
        record.confidence = 8_000;
        record.asserted_at = observed_at.clone();
        record.effective_from = observed_at.clone();
        record.effective_until = time_string(map.get("effective_until").and_then(Value::as_str));
        record.receipt_observed_at = observed_at;
        record.receipt_expires_at = time_string(map.get("expires_at").and_then(Value::as_str));
        record.environment_id = environment;
        record.owner_id = owner;
        record.origin = repo.origin_trust(&path);
        record.revision = path_revision(repo, &relpath);
        record.branch = repo.branch().ok();
        record
            .attributes
            .insert("exit_code".to_owned(), json!(exit_code));
        record
            .attributes
            .insert("command".to_owned(), json!(command));
        scan.unit_ids.insert(relpath);
        scan.records.push(record);
    }
    if envelope_count == 0 {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            format!("{source_kind} source contains no command-result envelope"),
            "Use a valid native source envelope.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    Ok(scan)
}

/// The objects of one JSONL export file that carry a string `id`, with their
/// line text. A byte-order mark is not part of the first line. A line that does
/// not parse, is not an object, or has no id is skipped and counted: a
/// malformed record is never guessed at, and never dropped unseen.
fn export_documents(
    scan: &mut SourceScan,
    kind: &str,
    bytes: &[u8],
) -> Vec<(String, Value, String)> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let mut documents = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        scan.export_lines += 1;
        let Ok(document) = serde_json::from_str::<Value>(line) else {
            scan.skip(format!("{kind}: line is not JSON"));
            continue;
        };
        let id = match document.get("id") {
            Some(Value::String(id)) if !id.is_empty() && document.is_object() => id.clone(),
            _ => {
                scan.skip(format!("{kind}: line has no string id"));
                continue;
            }
        };
        documents.push((line.to_owned(), document, id));
    }
    documents
}

/// An export with lines and no readable record is the wrong format, not an
/// empty source: treating it as empty retired every record it held before.
fn refuse_unreadable_export(scan: &SourceScan, kind: &str) -> Result<(), ContractError> {
    if scan.export_lines == 0 || !scan.records.is_empty() {
        return Ok(());
    }
    Err(ContractError::new(
        "CONFIG_INVARIANT",
        format!(
            "{kind} source has {} line(s) and none is a record with a string id",
            scan.export_lines
        ),
        "Export one JSON object per line, each with a string `id`; nothing was retired.",
        false,
        crate::error::ExitCode::Refused,
    )
    .with_detail(json!({"omitted_count": scan.export_lines})))
}

// --------------------------------------------------------------------------
// issue_tracker: Linear / Jira issues, one JSON object per line
// --------------------------------------------------------------------------

/// A ticket is the only artifact that reliably records *why* a change happened,
/// and it links outward: to the pull request carrying the code, to the document
/// that argued the design, to the thread where it was disputed. Those links are
/// what turn scattered evidence into an association anchored on real lines.
///
/// Envelope, one object per line:
///   id, title, body, state, team, creator, creator_kind, labels[],
///   links[{type,url,title}], comments[{author,body}], created_at, updated_at, url
/// Normalise a vendor timestamp to the millisecond-precision RFC 3339 the store
/// requires.
///
/// Linear returns `2026-02-12T06:20:11Z`, GitHub the same, Slack an epoch float.
/// The store's demand for exactly three fractional digits is reasonable -- it is
/// what makes event bytes canonical and comparable -- but no external system emits
/// it, so every adapter must convert rather than pass a vendor string through and
/// fail at admission with a digest error a long way from the cause.
/// The store bounds a single statement at 16 KiB. A design document is far longer
/// than that and is not one fact anyway, so the adapter carries a bounded excerpt
/// and leaves the full bytes addressable through the observation's content digest.
/// Truncating at a character boundary keeps the text valid UTF-8.
fn bounded_statement(text: &str) -> String {
    // The canonical data model rejects every character at or below 0x1f, newlines
    // and tabs included, so a statement assembled as "title\nbody" is refused. Real
    // text from real systems is full of both. Collapse all control characters to a
    // single space at the adapter -- the boundary that meets the outside world --
    // rather than letting the store refuse an observation whose cause is three
    // layers away from the error.
    let mut cleaned = String::with_capacity(text.len());
    let mut last_was_space = false;
    for character in text.chars() {
        let replaced = if (character as u32) <= 0x1f || (0x7f..=0x9f).contains(&(character as u32))
        {
            ' '
        } else {
            character
        };
        if replaced == ' ' {
            if last_was_space {
                continue;
            }
            last_was_space = true;
        } else {
            last_was_space = false;
        }
        cleaned.push(replaced);
    }
    let text = cleaned.trim();
    const LIMIT: usize = 15_000;
    if text.len() <= LIMIT {
        return text.to_owned();
    }
    let mut end = LIMIT;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{} [excerpt; full source retained by content digest]",
        &text[..end]
    )
}

fn normalise_stamp(value: Option<&str>) -> Option<String> {
    let raw = value?.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(raw).ok()?;
    Some(
        parsed
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string(),
    )
}

/// When an exported record last changed: the latest of the named envelope
/// times and, for a thread, of its messages. Re-ingesting an older export
/// must not make its snapshot the head.
fn export_updated_at(document: &Value, fields: &[&str]) -> Option<String> {
    let messages = document
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|message| normalise_stamp(crate::json::get_str(message, "ts")));
    fields
        .iter()
        .filter_map(|field| normalise_stamp(crate::json::get_str(document, field)))
        .chain(messages)
        .max()
}

fn scan_issue_tracker(source: &Path, _repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        scan.unit_ids
            .insert(name.trim_end_matches(".jsonl").to_owned());
        let unit = name.trim_end_matches(".jsonl").to_owned();
        for (line, document, id) in export_documents(&mut scan, "issue_tracker", &bytes) {
            let line = line.as_str();
            // A malformed ticket is skipped, never guessed at: half-parsed evidence
            // about why a change happened is worse than none.
            let title = crate::json::get_str(&document, "title").unwrap_or_default();
            let body = crate::json::get_str(&document, "body").unwrap_or_default();
            let state = crate::json::get_str(&document, "state").unwrap_or("unknown");

            let mut record = SourceRecord::new(&format!("issue_tracker:{id}"), &unit);
            record.logical_key = format!("issue_tracker:{id}");
            record.statement = bounded_statement(&format!("{id}: {title}\n{body}"));
            // A ticket states a problem and its resolution; it is not itself a ruling.
            // Whether it becomes one depends on who closed it and what they said, which
            // is a question for the authority loop, not a guess for the adapter.
            record.atom_kind = "claim".to_owned();
            record.disposition = match state {
                "completed" => "accepted",
                "canceled" => "rejected",
                _ => "proposed",
            }
            .to_owned();
            // A ticket a person wrote is human evidence. One an agent filed is not,
            // and `creator_kind` is the only place that distinction survives.
            record.provenance = match crate::json::get_str(&document, "creator_kind") {
                Some("agent") => "ai_generated".to_owned(),
                Some("human") => "human".to_owned(),
                _ => "unknown".to_owned(),
            };
            record.asserted_at = normalise_stamp(crate::json::get_str(&document, "created_at"));
            if let Some(updated) = export_updated_at(&document, &["updated_at", "created_at"]) {
                record
                    .attributes
                    .insert("updated_at".to_owned(), json!(updated));
            }

            // Every outbound link is an edge in the association graph. Labels are the
            // subjects: `example/web-app` names a component, `Bug` names a
            // kind, and a label that recurs across tickets pointing at one span is
            // exactly the signal we want to accumulate.
            let mut references = Vec::new();
            if let Some(labels) = document.get("labels").and_then(Value::as_array) {
                for label in labels.iter().filter_map(Value::as_str) {
                    references.push(format!("label:{label}"));
                }
            }
            if let Some(links) = document.get("links").and_then(Value::as_array) {
                for link in links {
                    let kind = crate::json::get_str(link, "type").unwrap_or("link");
                    if let Some(url) = crate::json::get_str(link, "url") {
                        references.push(format!("{kind}:{url}"));
                    }
                }
            }
            if let Some(url) = crate::json::get_str(&document, "url") {
                references.push(format!("issue:{url}"));
            }
            // Carried as attributes: these are the edges of the association graph --
            // labels name the subject, links name the artifacts that point at the code.
            record.attributes.insert(
                "references".to_owned(),
                Value::Array(references.into_iter().map(Value::String).collect()),
            );
            record.content = line.as_bytes().to_vec();
            record.confidence = 7_000;
            scan.records.push(record);
        }
    }
    refuse_unreadable_export(&scan, "issue_tracker")?;
    Ok(scan)
}

// --------------------------------------------------------------------------
// pull_request: a stated intent bound to the exact lines that changed
// --------------------------------------------------------------------------

/// Files whose diffs are machine-written and carry no intent. A lockfile with 524
/// changed lines would otherwise dominate every anchor set it appears in, which is
/// the association graph's version of letting volume win.
fn is_generated_path(path: &str) -> bool {
    const GENERATED: [&str; 10] = [
        "lock.yaml",
        "lock.json",
        ".lock",
        "Cargo.lock",
        "go.sum",
        ".min.js",
        ".min.css",
        "/dist/",
        "/vendor/",
        ".snap",
    ];
    GENERATED.iter().any(|marker| path.contains(marker))
}

/// A pull request states why a change was made and shows exactly which lines it
/// touched. That pairing is what an anchor is: everything else in the graph points
/// at code by inference, and this points at it by record.
fn scan_pull_request(source: &Path, _repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        scan.unit_ids
            .insert(name.trim_end_matches(".jsonl").to_owned());
        let unit = name.trim_end_matches(".jsonl").to_owned();
        for (line, document, id) in export_documents(&mut scan, "pull_request", &bytes) {
            let line = line.as_str();
            let title = crate::json::get_str(&document, "title").unwrap_or_default();
            let merged = document
                .get("merged")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let revision = crate::json::get_str(&document, "merge_commit").map(str::to_owned);

            let mut record = SourceRecord::new(&format!("pull_request:{id}"), &unit);
            record.logical_key = format!("pull_request:{id}");
            record.statement = bounded_statement(&format!(
                "{id}: {title}\n{}",
                crate::json::get_str(&document, "body").unwrap_or_default()
            ));
            record.atom_kind = "claim".to_owned();
            // Only a merged pull request is evidence of anything. An open or closed
            // one is a proposal that may never have been accepted.
            record.disposition = if merged { "accepted" } else { "proposed" }.to_owned();
            // The author wrote the code; the merger accepted it. An agent-authored
            // change a person merged is `human_review` -- they approved an output,
            // which is weaker than having chosen the approach, and far from nothing.
            record.provenance = match (
                crate::json::get_str(&document, "author_kind"),
                crate::json::get_str(&document, "merged_by_kind"),
            ) {
                (Some("human"), _) => "human".to_owned(),
                (Some("agent"), Some("human")) => "human_review".to_owned(),
                (Some("agent"), _) => "ai_generated".to_owned(),
                (Some("bot"), _) => "bot".to_owned(),
                _ => "unknown".to_owned(),
            };
            record.asserted_at = normalise_stamp(crate::json::get_str(&document, "merged_at"));
            if let Some(updated) =
                export_updated_at(&document, &["updated_at", "merged_at", "created_at"])
            {
                record
                    .attributes
                    .insert("updated_at".to_owned(), json!(updated));
            }
            record.revision = revision.clone();

            let mut anchors = Vec::new();
            if let Some(files) = document.get("files").and_then(Value::as_array) {
                for file in files {
                    let Some(file_path) = crate::json::get_str(file, "path") else {
                        continue;
                    };
                    if is_generated_path(file_path) {
                        continue;
                    }
                    for span in file
                        .get("spans")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let start = span.get("start").and_then(Value::as_u64).unwrap_or(0) as u32;
                        let end = span.get("end").and_then(Value::as_u64).unwrap_or(0) as u32;
                        if start == 0 || end < start {
                            continue;
                        }
                        anchors.push(crate::model::CodeAnchor {
                            path: file_path.to_owned(),
                            line_start: start,
                            line_end: end,
                            revision: revision.clone(),
                            span_sha256: None,
                        });
                    }
                }
            }
            record.anchors = anchors;

            let mut references = Vec::new();
            if let Some(url) = crate::json::get_str(&document, "url") {
                references.push(format!("pull_request:{url}"));
            }
            for ticket in document
                .get("tickets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(key) = ticket.as_str() {
                    references.push(format!("issue_tracker:{key}"));
                }
            }
            record.attributes.insert(
                "references".to_owned(),
                Value::Array(references.into_iter().map(Value::String).collect()),
            );
            record.content = line.as_bytes().to_vec();
            record.confidence = 7_500;
            scan.records.push(record);
        }
    }
    refuse_unreadable_export(&scan, "pull_request")?;
    Ok(scan)
}

// --------------------------------------------------------------------------
// chat_thread: where decisions are argued before anyone writes them down
// --------------------------------------------------------------------------

/// A thread is one conversation however many messages it holds, so it becomes one
/// record. Sixty messages arguing about retry budgets is a single piece of evidence
/// that the argument happened, not sixty independent claims -- counting messages
/// would let the loudest channel outweigh a written decision.
///
/// Envelope: id, channel, permalink, participants[], messages[{author,author_kind,
/// text,ts}], started_at.
fn scan_chat_thread(source: &Path, _repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        scan.unit_ids
            .insert(name.trim_end_matches(".jsonl").to_owned());
        let unit = name.trim_end_matches(".jsonl").to_owned();
        for (line, document, id) in export_documents(&mut scan, "chat_thread", &bytes) {
            let line = line.as_str();
            let channel = crate::json::get_str(&document, "channel").unwrap_or_default();
            let messages = document
                .get("messages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            let mut body = String::new();
            let mut any_human = false;
            let mut all_agent = !messages.is_empty();
            for message in &messages {
                let author = crate::json::get_str(message, "author").unwrap_or("unknown");
                let kind = crate::json::get_str(message, "author_kind").unwrap_or("unknown");
                if kind == "human" {
                    any_human = true;
                }
                if kind != "agent" && kind != "bot" {
                    all_agent = false;
                }
                let line_text = crate::json::get_str(message, "text").unwrap_or_default();
                body.push_str(&format!("{author}: {line_text}\n"));
            }

            let mut record = SourceRecord::new(&format!("chat_thread:{id}"), &unit);
            record.logical_key = format!("chat_thread:{id}");
            record.statement = bounded_statement(&format!("#{channel}\n{body}"));
            // A thread records that something was discussed. Whether it settled
            // anything is a question for the authority who was in it, not a
            // conclusion the adapter may draw from people talking.
            record.atom_kind = "claim".to_owned();
            record.disposition = "proposed".to_owned();
            record.provenance = if all_agent {
                "ai_generated".to_owned()
            } else if any_human {
                "human".to_owned()
            } else {
                "unknown".to_owned()
            };
            record.asserted_at = normalise_stamp(crate::json::get_str(&document, "started_at"));
            if let Some(updated) = export_updated_at(&document, &["started_at"]) {
                record
                    .attributes
                    .insert("updated_at".to_owned(), json!(updated));
            }

            let mut references = vec![format!("channel:{channel}")];
            if let Some(permalink) = crate::json::get_str(&document, "permalink") {
                references.push(format!("chat_thread:{permalink}"));
            }
            for ticket in document
                .get("tickets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(key) = ticket.as_str() {
                    references.push(format!("issue_tracker:{key}"));
                }
            }
            record.attributes.insert(
                "references".to_owned(),
                Value::Array(references.into_iter().map(Value::String).collect()),
            );
            record.content = line.as_bytes().to_vec();
            // Deliberately the lowest of any adapter: chat is the least considered
            // form of evidence in a company, and the scanner has the most work to do
            // on it.
            record.confidence = 5_000;
            scan.records.push(record);
        }
    }
    refuse_unreadable_export(&scan, "chat_thread")?;
    Ok(scan)
}

// --------------------------------------------------------------------------
// document: prose that states direction
// --------------------------------------------------------------------------

/// A written document is the strongest evidence short of asking a person, because
/// somebody sat down and decided what it should say. That is why `standing` and
/// `governs_paths` are read from the envelope here and nowhere else: a document is
/// the natural home of a north star, and a north star that cannot say which paths
/// it governs cannot demote the code it supersedes.
///
/// Envelope: id, title, body, author, author_kind, standing, atom_kind,
/// governs_paths[], url, modified_at.
fn scan_document(source: &Path, _repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !name.ends_with(".jsonl") {
            continue;
        }
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        scan.unit_ids
            .insert(name.trim_end_matches(".jsonl").to_owned());
        let unit = name.trim_end_matches(".jsonl").to_owned();
        for (line, document, id) in export_documents(&mut scan, "document", &bytes) {
            let line = line.as_str();
            let title = crate::json::get_str(&document, "title").unwrap_or_default();
            let mut record = SourceRecord::new(&format!("document:{id}"), &unit);
            record.logical_key = format!("document:{id}");
            record.statement = bounded_statement(&format!(
                "{title}\n{}",
                crate::json::get_str(&document, "body").unwrap_or_default()
            ));
            // A document may declare what kind of claim it makes, but only from the
            // ruling vocabulary. Anything else is an ordinary claim: a doc does not
            // get to promote itself to `invariant` by saying so in its own metadata.
            record.atom_kind = match crate::json::get_str(&document, "atom_kind") {
                Some(
                    kind @ ("north_star" | "directional" | "invariant" | "decision" | "constraint"
                    | "rationale"),
                ) => kind.to_owned(),
                _ => "claim".to_owned(),
            };
            record.disposition = crate::json::get_str(&document, "disposition")
                .unwrap_or("proposed")
                .to_owned();
            record.provenance = match crate::json::get_str(&document, "author_kind") {
                Some("human") => "human".to_owned(),
                // A meeting transcript is human speech a machine wrote down; the
                // summary of that meeting is the machine's own words. They are not
                // the same evidence and do not carry the same weight.
                Some("transcript") => "transcript".to_owned(),
                Some("agent") => "ai_generated".to_owned(),
                _ => "unknown".to_owned(),
            };
            record.asserted_at = normalise_stamp(crate::json::get_str(&document, "modified_at"));

            let mut references = Vec::new();
            if let Some(url) = crate::json::get_str(&document, "url") {
                references.push(format!("document:{url}"));
            }
            // Governance is a field, not an evidence reference. Smuggling it
            // through `evidence_refs` meant two rulings that governed the same
            // path each looked like evidence sitting under the other one.
            record.governs_paths = document
                .get("governs_paths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect();
            record.attributes.insert(
                "references".to_owned(),
                Value::Array(references.into_iter().map(Value::String).collect()),
            );
            record.content = line.as_bytes().to_vec();
            record.confidence = 7_000;
            scan.records.push(record);
        }
    }
    refuse_unreadable_export(&scan, "document")?;
    Ok(scan)
}

// --------------------------------------------------------------------------
// git_history: commits and refs from the repository itself
// --------------------------------------------------------------------------

struct CommitInfo {
    sha: String,
    parents: Vec<String>,
    tree: String,
    author_date: String,
    subject: String,
    /// One of `crate::model::PROVENANCE`. Decides the ceiling this commit's
    /// evidence may reach, so that agent-written code cannot enter the ranks
    /// that mean "this is the direction".
    provenance: String,
}

/// Agent markers that actually appear in commit metadata.
const AGENT_MARKERS: [&str; 7] = [
    "claude", "codex", "copilot", "cursor", "devin", "aider", "gpt-",
];

const BOT_MARKERS: [&str; 5] = [
    "dependabot",
    "renovate",
    "github-actions",
    "[bot]",
    "semantic-release",
];

/// Classify a commit's authorship from what git actually records.
///
/// This is deliberately conservative in one direction: an unmarked commit is
/// `unknown`, never `human`. Absence of an agent trailer is not proof a person
/// wrote it -- most tools leave no marker at all, so any existing repository's
/// history is largely unrecoverable. Claiming those commits as deliberate human
/// direction would manufacture exactly the signal this field exists to protect.
fn commit_provenance(author: &str, email: &str, trailers: &str, subject: &str) -> String {
    let identity = format!("{author} {email}").to_lowercase();
    if BOT_MARKERS.iter().any(|marker| identity.contains(marker)) {
        return "bot".to_owned();
    }
    let attributed = format!("{trailers} {subject}").to_lowercase();
    let agent = AGENT_MARKERS
        .iter()
        .any(|marker| attributed.contains(marker) || identity.contains(marker));
    if !agent {
        return "unknown".to_owned();
    }
    // An agent is named. If a person's identity is on the commit as well, they
    // reviewed and took ownership of the output; that is weaker than authorship
    // but stronger than an unattended write.
    if AGENT_MARKERS.iter().any(|marker| identity.contains(marker)) {
        "ai_generated".to_owned()
    } else {
        "human_review".to_owned()
    }
}

/// A sweeping refactor touches hundreds of files and says very little about any
/// one of them. Anchoring every path would let one such commit dominate the
/// association graph for a whole service, so the record keeps the first few and
/// the commit stays addressable by sha for anyone who wants the rest.
const MAX_COMMIT_ANCHORS: usize = 32;

fn scan_git_history(
    repo: &Repository,
    checkpoint: Option<&str>,
) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let default = repo.default_branch();
    // Ingest refuses a batch over 10,000 observations, and the adapter cannot page:
    // `scan` never receives the checkpoint. The largest repository measured has 148,004
    // commits, so an unbounded walk produced nothing at all -- the whole batch was
    // refused and the repository ended up with no code history whatsoever.
    //
    // Bounding to the most recent commits is a sampling decision, not an authority
    // one: what a commit is worth is still decided by standing and provenance. Old
    // history is the least informative part of a brownfield repository anyway, and
    // some history beats none by a wide margin. Paging by checkpoint is the better
    // answer and wants `scan` to carry it.
    // Paging window, taken from the ingest checkpoint. Ingest refuses a batch over
    // 10,000 observations, so an unbounded walk over a repository with 148,004
    // commits was refused entirely and that repository ended up with no code history
    // at all. `--checkpoint skip:N` moves the window back; the size is fixed below
    // the batch ceiling with headroom for the ref and merge records emitted with the
    // commits.
    //
    // Deliberately not environment variables: the control policy forbids the product
    // branching on environment names that are not permitted controls, and it is
    // right -- a documented argument is inspectable and reproducible where an
    // ambient variable is neither.
    let max: usize = 6_000;
    let skip: usize = checkpoint
        .and_then(|value| value.strip_prefix("skip:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let max_flag = format!("-{max}");
    let skip_flag = format!("--skip={skip}");
    let log = git(
        &repo.root,
        &[
            "log",
            // Branches and remote branches only: `--all` also walked stashes,
            // notes, filter-branch backups and prefetch refs, whose commits
            // are nobody's history.
            "--branches",
            "--remotes",
            &max_flag,
            &skip_flag,
            // The changed paths ride along in the same walk rather than costing
            // one `git` process per commit. Without them a commit fact knows
            // nothing about where it happened, so no ruling about a directory
            // could reach it and no caller could ask "what is known about this
            // file" -- the association between knowledge and code was missing
            // at its largest source.
            "--name-only",
            "--format=%x01%H%x00%P%x00%T%x00%aI%x00%an%x00%ae%x00%(trailers:key=Co-authored-by,valueonly,separator=%x2C)%x00%s",
        ],
    )
    .map_err(|error| {
        ContractError::new(
            "RUN_INTEGRITY_FAILED",
            format!("git history source is unreadable: {}", error.message),
            "Check the repository and git installation.",
            false,
            crate::error::ExitCode::InternalFailure,
        )
    })?;
    let mut commits = Vec::new();
    // `--name-only` interleaves the changed paths after each commit's format
    // line. 0x01 marks a format line: a path can contain anything a filename
    // can, so the separator has to be something git will not emit as content.
    let mut paths_by_sha: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in log.lines() {
        let Some(header) = line.strip_prefix('\u{1}') else {
            let path = line.trim();
            // A path git had to quote (non-UTF-8 or control bytes) is skipped
            // rather than guessed at: a wrong path is worse than no path.
            if path.is_empty() || path.starts_with('"') {
                continue;
            }
            if let Some(sha) = &current {
                paths_by_sha
                    .entry(sha.clone())
                    .or_default()
                    .push(path.to_owned());
            }
            continue;
        };
        let parts: Vec<&str> = header.splitn(8, '\0').collect();
        if parts.len() < 8 {
            continue;
        }
        current = Some(parts[0].to_owned());
        commits.push(CommitInfo {
            sha: parts[0].to_owned(),
            parents: parts[1].split_whitespace().map(str::to_owned).collect(),
            tree: parts[2].to_owned(),
            author_date: parts[3].to_owned(),
            subject: parts[7].to_owned(),
            provenance: commit_provenance(parts[4], parts[5], parts[6], parts[7]),
        });
    }
    let by_sha: BTreeMap<&str, &CommitInfo> = commits.iter().map(|c| (c.sha.as_str(), c)).collect();
    let reachable: BTreeSet<String> = git(&repo.root, &["rev-list", &default])
        .map(|text| text.lines().map(|l| l.trim().to_owned()).collect())
        .unwrap_or_default();
    // The window is a partial view of the history. A commit outside it that
    // a branch still reaches is present; only one no branch reaches any more
    // (a rewrite) may be retired. Retiring everything outside the window
    // withdrew every trusted merge once it aged past 6,000 commits.
    let windowed: BTreeSet<&str> = commits.iter().map(|commit| commit.sha.as_str()).collect();
    if let Ok(all) = git(&repo.root, &["rev-list", "--branches", "--remotes"]) {
        scan.present_elsewhere = all
            .lines()
            .map(str::trim)
            .filter(|sha| !sha.is_empty() && !windowed.contains(sha))
            .map(|sha| {
                let origin = if reachable.contains(sha) {
                    "merged-default"
                } else {
                    "unreviewed-branch"
                };
                (format!("commit:{sha}"), origin.to_owned())
            })
            .collect();
    }
    if commits.len() == max {
        scan.next_checkpoint = Some(format!("skip:{}", skip + max));
    }
    // Git-evidenced revert detection: a commit undid its parent when every
    // path the parent changed (against the parent's first parent) is back at
    // the grandparent's blob. Tree identity is the exact case; the path rule
    // also covers reverts that carry unrelated worktree additions.
    let mut reverted_by: BTreeMap<String, String> = BTreeMap::new();
    for commit in &commits {
        // A revert that never reached the default branch undid nothing
        // there: an unmerged `revert-…` branch must not withdraw a merge.
        if !reachable.contains(&commit.sha) {
            continue;
        }
        let Some(parent_sha) = commit.parents.first() else {
            continue;
        };
        let Some(parent) = by_sha.get(parent_sha.as_str()) else {
            continue;
        };
        let Some(grandparent_sha) = parent.parents.first() else {
            continue;
        };
        let Some(grandparent) = by_sha.get(grandparent_sha.as_str()) else {
            continue;
        };
        if commit.tree == grandparent.tree {
            reverted_by.insert(parent.sha.clone(), commit.sha.clone());
            continue;
        }
        let message_revert = commit.subject.to_ascii_lowercase().contains("revert");
        if !message_revert && parent.parents.len() < 2 {
            continue;
        }
        // NUL-separated, so a path git would quote (non-ASCII, controls) is
        // the path itself rather than a quoted spelling no lookup resolves.
        let Ok(changed) = git(
            &repo.root,
            &[
                "diff-tree",
                "-z",
                "--no-commit-id",
                "--name-only",
                "-r",
                &grandparent.sha,
                &parent.sha,
            ],
        ) else {
            continue;
        };
        let paths: Vec<&str> = changed.split('\0').filter(|p| !p.is_empty()).collect();
        if paths.is_empty() {
            continue;
        }
        // A path is restored when both commits hold the same entry for it,
        // or both hold none. A lookup that fails says nothing either way, and
        // a revert is never inferred from two failures.
        let entry = |sha: &str, path: &str| {
            git(
                &repo.root,
                &["--literal-pathspecs", "ls-tree", "-z", sha, "--", path],
            )
            .ok()
        };
        let restored = paths.iter().all(|path| {
            match (entry(&grandparent.sha, path), entry(&commit.sha, path)) {
                (Some(before), Some(after)) => before == after,
                _ => false,
            }
        });
        if restored {
            reverted_by.insert(parent.sha.clone(), commit.sha.clone());
        }
    }
    for commit in &commits {
        let is_merge = commit.parents.len() >= 2;
        let reverts = reverted_by
            .iter()
            .find(|(_, by)| **by == commit.sha)
            .map(|(target, _)| target.clone());
        let native_id = format!("commit:{}", commit.sha);
        let mut record = SourceRecord::new(&native_id, &native_id);
        record.logical_key = if is_merge {
            format!("git_history:merge:{}", commit.sha)
        } else {
            format!("git_history:commit:{}", commit.sha)
        };
        record.statement = if is_merge {
            format!(
                "merge {}: {}",
                &commit.sha[..12.min(commit.sha.len())],
                commit.subject
            )
        } else {
            format!(
                "commit {}: {}",
                &commit.sha[..12.min(commit.sha.len())],
                commit.subject
            )
        };
        record.atom_kind = if is_merge { "decision" } else { "observation" }.to_owned();
        record.disposition = if reverted_by.contains_key(&commit.sha) {
            "reverted"
        } else if reverts.is_some() {
            "revert"
        } else if is_merge {
            "merged"
        } else {
            "committed"
        }
        .to_owned();
        record.content = commit.sha.as_bytes().to_vec();
        record.provenance = commit.provenance.clone();
        record.confidence = 8_000;
        record.asserted_at = crate::time::normalize_foreign_time(&commit.author_date);
        record.origin = if reachable.contains(&commit.sha) {
            "merged-default".to_owned()
        } else {
            "unreviewed-branch".to_owned()
        };
        record.revision = Some(commit.sha.clone());
        // A whole-file anchor: the commit touched this path at this revision.
        // Line 0 to 0 is the file-level span -- a commit is evidence about the
        // file, and narrowing it to hunks would cost a diff per commit for a
        // precision nothing downstream asks for yet. A generated file is not
        // evidence of anyone's intent, so it anchors nothing.
        record.anchors = paths_by_sha
            .get(&commit.sha)
            .map(|paths| {
                paths
                    .iter()
                    .filter(|path| !is_generated_path(path))
                    .take(MAX_COMMIT_ANCHORS)
                    .map(|path| crate::model::CodeAnchor {
                        path: path.clone(),
                        line_start: 0,
                        line_end: 0,
                        revision: Some(commit.sha.clone()),
                        span_sha256: None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        record
            .attributes
            .insert("parents".to_owned(), json!(commit.parents));
        record
            .attributes
            .insert("tree".to_owned(), json!(commit.tree));
        record
            .attributes
            .insert("is_merge".to_owned(), json!(is_merge));
        if let Some(by) = reverted_by.get(&commit.sha) {
            record
                .attributes
                .insert("reverted_by".to_owned(), json!(by));
        }
        if let Some(target) = reverts {
            record
                .attributes
                .insert("reverts".to_owned(), json!(target));
        }
        // Historical validity claims are never quarantined; an author date
        // that precedes the parent's is recorded as bounded ordering evidence.
        if let Some(parent) = commit.parents.first().and_then(|p| by_sha.get(p.as_str())) {
            let earlier = crate::time::normalize_foreign_time(&commit.author_date)
                .zip(crate::time::normalize_foreign_time(&parent.author_date))
                .is_some_and(|(mine, theirs)| mine < theirs);
            if earlier {
                record
                    .attributes
                    .insert("skew_bounded".to_owned(), json!(true));
            }
        }
        scan.unit_ids.insert(native_id);
        scan.records.push(record);
    }
    if let Ok(refs) = git(
        &repo.root,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)",
            "refs/heads",
            "refs/remotes",
        ],
    ) {
        for line in refs.lines() {
            let Some((name, sha)) = line.split_once('\0') else {
                continue;
            };
            let native_id = format!("ref:{name}");
            let mut record = SourceRecord::new(&native_id, &native_id);
            record.logical_key = format!("git_history:ref:{name}");
            record.statement = format!("{name} at {sha}");
            record.atom_kind = "observation".to_owned();
            record.disposition = "ref".to_owned();
            record.content = format!("{name}\0{sha}").into_bytes();
            record.confidence = 8_000;
            record.origin = if reachable.contains(sha) {
                "merged-default".to_owned()
            } else {
                "unreviewed-branch".to_owned()
            };
            record.revision = Some(sha.to_owned());
            record.branch = Some(name.trim_start_matches("refs/heads/").to_owned());
            scan.unit_ids.insert(native_id);
            scan.records.push(record);
        }
    }
    if scan.records.is_empty() {
        return Err(ContractError::invariant(
            "git history source contains no commits or refs",
        ));
    }
    Ok(scan)
}

// --------------------------------------------------------------------------
// github_export: snapshot exports, newest snapshot defines presence
// --------------------------------------------------------------------------

fn scan_github_export(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let mut files: Vec<(i64, PathBuf)> = source_files(source)?
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e == "json")
        })
        .map(|path| (file_mtime(&path).unwrap_or(0), path))
        .collect();
    files.sort();
    // Only a parsed export can say what exists now. The most recently
    // written file failing to parse is most likely a download still in
    // progress: the scan is refused rather than read as "everything was
    // removed". Any other unreadable or unrelated JSON is skipped and counted.
    let last_written = files.last().map(|(_, path)| path.clone());
    let mut exports: Vec<(String, i64, PathBuf, Map<String, Value>)> = Vec::new();
    for (mtime, path) in files {
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        let Ok(parsed) = serde_json::from_slice::<Value>(&bytes) else {
            if Some(&path) == last_written.as_ref() {
                return Err(ContractError::new(
                    "CONFIG_INVARIANT",
                    format!(
                        "the most recent GitHub export ({}) is not valid JSON",
                        relative_to(&repo.root, &path)
                    ),
                    "Finish or remove the partial export, then ingest again.",
                    false,
                    crate::error::ExitCode::Refused,
                ));
            }
            scan.skip("github_export: file is not valid JSON");
            continue;
        };
        // Valid JSON of another shape is some other document, not a
        // half-written export.
        let Value::Object(map) = parsed else {
            scan.skip("github_export: JSON document is not an export");
            continue;
        };
        let is_export = ["issues", "pullRequests"]
            .iter()
            .any(|key| map.get(*key).is_some_and(Value::is_array));
        if !is_export {
            scan.skip("github_export: JSON document is not an export");
            continue;
        }
        let time = export_time(&map).unwrap_or_else(|| mtime_rfc3339(mtime));
        exports.push((time, mtime, path, map));
    }
    // The export's own time orders snapshots (its header, else its latest
    // item update); a checkout gives files near-identical modification times,
    // which made "newest" a lexical accident.
    exports.sort_by(|a, b| (&a.0, a.1, &a.2).cmp(&(&b.0, b.1, &b.2)));
    let mut latest: BTreeMap<String, SourceRecord> = BTreeMap::new();
    let mut newest_ids: BTreeSet<String> = BTreeSet::new();
    let document_count = exports.len();
    let total = exports.len();
    for (index, (_, _, path, map)) in exports.into_iter().enumerate() {
        let relpath = relative_to(&repo.root, &path);
        scan.unit_ids.insert(relpath.clone());
        let is_newest = index + 1 == total;
        for (key, prefix) in [("issues", "issue"), ("pullRequests", "pull")] {
            let Some(items) = map.get(key).and_then(Value::as_array) else {
                continue;
            };
            for item in items {
                let Some(object) = item.as_object() else {
                    scan.skip("github_export: item is not an object");
                    continue;
                };
                // Items without a number used to collapse into one `…:0`.
                let Some(number) = object.get("number").and_then(Value::as_i64) else {
                    scan.skip("github_export: item has no number");
                    continue;
                };
                let native_id = format!("{prefix}:{number}");
                let title = object
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let body = object
                    .get("body")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let state = object
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or("open");
                let merged = object.get("merged") == Some(&Value::Bool(true));
                let reopened = object.get("reopened") == Some(&Value::Bool(true));
                let reviews: Vec<String> = object
                    .get("reviews")
                    .and_then(Value::as_array)
                    .map(|reviews| {
                        reviews
                            .iter()
                            .filter_map(|review| review.get("state").and_then(Value::as_str))
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                let mut record = SourceRecord::new(&native_id, &relpath);
                record.logical_key = format!("github_export:{native_id}");
                record.statement = format!("{title}: {body}").trim().to_owned();
                record.atom_kind = if prefix == "pull" {
                    "decision"
                } else {
                    "question"
                }
                .to_owned();
                record.disposition = if prefix == "pull" {
                    if merged {
                        "merged".to_owned()
                    } else if state == "closed" {
                        "rejected".to_owned()
                    } else if reviews.iter().any(|r| r == "APPROVED")
                        && reviews.iter().any(|r| r == "CHANGES_REQUESTED")
                    {
                        "disputed".to_owned()
                    } else if reviews.iter().any(|r| r == "APPROVED") {
                        "approved".to_owned()
                    } else {
                        "proposed".to_owned()
                    }
                } else if reopened {
                    "reopened".to_owned()
                } else if state == "closed" {
                    "closed".to_owned()
                } else {
                    "open".to_owned()
                };
                record.content = crate::json::canonical_bytes(item);
                record.confidence = if merged { 8_000 } else { 6_000 };
                record.asserted_at = time_string(object.get("updatedAt").and_then(Value::as_str));
                record.origin = repo.origin_trust(&path);
                record.attributes.insert("state".to_owned(), json!(state));
                record.attributes.insert("merged".to_owned(), json!(merged));
                record
                    .attributes
                    .insert("reopened".to_owned(), json!(reopened));
                record
                    .attributes
                    .insert("reviews".to_owned(), json!(reviews));
                record
                    .attributes
                    .insert("snapshot".to_owned(), json!(relpath));
                if object.get("edited") == Some(&Value::Bool(true)) {
                    record.attributes.insert("edited".to_owned(), json!(true));
                }
                record.present = is_newest;
                if is_newest {
                    newest_ids.insert(native_id.clone());
                }
                latest.insert(native_id, record);
            }
        }
    }
    if document_count == 0 {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "GitHub export contains no export document",
            "Use a valid native source envelope.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    for (native_id, mut record) in latest {
        record.present = newest_ids.contains(&native_id);
        scan.records.push(record);
    }
    Ok(scan)
}

/// An export's own time: an `exported_at`/`generated_at` header, else the
/// latest `updatedAt` among the items that are records (objects with a
/// number). None when it carries neither; the caller then uses file time.
fn export_time(map: &Map<String, Value>) -> Option<String> {
    let header = ["exported_at", "exportedAt", "generated_at", "generatedAt"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_str))
        .find_map(crate::time::normalize_foreign_time);
    if header.is_some() {
        return header;
    }
    ["issues", "pullRequests"]
        .iter()
        .filter_map(|key| map.get(*key).and_then(Value::as_array))
        .flatten()
        .filter(|item| item.get("number").and_then(Value::as_i64).is_some())
        .filter_map(|item| item.get("updatedAt").and_then(Value::as_str))
        .filter_map(crate::time::normalize_foreign_time)
        .max()
}

fn mtime_rfc3339(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0)
        .map(crate::time::format_rfc3339_millis)
        .unwrap_or_default()
}

// --------------------------------------------------------------------------
// kindex: SQLite exports (nodes and edges) or a `.kin/` event tree
// --------------------------------------------------------------------------

fn sqlite_files(source: &Path) -> Result<Vec<PathBuf>, ContractError> {
    Ok(source_files(source)?
        .into_iter()
        .filter(|path| {
            path.extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| matches!(e, "sqlite" | "sqlite3" | "db"))
        })
        .collect())
}

pub fn is_kindex_sqlite_source(source: &Path) -> bool {
    sqlite_files(source)
        .map(|files| !files.is_empty())
        .unwrap_or(false)
}

/// Column names present on a Kindex `nodes` table.
///
/// Kindex has shipped more than one shape and Kinbase must read whichever is in
/// front of it, so the adapter asks rather than assumes.
fn kindex_columns(connection: &rusqlite::Connection) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    if let Ok(mut statement) = connection.prepare("PRAGMA table_info(nodes)") {
        if let Ok(mut rows) = statement.query([]) {
            while let Ok(Some(row)) = rows.next() {
                if let Ok(name) = row.get::<_, String>(1) {
                    names.insert(name);
                }
            }
        }
    }
    names
}

fn scan_kindex(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    let files = sqlite_files(source)?;
    let mut nodes: BTreeMap<String, SourceRecord> = BTreeMap::new();
    let mut edges: Vec<(String, String, String)> = Vec::new();
    for path in files {
        let relpath = relative_to(&repo.root, &path);
        scan.unit_ids.insert(relpath.clone());
        let connection = rusqlite::Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("Kindex export is unreadable: {error}"),
                "Use a valid Kindex 0.36 SQLite export or signed `.kin/events` tree.",
            )
        })?;
        // Kindex and Kinbase are the same family and must interoperate, so this
        // reads the schema Kindex actually ships rather than an export format it
        // never emitted. The columns were guessed once and never run against a real
        // store: `node_type` and `payload` do not exist, and the query failed on
        // every one of 87 populated Kindex databases in one deployment.
        //
        // Real Kindex carries more than Kinbase asked for, and the extra columns are
        // exactly the ones this product needs: `prov_who` and `prov_source` are
        // provenance, `status` is disposition, `audience` says who a node is for.
        // The older export shape is still accepted so a genuine export keeps working.
        let columns = kindex_columns(&connection);
        let node_type_column = if columns.contains("type") {
            "type"
        } else {
            "node_type"
        };
        let payload_column = if columns.contains("extra") {
            "extra"
        } else {
            "payload"
        };
        let provenance_column = if columns.contains("prov_source") {
            "prov_source"
        } else if columns.contains("prov_who") {
            "prov_who"
        } else {
            "NULL"
        };
        let status_column = if columns.contains("status") {
            "status"
        } else {
            "NULL"
        };
        let audience_column = if columns.contains("audience") {
            "audience"
        } else {
            "NULL"
        };
        let query = format!(
            "SELECT id, {node_type_column}, title, content, {payload_column}, created_at, \
             {provenance_column}, {status_column}, {audience_column} FROM nodes"
        );
        let mut statement = connection.prepare(&query).map_err(|error| {
            ContractError::refused(
                "CONFIG_INVARIANT",
                format!("Kindex nodes table is unavailable: {error}"),
                "Use a Kindex store or a 0.36 SQLite export.",
            )
        })?;
        let mut rows = statement.query([]).map_err(|error| {
            ContractError::invariant(format!("Kindex nodes cannot be read: {error}"))
        })?;
        while let Some(row) = rows
            .next()
            .map_err(|error| ContractError::invariant(error.to_string()))?
        {
            let id: String = row.get(0).unwrap_or_default();
            let node_type: Option<String> = row.get(1).ok();
            let title: Option<String> = row.get(2).ok();
            let content: Option<String> = row.get(3).ok();
            let payload: Option<Vec<u8>> = row.get(4).ok();
            let created_at: Option<String> = row.get(5).ok();
            let kindex_provenance: Option<String> = row.get(6).ok();
            let kindex_status: Option<String> = row.get(7).ok();
            let kindex_audience: Option<String> = row.get(8).ok();
            // Kindex says who a node is for and whether it stands. This adapter
            // feeds the Codebase store, which ships with the repository, so it
            // takes only standing nodes meant for the team or the public. The
            // older export shape has neither column and keeps its behaviour.
            if let Some(status) = kindex_status.as_deref() {
                if !matches!(status, "active" | "open-question") {
                    scan.skip("kindex: node is not active");
                    continue;
                }
            }
            if let Some(audience) = kindex_audience.as_deref() {
                if !matches!(audience, "team" | "public") {
                    scan.skip("kindex: audience is not team or public");
                    continue;
                }
            }
            let payload_text = payload
                .as_ref()
                .map(|bytes| String::from_utf8_lossy(bytes).trim().to_owned())
                .unwrap_or_default();
            let metadata: Map<String, Value> = serde_json::from_str::<Value>(&payload_text)
                .ok()
                .and_then(|value| value.as_object().cloned())
                .unwrap_or_default();
            let statement_text = content
                .filter(|value| !value.trim().is_empty())
                .or_else(|| title.clone().filter(|value| !value.trim().is_empty()))
                .unwrap_or_else(|| format!("Kindex node {id}"));
            let mut record = SourceRecord::new(&id, &relpath);
            record.logical_key = format!("kindex:{id}");
            record.statement = statement_text.clone();
            // Kindex records who put a node there. Honour it rather than defaulting
            // everything to `unknown`: a node a person wrote is human evidence, and a
            // node an agent captured during a session is not, which is the same
            // distinction Kinbase draws everywhere else.
            record.provenance = match kindex_provenance.as_deref().map(str::to_lowercase) {
                Some(ref who)
                    if ["claude", "codex", "agent", "gpt", "copilot", "cursor"]
                        .iter()
                        .any(|marker| who.contains(marker)) =>
                {
                    "ai_generated".to_owned()
                }
                Some(ref who) if who.contains("transcript") => "transcript".to_owned(),
                Some(ref who) if !who.trim().is_empty() => "human".to_owned(),
                _ => "unknown".to_owned(),
            };
            record.atom_kind = match node_type.as_deref() {
                Some("decision") => "decision",
                Some("constraint") => "constraint",
                Some("question") => "question",
                Some("rationale") => "rationale",
                _ => "claim",
            }
            .to_owned();
            record.disposition = metadata
                .get("disposition")
                .and_then(Value::as_str)
                .unwrap_or("accepted")
                .to_owned();
            record.content = crate::json::canonical_bytes(&json!({
                "id": id, "node_type": node_type, "title": title, "content": statement_text,
                "payload": metadata
            }));
            record.confidence = 8_000;
            record.asserted_at = time_string(created_at.as_deref());
            record.effective_until = metadata
                .get("effective_until")
                .and_then(Value::as_str)
                .and_then(|value| time_string(Some(value)));
            record.parents = metadata
                .get("supersedes")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            record.origin = repo.origin_trust(&path);
            record
                .attributes
                .insert("node_type".to_owned(), json!(node_type));
            record
                .attributes
                .insert("payload".to_owned(), Value::Object(metadata));
            nodes.entry(id).or_insert(record);
        }
        if let Ok(mut edge_statement) =
            connection.prepare("SELECT src, dst, relationship, reason FROM edges")
        {
            if let Ok(mut rows) = edge_statement.query([]) {
                while let Ok(Some(row)) = rows.next() {
                    let src: String = row.get(0).unwrap_or_default();
                    let dst: String = row.get(1).unwrap_or_default();
                    let relationship: Option<String> = row.get(2).ok();
                    edges.push((
                        src,
                        dst,
                        relationship.unwrap_or_else(|| "relates-to".to_owned()),
                    ));
                }
            }
        }
    }
    for (src, dst, relationship) in edges {
        match relationship.as_str() {
            "supersedes" => {
                if let Some(record) = nodes.get_mut(&src) {
                    if !record.parents.contains(&dst) {
                        record.parents.push(dst.clone());
                    }
                }
                if let Some(target) = nodes.get_mut(&dst) {
                    target
                        .attributes
                        .insert("superseded_by".to_owned(), json!(src));
                }
            }
            "contradicts" => {
                for (a, b) in [(&src, &dst), (&dst, &src)] {
                    if let Some(record) = nodes.get_mut(a) {
                        let mut list = record
                            .attributes
                            .get("contradicts")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        list.push(json!(b));
                        record
                            .attributes
                            .insert("contradicts".to_owned(), Value::Array(list));
                    }
                }
            }
            _ => {}
        }
    }
    scan.records = nodes.into_values().collect();
    if scan.records.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "Kindex export contains no nodes",
            "Use a valid Kindex 0.36 SQLite export.",
        ));
    }
    Ok(scan)
}

// --------------------------------------------------------------------------
// authority_answer: signed answers to registered questions
// --------------------------------------------------------------------------

fn scan_answers(source: &Path, repo: &Repository) -> Result<SourceScan, ContractError> {
    let mut scan = SourceScan::default();
    for path in source_files(source)? {
        let bytes = read_bounded(&path)?;
        check_budget(&mut scan, bytes.len())?;
        let Ok(value) = crate::json::parse_strict_value(&bytes) else {
            continue;
        };
        let Some(map) = value.as_object() else {
            continue;
        };
        let is_answer = map.get("schema").and_then(Value::as_str) == Some("kinbase-answer/1")
            || map.get("message_type").and_then(Value::as_str) == Some("answer")
            || (map.get("question_id").is_some() && map.get("answer").is_some());
        if !is_answer {
            continue;
        }
        let relpath = relative_to(&repo.root, &path);
        let digest = sha256_bytes(&crate::json::canonical_bytes(&value));
        let question_id = map
            .get("question_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-question");
        let native_id = format!("answer:{}", &digest[..16]);
        let mut record = SourceRecord::new(&native_id, &relpath);
        record.logical_key = format!("authority_answer:{question_id}");
        record.statement = map
            .get("answer")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        record.atom_kind = "decision".to_owned();
        record.disposition = "answered".to_owned();
        record.content = crate::json::canonical_bytes(&value);
        record.scope = map
            .get("authority_scope")
            .and_then(Value::as_str)
            .unwrap_or("architecture:company")
            .to_owned();
        record.confidence = 9_800;
        record.asserted_at = time_string(
            map.get("asserted_at")
                .or_else(|| map.get("answered_at"))
                .and_then(Value::as_str),
        );
        record.signer = map.get("signer").and_then(Value::as_str).map(str::to_owned);
        record.parents = map
            .get("parents")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        record.origin = repo.origin_trust(&path);
        let signature_valid = crate::crypto::PublicKey::verify_document("answer", &value).is_some();
        record
            .attributes
            .insert("question_id".to_owned(), json!(question_id));
        record.attributes.insert(
            "authority_id".to_owned(),
            map.get("authority_id").cloned().unwrap_or(Value::Null),
        );
        record
            .attributes
            .insert("signature_valid".to_owned(), json!(signature_valid));
        record
            .attributes
            .insert("content_digest".to_owned(), json!(digest));
        scan.unit_ids.insert(relpath);
        scan.records.push(record);
    }
    if scan.records.is_empty() {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "authority_answer source contains no signed answer",
            "Use a valid native source envelope.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    Ok(scan)
}

// ==========================================================================
// Projection: observation ledger -> derived facts and Unknowns
// ==========================================================================

/// Authority facts the projection needs; a narrow view of the trust context.
#[derive(Debug, Clone, Default)]
pub struct TrustFacts {
    pub repository_uuid: Option<String>,
    /// Active registry entries: (scope, public_key, authority_id, cursor).
    pub active_entries: Vec<(String, String, String, String)>,
    /// Revocations: (revoked_key, cursor, effective_at).
    pub revocations: Vec<(String, String, String)>,
    pub steward_authority_id: Option<String>,
    pub certificate_valid: bool,
    pub personal_owner: String,
    /// revoked_key -> (latest revocation cursor, ledger cursor when first observed).
    pub revocation_watermarks: BTreeMap<String, (String, u64)>,
    /// The keys the publishing authority still reports as revoked at the
    /// current authority cursor. The registry authority owns this fact: its
    /// entry cursors and its revocation cursors live in different spaces, so a
    /// client that re-derives revocation by comparing them decides it locally
    /// and gets it wrong. `None` means no authority answer was read and the
    /// cursor comparison below is the only evidence available.
    pub governing_revoked_keys: Option<BTreeSet<String>>,
    /// The operator's certificate-bound maintainer keys, which warrant a
    /// certified repository without a registry entry.
    pub maintainer_keys: BTreeSet<String>,
    /// Every key a registry entry has named for this repository's
    /// `codebase:`/`repository:` scope, whether still active or since
    /// revoked.
    pub repository_keys: BTreeSet<String>,
}

impl TrustFacts {
    /// Whether an unrevoked key still warrants this repository's derived
    /// facts: an active `codebase:`/`repository:` owner, or a
    /// certificate-bound maintainer key (as `TrustContext::is_maintainer`
    /// accepts them).
    fn repository_warranted(&self) -> bool {
        let Some(uuid) = &self.repository_uuid else {
            return false;
        };
        let scopes = [format!("codebase:{uuid}"), format!("repository:{uuid}")];
        self.active_entries
            .iter()
            .filter(|(scope, _, _, _)| scopes.contains(scope))
            .map(|(_, key, _, _)| key)
            .chain(self.maintainer_keys.iter())
            .any(|key| !self.key_revoked(key))
    }

    fn owner_of_scope(&self, scope: &str) -> Option<(String, String)> {
        let owners: Vec<&(String, String, String, String)> = self
            .active_entries
            .iter()
            .filter(|(s, key, _, _)| s == scope && !self.key_revoked(key))
            .collect();
        owners
            .first()
            .map(|(_, key, identity, _)| (key.clone(), identity.clone()))
    }

    fn maintainer_scope(&self) -> Option<String> {
        self.repository_uuid
            .as_ref()
            .map(|uuid| format!("codebase:{uuid}"))
    }

    /// Currently revoked: the newest revocation of the key is not followed
    /// by a re-registration at a later cursor.
    fn key_revoked(&self, key: &str) -> bool {
        if let Some(governing) = &self.governing_revoked_keys {
            return governing.contains(key);
        }
        let Some(latest) = self
            .revocations
            .iter()
            .filter(|(k, _, _)| k == key)
            .map(|(_, cursor, _)| cursor.parse::<u128>().unwrap_or(0))
            .max()
        else {
            return false;
        };
        let reregistered = self
            .active_entries
            .iter()
            .filter(|(_, k, _, _)| k == key)
            .map(|(_, _, _, cursor)| cursor.parse::<u128>().unwrap_or(0))
            .max()
            .unwrap_or(0);
        reregistered <= latest
    }

    /// Whether an artefact warranted by `key` and asserted at `asserted_at`
    /// is historical: the key was revoked after the assertion, so the fact
    /// remains history and never re-enters the trusted projection.
    fn revoked_for(&self, key: &str, asserted_at: Option<&str>) -> Option<String> {
        if self.key_revoked(key) {
            return self
                .revocations
                .iter()
                .filter(|(k, _, _)| k == key)
                .map(|(_, _, effective)| effective.clone())
                .max()
                .or_else(|| Some(String::new()));
        }
        let asserted = asserted_at?;
        self.revocations
            .iter()
            .filter(|(k, _, effective)| k == key && effective.as_str() > asserted)
            .map(|(_, _, effective)| effective.clone())
            .max()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DerivedFact {
    pub fact_id: String,
    pub logical_key: String,
    pub statement: Option<String>,
    pub statement_digest: String,
    pub state: String,
    pub disposition: String,
    pub atom_kind: String,
    pub source_kind: String,
    pub store_kind: String,
    pub evidence_refs: Vec<String>,
    pub support_event_ids: Vec<String>,
    pub independent_support_count: usize,
    pub owner_identity: Option<String>,
    pub owner_role: Option<String>,
    pub origin_trust_class: String,
    pub effective_until: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DerivedUnknownRow {
    pub unknown_id: String,
    pub logical_key: String,
    pub kind: String,
    pub status: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub owner: String,
    pub question: String,
    pub decision_blocked: String,
    pub evidence_refs: Vec<String>,
    pub affected_logical_keys: Vec<String>,
    pub source_kind: String,
    pub store_kind: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DerivedView {
    pub facts: Vec<DerivedFact>,
    pub unknowns: Vec<DerivedUnknownRow>,
    /// observation_id -> (state, disposition)
    pub observation_states: BTreeMap<String, (String, String)>,
}

pub fn store_for(source_kind: &str) -> &'static str {
    match source_kind {
        "codex_jsonl" | "claude_jsonl" => "personal",
        "authority_answer" => "company",
        _ => "codebase",
    }
}

fn attr<'a>(observation: &'a Observation, key: &str) -> Option<&'a Value> {
    observation.attributes.as_ref().and_then(|a| a.get(key))
}

fn attr_str<'a>(observation: &'a Observation, key: &str) -> Option<&'a str> {
    attr(observation, key).and_then(Value::as_str)
}

fn alive(observation: &Observation) -> bool {
    observation.lifecycle == "observed"
}

fn withdrawn_lifecycle(observation: &Observation) -> bool {
    matches!(
        observation.lifecycle.as_str(),
        "retracted" | "absent" | "rewritten"
    )
}

fn expired(observation: &Observation, as_of: &str) -> bool {
    observation
        .effective_until
        .as_deref()
        .is_some_and(|until| until <= as_of)
}

fn squeeze(statement: &str) -> String {
    crate::scanner::squeeze(statement)
}

fn fact_id_for(logical_key: &str, statement_digest: &str) -> String {
    format!(
        "dfact_{}",
        &crate::hash::sha256_text(&format!("{logical_key}\0{statement_digest}"))[..40]
    )
}

fn unknown_id_for(logical_key: &str, kind: &str, evidence: &[String]) -> String {
    format!(
        "unknown_{}",
        &crate::hash::sha256_text(&format!(
            "derived\0{logical_key}\0{kind}\0{}",
            evidence.join(",")
        ))[..40]
    )
}

struct FactBuilder<'a> {
    trust: &'a TrustFacts,
    as_of: &'a str,
    view: DerivedView,
}

impl FactBuilder<'_> {
    fn owner_for(&self, observation: &Observation) -> (String, String) {
        let source_kind = observation.source_kind.as_str();
        match store_for(source_kind) {
            "personal" => (
                "session-owner".to_owned(),
                self.trust.personal_owner.clone(),
            ),
            "company" => {
                let scope = observation.scope.clone().unwrap_or_default();
                if let Some((_, identity)) = self.trust.owner_of_scope(&scope) {
                    ("scope-authority".to_owned(), identity)
                } else if let Some(steward) = &self.trust.steward_authority_id {
                    ("company-steward".to_owned(), steward.clone())
                } else {
                    ("company-steward".to_owned(), "company-steward".to_owned())
                }
            }
            _ => {
                if source_kind == "runtime_evidence" {
                    if let Some(owner) = observation.owner_id.as_deref() {
                        return ("deploy-owner".to_owned(), owner.to_owned());
                    }
                }
                let maintainer = self
                    .trust
                    .maintainer_scope()
                    .and_then(|scope| self.trust.owner_of_scope(&scope))
                    .map(|(_, identity)| identity);
                match maintainer {
                    Some(identity) => ("repository-maintainer".to_owned(), identity),
                    None => (
                        "repository-maintainer".to_owned(),
                        "repository-maintainer".to_owned(),
                    ),
                }
            }
        }
    }

    fn set_state(&mut self, observation: &Observation, state: &str, disposition: &str) {
        self.view.observation_states.insert(
            observation.observation_id.clone(),
            (state.to_owned(), disposition.to_owned()),
        );
    }

    fn push_fact(
        &mut self,
        head: &Observation,
        supports: &[&Observation],
        state: &str,
        reason: &str,
    ) -> String {
        let personal = store_for(&head.source_kind) == "personal";
        let statement = head.statement.clone().unwrap_or_default();
        let statement_digest = crate::hash::sha256_text(&squeeze(&statement));
        let logical_key = head
            .logical_key
            .clone()
            .unwrap_or_else(|| format!("{}:{}", head.source_kind, head.native_id));
        let fact_id = fact_id_for(
            &logical_key,
            &format!("{statement_digest}\0{}", head.observation_id),
        );
        let (owner_role, owner_identity) = self.owner_for(head);
        let evidence: Vec<String> = std::iter::once(head.observation_id.clone())
            .chain(supports.iter().map(|s| s.observation_id.clone()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let sources: BTreeSet<&str> = std::iter::once(head.source_identity.as_str())
            .chain(supports.iter().map(|s| s.source_identity.as_str()))
            .collect();
        if let Some(reason) = attr_str(head, "narrowed_view") {
            let evidence_ids: Vec<String> = evidence.clone();
            let narrowed_key = logical_key.clone();
            let (owner_role, owner_identity) = self.owner_for(head);
            let unknown_id = unknown_id_for(&narrowed_key, "narrowed-view", &evidence_ids);
            if !self
                .view
                .unknowns
                .iter()
                .any(|u| u.unknown_id == unknown_id)
            {
                self.view.unknowns.push(DerivedUnknownRow {
                    unknown_id,
                    logical_key: narrowed_key.clone(),
                    kind: "narrowed-view".to_owned(),
                    status: "open".to_owned(),
                    owner_role,
                    owner_identity: owner_identity.clone(),
                    owner: owner_identity,
                    question: format!("{reason}; the observation of {} may be incomplete. Is the full history or tree available?", head.native_id),
                    decision_blocked: format!("use of logical key {narrowed_key}"),
                    evidence_refs: evidence_ids,
                    affected_logical_keys: vec![narrowed_key],
                    source_kind: head.source_kind.clone(),
                    store_kind: store_for(&head.source_kind).to_owned(),
                });
            }
        }
        self.view.facts.push(DerivedFact {
            fact_id: fact_id.clone(),
            logical_key,
            statement: if personal { None } else { Some(statement) },
            statement_digest,
            state: state.to_owned(),
            disposition: head.disposition.clone(),
            atom_kind: head.atom_kind.clone().unwrap_or_else(|| "claim".to_owned()),
            source_kind: head.source_kind.clone(),
            store_kind: store_for(&head.source_kind).to_owned(),
            evidence_refs: evidence.clone(),
            support_event_ids: if state == "current" {
                evidence
            } else {
                Vec::new()
            },
            independent_support_count: if state == "current" { sources.len() } else { 0 },
            owner_identity: Some(owner_identity),
            owner_role: Some(owner_role),
            origin_trust_class: head.origin_trust.clone().unwrap_or_default(),
            effective_until: head.effective_until.clone(),
            reason: reason.to_owned(),
        });
        fact_id
    }

    fn push_unknown(
        &mut self,
        observation: &Observation,
        kind: &str,
        status: &str,
        question: String,
        evidence: Vec<String>,
        owner_override: Option<(String, String)>,
    ) {
        let logical_key = observation
            .logical_key
            .clone()
            .unwrap_or_else(|| format!("{}:{}", observation.source_kind, observation.native_id));
        let (owner_role, owner_identity) =
            owner_override.unwrap_or_else(|| self.owner_for(observation));
        let unknown_id = unknown_id_for(&logical_key, kind, &evidence);
        if self
            .view
            .unknowns
            .iter()
            .any(|u| u.unknown_id == unknown_id)
        {
            return;
        }
        self.view.unknowns.push(DerivedUnknownRow {
            unknown_id,
            logical_key: logical_key.clone(),
            kind: kind.to_owned(),
            status: status.to_owned(),
            owner_role,
            owner_identity: owner_identity.clone(),
            owner: owner_identity,
            question,
            decision_blocked: format!("use of logical key {logical_key}"),
            evidence_refs: evidence,
            affected_logical_keys: vec![logical_key],
            source_kind: observation.source_kind.clone(),
            store_kind: store_for(&observation.source_kind).to_owned(),
        });
    }

    /// A historical row for every observation that no longer supports a
    /// current fact, so history stays addressable from its own evidence.
    fn push_history(&mut self, observation: &Observation, state: &str, reason: &str) {
        let personal = store_for(&observation.source_kind) == "personal";
        let statement = observation.statement.clone().unwrap_or_default();
        let statement_digest = crate::hash::sha256_text(&squeeze(&statement));
        let logical_key = observation
            .logical_key
            .clone()
            .unwrap_or_else(|| format!("{}:{}", observation.source_kind, observation.native_id));
        let (owner_role, owner_identity) = self.owner_for(observation);
        self.view.facts.push(DerivedFact {
            fact_id: fact_id_for(
                &logical_key,
                &format!("history\0{}", observation.observation_id),
            ),
            logical_key,
            statement: if personal { None } else { Some(statement) },
            statement_digest,
            state: state.to_owned(),
            disposition: observation.disposition.clone(),
            atom_kind: observation
                .atom_kind
                .clone()
                .unwrap_or_else(|| "claim".to_owned()),
            source_kind: observation.source_kind.clone(),
            store_kind: store_for(&observation.source_kind).to_owned(),
            evidence_refs: vec![observation.observation_id.clone()],
            support_event_ids: Vec::new(),
            independent_support_count: 0,
            owner_identity: Some(owner_identity),
            owner_role: Some(owner_role),
            origin_trust_class: observation.origin_trust.clone().unwrap_or_default(),
            effective_until: observation.effective_until.clone(),
            reason: reason.to_owned(),
        });
    }
}

fn eligible_disposition(observation: &Observation) -> bool {
    !matches!(
        observation.disposition.as_str(),
        "proposed"
            | "rejected"
            | "superseded"
            | "retracted"
            | "reverted"
            | "revert"
            | "open"
            | "closed"
            | "reopened"
            | "approved"
            | "disputed"
            | "terminal"
            | "committed"
            | "ref"
            | "expired"
            | "manifest_observation_expired"
    )
}

/// Trusted durable direction: the default lineage or a reviewed merge.
fn trusted_origin(observation: &Observation) -> bool {
    matches!(
        observation.origin_trust.as_deref(),
        Some("merged-default")
            | Some("approved-pr")
            | Some("merged-pull")
            | Some("personal-host")
            | Some("company-authority")
            | None
    )
}

/// Eligible to be the head of a key: everything the operator's own worktree
/// holds (committed on the default lineage or a local uncommitted edit), but
/// never a checked-out or divergent unmerged branch, which can only conflict
/// or stay unverified (architecture §4: checking out a branch cannot promote
/// its ADR).
fn head_eligible(observation: &Observation) -> bool {
    trusted_origin(observation)
        || observation.origin_trust.as_deref() == Some("uncommitted-worktree")
}

/// Whether the ledger admitted this observation before the client observed
/// the revocation that withdraws it (then the warranted trace reopens).
fn admitted_before_revocation(
    trust: &TrustFacts,
    observation: &Observation,
    key: Option<&str>,
) -> bool {
    let Some(cursor) = observation.cursor else {
        return true;
    };
    let watermark = match key.and_then(|key| trust.revocation_watermarks.get(key)) {
        Some((_, watermark)) => *watermark,
        None => trust
            .revocation_watermarks
            .values()
            .map(|(_, watermark)| *watermark)
            .max()
            .unwrap_or(u64::MAX),
    };
    cursor <= watermark
}

/// The key whose revocation withdraws the observation: its signer, or the
/// registered repository owner for unsigned Codebase derivations.
fn warranting_key(trust: &TrustFacts, observation: &Observation) -> Option<String> {
    if let Some(signer) = observation.signer.as_deref() {
        return Some(signer.to_owned());
    }
    if store_for(&observation.source_kind) == "codebase" {
        return trust
            .revocation_watermarks
            .keys()
            .find(|key| {
                trust
                    .revocations
                    .iter()
                    .any(|(revoked, _, _)| revoked == *key)
            })
            .cloned();
    }
    None
}

/// The revocation effective time that withdraws this observation, if any.
fn revocation_of(trust: &TrustFacts, observation: &Observation) -> Option<String> {
    if let Some(signer) = observation.signer.as_deref() {
        return trust.revoked_for(signer, observation.asserted_at.as_deref());
    }
    if store_for(&observation.source_kind) == "codebase" {
        // Derived Codebase facts are warranted by the registered repository
        // authority; with no active owner for the repository scope there is
        // no authority left to warrant them. But a revocation is an event
        // that happened, with a time. When nothing has ever been revoked, a
        // registry that simply never named a per-repository owner is not a
        // revocation, and reporting one made every certified repository in the
        // measured deployment show ~45,000 "revoked" unknowns over a store
        // nobody had revoked.
        let nothing_revoked = trust.revocations.is_empty()
            && trust
                .governing_revoked_keys
                .as_ref()
                .is_none_or(|keys| keys.is_empty());
        if nothing_revoked {
            return None;
        }
        // Withdrawn only when nothing unrevoked warrants this repository any
        // more and a revocation names a key that did. A revocation of some
        // other repository's key, with a registry that never named a
        // per-repository owner, used to withdraw every derived fact.
        if !trust.certificate_valid || trust.repository_warranted() {
            return None;
        }
        return trust
            .revocations
            .iter()
            .filter(|(key, _, _)| {
                trust.repository_keys.contains(key) || trust.maintainer_keys.contains(key)
            })
            .map(|(_, _, effective)| effective.clone())
            .max();
    }
    None
}

/// Derive facts and Unknowns from the whole observation ledger.
pub fn derive(observations: &[Observation], trust: &TrustFacts, as_of: &str) -> DerivedView {
    let mut builder = FactBuilder {
        trust,
        as_of,
        view: DerivedView::default(),
    };
    let mut by_key: BTreeMap<String, Vec<&Observation>> = BTreeMap::new();
    for observation in observations {
        if observation.reducer_owned == Some(true) || observation.disposition == "CLOCK_SKEW" {
            continue;
        }
        let key = observation
            .logical_key
            .clone()
            .unwrap_or_else(|| format!("{}:{}", observation.source_kind, observation.native_id));
        by_key.entry(key).or_default().push(observation);
    }
    for (key, mut rows) in by_key {
        rows.sort_by(|a, b| {
            a.observed_at
                .cmp(&b.observed_at)
                .then_with(|| a.native_id.cmp(&b.native_id))
                .then_with(|| a.observation_id.cmp(&b.observation_id))
        });
        let source_kind = rows[0].source_kind.clone();
        match source_kind.as_str() {
            "codex_jsonl" | "claude_jsonl" => derive_personal(&mut builder, &key, &rows),
            "repo_code" | "docs_adr" => derive_repository_file(&mut builder, &key, &rows),
            "repo_tests" | "runtime_evidence" => derive_ordered(&mut builder, &key, &rows),
            "git_history" => derive_git(&mut builder, &key, &rows),
            "github_export" => derive_github(&mut builder, &key, &rows),
            "issue_tracker" | "pull_request" | "chat_thread" | "document" => {
                derive_export(&mut builder, &key, &rows)
            }
            "repo_symbols" => derive_symbols(&mut builder, &key, &rows),
            "kindex" => derive_kindex(&mut builder, &key, &rows),
            "authority_answer" => derive_answers(&mut builder, &key, &rows),
            _ => derive_ordered(&mut builder, &key, &rows),
        }
    }
    builder.view
}

/// Observation-level state for a row that is not the current head.
fn historical_state(observation: &Observation) -> (&'static str, String) {
    match observation.lifecycle.as_str() {
        "retracted" => ("retracted", "retracted_observation".to_owned()),
        "absent" => ("retracted", "absent_source_recorded".to_owned()),
        "rewritten" => ("stale", "rewritten_lineage".to_owned()),
        "renamed" => ("stale", "renamed".to_owned()),
        "superseded" => ("stale", "superseded".to_owned()),
        _ => ("stale", "superseded".to_owned()),
    }
}

fn would_be_current(observation: &Observation, as_of: &str) -> bool {
    eligible_disposition(observation)
        && head_eligible(observation)
        && !observation.native_id.contains('@')
        && !expired(observation, as_of)
}

/// Mark non-alive rows as history and return the alive rows.
fn settle_history<'a>(
    builder: &mut FactBuilder<'_>,
    rows: &[&'a Observation],
    was_current: impl Fn(&Observation) -> bool,
) -> Vec<&'a Observation> {
    let mut alive_rows = Vec::new();
    for row in rows {
        if alive(row) {
            alive_rows.push(*row);
            continue;
        }
        let (state, disposition) = historical_state(row);
        builder.set_state(row, state, &disposition);
        let withdrawn = withdrawn_lifecycle(row);
        let fact_state = if withdrawn { "withdrawn" } else { "superseded" };
        builder.push_history(row, fact_state, &format!("observation {}", row.lifecycle));
        if withdrawn && was_current(row) {
            let evidence = vec![row.observation_id.clone()];
            let question = format!(
                "The native source for {} was {}; the fact it supported is withdrawn. Does it still hold?",
                row.native_id,
                if row.lifecycle == "absent" {
                    "removed"
                } else {
                    "retracted"
                }
            );
            builder.push_unknown(row, "withdrawn", "open", question, evidence, None);
        }
    }
    alive_rows
}

fn derive_personal(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let alive_rows = settle_history(builder, rows, |row| {
        row.disposition == "current" && row.atom_kind.as_deref() != Some("observation")
    });
    for row in alive_rows {
        if row.disposition == "terminal" || row.atom_kind.as_deref() == Some("observation") {
            builder.set_state(row, "current", "terminal");
            continue;
        }
        let disposition = if row.raw_withheld == Some(true) {
            "expired_raw_withheld"
        } else if attr(row, "resumed_from").is_some() {
            "resumed"
        } else if attr(row, "edited").is_some() {
            "amended_new_observation"
        } else {
            "current"
        };
        builder.set_state(row, "current", disposition);
        builder.push_fact(row, &[], "current", "personal observation");
    }
}

fn derive_repository_file(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| would_be_current(row, as_of));
    if alive_rows.is_empty() {
        return;
    }
    let revocation = alive_rows
        .iter()
        .find_map(|row| revocation_of(builder.trust, row));
    // The head is the worktree copy on the default lineage; divergent branch
    // heads (native id `path@branch`) never become the head.
    let head = alive_rows
        .iter()
        .copied()
        .filter(|row| head_eligible(row) && !row.native_id.contains('@'))
        .max_by(|a, b| a.observed_at.cmp(&b.observed_at));
    for row in &alive_rows {
        let is_head = head.is_some_and(|h| h.observation_id == row.observation_id);
        if let Some(effective) = &revocation {
            builder.set_state(row, "quarantined", "revoked_observation");
            if is_head {
                builder.push_fact(row, &[], "withdrawn", "repository authority revoked");
                let evidence = vec![row.observation_id.clone()];
                if admitted_before_revocation(
                    builder.trust,
                    row,
                    warranting_key(builder.trust, row).as_deref(),
                ) {
                    let _ = &effective;
                    let owner = builder
                        .trust
                        .steward_authority_id
                        .clone()
                        .map(|id| ("company-steward".to_owned(), id));
                    builder.push_unknown(
                        row,
                        "revoked",
                        "reopened",
                        format!("The repository authority warranting {} was revoked; the fact is withdrawn pending a re-registered owner.", row.native_id),
                        evidence,
                        owner,
                    );
                }
            } else {
                builder.push_history(row, "withdrawn", "repository authority revoked");
            }
            continue;
        }
        if is_head {
            let disposition = row.disposition.as_str();
            let state = match disposition {
                "proposed" => "proposed",
                "rejected" => "rejected",
                "superseded" => "superseded",
                _ => "current",
            };
            let obs_disposition = if row.renamed_from.is_some() {
                "amended_new_observation"
            } else {
                disposition
            };
            builder.set_state(row, "current", obs_disposition);
            let supports: Vec<&Observation> = alive_rows
                .iter()
                .copied()
                .filter(|other| {
                    other.observation_id != row.observation_id
                        && other.content_digest == row.content_digest
                })
                .collect();
            builder.push_fact(
                row,
                &supports,
                state,
                "repository file at the default lineage",
            );
            continue;
        }
        // Not the head: a divergent branch head or an untrusted worktree copy.
        let same_content = head.is_some_and(|h| h.content_digest == row.content_digest);
        if same_content {
            builder.set_state(row, "current", "supporting");
            continue;
        }
        match head {
            Some(h) if head_eligible(h) => {
                builder.set_state(row, "current", "conflicting_observations");
                builder.push_fact(
                    row,
                    &[],
                    "conflict",
                    "a divergent head contradicts the default lineage",
                );
                let evidence = vec![row.observation_id.clone(), h.observation_id.clone()];
                builder.push_unknown(
                    row,
                    "conflict",
                    "open",
                    format!(
                        "{} on {} disagrees with the default lineage. Which version is intended?",
                        row.native_id,
                        row.branch.as_deref().unwrap_or("another head")
                    ),
                    evidence,
                    None,
                );
            }
            _ => {
                builder.set_state(row, "current", "unreviewed");
                builder.push_fact(
                    row,
                    &[],
                    "unverified",
                    "origin below merged-default is ineligible for trusted direction",
                );
            }
        }
    }
}

/// Ordered evidence (test results, runtime observations): the newest
/// receipt-time observation is the head; older arrivals never overwrite it.
fn derive_ordered(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |_| false);
    if alive_rows.is_empty() {
        return;
    }
    let mut ordered: Vec<&Observation> = alive_rows.clone();
    ordered.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.observed_at.cmp(&b.observed_at))
            .then_with(|| a.native_id.cmp(&b.native_id))
    });
    let head = *ordered.last().unwrap();
    let revocation = revocation_of(builder.trust, head);
    let first_owner = ordered.first().and_then(|row| row.owner_id.clone());
    let head_failed = attr(head, "exit_code").and_then(Value::as_i64).unwrap_or(0) != 0;
    let any_earlier_failure = ordered
        .iter()
        .filter(|row| row.observation_id != head.observation_id)
        .any(|row| attr(row, "exit_code").and_then(Value::as_i64).unwrap_or(0) != 0);
    for row in &ordered {
        let is_head = row.observation_id == head.observation_id;
        if !is_head {
            let disposition =
                if row.asserted_at < head.asserted_at && row.observed_at > head.observed_at {
                    "late_arrival_ordered"
                } else {
                    "superseded"
                };
            builder.set_state(row, "stale", disposition);
            builder.push_history(row, "superseded", "an older result of the same command");
            continue;
        }
        if let Some(effective) = &revocation {
            builder.set_state(row, "quarantined", "revoked_observation");
            builder.push_fact(row, &[], "withdrawn", "repository authority revoked");
            if admitted_before_revocation(
                builder.trust,
                row,
                warranting_key(builder.trust, row).as_deref(),
            ) {
                let _ = &effective;
                let owner = builder
                    .trust
                    .steward_authority_id
                    .clone()
                    .map(|id| ("company-steward".to_owned(), id));
                builder.push_unknown(
                    row,
                    "revoked",
                    "reopened",
                    format!("The authority warranting {} was revoked.", row.native_id),
                    vec![row.observation_id.clone()],
                    owner,
                );
            }
            continue;
        }
        if expired(row, as_of) {
            builder.set_state(row, "stale", "expired_raw_withheld");
            builder.push_fact(
                row,
                &[],
                "withdrawn",
                "the observation passed its effective_until",
            );
            let evidence = vec![row.observation_id.clone()];
            builder.push_unknown(
                row,
                "expired",
                "open",
                format!(
                    "The operational observation {} expired at {}. Is the value still in force?",
                    row.native_id,
                    row.effective_until
                        .as_deref()
                        .unwrap_or("its freshness deadline")
                ),
                evidence,
                None,
            );
            continue;
        }
        let skew_bounded = row
            .receipt_observed_at
            .as_deref()
            .zip(Some(row.observed_at.as_str()))
            .and_then(|(claim, receipt)| crate::time::seconds_between(claim, receipt).ok())
            .is_some_and(|seconds| seconds.abs() > 60);
        builder.set_state(
            row,
            "current",
            if skew_bounded {
                "skew_bounded"
            } else {
                row.disposition.as_str()
            },
        );
        builder.push_fact(
            row,
            &[],
            "current",
            "newest receipt-time observation of the command",
        );
        if row.source_kind == "repo_tests" {
            let evidence = vec![row.observation_id.clone()];
            if head_failed {
                builder.push_unknown(
                    row,
                    "test-failure",
                    "open",
                    format!(
                        "The latest run of {} failed. Which behaviour is intended?",
                        attr_str(row, "command").unwrap_or("the test command")
                    ),
                    evidence,
                    None,
                );
            } else if any_earlier_failure {
                builder.push_unknown(
                    row,
                    "test-failure",
                    "closed",
                    format!(
                        "An earlier failure of {} is resolved by the latest passing run.",
                        attr_str(row, "command").unwrap_or("the test command")
                    ),
                    evidence,
                    None,
                );
            }
        }
        if row.source_kind == "runtime_evidence" {
            if let (Some(first), Some(current)) = (first_owner.as_deref(), row.owner_id.as_deref())
            {
                if first != current {
                    let owner = Some(("deploy-owner".to_owned(), current.to_owned()));
                    let evidence = vec![row.observation_id.clone()];
                    builder.push_unknown(row, "owner-change", "open",
                        format!("The environment owner for {} changed from {first} to {current}. Does the operational fact still hold under the new owner?", row.native_id),
                        evidence, owner);
                }
            }
        }
    }
}

fn derive_git(builder: &mut FactBuilder<'_>, key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| {
        key.starts_with("git_history:merge:") && would_be_current(row, as_of)
    });
    if alive_rows.is_empty() {
        return;
    }
    let head = *alive_rows.last().unwrap();
    let supports: Vec<&Observation> = alive_rows
        .iter()
        .copied()
        .filter(|row| row.observation_id != head.observation_id)
        .collect();
    for row in &supports {
        builder.set_state(row, "current", "supporting");
    }
    if key.starts_with("git_history:ref:") {
        builder.set_state(head, "current", "ref");
        builder.push_fact(
            head,
            &supports,
            "evidence",
            "a ref is structural evidence, not durable direction",
        );
        return;
    }
    if key.starts_with("git_history:merge:") {
        if let Some(by) = attr_str(head, "reverted_by") {
            builder.set_state(head, "current", "reverted");
            builder.push_fact(head, &supports, "withdrawn", "the merge was reverted");
            let evidence = vec![head.observation_id.clone()];
            builder.push_unknown(
                head,
                "reverted",
                "reopened",
                format!(
                    "The merge {} was reverted by {by}. Is the reverted direction still intended?",
                    head.native_id
                ),
                evidence,
                None,
            );
            return;
        }
        if trusted_origin(head) {
            builder.set_state(head, "current", "merged");
            builder.push_fact(
                head,
                &supports,
                "current",
                "a merge into the default lineage is an accepted integration decision",
            );
        } else {
            builder.set_state(head, "current", "unreviewed");
            builder.push_fact(
                head,
                &supports,
                "unverified",
                "a merge on an unreviewed branch",
            );
        }
        return;
    }
    // Plain commits are history: observed, never a fact on their own.
    let disposition = if attr(head, "skew_bounded").is_some() {
        "skew_bounded"
    } else if attr(head, "reverts").is_some() {
        "revert"
    } else if attr(head, "reverted_by").is_some() {
        "reverted"
    } else {
        "committed"
    };
    builder.set_state(head, "current", disposition);
}

fn derive_github(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| {
        would_be_current(row, as_of) && row.disposition == "merged"
    });
    if alive_rows.is_empty() {
        return;
    }
    let head = *alive_rows.last().unwrap();
    for row in alive_rows
        .iter()
        .filter(|r| r.observation_id != head.observation_id)
    {
        builder.set_state(row, "stale", "superseded");
        builder.push_history(row, "superseded", "an earlier export version");
    }
    let disposition = head.disposition.as_str();
    let obs_disposition = if attr(head, "edited").is_some() {
        "amended_new_observation"
    } else {
        disposition
    };
    let evidence = vec![head.observation_id.clone()];
    match disposition {
        "merged" => {
            builder.set_state(head, "current", obs_disposition);
            builder.push_fact(
                head,
                &[],
                "current",
                "a merged pull request is an accepted decision",
            );
            builder.push_unknown(
                head,
                "review-conflict",
                "closed",
                format!(
                    "Reviews of {} disagreed; the merge closed the question.",
                    head.native_id
                ),
                evidence,
                None,
            );
        }
        "disputed" => {
            builder.set_state(head, "current", obs_disposition);
            builder.push_fact(
                head,
                &[],
                "conflict",
                "approval and change requests disagree",
            );
            builder.push_unknown(
                head,
                "review-conflict",
                "open",
                format!(
                    "Reviews of {} disagree (approved and changes requested). Which review stands?",
                    head.native_id
                ),
                evidence,
                None,
            );
        }
        "reopened" => {
            builder.set_state(head, "current", obs_disposition);
            builder.push_fact(head, &[], "open", "a reopened issue is an open question");
            builder.push_unknown(head, "reopened", "reopened",
                format!("Issue {} was reopened after a merge regressed it. What is the intended behaviour?", head.native_id),
                evidence, None);
        }
        "rejected" => {
            builder.set_state(head, "current", obs_disposition);
            builder.push_fact(
                head,
                &[],
                "rejected",
                "a closed, unmerged pull request is negative evidence",
            );
        }
        other => {
            builder.set_state(head, "current", obs_disposition);
            builder.push_fact(head, &[], other, "an open object is not durable direction");
        }
    }
}

/// A row whose warranting repository authority was revoked: quarantined, its
/// fact withdrawn, and, when it was trusted before the revocation, the
/// steward-owned question reopened (as the ordered derivation does).
fn withdraw_revoked(builder: &mut FactBuilder<'_>, row: &Observation) {
    builder.set_state(row, "quarantined", "revoked_observation");
    builder.push_fact(row, &[], "withdrawn", "repository authority revoked");
    if admitted_before_revocation(
        builder.trust,
        row,
        warranting_key(builder.trust, row).as_deref(),
    ) {
        let owner = builder
            .trust
            .steward_authority_id
            .clone()
            .map(|id| ("company-steward".to_owned(), id));
        builder.push_unknown(
            row,
            "revoked",
            "reopened",
            format!("The authority warranting {} was revoked.", row.native_id),
            vec![row.observation_id.clone()],
            owner,
        );
    }
}

/// Exported declarations sharing one key: each definition site is its own
/// reading, not a version of the others. Sites that agree on the shape support
/// one current fact; sites that disagree are a conflict with an open Unknown.
/// The ordered derivation kept only the newest site and called the rest
/// superseded, which is exactly the disagreement the shared key exists to
/// surface.
fn derive_symbols(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| would_be_current(row, as_of));
    if alive_rows.is_empty() {
        return;
    }
    // Rows arrive in observation order: the last reading of a site is its head.
    let mut sites: BTreeMap<&str, &Observation> = BTreeMap::new();
    for row in &alive_rows {
        if let Some(previous) = sites.insert(row.native_id.as_str(), row) {
            builder.set_state(previous, "stale", "superseded");
            builder.push_history(
                previous,
                "superseded",
                "an earlier reading of the same declaration",
            );
        }
    }
    let heads: Vec<&Observation> = sites.into_values().collect();
    if heads
        .iter()
        .any(|row| revocation_of(builder.trust, row).is_some())
    {
        for row in &heads {
            withdraw_revoked(builder, row);
        }
        return;
    }
    let shapes: BTreeSet<&str> = heads
        .iter()
        .map(|row| attr_str(row, "shape").unwrap_or_default())
        .collect();
    let head = heads[0];
    let others: Vec<&Observation> = heads[1..].to_vec();
    if shapes.len() > 1 {
        for row in &heads {
            builder.set_state(row, "current", "conflicting_observations");
        }
        builder.push_fact(
            head,
            &others,
            "conflict",
            "definitions of one exported name disagree in shape",
        );
        let evidence = heads.iter().map(|row| row.observation_id.clone()).collect();
        builder.push_unknown(
            head,
            "conflict",
            "open",
            format!(
                "{} is declared with {} different shapes across {} sites. Which declaration is the interface?",
                attr_str(head, "symbol").unwrap_or("the symbol"),
                shapes.len(),
                heads.len()
            ),
            evidence,
            None,
        );
        return;
    }
    builder.set_state(head, "current", head.disposition.as_str());
    for row in &others {
        builder.set_state(row, "current", "supporting");
    }
    builder.push_fact(head, &others, "current", "the exported declaration's shape");
}

/// Exported records (tickets, pull requests, threads, documents). The newest
/// snapshot by the record's own update time is the head, and it is current
/// direction only when its disposition is eligible (an accepted ticket, a
/// merged pull request); a proposed, open or cancelled record is reported
/// with its disposition. The generic ordered derivation reported every one of
/// them as a current fact.
fn derive_export(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| would_be_current(row, as_of));
    if alive_rows.is_empty() {
        return;
    }
    let updated = |row: &Observation| -> Option<String> {
        attr_str(row, "updated_at")
            .map(str::to_owned)
            .or_else(|| row.asserted_at.clone())
    };
    let mut ordered = alive_rows;
    ordered.sort_by(|a, b| {
        updated(a)
            .cmp(&updated(b))
            .then_with(|| a.observed_at.cmp(&b.observed_at))
            .then_with(|| a.observation_id.cmp(&b.observation_id))
    });
    let head = *ordered.last().unwrap();
    for row in ordered
        .iter()
        .filter(|row| row.observation_id != head.observation_id)
    {
        builder.set_state(row, "stale", "superseded");
        builder.push_history(
            row,
            "superseded",
            "an earlier version of the exported record",
        );
    }
    if revocation_of(builder.trust, head).is_some() {
        withdraw_revoked(builder, head);
        return;
    }
    if expired(head, as_of) {
        builder.set_state(head, "stale", "expired_raw_withheld");
        builder.push_fact(
            head,
            &[],
            "withdrawn",
            "the observation passed its effective_until",
        );
        return;
    }
    if would_be_current(head, as_of) {
        builder.set_state(head, "current", head.disposition.as_str());
        builder.push_fact(
            head,
            &[],
            "current",
            "the newest version of an accepted exported record",
        );
        return;
    }
    // The observation is the record's current version; what it states is
    // not durable direction.
    builder.set_state(head, "current", head.disposition.as_str());
    builder.push_fact(
        head,
        &[],
        head.disposition.as_str(),
        "an exported record that is not accepted is not durable direction",
    );
}

fn derive_kindex(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| {
        would_be_current(row, as_of) && attr(row, "contradicts").is_none()
    });
    if alive_rows.is_empty() {
        return;
    }
    let head = *alive_rows.last().unwrap();
    for row in alive_rows
        .iter()
        .filter(|r| r.observation_id != head.observation_id)
    {
        builder.set_state(row, "stale", "superseded");
        builder.push_history(row, "superseded", "an earlier version of the node");
    }
    if let Some(effective) = revocation_of(builder.trust, head) {
        builder.set_state(head, "quarantined", "revoked_observation");
        builder.push_fact(head, &[], "withdrawn", "repository authority revoked");
        if admitted_before_revocation(
            builder.trust,
            head,
            warranting_key(builder.trust, head).as_deref(),
        ) {
            let _ = &effective;
            let owner = builder
                .trust
                .steward_authority_id
                .clone()
                .map(|id| ("company-steward".to_owned(), id));
            builder.push_unknown(
                head,
                "revoked",
                "reopened",
                format!(
                    "The repository authority warranting node {} was revoked.",
                    head.native_id
                ),
                vec![head.observation_id.clone()],
                owner,
            );
        }
        return;
    }
    let evidence = vec![head.observation_id.clone()];
    let payload_disposition = head.disposition.as_str();
    if expired(head, as_of) || payload_disposition == "manifest_observation_expired" {
        builder.set_state(head, "stale", "expired_raw_withheld");
        builder.push_fact(
            head,
            &[],
            "historical",
            "the node passed its publication horizon",
        );
        builder.push_unknown(
            head,
            "expired",
            "open",
            format!(
                "Node {} expired at its publication horizon. Should it be republished?",
                head.native_id
            ),
            evidence,
            None,
        );
        return;
    }
    if let Some(contradicts) = attr(head, "contradicts").and_then(Value::as_array) {
        builder.set_state(head, "current", "conflicting_observations");
        builder.push_fact(
            head,
            &[],
            "conflict",
            "a contradicts edge names an incompatible node",
        );
        let others: Vec<String> = contradicts
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        builder.push_unknown(
            head,
            "conflict",
            "open",
            format!(
                "Node {} contradicts {}. Which statement is current?",
                head.native_id,
                others.join(", ")
            ),
            evidence,
            None,
        );
        return;
    }
    match payload_disposition {
        "retracted" => {
            builder.set_state(head, "retracted", "retracted_observation");
            builder.push_fact(head, &[], "withdrawn", "the node was retracted");
            builder.push_unknown(head, "withdrawn", "reopened",
                format!("Node {} was retracted; the fact it supported is withdrawn. Does it still hold?", head.native_id),
                evidence, None);
        }
        "superseded" => {
            builder.set_state(head, "stale", "superseded");
            builder.push_fact(
                head,
                &[],
                "superseded",
                "the node declares itself superseded",
            );
        }
        _ if attr(head, "superseded_by").is_some() => {
            builder.set_state(head, "stale", "superseded");
            builder.push_fact(
                head,
                &[],
                "superseded",
                "a supersedes edge names a successor",
            );
        }
        _ => {
            builder.set_state(
                head,
                "current",
                if attr(head, "superseded_by").is_some() {
                    "superseded"
                } else {
                    "current"
                },
            );
            let supports: Vec<&Observation> = Vec::new();
            builder.push_fact(head, &supports, "current", "an accepted Kindex node");
        }
    }
}

fn derive_answers(builder: &mut FactBuilder<'_>, _key: &str, rows: &[&Observation]) {
    let as_of = builder.as_of;
    let alive_rows = settle_history(builder, rows, |row| would_be_current(row, as_of));
    if alive_rows.is_empty() {
        return;
    }
    // Signature and scope: an answer whose signer is not the registered
    // authority of its scope is unverified.
    let mut verified: Vec<&Observation> = Vec::new();
    for row in &alive_rows {
        let signature_valid = attr(row, "signature_valid") == Some(&Value::Bool(true));
        let scope = row.scope.clone().unwrap_or_default();
        let owner_key = builder.trust.owner_of_scope(&scope).map(|(key, _)| key);
        let signer = row.signer.clone().unwrap_or_default();
        let registered = builder
            .trust
            .active_entries
            .iter()
            .any(|(s, key, _, _)| *s == scope && *key == signer);
        let _ = owner_key;
        if !signature_valid || !registered {
            if let Some(effective) = revocation_of(builder.trust, row) {
                builder.set_state(row, "quarantined", "revoked_observation");
                builder.push_fact(row, &[], "withdrawn", "the answering key is revoked");
                if admitted_before_revocation(builder.trust, row, row.signer.as_deref()) {
                    let _ = &effective;
                    let evidence = vec![row.observation_id.clone()];
                    builder.push_unknown(
                        row,
                        "revoked",
                        "reopened",
                        format!(
                            "The answer {} was warranted by a revoked key.",
                            row.native_id
                        ),
                        evidence,
                        None,
                    );
                }
                continue;
            }
            builder.set_state(row, "quarantined", "unverified_signature");
            builder.push_fact(
                row,
                &[],
                "unverified",
                "the signer is not the registered authority for the scope",
            );
            continue;
        }
        if let Some(effective) = revocation_of(builder.trust, row) {
            builder.set_state(row, "quarantined", "revoked_observation");
            builder.push_fact(
                row,
                &[],
                "withdrawn",
                "the answering key was revoked after this answer",
            );
            if admitted_before_revocation(builder.trust, row, row.signer.as_deref()) {
                let evidence = vec![row.observation_id.clone()];
                builder.push_unknown(row, "revoked", "reopened",
                    format!("The answer {} was warranted by a key revoked at {effective}; the question reopens.", row.native_id),
                    evidence, None);
            }
            continue;
        }
        verified.push(row);
    }
    // Explicit parent supersession by content digest.
    let named_parents: BTreeSet<String> = verified
        .iter()
        .flat_map(|row| row.parents.clone().unwrap_or_default())
        .collect();
    let mut heads: Vec<&Observation> = Vec::new();
    for row in &verified {
        let digest = attr_str(row, "content_digest").unwrap_or_default();
        if named_parents.contains(digest) {
            builder.set_state(row, "stale", "superseded");
            builder.push_history(
                row,
                "superseded",
                "an explicit parent supersession names this answer",
            );
        } else {
            heads.push(row);
        }
    }
    if heads.len() > 1 {
        let evidence: Vec<String> = heads.iter().map(|h| h.observation_id.clone()).collect();
        for head in &heads {
            builder.set_state(head, "current", "conflicting_observations");
            builder.push_fact(
                head,
                &[],
                "conflict",
                "two unparented answers to one question",
            );
        }
        if let Some(head) = heads.last() {
            builder.push_unknown(
                head,
                "conflict",
                "open",
                format!(
                    "Two answers to {} do not name each other as parents. Which is current?",
                    attr_str(head, "question_id").unwrap_or("the question")
                ),
                evidence,
                None,
            );
        }
        return;
    }
    if let Some(head) = heads.first() {
        let late = head
            .asserted_at
            .as_deref()
            .zip(Some(head.observed_at.as_str()))
            .and_then(|(asserted, observed)| crate::time::seconds_between(asserted, observed).ok())
            .is_some_and(|seconds| seconds > 7 * 24 * 3600);
        builder.set_state(
            head,
            "current",
            if late {
                "late_arrival_ordered"
            } else {
                "answered"
            },
        );
        builder.push_fact(head, &[], "current", "the registered authority answered");
        let evidence = vec![head.observation_id.clone()];
        builder.push_unknown(
            head,
            "question",
            "closed",
            format!(
                "Question {} is closed by the registered authority's answer.",
                attr_str(head, "question_id").unwrap_or("?")
            ),
            evidence,
            None,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_repo() -> (tempfile::TempDir, Repository) {
        let dir = tempfile::tempdir().expect("temp dir");
        let run = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(dir.path())
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
                .output()
                .expect("git");
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["init", "-q", "-b", "main"]);
        std::fs::create_dir_all(dir.path().join("sources/adr")).unwrap();
        std::fs::write(dir.path().join("README.md"), "seed\n").unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-q", "-m", "seed"]);
        let repo = Repository::discover(dir.path()).expect("repository");
        (dir, repo)
    }

    fn observation(
        kind: &str,
        native: &str,
        key: &str,
        statement: &str,
        disposition: &str,
    ) -> Observation {
        Observation {
            observation_id: format!("obs_{native}"),
            source_kind: kind.to_owned(),
            source_identity: "source:test".to_owned(),
            native_id: native.to_owned(),
            content_digest: sha256_bytes(statement.as_bytes()),
            disposition: disposition.to_owned(),
            observed_at: "2026-09-08T00:00:00.000Z".to_owned(),
            body_ref: String::new(),
            extraction_version: "kinbase-extract/1".to_owned(),
            origin_trust: Some("merged-default".to_owned()),
            lifecycle: "observed".to_owned(),
            statement: Some(statement.to_owned()),
            logical_key: Some(key.to_owned()),
            atom_kind: Some("claim".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn an_export_is_current_only_when_accepted() {
        let open_pr = observation(
            "pull_request",
            "pr-1",
            "pull_request:1",
            "1: add retries",
            "proposed",
        );
        let cancelled = observation(
            "issue_tracker",
            "ENG-2",
            "issue_tracker:ENG-2",
            "ENG-2: drop the cache",
            "rejected",
        );
        let thread = observation(
            "chat_thread",
            "t-1",
            "chat_thread:t-1",
            "we might cap retries",
            "proposed",
        );
        let accepted = observation(
            "issue_tracker",
            "ENG-3",
            "issue_tracker:ENG-3",
            "ENG-3: cap retries at three",
            "accepted",
        );
        let view = derive(
            &[open_pr, cancelled, thread, accepted.clone()],
            &TrustFacts::default(),
            "2026-09-08T00:00:03.000Z",
        );
        let current: Vec<&str> = view
            .facts
            .iter()
            .filter(|fact| fact.state == "current")
            .map(|fact| fact.logical_key.as_str())
            .collect();
        assert_eq!(current, ["issue_tracker:ENG-3"]);
        let states: BTreeMap<&str, &str> = view
            .facts
            .iter()
            .map(|fact| (fact.logical_key.as_str(), fact.state.as_str()))
            .collect();
        assert_eq!(states["pull_request:1"], "proposed");
        assert_eq!(states["issue_tracker:ENG-2"], "rejected");
        assert_eq!(states["chat_thread:t-1"], "proposed");
    }

    #[test]
    fn a_revoked_export_or_symbol_is_withdrawn_and_reopened() {
        let trust = TrustFacts {
            revocations: vec![(
                "key-a".to_owned(),
                "rev-1".to_owned(),
                "2026-09-05T00:00:00.000Z".to_owned(),
            )],
            ..TrustFacts::default()
        };
        let mut accepted = observation(
            "issue_tracker",
            "ENG-5",
            "issue_tracker:ENG-5",
            "ENG-5: cap retries at three",
            "accepted",
        );
        let mut declared = observation(
            "repo_symbols",
            "a.ts:1",
            "symbol:function:retry",
            "function retry has shape (n)",
            "current",
        );
        declared.attributes = Some(json!({"symbol": "retry", "shape": "(n)"}));
        for row in [&mut accepted, &mut declared] {
            row.signer = Some("key-a".to_owned());
            row.asserted_at = Some("2026-09-01T00:00:00.000Z".to_owned());
        }
        let view = derive(&[accepted, declared], &trust, "2026-09-08T00:00:03.000Z");
        assert!(
            view.facts.iter().all(|fact| fact.state == "withdrawn"),
            "{:?}",
            view.facts
        );
        assert_eq!(view.facts.len(), 2);
        let reopened = view
            .unknowns
            .iter()
            .filter(|u| u.kind == "revoked" && u.status == "reopened")
            .count();
        assert_eq!(reopened, 2);
    }

    #[test]
    fn an_export_snapshot_is_ordered_by_its_update_time() {
        let mut newer = observation(
            "issue_tracker",
            "ENG-4",
            "issue_tracker:ENG-4",
            "ENG-4: retries capped at five",
            "accepted",
        );
        newer.observation_id = "obs_new".to_owned();
        newer.attributes = Some(json!({"updated_at": "2026-09-07T00:00:00.000Z"}));
        newer.observed_at = "2026-09-08T00:00:00.000Z".to_owned();
        // An older export ingested later.
        let mut older = observation(
            "issue_tracker",
            "ENG-4",
            "issue_tracker:ENG-4",
            "ENG-4: retries capped at three",
            "accepted",
        );
        older.observation_id = "obs_old".to_owned();
        older.attributes = Some(json!({"updated_at": "2026-09-01T00:00:00.000Z"}));
        older.observed_at = "2026-09-08T00:00:01.000Z".to_owned();
        let view = derive(
            &[newer, older],
            &TrustFacts::default(),
            "2026-09-08T00:00:03.000Z",
        );
        let current: Vec<&DerivedFact> =
            view.facts.iter().filter(|f| f.state == "current").collect();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].evidence_refs, ["obs_new"]);
        assert_eq!(view.observation_states["obs_old"].0, "stale");
    }

    #[test]
    fn differing_declarations_on_one_symbol_key_are_a_conflict() {
        let symbol = |native: &str, shape: &str| {
            let mut row = observation(
                "repo_symbols",
                native,
                "symbol:function:retry",
                &format!("function retry has shape {shape}"),
                "current",
            );
            row.attributes = Some(json!({"symbol": "retry", "shape": shape}));
            row
        };
        let agreeing = derive(
            &[symbol("a.ts:1", "(n)"), symbol("b.ts:4", "(n)")],
            &TrustFacts::default(),
            "2026-09-08T00:00:03.000Z",
        );
        assert_eq!(agreeing.facts.len(), 1);
        assert_eq!(agreeing.facts[0].state, "current");
        assert_eq!(agreeing.facts[0].evidence_refs.len(), 2);

        let disagreeing = derive(
            &[symbol("a.ts:1", "(n)"), symbol("b.ts:4", "(n, delay)")],
            &TrustFacts::default(),
            "2026-09-08T00:00:03.000Z",
        );
        assert_eq!(disagreeing.facts.len(), 1);
        assert_eq!(disagreeing.facts[0].state, "conflict");
        assert!(
            disagreeing
                .observation_states
                .values()
                .all(|(state, _)| state == "current"),
            "neither site is superseded by the other"
        );
        assert!(
            disagreeing
                .unknowns
                .iter()
                .any(|u| u.kind == "conflict" && u.status == "open")
        );
    }

    #[test]
    fn transcripts_keep_stable_record_ids_and_detect_edits() {
        let (dir, repo) = git_repo();
        let root = dir.path().join("sources/codex");
        std::fs::create_dir_all(&root).unwrap();
        let line1 = r#"{"type":"response_item","id":"s1-0000","timestamp":"2026-03-01T00:00:00.000Z","payload":{"content":[{"type":"input_text","text":"the ceiling is four"}]}}"#;
        let edited = r#"{"type":"response_item","id":"s1-0000","timestamp":"2026-03-01T03:00:00.000Z","edited":true,"payload":{"content":[{"type":"input_text","text":"the ceiling is four"}]}}"#;
        std::fs::write(
            root.join("s1.jsonl"),
            format!("{line1}\n{edited}\n{line1}\n"),
        )
        .unwrap();
        let scan = scan(
            "codex_jsonl",
            &root,
            &repo,
            "2026-09-08T00:00:00.000Z",
            None,
        )
        .expect("scan");
        let ids: Vec<&str> = scan.records.iter().map(|r| r.native_id.as_str()).collect();
        assert_eq!(ids, ["s1/s1-0000", "s1/s1-0000", "s1/s1-0000"]);
        let digests: BTreeSet<String> = scan.records.iter().map(|r| r.content_digest()).collect();
        assert_eq!(
            digests.len(),
            2,
            "an edited line is a new content identity; a duplicate is not"
        );
        assert!(
            scan.records
                .iter()
                .all(|r| r.logical_key == "codex_jsonl:s1/s1-0000")
        );
    }

    #[test]
    fn adr_scan_reads_front_matter_and_folds_statements() {
        let (dir, repo) = git_repo();
        let path = dir.path().join("sources/adr/0011-lookahead.md");
        std::fs::write(&path, "---\nadr: 0011\ntitle: scheduler lookahead\nstatus: Accepted\n---\n\n# scheduler lookahead\n\nwiden the window\n").unwrap();
        let scan = scan(
            "docs_adr",
            &dir.path().join("sources/adr"),
            &repo,
            "2026-09-08T00:00:00.000Z",
            None,
        )
        .expect("scan");
        assert_eq!(scan.records.len(), 1);
        let record = &scan.records[0];
        assert_eq!(record.logical_key, "docs_adr:0011-lookahead");
        assert_eq!(record.disposition, "accepted");
        assert!(
            !record.statement.contains('\n'),
            "statements fold onto one line: {}",
            record.statement
        );
        assert_eq!(record.origin, "uncommitted-worktree");
    }

    #[test]
    fn github_snapshots_newest_export_defines_presence() {
        let (dir, repo) = git_repo();
        let root = dir.path().join("sources/github");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("export-1.json"), r#"{"schema":"gh-export/1","issues":[{"number":7,"title":"narrow","state":"open","body":"x"}],"pullRequests":[]}"#).unwrap();
        let later = root.join("export-2.json");
        std::fs::write(&later, r#"{"schema":"gh-export/1","issues":[{"number":8,"title":"other","state":"open","body":"y"}],"pullRequests":[]}"#).unwrap();
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::open(&later)
            .unwrap()
            .set_modified(future)
            .unwrap();
        let scan = scan(
            "github_export",
            &root,
            &repo,
            "2026-09-08T00:00:00.000Z",
            None,
        )
        .expect("scan");
        let present: BTreeMap<&str, bool> = scan
            .records
            .iter()
            .map(|r| (r.native_id.as_str(), r.present))
            .collect();
        assert_eq!(present.get("issue:7"), Some(&false));
        assert_eq!(present.get("issue:8"), Some(&true));
    }

    #[test]
    fn ordered_evidence_keeps_the_newest_receipt_as_head() {
        let mut older = observation(
            "repo_tests",
            "run-1",
            "repo_tests:pytest",
            "pytest -> exit 0: passed",
            "passed",
        );
        older.asserted_at = Some("2026-09-08T00:00:01.000Z".to_owned());
        older.attributes = Some(json!({"exit_code": 0, "command": "pytest"}));
        let mut newer = observation(
            "repo_tests",
            "run-2",
            "repo_tests:pytest",
            "pytest -> exit 1: failed",
            "failed",
        );
        newer.asserted_at = Some("2026-09-08T00:00:02.000Z".to_owned());
        newer.attributes = Some(json!({"exit_code": 1, "command": "pytest"}));
        let view = derive(
            &[older.clone(), newer.clone()],
            &TrustFacts::default(),
            "2026-09-08T00:00:03.000Z",
        );
        let current: Vec<&DerivedFact> =
            view.facts.iter().filter(|f| f.state == "current").collect();
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].evidence_refs, vec![newer.observation_id.clone()]);
        assert_eq!(view.observation_states[&older.observation_id].0, "stale");
        assert!(
            view.unknowns
                .iter()
                .any(|u| u.kind == "test-failure" && u.status == "open")
        );
    }

    #[test]
    fn a_withdrawn_current_fact_opens_an_unknown_and_history_stays_addressable() {
        let mut removed = observation(
            "repo_code",
            "src/a.py",
            "repo_code:src/a.py",
            "src/a.py declares: def a",
            "current",
        );
        removed.lifecycle = "absent".to_owned();
        let view = derive(
            &[removed.clone()],
            &TrustFacts::default(),
            "2026-09-08T00:00:00.000Z",
        );
        assert_eq!(view.facts.len(), 1);
        assert_eq!(view.facts[0].state, "withdrawn");
        assert_eq!(
            view.facts[0].evidence_refs,
            vec![removed.observation_id.clone()]
        );
        assert_eq!(
            view.observation_states[&removed.observation_id].0,
            "retracted"
        );
        assert!(
            view.unknowns
                .iter()
                .any(|u| u.kind == "withdrawn" && u.status == "open")
        );
    }

    #[test]
    fn a_divergent_branch_head_conflicts_without_promotion() {
        let head = observation(
            "docs_adr",
            "sources/adr/0013.md",
            "docs_adr:0013",
            "adaptive",
            "accepted",
        );
        let mut branch = observation(
            "docs_adr",
            "sources/adr/0013.md@adr/alternate",
            "docs_adr:0013",
            "fixed at 90",
            "accepted",
        );
        branch.origin_trust = Some("unreviewed-branch".to_owned());
        let view = derive(
            &[head.clone(), branch.clone()],
            &TrustFacts::default(),
            "2026-09-08T00:00:00.000Z",
        );
        let states: BTreeMap<String, String> = view
            .facts
            .iter()
            .map(|f| (f.evidence_refs[0].clone(), f.state.clone()))
            .collect();
        assert_eq!(states[&head.observation_id], "current");
        assert_eq!(states[&branch.observation_id], "conflict");
        assert!(view.unknowns.iter().any(|u| u.kind == "conflict"));
    }

    #[test]
    fn clean_text_folds_controls_and_whitespace() {
        assert_eq!(
            clean_text("# title\n\nbody\tline\u{202e}x"),
            "# title body line x"
        );
    }
}

#[cfg(test)]
mod revocation_warrant_tests {
    use super::*;

    const UUID: &str = "00000000-0000-4000-8000-000000000001";

    fn derived() -> Observation {
        Observation {
            observation_id: "obs_adr".to_owned(),
            source_kind: "adr".to_owned(),
            native_id: "adr-1".to_owned(),
            ..Default::default()
        }
    }

    fn certified() -> TrustFacts {
        TrustFacts {
            repository_uuid: Some(UUID.to_owned()),
            certificate_valid: true,
            ..Default::default()
        }
    }

    fn revoke(trust: &mut TrustFacts, key: &str, effective_at: &str) {
        trust
            .revocations
            .push((key.to_owned(), "7".to_owned(), effective_at.to_owned()));
        trust
            .governing_revoked_keys
            .get_or_insert_with(BTreeSet::new)
            .insert(key.to_owned());
    }

    #[test]
    fn another_repositorys_revocation_withdraws_nothing() {
        let mut trust = certified();
        revoke(&mut trust, "other-key", "2026-09-01T00:00:00.000Z");
        assert_eq!(revocation_of(&trust, &derived()), None);
    }

    #[test]
    fn revoking_the_repository_key_withdraws_its_derived_facts() {
        let mut trust = certified();
        trust.repository_keys.insert("repo-key".to_owned());
        revoke(&mut trust, "other-key", "2026-09-03T00:00:00.000Z");
        revoke(&mut trust, "repo-key", "2026-09-02T00:00:00.000Z");
        assert_eq!(
            revocation_of(&trust, &derived()).as_deref(),
            Some("2026-09-02T00:00:00.000Z")
        );
    }

    #[test]
    fn a_live_warrant_keeps_derived_facts() {
        let mut trust = certified();
        trust
            .repository_keys
            .extend(["old-key".to_owned(), "new-key".to_owned()]);
        trust.active_entries.push((
            format!("codebase:{UUID}"),
            "new-key".to_owned(),
            "owner".to_owned(),
            "9".to_owned(),
        ));
        revoke(&mut trust, "old-key", "2026-09-02T00:00:00.000Z");
        assert_eq!(revocation_of(&trust, &derived()), None);

        let mut trust = certified();
        trust.repository_keys.insert("repo-key".to_owned());
        trust.maintainer_keys.insert("maintainer-key".to_owned());
        revoke(&mut trust, "repo-key", "2026-09-02T00:00:00.000Z");
        assert_eq!(revocation_of(&trust, &derived()), None);
        revoke(&mut trust, "maintainer-key", "2026-09-04T00:00:00.000Z");
        assert_eq!(
            revocation_of(&trust, &derived()).as_deref(),
            Some("2026-09-04T00:00:00.000Z")
        );
    }
}
