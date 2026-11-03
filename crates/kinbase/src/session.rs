use crate::error::{ContractError, ExitCode};
use crate::hash::{sha256_bytes, sha256_text};
use crate::json::parse_strict_object;
use crate::model::{CompanyReference, Distortion, FactEvent, Observation, UnknownEvent};
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, parse_rfc3339_millis};
use chrono::Duration;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use uuid::Uuid;

const SESSION_OBSERVATION_LIMIT: usize = 10_000;
const SESSION_OBSERVATION_KEYS: [&str; 5] = ["id", "role", "text", "observed_at", "source_kind"];

pub fn start(repo: &Path, host: crate::HostKind, json: bool) -> Result<(), ContractError> {
    let session_id = format!("session_{}", Uuid::new_v4());
    let host_name = host_name(host);
    let repository_id = crate::repository::repository_id(repo).ok();
    let record = json!({
        "session_id": session_id,
        "host": host_name,
        "repository_id": repository_id,
        "started_at": now_rfc3339_millis(),
        "status": "started"
    });
    append_personal("sessions.jsonl", &record)?;
    let result = json!({
        "session_id": session_id,
        "host": host_name,
        "repository_id": repository_id,
        "status": "started"
    });
    print_value(&result, json);
    Ok(())
}

/// Directory under the Personal root where a host prompt waits for its
/// detached `session observe` worker.
pub const PENDING_OBSERVATIONS: &str = "pending-observations";
/// A worker gets this many attempts at a prompt before it is dropped (and
/// the drop audited).
const PENDING_MAX_ATTEMPTS: u32 = 3;
/// A raw prompt is kept no longer than the private raw-session default
/// retention (verification.md, operational limits).
const PENDING_RETENTION_SECONDS: i64 = 24 * 3600;
/// A queued prompt whose worker has not held its lock for this long is
/// presumed stranded (the worker crashed or was never scheduled) and is
/// started again.
const PENDING_STALE_SECONDS: i64 = 120;
/// How long a Stop waits for its session's queued prompts: a rule-based
/// classification finishes well inside it; a slower one is reported as
/// pending and counted by the next Stop instead of holding the host.
const STOP_PENDING_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// What a queued prompt needs to be classified again: the session, the
/// repository the host named, how often a worker has tried, and which
/// worker holds it now.
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingMeta {
    session: String,
    repo: String,
    queued_at: String,
    spawned_at: String,
    attempts: u32,
    #[serde(default)]
    worker_pid: Option<u32>,
}

pub fn pending_observations_dir() -> std::path::PathBuf {
    let repo = std::env::current_dir().unwrap_or_default();
    crate::store::store_root(crate::StoreKind::Personal, &repo).join(PENDING_OBSERVATIONS)
}

// A queued prompt is `<token>.jsonl`; a worker claims it by renaming it to
// `<token>.working.jsonl` (atomic, and no descriptor stays open under the
// Personal root while it classifies); `<token>.meta.json` describes it.
fn queued_path(directory: &Path, token: &str) -> std::path::PathBuf {
    directory.join(format!("{token}.jsonl"))
}

fn working_path(directory: &Path, token: &str) -> std::path::PathBuf {
    directory.join(format!("{token}.working.jsonl"))
}

fn meta_path(directory: &Path, token: &str) -> std::path::PathBuf {
    directory.join(format!("{token}.meta.json"))
}

fn token_of(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let token = name.split('.').next()?;
    (!token.is_empty() && token.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| token.to_owned())
}

fn read_meta(directory: &Path, token: &str) -> Option<PendingMeta> {
    serde_json::from_slice(&std::fs::read(meta_path(directory, token)).ok()?).ok()
}

fn write_meta(directory: &Path, token: &str, meta: &PendingMeta) -> Result<(), ContractError> {
    let bytes =
        serde_json::to_vec(meta).map_err(|error| ContractError::internal(error.to_string()))?;
    let path = meta_path(directory, token);
    let staged = directory.join(format!("{token}.meta.tmp"));
    let _ = std::fs::remove_file(&staged);
    write_new_private_file(&staged, &bytes)?;
    std::fs::rename(&staged, &path).map_err(io_error)
}

fn remove_pending(directory: &Path, token: &str) {
    let _ = std::fs::remove_file(queued_path(directory, token));
    let _ = std::fs::remove_file(working_path(directory, token));
    let _ = std::fs::remove_file(meta_path(directory, token));
}

fn process_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Hand a host prompt to the session it belongs to, classified off the host's
/// response path (architecture §9). The prompt goes to a private file that a
/// detached `session observe` worker reads and classifies, so the
/// observation and its atoms carry `session:<id>` and the session's Stop
/// finds them; a prompt recorded only as `hook:UserPromptSubmit` was never
/// counted or classified. The worker runs in `repo`, the repository the host
/// named. Without a session id, or if no worker can be started, the prompt's
/// minimized observation is recorded here instead.
pub fn queue_hook_observation(
    host: &str,
    map: &Map<String, Value>,
    repo: &Path,
) -> Result<Option<String>, ContractError> {
    let session = map
        .get("session_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty());
    let prompt = map
        .get("prompt")
        .or_else(|| map.get("text"))
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty());
    let (Some(session), Some(prompt)) = (session, prompt) else {
        return record_hook_observation_as(host, map, None, repo);
    };
    // The host sends no event id with a prompt; one is derived from the
    // session and the text, so a repeated delivery names the same event.
    let event_id = map
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "prompt_{}",
                &sha256_text(&format!("{session}\0{prompt}"))[..24]
            )
        });
    let observed_at = map
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| parse_rfc3339_millis(value).ok())
        .map(format_rfc3339_millis)
        .unwrap_or_else(now_rfc3339_millis);
    let record = json!({
        "id": event_id,
        "role": "user",
        "text": prompt,
        "observed_at": observed_at,
        "source_kind": if host == "claude" { "claude_jsonl" } else { "codex_jsonl" }
    });
    let directory = pending_observations_dir();
    crate::paths::ensure_private_dir(&directory, "pending observations")?;
    sweep_pending(&directory);
    let token: String = crate::crypto::random_token()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(24)
        .collect();
    let event = queued_path(&directory, &token);
    let mut line = crate::json::jcs_text(&record);
    line.push('\n');
    let now = now_rfc3339_millis();
    // Metadata first: a queued prompt is never without it.
    write_meta(
        &directory,
        &token,
        &PendingMeta {
            session: session.to_owned(),
            repo: repo.to_string_lossy().into_owned(),
            queued_at: now.clone(),
            spawned_at: now,
            attempts: 0,
            worker_pid: None,
        },
    )?;
    write_new_private_file(&event, line.as_bytes())?;
    if spawn_observe_worker(session, &event, repo) {
        return Ok(Some(event_id));
    }
    remove_pending(&directory, &token);
    let mut fallback = map.clone();
    fallback.insert("id".to_owned(), Value::String(event_id));
    record_hook_observation_as(host, &fallback, Some(session), repo)
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), ContractError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io_error)
}

fn spawn_observe_worker(session: &str, event: &Path, repo: &Path) -> bool {
    use std::os::unix::process::CommandExt;
    let Ok(program) = std::env::current_exe() else {
        return false;
    };
    std::process::Command::new(program)
        .args([
            "session",
            "observe",
            session,
            "--consume",
            "--json",
            "--event",
        ])
        .arg(event)
        .current_dir(repo)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .is_ok()
}

/// A worker's hold on one queued prompt, which it has renamed to its
/// working name.
pub struct PendingClaim {
    directory: std::path::PathBuf,
    token: String,
}

impl PendingClaim {
    /// The claimed prompt, for the worker to read.
    pub fn path(&self) -> std::path::PathBuf {
        working_path(&self.directory, &self.token)
    }
}

/// Claim a queued prompt for this worker; None when it is not a queued
/// prompt, is gone, or another worker took it first.
pub fn claim_pending(event: &Path) -> Option<PendingClaim> {
    let directory = pending_observations_dir();
    let inside = match (
        event.parent().map(std::fs::canonicalize),
        std::fs::canonicalize(&directory),
    ) {
        (Some(Ok(parent)), Ok(expected)) => parent == expected,
        _ => false,
    };
    let token = token_of(event)?;
    if !inside || event != queued_path(event.parent()?, &token) {
        return None;
    }
    let directory = event.parent()?.to_path_buf();
    std::fs::rename(event, working_path(&directory, &token)).ok()?;
    if let Some(mut meta) = read_meta(&directory, &token) {
        meta.worker_pid = Some(std::process::id());
        let _ = write_meta(&directory, &token, &meta);
    }
    Some(PendingClaim { directory, token })
}

/// Settle a claimed prompt: removed once its observation is recorded; after
/// a failure it is queued again for a later attempt, up to the bound, then
/// dropped with an audit record (which never carries the prompt).
pub fn finish_pending(claim: PendingClaim, failure: Option<&ContractError>) {
    let PendingClaim { directory, token } = claim;
    match failure {
        None => remove_pending(&directory, &token),
        Some(error) => record_failed_attempt(&directory, &token, &error.code),
    }
}

fn record_failed_attempt(directory: &Path, token: &str, code: &str) {
    let Some(mut meta) = read_meta(directory, token) else {
        remove_pending(directory, token);
        return;
    };
    meta.attempts += 1;
    meta.worker_pid = None;
    if meta.attempts >= PENDING_MAX_ATTEMPTS {
        remove_pending(directory, token);
        if let Ok(private) = crate::private::PrivateStore::open_core() {
            let _ = private.audit(
                "pending-observation-dropped",
                &json!({
                    "session_id": meta.session,
                    "attempts": meta.attempts,
                    "code": code,
                    "observed_at": now_rfc3339_millis()
                }),
            );
        }
        return;
    }
    // Retried by a later sweep, not at once.
    meta.spawned_at = now_rfc3339_millis();
    if write_meta(directory, token, &meta).is_ok() {
        let _ = std::fs::rename(
            working_path(directory, token),
            queued_path(directory, token),
        );
    }
}

fn seconds_since(stamp: &str) -> i64 {
    parse_rfc3339_millis(stamp)
        .map(|then| (chrono::Utc::now() - then).num_seconds())
        .unwrap_or(i64::MAX)
}

/// Every prompt still queued or being worked, by token.
fn pending_entries(directory: &Path) -> Vec<(String, PendingMeta)> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let tokens: BTreeSet<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".jsonl"))
        })
        .filter_map(|path| token_of(&path))
        .collect();
    tokens
        .into_iter()
        .filter_map(|token| read_meta(directory, &token).map(|meta| (token, meta)))
        .collect()
}

/// Drop prompts past retention, requeue ones whose worker died, and restart
/// ones no worker has taken.
fn sweep_pending(directory: &Path) {
    for (token, mut meta) in pending_entries(directory) {
        let working = working_path(directory, &token).exists();
        if working && meta.worker_pid.is_some_and(process_alive) {
            continue;
        }
        if seconds_since(&meta.queued_at) > PENDING_RETENTION_SECONDS {
            remove_pending(directory, &token);
            continue;
        }
        if working {
            // Its worker died mid-classification: that was an attempt.
            record_failed_attempt(directory, &token, "WORKER_LOST");
            continue;
        }
        if seconds_since(&meta.spawned_at) > PENDING_STALE_SECONDS {
            meta.spawned_at = now_rfc3339_millis();
            if write_meta(directory, &token, &meta).is_ok() {
                spawn_observe_worker(
                    &meta.session,
                    &queued_path(directory, &token),
                    Path::new(&meta.repo),
                );
            }
        }
    }
}

/// Before a Stop reads its session: sweep, then wait briefly for this
/// session's queued prompts. Returns how many are still queued or being
/// classified; the receipt reports them, and a later Stop or SessionEnd
/// counts them.
fn settle_pending(session: &str) -> usize {
    let directory = pending_observations_dir();
    sweep_pending(&directory);
    let deadline = std::time::Instant::now() + STOP_PENDING_WAIT;
    loop {
        let waiting = pending_entries(&directory)
            .into_iter()
            .filter(|(_, meta)| meta.session == session)
            .count();
        if waiting == 0 || std::time::Instant::now() >= deadline {
            return waiting;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Record the privacy-minimized observation identity of a host prompt. The
/// body itself is not copied into the observation record; only its digest is
/// retained for reset authorization.
fn record_hook_observation_as(
    host: &str,
    map: &Map<String, Value>,
    session: Option<&str>,
    repo: &Path,
) -> Result<Option<String>, ContractError> {
    let Some(event_id) = map
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return Ok(None);
    };
    let Some(prompt) = map
        .get("prompt")
        .or_else(|| map.get("text"))
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
    else {
        return Ok(None);
    };
    // The prompt arrived through the host envelope, so it is already folded
    // to canonical text: this digest names the stored text, not the host's
    // raw bytes, and a transcript that kept those bytes will not reproduce it.
    let digest = sha256_bytes(prompt.as_bytes());
    let observed_at = map
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(|value| crate::time::parse_rfc3339_millis(value).ok())
        .map(crate::time::format_rfc3339_millis)
        .unwrap_or_else(now_rfc3339_millis);
    let observation = Observation {
        observation_id: format!(
            "obs_{:x}",
            Sha256::digest(
                format!("{}\0{event_id}\0{digest}", session.unwrap_or("hook")).as_bytes()
            )
        ),
        source_kind: if host == "claude" {
            "claude_jsonl"
        } else {
            "codex_jsonl"
        }
        .to_owned(),
        source_identity: session
            .map(|session| format!("session:{session}"))
            .unwrap_or_else(|| "hook:UserPromptSubmit".to_owned()),
        native_id: event_id.to_owned(),
        content_digest: digest.clone(),
        repository_id: crate::repository::repository_id(repo).ok(),
        revision: None,
        branch: None,
        disposition: "current".to_owned(),
        observed_at,
        asserted_at: None,
        effective_from: None,
        effective_until: None,
        body_ref: format!("sha256:{digest}"),
        extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
        origin_trust: Some("uncommitted-worktree".to_owned()),
        environment_id: None,
        owner_id: None,
        lifecycle: "observed".to_owned(),
        ..Default::default()
    };
    let value = serde_json::to_value(&observation)
        .map_err(|error| ContractError::internal(error.to_string()))?;
    crate::store::append_record(
        crate::StoreKind::Personal,
        repo,
        "observations.jsonl",
        &value,
    )?;
    Ok(Some(event_id.to_owned()))
}

pub fn observe(
    classifier: Option<&crate::config::SharedClassifier>,
    principal_id: &str,
    host_instance_id: &str,
    session: &str,
    event: &Path,
    json: bool,
) -> Result<(), ContractError> {
    // Loaded before anything is scanned or written: the scan needs the
    // user's registered canaries and identifiers, and a registry that cannot
    // be read stops the observation before any record is written.
    let launcher = crate::launcher::Launcher::load()?;
    let registry = launcher.scanner_registry()?;
    let bytes = std::fs::read(event).map_err(io_error)?;
    let mut parsed_records = parse_session_corpus(&bytes)?;
    // Known secrets become `$NAME` before the text is digested, classified,
    // stored or minted into a candidate (`crate::secret_mask`).
    if let Some(table) = crate::secret_mask::active_table() {
        for record in parsed_records.iter_mut() {
            let mut value = Value::Object(std::mem::take(record));
            crate::secret_mask::mask_value_with(&mut value, &table);
            if let Value::Object(map) = value {
                *record = map;
            }
        }
    }
    // The session belongs to the host the batch names, not always Codex.
    let host = parsed_records
        .first()
        .and_then(|record| record.get("source_kind"))
        .and_then(Value::as_str)
        .map(host_of_source_kind)
        .unwrap_or("unknown");
    ensure_session_record(session, host)?;
    if parsed_records.len() > SESSION_OBSERVATION_LIMIT {
        return Err(ContractError::limit(
            format!(
                "session observation batch exceeds the {}-line bound",
                SESSION_OBSERVATION_LIMIT
            ),
            json!({
                "omitted_count": parsed_records.len(),
                "line_limit": SESSION_OBSERVATION_LIMIT
            }),
        ));
    }

    let repo = std::env::current_dir().map_err(io_error)?;
    let repository_id = crate::repository::repository_id(&repo).ok();
    let company_destination = company_destination(&launcher, repository_id.as_deref());
    let proof_clock = now_rfc3339_millis();
    let mut records = Vec::new();
    let mut quarantined_observations = Vec::new();
    for record in records_into_quarantine_or_admitted(parsed_records, &proof_clock)? {
        match record {
            QuarantineDecision::Admitted(record) => records.push(record),
            QuarantineDecision::ClockSkew(record) => {
                let private = crate::private::PrivateStore::open_core()?;
                private.quarantine("CLOCK_SKEW", &record)?;
                quarantined_observations.push(record);
            }
        }
    }
    let mut observations = Vec::new();
    for record in &records {
        let event_id = record["id"].as_str().unwrap_or_default().to_owned();
        let text = record["text"].as_str().unwrap_or_default().to_owned();
        let observed_at = record["observed_at"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let digest = sha256_bytes(text.as_bytes());
        let observation_id = format!(
            "obs_{:x}",
            Sha256::digest(format!("{session}\0{event_id}\0{digest}").as_bytes())
        );
        let observation = Observation {
            observation_id: observation_id.clone(),
            source_kind: record["source_kind"]
                .as_str()
                .unwrap_or("codex_jsonl")
                .to_owned(),
            source_identity: format!("session:{session}"),
            native_id: event_id.clone(),
            content_digest: digest.clone(),
            repository_id: repository_id.clone(),
            revision: None,
            branch: None,
            disposition: "current".to_owned(),
            observed_at: observed_at.clone(),
            asserted_at: None,
            effective_from: None,
            effective_until: None,
            body_ref: format!("sha256:{digest}"),
            extraction_version: crate::classify::EXTRACTION_VERSION.to_owned(),
            origin_trust: Some("uncommitted-worktree".to_owned()),
            environment_id: None,
            owner_id: None,
            lifecycle: "observed".to_owned(),
            ..Default::default()
        };
        observations.push((
            observation,
            json!({
                "session_id": session,
                "event_id": event_id,
                "event_type": "observation",
                "observed_at": observed_at,
                "text_digest": digest
            }),
        ));
    }

    // An observation holding hard-blocking material yields no shared
    // candidate at all, and its text reaches no classifier: blocking each
    // atom on its own let the rest of the message (or a paraphrase of the
    // secret) through.
    // The configured canary and forbidden-identifier registries apply here
    // too, and a scan that cannot complete blocks.
    let blocked_observations: BTreeSet<String> = observations
        .iter()
        .filter(|(_, event)| {
            let native_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            crate::scanner::scan(&session_corpus_text(&records, native_id), &registry)
                .map(|result| result.hard_block)
                .unwrap_or(true)
        })
        .map(|(observation, _)| observation.observation_id.clone())
        .collect();
    let classifier_observations = observations
        .iter()
        .filter(|(observation, _)| !blocked_observations.contains(&observation.observation_id))
        .map(|(observation, event)| {
            let native_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            json!({
                "observation_id": observation.observation_id,
                "source_kind": observation.source_kind,
                "source_identity": observation.source_identity,
                "content_digest": observation.content_digest,
                "observed_at": observation.observed_at,
                "disposition": observation.disposition,
                "extraction_version": observation.extraction_version,
                "body": crate::classifier::request_body(&session_corpus_text(&records, native_id)),
                "scope": "host-session",
                "confidence": 8_000
            })
        })
        .collect::<Vec<_>>();
    let provider = select_provider(classifier);
    let extraction = extract_atoms(classifier, &provider, classifier_observations)?;
    let external_atoms = extraction.atoms;

    let mut atom_records = Vec::new();
    let mut candidate_records = Vec::new();
    // Each atom carries its observation's own source kind; every one was
    // labelled codex_jsonl, whichever host the batch came from.
    for (observation, event) in &observations {
        let native_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let text = session_corpus_text(&records, native_id);
        let mut atoms = Vec::new();
        if blocked_observations.contains(&observation.observation_id) {
            let mut atom = crate::classify::atomize(
                &observation.source_kind,
                native_id,
                &text,
                "host-session",
                8_000,
                &observation.observation_id,
                &observation.content_digest,
                repository_id.as_deref(),
                &registry,
            );
            atom.hard_blocked = true;
            atom.proposed_destinations = vec!["none".to_owned()];
            atom.eligible_destinations = Vec::new();
            atoms.push(atom);
        } else if let Some(external) = external_atoms.get(&observation.observation_id) {
            for item in external {
                atoms.push(atom_from_classifier(
                    item,
                    &observation.source_kind,
                    native_id,
                    &observation.observation_id,
                    &observation.content_digest,
                    repository_id.as_deref(),
                    &registry,
                )?);
            }
        }
        if atoms.is_empty() {
            if extraction.abstained.contains(&observation.observation_id)
                || provider.live_model.is_some()
            {
                // The live classifier abstained (timeout, transport failure,
                // or no atoms): the observation stays private at low
                // confidence with destination none. No rule provider guesses
                // in its place inside a pinned live run.
                let mut atom = crate::classify::atomize(
                    &observation.source_kind,
                    native_id,
                    &text,
                    "host-session",
                    3_000,
                    &observation.observation_id,
                    &observation.content_digest,
                    repository_id.as_deref(),
                    &registry,
                );
                atom.proposed_destinations = vec!["none".to_owned()];
                atom.eligible_destinations = Vec::new();
                atom.unresolved_uncertainty = Some(
                    "classifier abstained for this observation; no destination was guessed"
                        .to_owned(),
                );
                atoms.push(atom);
            } else {
                atoms.push(crate::classify::atomize(
                    &observation.source_kind,
                    native_id,
                    &text,
                    "host-session",
                    8_000,
                    &observation.observation_id,
                    &observation.content_digest,
                    repository_id.as_deref(),
                    &registry,
                ));
            }
        }
        for atom in atoms {
            // Hard-blocked material never has a shared candidate, including
            // a Personal candidate: the only reported destination is `none`.
            if atom.hard_blocked {
                atom_records.push(
                    serde_json::to_value(&atom)
                        .map_err(|error| ContractError::internal(error.to_string()))?,
                );
                continue;
            }
            let destinations = atom
                .eligible_destinations
                .iter()
                .filter(|destination| destination.as_str() != "none")
                .cloned()
                .collect::<Vec<_>>();
            for destination in destinations {
                let destination = match resolved_destination(
                    destination.as_str(),
                    repository_id.as_deref(),
                    company_destination.as_deref(),
                ) {
                    Some(destination) => destination,
                    None => continue,
                };
                // Nothing is left to share once de-identification removed
                // every word.
                if let Some(candidate) = build_candidate(
                    session,
                    &destination,
                    &atom,
                    native_id,
                    principal_id,
                    host_instance_id,
                    repository_id.as_deref(),
                )? {
                    candidate_records.push(candidate);
                }
            }
            atom_records.push(
                serde_json::to_value(&atom)
                    .map_err(|error| ContractError::internal(error.to_string()))?,
            );
        }
    }

    for (_, event) in &observations {
        append_personal("session-events.jsonl", event)?;
    }
    for (observation, _) in &observations {
        let value = serde_json::to_value(observation)
            .map_err(|error| ContractError::internal(error.to_string()))?;
        append_personal("observations.jsonl", &value)?;
    }
    for atom in &atom_records {
        append_personal("atoms.jsonl", atom)?;
    }
    for candidate in &candidate_records {
        append_personal("candidates.jsonl", candidate)?;
    }

    let mut admissions = Vec::new();
    let mut questions = BTreeSet::new();
    for atom in &atom_records {
        if let Some(question) = question_for_unresolved_atom(&repo, atom)? {
            questions.insert(question);
        }
    }
    for candidate in &candidate_records {
        admissions.push(admit_candidate(&launcher, &repo, candidate)?);
    }

    let quarantine_count = quarantined_observations.len();
    let result = json!({
        "session_id": session,
        "status": if quarantine_count == 0 { "observed" } else { "quarantined" },
        "code": if quarantine_count == 0 { Value::Null } else { Value::String("CLOCK_SKEW".to_owned()) },
        "disposition": if quarantine_count == 0 { "current" } else { "CLOCK_SKEW" },
        "state": if quarantine_count == 0 { "observed" } else { "CLOCK_SKEW" },
        "observation_count": observations.len(),
        "atom_count": atom_records.len(),
        "candidate_count": candidate_records.len(),
        "admissions": admissions,
        "questions": questions,
        "quarantine_count": quarantine_count,
        "quarantined_observations": quarantined_observations,
        "classifier": {
            "fingerprint": classifier_fingerprint(classifier, &provider),
            "provider": provider.name(),
            "model": provider.live_model.clone(),
            "configured_model": provider.configured_model.clone(),
            "fallback_from": provider.fallback_from.clone(),
            "fallback_reason": provider.fallback_reason.clone(),
            "processor": provider.processor,
            "processor_scope": provider.processor_scope.clone(),
            "abstained_observations": extraction.abstained.len(),
            "requests": extraction.requests,
            "retries": extraction.retries
        }
    });
    print_value(&result, json);
    Ok(())
}

/// A host session token is caller-supplied and opaque.  Record it as active
/// when it has not been seen before so Stop/SessionEnd can checkpoint it.
/// The host a session source kind comes from.
fn host_of_source_kind(source_kind: &str) -> &'static str {
    match source_kind {
        "claude_jsonl" => "claude",
        "codex_jsonl" => "codex",
        _ => "other",
    }
}

fn ensure_session_record(session: &str, host: &str) -> Result<(), ContractError> {
    if personal_records("sessions.jsonl")
        .into_iter()
        .any(|record| {
            record.get("session_id").and_then(Value::as_str) == Some(session)
                && record.get("status").and_then(Value::as_str) != Some("ended")
        })
    {
        return Ok(());
    }
    let repo = std::env::current_dir().map_err(io_error)?;
    let record = json!({
        "session_id": session,
        "host": host,
        "repository_id": crate::repository::repository_id(&repo).ok(),
        "started_at": now_rfc3339_millis(),
        "status": "started",
        "caller_supplied": true
    });
    append_personal("sessions.jsonl", &record)
}

fn parse_session_corpus(bytes: &[u8]) -> Result<Vec<Map<String, Value>>, ContractError> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        host_error(format!(
            "corpus is not valid UTF-8: {}",
            error.valid_up_to()
        ))
    })?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = crate::json::parse_strict_value(line.as_bytes())
            .map_err(|error| host_error(format!("line {}: {error}", index + 1)))?;
        let map = value
            .as_object()
            .cloned()
            .ok_or_else(|| host_error(format!("line {} is not a JSON object", index + 1)))?;
        for key in map.keys() {
            if !SESSION_OBSERVATION_KEYS.contains(&key.as_str()) {
                return Err(host_error(format!(
                    "line {} has unknown key `{key}`",
                    index + 1
                )));
            }
        }
        for key in SESSION_OBSERVATION_KEYS {
            if !map.get(key).is_some_and(Value::is_string) {
                return Err(host_error(format!(
                    "line {} field `{key}` must be a string",
                    index + 1
                )));
            }
        }
        let id = map["id"].as_str().unwrap_or_default();
        if id.is_empty() {
            return Err(host_error(format!(
                "line {} id must be nonempty",
                index + 1
            )));
        }
        if !matches!(map["role"].as_str(), Some("user" | "assistant")) {
            return Err(host_error(format!(
                "line {} role must be user or assistant",
                index + 1
            )));
        }
        // The host adapter declares which native artefact each line came
        // from.  Any source kind the extractor supports is admissible; an
        // unknown one is a host-version defect, not a silent relabel.
        let source_kind = map["source_kind"].as_str().unwrap_or_default();
        if !crate::classify::source_kind_is_supported(source_kind) {
            return Err(host_error(format!(
                "line {} source_kind `{source_kind}` is not a supported native source",
                index + 1
            )));
        }
        let observed_at = map["observed_at"].as_str().unwrap_or_default();
        crate::time::parse_rfc3339_millis(observed_at).map_err(|error| {
            host_error(format!(
                "line {} observed_at is invalid: {error}",
                index + 1
            ))
        })?;
        records.push(map);
    }
    if records.is_empty() {
        return Err(host_error("session corpus contains no observation objects"));
    }
    Ok(records)
}

fn session_corpus_text(records: &[Map<String, Value>], native_id: &str) -> String {
    records
        .iter()
        .find(|record| record.get("id").and_then(Value::as_str) == Some(native_id))
        .and_then(|record| record.get("text").and_then(Value::as_str))
        .unwrap_or_default()
        .to_owned()
}

/// Which classifier provider a pinned run actually uses. The configured
/// `model` selects the live Ollama provider (R-11); when Ollama does not
/// serve that model the run falls back to the product's own deterministic
/// rule provider and says so in every receipt, never silently. A provider
/// whose processor `processor_scope` does not name falls back the same way,
/// before any session text is sent to it.
#[derive(Debug, Clone)]
pub(crate) struct SelectedProvider {
    pub configured_model: Option<String>,
    pub live_model: Option<String>,
    pub fallback_from: Option<String>,
    pub fallback_reason: Option<String>,
    /// Where the run's session text goes: `local`, `agy` or `ollama-cloud`.
    pub processor: &'static str,
    /// The processors the configuration authorizes.
    pub processor_scope: String,
}

impl SelectedProvider {
    pub(crate) fn name(&self) -> &'static str {
        match self.live_model.as_deref() {
            Some(model) if model.starts_with("agy:") => "agy",
            Some(_) => "ollama",
            None => "deterministic",
        }
    }
}

pub(crate) fn select_provider(
    classifier: Option<&crate::config::SharedClassifier>,
) -> SelectedProvider {
    let processor_scope = classifier
        .map(|classifier| classifier.processor_scope.clone())
        .unwrap_or_else(|| "local".to_owned());
    let configured = classifier
        .map(|classifier| classifier.model.clone())
        .filter(|model| model.starts_with("ollama:") || model.starts_with("agy:"));
    let Some(model) = configured.clone() else {
        return SelectedProvider {
            configured_model: classifier.map(|classifier| classifier.model.clone()),
            live_model: None,
            fallback_from: None,
            fallback_reason: None,
            processor: "local",
            processor_scope,
        };
    };
    // Authorization is settled before the availability probe where the
    // model name alone decides the processor; an Ollama model's processor is
    // known only from the daemon's list, which carries no session text.
    let available = if model.starts_with("agy:") {
        crate::classifier::authorize_processor("agy", &processor_scope, &model)
            .map_err(|error| format!("{}: {}", error.code, error.message))
            .and_then(|()| crate::classifier::agy_available())
            .map(|()| "agy")
    } else {
        crate::classifier::ollama_model_available(model.trim_start_matches("ollama:")).and_then(
            |processor| {
                crate::classifier::authorize_processor(processor, &processor_scope, &model)
                    .map(|()| processor)
                    .map_err(|error| format!("{}: {}", error.code, error.message))
            },
        )
    };
    match available {
        Ok(processor) => SelectedProvider {
            configured_model: Some(model.clone()),
            live_model: Some(model),
            fallback_from: None,
            fallback_reason: None,
            processor,
            processor_scope,
        },
        Err(reason) => {
            crate::output::diagnostic(
                "classifier-fallback",
                json!({
                    "configured_model": model,
                    "provider": "deterministic",
                    "reason": reason
                }),
            );
            SelectedProvider {
                configured_model: Some(model.clone()),
                live_model: None,
                fallback_from: Some(model),
                fallback_reason: Some(reason),
                processor: "local",
                processor_scope,
            }
        }
    }
}

pub(crate) struct Extraction {
    pub(crate) atoms: BTreeMap<String, Vec<Value>>,
    pub(crate) abstained: BTreeSet<String>,
    pub(crate) requests: usize,
    pub(crate) retries: usize,
}

/// Bounded parallelism for live single-observation requests: enough to keep
/// a session batch inside the command budget, few enough that requests are
/// served rather than queued (queue time counts against each request's
/// timeout, so more workers than the provider serves concurrently only
/// manufactures timeouts).
const LIVE_CLASSIFIER_WORKERS: usize = 16;

/// Wall budget for one live extraction pass (the host command itself is
/// bounded at two minutes by its callers; the remainder is for candidate
/// construction and durable writes).
const LIVE_EXTRACTION_BUDGET_SECONDS: u64 = 95;

/// The shortest request worth starting. Below this the queue closes rather
/// than spend the tail of the budget on a request that would be killed.
const LIVE_MINIMUM_REQUEST_SECONDS: u64 = 3;

/// How much of the extraction budget is left, or `None` when what remains is
/// too little to finish a request inside it.
fn remaining_budget_for(
    started: &std::time::Instant,
    budget_seconds: u64,
) -> Option<std::time::Duration> {
    let spent = started.elapsed();
    let budget = std::time::Duration::from_secs(budget_seconds);
    let remaining = budget.checked_sub(spent)?;
    (remaining.as_secs() >= LIVE_MINIMUM_REQUEST_SECONDS).then_some(remaining)
}

#[allow(dead_code)]
fn remaining_budget(started: &std::time::Instant) -> Option<std::time::Duration> {
    let elapsed = started.elapsed().as_secs();
    let remaining = LIVE_EXTRACTION_BUDGET_SECONDS.saturating_sub(elapsed);
    (remaining >= LIVE_MINIMUM_REQUEST_SECONDS).then(|| std::time::Duration::from_secs(remaining))
}

/// The queue closed on its own wall bound. This is a fact about the command's
/// budget, never an observation the model declined to read.
fn budget_closed() -> ContractError {
    ContractError::degraded(
        "UNKNOWN_OWNER_UNRESOLVED",
        "classifier wall budget closed the sample queue",
        "Raise classifier.timeout_seconds or reduce the observation batch.",
    )
}

fn is_budget_closed(error: &ContractError) -> bool {
    error
        .message
        .contains("wall budget closed the sample queue")
}

pub(crate) fn extract_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    observations: Vec<Value>,
) -> Result<Extraction, ContractError> {
    extract_atoms_bounded(
        classifier,
        provider,
        observations,
        LIVE_CLASSIFIER_WORKERS,
        LIVE_EXTRACTION_BUDGET_SECONDS,
        LIVE_OBSERVATIONS_PER_REQUEST,
    )
}

/// The same extraction under a caller-chosen concurrency and wall budget. A
/// host hook must answer inside its own two minutes; a bulk corpus load has
/// no such bound and a cloud provider that is latency-bound per request, so
/// it buys throughput with workers rather than losing draws to the budget.
pub(crate) fn extract_atoms_bounded(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    observations: Vec<Value>,
    workers: usize,
    budget_seconds: u64,
    per_request: usize,
) -> Result<Extraction, ContractError> {
    let mut extraction = Extraction {
        atoms: BTreeMap::new(),
        abstained: BTreeSet::new(),
        requests: 0,
        retries: 0,
    };
    if provider.live_model.is_none() {
        for batch in crate::classifier::request_batches(observations)? {
            extraction.requests += 1;
            for (observation_id, atoms) in
                pinned_classifier_atoms(classifier, provider, &batch, None)?
            {
                extraction
                    .atoms
                    .entry(observation_id)
                    .or_default()
                    .extend(atoms);
            }
        }
        return Ok(extraction);
    }
    // Every observation is read `LIVE_BASE_SAMPLES` times and the product
    // decides the answer by self-consistency (below): one draw from a
    // sampling decoder is a draw from the model's distribution, not the
    // model's reading, and P-2 makes the destination set a fact this product
    // owns.
    let started = std::time::Instant::now();
    let mut samples: BTreeMap<String, Vec<Vec<Value>>> = BTreeMap::new();
    let mut taken = 0usize;
    let mut wanted = 0usize;

    let base = live_sample_pass(
        classifier,
        provider,
        &observations,
        LIVE_BASE_SAMPLES,
        &started,
        &mut extraction,
        workers,
        budget_seconds,
        per_request,
    )?;
    wanted += live_batches(&observations, per_request)?.len() * LIVE_BASE_SAMPLES;
    taken += base.0;
    merge_samples(&observations, base.1, &mut samples);

    // A third draw is bought only where the first two disagree --- where a
    // tie would otherwise be settled by rule rather than by evidence --- so
    // the extra requests go to the observations that are actually contested.
    let contested: Vec<Value> = observations
        .iter()
        .filter(|observation| {
            let id = observation["observation_id"].as_str().unwrap_or_default();
            readings_disagree(samples.get(id).map(Vec::as_slice).unwrap_or(&[]))
        })
        .cloned()
        .collect();
    if !contested.is_empty() {
        let tiebreak = live_sample_pass(
            classifier,
            provider,
            &contested,
            LIVE_TIEBREAK_SAMPLES,
            &started,
            &mut extraction,
            workers,
            budget_seconds,
            per_request,
        )?;
        wanted += live_batches(&contested, per_request)?.len() * LIVE_TIEBREAK_SAMPLES;
        taken += tiebreak.0;
        merge_samples(&contested, tiebreak.1, &mut samples);
    }

    if taken < wanted {
        // One line, not one per skipped request: the budget closed and the
        // vote was taken over fewer draws. Saying so is the point --- a
        // quieter answer is still a weaker one.
        crate::output::diagnostic(
            "classifier-budget-closed",
            json!({
                "requests_planned": wanted,
                "requests_taken": taken,
                "observations": observations.len(),
                "contested_observations": contested.len(),
                "budget_seconds": budget_seconds
            }),
        );
    }
    for observation in &observations {
        let observation_id = observation["observation_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let drawn = samples.remove(&observation_id).unwrap_or_default();
        match self_consistent_atoms(&drawn) {
            Some(atoms) if !atoms.is_empty() => {
                extraction
                    .atoms
                    .entry(observation_id)
                    .or_default()
                    .extend(atoms);
            }
            _ => {
                extraction.abstained.insert(observation_id);
            }
        }
    }
    Ok(extraction)
}

/// Group observations into live requests. A request carries a few
/// observations rather than one: the routing instruction is the same for
/// every request and is far larger than an observation, so asking one
/// observation at a time spends most of the wall budget re-sending the
/// instruction. `classifier::request_batches` still splits any group whose
/// bytes exceed the request bound.
fn live_batches(observations: &[Value], per_request: usize) -> Result<Vec<Value>, ContractError> {
    let mut batches = Vec::new();
    for chunk in observations.chunks(per_request.max(1)) {
        for batch in crate::classifier::request_batches(chunk.to_vec())? {
            if batch["observations"]
                .as_array()
                .is_some_and(|values| !values.is_empty())
            {
                batches.push(batch);
            }
        }
    }
    Ok(batches)
}

/// One request's outcome: which batch it answered for, and what came back.
type SampleOutcome = (
    usize,
    Result<BTreeMap<String, Vec<Value>>, ContractError>,
    usize,
);

/// Ask for `samples` more draws of every observation, concurrently, inside
/// the extraction budget. Work is queued sample-major --- every batch is asked
/// once before any is asked twice --- so exhausting the budget costs later
/// *samples*, never a batch's only answer. Returns how many requests were
/// actually taken and their outcomes.
#[allow(clippy::type_complexity)]
fn live_sample_pass(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    observations: &[Value],
    samples: usize,
    started: &std::time::Instant,
    extraction: &mut Extraction,
    workers: usize,
    budget_seconds: u64,
    per_request: usize,
) -> Result<(usize, Vec<(usize, BTreeMap<String, Vec<Value>>)>), ContractError> {
    let batches = live_batches(observations, per_request)?;
    let work = batches.len() * samples;
    if work == 0 {
        return Ok((0, Vec::new()));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let closed = std::sync::atomic::AtomicBool::new(false);
    let results: std::sync::Mutex<Vec<SampleOutcome>> = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..workers.max(1).min(work) {
            scope.spawn(|| {
                loop {
                    if closed.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let item = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if item >= work {
                        break;
                    }
                    let index = item % batches.len();
                    let Some(batch) = batches.get(index) else {
                        break;
                    };
                    let mut attempts = 0usize;
                    let outcome = loop {
                        // The command answers inside its own wall bound. A
                        // request that could outlive the budget is never
                        // started: the queue closes instead, so the cost of a
                        // slow provider is a later sample, not a request the
                        // caller must wait past its deadline for.
                        let Some(remaining) = remaining_budget_for(started, budget_seconds) else {
                            closed.store(true, std::sync::atomic::Ordering::Relaxed);
                            break Err(budget_closed());
                        };
                        let allowed = if remaining.as_secs() > budget_seconds * 2 / 3 {
                            3
                        } else if remaining.as_secs() > budget_seconds / 3 {
                            2
                        } else {
                            1
                        };
                        attempts += 1;
                        match pinned_classifier_atoms(classifier, provider, batch, Some(remaining))
                        {
                            Ok(atoms) => break Ok(atoms),
                            // Backpressure is not an answer: the provider is
                            // asking us to wait, so it never consumes the
                            // answer-quality retry budget, only the wall
                            // budget. Everything else keeps that budget.
                            Err(error) if provider_backpressure(&error) => {
                                std::thread::sleep(backpressure_pause(attempts));
                                continue;
                            }
                            Err(error) if attempts < allowed && retryable_extraction(&error) => {
                                continue;
                            }
                            Err(error) => break Err(error),
                        }
                    };
                    if let Ok(mut results) = results.lock() {
                        results.push((index, outcome, attempts));
                    }
                }
            });
        }
    });
    let mut outcomes = results.into_inner().unwrap_or_default();
    outcomes.sort_by_key(|(index, _, _)| *index);
    let mut answered = Vec::new();
    let mut taken = 0usize;
    for (index, outcome, attempts) in outcomes {
        extraction.requests += attempts;
        extraction.retries += attempts.saturating_sub(1);
        match outcome {
            Ok(atoms) => {
                taken += 1;
                answered.push((index, atoms));
            }
            Err(error) if is_budget_closed(&error) => {}
            Err(error) => {
                taken += 1;
                // A configuration or authorization defect is not a draw from
                // the model: it stops the run rather than losing one vote.
                if !retryable_extraction(&error) {
                    return Err(error);
                }
                crate::output::diagnostic(
                    "classifier-sample-abstained",
                    json!({"batch": index, "code": error.code, "message": error.message}),
                );
            }
        }
    }
    Ok((taken, answered))
}

/// Fold one pass's answers into the per-observation draws. A batch answer
/// carries every observation it was asked about, so an observation the model
/// omitted contributes an empty draw, which never wins a vote.
fn merge_samples(
    observations: &[Value],
    answered: Vec<(usize, BTreeMap<String, Vec<Value>>)>,
    samples: &mut BTreeMap<String, Vec<Vec<Value>>>,
) {
    let known: BTreeSet<&str> = observations
        .iter()
        .filter_map(|observation| observation["observation_id"].as_str())
        .collect();
    for (_, atoms) in answered {
        for (observation_id, drawn) in atoms {
            if !known.contains(observation_id.as_str()) {
                continue;
            }
            samples.entry(observation_id).or_default().push(drawn);
        }
    }
}

/// Whether the draws taken so far leave the reading contested: fewer than two
/// answered, or the two that answered proposed different destination sets.
fn readings_disagree(drawn: &[Vec<Value>]) -> bool {
    let readings: Vec<Vec<String>> = drawn
        .iter()
        .filter(|atoms| !atoms.is_empty())
        .map(|atoms| sample_destinations(atoms))
        .collect();
    match readings.len() {
        0 | 1 => true,
        _ => readings.iter().any(|reading| *reading != readings[0]),
    }
}

/// How many times a sampling decoder is asked to read every observation. One
/// draw is a sample, not an answer, so two are always taken and compared.
const LIVE_BASE_SAMPLES: usize = 2;

/// How many observations one live request carries. The routing instruction is
/// the same for every request and is far larger than an observation, so a
/// request per observation spends the wall budget re-sending the instruction:
/// measured on this provider, thirty-two observations cost 4.4s one at a time
/// and 1.4s in groups of four. Small enough that one slow answer costs a few
/// observations' draw, never the pass.
const LIVE_OBSERVATIONS_PER_REQUEST: usize = 4;

/// How many further draws a *contested* observation buys --- one, which turns
/// a disagreement into a majority. Uncontested observations pay nothing for
/// it, so the extra requests go where the reading is actually in doubt.
const LIVE_TIEBREAK_SAMPLES: usize = 1;

/// The provider refusing work because too many requests are already in
/// flight. This carries no information about the observation, so it is a wait,
/// never an abstention.
fn provider_backpressure(error: &ContractError) -> bool {
    matches!(
        error.code.as_str(),
        "PROCESSOR_UNAUTHORIZED" | "UNKNOWN_OWNER_UNRESOLVED"
    ) && (error.message.contains("429")
        || error.message.contains("too many")
        || error.message.contains("rate limit"))
}

/// Bounded, growing pause before re-offering a request the provider pushed
/// back on, so a saturated provider is drained rather than hammered.
fn backpressure_pause(attempts: usize) -> std::time::Duration {
    std::time::Duration::from_millis((100 * attempts.min(10)) as u64)
}

/// The destination set one sample proposed for an observation. This is the
/// unit the vote is taken over: P-2 makes the *set* of destinations the
/// classification, so voting per atom would let two samples that disagree
/// about how to split a message manufacture a third reading neither gave.
fn sample_destinations(atoms: &[Value]) -> Vec<String> {
    let mut destinations: BTreeSet<String> = BTreeSet::new();
    for atom in atoms {
        if let Some(values) = atom.get("proposed_destinations").and_then(Value::as_array) {
            for value in values {
                if let Some(label) = value.as_str() {
                    destinations.insert(label.to_owned());
                }
            }
        }
    }
    destinations.into_iter().collect()
}

/// Decide what the model read by self-consistency over the samples that
/// answered: the modal destination set wins; ties go to the smaller set (the
/// product never invents a destination a tie could not settle) and then to
/// lexicographic order, so the choice is deterministic given the samples. The
/// atoms returned are one sample's own atoms --- the first that proposed the
/// winning set --- never a merge, so every emitted atom is text some sample
/// actually produced.
fn self_consistent_atoms(drawn: &[Vec<Value>]) -> Option<Vec<Value>> {
    let readings: Vec<(Vec<String>, &Vec<Value>)> = drawn
        .iter()
        .filter(|atoms| !atoms.is_empty())
        .map(|atoms| (sample_destinations(atoms), atoms))
        .collect();
    if readings.is_empty() {
        return None;
    }
    let mut votes: BTreeMap<&Vec<String>, usize> = BTreeMap::new();
    for (destinations, _) in &readings {
        *votes.entry(destinations).or_default() += 1;
    }
    let winner = votes
        .into_iter()
        .max_by(|left, right| {
            left.1
                .cmp(&right.1)
                // Ties: the smaller set, then lexicographic order. Both are
                // properties of the reading, so the same samples always
                // decide the same way.
                .then_with(|| right.0.len().cmp(&left.0.len()))
                .then_with(|| right.0.cmp(left.0))
        })
        .map(|(destinations, _)| destinations.clone())?;
    readings
        .into_iter()
        .find(|(destinations, _)| *destinations == winner)
        .map(|(_, atoms)| atoms.clone())
}

/// Transport, timeout, and malformed-answer failures abstain per
/// observation; configuration and authorization failures stop the run.
fn retryable_extraction(error: &ContractError) -> bool {
    matches!(
        error.code.as_str(),
        "COMPANY_UNREACHABLE" | "UNKNOWN_OWNER_UNRESOLVED"
    ) || (error.code == "PROCESSOR_UNAUTHORIZED"
        && (error.message.contains("Ollama") || error.message.contains("classifier output")))
}

fn pinned_classifier_atoms(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
    input: &Value,
    timeout: Option<std::time::Duration>,
) -> Result<BTreeMap<String, Vec<Value>>, ContractError> {
    let bytes = if let Some(classifier) = classifier {
        // The pinned child selects its provider from explicit arguments: the
        // configured live model, or the deterministic provider after a loud
        // fallback. It never reads the launcher config itself.
        let mut args = classifier.args.clone();
        match &provider.live_model {
            Some(model) => {
                args.push("--model".to_owned());
                args.push(model.clone());
                args.push("--processor-scope".to_owned());
                args.push(provider.processor_scope.clone());
            }
            None => {
                args.push("--provider".to_owned());
                args.push("deterministic".to_owned());
            }
        }
        crate::sandbox::run_verified_executable(
            &classifier.executable,
            &classifier.executable_sha256,
            &args,
            &crate::json::canonical_bytes(input),
            // A request is never given more time than the extraction budget
            // has left: the command must answer inside its own bound, and a
            // request that could outlive the budget is not started at all.
            timeout
                .unwrap_or(std::time::Duration::from_secs(classifier.timeout_seconds))
                .min(std::time::Duration::from_secs(classifier.timeout_seconds)),
        )?
    } else {
        // No pinned executable means the product-owned deterministic provider
        // from `classifier --json`; it is replayable and has the same strict
        // output contract as an external provider.
        crate::json::canonical_bytes(&crate::classifier::deterministic(input)?)
    };
    let output = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::integrity(
            "PROCESSOR_UNAUTHORIZED",
            format!("classifier output is not strict JSON: {error}"),
            "Repair the pinned classifier; no output was promoted.",
        )
    })?;
    crate::classifier::validate_output(&output)?;
    let mut result: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    if let Some(atoms) = output.get("atoms").and_then(Value::as_array) {
        for atom in atoms {
            let observation_id = atom
                .get("observation_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ContractError::integrity(
                        "PROCESSOR_UNAUTHORIZED",
                        "classifier atom has no observation_id",
                        "Repair the pinned classifier; no output was promoted.",
                    )
                })?
                .to_owned();
            result.entry(observation_id).or_default().push(atom.clone());
        }
    }
    Ok(result)
}

pub(crate) fn atom_from_classifier(
    external: &Value,
    source_kind: &str,
    native_id: &str,
    observation_id: &str,
    content_digest: &str,
    repository_id: Option<&str>,
    registry: &crate::scanner::Registry,
) -> Result<crate::model::Atom, ContractError> {
    let text = external
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractError::integrity(
                "PROCESSOR_UNAUTHORIZED",
                "classifier atom has no text",
                "Repair the pinned classifier; no output was promoted.",
            )
        })?;
    let scope = external
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("host-session");
    let confidence = match external.get("confidence").and_then(Value::as_str) {
        Some("high") => 8_000,
        Some("medium") => 6_000,
        _ => 3_000,
    };
    let mut atom = crate::classify::atomize(
        source_kind,
        native_id,
        text,
        scope,
        confidence,
        observation_id,
        content_digest,
        repository_id,
        registry,
    );
    if let Some(value) = external.get("atom_id").and_then(Value::as_str) {
        atom.atom_id = value.to_owned();
    }
    if let Some(value) = external.get("atom_kind").and_then(Value::as_str) {
        atom.atom_kind = value.to_owned();
    }
    let external_taints: Vec<crate::scanner::Taint> = external
        .get("taint")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str())
                .filter_map(crate::scanner::Taint::parse)
                .collect()
        })
        .unwrap_or_default();
    // A hard-block taint the classifier reports blocks the atom as the
    // scanner's would; it used to be recorded and the atom admitted anyway.
    if external_taints.iter().any(|taint| taint.hard_block()) && !atom.hard_blocked {
        atom.hard_blocked = true;
        atom.proposed_destinations
            .retain(|destination| destination == "personal");
        atom.eligible_destinations
            .retain(|destination| destination == "personal");
    }
    if let Some(values) = external
        .get("proposed_destinations")
        .and_then(Value::as_array)
    {
        let proposed_destinations = values
            .iter()
            .filter_map(Value::as_str)
            .map(|value| match value {
                "codebase" => repository_id
                    .map(|id| format!("codebase:{id}"))
                    .unwrap_or_else(|| "codebase".to_owned()),
                other => other.to_owned(),
            })
            .collect::<Vec<_>>();
        let taint_boundary = external_taints.iter().any(|taint| {
            taint.hard_block()
                || matches!(
                    taint,
                    crate::scanner::Taint::PersonalSession
                        | crate::scanner::Taint::CompanyConfidential
                )
        });
        let mut proposed_destinations = proposed_destinations;
        let mut eligible_destinations = if atom.hard_blocked || atom.confidence < 6_000 {
            Vec::new()
        } else {
            proposed_destinations.clone()
        };
        if !atom.hard_blocked && atom.confidence >= 6_000 && taint_boundary {
            // Keep taint provenance in the audit record while admitting the
            // minimized evidence to eligible destinations. Personal memory
            // remains an additional home for the original session atom.
            let eligible_personal = eligible_destinations
                .iter()
                .any(|value| value == "personal");
            if !eligible_personal {
                eligible_destinations.push("personal".to_owned());
            }
        }
        if atom.hard_blocked || atom.confidence < 6_000 {
            proposed_destinations = vec!["none".to_owned()];
        }
        if proposed_destinations.is_empty() {
            proposed_destinations.push("none".to_owned());
        }
        // Classifier routing determines the destinations for minimized
        // evidence. Hard-blocked material is never admitted.
        atom.proposed_destinations = proposed_destinations;
        atom.eligible_destinations = eligible_destinations;
    }
    // The classifier adds taints; it never erases what the scanner found.
    if let Some(values) = external.get("taint").and_then(Value::as_array) {
        for value in values.iter().filter_map(Value::as_str) {
            if !atom.taints.iter().any(|taint| taint == value) {
                atom.taints.push(value.to_owned());
            }
        }
    }
    if let Some(value) = external
        .get("unresolved_uncertainty")
        .and_then(Value::as_str)
    {
        atom.unresolved_uncertainty = (!value.is_empty()).then(|| value.to_owned());
    }
    Ok(atom)
}

pub(crate) fn classifier_fingerprint(
    classifier: Option<&crate::config::SharedClassifier>,
    provider: &SelectedProvider,
) -> String {
    match classifier {
        Some(classifier) => format!(
            "sha256:{}:{}",
            classifier.executable_sha256,
            match &provider.live_model {
                Some(model) => model.clone(),
                None => "deterministic".to_owned(),
            }
        ),
        None => {
            let executable = std::env::current_exe().unwrap_or_else(|_| "kinbase".into());
            let digest = std::fs::read(&executable)
                .map(|bytes| sha256_bytes(&bytes))
                .unwrap_or_default();
            format!("sha256:{digest}:deterministic")
        }
    }
}

enum QuarantineDecision {
    Admitted(Map<String, Value>),
    ClockSkew(Value),
}

fn records_into_quarantine_or_admitted(
    records: Vec<Map<String, Value>>,
    proof_clock: &str,
) -> Result<Vec<QuarantineDecision>, ContractError> {
    let mut output = Vec::new();
    for record in records {
        let event_id = record
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let text = record
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let observed_at = record
            .get("observed_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let source_kind = record
            .get("source_kind")
            .and_then(Value::as_str)
            .unwrap_or("codex_jsonl")
            .to_owned();
        let digest = sha256_bytes(text.as_bytes());
        if let Some((direction, seconds)) =
            crate::time::receipt_clock_skew(&observed_at, proof_clock)
        {
            output.push(QuarantineDecision::ClockSkew(json!({
                "observation_id": format!(
                    "obs_{:x}",
                    Sha256::digest(format!("session\0{event_id}\0{digest}").as_bytes())
                ),
                "source_kind": source_kind,
                "source_identity": "host-session",
                "native_id": event_id,
                "content_digest": digest,
                "field": "observed_at",
                "direction": direction,
                "skew_seconds": seconds,
                "proof_clock": proof_clock,
                "observed_at": observed_at,
                "code": "CLOCK_SKEW",
                "disposition": "CLOCK_SKEW",
                "state": "CLOCK_SKEW",
                "remediation": "owner must supply corrected receipt evidence"
            })));
            continue;
        }
        output.push(QuarantineDecision::Admitted(record));
    }
    Ok(output)
}

fn host_error(message: impl Into<String>) -> ContractError {
    ContractError::degraded(
        "UNSUPPORTED_HOST_VERSION",
        message,
        "Use a JSONL corpus of objects with exactly id, role, text, observed_at, and source_kind.",
    )
}

fn build_candidate(
    session: &str,
    destination: &str,
    atom: &crate::model::Atom,
    message_id: &str,
    principal_id: &str,
    host_instance_id: &str,
    repository_id: Option<&str>,
) -> Result<Option<Value>, ContractError> {
    let store = destination_store(destination)?;
    // Shared admissions are minimized and de-identified. Opaque private
    // codes and the bookkeeping notes that carry them stay in the private
    // atom; the shared payload keeps the knowledge without them.
    let (statement, removed) = if store == crate::StoreKind::Personal {
        (atom.statement.clone(), 0)
    } else {
        deidentify_statement(&atom.statement)
    };
    if statement.is_empty() {
        return Ok(None);
    }
    let payload = json!({
        "destination": destination,
        "atom_kind": atom.atom_kind,
        "scope": atom.scope,
        "statement": statement
    });
    let canonical = crate::json::record_text(&payload)?;
    let payload_digest = sha256_text(&canonical);
    let candidate_id = format!(
        "cand_{}",
        sha256_text(&format!(
            "{session}\0{message_id}\0{principal_id}\0{destination}\0{payload_digest}"
        ))
    );
    let repo = std::env::current_dir().map_err(io_error)?;
    let record = json!({
        "candidate_id": candidate_id,
        "admission_mode": "automatic",
        "session_id": session,
        "message_id": message_id,
        "destination": destination,
        "canonical": canonical,
        "payload_digest": payload_digest,
        "principal": principal_id,
        "host_instance_id": host_instance_id,
        "source_revision": crate::repository::git_revision(&repo).unwrap_or_default(),
        "created_at": now_rfc3339_millis(),
        "nonce": Uuid::new_v4().to_string(),
        "confidence": atom.confidence,
        "unresolved_uncertainty": atom.unresolved_uncertainty,
        "taint_cleared": false,
        "hard_block_respected": true,
        "deidentified_tokens": removed
    });
    // A candidate bound to one of several Companies also names the
    // repository it came from: admission delivers it only from that
    // repository with that Company selected (see `admit_candidate`).
    let mut record = record;
    if company_bound_to_id(destination).is_some()
        && let (Some(object), Some(uuid)) = (record.as_object_mut(), repository_id)
    {
        object.insert("repository_uuid".to_owned(), Value::String(uuid.to_owned()));
    }
    Ok(Some(record))
}

/// Where this host sends Company-labelled knowledge from this repository:
/// the single form's `company:root`; under the named form the selected
/// Company's id, so the candidate cannot be delivered to another one; and
/// nowhere when no Company is selected or its id is not yet known.
fn company_destination(
    launcher: &crate::launcher::Launcher,
    repository_id: Option<&str>,
) -> Option<String> {
    launcher.shared.company.as_ref()?;
    if !launcher.named_form() {
        return Some("company:root".to_owned());
    }
    repository_id?;
    launcher
        .company_key_scope()
        .map(|company_id| format!("company:{company_id}"))
}

/// The company_id a named-form Company destination is bound to.
fn company_bound_to_id(destination: &str) -> Option<&str> {
    destination
        .strip_prefix("company:")
        .filter(|id| *id != "root" && !id.is_empty())
}

/// Remove opaque identifiers (long hex, base64-like, or digit-dense tokens)
/// from a statement bound for a shared destination, together with a trailing
/// bookkeeping note that only carried such a code. Returns the minimized
/// text and the number of tokens removed.
pub(crate) fn deidentify_statement(statement: &str) -> (String, usize) {
    fn opaque(word: &str) -> bool {
        let core: String = word
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '=' && c != '+' && c != '/')
            .to_owned();
        if core.len() < 16 {
            return false;
        }
        let hex_run = core
            .split(|c: char| !c.is_ascii_hexdigit())
            .map(str::len)
            .max()
            .unwrap_or(0);
        if hex_run >= 12 {
            return true;
        }
        let digits = core.chars().filter(char::is_ascii_digit).count();
        let letters = core.chars().filter(char::is_ascii_alphabetic).count();
        let base64_like = core.len() >= 20
            && core
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
            && digits >= 2
            && letters >= 2
            && (core.ends_with('=')
                || digits >= 4
                || core.chars().any(|c| c.is_ascii_uppercase())
                    && core.chars().any(|c| c.is_ascii_lowercase()));
        base64_like
    }
    let mut removed = 0usize;
    let mut sentences: Vec<String> = Vec::new();
    for sentence in split_sentences_keep(statement) {
        let mut kept: Vec<&str> = Vec::new();
        let mut dropped_here = 0usize;
        for word in sentence.split_whitespace() {
            if opaque(word) {
                dropped_here += 1;
            } else {
                kept.push(word);
            }
        }
        removed += dropped_here;
        let text = kept.join(" ");
        // A note that only carried a code ("Ref <code>", "I logged this as
        // <code>") has nothing left to share once the code is gone.
        let residual_words = text
            .split_whitespace()
            .filter(|w| w.chars().any(char::is_alphanumeric))
            .count();
        if dropped_here > 0 && residual_words <= 5 && !sentences.is_empty() {
            continue;
        }
        if dropped_here > 0 && residual_words == 0 {
            continue;
        }
        sentences.push(text);
    }
    // A statement made only of opaque codes minimizes to nothing. Returning
    // the original there, as this once did, shared exactly the code the pass
    // exists to remove; callers treat an empty result as nothing to share.
    (sentences.join(" ").trim().to_owned(), removed)
}

/// Sentence split that keeps terminators and never breaks inside a token.
fn split_sentences_keep(text: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = String::new();
    let characters: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        current.push(character);
        if matches!(character, '.' | '!' | '?') {
            let boundary = index + 1 >= characters.len() || characters[index + 1].is_whitespace();
            let previous_is_digit_dot = character == '.'
                && index > 0
                && characters[index - 1].is_ascii_digit()
                && index + 1 < characters.len()
                && characters[index + 1].is_ascii_digit();
            if boundary && !previous_is_digit_dot {
                let trimmed = current.trim().to_owned();
                if !trimmed.is_empty() {
                    output.push(trimmed);
                }
                current.clear();
            }
        }
        index += 1;
    }
    let trimmed = current.trim().to_owned();
    if !trimmed.is_empty() {
        output.push(trimmed);
    }
    output
}

pub fn checkpoint(session: &str, json: bool) -> Result<(), ContractError> {
    let (record, failure) = checkpoint_internal(session, None)?;
    if let Some(error) = failure {
        // The checkpoint is written; the command still reports the refusal,
        // and a text reader sees every candidate's outcome with it.
        if !json {
            for line in admission_lines(&record) {
                println!("{line}");
            }
        }
        return Err(error.with_output_document(record));
    }
    print_value(&record, json);
    Ok(())
}

/// Checkpoint a session without emitting host output.  Stop and SessionEnd
/// use this path so Personal facts survive the host process.
/// Checkpoint a session, admitting each automatic candidate on its own.
/// Returns the checkpoint record and the first admission refusal, if any; the
/// record (with every candidate's outcome) is written either way.
/// `repo` is the repository the host named for this event (a hook
/// envelope's `cwd`); without one the process cwd stands in. Admission
/// checks a candidate against the same repository the launcher selected the
/// Company for.
pub fn checkpoint_internal(
    session: &str,
    repo: Option<&Path>,
) -> Result<(Value, Option<ContractError>), ContractError> {
    // A failed Company delivery or a crash after journaling is retried by the
    // ordinary session lifecycle; there is no proposal command to drain it.
    // The ledgers hold every session's records and one Stop wants one
    // session's. Read them by stream and parse only the lines that carry this
    // session's marker, spelled exactly as the canonical writer spells the
    // value (escaped, NFC), never the whole ledger: at 275 MB the
    // whole-ledger read cost 1.9 s and 1.6 GB at every turn end to find
    // nothing. The exact filter below still decides, against the same
    // normalised text a stored record carries.
    let canonical_session = crate::json::jcs_text(&Value::String(session.to_owned()));
    let session_text: String = serde_json::from_str(&canonical_session).map_err(|error| {
        ContractError::internal(format!("session id is not canonical text: {error}"))
    })?;
    let session_marker = format!("\"session_id\":{canonical_session}");
    let mut candidates = BTreeMap::new();
    for candidate in personal_records_tagged(
        "candidates.jsonl",
        "session_id",
        &[session_text.as_str()],
        |line| crate::store::bytes_contain(line, session_marker.as_bytes()),
    ) {
        if crate::json::get_str(&candidate, "session_id") == Some(session_text.as_str())
            && crate::json::get_str(&candidate, "admission_mode") == Some("automatic")
        {
            let id = crate::json::get_str(&candidate, "candidate_id")
                .unwrap_or_default()
                .to_owned();
            candidates.insert(id, candidate);
        }
    }
    let pending_observation_count = settle_pending(&session_text);
    // Each candidate is admitted on its own: one that fails (an uncertified
    // repository for a Company candidate, a digest mismatch, an unreachable
    // service) is recorded as that candidate's failure and retried at a
    // later checkpoint; it used to end the checkpoint and starve the rest.
    let mut admissions = Vec::new();
    let mut admission_failures = 0usize;
    let mut admissions_held = 0usize;
    // A candidate whose exact bytes already have a settled receipt is not
    // admitted again. Its receipt is still returned, since a host's Stop
    // recovers the session's receipts from it (V-9 parity), but the recorded
    // checkpoint only counts it: every recorded checkpoint used to re-list
    // every receipt the session had ever earned, so it grew with the session
    // (1.3 MB at 2,774 candidates) and the ledger with its square (808 MB
    // from one session).
    let mut settled = BTreeSet::new();
    let mut first_failure: Option<ContractError> = None;
    let repo = match repo {
        Some(repo) => repo.to_path_buf(),
        None => std::env::current_dir().map_err(io_error)?,
    };
    if !candidates.is_empty() {
        let launcher = crate::launcher::Launcher::load();
        let latest = latest_receipts(&candidates.keys().map(String::as_str).collect());
        let mut decisions_synced = false;
        for candidate in candidates.values() {
            let admitted = (|| {
                let digest = candidate_digest(candidate)?;
                let latest = latest.as_ref().map_err(Clone::clone)?;
                if let Some(previous) = candidate_key(candidate, &digest)
                    .and_then(|key| latest.get(&key))
                    .filter(|receipt| receipt_settled(receipt))
                {
                    // Acting on a found receipt: make sure it is on disk
                    // first, once for the whole checkpoint.
                    if !decisions_synced {
                        crate::store::sync_record(
                            crate::StoreKind::Personal,
                            &repo,
                            "proposal-decisions.jsonl",
                        )?;
                        decisions_synced = true;
                    }
                    return Ok(Admission::Settled(previous.clone()));
                }
                match &launcher {
                    Ok(launcher) => {
                        admit_unsettled(launcher, &repo, candidate, &digest).map(Admission::Decided)
                    }
                    Err(error) => Err(error.clone()),
                }
            })();
            match admitted {
                Ok(Admission::Settled(previous)) => {
                    settled.insert(admissions.len());
                    admissions.push(previous);
                }
                Ok(Admission::Decided(receipt)) => admissions.push(receipt),
                Err(error) if error.code == "REPO_UNCERTIFIED" => {
                    // Not a failure: this host simply has nowhere to put a
                    // shared candidate yet. Holding it says so once and keeps
                    // the candidate for a later checkpoint; reporting it as a
                    // failed admission per candidate, per checkpoint, forever
                    // buried every real signal and told the operator to run a
                    // certification they may not own.
                    admissions_held += 1;
                    admissions.push(admission_held(candidate, &error));
                }
                Err(error) => {
                    admission_failures += 1;
                    let failure = admission_failure(candidate, &error);
                    crate::output::diagnostic("candidate-admission-failed", failure.clone());
                    admissions.push(failure);
                    first_failure.get_or_insert(error);
                }
            }
        }
    }
    let source_identity = format!("session:{session_text}");
    let source_marker = format!(
        "\"source_identity\":{}",
        crate::json::jcs_text(&Value::String(source_identity.clone()))
    );
    let observations = personal_records_tagged(
        "observations.jsonl",
        "source_identity",
        &[source_identity.as_str()],
        |line| crate::store::bytes_contain(line, source_marker.as_bytes()),
    )
    .into_iter()
    .filter(|record| {
        record.get("source_identity").and_then(Value::as_str) == Some(&source_identity)
    })
    .collect::<Vec<_>>();
    let observation_ids = observations
        .iter()
        .filter_map(|record| record.get("observation_id").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    // A session with no observations has no atoms; do not read the ledger.
    // One search per line: the id after the key is looked up in the set,
    // rather than every id searched for in every line.
    let atoms = if observation_ids.is_empty() {
        Vec::new()
    } else {
        const ATOM_KEY: &[u8] = b"\"observation_id\":\"";
        let ids = observation_ids.iter().copied().collect::<Vec<_>>();
        personal_records_tagged("atoms.jsonl", "observation_id", &ids, |line| {
            crate::store::bytes_find(line, ATOM_KEY).is_some_and(|start| {
                let rest = &line[start + ATOM_KEY.len()..];
                rest.iter()
                    .position(|&byte| byte == b'"')
                    .is_some_and(|end| {
                        std::str::from_utf8(&rest[..end])
                            .is_ok_and(|id| observation_ids.contains(id))
                    })
            })
        })
        .into_iter()
        .filter(|atom| {
            atom.get("observation_id")
                .and_then(Value::as_str)
                .is_some_and(|id| observation_ids.contains(id))
        })
        .collect::<Vec<_>>()
    };
    let core = crate::private::PrivateStore::open_core()?;
    let now = now_rfc3339_millis();
    // Expiries (pending candidates, unanswered prompt reservations, raw
    // bodies past retention) are applied here, on the write path.
    let sweep = core.sweep(&now)?;
    let mut personal_fact_count = 0;
    for atom in &atoms {
        let personal = atom
            .get("proposed_destinations")
            .and_then(Value::as_array)
            .map(|destinations| {
                destinations
                    .iter()
                    .any(|value| value.as_str() == Some("personal"))
            })
            .unwrap_or(false);
        let hard_blocked = atom
            .get("hard_blocked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !personal || hard_blocked {
            continue;
        }
        let fact = json!({
            "schema": "kinbase-personal-fact/1",
            "fact_id": format!("fact_{}", atom.get("atom_id").and_then(Value::as_str).unwrap_or_default()),
            "logical_key": format!("logical_{}", atom.get("atom_id").and_then(Value::as_str).unwrap_or_default()),
            "session_id": session,
            "atom_id": atom.get("atom_id"),
            "statement": atom.get("statement"),
            "confidence": atom.get("confidence"),
            "status": "current"
        });
        if core.upsert_personal_fact(&fact, &now)? {
            personal_fact_count += 1;
        }
    }
    let decided = admissions
        .iter()
        .enumerate()
        .filter(|(index, _)| !settled.contains(index))
        .map(|(_, row)| row.clone())
        .collect::<Vec<_>>();
    // A checkpoint is identified by what it decided, never by when it ran:
    // the same admissions, holds, failures, facts and sweep in the same
    // session are the same checkpoint. The counters beside them
    // (observations, atoms, pending, settled) are derived from the ledgers
    // and are not part of it.
    let decision = checkpoint_decision(&json!({
        "session_id": session,
        "admissions": decided,
        "admission_failures": admission_failures,
        "admissions_held": admissions_held,
        "personal_fact_count": personal_fact_count,
        "sweep": sweep
    }));
    let checkpoint_id = checkpoint_id(&decision);
    let record = json!({
        "session_id": session,
        "checkpoint_id": checkpoint_id,
        "status": "checkpointed",
        "checkpointed": true,
        "checkpointed_at": now,
        "observation_count": observations.len(),
        "pending_observation_count": pending_observation_count,
        "atom_count": atoms.len(),
        "personal_fact_count": personal_fact_count,
        "sweep": sweep,
        "admissions": decided,
        "admission_failures": admission_failures,
        "admissions_held": admissions_held,
        "admissions_settled": settled.len()
    });
    // A checkpoint that decided nothing carries only counters the ledgers
    // already hold: it is not recorded. One that decided what an earlier one
    // did (the same candidates held again) is the same checkpoint, and the
    // identity-keyed append does not record it twice.
    let recorded = !checkpoint_is_empty(&decision);
    if recorded {
        append_personal("session-checkpoints.jsonl", &record)?;
    }
    let mut response = record;
    response["admissions"] = Value::Array(admissions);
    response["checkpoint_recorded"] = Value::Bool(recorded);
    Ok((response, first_failure))
}

/// The part of a checkpoint record that is its identity: what it decided.
pub(crate) fn checkpoint_decision(record: &Value) -> Value {
    json!({
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "admissions": record.get("admissions").cloned().unwrap_or_else(|| json!([])),
        "admission_failures": record.get("admission_failures").cloned().unwrap_or_else(|| json!(0)),
        "admissions_held": record.get("admissions_held").cloned().unwrap_or_else(|| json!(0)),
        "personal_fact_count": record.get("personal_fact_count").cloned().unwrap_or_else(|| json!(0)),
        "sweep": record.get("sweep").cloned().unwrap_or(Value::Null)
    })
}

/// A checkpoint's id: the digest of what it decided.
pub(crate) fn checkpoint_id(decision: &Value) -> String {
    format!(
        "checkpoint_{}",
        sha256_text(&crate::json::jcs_text(decision))
    )
}

/// Whether a receipt settles its candidate's admission (`receipt_settled`).
pub(crate) fn admission_settled(receipt: &Value) -> bool {
    receipt_settled(receipt)
}

/// Whether a checkpoint's decision part decided nothing: no admission, hold
/// or failure, no Personal fact and no swept state.
pub(crate) fn checkpoint_is_empty(decision: &Value) -> bool {
    let zero = |value: &Value| value.as_u64() == Some(0);
    decision["admissions"].as_array().is_some_and(Vec::is_empty)
        && zero(&decision["admission_failures"])
        && zero(&decision["admissions_held"])
        && zero(&decision["personal_fact_count"])
        && decision["sweep"]
            .as_object()
            .is_none_or(|sweep| sweep.values().all(zero))
}

/// One candidate's failed admission, as its checkpoint row: the candidate,
/// its destination and the typed refusal, with no receipt (nothing was
/// decided). The prose is folded to canonical text: a refusal carrying a
/// newline (git's stderr) made the checkpoint record unwritable.
/// One candidate's held admission: kept for a later checkpoint because this
/// host has no store for its destination yet. It carries the reason and no
/// receipt, and it is not a failure.
fn admission_held(candidate: &Value, error: &ContractError) -> Value {
    let text = crate::json::fold_to_canonical_text;
    json!({
        "candidate_id": text(crate::json::get_str(candidate, "candidate_id").unwrap_or_default()),
        "destination": text(crate::json::get_str(candidate, "destination").unwrap_or_default()),
        "state": "held",
        "reason": text(&error.message)
    })
}

fn admission_failure(candidate: &Value, error: &ContractError) -> Value {
    let text = crate::json::fold_to_canonical_text;
    json!({
        "candidate_id": text(crate::json::get_str(candidate, "candidate_id").unwrap_or_default()),
        "destination": text(crate::json::get_str(candidate, "destination").unwrap_or_default()),
        "state": "failed",
        "error": {
            "code": error.code,
            "message": text(&error.message),
            "remediation": text(&error.remediation),
            "retryable": error.retryable
        }
    })
}

/// The admissions a checkpoint decided, one line each, for a reader who sees
/// only text (a host shows a failed hook's stderr and nothing else).
pub fn admission_lines(record: &Value) -> Vec<String> {
    record
        .get("admissions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|row| {
            let field = |name: &str| crate::json::get_str(row, name).unwrap_or("-");
            if crate::json::get_str(row, "state") == Some("held") {
                return format!(
                    "admission {} -> {}: held (no store for it on this host yet)",
                    field("candidate_id"),
                    field("destination")
                );
            }
            match row.get("error") {
                Some(error) => format!(
                    "admission {} -> {}: failed ({})",
                    field("candidate_id"),
                    field("destination"),
                    crate::json::get_str(error, "code").unwrap_or("-")
                ),
                None => format!(
                    "admission {} -> {}: {} ({})",
                    field("candidate_id"),
                    field("destination"),
                    crate::json::get_str(row, "state")
                        .or_else(|| crate::json::get_str(row, "decision"))
                        .unwrap_or("-"),
                    field("receipt_id")
                ),
            }
        })
        .collect()
}

pub fn end(session: &str, json: bool) -> Result<(), ContractError> {
    require_session(session)?;
    let record = json!({
        "session_id": session,
        "status": "ended",
        "ended_at": now_rfc3339_millis()
    });
    append_personal("sessions.jsonl", &record)?;
    print_value(&record, json);
    Ok(())
}

fn require_session(session: &str) -> Result<(), ContractError> {
    if personal_records("sessions.jsonl")
        .into_iter()
        .any(|record| {
            record.get("session_id").and_then(Value::as_str) == Some(session)
                && record.get("status").and_then(Value::as_str) != Some("ended")
        })
    {
        Ok(())
    } else {
        Err(ContractError::new(
            "CONFIG_INVARIANT",
            "session not active",
            "Start a session before lifecycle operations.",
            false,
            ExitCode::Refused,
        ))
    }
}

/// Every readable record of a Personal ledger. Unreadable lines are skipped
/// and reported by the reader; a ledger that cannot be opened is signalled,
/// so an empty result is never silent.
fn personal_records(name: &str) -> Vec<Value> {
    personal_records_where(name, |_| true)
}

/// Every record of a Personal ledger, for a decision about whether a step
/// already happened: an unreadable line refuses (see
/// `store::read_records_complete`).
fn personal_records_complete(name: &str) -> Result<Vec<Value>, ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::read_records_complete(crate::StoreKind::Personal, &repo, name)
}

/// The text a record line holding `value` carries, for a marker filter:
/// only lines holding it are parsed, and the exact filter runs on the record.
/// The value alone, not `"key":value`, so a record written with other
/// spacing still matches.
fn value_marker(value: &str) -> String {
    crate::json::jcs_text(&Value::String(value.to_owned()))
}

/// `personal_records_complete` for the lines holding `marker`, read by
/// stream: one candidate's receipts, not every candidate's.
fn personal_records_complete_marked(name: &str, marker: &str) -> Result<Vec<Value>, ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::read_records_complete_where(crate::StoreKind::Personal, &repo, name, |line| {
        crate::store::bytes_contain(line, marker.as_bytes())
    })
}

/// `personal_records` restricted to the lines `keep` accepts, read by stream.
/// A ledger that cannot be read is Degraded, not empty: the failure is
/// signalled so a zero count is never mistaken for no records.
fn personal_records_where(name: &str, keep: impl Fn(&[u8]) -> bool) -> Vec<Value> {
    let Ok(repo) = std::env::current_dir() else {
        return Vec::new();
    };
    match crate::store::read_records_where(crate::StoreKind::Personal, &repo, name, keep) {
        Ok(records) => records,
        Err(error) => {
            crate::output::diagnostic(
                "unreadable-ledger",
                json!({"ledger": name, "code": error.code, "message": error.message}),
            );
            Vec::new()
        }
    }
}

/// `personal_records_where` for the records whose `field` holds one of
/// `values`, looked up in the ledger's identity index; `fallback` streams the
/// ledger when the index cannot answer (`store::read_records_tagged`).
fn personal_records_tagged(
    name: &str,
    field: &str,
    values: &[&str],
    fallback: impl Fn(&[u8]) -> bool,
) -> Vec<Value> {
    let Ok(repo) = std::env::current_dir() else {
        return Vec::new();
    };
    match crate::store::read_records_tagged(
        crate::StoreKind::Personal,
        &repo,
        name,
        field,
        values,
        fallback,
    ) {
        Ok(records) => records,
        Err(error) => {
            crate::output::diagnostic(
                "unreadable-ledger",
                json!({"ledger": name, "code": error.code, "message": error.message}),
            );
            Vec::new()
        }
    }
}

fn append_personal(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::append_record(crate::StoreKind::Personal, &repo, name, value)
}

fn append_personal_durable(name: &str, value: &Value) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::append_record_durable(crate::StoreKind::Personal, &repo, name, value)
}

fn host_name(host: crate::HostKind) -> &'static str {
    match host {
        crate::HostKind::Codex => "codex",
        crate::HostKind::Claude => "claude",
    }
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!("{}", serde_json::to_string(value).unwrap_or_default());
    } else {
        println!(
            "status: {}",
            value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("recorded")
        );
        if let Some(session) = value.get("session_id").and_then(Value::as_str) {
            println!("session: {session}");
        }
    }
}

fn io_error(error: std::io::Error) -> ContractError {
    ContractError::new(
        "RUN_INTEGRITY_FAILED",
        error.to_string(),
        "Check filesystem permissions and retry.",
        false,
        ExitCode::InternalFailure,
    )
}

#[cfg(test)]
mod tests {
    use super::resolved_destination;

    #[test]
    fn a_label_becomes_a_candidate_only_where_its_store_exists() {
        // With Company access configured, company work routes as before.
        assert_eq!(
            resolved_destination("company", None, Some("company:root")).as_deref(),
            Some("company:root")
        );
        // Without it there is no null-route noise: no candidate is minted,
        // so no checkpoint reports REPO_UNCERTIFIED for it.
        assert_eq!(resolved_destination("company", None, None), None);
        // Codebase keeps its existing rule: certified repository or nothing.
        assert_eq!(
            resolved_destination("codebase", Some("uuid-1"), None).as_deref(),
            Some("codebase:uuid-1")
        );
        assert_eq!(
            resolved_destination("codebase", None, Some("company:root")),
            None
        );
        // Personal is always available; it is this host's own store.
        assert_eq!(
            resolved_destination("personal", None, None).as_deref(),
            Some("personal")
        );
    }

    use super::deidentify_statement;

    #[test]
    fn shared_payload_drops_opaque_codes_and_their_carrier_note() {
        let (text, removed) = deidentify_statement(
            "The scheduler retries at most three times. Ref kxslot0a1b2c3d4e5f6a7b",
        );
        assert_eq!(text, "The scheduler retries at most three times.");
        assert_eq!(removed, 1);
        let (text, removed) = deidentify_statement(
            "The migration adds the composite index. I logged this as kxticket9f8e7d6c5b4a3921",
        );
        assert_eq!(text, "The migration adds the composite index.");
        assert_eq!(removed, 1);
        let (text, removed) =
            deidentify_statement("My passphrase is a3hkZWFkYmVlZjEyMzQ1Njc4OTAxMg==");
        assert_eq!(text, "My passphrase is");
        assert_eq!(removed, 1);
    }

    #[test]
    fn shared_payload_keeps_ordinary_statements_intact() {
        let statement = "The lookahead window defaults to 15 minutes in scheduler/lookahead.py.";
        assert_eq!(deidentify_statement(statement), (statement.to_owned(), 0));
        let version = "We pinned requests to 2.31 because 2.32 broke the proxy handling.";
        assert_eq!(deidentify_statement(version), (version.to_owned(), 0));
    }

    #[test]
    fn a_statement_of_only_codes_minimizes_to_nothing() {
        assert_eq!(
            deidentify_statement("kx0a1b2c3d4e5f6a7b8c9d0e1f"),
            (String::new(), 1)
        );
        assert_eq!(deidentify_statement(""), (String::new(), 0));
    }
}

#[cfg(test)]
mod admission_failure_tests {
    use super::{admission_failure, admission_lines};
    use crate::error::ContractError;
    use serde_json::json;

    #[test]
    fn a_multi_line_refusal_is_still_a_writable_record() {
        let error = ContractError::user_action(
            "REPO_UNCERTIFIED",
            "git rev-parse failed: fatal: not a git repository\nStopping at filesystem boundary",
            "Run the command inside a Git worktree;\tthen retry.",
        );
        let row = admission_failure(
            &json!({"candidate_id": "cand_1", "destination": "company:root"}),
            &error,
        );
        crate::json::validate_json(&row).expect("canonical record");
        assert!(!crate::json::canonical_text(&row).is_empty());
        assert_eq!(
            admission_lines(&json!({"admissions": [row]})),
            ["admission cand_1 -> company:root: failed (REPO_UNCERTIFIED)"]
        );
    }
}

#[cfg(test)]
mod external_classifier_tests {
    use super::atom_from_classifier;
    use serde_json::json;

    fn atom(external: serde_json::Value) -> crate::model::Atom {
        atom_from_classifier(
            &external,
            "claude_jsonl",
            "native-1",
            "obs-1",
            "digest-1",
            Some("repo-uuid"),
            &crate::scanner::Registry::default(),
        )
        .expect("atom")
    }

    #[test]
    fn a_hard_block_taint_from_the_classifier_blocks_the_atom() {
        let blocked = atom(json!({
            "text": "Retries are capped at three attempts.",
            "confidence": "high",
            "taint": ["credential"],
            "proposed_destinations": ["codebase", "company"]
        }));
        assert!(blocked.hard_blocked);
        assert!(blocked.eligible_destinations.is_empty());
        assert_eq!(blocked.proposed_destinations, ["none"]);

        // Without proposed destinations, only the Personal home remains.
        let bare = atom(json!({
            "text": "Retries are capped at three attempts.",
            "taint": ["secret"]
        }));
        assert!(bare.hard_blocked);
        assert!(
            bare.eligible_destinations
                .iter()
                .all(|destination| destination == "personal")
        );
    }

    #[test]
    fn classifier_taints_add_to_the_scanners() {
        let atom = atom(json!({
            "text": "Retries are capped at three attempts.",
            "confidence": "high",
            "taint": ["public"],
            "proposed_destinations": ["codebase"]
        }));
        assert!(
            atom.taints.iter().any(|taint| taint == "personal-session"),
            "{:?}",
            atom.taints
        );
        assert!(
            atom.taints.iter().any(|taint| taint == "public"),
            "{:?}",
            atom.taints
        );
        assert!(!atom.hard_blocked);
    }
}

#[cfg(test)]
mod consistency_tests {
    use super::*;

    fn atom(observation: &str, text: &str, destination: &str) -> Value {
        json!({
            "atom_id": format!("atom_{text}_{destination}"),
            "observation_id": observation,
            "text": text,
            "proposed_destinations": [destination],
            "confidence": "high"
        })
    }

    #[test]
    fn the_modal_reading_wins_over_a_single_odd_draw() {
        let drawn = vec![
            vec![atom("o1", "the scheduler default", "codebase")],
            vec![atom("o1", "the scheduler default", "personal")],
            vec![atom("o1", "the scheduler default", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["codebase".to_owned()]);
    }

    #[test]
    fn a_tie_takes_the_smaller_set_then_lexicographic_order() {
        let drawn = vec![
            vec![atom("o1", "a", "codebase"), atom("o1", "b", "company")],
            vec![atom("o1", "a", "personal")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["personal".to_owned()]);

        let drawn = vec![
            vec![atom("o1", "a", "personal")],
            vec![atom("o1", "a", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(sample_destinations(&chosen), vec!["codebase".to_owned()]);
    }

    #[test]
    fn every_emitted_atom_comes_from_one_sample_never_a_merge() {
        let drawn = vec![
            vec![atom("o1", "first half", "codebase")],
            vec![
                atom("o1", "first half", "codebase"),
                atom("o1", "second half", "codebase"),
            ],
            vec![atom("o1", "first half", "codebase")],
        ];
        let chosen = self_consistent_atoms(&drawn).expect("a reading");
        assert_eq!(
            chosen.len(),
            1,
            "the first sample with the winning set is emitted whole"
        );
        assert_eq!(chosen[0]["text"], json!("first half"));
    }

    #[test]
    fn an_observation_no_sample_answered_abstains() {
        assert!(self_consistent_atoms(&[]).is_none());
        assert!(self_consistent_atoms(&[Vec::new()]).is_none());
    }

    #[test]
    fn a_third_draw_is_bought_only_where_the_first_two_disagree() {
        let agree = vec![
            vec![atom("o1", "a", "codebase")],
            vec![atom("o1", "a", "codebase")],
        ];
        assert!(!readings_disagree(&agree));
        let differ = vec![
            vec![atom("o1", "a", "codebase")],
            vec![atom("o1", "a", "personal")],
        ];
        assert!(readings_disagree(&differ));
        // One answer is not a majority either.
        assert!(readings_disagree(&[vec![atom("o1", "a", "codebase")]]));
        assert!(readings_disagree(&[]));
    }
}

// Durable admission transactions, shared by observation and repository recovery.
/// Append the principal's copy of a destination receipt and make it durable
/// (file and directory fsync): receipt finalization is one generation, and
/// the record must survive a crash that follows the destination commit.
fn finalize_principal_receipt(base: &Value, saga: &Value) -> Result<Value, ContractError> {
    let mut receipt = base.clone();
    merge_receipt(&mut receipt, saga);
    let repo_root = repo()?;
    let already = personal_records_complete_marked(
        "proposal-decisions.jsonl",
        &value_marker(crate::json::get_str(&receipt, "candidate_id").unwrap_or_default()),
    )?
    .into_iter()
    .any(|record| {
        crate::json::get_str(&record, "candidate_id")
            == crate::json::get_str(&receipt, "candidate_id")
            && crate::json::get_str(&record, "receipt_id")
                == crate::json::get_str(&receipt, "receipt_id")
            && crate::json::get_str(&record, "state") == crate::json::get_str(&receipt, "state")
    });
    if already {
        // Found, possibly from an attempt whose sync failed.
        crate::store::sync_record(
            crate::StoreKind::Personal,
            &repo_root,
            "proposal-decisions.jsonl",
        )?;
    } else {
        crate::store::append_record_durable(
            crate::StoreKind::Personal,
            &repo_root,
            "proposal-decisions.jsonl",
            &receipt,
        )?;
    }
    Ok(receipt)
}

fn merge_receipt(receipt: &mut Value, saga: &Value) {
    if let (Value::Object(target), Value::Object(source)) = (receipt, saga) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Fan-out saga: one journaled destination transaction per (candidate,
// destination). Every transition is a durable marker in the destination
// journal (`.kin/local/journal/fanout/<candidate>/<transition>.json`) written
// before its side effect and completed after it, so a restart replays or
// rolls back from the journal; the admission lock serializes competing local
// writers on one repository identity.
// ---------------------------------------------------------------------------

const FANOUT_JOURNAL_SCHEMA: &str = "kinbase-fanout-journal/1";
/// Company's admission status for an approved event awaiting a steward.
const STEWARD_REVIEW: &str = "pending-steward-review";
const APOLOGY_RESPONSE_WINDOW_HOURS: i64 = 24;

/// The closed transition enum of the destination journal (architecture §3:
/// nonce reservation, event append/rename, manifest, receipt, apology).
pub const FANOUT_TRANSITIONS: [(&str, &str); 5] = [
    ("nonce_reservation", "nonce_reserved"),
    ("event_append_rename", "event_appended"),
    ("manifest", "manifest_written"),
    ("receipt", "receipt_written"),
    ("apology", "apology_written"),
];

fn completed_state(transition: &str) -> &'static str {
    FANOUT_TRANSITIONS
        .iter()
        .find(|(name, _)| *name == transition)
        .map(|(_, completed)| *completed)
        .unwrap_or("done")
}

struct FanoutJournal {
    dir: std::path::PathBuf,
    candidate_id: String,
    destination: String,
}

impl FanoutJournal {
    fn open(
        repository: &crate::codebase::Repository,
        candidate_id: &str,
        destination: &str,
    ) -> Result<Self, ContractError> {
        let local = repository.ensure_local()?;
        let dir = local.join("journal").join("fanout").join(candidate_id);
        crate::paths::ensure_private_dir(&dir, "fan-out journal")?;
        Ok(Self {
            dir,
            candidate_id: candidate_id.to_owned(),
            destination: destination.to_owned(),
        })
    }

    fn marker_path(&self, transition: &str) -> std::path::PathBuf {
        self.dir.join(format!("{transition}.json"))
    }

    fn read(&self, transition: &str) -> Option<Value> {
        let bytes = std::fs::read(self.marker_path(transition)).ok()?;
        crate::json::parse_strict_value(&bytes).ok()
    }

    fn state(&self, transition: &str) -> Option<String> {
        self.read(transition)
            .and_then(|marker| crate::json::get_str(&marker, "journal_state").map(str::to_owned))
    }

    fn is_complete(&self, transition: &str) -> bool {
        self.state(transition).as_deref() == Some(completed_state(transition))
    }

    fn is_done(&self) -> bool {
        self.state("done").as_deref() == Some("done")
    }

    /// Durably record a transition state. The marker carries the candidate
    /// identity so a reader can attribute it, and it is fsynced (file and
    /// directory) before the caller proceeds to the next side effect.
    fn write(
        &self,
        transition: &str,
        journal_state: &str,
        extra: Value,
    ) -> Result<Value, ContractError> {
        let mut marker = json!({});
        if let (Value::Object(target), Value::Object(source)) = (&mut marker, extra) {
            for (key, value) in source {
                target.insert(key, value);
            }
        }
        marker["schema"] = Value::String(FANOUT_JOURNAL_SCHEMA.to_owned());
        marker["candidate_id"] = Value::String(self.candidate_id.clone());
        marker["destination"] = Value::String(self.destination.clone());
        marker["transition"] = Value::String(transition.to_owned());
        marker["journal_state"] = Value::String(journal_state.to_owned());
        marker["updated_at"] = Value::String(now_rfc3339_millis());
        crate::paths::write_atomic(
            &self.marker_path(transition),
            &crate::json::record_bytes(&marker)?,
            0o600,
            false,
        )?;
        Ok(marker)
    }

    /// Mark the intent to perform a transition (its side effect may or may
    /// not follow before a crash; replay treats it as not yet done).
    fn begin(&self, transition: &str, extra: Value) -> Result<Value, ContractError> {
        if let Some(existing) = self.read(transition) {
            if crate::json::get_str(&existing, "journal_state") == Some(completed_state(transition))
            {
                return Ok(existing);
            }
            // Preserve the bytes bound at the first attempt so a replay
            // reuses exactly them.
            let mut merged = existing.clone();
            if let (Value::Object(target), Value::Object(source)) = (&mut merged, extra) {
                for (key, value) in source {
                    target.entry(key).or_insert(value);
                }
            }
            let extra = merged;
            return self.write(transition, transition, extra);
        }
        self.write(transition, transition, extra)
    }

    fn complete(&self, transition: &str, extra: Value) -> Result<Value, ContractError> {
        let mut merged = self.read(transition).unwrap_or_else(|| json!({}));
        if let (Value::Object(target), Value::Object(source)) = (&mut merged, extra) {
            for (key, value) in source {
                target.insert(key, value);
            }
        }
        self.write(transition, completed_state(transition), merged)
    }

    fn finish(&self) -> Result<(), ContractError> {
        self.write("done", "done", json!({}))?;
        Ok(())
    }
}

fn fanout_saga_result(
    launcher: &crate::launcher::Launcher,
    repo_root: &Path,
    record: &Value,
    destination: &str,
    payload_digest: &str,
    receipt_id: &str,
    base_receipt: &Value,
) -> Result<Value, ContractError> {
    let repository = crate::codebase::Repository::discover(repo_root)?;
    let repository_uuid = crate::repository::repository_id(repo_root)?;
    if let Some(bound) = destination.strip_prefix("codebase:") {
        if bound != repository_uuid {
            return Err(ContractError::refused(
                "AUTHORITY_SCOPE_DENIED",
                "candidate names a different repository identity than the certified one",
                "Create a candidate for the certified repository identity.",
            ));
        }
    }
    let candidate_id = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    // Every transition below is one generation under the exclusive
    // admission lock; the journal carries the transaction between
    // generations, so the lock is never held across a Company round trip
    // and competing local writers retry from the committed generation.
    recover_fanout_journal(launcher, &repository, &repository_uuid, Some(candidate_id))?;
    let journal = FanoutJournal::open(&repository, candidate_id, destination)?;
    if destination.starts_with("codebase:") {
        commit_codebase(
            launcher,
            &repository,
            &repository_uuid,
            &journal,
            record,
            payload_digest,
            receipt_id,
            base_receipt,
        )
    } else {
        commit_company(
            launcher,
            &repository,
            &repository_uuid,
            &journal,
            record,
            payload_digest,
            receipt_id,
            base_receipt,
        )
    }
}

/// Build the destination event once and bind the admission nonce to its
/// exact bytes in the journal (nonce reservation). A replay reuses the bound
/// bytes, so a retry can never mint a second content-addressed event.
#[allow(clippy::too_many_arguments)]
fn reserve_nonce(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    journal: &FanoutJournal,
    repository_uuid: &str,
    store: crate::StoreKind,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
) -> Result<(Vec<u8>, Value), ContractError> {
    let bound = journal
        .read("nonce_reservation")
        .and_then(|marker| crate::json::get_str(&marker, "event_canonical").map(str::to_owned));
    let (canonical, event) = match bound {
        Some(canonical) => {
            let event = crate::json::parse_strict_value(canonical.as_bytes()).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!("journaled event bytes are not canonical: {error}"),
                    "Preserve the journal; the bound event bytes are never reinterpreted.",
                )
            })?;
            (canonical, event)
        }
        None => {
            let event = build_destination_event(Some(launcher), store, repository_uuid, record)?;
            (crate::json::record_text(&event)?, event)
        }
    };
    if !journal.is_complete("nonce_reservation") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "nonce_reservation",
            json!({
                "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
                "payload_digest": payload_digest,
                "receipt_id": receipt_id,
                "principal": record.get("principal").cloned().unwrap_or(Value::Null),
                "event_canonical": canonical,
                "event_digest": sha256_text(&canonical),
                "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
                "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
                "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null)
            }),
        )?;
        append_personal_durable(
            "nonce-reservations.jsonl",
            &json!({
                "nonce": record.get("nonce").cloned().unwrap_or(Value::Null),
                "candidate_id": journal.candidate_id,
                "destination": journal.destination,
                "payload_digest": payload_digest,
                "receipt_id": receipt_id,
                "event_digest": sha256_text(&canonical)
            }),
        )?;
        journal.complete("nonce_reservation", json!({}))?;
    }
    Ok((canonical.into_bytes(), event))
}

#[allow(clippy::too_many_arguments)]
fn commit_codebase(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    journal: &FanoutJournal,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
    base_receipt: &Value,
) -> Result<Value, ContractError> {
    let (bytes, event) = reserve_nonce(
        launcher,
        repository,
        journal,
        repository_uuid,
        crate::StoreKind::Codebase,
        record,
        payload_digest,
        receipt_id,
    )?;
    let event_digest = crate::hash::sha256_bytes(&bytes);
    let relative = crate::paths::sharded_relative(&event_digest)?;
    let final_path = crate::paths::contained(&repository.kin.join("events"), &relative)?;
    let event_path = format!(".kin/events/{}", relative.to_string_lossy());
    let local = repository.ensure_local()?;
    // event append + atomic rename to the content-addressed path
    if !journal.is_complete("event_append_rename") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "event_append_rename",
            json!({"event_digest": event_digest, "event_path": event_path}),
        )?;
        let staging = local.join("staging");
        crate::paths::ensure_private_dir(&staging, "staging")?;
        let staged = staging.join(format!("{event_digest}.json"));
        crate::paths::write_atomic(&staged, &bytes, 0o600, false)?;
        let created = crate::paths::write_atomic(&final_path, &bytes, 0o644, true)?;
        let _ = std::fs::remove_file(&staged);
        journal.complete("event_append_rename", json!({"created": created}))?;
    }
    // manifest: the destination's local index of admitted digests
    if !journal.is_complete("manifest") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "manifest",
            json!({"index": ".kin/local/kinbase-index.json"}),
        )?;
        repository.update_index_cache()?;
        journal.complete("manifest", json!({}))?;
    }
    // receipt: the destination's own committed receipt
    let receipts_dir = local.join("receipts").join(repository_uuid);
    crate::paths::ensure_private_dir(&receipts_dir, "receipts")?;
    let receipt_path = receipts_dir.join(format!("{event_digest}.json"));
    if !journal.is_complete("receipt") {
        let _generation = repository.admission_lock(repository_uuid)?;
        journal.begin(
            "receipt",
            json!({"receipt_path": receipt_path.to_string_lossy()}),
        )?;
        if !receipt_path.exists() {
            let receipt = json!({
                "schema": crate::model::RECEIPT_SCHEMA,
                "receipt_id": receipt_id,
                "candidate_id": journal.candidate_id,
                "destination": journal.destination,
                "repository_uuid": repository_uuid,
                "status": "committed",
                "state": "committed",
                "event_digest": event_digest,
                "event_path": event_path,
                "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
                "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
                "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null),
                "payload_digest": payload_digest,
                "committed_at": now_rfc3339_millis()
            });
            crate::paths::write_atomic(
                &receipt_path,
                &crate::json::record_bytes(&receipt)?,
                0o600,
                false,
            )?;
        }
        // The receipt names exactly the bytes the destination holds: re-read
        // and re-hash the committed event before the receipt is final.
        let committed = std::fs::read(&final_path)
            .map_err(|error| ContractError::io("re-read committed event", error))?;
        if crate::hash::sha256_bytes(&committed) != event_digest {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                "committed event bytes differ from the bound bytes",
                "Run full fsck; the destination journal is inconsistent.",
            ));
        }
        let summary = receipt_summary(
            &receipt_path,
            receipt_id,
            &event_digest,
            &event_path,
            &event,
            journal,
        )?;
        finalize_principal_receipt(base_receipt, &summary)?;
        journal.complete("receipt", json!({}))?;
        journal.finish()?;
    }
    receipt_summary(
        &receipt_path,
        receipt_id,
        &event_digest,
        &event_path,
        &event,
        journal,
    )
}

fn receipt_summary(
    receipt_path: &Path,
    receipt_id: &str,
    event_digest: &str,
    event_path: &str,
    event: &Value,
    journal: &FanoutJournal,
) -> Result<Value, ContractError> {
    let stored =
        std::fs::read(receipt_path).map_err(|error| ContractError::io("read receipt", error))?;
    let stored = crate::json::parse_strict_value(&stored).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!("receipt is not canonical JSON: {error}"),
            "Run fsck; the receipt store is corrupt.",
        )
    })?;
    Ok(json!({
        "state": "committed",
        "receipt_id": crate::json::get_str(&stored, "receipt_id").unwrap_or(receipt_id),
        "event_digest": event_digest,
        "event_path": event_path,
        "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
        "fact_id": event.get("fact_id").cloned().unwrap_or(Value::Null),
        "logical_key": event.get("logical_key").cloned().unwrap_or(Value::Null),
        "journal_generation": journal.candidate_id
    }))
}

fn commit_company(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    journal: &FanoutJournal,
    record: &Value,
    payload_digest: &str,
    receipt_id: &str,
    base_receipt: &Value,
) -> Result<Value, ContractError> {
    let (_bytes, event) = reserve_nonce(
        launcher,
        repository,
        journal,
        repository_uuid,
        crate::StoreKind::Company,
        record,
        payload_digest,
        receipt_id,
    )?;
    // A terminal receipt is replayed as-is; a pending one is re-attempted.
    if journal.is_complete("receipt") {
        if let Some(marker) = journal.read("receipt") {
            if matches!(
                crate::json::get_str(&marker, "state"),
                Some("committed") | Some("refused")
            ) {
                let summary = receipt_from_marker(&marker, receipt_id);
                finalize_principal_receipt(base_receipt, &summary)?;
                journal.finish()?;
                return Ok(summary);
            }
        }
    }
    // The Company destination runs its own transaction; the client sends
    // the event once per attempt and records the outcome it was given.
    let attempt = match launcher.company() {
        Ok(Some(access)) => match approved_submission(launcher, repository, record, &event)
            .and_then(|submission| access.client.post_fact(&submission))
        {
            // A signer that is not the Company authority for the scope is
            // queued for steward review (202). Until a steward admits it the
            // Company destination is pending: its apology stays open and
            // later passes ask again.
            Ok(body) => {
                let admission = crate::json::get_str(&body, "status")
                    .or_else(|| crate::json::get_str(&body, "admission_status"))
                    .unwrap_or("committed")
                    .to_owned();
                json!({
                    "state": if admission == STEWARD_REVIEW { "pending" } else { "committed" },
                    "company_receipt": body,
                    "company_admission": admission
                })
            }
            Err(error) => json!({
                "state": if error.code == "COMPANY_UNREACHABLE" { "pending" } else { "refused" },
                "error_code": error.code,
                "error_message": error.message,
                "retryable": error.retryable,
                "company_unreachable": error.code == "COMPANY_UNREACHABLE",
                "timeout_observed": error.code == "COMPANY_UNREACHABLE"
            }),
        },
        Ok(None) => json!({
            "state": "refused",
            "error_code": "AUTHORITY_SCOPE_DENIED",
            "error_message": "no Company endpoint is configured for this principal",
            "retryable": false
        }),
        Err(error) => json!({
            "state": "refused",
            "error_code": error.code,
            "error_message": error.message,
            "retryable": error.retryable
        }),
    };
    let state = crate::json::get_str(&attempt, "state")
        .unwrap_or("refused")
        .to_owned();
    let mut apology_ids = Vec::new();
    if state == "committed" {
        // The apology opened while Company had not answered is settled: the
        // claim is no longer orphaned, and its deadline must not abandon it.
        reconcile_apologies(launcher, receipt_id, &now_rfc3339_millis())?;
    } else {
        // Divergence: another destination of the same source already holds
        // a durable commit that this failure cannot roll back. The
        // admitting principal owns the divergence; the committed
        // destination receives the apology Unknown. A pending (unreachable)
        // attempt is retried by later admissions, and a commit before the
        // deadline reconciles the apology.
        for sibling in committed_siblings(record)? {
            let apology_id = apology_id_for(receipt_id, &sibling);
            if !journal.is_complete("apology") || !apology_exists(&apology_id)? {
                let _generation = repository.admission_lock(repository_uuid)?;
                journal.begin("apology", json!({"apology_id": apology_id, "committed_receipt_id": sibling.get("receipt_id").cloned().unwrap_or(Value::Null)}))?;
                let unknown_id = write_apology(
                    launcher,
                    repository,
                    repository_uuid,
                    record,
                    receipt_id,
                    &attempt,
                    &sibling,
                    &apology_id,
                )?;
                journal.complete("apology", json!({"unknown_id": unknown_id}))?;
            }
            apology_ids.push(apology_id);
        }
        // Outside the admission lock: a slow Company must not hold it. An
        // unreachable Company gets the Unknowns from a later pass.
        if !apology_ids.is_empty() && attempt.get("company_unreachable") != Some(&Value::Bool(true))
        {
            deliver_apology_unknowns(launcher, repository_uuid)?;
        }
    }
    let _generation = repository.admission_lock(repository_uuid)?;
    journal.begin("receipt", json!({}))?;
    let marker = journal.complete(
        "receipt",
        json!({
            "state": state,
            "attempt": attempt,
            "apology_ids": apology_ids,
            "receipt_id": receipt_id
        }),
    )?;
    let summary = receipt_from_marker(&marker, receipt_id);
    finalize_principal_receipt(base_receipt, &summary)?;
    if state != "pending" {
        journal.finish()?;
    }
    Ok(summary)
}

/// The event with the admitting principal's approval of its exact bytes.
/// Company admits a verified authority's event directly and queues any other
/// signer's approved event for steward review; a bare event from a
/// non-authority signer is refused.
fn approved_submission(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    record: &Value,
    event: &Value,
) -> Result<Value, ContractError> {
    let key = destination_signing_key(Some(launcher), crate::StoreKind::Company, &repository.root)?;
    approval_envelope(&key, record, event, &now_rfc3339_millis())
}

fn approval_envelope(
    key: &crate::crypto::PrivateKey,
    record: &Value,
    event: &Value,
    now: &str,
) -> Result<Value, ContractError> {
    let approval = key.sign_document(
        "approval-token",
        &json!({
            "schema": "kinbase-approval/1",
            "candidate_id": record.get("candidate_id").cloned().unwrap_or(Value::Null),
            "destination": record.get("destination").cloned().unwrap_or(Value::Null),
            "principal": record.get("principal").cloned().unwrap_or(Value::Null),
            "event_id": event.get("event_id").cloned().unwrap_or(Value::Null),
            "event_digest": crate::json::digest(event),
            "approved_at": now
        }),
    )?;
    Ok(json!({"event": event, "approval_token": approval}))
}

fn receipt_from_marker(marker: &Value, receipt_id: &str) -> Value {
    let mut receipt = json!({
        "state": crate::json::get_str(marker, "state").unwrap_or("pending"),
        "receipt_id": crate::json::get_str(marker, "receipt_id").unwrap_or(receipt_id),
        "apology_ids": marker.get("apology_ids").cloned().unwrap_or_else(|| json!([]))
    });
    if let Some(Value::Object(attempt)) = marker.get("attempt") {
        for (key, value) in attempt {
            if key != "state" {
                receipt[key] = value.clone();
            }
        }
    }
    if let Some(unknown) = marker.get("unknown_id") {
        receipt["unknown_id"] = unknown.clone();
    }
    receipt
}

/// Committed decisions of other destinations for the same source message
/// (the siblings of one fan-out).
fn committed_siblings(record: &Value) -> Result<Vec<Value>, ContractError> {
    let message_id = crate::json::get_str(record, "message_id").unwrap_or_default();
    let session_id = crate::json::get_str(record, "session_id").unwrap_or_default();
    let candidate_id = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    let message_marker = value_marker(message_id);
    let siblings: Vec<Value> = personal_records_where("candidates.jsonl", |line| {
        crate::store::bytes_contain(line, message_marker.as_bytes())
    })
    .into_iter()
    .filter(|other| {
        crate::json::get_str(other, "message_id") == Some(message_id)
            && crate::json::get_str(other, "session_id") == Some(session_id)
            && crate::json::get_str(other, "candidate_id") != Some(candidate_id)
    })
    .collect();
    // Whether a sibling committed decides whether an apology is owed; only
    // the siblings' receipts are read.
    let sibling_markers: Vec<String> = siblings
        .iter()
        .filter_map(|sibling| crate::json::get_str(sibling, "candidate_id"))
        .map(value_marker)
        .collect();
    let decisions = if sibling_markers.is_empty() {
        Vec::new()
    } else {
        let repo = std::env::current_dir().map_err(io_error)?;
        crate::store::read_records_complete_where(
            crate::StoreKind::Personal,
            &repo,
            "proposal-decisions.jsonl",
            |line| {
                sibling_markers
                    .iter()
                    .any(|marker| crate::store::bytes_contain(line, marker.as_bytes()))
            },
        )?
    };
    let mut committed = Vec::new();
    for sibling in siblings {
        let sibling_id = crate::json::get_str(&sibling, "candidate_id").unwrap_or_default();
        if let Some(decision) = decisions
            .iter()
            .filter(|decision| crate::json::get_str(decision, "candidate_id") == Some(sibling_id))
            .last()
        {
            if decision_state(decision) == "committed"
                && matches!(
                    crate::json::get_str(decision, "decision"),
                    Some("approve" | "admit")
                )
            {
                committed.push(decision.clone());
            }
        }
    }
    Ok(committed)
}

/// Mark every open apology for `failed_receipt_id` reconciled: the
/// destination that had not answered has committed after all.
fn reconcile_apologies(
    launcher: &crate::launcher::Launcher,
    failed_receipt_id: &str,
    now: &str,
) -> Result<(), ContractError> {
    for apology in current_apologies_complete()? {
        if crate::json::get_str(&apology, "failed_receipt_id") != Some(failed_receipt_id)
            || crate::json::get_str(&apology, "state") != Some("awaiting_reconcile_or_abandon")
        {
            continue;
        }
        let update = json!({
            "apology_id": apology.get("apology_id").cloned().unwrap_or(Value::Null),
            "state": "reconciled",
            "reconciled_at": now,
            "reconciled_by": "failed-destination-committed"
        });
        append_personal_durable("apologies.jsonl", &update)?;
        // The cached saga row `status` counts is settled with it.
        if let Ok(Some((cache, _))) = launcher.company_cache() {
            let mut settled = apology.clone();
            merge_receipt(&mut settled, &update);
            let _ = cache.save_saga(
                crate::json::get_str(&apology, "candidate_id").unwrap_or_default(),
                &settled,
                now,
            );
        }
    }
    Ok(())
}

fn apology_id_for(failed_receipt_id: &str, committed: &Value) -> String {
    let committed_receipt = crate::json::get_str(committed, "receipt_id").unwrap_or_default();
    format!(
        "apology_{}",
        &crate::hash::sha256_text(&format!("{failed_receipt_id}\0{committed_receipt}"))[..40]
    )
}

fn apology_exists(apology_id: &str) -> Result<bool, ContractError> {
    Ok(personal_records_complete("apologies.jsonl")?
        .iter()
        .any(|apology| crate::json::get_str(apology, "apology_id") == Some(apology_id)))
}

/// The latest state of every apology (append-only records; last wins).
fn current_apologies() -> Vec<Value> {
    latest_apologies(personal_records("apologies.jsonl"))
}

/// `current_apologies` for a decision about whether an apology exists or is
/// due: an unreadable line refuses, and what was found is on disk first.
fn current_apologies_complete() -> Result<Vec<Value>, ContractError> {
    let records = personal_records_complete("apologies.jsonl")?;
    sync_personal("apologies.jsonl")?;
    Ok(latest_apologies(records))
}

fn sync_personal(name: &str) -> Result<(), ContractError> {
    let repo = std::env::current_dir().map_err(io_error)?;
    crate::store::sync_record(crate::StoreKind::Personal, &repo, name)
}

fn latest_apologies(records: Vec<Value>) -> Vec<Value> {
    let mut latest: BTreeMap<String, Value> = BTreeMap::new();
    for record in records {
        let Some(id) = crate::json::get_str(&record, "apology_id") else {
            continue;
        };
        let entry = latest
            .entry(id.to_owned())
            .or_insert_with(|| record.clone());
        if let (Value::Object(target), Value::Object(source)) = (entry, &record) {
            for (key, value) in source {
                target.insert(key.clone(), value.clone());
            }
        }
    }
    latest.into_values().collect()
}

/// Resolve the in-scope closing authority of a destination from the cached
/// authority registry: the repository maintainer for the Codebase, the
/// steward for Company. Unresolved identities stay Unknown-owned by role.
fn closing_authority(
    launcher: &crate::launcher::Launcher,
    destination: &str,
    repository_uuid: &str,
) -> (String, Option<String>) {
    let role = if destination.starts_with("company") {
        "company-steward"
    } else {
        "repository-maintainer"
    };
    let scope = if destination.starts_with("company") {
        "company:root".to_owned()
    } else {
        format!("codebase:{repository_uuid}")
    };
    let identity = launcher
        .company_cache()
        .ok()
        .flatten()
        .and_then(|(cache, _)| cache.snapshot().ok().flatten())
        .and_then(|snapshot| {
            crate::json::get_array(&snapshot, "registry").and_then(|entries| {
                let ids: Vec<String> = entries
                    .iter()
                    .filter(|entry| crate::json::get_str(entry, "scope") == Some(scope.as_str()))
                    .filter(|entry| {
                        crate::json::get_str(entry, "status").unwrap_or("active") == "active"
                    })
                    .filter_map(|entry| {
                        crate::json::get_str(entry, "authority_id").map(str::to_owned)
                    })
                    .collect();
                (ids.len() == 1).then(|| ids[0].clone())
            })
        });
    (role.to_owned(), identity)
}

/// Write the apology Unknown for one divergent fan-out into the committed
/// destination's private Unknown store and the saga record. Idempotent per
/// apology id: a replay after a crash writes the same Unknown once.
fn write_apology(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    record: &Value,
    failed_receipt_id: &str,
    attempt: &Value,
    committed: &Value,
    apology_id: &str,
) -> Result<String, ContractError> {
    if let Some(existing) = current_apologies_complete()?
        .into_iter()
        .find(|apology| crate::json::get_str(apology, "apology_id") == Some(apology_id))
    {
        // A replay after a crash finds the apology already written: the
        // same Unknown, never a second (recursive) apology.
        return Ok(crate::json::get_str(&existing, "unknown_id")
            .unwrap_or_default()
            .to_owned());
    }
    let committed_destination = crate::json::get_str(committed, "destination")
        .unwrap_or_default()
        .to_owned();
    let failed_destination = crate::json::get_str(record, "destination")
        .unwrap_or_default()
        .to_owned();
    let principal = crate::json::get_str(record, "principal")
        .map(str::to_owned)
        .unwrap_or_else(principal_id);
    let (closing_role, closing_identity) =
        closing_authority(launcher, &committed_destination, repository_uuid);
    let closing_name = closing_identity
        .clone()
        .unwrap_or_else(|| closing_role.clone());
    // The same proof clock that later decides the apology is overdue.
    let now = crate::time::proof_clock_instant();
    let response_due_at =
        format_rfc3339_millis(now + Duration::hours(APOLOGY_RESPONSE_WINDOW_HOURS));
    let store = destination_store(&committed_destination)?;
    let question = format!(
        "Apology Unknown for divergent fan-out: destination {failed_destination} failed ({}) after {committed_destination} committed receipt {}. Admitting principal {principal} is responsible; closing authority {closing_name} ({closing_role}) must reconcile or abandon by {response_due_at}. The orphaned claim is withheld from trusted use until then.",
        crate::json::get_str(attempt, "error_code")
            .or_else(|| crate::json::get_str(attempt, "company_admission"))
            .unwrap_or("refused"),
        crate::json::get_str(committed, "receipt_id").unwrap_or_default()
    );
    let scope = "architecture:escalation";
    let logical_key = crate::model::logical_key(store_name(store), scope, apology_id);
    let mut unknown = UnknownEvent::new(
        store_name(store),
        (store == crate::StoreKind::Codebase).then_some(repository_uuid),
        &closing_role,
        scope,
        &logical_key,
        scope,
        &committed_destination,
        &closing_role,
        &closing_name,
        &question,
        8_000,
        &format_rfc3339_millis(now),
        &response_due_at,
        "block-dependent-decision",
        "0",
    );
    unknown.parents = vec![
        crate::json::get_str(committed, "event_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    unknown.evidence_refs = vec![
        failed_receipt_id.to_owned(),
        crate::json::get_str(committed, "receipt_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    let unknown_id = unknown.fact_id.clone();
    let (private_path, _) = crate::crypto::ensure_keypair(store, &repository.root)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local escalation-closing key")?;
    unknown.sign(&private_key)?;
    // Unknowns are private runtime state of the committed destination, never
    // additional tracked `.kin/` artefacts.
    crate::store::append_record(
        crate::StoreKind::Personal,
        &repository.root,
        "unknowns.jsonl",
        &unknown.to_value(),
    )?;
    let apology = json!({
        "apology_id": apology_id,
        "candidate_id": record.get("candidate_id").cloned().unwrap_or(Value::Null),
        "session_id": record.get("session_id").cloned().unwrap_or(Value::Null),
        "message_id": record.get("message_id").cloned().unwrap_or(Value::Null),
        "failed_destination": failed_destination,
        "failed_receipt_id": failed_receipt_id,
        "failure_code": attempt.get("error_code").cloned().unwrap_or(Value::Null),
        "committed_destination": committed_destination,
        "committed_candidate_id": committed.get("candidate_id").cloned().unwrap_or(Value::Null),
        "committed_receipt_id": committed.get("receipt_id").cloned().unwrap_or(Value::Null),
        "orphaned_event_id": committed.get("event_id").cloned().unwrap_or(Value::Null),
        "orphaned_fact_id": committed.get("fact_id").cloned().unwrap_or(Value::Null),
        "orphaned_logical_key": committed.get("logical_key").cloned().unwrap_or(Value::Null),
        "orphaned_event_digest": committed.get("event_digest").cloned().unwrap_or(Value::Null),
        "repository_uuid": repository_uuid,
        "responsible_party_role": "admitting-principal",
        "responsible_party": principal,
        "closing_authority_role": closing_role,
        "closing_authority": closing_name,
        "closing_authority_resolved": closing_identity.is_some(),
        "orphaned_fact_withheld": true,
        "unknown_id": unknown_id,
        "response_due_at": response_due_at,
        "created_at": format_rfc3339_millis(now),
        "state": "awaiting_reconcile_or_abandon",
        "unknown_delivered": false
    });
    append_personal_durable("apologies.jsonl", &apology)?;
    // The pending saga is also visible to the Company cache so `status`
    // counts it among the orphans awaiting reconcile/abandon.
    if let Ok(Some((cache, _))) = launcher.company_cache() {
        let _ = cache.save_saga(
            crate::json::get_str(record, "candidate_id").unwrap_or_default(),
            &apology,
            &format_rfc3339_millis(now),
        );
    }
    Ok(unknown_id)
}

/// How many Company sagas one recovery pass retries, so an admission inside a
/// host hook's budget is not spent draining a backlog.
const COMPANY_RETRIES_PER_PASS: usize = 8;

/// Replay every unfinished fan-out saga of this repository under the lock:
/// a transaction whose event bytes are durable completes forward; one that
/// never bound its bytes is rolled back. A Company saga left pending by any
/// earlier session (Company did not answer) is posted again while Company
/// answers. The candidate being decided now is replayed by its own
/// idempotent transitions.
fn recover_fanout_journal(
    launcher: &crate::launcher::Launcher,
    repository: &crate::codebase::Repository,
    repository_uuid: &str,
    current_candidate: Option<&str>,
) -> Result<Vec<Value>, ContractError> {
    let root = repository.local_dir().join("journal").join("fanout");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut replayed = Vec::new();
    let mut company_retries = 0usize;
    let mut company_answering = true;
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(&root)
        .map_err(|error| ContractError::io("read fan-out journal", error))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    // The candidate journal is read once per pass, and only if some fan-out
    // is unfinished: it used to be parsed in full for every journal directory,
    // finished or not, on every shared admission.
    let mut candidates: Option<std::collections::HashMap<String, Value>> = None;
    for dir in entries {
        let candidate_id = dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if current_candidate == Some(candidate_id.as_str()) {
            continue;
        }
        // Finished needs only the journal's own directory.
        let finished = FanoutJournal {
            dir: dir.clone(),
            candidate_id: candidate_id.clone(),
            destination: String::new(),
        }
        .is_done();
        if finished {
            continue;
        }
        let candidates = candidates.get_or_insert_with(|| {
            let mut by_id = std::collections::HashMap::new();
            for record in personal_records("candidates.jsonl") {
                if let Some(id) = crate::json::get_str(&record, "candidate_id") {
                    // The first record for an id wins, as a forward search found it.
                    by_id.entry(id.to_owned()).or_insert(record);
                }
            }
            by_id
        });
        let Some(record) = candidates.get(&candidate_id).cloned() else {
            continue;
        };
        let destination = crate::json::get_str(&record, "destination")
            .unwrap_or_default()
            .to_owned();
        let journal = FanoutJournal {
            dir: dir.clone(),
            candidate_id: candidate_id.clone(),
            destination: destination.clone(),
        };
        if journal.is_done() {
            continue;
        }
        if destination.starts_with("company") {
            if !company_answering || company_retries >= COMPANY_RETRIES_PER_PASS {
                continue;
            }
            let Some(reservation) = journal.read("nonce_reservation") else {
                continue;
            };
            if crate::json::get_str(&reservation, "event_canonical").is_none() {
                continue;
            }
            company_retries += 1;
            let payload_digest = crate::json::get_str(&reservation, "payload_digest")
                .unwrap_or_default()
                .to_owned();
            let receipt_id = crate::json::get_str(&reservation, "receipt_id")
                .unwrap_or_default()
                .to_owned();
            let base_receipt = json!({
                "candidate_id": candidate_id,
                "destination": destination,
                "decision": "admit",
                "digest": payload_digest,
                "decided_at": now_rfc3339_millis(),
                "receipt_id": receipt_id,
                "state": "pending",
                "recovered": true
            });
            let summary = commit_company(
                launcher,
                repository,
                repository_uuid,
                &journal,
                &record,
                &payload_digest,
                &receipt_id,
                &base_receipt,
            )?;
            let state = crate::json::get_str(&summary, "state").unwrap_or("pending");
            if state == "pending" {
                company_answering = false;
            }
            replayed
                .push(json!({"candidate_id": candidate_id, "action": format!("company-{state}")}));
            continue;
        }
        if !destination.starts_with("codebase:") {
            continue;
        }
        let Some(reservation) = journal.read("nonce_reservation") else {
            continue;
        };
        let Some(canonical) = crate::json::get_str(&reservation, "event_canonical") else {
            journal.write(
                "rolled_back",
                "rolled_back",
                json!({"reason": "no event bytes were bound"}),
            )?;
            journal.finish()?;
            replayed.push(json!({"candidate_id": candidate_id, "action": "rolled-back"}));
            continue;
        };
        let digest = sha256_text(canonical);
        let payload_digest = crate::json::get_str(&reservation, "payload_digest")
            .unwrap_or_default()
            .to_owned();
        let receipt_id = crate::json::get_str(&reservation, "receipt_id")
            .unwrap_or_default()
            .to_owned();
        // A replayed transaction completes with the principal's receipt copy
        // reconstructed from the bound reservation.
        let base_receipt = json!({
            "candidate_id": candidate_id,
            "destination": destination,
            "decision": "admit",
            "digest": payload_digest,
            "decided_at": now_rfc3339_millis(),
            "receipt_id": receipt_id,
            "state": "committed",
            "receipt_ids_equal": true,
                        "recovered": true
        });
        commit_codebase(
            launcher,
            repository,
            repository_uuid,
            &journal,
            &record,
            &payload_digest,
            &receipt_id,
            &base_receipt,
        )?;
        replayed
            .push(json!({"candidate_id": candidate_id, "digest": digest, "action": "completed"}));
    }
    if company_answering {
        deliver_apology_unknowns(launcher, repository_uuid)?;
    }
    Ok(replayed)
}

/// Send this repository's undelivered apology Unknowns to Company, where
/// the closing authority reads them; they were kept only in the admitting
/// principal's store, so no authority ever saw one before its deadline.
fn deliver_apology_unknowns(
    launcher: &crate::launcher::Launcher,
    repository_uuid: &str,
) -> Result<(), ContractError> {
    let destination = format!("codebase:{repository_uuid}");
    let undelivered: Vec<Value> = current_apologies()
        .into_iter()
        .filter(|apology| {
            crate::json::get_str(apology, "state") == Some("awaiting_reconcile_or_abandon")
                && crate::json::get_str(apology, "committed_destination")
                    == Some(destination.as_str())
                && apology.get("unknown_delivered") != Some(&Value::Bool(true))
        })
        .take(COMPANY_RETRIES_PER_PASS)
        .collect();
    if undelivered.is_empty() {
        return Ok(());
    }
    let Ok(Some(access)) = launcher.company() else {
        return Ok(());
    };
    let unknowns = personal_records("unknowns.jsonl");
    for apology in undelivered {
        let unknown_id = crate::json::get_str(&apology, "unknown_id").unwrap_or_default();
        let Some(document) = unknowns
            .iter()
            .find(|unknown| crate::json::get_str(unknown, "fact_id") == Some(unknown_id))
        else {
            continue;
        };
        match access.client.post_unknown(document) {
            Ok(_) => append_personal(
                "apologies.jsonl",
                &json!({
                    "apology_id": apology.get("apology_id").cloned().unwrap_or(Value::Null),
                    "unknown_delivered": true,
                    "delivered_at": now_rfc3339_millis()
                }),
            )?,
            Err(error) if error.code == "COMPANY_UNREACHABLE" => break,
            // Refused: it stays undelivered and is offered again next pass.
            Err(error) => crate::output::diagnostic(
                "apology-unknown-undelivered",
                json!({"unknown_id": unknown_id, "code": error.code, "message": error.message}),
            ),
        }
    }
    Ok(())
}

/// In-flight fan-out journal markers (for `status`/`fsck`): every marker of
/// a saga that has not reached `done`.
pub fn inflight_journal_state(repo_root: &Path) -> Value {
    let Ok(repository) = crate::codebase::Repository::discover(repo_root) else {
        return json!([]);
    };
    let root = repository.local_dir().join("journal").join("fanout");
    let mut markers = Vec::new();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return json!([]);
    };
    for entry in entries.filter_map(Result::ok) {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let done = std::fs::read(dir.join("done.json"))
            .ok()
            .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok())
            .is_some_and(|marker| crate::json::get_str(&marker, "journal_state") == Some("done"));
        if done {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<std::path::PathBuf> = files
            .filter_map(|file| file.ok().map(|file| file.path()))
            .collect();
        paths.sort();
        for path in paths {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.starts_with(".tmp-") || !name.ends_with(".json") {
                continue;
            }
            if let Some(marker) = std::fs::read(&path)
                .ok()
                .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok())
            {
                markers.push(json!({
                    "candidate_id": marker.get("candidate_id").cloned().unwrap_or(Value::Null),
                    "destination": marker.get("destination").cloned().unwrap_or(Value::Null),
                    "transition": marker.get("transition").cloned().unwrap_or(Value::Null),
                    "journal_state": marker.get("journal_state").cloned().unwrap_or(Value::Null),
                    "updated_at": marker.get("updated_at").cloned().unwrap_or(Value::Null)
                }));
            }
        }
    }
    json!(markers)
}

/// This repository's apologies still awaiting reconcile/abandon (the orphans
/// that are not yet terminally closed). The Personal store holds every
/// repository's.
pub fn pending_orphan_count(repo_root: &Path) -> usize {
    let Ok(repository_uuid) = crate::repository::repository_id(repo_root) else {
        return 0;
    };
    let destination = format!("codebase:{repository_uuid}");
    current_apologies()
        .iter()
        .filter(|apology| {
            crate::json::get_str(apology, "state") == Some("awaiting_reconcile_or_abandon")
                && crate::json::get_str(apology, "committed_destination")
                    == Some(destination.as_str())
        })
        .count()
}

/// Saga-authoritative fields for a terminal `orphan_abandoned` event that the
/// destination service emitted: the saga state and the unresponsive closing
/// authority. The fact's state is the reducer's, never the saga ledger's.
/// `None` for every other event.
pub fn saga_terminal_event_fields(event_id: &str) -> Option<Value> {
    personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .find(|record| crate::json::get_str(record, "event_id") == Some(event_id))
        .map(|record| {
            json!({
                "saga_state": "abandoned",
                "unresponsive_closing_authority": record.get("unresponsive_closing_authority").cloned().unwrap_or(Value::Null),
                "apology_id": record.get("apology_id").cloned().unwrap_or(Value::Null)
            })
        })
}

/// The store a classifier label names here, or `None` when this host has
/// nowhere to put it.
///
/// A label only becomes a candidate if its destination exists. Outside a
/// certified repository there is no Codebase to admit to, and with no
/// `[company]` in the user config there is no Company either: minting the
/// candidate anyway produced a failed admission at every single checkpoint
/// (`REPO_UNCERTIFIED`), which is noise, not a finding. The operator whose
/// own repositories are not company work runs a config without `[company]`,
/// and this is what makes that a real null route rather than a louder one.
/// A candidate already minted is still admitted and still fails loudly: this
/// governs creation only.
fn resolved_destination(
    label: &str,
    repository_id: Option<&str>,
    company_destination: Option<&str>,
) -> Option<String> {
    match label {
        "company" => company_destination.map(str::to_owned),
        "codebase" => repository_id.map(|uuid| format!("codebase:{uuid}")),
        other => Some(other.to_owned()),
    }
}

pub fn destination_store(destination: &str) -> Result<crate::StoreKind, ContractError> {
    if destination == "personal" {
        Ok(crate::StoreKind::Personal)
    } else if destination == "company"
        || destination == "company:root"
        || company_bound_to_id(destination).is_some()
    {
        Ok(crate::StoreKind::Company)
    } else if destination.starts_with("codebase:") && destination.len() > "codebase:".len() {
        Ok(crate::StoreKind::Codebase)
    } else {
        Err(ContractError::new(
            "CONFIG_INVARIANT",
            format!("unsupported destination: {destination}"),
            "Use company or codebase:<repository-id>.",
            false,
            ExitCode::Refused,
        ))
    }
}

pub fn write_fact_event(
    store: crate::StoreKind,
    repo: &Path,
    record: &Value,
) -> Result<(String, String), ContractError> {
    let event = build_destination_event(None, store, "", record)?;
    let fact_id = crate::json::get_str(&event, "fact_id")
        .unwrap_or_default()
        .to_owned();
    let event_id = crate::json::get_str(&event, "event_id")
        .unwrap_or_default()
        .to_owned();
    let parsed = FactEvent::from_value(&event).map_err(|error| {
        ContractError::integrity("DIGEST_MISMATCH", error, "Use the exact candidate bytes.")
    })?;
    let root = crate::store::ensure_store_root(store, repo)?;
    crate::store::write_content_addressed_event(&root, &parsed)?;
    Ok((fact_id, event_id))
}

/// Build and sign the destination event for an admitted candidate. The
/// admitting principal's local destination key signs it; the event carries
/// the candidate id as evidence and binds the certified repository identity
/// for Codebase.
fn build_destination_event(
    launcher: Option<&crate::launcher::Launcher>,
    store: crate::StoreKind,
    repository_uuid: &str,
    record: &Value,
) -> Result<Value, ContractError> {
    let repo = repo()?;
    let key = destination_signing_key(launcher, store, &repo)?;
    let company_authority = match (store, launcher) {
        (crate::StoreKind::Company, Some(launcher)) => {
            registered_authority_id(launcher, &key.public().to_hex())
        }
        _ => None,
    };
    signed_destination_event(
        store,
        repository_uuid,
        record,
        &key,
        company_authority,
        &now_rfc3339_millis(),
    )
}

/// The destination event for a candidate, signed by `key` at `now`.
/// `company_authority` is the registered identity of `key`, if any.
fn signed_destination_event(
    store: crate::StoreKind,
    repository_uuid: &str,
    record: &Value,
    key: &crate::crypto::PrivateKey,
    company_authority: Option<String>,
    now: &str,
) -> Result<Value, ContractError> {
    let canonical = record
        .get("canonical")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let map: Map<String, Value> = parse_strict_object(canonical.as_bytes()).map_err(|error| {
        ContractError::new(
            "DIGEST_MISMATCH",
            error,
            "Use the exact candidate bytes.",
            false,
            ExitCode::IntegrityFailure,
        )
    })?;
    let scope = map
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("repository");
    let statement = map
        .get("statement")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractError::new(
                "DIGEST_MISMATCH",
                "candidate lacks statement",
                "Create a valid candidate.",
                false,
                ExitCode::IntegrityFailure,
            )
        })?;
    let atom_kind = map
        .get("atom_kind")
        .and_then(Value::as_str)
        .unwrap_or("observation");
    let repository_id = (store == crate::StoreKind::Codebase && !repository_uuid.is_empty())
        .then(|| repository_uuid.to_owned());
    let signer = key.public().to_hex();
    let store_kind = store_name(store);
    // A Company-bound candidate is a proposal to the Company scope its
    // destination names, attributed to the principal whose key signs it:
    // the atom's own scope (`host-session`) is no Company authority scope,
    // and naming the steward while a maintainer key signed misattributed it.
    let (authority_id, authority_scope) = if store == crate::StoreKind::Company {
        let authority_id = company_authority.unwrap_or_else(|| {
            crate::json::get_str(record, "principal")
                .map(str::to_owned)
                .unwrap_or_else(principal_id)
        });
        (authority_id, "company:root".to_owned())
    } else {
        ("repository-maintainer".to_owned(), scope.to_owned())
    };
    // The canonical identities: one fact per statement in its scope, one
    // logical key per fact (a scope-wide key made every session statement a
    // competing head of one claim), and one event per signed assertion. The
    // event id used to be the payload digest alone, so the same statement in
    // a second session reused the id with different bytes and was refused.
    // The journal binds the bytes built here, so a retry reuses them.
    let fact_id = crate::model::fact_id(store_kind, scope, statement);
    let logical_key = crate::model::logical_key(store_kind, &authority_scope, &fact_id);
    let event_id = crate::model::event_id(
        &fact_id,
        &crate::model::semantic_digest(statement),
        now,
        &signer,
    );
    let event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id,
        store_kind: store_kind.to_owned(),
        authority_id,
        authority_scope,
        repository_id,
        fact_id,
        logical_key,
        atom_kind: atom_kind.to_owned(),
        scope: scope.to_owned(),
        statement: statement.to_owned(),
        evidence_refs: vec![
            record
                .get("candidate_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ],
        asserted_at: now.to_owned(),
        effective_from: now.to_owned(),
        effective_until: None,
        disposition: "current".to_owned(),
        distortion: Distortion {
            trigger: "dependent decision uses admitted evidence".to_owned(),
            loss_if_absent: 8_000,
            rationale:
                "extracted evidence requires authority resolution before it becomes direction"
                    .to_owned(),
        },
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: crate::model::Bp(
            record
                .get("confidence")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(10_000) as u16,
        ),
        unresolved_uncertainty: crate::json::get_str(record, "unresolved_uncertainty")
            .map(str::to_owned),
        signer: String::new(),
        signature: String::new(),
        raw: None,
        // A fact admitted from a candidate inherits the authorship the adapter
        // established. Hard-coding `unknown` here is what made git trailers, ticket
        // creators and Kindex `prov_who` all arrive at the store as anonymous, which
        // leaves the provenance ceiling nothing to clamp.
        standing: crate::json::get_str(record, "standing")
            .unwrap_or("present")
            .to_owned(),
        provenance: crate::json::get_str(record, "provenance")
            .unwrap_or("unknown")
            .to_owned(),
        governs_paths: record
            .get("governs_paths")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        anchors: record
            .get("anchors")
            .and_then(|value| serde_json::from_value(value.clone()).ok())
            .unwrap_or_default(),
    };
    key.sign_document("fact-event", &event.to_value())
}

/// The registered authority identity of a signing key, from the cached
/// Company registry, when exactly one active entry names it.
fn registered_authority_id(
    launcher: &crate::launcher::Launcher,
    public_key: &str,
) -> Option<String> {
    let snapshot = launcher
        .company_cache()
        .ok()
        .flatten()
        .and_then(|(cache, _)| cache.snapshot().ok().flatten())?;
    let ids: BTreeSet<String> = crate::json::get_array(&snapshot, "registry")?
        .iter()
        .filter(|entry| crate::json::get_str(entry, "public_key") == Some(public_key))
        .filter(|entry| crate::json::get_str(entry, "status").unwrap_or("active") == "active")
        .filter_map(|entry| crate::json::get_str(entry, "authority_id").map(str::to_owned))
        .collect();
    (ids.len() == 1).then(|| ids.into_iter().next().unwrap_or_default())
}

/// One signer per shared store. A repository trusts its configured maintainer
/// key once it holds a certificate and nothing else it has not registered, so
/// a session admission signed with a generated local key was structurally
/// perfect and entirely untrusted: the same defect bulk admission had, on the
/// other path. Shared stores sign as the maintainer whenever Company access is
/// configured; Personal, and a machine with no Company access, keep the local
/// key. The caller's launcher decides: loading another one here failed
/// whenever a lock was held (the descriptor attestation refuses the lock's
/// descriptors), and the failure silently fell back to the local key.
pub(crate) fn destination_signing_key(
    launcher: Option<&crate::launcher::Launcher>,
    store: crate::StoreKind,
    repo: &Path,
) -> Result<crate::crypto::PrivateKey, ContractError> {
    if store != crate::StoreKind::Personal {
        if let Some(access) = launcher.and_then(|launcher| launcher.shared.company.as_ref()) {
            return access.maintainer_key();
        }
    }
    let (private_path, _) = crate::crypto::ensure_keypair(store, repo)?;
    crate::crypto::PrivateKey::load_or_generate(&private_path, "local destination key")
}

/// Close overdue apology Unknowns with exactly one signed `orphan_abandoned`
/// terminal event each, emitted by the committed destination. The orphaned
/// claim stays withdrawn; the saga is closed, never left pending forever.
pub(crate) fn emit_due_orphan_abandonments(
    launcher: &crate::launcher::Launcher,
    repository_root: &Path,
    clock: &crate::time::AsOf,
) -> Result<usize, ContractError> {
    let existing: BTreeSet<String> = personal_records_complete("orphan-abandonments.jsonl")?
        .into_iter()
        .filter_map(|record| crate::json::get_str(&record, "apology_id").map(str::to_owned))
        .collect();
    // An abandonment found here is trusted to be on disk; make it so.
    sync_personal("orphan-abandonments.jsonl")?;
    // The Personal store holds every repository's apologies; this repository
    // closes only those its own Codebase committed, and an uncertified
    // repository closes none (it has no destination to write to).
    let Ok(repository_uuid) = crate::repository::repository_id(repository_root) else {
        return Ok(existing.len());
    };
    let this_destination = format!("codebase:{repository_uuid}");
    // The caller's clock: the proof clock, so a pinned acceptance run closes
    // exactly what it expects and a report can say which clock it read.
    let now = parse_rfc3339_millis(&clock.as_of).map_err(ContractError::internal)?;
    let due: Vec<Value> = current_apologies_complete()?
        .into_iter()
        .filter(|apology| {
            crate::json::get_str(apology, "state") == Some("awaiting_reconcile_or_abandon")
        })
        .filter(|apology| {
            crate::json::get_str(apology, "committed_destination")
                == Some(this_destination.as_str())
        })
        .filter(|apology| {
            crate::json::get_str(apology, "response_due_at")
                .and_then(|value| parse_rfc3339_millis(value).ok())
                .is_some_and(|due| due <= now)
        })
        .filter(|apology| {
            crate::json::get_str(apology, "apology_id").is_some_and(|id| !existing.contains(id))
        })
        .collect();
    if due.is_empty() {
        return Ok(existing.len());
    }
    // Written through the discovered repository root: `status` may run in a
    // subdirectory, where `<cwd>/.kin` is a stray tree nothing reads.
    let repository = crate::codebase::Repository::discover(repository_root)?;
    repository.ensure_local()?;
    let _lock = repository.admission_lock(&repository_uuid)?;
    let now_text = format_rfc3339_millis(now);
    for apology in due {
        let apology_id = crate::json::get_str(&apology, "apology_id")
            .unwrap_or_default()
            .to_owned();
        let committed_destination = this_destination.clone();
        let store = crate::StoreKind::Codebase;
        let closing_authority = crate::json::get_str(&apology, "closing_authority")
            .or_else(|| crate::json::get_str(&apology, "closing_authority_role"))
            .unwrap_or("repository-maintainer")
            .to_owned();
        let closing_role = crate::json::get_str(&apology, "closing_authority_role")
            .unwrap_or("repository-maintainer")
            .to_owned();
        let due_at = crate::json::get_str(&apology, "response_due_at")
            .unwrap_or_default()
            .to_owned();
        let orphaned_event_id = crate::json::get_str(&apology, "orphaned_event_id")
            .unwrap_or_default()
            .to_owned();
        let logical_key = crate::json::get_str(&apology, "orphaned_logical_key")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("logical_{:x}", Sha256::digest(apology_id.as_bytes())));
        let fact_id = crate::json::get_str(&apology, "orphaned_fact_id")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("fact_{:x}", Sha256::digest(apology_id.as_bytes())));
        let event_id = format!(
            "event_{:x}",
            Sha256::digest(format!("orphan_abandoned\0{apology_id}").as_bytes())
        );
        let statement = format!(
            "orphan_abandoned: closing authority {closing_authority} ({closing_role}) did not reconcile or abandon apology {apology_id} by {due_at}; the orphaned claim stays withdrawn and the saga is closed"
        );
        let mut document = json!({
            "schema": crate::model::EVENT_SCHEMA,
            "event_id": event_id,
            "store_kind": store_name(store),
            "authority_id": closing_role,
            "authority_scope": "architecture:escalation",
            "fact_id": fact_id,
            "logical_key": logical_key,
            "atom_kind": "observation",
            "scope": "architecture:escalation",
            "statement": statement,
            "evidence_refs": [apology_id.clone(), crate::json::get_str(&apology, "unknown_id").unwrap_or_default()],
            "asserted_at": now_text,
            "effective_from": now_text,
            "disposition": "orphan_abandoned",
            "distortion": {
                "trigger": "closing authority response_due_at passed",
                "loss_if_absent": 8000,
                "rationale": "an unanswered apology must be closed exactly once and the fact withheld"
            },
            "parents": if orphaned_event_id.is_empty() { json!([]) } else { json!([orphaned_event_id]) },
            "supersedes": [],
            "redundancy_with": [],
            "complements": [],
            "company_refs": [],
            "authority_snapshot_cursor": "0",
            "confidence": 8000,
            "unresolved_uncertainty": "orphan abandoned without closing-authority action",
            "unresponsive_closing_authority": closing_authority,
            "apology_id": apology_id,
            "response_due_at": due_at,
            "fact_state": "withdrawn"
        });
        document["repository_id"] = Value::String(repository_uuid.clone());
        let key = destination_signing_key(Some(launcher), store, &repository.root)?;
        let signed = key.sign_document("fact-event", &document)?;
        let parsed = FactEvent::from_value(&signed).map_err(|error| {
            ContractError::integrity(
                "DIGEST_MISMATCH",
                error,
                "Preserve the saga record; the terminal event is malformed.",
            )
        })?;
        let root = crate::store::ensure_store_root(store, &repository.root)?;
        let (_, digest) = crate::store::write_content_addressed_event(&root, &parsed)?;
        repository.update_index_cache()?;
        append_personal_durable(
            "orphan-abandonments.jsonl",
            &json!({
                "orphan_id": format!("orphan_{}", &crate::hash::sha256_text(&apology_id)[..40]),
                "apology_id": apology_id,
                "event_id": crate::json::get_str(&signed, "event_id").unwrap_or_default(),
                "event_digest": digest,
                "destination": committed_destination,
                "unresponsive_closing_authority": closing_authority,
                "closing_authority_role": closing_role,
                "orphaned_event_id": orphaned_event_id,
                "fact_state": "withdrawn",
                "orphaned_fact_withheld": true,
                "emitted_at": now_text
            }),
        )?;
        append_personal(
            "apologies.jsonl",
            &json!({"apology_id": apology_id, "state": "abandoned", "abandoned_at": now_text, "orphan_abandoned_event_id": crate::json::get_str(&signed, "event_id").unwrap_or_default()}),
        )?;
        if let Ok(Some((cache, _))) = launcher.company_cache() {
            let mut closed = apology.clone();
            closed["state"] = Value::String("abandoned".to_owned());
            let _ = cache.save_saga(
                crate::json::get_str(&apology, "candidate_id").unwrap_or_default(),
                &closed,
                &now_text,
            );
        }
    }
    Ok(personal_records("orphan-abandonments.jsonl")
        .into_iter()
        .filter_map(|record| crate::json::get_str(&record, "apology_id").map(str::to_owned))
        .collect::<BTreeSet<_>>()
        .len())
}

fn principal_id() -> String {
    std::env::var("KINBASE_PRINCIPAL").unwrap_or_else(|_| "local-user".to_owned())
}

fn receipt_id(candidate: &str, destination: &str, digest: &str) -> String {
    format!(
        "receipt_{:x}",
        Sha256::digest(format!("{candidate}\0{destination}\0{digest}").as_bytes())
    )
}

fn store_name(store: crate::StoreKind) -> &'static str {
    crate::ingest::store_name(store)
}

fn decision_state(decision: &Value) -> &'static str {
    match crate::json::get_str(decision, "state").unwrap_or("committed") {
        "committed" => "committed",
        "pending" => "pending",
        "abandoned" => "abandoned",
        _ => "refused",
    }
}

fn repo() -> Result<std::path::PathBuf, ContractError> {
    std::env::current_dir().map_err(io_error)
}

/// Admit exact candidate bytes without consuming human attention. Destination
/// signatures, content addresses, durable receipts and replay remain mandatory.
/// A Company candidate is delivered only where it was minted. Under the
/// named form a checkpoint runs in whatever repository the host stops in, and
/// the candidates it collects belong to the whole session; delivering by the
/// checkpoint's repository would send one organization's knowledge to
/// another's Company. A candidate that does not match is held for a
/// checkpoint in its own repository, never failed and never delivered.
fn company_binding_holds(
    launcher: &crate::launcher::Launcher,
    repo: &Path,
    destination: &str,
    record: &Value,
) -> Result<(), ContractError> {
    let held = |why: &str| {
        Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!("candidate held: {why}"),
            "It is delivered by a checkpoint in the repository it came from.",
        ))
    };
    match (launcher.named_form(), company_bound_to_id(destination)) {
        (false, None) => Ok(()),
        (false, Some(_)) => {
            held("it is bound to one of several Companies and this configuration names one")
        }
        (true, None) => held("it names no Company and several are configured"),
        (true, Some(bound)) => {
            if launcher.company_key_scope().as_deref() != Some(bound) {
                return held("it is bound to a Company other than the one selected here");
            }
            let here = crate::repository::repository_id(repo).ok();
            if here.is_none() || crate::json::get_str(record, "repository_uuid") != here.as_deref()
            {
                return held("it came from another repository");
            }
            Ok(())
        }
    }
}

fn admit_candidate(
    launcher: &crate::launcher::Launcher,
    repo: &Path,
    record: &Value,
) -> Result<Value, ContractError> {
    let candidate = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    let digest = candidate_digest(record)?;
    // Reads only this candidate's receipts rather than the whole decision
    // ledger. A checkpoint, which admits many candidates at once, reads the
    // ledger once for all of them instead (`latest_receipts`).
    let receipts =
        personal_records_complete_marked("proposal-decisions.jsonl", &value_marker(candidate))?;
    if let Some(key) = candidate_key(record, &digest)
        && let Some(previous) = receipts
            .into_iter()
            .rev()
            .find(|receipt| receipt_key(receipt).as_ref() == Some(&key))
        && receipt_settled(&previous)
    {
        // Acting on a found receipt: make sure it is on disk first.
        crate::store::sync_record(crate::StoreKind::Personal, repo, "proposal-decisions.jsonl")?;
        return Ok(previous);
    }
    admit_unsettled(launcher, repo, record, &digest)
}

/// The content address of a candidate's bytes, refused when it differs from
/// the one the candidate carries.
fn candidate_digest(record: &Value) -> Result<String, ContractError> {
    let canonical = crate::json::get_str(record, "canonical").unwrap_or_default();
    let digest = sha256_text(canonical);
    if crate::json::get_str(record, "payload_digest") != Some(digest.as_str()) {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "candidate content address differs from its bytes",
            "Preserve the candidate and inspect its source.",
        ));
    }
    Ok(digest)
}

/// What a checkpoint got for one candidate. A settled receipt is returned to
/// the host but only counted in the recorded checkpoint, so the two cases
/// have to stay apart until the record is written.
enum Admission {
    /// A receipt an earlier admission of the same bytes settled.
    Settled(Value),
    /// The receipt this checkpoint's admission produced.
    Decided(Value),
}

/// What a receipt decides: one candidate's exact bytes for one destination.
type ReceiptKey = (String, String, String);

fn candidate_key(record: &Value, digest: &str) -> Option<ReceiptKey> {
    Some((
        crate::json::get_str(record, "candidate_id")?.to_owned(),
        crate::json::get_str(record, "destination")?.to_owned(),
        digest.to_owned(),
    ))
}

fn receipt_key(receipt: &Value) -> Option<ReceiptKey> {
    Some((
        crate::json::get_str(receipt, "candidate_id")?.to_owned(),
        crate::json::get_str(receipt, "destination")?.to_owned(),
        crate::json::get_str(receipt, "digest")?.to_owned(),
    ))
}

/// A receipt that ends its candidate's admission: admitting the same bytes
/// again would only return it.
fn receipt_settled(receipt: &Value) -> bool {
    matches!(decision_state(receipt), "committed" | "refused")
}

/// The last receipt for each of `candidates`, from one streamed read of the
/// decision ledger. Looking each candidate's receipts up on its own read the
/// whole ledger once per candidate: a Stop in a session with 2,774
/// candidates read 6 MB 2,774 times and took 28 s.
fn latest_receipts(
    candidates: &BTreeSet<&str>,
) -> Result<std::collections::HashMap<ReceiptKey, Value>, ContractError> {
    let mut latest = std::collections::HashMap::new();
    if candidates.is_empty() {
        return Ok(latest);
    }
    // Lines are kept by the value, as the reader asks: each JSON string on
    // the line, spelled as the canonical writer spells it, is looked up in
    // the set, rather than every id searched for in every line. The exact
    // filter on the parsed receipt below still decides.
    let markers: std::collections::HashSet<String> =
        candidates.iter().map(|id| value_marker(id)).collect();
    let repo = std::env::current_dir().map_err(io_error)?;
    let receipts = crate::store::read_records_complete_where(
        crate::StoreKind::Personal,
        &repo,
        "proposal-decisions.jsonl",
        |line| line_holds_marker(line, &markers),
    )?;
    for receipt in receipts {
        if let Some(key) = receipt_key(&receipt)
            && candidates.contains(key.0.as_str())
        {
            latest.insert(key, receipt);
        }
    }
    Ok(latest)
}

/// Whether any JSON string on `line`, quotes included and spelled as the
/// canonical writer spells it, is one of `markers`. A string is closed by the
/// first quote no backslash escapes, so an escaped quote inside an id does not
/// end it early. An unterminated string matches nothing.
fn line_holds_marker(line: &[u8], markers: &std::collections::HashSet<String>) -> bool {
    let mut start = 0;
    while let Some(open) = line[start..].iter().position(|&byte| byte == b'"') {
        let open = start + open;
        let mut close = open + 1;
        while close < line.len() && line[close] != b'"' {
            close += if line[close] == b'\\' { 2 } else { 1 };
        }
        let Some(text) = line.get(open..=close) else {
            return false;
        };
        if std::str::from_utf8(text).is_ok_and(|text| markers.contains(text)) {
            return true;
        }
        start = close + 1;
    }
    false
}

/// Admit a candidate that has no settled receipt for its exact bytes.
fn admit_unsettled(
    launcher: &crate::launcher::Launcher,
    repo: &Path,
    record: &Value,
    digest: &str,
) -> Result<Value, ContractError> {
    let candidate = crate::json::get_str(record, "candidate_id").unwrap_or_default();
    let destination = crate::json::get_str(record, "destination").unwrap_or_default();
    // Checked here, past any settled receipt: a settled candidate delivers
    // nothing, and every path that can deliver one comes through here.
    if destination.starts_with("company") {
        company_binding_holds(launcher, repo, destination, record)?;
    }
    let receipt_id = receipt_id(candidate, destination, digest);
    let receipt = json!({
        "candidate_id": candidate,
        "destination": destination,
        "decision": "admit",
        "digest": digest,
        "decided_at": now_rfc3339_millis(),
        "receipt_id": receipt_id,
        "state": "pending"
    });
    match destination_store(destination)? {
        crate::StoreKind::Personal => {
            let (fact_id, event_id) = write_fact_event(crate::StoreKind::Personal, repo, record)?;
            finalize_principal_receipt(
                &receipt,
                &json!({"fact_id": fact_id, "event_id": event_id, "state": "committed"}),
            )
        }
        _ => {
            let saga = fanout_saga_result(
                launcher,
                repo,
                record,
                destination,
                digest,
                &receipt_id,
                &receipt,
            )?;
            let mut receipt = receipt;
            merge_receipt(&mut receipt, &saga);
            Ok(receipt)
        }
    }
}

/// Route unresolved evidence to one durable question per scope and decision.
/// Repeated sessions reuse the question instead of asking for each byte.
fn question_for_unresolved_atom(
    repo: &Path,
    atom: &Value,
) -> Result<Option<String>, ContractError> {
    if atom.get("hard_blocked").and_then(Value::as_bool) == Some(true) {
        return Ok(None);
    }
    let scope = crate::json::get_str(atom, "scope").unwrap_or("repository");
    let uncertainty =
        crate::json::get_str(atom, "unresolved_uncertainty").filter(|text| !text.trim().is_empty());
    let shared = atom
        .get("eligible_destinations")
        .and_then(Value::as_array)
        .is_some_and(|destinations| {
            destinations
                .iter()
                .filter_map(Value::as_str)
                .any(|destination| {
                    destination.starts_with("company") || destination.starts_with("codebase:")
                })
        });
    if uncertainty.is_none() && !shared {
        return Ok(None);
    }
    let authority = crate::questions::active_authority_with_repo(
        repo,
        scope,
        crate::questions::scope_kind(scope),
    );
    let owner = match authority {
        Ok(authority) => {
            if uncertainty.is_none() {
                return Ok(None);
            }
            crate::json::get_str(&authority, "authority_id")
                .unwrap_or_default()
                .to_owned()
        }
        Err(error) if error.code == "UNKNOWN_OWNER_UNRESOLVED" => String::new(),
        Err(error) => return Err(error),
    };
    let decision = format!("Resolve direction for {scope}");
    let question = if uncertainty.is_some() {
        format!(
            "Which evidence governs {scope}, and how should the unresolved interpretations be reconciled?"
        )
    } else {
        format!("Who has authority to rule on direction in {scope}?")
    };
    let evidence = vec![
        crate::json::get_str(atom, "atom_id")
            .unwrap_or_default()
            .to_owned(),
    ];
    let unknown = crate::projector::UnknownOut {
        unknown_id: format!("unknown_{}", sha256_text(&format!("{scope}\0{question}"))),
        logical_key: crate::model::logical_key("company", scope, &decision),
        scope: scope.to_owned(),
        decision_blocked: decision.clone(),
        owner_role: if scope.starts_with("architecture:") {
            "chief-architect"
        } else {
            "company-steward"
        }
        .to_owned(),
        owner_identity: owner,
        question,
        evidence: evidence.clone(),
        loss_if_absent: 6_000,
        status: "open".to_owned(),
        kind: "unresolved-evidence".to_owned(),
    };
    let alternatives: Vec<String> = uncertainty.into_iter().map(str::to_owned).collect();
    crate::questions::ensure_question(repo, &unknown, &decision, &evidence, &alternatives)
}

#[cfg(test)]
mod line_holds_marker_tests {
    use super::{line_holds_marker, value_marker};
    use std::collections::HashSet;

    fn markers(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|id| value_marker(id)).collect()
    }

    #[test]
    fn a_line_holding_a_marked_id_as_a_value_is_kept() {
        let line = br#"{"candidate_id":"cand_a","digest":"abc"}"#;
        assert!(line_holds_marker(line, &markers(&["cand_a"])));
        assert!(!line_holds_marker(line, &markers(&["cand_b"])));
    }

    #[test]
    fn an_id_that_is_only_part_of_a_string_is_not_kept() {
        let line = br#"{"candidate_id":"cand_ab","note":"xcand_a"}"#;
        assert!(!line_holds_marker(line, &markers(&["cand_a"])));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        // Were `\"` to close the string, `cand_a` would be read as a string
        // of its own and the line kept for the wrong candidate.
        let line = br#"{"note":"say \"cand_a\" twice","candidate_id":"cand_b"}"#;
        assert!(!line_holds_marker(line, &markers(&["cand_a"])));
        assert!(line_holds_marker(line, &markers(&["cand_b"])));
        let escaped = value_marker("cand\"q");
        let line = format!(r#"{{"candidate_id":{escaped}}}"#);
        assert!(line_holds_marker(line.as_bytes(), &markers(&["cand\"q"])));
    }

    #[test]
    fn a_torn_line_matches_nothing_and_does_not_panic() {
        for line in [
            &br#"{"candidate_id":"cand_a"#[..],
            &br#"{"candidate_id":"cand_a\"#[..],
            &br#"""#[..],
            &b""[..],
        ] {
            assert!(!line_holds_marker(line, &markers(&["cand_a"])));
        }
    }
}

#[cfg(test)]
mod processor_scope_tests {
    use super::select_provider;
    use crate::config::SharedClassifier;

    fn classifier(model: &str, processor_scope: &str) -> SharedClassifier {
        SharedClassifier {
            model: model.to_owned(),
            executable: "/nonexistent/classifier".into(),
            executable_sha256: "0".repeat(64),
            args: Vec::new(),
            timeout_seconds: 5,
            processor_scope: processor_scope.to_owned(),
        }
    }

    #[test]
    fn an_unauthorized_processor_falls_back_before_any_request() {
        for scope in ["local", "ollama-cloud"] {
            let selected = select_provider(Some(&classifier("agy:default", scope)));
            assert_eq!(selected.live_model, None);
            assert_eq!(selected.name(), "deterministic");
            assert_eq!(selected.processor, "local");
            assert_eq!(selected.processor_scope, scope);
            assert_eq!(selected.fallback_from.as_deref(), Some("agy:default"));
            let reason = selected.fallback_reason.unwrap_or_default();
            assert!(reason.starts_with("PROCESSOR_UNAUTHORIZED"), "{reason}");
        }
    }
}

#[cfg(test)]
mod saga_identity_tests {
    use super::*;
    use crate::crypto::{PrivateKey, PublicKey};

    fn record(scope: &str, statement: &str) -> Value {
        let canonical = crate::json::canonical_text(&json!({
            "destination": "codebase:repo-uuid",
            "atom_kind": "constraint",
            "scope": scope,
            "statement": statement
        }));
        json!({
            "candidate_id": "cand_1",
            "destination": "codebase:repo-uuid",
            "principal": "principal-a",
            "payload_digest": sha256_text(&canonical),
            "canonical": canonical,
            "confidence": 8000
        })
    }

    fn event(
        store: crate::StoreKind,
        record: &Value,
        key: &PrivateKey,
        authority: Option<&str>,
        now: &str,
    ) -> FactEvent {
        let signed = signed_destination_event(
            store,
            "repo-uuid",
            record,
            key,
            authority.map(str::to_owned),
            now,
        )
        .expect("event");
        let parsed = FactEvent::from_value(&signed).expect("parse");
        assert!(parsed.verify_signature().is_some(), "the event verifies");
        parsed
    }

    #[test]
    fn a_statement_asserted_twice_gets_two_events_of_one_fact() {
        let key = PrivateKey::generate();
        let statement = "Backoff is capped at 30 seconds.";
        let first = event(
            crate::StoreKind::Codebase,
            &record("host-session", statement),
            &key,
            None,
            "2026-09-17T10:00:00.000Z",
        );
        let second = event(
            crate::StoreKind::Codebase,
            &record("host-session", statement),
            &key,
            None,
            "2026-09-17T11:00:00.000Z",
        );
        assert_ne!(first.event_id, second.event_id);
        assert_eq!(first.fact_id, second.fact_id);
        assert_eq!(
            first.fact_id,
            crate::model::fact_id("codebase", "host-session", statement)
        );
        assert_eq!(
            first.logical_key,
            crate::model::logical_key("codebase", "host-session", &first.fact_id)
        );
        assert_eq!(first.repository_id.as_deref(), Some("repo-uuid"));

        let other = event(
            crate::StoreKind::Codebase,
            &record("host-session", "Retries use jitter."),
            &key,
            None,
            "2026-09-17T10:00:00.000Z",
        );
        assert_ne!(
            other.logical_key, first.logical_key,
            "one logical key per statement, not per scope"
        );
    }

    #[test]
    fn a_company_proposal_names_its_company_scope_and_its_signer() {
        let key = PrivateKey::generate();
        let proposal = record("host-session", "Refunds settle in two days.");
        let registered = event(
            crate::StoreKind::Company,
            &proposal,
            &key,
            Some("payments-architect"),
            "2026-09-17T10:00:00.000Z",
        );
        assert_eq!(registered.authority_scope, "company:root");
        assert_eq!(registered.authority_id, "payments-architect");
        assert_eq!(registered.scope, "host-session");
        assert_eq!(registered.repository_id, None);
        let unregistered = event(
            crate::StoreKind::Company,
            &proposal,
            &key,
            None,
            "2026-09-17T10:00:00.000Z",
        );
        assert_eq!(unregistered.authority_id, "principal-a");

        let envelope = approval_envelope(
            &key,
            &proposal,
            &registered.to_value(),
            "2026-09-17T10:00:01.000Z",
        )
        .expect("envelope");
        assert_eq!(envelope["event"], registered.to_value());
        let token = &envelope["approval_token"];
        assert_eq!(
            PublicKey::verify_document("approval-token", token).map(|key| key.to_hex()),
            Some(key.public().to_hex())
        );
        assert_eq!(
            token["event_digest"],
            json!(crate::json::digest(&registered.to_value()))
        );
        assert_eq!(token["candidate_id"], "cand_1");
    }
}
