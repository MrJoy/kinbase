//! P-6: the authority question loop as an executed behavior.

use crate::error::{ContractError, ExitCode};
use crate::json::{canonical_bytes, canonical_text, parse_strict_object};
use crate::model::{CompanyReference, Distortion, FactEvent, UnknownEvent};
use crate::scanner::hard_blocked;
use crate::time::{format_rfc3339_millis, now_rfc3339_millis, plus_seconds};
use chrono::{Duration, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

pub fn dispatch(
    command: crate::command_types::QuestionCommand,
    json: bool,
) -> Result<(), ContractError> {
    match command {
        crate::command_types::QuestionCommand::List { owner } => list(owner.as_deref(), json),
        crate::command_types::QuestionCommand::Ask { question_id } => ask(&question_id, json),
        crate::command_types::QuestionCommand::Answer {
            question_id,
            answer_file,
            key_file,
        } => answer(&question_id, &answer_file, &key_file, json),
        crate::command_types::QuestionCommand::Status { question_id } => status(&question_id, json),
    }
}

fn repo() -> Result<PathBuf, ContractError> {
    std::env::current_dir().map_err(io_error)
}

fn company_records_with_repo(repo: &Path, name: &str) -> Vec<Value> {
    crate::store::read_records(crate::StoreKind::Company, repo, name).unwrap_or_default()
}

fn append_company(repo: &Path, name: &str, value: &Value) -> Result<(), ContractError> {
    crate::store::append_record(crate::StoreKind::Company, repo, name, value)
}

fn list(owner: Option<&str>, json: bool) -> Result<(), ContractError> {
    let questions = latest_questions(&repo().unwrap_or_else(|_| PathBuf::from(".")))
        .into_values()
        .filter(|record| {
            owner
                .map(|owner| record.get("authority_id").and_then(Value::as_str) == Some(owner))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();
    let result = json!({"questions": questions});
    print_value(&result, json);
    Ok(())
}

fn latest_questions(repo: &Path) -> BTreeMap<String, Value> {
    let mut latest: BTreeMap<String, Value> = BTreeMap::new();
    for record in company_records_with_repo(repo, "questions.jsonl") {
        if let Some(question_id) = record.get("question_id").and_then(Value::as_str) {
            latest.insert(question_id.to_owned(), record);
        }
    }
    latest
}

fn find_question(question_id: &str) -> Result<Value, ContractError> {
    latest_questions(&repo()?)
        .into_values()
        .find(|record| {
            record.get("question_id").and_then(Value::as_str) == Some(question_id)
                || record.get("unknown_id").and_then(Value::as_str) == Some(question_id)
        })
        .ok_or_else(|| {
            ContractError::new(
                "CONFIG_INVARIANT",
                "question not found",
                "Use a question ID returned by questions list.",
                false,
                ExitCode::Refused,
            )
        })
}

fn find_unknown_in(repo: &Path, question_id: &str) -> Result<Value, ContractError> {
    for store in [crate::StoreKind::Company, crate::StoreKind::Codebase] {
        if let Ok(records) = crate::store::read_records(store, repo, "unknowns.jsonl") {
            if let Some(record) = records.into_iter().rev().find(|record| {
                ["unknown_id", "fact_id", "event_id"]
                    .iter()
                    .any(|field| record.get(*field).and_then(Value::as_str) == Some(question_id))
            }) {
                return Ok(record);
            }
        }
    }
    Err(ContractError::new(
        "CONFIG_INVARIANT",
        "Unknown not found",
        "Create the Unknown from a blocked decision before asking authority.",
        false,
        ExitCode::Refused,
    ))
}

pub(crate) fn scope_kind(scope: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "architecture"
    } else if scope.starts_with("environment:") {
        "environment"
    } else {
        "general"
    }
}

fn registry_entries(repo: &Path) -> Vec<Value> {
    let mut entries = company_records_with_repo(repo, "authority-registry.jsonl");
    if let Ok(launcher) = crate::launcher::Launcher::load() {
        if let Ok(Some((cache, _root))) = launcher.company_cache() {
            if let Ok(Some(snapshot)) = cache.snapshot() {
                if let Some(registry) = crate::json::get_array(&snapshot, "registry") {
                    entries.extend(registry.iter().cloned());
                }
            }
        }
    }
    let mut unique: BTreeSet<String> = BTreeSet::new();
    entries.retain(|entry| unique.insert(crate::json::canonical_text(entry)));
    entries
}

fn authority_entry_matches(
    entry: &Value,
    scope: &str,
    question_kind: &str,
    exact_scope: bool,
) -> bool {
    if entry
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("active")
        != "active"
    {
        return false;
    }
    let entry_scope = entry
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope_matches = if exact_scope {
        entry_scope == scope
    } else {
        question_kind == "architecture" && entry_scope.starts_with("architecture:")
    };
    if !scope_matches {
        return false;
    }
    let kind_matches = entry.get("question_kind").and_then(Value::as_str) == Some(question_kind);
    let capability_matches = entry
        .get("capabilities")
        .and_then(Value::as_array)
        .is_some_and(|capabilities| {
            capabilities.iter().any(|capability| {
                capability.as_str() == Some(question_kind) || capability.as_str() == Some("answer")
            })
        });
    kind_matches || capability_matches
}

fn active_authority_entries(
    repo: &Path,
    scope: &str,
    question_kind: &str,
) -> Result<Vec<Value>, ContractError> {
    let exact = registry_entries(repo)
        .into_iter()
        .filter(|entry| authority_entry_matches(entry, scope, question_kind, true))
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return Ok(exact);
    }
    // An architecture Unknown can name a narrower leaf scope than the
    // registry. Resolve it only when the active architecture authority is
    // unique; overlapping architects deliberately remain unresolved.
    if question_kind == "architecture" {
        return Ok(registry_entries(repo)
            .into_iter()
            .filter(|entry| authority_entry_matches(entry, scope, question_kind, false))
            .collect());
    }
    Ok(Vec::new())
}

pub(crate) fn active_authority_with_repo(
    repo: &Path,
    scope: &str,
    question_kind: &str,
) -> Result<Value, ContractError> {
    let entries = active_authority_entries(repo, scope, question_kind)?;
    let mut distinct_owners = BTreeSet::new();
    for entry in &entries {
        distinct_owners.insert((
            entry
                .get("authority_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            entry
                .get("public_key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        ));
    }
    if distinct_owners.len() > 1 {
        return Err(ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "multiple active authorities overlap the requested scope",
            "The Company steward must repair the registry before guidance is trusted.",
            true,
            ExitCode::DegradedSafe,
        ));
    }
    // A registry may register one signer under several delivery channels. The
    // interactive HTTP channel is preferred when present; otherwise channel
    // order is deterministic.
    let entry = entries
        .into_iter()
        .min_by(|left, right| {
            let left_http = left
                .get("channel")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .starts_with("http://");
            let right_http = right
                .get("channel")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .starts_with("http://");
            right_http
                .cmp(&left_http)
                .then_with(|| {
                    left.get("channel")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .cmp(
                            right
                                .get("channel")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        )
                })
                .then_with(|| {
                    left.get("authority_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .cmp(
                            right
                                .get("authority_id")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        )
                })
        })
        .ok_or_else(|| {
            ContractError::new(
                "UNKNOWN_OWNER_UNRESOLVED",
                if question_kind == "architecture" {
                    "no active architecture authority is registered"
                } else {
                    "no exact in-scope authority is registered"
                },
                "The Company steward must repair the registry before guidance is trusted.",
                true,
                ExitCode::DegradedSafe,
            )
        })?;
    if entry
        .get("public_key")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "authority public key missing",
            "Publish a 64-hex Ed25519 public key in the registry entry.",
            false,
            ExitCode::Refused,
        ));
    }
    Ok(entry)
}

/// Resolve the registered authority an Unknown names as its owner.
///
/// The Unknown carries the stable owner identity (architecture §7: the
/// registry maps to a named principal, public key and channel). The registry
/// must confirm that identity as an active answering authority with exactly
/// one key; a second key for the same identity is a registry conflict owned
/// by the Company steward and resolves nothing. When the Unknown names no
/// registered owner, the exact scope resolves it instead.
fn resolve_owner_authority(
    repo: &Path,
    unknown: &crate::projector::UnknownOut,
) -> Result<Value, ContractError> {
    let by_identity: Vec<Value> = registry_entries(repo)
        .into_iter()
        .filter(|entry| {
            entry
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("active")
                == "active"
                && entry.get("authority_id").and_then(Value::as_str)
                    == Some(unknown.owner_identity.as_str())
                && entry
                    .get("capabilities")
                    .and_then(Value::as_array)
                    .is_some_and(|capabilities| {
                        capabilities
                            .iter()
                            .any(|capability| capability.as_str() == Some("answer"))
                    })
        })
        .collect();
    if by_identity.is_empty() {
        let question_kind = scope_kind(&unknown.scope);
        return active_authority_with_repo(repo, &unknown.scope, question_kind);
    }
    let keys: BTreeSet<&str> = by_identity
        .iter()
        .filter_map(|entry| entry.get("public_key").and_then(Value::as_str))
        .collect();
    if keys.len() != 1 || keys.iter().any(|key| key.is_empty()) {
        return Err(ContractError::new(
            "UNKNOWN_OWNER_UNRESOLVED",
            "the registry publishes more than one key for the Unknown's owner",
            "The Company steward must repair the registry before guidance is trusted.",
            true,
            ExitCode::DegradedSafe,
        ));
    }
    let scope = by_identity
        .first()
        .and_then(|entry| entry.get("scope").and_then(Value::as_str))
        .unwrap_or(unknown.scope.as_str())
        .to_owned();
    active_authority_with_repo(repo, &scope, scope_kind(&scope))
}

pub(crate) fn ensure_question(
    repo: &Path,
    unknown: &crate::projector::UnknownOut,
    decision: &str,
    evidence_examined: &[String],
    remaining_alternatives: &[String],
) -> Result<Option<String>, ContractError> {
    let authority = match resolve_owner_authority(repo, unknown) {
        Ok(authority) => authority,
        Err(error) if error.code == "UNKNOWN_OWNER_UNRESOLVED" => Value::Null,
        Err(error) => return Err(error),
    };
    let authority_scope = authority
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or(unknown.scope.as_str())
        .to_owned();
    let question_kind = scope_kind(&authority_scope).to_owned();
    let authority_id = authority
        .get("authority_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let question_id = format!(
        "question_{}",
        &crate::hash::sha256_text(&format!(
            "{}\0{}\0{}",
            unknown.unknown_id, decision, unknown.question
        ))[..40]
    );
    let existing = latest_questions(repo).get(&question_id).cloned();
    if let Some(existing) = &existing {
        // A registry repair may supply the missing owner. Preserve answered
        // questions and delivery state; only unresolved ownership is retried.
        if existing.get("status").and_then(Value::as_str) != Some("awaiting_authority")
            || authority.is_null()
        {
            return Ok(Some(question_id));
        }
    }
    if !company_records_with_repo(repo, "unknowns.jsonl")
        .iter()
        .any(|record| {
            record.get("fact_id").and_then(Value::as_str) == Some(unknown.unknown_id.as_str())
        })
    {
        persist_unknown(repo, unknown, &authority_id)?;
    }
    let now = now_rfc3339_millis();
    let response_due_at = plus_seconds(&now, 86_400)
        .unwrap_or_else(|_| format_rfc3339_millis(Utc::now() + Duration::hours(24)));
    let task_id = format!(
        "task_{}",
        &crate::hash::sha256_text(&format!("{question_id}\0{decision}"))[..32]
    );
    let record = json!({
        "schema": "kinbase-question/1",
        "question_id": question_id,
        "task_id": task_id,
        "unknown_id": unknown.unknown_id,
        "decision": decision,
        "blocked_decision": decision,
        "evidence_examined": evidence_examined,
        "closure_evidence": evidence_examined,
        "remaining_alternatives": remaining_alternatives,
        "distortion_if_wrong": unknown.loss_if_absent,
        "question": unknown.question,
        "owner_role": if question_kind == "architecture" { "chief-architect".to_owned() } else { unknown.owner_role.clone() },
        "owner_identity": authority_id.clone(),
        "architect_identity": if question_kind == "architecture" { Some(Value::String(authority_id.clone())) } else { None },
        "authority_id": authority_id,
        "authority_scope": authority_scope,
        "scope": authority_scope,
        "unknown_scope": unknown.scope,
        "logical_key": unknown.logical_key,
        "question_kind": question_kind,
        "channel": authority.get("channel").cloned().unwrap_or(Value::Null),
        "status": if authority.is_null() { "awaiting_authority" } else { "open" },
        "created_at": existing.as_ref().and_then(|value| value.get("created_at")).cloned().unwrap_or_else(|| Value::String(now.clone())),
        "response_due_at": response_due_at,
        "expiry_policy": "block_dependent_decision"
    });
    append_company(repo, "questions.jsonl", &record)?;
    Ok(Some(question_id))
}

fn persist_unknown(
    repo: &Path,
    unknown: &crate::projector::UnknownOut,
    authority_id: &str,
) -> Result<(), ContractError> {
    let now = now_rfc3339_millis();
    let response_due_at = plus_seconds(&now, 86_400)
        .unwrap_or_else(|_| format_rfc3339_millis(Utc::now() + Duration::hours(24)));
    let mut event = UnknownEvent::new(
        "company",
        None,
        authority_id,
        &unknown.scope,
        &unknown.logical_key,
        &unknown.scope,
        &unknown.decision_blocked,
        &unknown.owner_role,
        &unknown.owner_identity,
        &unknown.question,
        unknown.loss_if_absent,
        &now,
        &response_due_at,
        "block_dependent_decision",
        "0",
    );
    event.fact_id = unknown.unknown_id.clone();
    event.event_id = format!("{}:open", unknown.unknown_id);
    event.evidence_refs = unknown.evidence.clone();
    let (private_path, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, repo)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local Company Unknown key")?;
    event.sign(&private_key)?;
    append_company(repo, "unknowns.jsonl", &event.to_value())
}

fn ask(question_id: &str, json: bool) -> Result<(), ContractError> {
    let repo = repo()?;
    let mut question = find_question(question_id)?;
    let scope = question
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let question_kind = question
        .get("question_kind")
        .and_then(Value::as_str)
        .unwrap_or("general");
    let authority = active_authority_with_repo(&repo, scope, question_kind)?;
    if question.get("status").and_then(Value::as_str) == Some("awaiting_authority") {
        question["authority_id"] = authority
            .get("authority_id")
            .cloned()
            .unwrap_or(Value::Null);
        question["owner_identity"] = question["authority_id"].clone();
        question["authority_scope"] = authority.get("scope").cloned().unwrap_or(Value::Null);
        question["scope"] = question["authority_scope"].clone();
        question["channel"] = authority.get("channel").cloned().unwrap_or(Value::Null);
        question["status"] = Value::String("open".to_owned());
        append_company(&repo, "questions.jsonl", &question)?;
    }
    let channel = authority
        .get("channel")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let body = json!({
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "task_id": question.get("task_id").cloned().unwrap_or(Value::Null),
        "decision": question.get("decision").cloned().unwrap_or(Value::Null),
        "evidence_examined": question.get("evidence_examined").cloned().unwrap_or_default(),
        "remaining_alternatives": question.get("remaining_alternatives").cloned().unwrap_or_default(),
        "distortion_if_wrong": question.get("distortion_if_wrong").cloned().unwrap_or(Value::Null),
        "question": question.get("question").cloned().unwrap_or(Value::Null)
    });
    let delivery = if channel.starts_with("http://") {
        let reply = http_post(&channel, canonical_bytes(&body).as_slice())?;
        let status = reply.status;
        let digest = crate::hash::sha256_bytes(reply.body.as_slice());
        let receipt = json!({
            "schema": "kinbase-question-receipt/1",
            "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
            "task_id": question.get("task_id").cloned().unwrap_or(Value::Null),
            "channel": channel,
            "delivery": "http",
            "http_status": status,
            "response_digest": digest,
            "recorded_at": now_rfc3339_millis()
        });
        append_company(&repo, "question-receipts.jsonl", &receipt)?;
        if status == 429 {
            return Err(ContractError::new(
                "LIMIT_EXCEEDED",
                "the authority channel refused the third delivery for this task",
                "Wait for the existing authority answer or request a new task decision.",
                false,
                ExitCode::Refused,
            ));
        }
        if !(200..300).contains(&status) {
            return Err(ContractError::new(
                "COMPANY_UNREACHABLE",
                format!("authority channel returned HTTP {status}"),
                "Check the registered channel and retry after the authority restores service.",
                true,
                ExitCode::DependencyUnavailable,
            ));
        }
        "http"
    } else {
        let outbox = write_signed_outbox(&repo, &question, &body)?;
        let receipt = json!({
            "schema": "kinbase-question-receipt/1",
            "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
            "task_id": question.get("task_id").cloned().unwrap_or(Value::Null),
            "channel": channel,
            "delivery": "signed_outbox",
            "outbox_path": outbox.to_string_lossy(),
            "recorded_at": now_rfc3339_millis()
        });
        append_company(&repo, "question-receipts.jsonl", &receipt)?;
        "signed_outbox"
    };
    let mut asked = question.clone();
    if let Value::Object(map) = &mut asked {
        map.insert("status".to_owned(), Value::String("asked".to_owned()));
        map.insert("asked_at".to_owned(), Value::String(now_rfc3339_millis()));
    }
    append_company(&repo, "questions.jsonl", &asked)?;
    let result = json!({
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "task_id": question.get("task_id").cloned().unwrap_or(Value::Null),
        "delivery": delivery,
        "status": "asked"
    });
    print_value(&result, json);
    Ok(())
}

fn write_signed_outbox(
    repo: &Path,
    question: &Value,
    body: &Value,
) -> Result<PathBuf, ContractError> {
    let directory = repo.join(".kin").join("outbox");
    std::fs::create_dir_all(&directory).map_err(io_error)?;
    let (private_path, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, repo)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local question delivery key")?;
    let signature = private_key.sign("question", canonical_bytes(body).as_slice())?;
    let document = json!({
        "schema": "kinbase-question-delivery/1",
        "body": body,
        "signature": signature
    });
    let question_id = question
        .get("question_id")
        .and_then(Value::as_str)
        .unwrap_or("question");
    let path = directory.join(format!("{question_id}.json"));
    std::fs::write(&path, crate::json::record_text(&document)?.as_bytes()).map_err(io_error)?;
    Ok(path)
}

struct HttpReply {
    status: u16,
    body: Vec<u8>,
}

fn http_post(url: &str, body: &[u8]) -> Result<HttpReply, ContractError> {
    let rest = url.strip_prefix("http://").ok_or_else(|| {
        ContractError::new(
            "CONFIG_INVARIANT",
            "only plain HTTP authority channels are supported",
            "Register an HTTP channel or a signed outbox file.",
            false,
            ExitCode::Refused,
        )
    })?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    let address = authority
        .to_socket_addrs()
        .map_err(io_error)?
        .next()
        .ok_or_else(|| {
            ContractError::new(
                "COMPANY_UNREACHABLE",
                "authority channel address did not resolve",
                "Repair the registered authority channel.",
                true,
                ExitCode::DependencyUnavailable,
            )
        })?;
    let mut stream =
        TcpStream::connect_timeout(&address, StdDuration::from_millis(250)).map_err(io_error)?;
    stream
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .map_err(io_error)?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(io_error)?;
    stream.write_all(body).map_err(io_error)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(io_error)?;
    let header_end = response
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            ContractError::new(
                "COMPANY_UNREACHABLE",
                "authority channel returned a malformed HTTP response",
                "Repair the registered authority channel.",
                true,
                ExitCode::DependencyUnavailable,
            )
        })?;
    let header = String::from_utf8_lossy(&response[..header_end]).to_string();
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            ContractError::new(
                "COMPANY_UNREACHABLE",
                "authority channel returned no HTTP status",
                "Repair the registered authority channel.",
                true,
                ExitCode::DependencyUnavailable,
            )
        })?;
    Ok(HttpReply {
        status,
        body: response[header_end + 4..].to_vec(),
    })
}

/// Whether `answer` carries a valid signature by `public_key`. Signed answer
/// documents are produced by both conventions: some legacy lifecycle writers
/// keep `signer` outside the signed body, while the live helper includes it.
/// Only a signature valid under one of those two exact canonical forms counts.
pub(crate) fn answer_signature_valid(
    answer: &Map<String, Value>,
    public_key: &crate::crypto::PublicKey,
) -> bool {
    let Some(signature) = answer.get("signature").and_then(Value::as_str) else {
        return false;
    };
    [false, true].into_iter().any(|remove_signer| {
        let mut unsigned = answer.clone();
        unsigned.remove("signature");
        if remove_signer {
            unsigned.remove("signer");
        }
        public_key.verify(
            "answer",
            canonical_bytes(&Value::Object(unsigned)).as_slice(),
            signature,
        )
    })
}

fn answer(
    question_id: &str,
    answer_file: &Path,
    key_file: &Path,
    json: bool,
) -> Result<(), ContractError> {
    let answer_bytes = std::fs::read(answer_file).map_err(io_error)?;
    let map: Map<String, Value> = parse_strict_object(&answer_bytes).map_err(|error| {
        ContractError::new(
            "CONFIG_INVARIANT",
            error,
            "Use a canonical signed answer object.",
            false,
            ExitCode::Refused,
        )
    })?;
    // The key file is deliberately informational: registry state, not a
    // caller-supplied key, decides who may close the Unknown.
    std::fs::read(key_file).map_err(io_error)?;
    let repo = repo()?;
    let question = find_question(question_id)?;
    let scope = question
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let authority_id = question
        .get("authority_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let authority = active_authority_with_repo(
        &repo,
        scope,
        question
            .get("question_kind")
            .and_then(Value::as_str)
            .unwrap_or("general"),
    )?;
    let signer = map
        .get("signer")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let expected_signer = authority
        .get("public_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if signer.is_empty() || signer != expected_signer {
        return Err(ContractError::new(
            "AUTHORITY_WRONG_SCOPE",
            "answer signer does not own the exact question scope",
            "Route the answer through the registered in-scope authority.",
            false,
            ExitCode::Refused,
        ));
    }
    if let Some(answer_authority_id) = map.get("authority_id").and_then(Value::as_str) {
        if answer_authority_id != authority_id {
            return Err(ContractError::new(
                "AUTHORITY_WRONG_SCOPE",
                "answer authority does not own the exact question scope",
                "Route the answer through the registered in-scope authority.",
                false,
                ExitCode::Refused,
            ));
        }
    }
    // The signer's registered key decides who may answer (checked above).
    // A declared answer scope must then be the scope the authority is
    // registered for or the exact scope of the Unknown it closes; an
    // architect registered for an ancestor scope answers a leaf question.
    let unknown_scope = question
        .get("unknown_scope")
        .and_then(Value::as_str)
        .unwrap_or(scope);
    if let Some(answer_scope) = map.get("authority_scope").and_then(Value::as_str) {
        if answer_scope != scope && answer_scope != unknown_scope {
            return Err(ContractError::new(
                "AUTHORITY_WRONG_SCOPE",
                "answer signer does not own the exact question scope",
                "Route the answer through the registered in-scope authority.",
                false,
                ExitCode::Refused,
            ));
        }
    }
    let signature = map
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if signature.is_empty() {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            "authority answer signature missing",
            "Quarantine the answer and contact the named authority.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let public_key_text = authority
        .get("public_key")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_key = crate::crypto::PublicKey::from_hex(public_key_text)?;
    if !answer_signature_valid(&map, &public_key) {
        return Err(ContractError::new(
            "SIGNATURE_INVALID",
            "authority answer signature failed",
            "Quarantine the answer and contact the named authority.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let answer_text = map.get("answer").and_then(Value::as_str).ok_or_else(|| {
        ContractError::new(
            "CONFIG_INVARIANT",
            "answer text missing",
            "Use a canonical answer object.",
            false,
            ExitCode::Refused,
        )
    })?;
    if hard_blocked(answer_text) {
        return Err(ContractError::new(
            "PERSONAL_TAINT_BLOCKED",
            "hard-blocking material reached Company admission",
            "Keep the source private and provide a safe minimized answer.",
            false,
            ExitCode::IntegrityFailure,
        ));
    }
    let parents: Vec<String> = map
        .get("parents")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let prior_answers: Vec<Value> = company_records_with_repo(&repo, "answers.jsonl")
        .into_iter()
        .filter(|record| {
            record.get("question_id").and_then(Value::as_str)
                == question.get("question_id").and_then(Value::as_str)
        })
        .collect();
    let superseded_events: Vec<String> = if parents.is_empty() {
        Vec::new()
    } else {
        prior_answers
            .iter()
            .filter_map(|record| {
                record
                    .get("event_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    };
    // An answer that declares when it was given keeps that instant. One that
    // does not is admitted at the repository's recorded proof clock: the
    // reducer's `as_of` for this repository is that clock (C12), so a fact the
    // product admits now must be effective now under it, never "in the
    // future" because the wall clock has moved on since `repo init`.
    let answered_at = map
        .get("answered_at")
        .and_then(Value::as_str)
        .or_else(|| map.get("asserted_at").and_then(Value::as_str))
        .map(str::to_owned)
        .unwrap_or_else(|| admission_clock(&repo));
    let answer_id = format!(
        "answer_{:x}",
        Sha256::digest(format!("{question_id}\0{answer_text}\0{signature}").as_bytes())
    );
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(format!("{scope}\0{answer_text}\0{answer_id}").as_bytes())
    );
    let answer_record = json!({
        "schema": "kinbase-answer/1",
        "answer_id": answer_id,
        "event_id": event_id,
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "unknown_id": question.get("unknown_id").cloned().unwrap_or(Value::Null),
        "authority_id": authority_id,
        "authority_scope": scope,
        "answer": answer_text,
        "rationale": map.get("rationale").cloned().unwrap_or(Value::Null),
        "parents": parents,
        "answered_at": answered_at,
        "signer": signer,
        "signature": signature,
        // The authority's own signed document, so a reader can re-check the
        // answer the local fact event cites.
        "signed_answer": Value::Object(map.clone())
    });
    append_company(&repo, "answers.jsonl", &answer_record)?;
    // A later answer joins the group of the question's first answer, so it
    // supersedes (or conflicts with) the earlier ones; an answer written
    // before offline answers took the service's logical key sits under
    // another key, where a correction under the new key never reached it.
    let mut fact_question = question.clone();
    if !prior_answers.is_empty() {
        let company_root = crate::store::store_root(crate::StoreKind::Company, &repo);
        let local_events = crate::store::read_events(&company_root).unwrap_or_default();
        if let Some(key) = answer_chain_key(&prior_answers, &local_events) {
            fact_question["logical_key"] = Value::String(key);
        }
    }
    let (fact_id, fact_event_id) = write_authority_fact(
        &repo,
        &fact_question,
        answer_text,
        &answer_id,
        authority_id,
        scope,
        &answered_at,
        &parents,
        &superseded_events,
    )?;
    let closure_event_id = if parents.is_empty() && !prior_answers.is_empty() {
        None
    } else {
        Some(close_unknown(&repo, &question, &answer_id)?)
    };
    let mut updated = question.clone();
    if let Value::Object(values) = &mut updated {
        let status = if parents.is_empty() && !prior_answers.is_empty() {
            "conflict"
        } else if parents.is_empty() {
            "closed"
        } else {
            "superseded"
        };
        values.insert("status".to_owned(), Value::String(status.to_owned()));
        values.insert("answer_id".to_owned(), Value::String(answer_id.clone()));
        values.insert(
            "closure_event_id".to_owned(),
            closure_event_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
    }
    append_company(&repo, "questions.jsonl", &updated)?;
    let result = json!({
        "status": if parents.is_empty() && !prior_answers.is_empty() { "conflict" } else if parents.is_empty() { "closed" } else { "superseded" },
        "answer_id": answer_id,
        "question_id": question.get("question_id").cloned().unwrap_or(Value::Null),
        "unknown_id": question.get("unknown_id").cloned().unwrap_or(Value::Null),
        "fact_id": fact_id,
        "event_id": fact_event_id,
        "closure_event_id": closure_event_id
    });
    print_value(&result, json);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_authority_fact(
    repo: &Path,
    question: &Value,
    answer_text: &str,
    answer_id: &str,
    authority_id: &str,
    scope: &str,
    answered_at: &str,
    parents: &[String],
    superseded_events: &[String],
) -> Result<(String, String), ContractError> {
    let (private_path, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, repo)?;
    let private_key =
        crate::crypto::PrivateKey::load_or_generate(&private_path, "local Company answer key")?;
    let event = authority_fact_event(
        &private_key,
        question,
        answer_text,
        answer_id,
        authority_id,
        scope,
        answered_at,
        parents,
        superseded_events,
    )?;
    let root = crate::store::ensure_store_root(crate::StoreKind::Company, repo)?;
    crate::store::write_content_addressed_event(&root, &event)?;
    Ok((event.fact_id, event.event_id))
}

/// The logical key of a question's first recorded answer event, which every
/// later answer to the question shares.
pub(crate) fn answer_chain_key(prior_answers: &[Value], events: &[FactEvent]) -> Option<String> {
    let first = prior_answers
        .iter()
        .find_map(|record| record.get("event_id").and_then(Value::as_str))?;
    events
        .iter()
        .find(|event| event.event_id == first)
        .map(|event| event.logical_key.clone())
}

/// The local Company fact event for an authority answer, signed by the local
/// answer key and naming it, so the signature verifies; the authority's own
/// signature is on the answer the event cites.
#[allow(clippy::too_many_arguments)]
pub(crate) fn authority_fact_event(
    private_key: &crate::crypto::PrivateKey,
    question: &Value,
    answer_text: &str,
    answer_id: &str,
    authority_id: &str,
    scope: &str,
    answered_at: &str,
    parents: &[String],
    superseded_events: &[String],
) -> Result<FactEvent, ContractError> {
    // The same identities the Company service gives an admitted answer, so
    // the offline answer groups with the Unknown it closes.
    let fact_id = crate::model::fact_id("company", scope, answer_text);
    let question_id = question
        .get("question_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let logical_key = question
        .get("logical_key")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| crate::model::logical_key("company", scope, question_id));
    let event_id = format!(
        "event_{:x}",
        Sha256::digest(format!("{scope}\0{answer_text}\0{answer_id}").as_bytes())
    );
    let asserted_at = answered_at.to_owned();
    let mut event = FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id,
        store_kind: "company".to_owned(),
        authority_id: authority_id.to_owned(),
        authority_scope: scope.to_owned(),
        repository_id: None,
        fact_id,
        logical_key,
        atom_kind: "decision".to_owned(),
        scope: scope.to_owned(),
        statement: answer_text.to_owned(),
        evidence_refs: vec![
            question
                .get("question_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            answer_id.to_owned(),
        ],
        asserted_at: asserted_at.clone(),
        effective_from: asserted_at,
        effective_until: None,
        disposition: "current".to_owned(),
        distortion: Distortion {
            trigger: question
                .get("decision")
                .and_then(Value::as_str)
                .unwrap_or("authority answer")
                .to_owned(),
            loss_if_absent: 9_000,
            rationale: "the registered authority resolved a blocking Unknown".to_owned(),
        },
        parents: parents.to_vec(),
        supersedes: superseded_events.to_vec(),
        redundancy_with: Vec::new(),
        complements: Vec::new(),
        company_refs: Vec::<CompanyReference>::new(),
        authority_snapshot_cursor: "0".to_owned(),
        confidence: crate::model::Bp(9_800),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
        standing: "authoritative".to_owned(),
        provenance: "human".to_owned(),
        governs_paths: Vec::new(),
        anchors: Vec::new(),
    };
    event.sign(private_key)?;
    Ok(event)
}

/// The short form of a closing record's id used in the closure event id: the
/// twelve characters after a seven-byte prefix (`answer_`), or the whole id
/// when that range is not on character boundaries. A shrug's fact id has no
/// such prefix, and byte slicing panicked on a short or multibyte one.
fn closure_suffix(answer_id: &str) -> &str {
    answer_id
        .get(7..min(19, answer_id.len()))
        .unwrap_or(answer_id)
}

fn close_unknown(repo: &Path, question: &Value, answer_id: &str) -> Result<String, ContractError> {
    let unknown_id = question
        .get("unknown_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let prior = find_unknown_in(repo, unknown_id)?;
    let field = |key: &str, fallback: &str| {
        prior
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or(fallback)
            .to_owned()
    };
    let store_kind = field("store_kind", "company");
    let repository_id = prior
        .get("repository_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let owner_role = field("owner_role", "company-steward");
    let owner_identity = field("owner_identity", &owner_role);
    let authority_id = field("authority_id", &owner_identity);
    let authority_scope = field(
        "authority_scope",
        field("scope", "architecture:company").as_str(),
    );
    let logical_key = field("logical_key", "");
    let scope = field("scope", &authority_scope);
    let decision_blocked = field("decision_blocked", "authority answer");
    let question_text = field("question", "");
    let response_due_at = field("response_due_at", &now_rfc3339_millis());
    let expiry_policy = field("expiry_policy", "block_dependent_decision");
    let cursor = field("authority_snapshot_cursor", "0");
    let loss = prior
        .get("distortion")
        .and_then(|distortion| distortion.get("loss_if_absent"))
        .and_then(Value::as_u64)
        .unwrap_or(9_000)
        .min(u64::from(u16::MAX)) as u16;
    let now = now_rfc3339_millis();
    let mut unknown = UnknownEvent::new(
        &store_kind,
        repository_id.as_deref(),
        &authority_id,
        &authority_scope,
        &logical_key,
        &scope,
        &decision_blocked,
        &owner_role,
        &owner_identity,
        &question_text,
        loss,
        &now,
        &response_due_at,
        &expiry_policy,
        &cursor,
    );
    unknown.fact_id = unknown_id.to_owned();
    unknown.event_id = format!("{unknown_id}:closed:{}", closure_suffix(answer_id));
    unknown.status = "closed".to_owned();
    unknown.closure_evidence = vec![answer_id.to_owned()];
    let (private_path, _) = crate::crypto::ensure_keypair(crate::StoreKind::Company, repo)?;
    let private_key = crate::crypto::PrivateKey::load_or_generate(
        &private_path,
        "local Company Unknown-closing key",
    )?;
    unknown.sign(&private_key)?;
    let store = if unknown.store_kind == "codebase" {
        crate::StoreKind::Codebase
    } else {
        crate::StoreKind::Company
    };
    crate::store::append_record(store, repo, "unknowns.jsonl", &unknown.to_value())?;
    Ok(unknown.event_id.clone())
}

/// Close every still-open question whose key a current `shrug` rules; the
/// Unknown's closure event names the shrug fact as its evidence. Already-closed questions are untouched,
/// so repeated projections append nothing.
///
/// `shrugs` is keyed by (logical key, scope); a question matches on its key and
/// the scope of the Unknown it asks about, so a shrug in one store or
/// repository never closes a question raised about another.
pub(crate) fn close_shrugged(
    repo: &Path,
    shrugs: &BTreeMap<(String, String), String>,
) -> Result<(), ContractError> {
    for question in latest_questions(repo).into_values() {
        let field = |name: &str| {
            question
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let Some(shrug_id) = shrugs.get(&(field("logical_key"), field("unknown_scope"))) else {
            continue;
        };
        if !matches!(
            question.get("status").and_then(Value::as_str),
            Some("open" | "asked" | "awaiting_authority")
        ) {
            continue;
        }
        let closure_event_id = close_unknown(repo, &question, shrug_id)?;
        let mut updated = question.clone();
        if let Value::Object(values) = &mut updated {
            values.insert("status".to_owned(), json!("closed"));
            values.insert("closure_event_id".to_owned(), json!(closure_event_id));
        }
        append_company(repo, "questions.jsonl", &updated)?;
    }
    Ok(())
}

/// The decision an Unknown was first asked under, if any question asks about it.
/// Whether `unknown_id` already has a question under exactly `decision`.
pub(crate) fn asked_under(repo: &Path, unknown_id: &str, decision: &str) -> bool {
    company_records_with_repo(repo, "questions.jsonl").iter().any(|record| {
        record.get("unknown_id").and_then(Value::as_str) == Some(unknown_id)
            && record.get("decision").and_then(Value::as_str) == Some(decision)
    })
}

pub(crate) fn decision_asked_for(repo: &Path, unknown_id: &str) -> Option<String> {
    company_records_with_repo(repo, "questions.jsonl")
        .into_iter()
        .find(|record| record.get("unknown_id").and_then(Value::as_str) == Some(unknown_id))
        .and_then(|record| {
            record
                .get("decision")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

fn status(question_id: &str, json: bool) -> Result<(), ContractError> {
    let repo = repo()?;
    let question = find_question(question_id)?;
    let qid = question
        .get("question_id")
        .and_then(Value::as_str)
        .unwrap_or(question_id);
    let answers: Vec<Value> = company_records_with_repo(&repo, "answers.jsonl")
        .into_iter()
        .filter(|record| record.get("question_id").and_then(Value::as_str) == Some(qid))
        .collect();
    let answer = answers.last().cloned();
    let status = question
        .get("status")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            if answer.is_some() {
                "closed".to_owned()
            } else {
                "open".to_owned()
            }
        });
    let result = json!({
        "question_id": qid,
        "question": question,
        "answer": answer,
        "status": status,
        "closure_event_id": question.get("closure_event_id").cloned().unwrap_or(Value::Null)
    });
    print_value(&result, json);
    Ok(())
}

/// The instant at which this repository admits a locally written fact: its
/// recorded proof clock when `repo init` recorded one, else the proof clock.
fn admission_clock(repo: &Path) -> String {
    crate::launcher::Launcher::load()
        .ok()
        .and_then(|launcher| {
            let repository = crate::codebase::Repository::discover(repo).ok()?;
            crate::repository::recorded_clock(&launcher, &repository).ok()
        })
        .unwrap_or_else(now_rfc3339_millis)
}

fn print_value(value: &Value, json: bool) {
    if json {
        println!("{}", canonical_text(value));
    } else {
        println!(
            "status: {}",
            value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("recorded")
        );
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
    use super::closure_suffix;

    #[test]
    fn a_short_or_multibyte_closing_id_does_not_panic() {
        assert_eq!(closure_suffix("answer_0123456789abcdef"), "0123456789ab");
        assert_eq!(closure_suffix("fact_1"), "fact_1");
        // Byte 7 falls inside the first `é`.
        assert_eq!(closure_suffix("fact_xéééééééé"), "fact_xéééééééé");
    }
}
