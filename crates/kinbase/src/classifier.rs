//! The product-owned classifier boundary (R-11).
//!
//! `kinbase classifier --json` is the only supported extraction interface.
//! It accepts one canonical observation batch on stdin and emits exactly one
//! JSON document. The deterministic provider is replayable; the Ollama provider
//! fails closed on every transport or contract violation.

use crate::error::{ContractError, ExitCode};
use crate::scanner::{ScanResult, scanner};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const CLASSIFIER_VERSION: &str = "kinbase-classifier/1";
const ALLOWED_KINDS: [&str; 6] = [
    "claim",
    "question",
    "decision",
    "constraint",
    "rationale",
    "observation",
];
const ALLOWED_CONFIDENCE: [&str; 3] = ["high", "medium", "low"];
const ALLOWED_DESTINATIONS: [&str; 4] = ["personal", "company", "codebase", "none"];
pub const CLASSIFIER_REQUEST_LIMIT: usize = 1024 * 1024;
const MAX_CLASSIFIER_INPUT: usize = 8 * 1024 * 1024;

pub fn run(
    provider: Option<&str>,
    model: Option<&str>,
    configured_model: &str,
    processor_scope: &str,
    json: bool,
) -> Result<(), ContractError> {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).map_err(|error| {
        ContractError::invariant(format!("classifier stdin is unreadable: {error}"))
    })?;
    if input.len() > MAX_CLASSIFIER_INPUT {
        return Err(ContractError::limit(
            format!("classifier input exceeds the {MAX_CLASSIFIER_INPUT}-byte bound"),
            json!({"omitted_count": 1}),
        ));
    }
    let document = crate::json::parse_strict_value(&input).map_err(|error| {
        ContractError::invariant(format!(
            "classifier input is not a strict JSON object: {error}"
        ))
    })?;
    let selected_provider = provider.map(str::to_owned).unwrap_or_else(|| {
        let name = model.unwrap_or(configured_model);
        if name.starts_with("ollama:") {
            "ollama".to_owned()
        } else if name.starts_with("agy:") {
            "agy".to_owned()
        } else {
            "deterministic".to_owned()
        }
    });
    let output = match selected_provider.as_str() {
        "deterministic" => deterministic(&document)?,
        "agy" => {
            let name = model
                .map(|model| model.trim_start_matches("agy:"))
                .or_else(|| configured_model.strip_prefix("agy:"))
                .unwrap_or("default");
            authorize_processor("agy", processor_scope, &format!("agy:{}", name.trim()))?;
            antigravity(name.trim(), &document)?
        }
        "ollama" => {
            let name = model
                .map(|model| model.trim_start_matches("ollama:"))
                .or_else(|| configured_model.strip_prefix("ollama:"))
                .ok_or_else(|| {
                    unauthorized("Ollama provider requires --model or classifier.model")
                })?;
            if name.trim().is_empty() {
                return Err(unauthorized(
                    "Ollama provider requires a nonempty model name",
                ));
            }
            let processor = ollama_model_available(name.trim()).map_err(unreachable)?;
            authorize_processor(
                processor,
                processor_scope,
                &format!("ollama:{}", name.trim()),
            )?;
            ollama(name.trim(), &document)?
        }
        other => {
            return Err(ContractError::invariant(format!(
                "unsupported classifier provider `{other}`; use deterministic, ollama or agy"
            )));
        }
    };
    if json {
        println!("{}", crate::json::canonical_text(&output));
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).unwrap_or_default()
        );
    }
    Ok(())
}

/// Split classifier input at whole-observation boundaries. A byte-sized cut
/// can split a JSON document and make a well-formed source look like EOF; each
/// emitted request is itself one complete strict JSON object.
pub(crate) fn request_batches(observations: Vec<Value>) -> Result<Vec<Value>, ContractError> {
    if observations.is_empty() {
        return Ok(vec![json!({ "observations": [] })]);
    }
    let mut batches = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    for observation in observations {
        let mut candidate = current.clone();
        candidate.push(observation.clone());
        let request = json!({ "observations": candidate });
        let bytes = crate::json::canonical_bytes(&request).len();
        if bytes <= CLASSIFIER_REQUEST_LIMIT {
            current = candidate;
            continue;
        }
        if !current.is_empty() {
            batches.push(json!({ "observations": current }));
            candidate = vec![observation];
        }
        let bytes = crate::json::canonical_bytes(&json!({ "observations": candidate })).len();
        if bytes > CLASSIFIER_REQUEST_LIMIT {
            return Err(ContractError::limit(
                format!(
                    "a single classifier observation exceeds the {CLASSIFIER_REQUEST_LIMIT}-byte request bound"
                ),
                json!({
                    "omitted_count": 1,
                    "bytes": bytes,
                    "ceiling_bytes": CLASSIFIER_REQUEST_LIMIT
                }),
            ));
        }
        current = candidate;
    }
    if !current.is_empty() {
        batches.push(json!({ "observations": current }));
    }
    Ok(batches)
}

/// Canonical records reject control characters, but native source bodies may
/// contain line breaks. Preserve sentence boundaries at those breaks and make
/// every otherwise-forbidden code point an explicit space so a classifier
/// request can never silently canonicalize to zero bytes.
pub(crate) fn request_body(text: &str) -> String {
    let line_breaks_replaced = text
        .replace("\r\n", ". ")
        .replace('\r', ". ")
        .replace('\n', ". ");
    line_breaks_replaced
        .chars()
        .map(|character| {
            let code = character as u32;
            if code <= 0x1f
                || (0x80..=0x9f).contains(&code)
                || code == 0x61c
                || (0x200e..=0x200f).contains(&code)
                || (0x202a..=0x202e).contains(&code)
                || (0x2066..=0x2069).contains(&code)
                || (0xfdd0..=0xfdef).contains(&code)
                || ((code & 0xfffe) == 0xfffe && code <= 0x10ffff)
            {
                ' '
            } else {
                character
            }
        })
        .collect()
}

pub(crate) fn deterministic(document: &Value) -> Result<Value, ContractError> {
    let observations = observations(document)?;
    let mut atoms = Vec::new();
    for observation in observations {
        let map = observation
            .as_object()
            .ok_or_else(|| invariant("each observation must be an object"))?;
        require_observation(map)?;
        let body = map.get("body").and_then(Value::as_str).unwrap_or_default();
        let base = base_confidence(map);
        for sentence in sentences(body) {
            let confidence = if base == "low" {
                "low"
            } else {
                let hedged = sentence_confidence(&sentence);
                if base == "medium" && hedged == "high" {
                    "medium"
                } else {
                    hedged
                }
            };
            let mut atom = atom_from_observation(map, &sentence, confidence, None);
            // A sentence that no destination rule places is not a
            // high-confidence `none`: the rule provider has no evidence of
            // ownership, so it abstains at low confidence rather than guess.
            if confidence != "low"
                && atom.get("proposed_destinations") == Some(&json!(["none"]))
                && !atom_hard_blocked(&atom)
            {
                atom = atom_from_observation(map, &sentence, "low", None);
                atom["unresolved_uncertainty"] = Value::String(
                    "no destination rule matched; ownership is ambiguous and the label was demoted to none"
                        .to_owned(),
                );
            }
            atoms.push(atom);
        }
    }
    Ok(json!({
        "classifier_version": CLASSIFIER_VERSION,
        "provider": "deterministic",
        "atoms": atoms
    }))
}

/// The routing instruction, written from the ratified store meanings
/// (product.md "Concrete store meanings" and P-2) rather than any corpus.
const OLLAMA_INSTRUCTION: &str = r#"You are the routing classifier of Kinbase, a knowledge system with three physically separate stores. You read messages a software developer typed (or received) in a coding session and split each message into knowledge atoms, giving every atom exactly one destination.

Destinations (choose exactly one per atom):
- "personal": the principal's private conversational memory. Anything about the person rather than the work: their life, family, health, feelings, plans, schedule, opinions, habits, preferences; private identifiers, account details, secrets, credentials, access tokens, opaque private codes or reference strings (a random-looking token such as an API key, a license key, a ticket or booking code, a device or account identifier belongs to the person's private memory). Also personal working notes that are about the person's own situation rather than the repository.
- "company": organization-wide direction owned by a steward or named authority: company policy, mandates that apply to all teams, standards, governance, roadmap, and architecture decisions signed off by the chief architect or another named authority. The signal is organization-wide ownership, not the mere mention of the company.
- "codebase": repository-scoped knowledge that travels with this repository: how this codebase works, its constraints, decisions, invariants, tests, configuration, modules, dependencies, bugs, deployment details, and the rationale behind them. Statements about what the code does or must do belong here.
- "none": nothing durable to store: ambiguous non-facts, temporary or throwaway suggestions ("for now", "let's just", "quick hack"), speculation and hedges ("maybe", "I think we could"), open questions, requests, greetings and small talk with no private or work content, or text so ambiguous that no owner can be named.

Rules:
1. Split a message into atoms, one per independent statement. A mixed message (for example a private remark followed by a repository fact) yields several atoms with different destinations. Never force one label on a whole mixed message.
2. Copy each atom's text verbatim from the message (the sentence or clause it came from). Do not paraphrase, summarize, or invent text.
3. Every statement in the message belongs to exactly one atom; do not drop a statement. Do not merge two statements with different destinations into one atom. A bare greeting, thanks, or acknowledgement that carries no content of its own is not an atom: omit it when the message says something else, and when the whole message is such filler return one atom for the whole message with destination "none".
4. A reference annotation is not an atom. A short trailing note that only attaches a reference code, ticket, record, or identifier to the statement before it (for example "Ref <code>", "Ticket <code>", "Tracked as <code>", "I logged this as <code>", "I filed it under <code>") is part of that statement: include it in that atom's text and give the atom the destination of the statement it annotates. Such a bookkeeping note is not private memory, even when phrased in the first person.
5. confidence is "high" when the destination is clear, "medium" when plausible, "low" when the ownership is genuinely ambiguous. When you are unsure between a shared store (company, codebase) and something else, prefer "personal" for private matters and "none" for non-facts; never guess a shared store at low confidence.
6. Private material stays private: a statement that is itself about the person's private life or private credentials (their own account, key, passphrase, booking, health, family, plans) is "personal" even if it also mentions code or the company. A private statement that opens a message stays a separate personal atom.

Answer with exactly one JSON object and nothing else (no prose, no markdown fences):
{"atoms":[{"id":"<message id>","text":"<verbatim atom text>","destination":"personal|company|codebase|none","confidence":"high|medium|low"}]}"#;

/// Report which processor serves `model` through the local Ollama daemon
/// (R-11 provider selection): `local`, or `ollama-cloud` for a model the
/// daemon forwards to a remote host. The check is a loopback list call within
/// the connect budget; it never sends observation bytes.
pub(crate) fn ollama_model_available(model: &str) -> Result<&'static str, String> {
    let response = ollama_request("GET", "/api/tags", None, Duration::from_secs(5))
        .map_err(|error| error.message)?;
    let parsed: Value = serde_json::from_slice(&response)
        .map_err(|error| format!("Ollama model list is not JSON: {error}"))?;
    ollama_processor(&parsed, model)
        .ok_or_else(|| format!("Ollama does not serve the configured model `{model}`"))
}

/// The processor behind `model` in an Ollama model list, if it is listed. A
/// listed model with a remote host is served off this machine.
fn ollama_processor(tags: &Value, model: &str) -> Option<&'static str> {
    let entry = tags
        .get("models")
        .and_then(Value::as_array)?
        .iter()
        .find(|entry| {
            ["name", "model"].iter().any(|key| {
                entry.get(key).and_then(Value::as_str).is_some_and(|name| {
                    name == model
                        || name.trim_end_matches(":latest") == model.trim_end_matches(":latest")
                })
            })
        })?;
    let remote = ["remote_host", "remote_model"].iter().any(|key| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
    });
    Some(if remote { "ollama-cloud" } else { "local" })
}

/// Refuse a provider whose processor the classifier configuration does not
/// name, before any observation byte is sent to it.
pub(crate) fn authorize_processor(
    processor: &str,
    processor_scope: &str,
    model: &str,
) -> Result<(), ContractError> {
    if processor == "local" || processor == processor_scope {
        return Ok(());
    }
    Err(ContractError::integrity(
        "PROCESSOR_UNAUTHORIZED",
        format!(
            "`{model}` sends session text to the `{processor}` processor, which classifier.processor_scope (`{processor_scope}`) does not authorize"
        ),
        format!(
            "Set classifier.processor_scope = \"{processor}\" to authorize that processor, or use a local model; nothing was sent."
        ),
    ))
}

/// Where the Antigravity CLI lives. It is a routing classifier here, not a
/// coder: the same instruction Ollama gets, one non-interactive turn, a JSON
/// schema enforced on the answer, and limits high enough that a corpus load
/// is not throttled into abstaining.
const AGY_PATHS: [&str; 2] = ["/opt/homebrew/bin/agy", "/usr/local/bin/agy"];
const KIN_PATHS: [&str; 2] = ["/opt/homebrew/bin/kin", "/usr/local/bin/kin"];
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

/// The conversation an Antigravity stream-json `init` event names, and the
/// directory it runs in, before the turn starts.
fn init_conversation(line: &[u8]) -> Option<(String, Option<String>)> {
    let event: Value = serde_json::from_slice(line).ok()?;
    if event.get("event").and_then(Value::as_str) != Some("init") {
        return None;
    }
    let id = event.get("conversation_id").and_then(Value::as_str)?;
    let well_formed = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if !well_formed {
        return None;
    }
    let cwd = event
        .get("init")
        .and_then(|init| init.get("cwd"))
        .and_then(Value::as_str)
        .filter(|cwd| std::path::Path::new(cwd).is_absolute())
        .map(str::to_owned);
    Some((id.to_owned(), cwd))
}

/// Tell Kindex's supervisor health, when Kindex is installed, that this
/// Antigravity conversation is a classifier turn and not a coding session.
/// Each turn is a non-interactive Antigravity session that Antigravity's own
/// records give no workspace, so health counted every one as unscoped host
/// activity and raised `observation_unavailable`. Best effort and bounded:
/// the turn is never held or failed by it; a failure is said on stderr.
fn register_automation_session(
    kin_paths: &[&str],
    conversation: &str,
    cwd: Option<&str>,
) -> Option<std::thread::JoinHandle<()>> {
    let kin = kin_paths
        .iter()
        .find(|path| std::path::Path::new(path).is_file())?
        .to_string();
    let project = cwd.map(str::to_owned).unwrap_or_else(real_home_dir);
    let conversation = conversation.to_owned();
    Some(std::thread::spawn(move || {
        let spawned = std::process::Command::new(&kin)
            .env_clear()
            .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
            .env("HOME", real_home_dir())
            .args(["supervisor-register", "--agent", "antigravity", "--session"])
            .arg(&conversation)
            .arg("--project")
            .arg(&project)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let outcome = match spawned {
            Ok(mut child) => {
                let started = std::time::Instant::now();
                loop {
                    match child.try_wait() {
                        Ok(Some(status)) if status.success() => break Ok(()),
                        Ok(Some(status)) => break Err(format!("exited with {status}")),
                        Ok(None) if started.elapsed() >= REGISTRATION_TIMEOUT => {
                            let _ = child.kill();
                            let _ = child.wait();
                            break Err("timed out".to_owned());
                        }
                        Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                        Err(error) => break Err(error.kind().to_string()),
                    }
                }
            }
            Err(error) => Err(error.kind().to_string()),
        };
        if let Err(reason) = outcome {
            eprintln!("kindex supervisor registration of classifier turn unavailable: {reason}");
        }
    }))
}

/// The invoking user's home directory from the password database, since the
/// sandboxed child's environment deliberately does not carry it.
fn real_home_dir() -> String {
    // SAFETY: getpwuid returns a pointer to static storage or null; the
    // fields are read immediately and copied out before any other call.
    unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if !entry.is_null() && !(*entry).pw_dir.is_null() {
            let dir = std::ffi::CStr::from_ptr((*entry).pw_dir);
            return dir.to_string_lossy().into_owned();
        }
    }
    "/nonexistent".to_owned()
}

pub(crate) fn agy_available() -> Result<(), String> {
    for path in AGY_PATHS {
        if std::path::Path::new(path).is_file() {
            return Ok(());
        }
    }
    Err(format!(
        "Antigravity CLI not found at {}",
        AGY_PATHS.join(" or ")
    ))
}

fn antigravity(model: &str, document: &Value) -> Result<Value, ContractError> {
    antigravity_with(&AGY_PATHS, &KIN_PATHS, model, document)
}

fn antigravity_with(
    agy_paths: &[&str],
    kin_paths: &[&str],
    model: &str,
    document: &Value,
) -> Result<Value, ContractError> {
    let input_observations = observations(document)?;
    for observation in input_observations {
        require_observation(
            observation
                .as_object()
                .ok_or_else(|| invariant("each observation must be an object"))?,
        )?;
    }
    let messages: Vec<Value> = input_observations
        .iter()
        .map(|observation| {
            json!({
                "id": observation.get("observation_id").cloned().unwrap_or(Value::Null),
                "text": observation.get("body").cloned().unwrap_or(Value::String(String::new()))
            })
        })
        .collect();
    let prompt = format!(
        "{OLLAMA_INSTRUCTION}\n\nInput:\n{}",
        serde_json::to_string(&json!({"messages": messages})).unwrap_or_default()
    );
    let schema = json!({
        "type": "object",
        "properties": {
            "atoms": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "text": {"type": "string"},
                        "destination": {"type": "string", "enum": ["personal", "company", "codebase", "none"]},
                        "confidence": {"type": "string", "enum": ["high", "medium", "low"]}
                    },
                    "required": ["id", "text", "destination", "confidence"]
                }
            }
        },
        "required": ["atoms"]
    });
    let binary = agy_paths
        .iter()
        .find(|path| std::path::Path::new(path).is_file())
        .ok_or_else(|| unauthorized("Antigravity CLI is not installed"))?;
    // The pinned classifier child runs with HOME=/nonexistent and a bare
    // PATH, which is right for a processor that must not read the user's
    // files. Antigravity cannot start without its state directory under the
    // real home, so the routing turn gets the home back, inside Antigravity's
    // own sandbox, with slash commands off and a single non-interactive turn:
    // the only thing it can do with that home is find its credentials.
    //
    // The prompt carries session text, so it travels on stdin as one
    // stream-json user message; argv is readable by every local process.
    let mut command = std::process::Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
        .env("HOME", real_home_dir())
        .env("TMPDIR", "/tmp")
        .arg("--sandbox")
        .arg("--effort")
        .arg("low")
        .arg("--input-format")
        .arg("stream-json")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--disable-slash-commands")
        .arg("--json-schema")
        .arg(schema.to_string());
    if model != "default" && !model.is_empty() {
        command.arg("--model").arg(model);
    }
    let mut message = serde_json::to_vec(&json!({
        "event": "user",
        "message": {"content": prompt}
    }))
    .unwrap_or_default();
    message.push(b'\n');
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| unauthorized(format!("Antigravity CLI failed to start: {error}")))?;
    let writer = child
        .stdin
        .take()
        .map(|mut stdin| std::thread::spawn(move || stdin.write_all(&message)));
    let stderr_reader = child.stderr.take().map(|mut stderr| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stderr.read_to_end(&mut bytes);
            bytes
        })
    });
    // Stdout is read as it arrives so the turn can be registered from its
    // `init` event, before it runs, rather than after health has seen it.
    let mut stdout_bytes = Vec::new();
    let mut registration = None;
    let mut registration_tried = false;
    if let Some(stdout) = child.stdout.take() {
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = Vec::new();
        loop {
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if !registration_tried
                        && let Some((conversation, cwd)) = init_conversation(&line)
                    {
                        registration_tried = true;
                        registration =
                            register_automation_session(kin_paths, &conversation, cwd.as_deref());
                    }
                    stdout_bytes.extend_from_slice(&line);
                }
            }
        }
    }
    let status = child
        .wait()
        .map_err(|error| unauthorized(format!("Antigravity CLI failed: {error}")))?;
    let stderr_bytes = stderr_reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    if let Some(writer) = writer {
        // A child that exits without reading its prompt breaks the pipe; its
        // exit status below is the error that matters.
        let _ = writer.join();
    }
    // A registration still running when the turn ends is not waited for: the
    // turn's answer must not miss its caller's deadline on its account, and
    // the sandbox ends what this process leaves in its group. It started at
    // `init`, so it has normally finished long before the turn has.
    if let Some(registration) = registration.filter(|handle| handle.is_finished()) {
        let _ = registration.join();
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        let first = stderr
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_default();
        return Err(unauthorized(format!(
            "Antigravity CLI exited with {}: {}",
            status,
            first.chars().take(200).collect::<String>()
        )));
    }
    let envelope = String::from_utf8_lossy(&stdout_bytes)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event.get("event").and_then(Value::as_str) == Some("result"))
        .filter_map(|event| event.get("result").cloned())
        .next_back()
        .ok_or_else(|| unauthorized("Antigravity stream carries no result"))?;
    if envelope.get("status").and_then(Value::as_str) != Some("SUCCESS") {
        return Err(unauthorized(format!(
            "Antigravity turn did not succeed: {}",
            envelope
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )));
    }
    // The schema-checked answer when the CLI reports one; otherwise the
    // first JSON object in the reply text.
    let candidate = match envelope.get("structured_output") {
        Some(structured) if structured.is_object() => structured.clone(),
        _ => {
            let content = envelope
                .get("response")
                .and_then(Value::as_str)
                .ok_or_else(|| unauthorized("Antigravity envelope carries no response"))?;
            extract_json_object(content)
                .ok_or_else(|| unauthorized("Antigravity response carries no JSON object"))?
        }
    };
    let normalized = normalize_ollama_output(document, &candidate)?;
    validate_output(&normalized)?;
    Ok(normalized)
}

fn ollama(model: &str, document: &Value) -> Result<Value, ContractError> {
    let input_observations = observations(document)?;
    for observation in input_observations {
        require_observation(
            observation
                .as_object()
                .ok_or_else(|| invariant("each observation must be an object"))?,
        )?;
    }
    let messages: Vec<Value> = input_observations
        .iter()
        .map(|observation| {
            json!({
                "id": observation.get("observation_id").cloned().unwrap_or(Value::Null),
                "text": observation.get("body").cloned().unwrap_or(Value::String(String::new()))
            })
        })
        .collect();
    // The model is asked for its lowest reasoning effort: the answer
    // contract is short and the routing judgement does not improve with a
    // long deliberation, while every generated token is paid for out of the
    // session's wall budget. If an answer carries no JSON object at all, one
    // retry allows the model its full thinking pass.
    let mut candidate: Option<Value> = None;
    for think in [json!("low"), json!(true)] {
        let request = json!({
            "model": model,
            "stream": false,
            "think": think,
            "messages": [
                {"role": "system", "content": OLLAMA_INSTRUCTION},
                {"role": "user", "content": serde_json::to_string(&json!({"messages": messages})).unwrap_or_default()}
            ],
            "options": {"temperature": 0}
        });
        let response = ollama_request(
            "POST",
            "/api/chat",
            Some(&request),
            Duration::from_secs(120),
        )?;
        let parsed: Value = serde_json::from_slice(&response)
            .map_err(|error| unauthorized(format!("Ollama response is not JSON: {error}")))?;
        if let Some(error) = parsed.get("error") {
            return Err(unauthorized(format!(
                "Ollama refused the request: {}",
                error.as_str().unwrap_or("unspecified error")
            )));
        }
        if parsed.get("atoms").is_some() {
            candidate = Some(parsed);
            break;
        }
        let content = parsed
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| unauthorized("Ollama response has no strict classifier document"))?;
        if let Some(object) = extract_json_object(content) {
            candidate = Some(object);
            break;
        }
    }
    let candidate =
        candidate.ok_or_else(|| unauthorized("Ollama message carries no JSON object"))?;
    let normalized = normalize_ollama_output(document, &candidate)?;
    validate_output(&normalized)?;
    Ok(normalized)
}

/// The model must answer with one JSON object; tolerate markdown fences and
/// surrounding prose by taking the last balanced object that carries `atoms`.
fn extract_json_object(content: &str) -> Option<Value> {
    let trimmed = content.trim();
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        if value.is_object() {
            return Some(value);
        }
    }
    let end = trimmed.rfind('}')?;
    let starts: Vec<usize> = trimmed
        .char_indices()
        .filter(|(_, character)| *character == '{')
        .map(|(index, _)| index)
        .collect();
    for start in starts.iter().rev() {
        if *start > end {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(&trimmed[*start..=end]) {
            if value.get("atoms").is_some() {
                return Some(value);
            }
        }
    }
    // A truncated answer: the longest prefix of the last object that parses.
    let start = *starts.first()?;
    let mut closers: Vec<usize> = trimmed[start..]
        .char_indices()
        .filter(|(_, character)| *character == '}')
        .map(|(index, _)| start + index)
        .collect();
    closers.reverse();
    for index in closers.into_iter().take(64) {
        if let Ok(value) = serde_json::from_str::<Value>(&trimmed[start..=index]) {
            if value.get("atoms").is_some() {
                return Some(value);
            }
        }
    }
    None
}

fn normalize_ollama_output(input: &Value, candidate: &Value) -> Result<Value, ContractError> {
    let model_atoms = candidate
        .get("atoms")
        .and_then(Value::as_array)
        .ok_or_else(|| unauthorized("Ollama output must contain an atoms array"))?;
    let inputs = observations(input)?;
    let single = (inputs.len() == 1).then(|| inputs[0].clone());
    let mut normalized_atoms = Vec::new();
    let mut emitted: BTreeSet<(String, String)> = BTreeSet::new();
    for model_atom in model_atoms {
        let Some(model_atom) = model_atom.as_object() else {
            continue;
        };
        let observation_id = model_atom
            .get("id")
            .or_else(|| model_atom.get("observation_id"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let observation = inputs
            .iter()
            .find(|observation| {
                observation.get("observation_id").and_then(Value::as_str) == Some(observation_id)
            })
            .cloned()
            .or_else(|| single.clone());
        let Some(observation) = observation.as_ref().and_then(Value::as_object) else {
            continue;
        };
        let text = model_atom
            .get("text")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        if !text.chars().any(char::is_alphanumeric) {
            continue;
        }
        let key = (
            observation
                .get("observation_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            text.to_owned(),
        );
        if !emitted.insert(key) {
            continue;
        }
        let confidence = normalized_atom_confidence(&Value::Object(model_atom.clone()), text);
        let mut atom = atom_from_observation_base(observation, text, confidence);
        let model_kind = model_atom.get("atom_kind").and_then(Value::as_str);
        if ALLOWED_KINDS.contains(&model_kind.unwrap_or_default()) {
            atom["atom_kind"] = Value::String(model_kind.unwrap_or_default().to_owned());
        }
        let destinations =
            normalized_destinations(&Value::Object(model_atom.clone()), &atom, confidence);
        atom["proposed_destinations"] =
            Value::Array(destinations.into_iter().map(Value::String).collect());
        if confidence == "low" {
            atom["unresolved_uncertainty"] =
                Value::String("low-confidence label demoted to none".to_owned());
        }
        normalized_atoms.push(atom);
    }
    Ok(json!({
        "classifier_version": CLASSIFIER_VERSION,
        "provider": "ollama",
        "atoms": normalized_atoms
    }))
}

/// Confidence is a fact the product owns (P-2), not one the provider reports.
///
/// A model's self-report is an input to that judgement: it may lower the
/// product's reading of an atom, never raise it above what the claim's own
/// language supports. A provider that answers "high" for every atom would
/// otherwise let an unsettled guess reach a shared store, which is exactly the
/// failure P-2 names.
fn normalized_atom_confidence(model_atom: &Value, text: &str) -> &'static str {
    if is_unsettled_claim(text) {
        return "low";
    }
    match model_atom.get("confidence") {
        Some(Value::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "medium",
        },
        Some(Value::Number(number)) => {
            let number = number.as_f64().unwrap_or_default();
            if number >= 7_000.0 || (number > 0.0 && number <= 1.0 && number >= 0.7) {
                "high"
            } else if number >= 4_000.0 || (number > 0.0 && number <= 1.0 && number >= 0.4) {
                "medium"
            } else {
                "low"
            }
        }
        _ => "medium",
    }
}

fn normalized_destinations(
    model_atom: &Value,
    canonical_atom: &Value,
    confidence: &str,
) -> Vec<String> {
    let mut labels: Vec<String> = match model_atom.get("destination") {
        Some(Value::String(label)) => vec![label.trim().to_ascii_lowercase()],
        _ => model_atom
            .get("proposed_destinations")
            .and_then(Value::as_array)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|label| label.trim().to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default(),
    };
    labels.retain(|label| ALLOWED_DESTINATIONS.contains(&label.as_str()));
    labels.dedup();
    if labels.is_empty() {
        labels = canonical_atom
            .get("proposed_destinations")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
    }
    // The deterministic taint gate is not the model's to override: a
    // hard-blocked atom has no shared destination.
    if atom_hard_blocked(canonical_atom) {
        return vec!["none".to_owned()];
    }
    if confidence == "low" || labels.is_empty() {
        return vec!["none".to_owned()];
    }
    // P-2: one message may fan out to several stores. Keeping every label the
    // model proposed preserves that fan-out; taking only the alphabetically
    // first silently dropped the second destination of a mixed claim.
    labels.retain(|label| label != "none");
    if labels.is_empty() {
        return vec!["none".to_owned()];
    }
    labels
}

fn ollama_request(
    method: &str,
    path: &str,
    request: Option<&Value>,
    read_timeout: Duration,
) -> Result<Vec<u8>, ContractError> {
    // A transport document, not a canonical event: serialize as ordinary
    // JSON so instruction text with line breaks survives.
    let body = request
        .map(|value| serde_json::to_vec(value).unwrap_or_default())
        .unwrap_or_default();
    let address = "127.0.0.1:11434"
        .to_socket_addrs()
        .map_err(|error| unreachable(format!("Ollama loopback address is malformed: {error}")))?
        .next()
        .ok_or_else(|| unreachable("Ollama loopback address did not resolve"))?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(250))
        .map_err(|error| unreachable(format!("Ollama is unreachable: {error}")))?;
    stream.set_read_timeout(Some(read_timeout)).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    if !body.is_empty() {
        stream
            .write_all(&body)
            .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    }
    stream
        .flush()
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| unreachable(format!("Ollama transport failed: {error}")))?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| unauthorized("Ollama returned a malformed HTTP response"))?;
    let header = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| unauthorized("Ollama returned a malformed HTTP status"))?;
    let chunked = header.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim() == "transfer-encoding" && value.contains("chunked")
        })
    });
    let mut body = response[split + 4..].to_vec();
    if chunked {
        body = decode_chunked(&body)?;
    }
    if status != 200 {
        let detail = String::from_utf8_lossy(&body);
        let detail: String = detail.chars().take(200).collect();
        return Err(unauthorized(format!(
            "Ollama returned HTTP status {status}: {detail}"
        )));
    }
    if body.len() > 4 * 1024 * 1024 {
        return Err(unauthorized("Ollama response exceeds the 4 MiB bound"));
    }
    Ok(body)
}

pub(crate) fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>, ContractError> {
    let mut output = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| unauthorized("Ollama chunked response is malformed"))?;
        let size_text = std::str::from_utf8(&bytes[..end])
            .map_err(|_| unauthorized("Ollama chunk size is malformed"))?;
        let size = usize::from_str_radix(size_text.trim().split(';').next().unwrap_or(""), 16)
            .map_err(|_| unauthorized("Ollama chunk size is malformed"))?;
        bytes = &bytes[end + 2..];
        if size == 0 {
            break;
        }
        if size > bytes.len() {
            return Err(unauthorized("Ollama chunked response is truncated"));
        }
        output.extend_from_slice(&bytes[..size]);
        if bytes.len() < size + 2 {
            return Err(unauthorized("Ollama chunked response is truncated"));
        }
        bytes = &bytes[size + 2..];
    }
    Ok(output)
}

fn observations(document: &Value) -> Result<&Vec<Value>, ContractError> {
    document
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| invariant("classifier input must contain an observations array"))
}

fn require_observation(map: &Map<String, Value>) -> Result<(), ContractError> {
    for key in [
        "observation_id",
        "source_kind",
        "source_identity",
        "content_digest",
        "observed_at",
        "disposition",
        "extraction_version",
    ] {
        if !map
            .get(key)
            .and_then(Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false)
        {
            return Err(invariant(format!(
                "classifier observation is missing nonempty string {key}"
            )));
        }
    }
    if map.get("body").and_then(Value::as_str).is_none()
        && map.get("body_ref").and_then(Value::as_str).is_none()
    {
        return Err(invariant(
            "classifier observation must carry body or body_ref",
        ));
    }
    Ok(())
}

fn base_confidence(map: &Map<String, Value>) -> &'static str {
    let explicit = map.get("confidence");
    if let Some(Value::String(value)) = explicit {
        return match value.as_str() {
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "medium",
        };
    }
    if let Some(number) = explicit.and_then(Value::as_f64) {
        if number >= 7000.0 || (number > 0.0 && number <= 1.0 && number >= 0.7) {
            return "high";
        }
        if number >= 4000.0 || (number > 0.0 && number <= 1.0 && number >= 0.4) {
            return "medium";
        }
        return "low";
    }
    match map.get("disposition").and_then(Value::as_str) {
        Some("current") => "high",
        Some("draft") | Some("proposed") | Some("open") => "medium",
        _ => "low",
    }
}

/// Marks of a claim its own author has not settled: hedged assertions,
/// unresolved questions and conditionals, vague attribution, and proposals
/// still only under consideration. Every entry is matched on whole words, so
/// "try" never fires inside "retry budget".
const UNSETTLED_PHRASES: [&str; 76] = [
    // Hedged assertion.
    "maybe",
    "perhaps",
    "possibly",
    "probably",
    "presumably",
    "apparently",
    "arguably",
    "supposedly",
    "allegedly",
    "reportedly",
    "might",
    "may be",
    "could be",
    "seem",
    "seems",
    "seemed",
    "appear",
    "appears",
    "i think",
    "we think",
    "i believe",
    "we believe",
    "i guess",
    "i suspect",
    "we suspect",
    "i heard",
    "not sure",
    "unsure",
    "not certain",
    "uncertain",
    "unclear",
    "no idea",
    "as far as i know",
    "roughly",
    "sort of",
    "kind of",
    "more or less",
    // Unsettled question.
    "wonder",
    "wonders",
    "wondering",
    "whether",
    "open question",
    "still open",
    "undecided",
    "not yet decided",
    "to be decided",
    "tbd",
    "without deciding",
    // Unresolved conditional.
    "in case",
    "depending on",
    "assuming",
    "if we",
    "unless we",
    // Vague attribution or quantity.
    "someone",
    "somebody",
    "some people",
    "somewhere",
    "a few",
    "a couple",
    "several",
    "various",
    // A proposal is not yet a fact.
    "we should",
    "we could",
    "we might",
    "we may",
    "i should",
    "consider",
    "let s",
    "let us",
    "i suggest",
    "we suggest",
    "i propose",
    "we propose",
    "ought to",
    "try",
    "trying",
];

/// Words that open an interrogative even when the writer dropped the mark.
const INTERROGATIVE_OPENERS: [&str; 22] = [
    "what", "why", "how", "when", "where", "who", "whom", "whose", "which", "whether", "is", "are",
    "was", "were", "am", "do", "does", "did", "can", "will", "shall", "should",
];

/// Lowercase the text and collapse every run of non-alphanumeric characters to
/// one space, framed by spaces, so a phrase test matches whole words only.
pub(crate) fn word_frame(text: &str) -> String {
    let mut frame = String::with_capacity(text.len() + 2);
    frame.push(' ');
    for character in text.chars() {
        if character.is_alphanumeric() {
            frame.extend(character.to_lowercase());
        } else if !frame.ends_with(' ') {
            frame.push(' ');
        }
    }
    if !frame.ends_with(' ') {
        frame.push(' ');
    }
    frame
}

pub(crate) fn frame_contains(frame: &str, phrase: &str) -> bool {
    frame.contains(&format!(" {phrase} "))
}

/// The one product-owned reading of whether a claim's own language leaves its
/// ownership unsettled (P-2). Both providers obey it: the deterministic one as
/// its confidence floor, the model one as the ceiling on a self-report.
fn is_unsettled_claim(text: &str) -> bool {
    if text.contains('?') {
        return true;
    }
    let frame = word_frame(text);
    if UNSETTLED_PHRASES
        .iter()
        .any(|phrase| frame_contains(&frame, phrase))
    {
        return true;
    }
    INTERROGATIVE_OPENERS
        .iter()
        .any(|opener| frame.starts_with(&format!(" {opener} ")))
}

fn sentence_confidence(text: &str) -> &'static str {
    if is_nonfact_statement(text) || is_unsettled_claim(text) {
        return "low";
    }
    let lower = text.to_lowercase();
    const HEDGES: [&str; 16] = [
        "maybe",
        "perhaps",
        "possibly",
        "probably",
        "might",
        "could",
        "seems",
        "appears",
        "not sure",
        "unclear",
        "uncertain",
        "i think",
        "we think",
        "as far as i know",
        "not certain",
        "hedged",
    ];
    if HEDGES.iter().any(|hedge| lower.contains(hedge)) {
        "low"
    } else if lower.contains("likely") || lower.contains("should") {
        "medium"
    } else {
        "high"
    }
}

fn is_nonfact_statement(text: &str) -> bool {
    let trimmed = text.trim();
    let lower = trimmed.to_lowercase();
    trimmed.contains('?')
        || lower.starts_with("what ")
        || lower.starts_with("why ")
        || lower.starts_with("how ")
        || lower.starts_with("should ")
        || lower.contains("maybe")
        || lower.contains("perhaps")
        || lower.contains("possibly")
        || lower.contains("not sure")
        || lower.contains("unclear")
        || lower.contains("uncertain")
        || lower.contains("i think")
        || lower.contains("we think")
        || lower.contains("i suggest")
        || lower.contains("we should")
        || lower.contains("temporary")
        || lower.contains("for now")
}

fn is_company_statement(lower: &str) -> bool {
    [
        "architecture decision",
        "architecture direction",
        "chief architect",
        "company policy",
        "organization",
        "company-wide",
        "corporate",
        "product policy",
        "standard",
        "governance",
        "roadmap",
        "company decision",
        "all teams",
        "every team",
        "named authority",
        "steward",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

fn is_codebase_statement(lower: &str) -> bool {
    [
        "repository",
        "codebase",
        "code",
        "function",
        "module",
        "test",
        "tests",
        "build",
        "dependency",
        "dependencies",
        "api",
        "schema",
        "migration",
        "service",
        "scheduler",
        "worker",
        "queue",
        "bug",
        "compiler",
        "type",
        "interface",
        "library",
        "branch",
        "commit",
        "deployment",
        "config",
        "configuration",
        "database",
    ]
    .iter()
    .any(|token| lower.contains(token))
}

/// Split a body into sentences. A sentence ends at `.`, `!` or `?` only when
/// the terminator is followed by whitespace (or the end of the text) so that
/// file names such as `config.py`, decimals and abbreviations do not split;
/// the terminator stays on the sentence so that a question is still a
/// question when its confidence is judged.
pub(crate) fn sentences(body: &str) -> Vec<String> {
    let normalized = body.replace("\r\n", "\n").replace(['\r', '\n'], "\n");
    let mut output = Vec::new();
    let mut current = String::new();
    let characters: Vec<char> = normalized.chars().collect();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character == '\n' {
            push_sentence(&mut output, &current);
            current.clear();
            index += 1;
            continue;
        }
        current.push(character);
        if character == '.' || character == '!' || character == '?' {
            // Swallow a run of terminators (`?!`, `...`) and closing quotes.
            let mut next = index + 1;
            while next < characters.len()
                && matches!(characters[next], '.' | '!' | '?' | '"' | '\'' | ')' | ']')
            {
                current.push(characters[next]);
                next += 1;
            }
            let boundary = next >= characters.len() || characters[next].is_whitespace();
            if boundary {
                push_sentence(&mut output, &current);
                current.clear();
            }
            index = next;
            continue;
        }
        index += 1;
    }
    push_sentence(&mut output, &current);
    output
}

fn push_sentence(output: &mut Vec<String>, sentence: &str) {
    let trimmed = sentence.trim();
    if trimmed.chars().any(char::is_alphabetic) {
        output.push(trimmed.to_owned());
    }
}

fn atom_from_observation(
    map: &Map<String, Value>,
    text: &str,
    confidence: &str,
    model_destinations: Option<&[&str]>,
) -> Value {
    let mut atom = atom_from_observation_base(map, text, confidence);
    if confidence == "low" {
        atom["proposed_destinations"] = json!(["none"]);
    } else if let Some(destinations) = model_destinations {
        let destinations: Vec<String> = destinations
            .iter()
            .filter(|destination| ALLOWED_DESTINATIONS.contains(destination))
            .map(|destination| (*destination).to_owned())
            .collect();
        if !destinations.is_empty() {
            atom["proposed_destinations"] = json!(destinations);
        }
    }
    atom
}

fn atom_from_observation_base(map: &Map<String, Value>, text: &str, confidence: &str) -> Value {
    let observation_id = map
        .get("observation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_kind = map
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let source_identity = map
        .get("source_identity")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let content_digest = map
        .get("content_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let scope = map
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or("unscoped");
    let scan: ScanResult = scanner(text);
    // `hard_block`, not the taints: a scanner error sets it with no taints.
    let hard_block = scan.hard_block;
    let mut taints: Vec<String> = scan
        .taints
        .iter()
        .map(|taint| taint.as_str().to_owned())
        .collect();
    if let Some(taint) = crate::classify::provenance_taint(source_kind) {
        let value = taint.as_str().to_owned();
        if !taints.contains(&value) {
            taints.push(value);
        }
    }
    // The classifier reports semantic destinations only.  Session promotion
    // separately records the privacy-eligible host boundary, so a Personal
    // source can yield a multi-destination prediction without claiming that
    // the raw classifier itself emitted the boundary label.
    let mut destinations: Vec<String> = Vec::new();
    let lower = text.to_lowercase();
    if !hard_block && confidence != "low" && !is_nonfact_statement(text) {
        if is_company_statement(&lower) || scope.contains("company") {
            destinations = vec!["company".to_owned()];
        } else if is_codebase_statement(&lower) || scope.contains("repository") {
            destinations = vec!["codebase".to_owned()];
        } else if is_personal_statement(&lower) {
            destinations = vec!["personal".to_owned()];
        }
    }
    if hard_block || confidence == "low" {
        destinations = vec!["none".to_owned()];
    }
    if destinations.is_empty() {
        destinations.push("none".to_owned());
    }
    let atom_id = format!(
        "atom_{:x}",
        Sha256::digest(format!("{observation_id}\0{text}").as_bytes())
    );
    json!({
        "atom_id": atom_id,
        "observation_id": observation_id,
        "text": text,
        "atom_kind": infer_kind(text),
        "scope": scope,
        "confidence": confidence,
        "proposed_destinations": destinations,
        "taint": taints,
        "provenance": {
            "source_kind": source_kind,
            "source_identity": source_identity,
            "content_digest": content_digest
        },
        "unresolved_uncertainty": if confidence == "low" { "low-confidence shared labels were demoted to none" } else { "" }
    })
}

fn atom_hard_blocked(atom: &Value) -> bool {
    atom.get("taint")
        .and_then(Value::as_array)
        .map(|taints| {
            taints
                .iter()
                .filter_map(Value::as_str)
                .filter_map(crate::scanner::Taint::parse)
                .any(|taint| taint.hard_block())
        })
        .unwrap_or(false)
}

fn is_personal_statement(lower: &str) -> bool {
    [
        " i ",
        "my ",
        " me",
        "myself",
        "yesterday i",
        "last night i",
        "personal anecdote",
        "private atom",
    ]
    .iter()
    .any(|token| lower.starts_with(token.trim_start()) || lower.contains(token))
        || lower.starts_with("i ")
}

fn infer_kind(text: &str) -> &'static str {
    let lower = text.to_lowercase();
    if lower.contains('?')
        || lower.starts_with("what ")
        || lower.starts_with("why ")
        || lower.starts_with("how ")
    {
        "question"
    } else if [
        "must",
        "required",
        "shall",
        "always",
        "never",
        "do not",
        "don't",
        "only",
        "forbid",
        "forbidden",
        "ensure",
    ]
    .iter()
    .any(|token| lower.contains(token))
    {
        "constraint"
    } else if lower.contains("because")
        || lower.contains("rationale")
        || lower.contains("the reason is")
    {
        "rationale"
    } else if [
        "we decided",
        "decision",
        "we choose",
        "we chose",
        "use ",
        "adopt",
        "selected",
        "preferred approach",
        "agreed to",
    ]
    .iter()
    .any(|token| lower.contains(token))
    {
        "decision"
    } else {
        "claim"
    }
}

pub fn validate_output(document: &Value) -> Result<(), ContractError> {
    let map = document
        .as_object()
        .ok_or_else(|| unauthorized("classifier output must be an object"))?;
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["atoms", "classifier_version", "provider"] {
        return Err(unauthorized(
            "classifier output keys violate the strict contract",
        ));
    }
    if !["deterministic", "ollama"].contains(
        &map.get("provider")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return Err(unauthorized(
            "classifier provider is outside the closed vocabulary",
        ));
    }
    let _ = map
        .get("classifier_version")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| unauthorized("classifier_version must be a nonempty string"))?;
    let atoms = map
        .get("atoms")
        .and_then(Value::as_array)
        .ok_or_else(|| unauthorized("atoms must be an array"))?;
    for atom in atoms {
        let atom = atom
            .as_object()
            .ok_or_else(|| unauthorized("each atom must be an object"))?;
        let mut keys: Vec<&str> = atom.keys().map(String::as_str).collect();
        keys.sort_unstable();
        if keys
            != [
                "atom_id",
                "atom_kind",
                "confidence",
                "observation_id",
                "proposed_destinations",
                "provenance",
                "scope",
                "taint",
                "text",
                "unresolved_uncertainty",
            ]
        {
            return Err(unauthorized("atom keys violate the strict contract"));
        }
        for key in [
            "atom_id",
            "observation_id",
            "text",
            "scope",
            "unresolved_uncertainty",
        ] {
            if !atom.get(key).map(Value::is_string).unwrap_or(false) {
                return Err(unauthorized(format!("atom.{key} must be a string")));
            }
        }
        if !ALLOWED_KINDS.contains(
            &atom
                .get("atom_kind")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) || !ALLOWED_CONFIDENCE.contains(
            &atom
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(unauthorized(
                "atom atom_kind or confidence is outside the closed vocabulary",
            ));
        }
        let Some(destinations) = atom.get("proposed_destinations").and_then(Value::as_array) else {
            return Err(unauthorized("atom proposed_destinations must be an array"));
        };
        for destination in destinations {
            if !ALLOWED_DESTINATIONS.contains(&destination.as_str().unwrap_or_default()) {
                return Err(unauthorized(
                    "atom destination is outside the closed vocabulary",
                ));
            }
        }
        let Some(taints) = atom.get("taint").and_then(Value::as_array) else {
            return Err(unauthorized("atom taint must be an array"));
        };
        if taints.iter().any(|value| !value.is_string()) {
            return Err(unauthorized("atom taint entries must be strings"));
        }
        let provenance = atom
            .get("provenance")
            .and_then(Value::as_object)
            .ok_or_else(|| unauthorized("atom provenance must be an object"))?;
        let mut provenance_keys: Vec<&str> = provenance.keys().map(String::as_str).collect();
        provenance_keys.sort_unstable();
        if provenance_keys != ["content_digest", "source_identity", "source_kind"] {
            return Err(unauthorized(
                "atom provenance keys violate the strict contract",
            ));
        }
        for value in provenance.values() {
            if !value.is_string() {
                return Err(unauthorized("atom provenance values must be strings"));
            }
        }
    }
    Ok(())
}

fn invariant(message: impl Into<String>) -> ContractError {
    ContractError::invariant(message)
}

fn unauthorized(message: impl Into<String>) -> ContractError {
    ContractError::integrity(
        "PROCESSOR_UNAUTHORIZED",
        message,
        "The classifier response violated its strict contract; no guess was promoted.",
    )
}

fn unreachable(message: impl Into<String>) -> ContractError {
    ContractError::new(
        "COMPANY_UNREACHABLE",
        message,
        "Start or repair the configured local processor; no fallback guess is permitted.",
        true,
        ExitCode::DependencyUnavailable,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_antigravity_init_event_names_its_conversation() {
        let init = br#"{"event":"init","conversation_id":"98ff4883-8ac5-4c7c-9567-13193d711589","init":{"cwd":"/work/classifier"}}"#;
        assert_eq!(
            init_conversation(init),
            Some((
                "98ff4883-8ac5-4c7c-9567-13193d711589".to_owned(),
                Some("/work/classifier".to_owned())
            ))
        );
        let relative = br#"{"event":"init","conversation_id":"c1","init":{"cwd":"work"}}"#;
        assert_eq!(init_conversation(relative), Some(("c1".to_owned(), None)));
        for other in [
            &br#"{"event":"step_update","conversation_id":"c1"}"#[..],
            br#"{"event":"init","conversation_id":""}"#,
            br#"{"event":"init","conversation_id":"c1 --agent codex"}"#,
            br#"{"event":"init"}"#,
            b"not json",
        ] {
            assert_eq!(
                init_conversation(other),
                None,
                "{}",
                String::from_utf8_lossy(other)
            );
        }
    }

    #[test]
    fn a_slow_registration_never_holds_the_turn() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temporary directory");
        let executable = |name: &str, body: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, body).expect("write fake executable");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            path.display().to_string()
        };
        // Answers at once: `init`, then a schema-checked result.
        let agy = executable(
            "agy",
            concat!(
                "#!/bin/sh\n",
                "read -r _prompt\n",
                "echo '{\"event\":\"init\",\"conversation_id\":\"turn-1\",\"init\":{\"cwd\":\"/\"}}'\n",
                "echo '{\"event\":\"result\",\"result\":{\"conversation_id\":\"turn-1\",\"status\":\"SUCCESS\",",
                "\"structured_output\":{\"atoms\":[{\"id\":\"obs-1\",\"text\":\"Retries back off exponentially.\",",
                "\"destination\":\"codebase\",\"confidence\":\"high\"}]}}}'\n",
            ),
        );
        let kin = executable("kin", "#!/bin/sh\nsleep 30\n");
        let document = json!({"observations": [{
            "observation_id": "obs-1",
            "source_kind": "claude_jsonl",
            "source_identity": "session:test",
            "content_digest": "digest-1",
            "observed_at": "2026-09-17T00:00:00.000Z",
            "disposition": "current",
            "extraction_version": "1",
            "scope": "unscoped",
            "body": "Retries back off exponentially."
        }]});

        let started = std::time::Instant::now();
        let output = antigravity_with(&[agy.as_str()], &[kin.as_str()], "default", &document)
            .expect("the turn's answer");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the answer waited {:?} on a registration that never finishes",
            started.elapsed()
        );
        assert_eq!(
            output["atoms"].as_array().map(Vec::len),
            Some(1),
            "{output}"
        );
    }

    #[test]
    fn a_classifier_turn_is_registered_with_kindex_when_it_is_installed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("temporary directory");
        let calls = dir.path().join("calls");
        let kin = dir.path().join("kin");
        std::fs::write(
            &kin,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", calls.display()),
        )
        .expect("write fake kin");
        std::fs::set_permissions(&kin, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let kin_path = kin.display().to_string();

        register_automation_session(&[kin_path.as_str()], "c1", Some("/work/classifier"))
            .expect("kin is installed")
            .join()
            .expect("registration thread");
        assert_eq!(
            std::fs::read_to_string(&calls).expect("kin ran"),
            "supervisor-register\n--agent\nantigravity\n--session\nc1\n--project\n/work/classifier\n"
        );

        let missing = dir.path().join("absent").display().to_string();
        assert!(
            register_automation_session(&[missing.as_str()], "c1", None).is_none(),
            "no Kindex, no registration"
        );

        // A failing registration is reported, never raised.
        std::fs::write(&kin, "#!/bin/sh\nexit 2\n").expect("rewrite fake kin");
        register_automation_session(&[kin_path.as_str()], "c1", None)
            .expect("kin is installed")
            .join()
            .expect("a failed registration does not panic");
    }

    #[test]
    fn an_ollama_cloud_model_is_its_own_processor() {
        let tags = json!({"models": [
            {"name": "qwen3:0.6b", "model": "qwen3:0.6b"},
            {"name": "glm-5.3:cloud", "remote_model": "glm-5.3", "remote_host": "https://ollama.example"}
        ]});
        assert_eq!(ollama_processor(&tags, "qwen3:0.6b"), Some("local"));
        assert_eq!(ollama_processor(&tags, "qwen3:0.6b:latest"), Some("local"));
        assert_eq!(
            ollama_processor(&tags, "glm-5.3:cloud"),
            Some("ollama-cloud")
        );
        assert_eq!(ollama_processor(&tags, "absent"), None);
    }

    #[test]
    fn a_non_local_processor_runs_only_when_named() {
        assert!(authorize_processor("local", "local", "ollama:qwen3").is_ok());
        assert!(authorize_processor("agy", "agy", "agy:default").is_ok());
        assert!(authorize_processor("ollama-cloud", "ollama-cloud", "ollama:m:cloud").is_ok());
        for (processor, scope) in [
            ("agy", "local"),
            ("agy", "ollama-cloud"),
            ("ollama-cloud", "local"),
        ] {
            let error = authorize_processor(processor, scope, "model").expect_err(processor);
            assert_eq!(error.code, "PROCESSOR_UNAUTHORIZED");
            assert_eq!(error.exit(), 5);
        }
    }

    #[test]
    fn deterministic_provider_routes_mixed_atoms_to_different_destinations() {
        let document = json!({
            "observations": [{
                "observation_id": "obs-mixed",
                "source_kind": "codex_jsonl",
                "source_identity": "source:test",
                "content_digest": "digest",
                "observed_at": "2026-09-08T10:00:00.000Z",
                "disposition": "current",
                "extraction_version": "1",
                "scope": "mixed",
                "body": "I kept my personal notes yesterday. The repository must never commit generated fixtures. Every organization-wide architecture decision must use company review. Maybe we should ask whether this is correct."
            }]
        });
        let output = deterministic(&document).expect("deterministic classifier");
        let atoms = output
            .get("atoms")
            .and_then(Value::as_array)
            .expect("atoms");
        assert_eq!(atoms.len(), 4);
        assert_eq!(
            atoms[0].get("proposed_destinations").unwrap(),
            &json!(["personal"])
        );
        assert_eq!(
            atoms[1].get("proposed_destinations").unwrap(),
            &json!(["codebase"])
        );
        assert_eq!(
            atoms[2].get("proposed_destinations").unwrap(),
            &json!(["company"])
        );
        assert_eq!(
            atoms[3].get("proposed_destinations").unwrap(),
            &json!(["none"])
        );
        assert_eq!(atoms[3].get("confidence").unwrap(), "low");
        assert!(
            atoms
                .iter()
                .any(|atom| atom.get("confidence") == Some(&Value::String("low".to_owned())))
        );
    }

    #[test]
    fn a_models_self_report_cannot_outrank_the_products_reading_of_the_claim() {
        let unsettled = [
            "I wonder whether the lookahead still matters here at all",
            "Try widening the retry budget for today's incident",
            "Is the queue worker still relevant",
            "Someone mentioned the shard rebalance in passing",
            "We should consider moving the scheduler off the shared helper",
            "This might be the wrong module",
        ];
        let settled = [
            "The retry budget must stay inside the repository default",
            "Organization-wide, the audit retention direction is owned by the architecture authority",
            "The queue worker retries failed jobs",
            "A private recollection with no shared content",
            "In this service we implement tenant isolation through the shared helper",
        ];
        for text in unsettled {
            let model_atom = json!({"confidence": "high"});
            assert_eq!(
                normalized_atom_confidence(&model_atom, text),
                "low",
                "unsettled claim kept the model's self-report: {text}"
            );
            assert_eq!(
                normalized_destinations(&model_atom, &json!({}), "low"),
                vec!["none".to_owned()],
                "a low-confidence claim kept a guessed destination: {text}"
            );
        }
        for text in settled {
            let model_atom = json!({"confidence": "high"});
            assert_eq!(
                normalized_atom_confidence(&model_atom, text),
                "high",
                "settled claim was demoted: {text}"
            );
        }
    }

    #[test]
    fn ollama_post_processing_is_self_consistent_across_thirty_sentences() {
        let cases: [(&str, &str); 30] = [
            ("I kept my private note from last night.", "personal"),
            ("My personal reminder is due tomorrow.", "personal"),
            ("I remembered my own login preference.", "personal"),
            ("The company policy requires signed releases.", "company"),
            (
                "Every team must follow the architecture standard.",
                "company",
            ),
            ("The organization roadmap prioritizes safety.", "company"),
            ("Company governance owns this release policy.", "company"),
            (
                "The corporate standard defines review authority.",
                "company",
            ),
            (
                "The repository scheduler must preserve single ownership.",
                "codebase",
            ),
            (
                "The codebase has a regression test for the queue.",
                "codebase",
            ),
            ("The service schema forbids breaking changes.", "codebase"),
            ("This module dependency is pinned.", "codebase"),
            ("The build configuration compiles offline.", "codebase"),
            ("The function signature changed in commit abc.", "codebase"),
            ("The compiler error came from the API.", "codebase"),
            ("Maybe we should try another approach.", "none"),
            ("Could you explain this?", "none"),
            ("Perhaps the option is unclear.", "none"),
            ("I think this might be temporary.", "none"),
            ("Should we ask the architect?", "none"),
            ("This might be a suggestion.", "none"),
            ("Is the current direction certain?", "none"),
            ("That seems possibly true.", "none"),
            ("We may revisit it later.", "none"),
            ("What if the rollout changes?", "none"),
            ("The queue worker retries failed jobs.", "codebase"),
            ("The migration updates the database schema.", "codebase"),
            ("The branch commit failed the test.", "codebase"),
            (
                "The library interface remains backward compatible.",
                "codebase",
            ),
            (
                "The deployment configuration names the service.",
                "codebase",
            ),
        ];
        let observations: Vec<Value> = cases
            .iter()
            .enumerate()
            .map(|(index, (text, _))| {
                json!({
                    "observation_id": format!("obs-{index}"),
                    "source_kind": "codex_jsonl",
                    "source_identity": "source:test",
                    "content_digest": format!("digest-{index}"),
                    "observed_at": "2026-09-08T10:00:00.000Z",
                    "disposition": "current",
                    "extraction_version": "1",
                    "scope": "unscoped",
                    "body": text
                })
            })
            .collect();
        let model_atoms: Vec<Value> = cases
            .iter()
            .enumerate()
            .map(|(index, (text, _))| {
                json!({
                    "observation_id": format!("obs-{index}"),
                    "text": text,
                    "confidence": "high",
                    "proposed_destinations": []
                })
            })
            .collect();
        let input = json!({"observations": observations});
        let candidate = json!({
            "classifier_version": "model-version",
            "provider": "model",
            "atoms": model_atoms
        });
        let output = normalize_ollama_output(&input, &candidate).expect("normalized Ollama output");
        validate_output(&output).expect("normalized output satisfies strict contract");
        let atoms = output
            .get("atoms")
            .and_then(Value::as_array)
            .expect("atoms");
        assert_eq!(atoms.len(), cases.len());
        assert_eq!(output.get("provider").unwrap(), "ollama");
        for (atom, (text, expected)) in atoms.iter().zip(cases) {
            let atom_text = atom.get("text").and_then(Value::as_str).unwrap_or_default();
            let expected_text = text.trim_end_matches(['.', '!', '?']);
            assert_eq!(atom_text.trim_end_matches(['.', '!', '?']), expected_text);
            assert_eq!(
                atom.get("proposed_destinations").unwrap(),
                &json!([expected])
            );
            assert!(
                atom.get("atom_id")
                    .and_then(Value::as_str)
                    .unwrap()
                    .starts_with("atom_")
            );
        }
    }
}
