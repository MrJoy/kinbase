//! A hook installs where the host reads it, answers in the host's shape, and
//! hands prompts to the session they belong to.
//!
//! - install/plan/doctor wrote `$HOME/.claude` even when `CLAUDE_CONFIG_DIR`
//!   named the directory the host reads, and refused a settings file with a
//!   float or a multi-line command as "not strict JSON";
//! - a re-fired Stop (`stop_hook_active`) checkpointed again;
//! - a prompt was recorded as `hook:UserPromptSubmit`, which Stop never
//!   counts and nothing classifies.
//!
//! Roles collapsed: the lane that wrote the fix wrote these probes.

mod support;

use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use support::SpawnAlone;
use tempfile::TempDir;

struct World {
    home: PathBuf,
    personal: PathBuf,
    repo: PathBuf,
    bin: PathBuf,
}

fn world(temp: &TempDir) -> World {
    let home = temp.path().join("home");
    let personal = temp.path().join("personal");
    fs::create_dir_all(&personal).expect("personal");
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).expect("chmod");
    let config = home.join(".config").join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n",
            personal.display()
        ),
    )
    .expect("config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status_alone()
            .expect("git")
            .success()
    );
    let bin = temp.path().join("bin");
    fs::create_dir_all(&bin).expect("bin");
    let claude = bin.join("claude");
    fs::write(&claude, "#!/bin/sh\necho '2.1.272'\n").expect("fake claude");
    fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).expect("chmod claude");
    World {
        home,
        personal,
        repo,
        bin,
    }
}

fn kinbase(world: &World, args: &[&str], envs: &[(&str, &Path)], stdin: &[u8]) -> Output {
    use std::io::Write as _;
    let path = format!(
        "{}:{}",
        world.bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .current_dir(&world.repo)
        .args(args)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", world.home.join(".config"))
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env("PATH", path)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn_alone().expect("spawn kinbase");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin");
    child.wait_with_output().expect("output")
}

fn ok(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

#[test]
fn install_writes_where_claude_config_dir_points() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let config_dir = temp.path().join("claude-config");
    let plan = ok(&kinbase(
        &world,
        &["hooks", "plan", "claude", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    ));
    let settings = config_dir.join("settings.json");
    assert_eq!(
        plan["files"][0]["resolved_path"],
        settings.display().to_string()
    );
    assert_eq!(
        plan["files"][0]["path"],
        settings.display().to_string(),
        "outside HOME: absolute"
    );
    ok(&kinbase(
        &world,
        &["hooks", "install", "claude", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    ));
    assert!(settings.is_file());
    assert!(!world.home.join(".claude").join("settings.json").exists());
    let doctor = kinbase(
        &world,
        &["doctor", "--json"],
        &[("CLAUDE_CONFIG_DIR", &config_dir)],
        b"",
    );
    let text = String::from_utf8_lossy(&doctor.stdout);
    assert!(
        text.contains(&settings.display().to_string()),
        "doctor names the file: {text}"
    );

    let default = ok(&kinbase(
        &world,
        &["hooks", "plan", "claude", "--json"],
        &[],
        b"",
    ));
    assert_eq!(default["files"][0]["path"], ".claude/settings.json");
}

#[test]
fn install_keeps_a_settings_file_with_floats_and_multi_line_commands() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let settings = world.home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().expect("parent")).expect("dir");
    let existing = "{\n  \"model\": \"opus\",\n  \"temperature\": 0.7,\n  \"statusLine\": {\"type\": \"command\", \"command\": \"line one\\nline two \\u202e\"},\n  \"hooks\": {}\n}\n";
    fs::write(&settings, existing).expect("settings");
    ok(&kinbase(
        &world,
        &["hooks", "install", "claude", "--json"],
        &[],
        b"",
    ));
    let written = fs::read_to_string(&settings).expect("settings");
    let document: Value = serde_json::from_str(&written).expect("valid JSON");
    assert_eq!(document["temperature"], json!(0.7));
    assert_eq!(
        document["statusLine"]["command"],
        "line one\nline two \u{202e}"
    );
    let keys: Vec<&String> = document.as_object().expect("object").keys().collect();
    assert_eq!(
        keys,
        ["model", "temperature", "statusLine", "hooks"],
        "key order kept"
    );
    assert!(written.lines().count() > 1, "written for a person to read");
}

#[test]
fn a_refired_stop_does_not_checkpoint_again() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let stop = json!({
        "session_id": "host-session-9",
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "Stop",
        "stop_hook_active": true
    });
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop"],
        &[],
        stop.to_string().as_bytes(),
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!world.personal.join("session-checkpoints.jsonl").exists());
}

#[test]
fn a_prompt_reaches_the_sessions_checkpoint() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let base = json!({"session_id": "host-session-7", "cwd": world.repo.display().to_string()});
    let mut prompt = base.clone();
    prompt["hook_event_name"] = json!("UserPromptSubmit");
    prompt["prompt"] = json!("We decided to keep the retry budget at three attempts.");
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "UserPromptSubmit"],
        &[],
        prompt.to_string().as_bytes(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pending = world.personal.join("pending-observations");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let observed = fs::read_to_string(world.personal.join("observations.jsonl"))
            .map(|text| text.contains("\"source_identity\":\"session:host-session-7\""))
            .unwrap_or(false);
        let drained = fs::read_dir(&pending)
            .map(|entries| entries.count() == 0)
            .unwrap_or(true);
        if observed && drained {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker never finished"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let mut stop = base.clone();
    stop["hook_event_name"] = json!("Stop");
    let receipt = ok(&kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    ));
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert!(
        receipt["atom_count"].as_u64().unwrap_or(0) >= 1,
        "{receipt}"
    );
}

fn pending_dir(world: &World) -> PathBuf {
    world.personal.join("pending-observations")
}

/// A queued prompt as a hook leaves it, with its metadata.
fn queue_entry(
    world: &World,
    name: &str,
    session: &str,
    record: &str,
    queued_ago: i64,
    spawned_ago: i64,
) -> PathBuf {
    let dir = pending_dir(world);
    fs::create_dir_all(&dir).expect("pending dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    let event = dir.join(format!("{name}.jsonl"));
    fs::write(&event, record).expect("event");
    let stamp = |ago: i64| {
        (chrono::Utc::now() - chrono::Duration::seconds(ago))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    };
    let meta = json!({
        "session": session,
        "repo": world.repo.display().to_string(),
        "queued_at": stamp(queued_ago),
        "spawned_at": stamp(spawned_ago),
        "attempts": 0
    });
    fs::write(dir.join(format!("{name}.meta.json")), meta.to_string()).expect("meta");
    event
}

fn prompt_record(text: &str) -> String {
    format!(
        "{}\n",
        json!({"id": "evt-q", "role": "user", "text": text,
               "observed_at": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
               "source_kind": "claude_jsonl"})
    )
}

#[test]
fn a_failed_worker_keeps_the_prompt_for_a_bounded_retry() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let event = queue_entry(&world, "bad", "host-session-3", "not a record\n", 0, 0);
    let event_arg = event.display().to_string();
    for attempt in 1..=3 {
        let output = kinbase(
            &world,
            &[
                "session",
                "observe",
                "host-session-3",
                "--consume",
                "--json",
                "--event",
                &event_arg,
            ],
            &[],
            b"",
        );
        assert!(!output.status.success(), "a malformed event fails");
        if attempt < 3 {
            assert!(event.is_file(), "kept after attempt {attempt}");
            let meta: Value = serde_json::from_slice(
                &fs::read(pending_dir(&world).join("bad.meta.json")).expect("meta"),
            )
            .expect("meta JSON");
            assert_eq!(meta["attempts"], attempt);
        }
    }
    assert!(!event.exists(), "dropped after the last attempt");
    assert!(!pending_dir(&world).join("bad.meta.json").exists());
}

#[test]
fn a_stop_reports_prompts_still_being_classified() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let queued = queue_entry(
        &world,
        "busy",
        "host-session-4",
        &prompt_record("still working"),
        0,
        0,
    );
    // A live worker (this test process) holds it.
    let event = pending_dir(&world).join("busy.working.jsonl");
    fs::rename(&queued, &event).expect("claim");
    let meta_file = pending_dir(&world).join("busy.meta.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_file).unwrap()).unwrap();
    meta["worker_pid"] = json!(std::process::id());
    fs::write(&meta_file, meta.to_string()).unwrap();
    let stop = json!({"session_id": "host-session-4", "cwd": world.repo.display().to_string(),
                      "hook_event_name": "Stop"});
    let started = std::time::Instant::now();
    let receipt = ok(&kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(receipt["pending_observation_count"], 1, "{receipt}");
    assert!(event.is_file(), "a held prompt is left to its worker");
}

#[test]
fn a_prompt_whose_worker_died_is_requeued_as_a_failed_attempt() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let queued = queue_entry(
        &world,
        "lost",
        "host-session-10",
        &prompt_record("lost work"),
        0,
        0,
    );
    fs::rename(&queued, pending_dir(&world).join("lost.working.jsonl")).expect("claim");
    let meta_file = pending_dir(&world).join("lost.meta.json");
    let mut meta: Value = serde_json::from_slice(&fs::read(&meta_file).unwrap()).unwrap();
    meta["worker_pid"] = json!(i32::MAX as u32); // no such process
    fs::write(&meta_file, meta.to_string()).unwrap();
    let stop = json!({"session_id": "host-session-11", "cwd": world.repo.display().to_string(),
                      "hook_event_name": "Stop"});
    kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    );
    assert!(queued.is_file(), "requeued");
    let meta: Value = serde_json::from_slice(&fs::read(&meta_file).unwrap()).unwrap();
    assert_eq!(meta["attempts"], 1);
    assert!(meta["worker_pid"].is_null());
}

#[test]
fn a_stranded_prompt_is_classified_by_the_next_stop() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let event = queue_entry(
        &world,
        "stranded",
        "host-session-5",
        &prompt_record("We chose to keep three retries."),
        600,
        600,
    );
    let expired = queue_entry(
        &world,
        "expired",
        "host-session-6",
        &prompt_record("an old prompt"),
        25 * 3600,
        25 * 3600,
    );
    let stop = json!({"session_id": "host-session-5", "cwd": world.repo.display().to_string(),
                      "hook_event_name": "Stop"});
    kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    );
    assert!(!expired.exists(), "a raw prompt past retention is removed");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while event.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the stranded prompt was never picked up"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let receipt = ok(&kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    ));
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert_eq!(receipt["pending_observation_count"], 0);
}

#[test]
fn the_worker_runs_in_the_repository_the_host_names() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    // The host names a repository this process cannot enter; the prompt is
    // then recorded at once, which shows the named repository was used.
    let prompt = json!({
        "session_id": "host-session-8",
        "cwd": temp.path().join("gone").display().to_string(),
        "hook_event_name": "UserPromptSubmit",
        "prompt": "a prompt for a repository that is not here"
    });
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "UserPromptSubmit"],
        &[],
        prompt.to_string().as_bytes(),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observations =
        fs::read_to_string(world.personal.join("observations.jsonl")).expect("recorded");
    assert!(observations.contains("\"source_identity\":\"session:host-session-8\""));
    assert_eq!(
        fs::read_dir(pending_dir(&world))
            .map(|entries| entries.count())
            .unwrap_or(0),
        0
    );
}

#[test]
fn one_failing_candidate_does_not_end_the_checkpoint() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let session = "host-session-12";
    let canonical = kinbase::json::canonical_text(&json!({
        "destination": "personal",
        "atom_kind": "constraint",
        "scope": "host-session",
        "statement": "Backoff is capped at 30 seconds."
    }));
    let candidate = |id: &str, digest: &str| {
        kinbase::json::canonical_text(&json!({
            "candidate_id": id,
            "session_id": session,
            "admission_mode": "automatic",
            "destination": "personal",
            "principal": "principal-a",
            "canonical": canonical,
            "payload_digest": digest,
            "confidence": 8000
        }))
    };
    // The first candidate (by id) no longer matches its content address.
    fs::write(
        world.personal.join("candidates.jsonl"),
        format!(
            "{}\n{}\n",
            candidate("cand_a", &"0".repeat(64)),
            candidate("cand_b", &kinbase::hash::sha256_text(&canonical))
        ),
    )
    .expect("candidates");

    let stop = json!({
        "session_id": session,
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "Stop",
        "stop_hook_active": false
    });
    let output = kinbase(
        &world,
        &["hooks", "dispatch", "claude", "Stop", "--json"],
        &[],
        stop.to_string().as_bytes(),
    );
    // Every candidate was tried and the checkpoint written; the refusal is
    // still reported (its own exit, never 2).
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("one JSON document");
    let admissions = response["admissions"].as_array().expect("admissions");
    assert_eq!(admissions.len(), 2, "{response}");
    assert_eq!(admissions[0]["candidate_id"], "cand_a");
    assert_eq!(admissions[0]["state"], "failed");
    assert_eq!(admissions[0]["error"]["code"], "DIGEST_MISMATCH");
    assert_eq!(admissions[1]["candidate_id"], "cand_b");
    assert_eq!(admissions[1]["state"], "committed", "{response}");
    assert_eq!(response["admission_failures"], 1);
    assert_eq!(response["checkpointed"], true);
}

#[test]
fn a_later_stop_counts_an_admitted_candidate_instead_of_admitting_it_again() {
    // Every Stop used to admit every automatic candidate of the session again
    // and list each receipt in its checkpoint, so checkpoints grew with the
    // session and the ledger with its square.
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let session = "host-session-13";
    let canonical = kinbase::json::canonical_text(&json!({
        "destination": "personal",
        "atom_kind": "constraint",
        "scope": "host-session",
        "statement": "Retries stop after five attempts."
    }));
    fs::write(
        world.personal.join("candidates.jsonl"),
        format!(
            "{}\n",
            kinbase::json::canonical_text(&json!({
                "candidate_id": "cand_c",
                "session_id": session,
                "admission_mode": "automatic",
                "destination": "personal",
                "principal": "principal-a",
                "canonical": canonical,
                "payload_digest": kinbase::hash::sha256_text(&canonical),
                "confidence": 8000
            }))
        ),
    )
    .expect("candidates");
    let stop = json!({
        "session_id": session,
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "Stop",
        "stop_hook_active": false
    });
    let dispatch = || {
        ok(&kinbase(
            &world,
            &["hooks", "dispatch", "claude", "Stop", "--json"],
            &[],
            stop.to_string().as_bytes(),
        ))
    };

    let first = dispatch();
    assert_eq!(first["admissions"][0]["candidate_id"], "cand_c", "{first}");
    assert_eq!(first["admissions"][0]["state"], "committed", "{first}");
    assert_eq!(first["admissions_settled"], 0, "{first}");
    let decisions = fs::read_to_string(world.personal.join("proposal-decisions.jsonl"))
        .expect("the admission is decided");

    let second = dispatch();
    assert_eq!(second["admissions"], json!([]), "{second}");
    assert_eq!(second["admissions_settled"], 1, "{second}");
    assert_eq!(second["admission_failures"], 0, "{second}");
    assert_eq!(second["checkpointed"], true, "{second}");
    assert_eq!(
        fs::read_to_string(world.personal.join("proposal-decisions.jsonl")).expect("decisions"),
        decisions,
        "nothing is decided twice"
    );
    let checkpoints = fs::read_to_string(world.personal.join("session-checkpoints.jsonl"))
        .expect("checkpoints");
    let lines: Vec<&str> = checkpoints.lines().collect();
    assert_eq!(lines.len(), 2, "{checkpoints}");
    assert!(lines[0].contains("\"candidate_id\":\"cand_c\""));
    assert!(!lines[1].contains("cand_c"), "{}", lines[1]);
}

#[test]
fn a_precompact_checkpoints_the_session_and_allows_the_compaction() {
    let temp = TempDir::new().expect("tempdir");
    let world = world(&temp);
    let compact = json!({
        "session_id": "host-session-compact",
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "PreCompact",
        "trigger": "auto"
    });
    let receipt = ok(&kinbase(
        &world,
        &["hooks", "dispatch", "claude", "PreCompact", "--json"],
        &[],
        compact.to_string().as_bytes(),
    ));
    assert_eq!(receipt["compact_allowed"], true, "{receipt}");
    assert_eq!(receipt["checkpointed"], true, "{receipt}");
    let ledger = fs::read_to_string(world.personal.join("session-checkpoints.jsonl"))
        .expect("the checkpoint is written");
    assert!(ledger.contains("\"session_id\":\"host-session-compact\""));
}
