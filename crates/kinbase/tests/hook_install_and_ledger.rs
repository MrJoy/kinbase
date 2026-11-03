//! Regression probes for two ledger-shaped failures found in a live install:
//! a hook install that replaced every host hook list, and Personal readers
//! that failed a whole read on one unreadable row.
//!
//! Roles collapsed: the lane that wrote the fix wrote these probes. They pin
//! the shape of the defect; they do not establish oracle independence.

mod support;

use kinbase::private::PrivateStore;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use support::SpawnAlone;
use tempfile::TempDir;

fn fake_host(bin: &Path, name: &str, version: &str) {
    fs::create_dir_all(bin).expect("bin dir");
    let path = bin.join(name);
    fs::write(&path, format!("#!/bin/sh\necho '{version}'\n")).expect("write fake host");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod fake host");
}

fn plan(home: &Path, bin: &Path, host: &str, cwd: &Path) -> Value {
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(cwd)
        .args(["hooks", "plan", host, "--json"])
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", home.join(".state"))
        .env("PATH", path)
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run hooks plan");
    assert!(
        output.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("plan JSON")
}

fn planned_content(plan: &Value) -> String {
    plan["files"][0]["content"]
        .as_str()
        .expect("plan content")
        .to_owned()
}

fn commands(document: &Value, event: &str) -> Vec<String> {
    document["hooks"][event]
        .as_array()
        .expect("event array")
        .iter()
        .flat_map(|entry| entry["hooks"].as_array().cloned().unwrap_or_default())
        .filter_map(|handler| handler["command"].as_str().map(str::to_owned))
        .collect()
}

/// The exact standalone dispatcher this build installs for `event`.
fn own_command(host: &str, event: &str) -> String {
    format!(
        "'{}' hooks dispatch {host} {event}",
        env!("CARGO_BIN_EXE_kinbase")
    )
}

fn own(commands: &[String], host: &str, event: &str) -> usize {
    let expected = own_command(host, event);
    commands
        .iter()
        .filter(|command| **command == expected)
        .count()
}

#[test]
fn claude_plan_keeps_foreign_handlers_and_replaces_only_its_own() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fake_host(&bin, "claude", "2.1.272");
    let settings = home.join(".claude").join("settings.json");
    fs::create_dir_all(settings.parent().expect("parent")).expect("claude dir");
    let existing = json!({
        "model": "opus",
        "hooks": {
            "SessionEnd": [{"matcher": "", "hooks": [
                {"type": "command", "command": "python3 ~/archive.py --hook", "timeout": 30000}
            ]}],
            "Stop": [{"matcher": "", "hooks": [
                {"type": "command", "command": "/usr/local/bin/stop.sh"},
                // A custom action that merely ends with a dispatcher is not ours.
                {"type": "command", "command": "audit-hook; '/old/build/kinbase' hooks dispatch claude Stop"}
            ]}],
            "SessionStart": [{"hooks": [
                {"type": "command", "command": "'/old/build/kinbase' hooks dispatch claude SessionStart"}
            ]}],
            "PreCompact": []
        }
    });
    fs::write(&settings, existing.to_string()).expect("write settings");

    let first = plan(&home, &bin, "claude", &repo);
    let document: Value = serde_json::from_str(&planned_content(&first)).expect("planned settings");
    assert_eq!(document["model"], "opus");
    let session_end = commands(&document, "SessionEnd");
    assert!(
        session_end.contains(&"python3 ~/archive.py --hook".to_owned()),
        "foreign SessionEnd handler dropped: {session_end:?}"
    );
    assert_eq!(
        document["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"], 30000,
        "foreign handler must be preserved byte for byte"
    );
    let stop = commands(&document, "Stop");
    assert!(
        stop.contains(&"/usr/local/bin/stop.sh".to_owned()),
        "{stop:?}"
    );
    assert!(
        stop.contains(&"audit-hook; '/old/build/kinbase' hooks dispatch claude Stop".to_owned()),
        "a compound command ending in a dispatcher is someone's action: {stop:?}"
    );
    assert_eq!(own(&stop, "claude", "Stop"), 1, "{stop:?}");
    let session_start = commands(&document, "SessionStart");
    assert_eq!(
        session_start.len(),
        1,
        "stale dispatcher replaced, not stacked: {session_start:?}"
    );
    assert!(!session_start[0].contains("/old/build/"));
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PreCompact",
        "Stop",
        "SessionEnd",
    ] {
        assert_eq!(
            own(&commands(&document, event), "claude", event),
            1,
            "{event}"
        );
    }

    // Applying the planned bytes and planning again changes nothing.
    fs::write(&settings, planned_content(&first)).expect("apply plan");
    let second = plan(&home, &bin, "claude", &repo);
    assert_eq!(planned_content(&second), planned_content(&first));
}

#[test]
fn codex_plan_keeps_foreign_handlers_and_replaces_only_its_own() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fake_host(&bin, "codex", "0.50.0");
    let config = home.join(".codex").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("codex dir");
    fs::write(
        &config,
        "model = \"gpt\"\n\n[hooks]\nStop = [\n  { type = \"command\", command = \"/usr/local/bin/stop.sh\" },\n  { type = \"command\", command = \"'/old/build/kinbase' hooks dispatch codex Stop\" },\n  { type = \"command\", command = \"audit; '/old/build/kinbase' hooks dispatch codex Stop\" },\n]\n",
    )
    .expect("write config");

    let first = plan(&home, &bin, "codex", &repo);
    let table: toml::Value = planned_content(&first).parse().expect("planned toml");
    assert_eq!(table["model"].as_str(), Some("gpt"));
    // Foreign flat entries stay; this program's own is a nested group, the
    // shape Codex runs.
    let document = serde_json::to_value(&table).expect("toml as json");
    let stop: Vec<String> = document["hooks"]["Stop"]
        .as_array()
        .expect("Stop array")
        .iter()
        .filter_map(|handler| handler["command"].as_str().map(str::to_owned))
        .chain(commands(&document, "Stop"))
        .collect();
    assert!(
        stop.contains(&"/usr/local/bin/stop.sh".to_owned()),
        "foreign Stop handler dropped: {stop:?}"
    );
    assert_eq!(own(&stop, "codex", "Stop"), 1, "{stop:?}");
    assert!(
        stop.contains(&"audit; '/old/build/kinbase' hooks dispatch codex Stop".to_owned()),
        "a compound command ending in a dispatcher is someone's action: {stop:?}"
    );
    assert_eq!(
        stop.iter()
            .filter(|command| command.contains("/old/build/"))
            .count(),
        1,
        "only the stale standalone dispatcher is replaced: {stop:?}"
    );

    fs::write(&config, planned_content(&first)).expect("apply plan");
    let second = plan(&home, &bin, "codex", &repo);
    assert_eq!(planned_content(&second), planned_content(&first));
}

#[test]
fn codex_plan_writes_hooks_json_when_the_user_keeps_one() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    fake_host(&bin, "codex", "0.50.0");
    let codex = home.join(".codex");
    fs::create_dir_all(&codex).expect("codex dir");
    let foreign = json!({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [
        {"type": "command", "command": "policy-check --adapter codex", "timeout": 30000}
    ]}]}});
    fs::write(codex.join("hooks.json"), foreign.to_string()).expect("hooks.json");
    // What an earlier build left: a flat entry Codex never ran, beside the
    // user's own settings and trust records.
    fs::write(
        codex.join("config.toml"),
        "model = \"gpt\"\n\n[hooks.state.\"x:pre_tool_use:0:0\"]\ntrusted_hash = \"abc\"\n\n[[hooks.Stop]]\ntype = \"command\"\ncommand = \"'/nix/store/old/bin/.kinbase-wrapped' hooks dispatch codex Stop\"\n",
    )
    .expect("config.toml");

    let first = plan(&home, &bin, "codex", &repo);
    assert_eq!(first["files"][0]["path"], ".codex/hooks.json");
    assert_eq!(first["files"][1]["path"], ".codex/config.toml");
    let toml: toml::Value = first["files"][1]["content"]
        .as_str()
        .expect("toml content")
        .parse()
        .expect("planned toml");
    assert_eq!(toml["model"].as_str(), Some("gpt"));
    assert!(toml["hooks"].get("Stop").is_none(), "stale flat entry kept: {toml}");
    assert_eq!(
        toml["hooks"]["state"]["x:pre_tool_use:0:0"]["trusted_hash"].as_str(),
        Some("abc")
    );
    let document: Value = serde_json::from_str(&planned_content(&first)).expect("hooks.json");
    assert_eq!(document["hooks"]["PreToolUse"][0], foreign["hooks"]["PreToolUse"][0]);
    for event in ["SessionStart", "UserPromptSubmit", "PreToolUse", "PreCompact", "Stop", "SessionEnd"] {
        assert_eq!(own(&commands(&document, event), "codex", event), 1, "{event}");
    }
    fs::write(codex.join("config.toml"), first["files"][1]["content"].as_str().unwrap())
        .expect("apply toml");
    let second = plan(&home, &bin, "codex", &repo);
    assert_eq!(second["files"].as_array().map(Vec::len), Some(1), "nothing left to clear");
}

fn personal_store(root: &Path) -> PrivateStore {
    fs::create_dir_all(root).expect("personal root");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("chmod root");
    PrivateStore::open_personal(root).expect("open personal store")
}

fn poison(root: &Path, session: &str, record: &str) {
    let raw = rusqlite::Connection::open(root.join("kinbase-personal.sqlite3")).expect("open raw");
    raw.execute(
        "INSERT INTO query_log(session_id, record, logged_at) VALUES (?1, ?2, '2026-01-01T00:00:00.000Z')",
        rusqlite::params![session, record],
    )
    .expect("poison row");
}

#[test]
fn query_log_reads_past_unreadable_rows() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("personal");
    let store = personal_store(&root);
    store
        .log_query(Some("session-a"), &json!({"declared_use": "first"}))
        .expect("log first");
    // The exact poison found in a live store: an empty record column.
    poison(&root, "", "");
    poison(&root, "x", "{not json");
    store
        .log_query(Some("session-b"), &json!({"declared_use": "second"}))
        .expect("log second");
    let rows = store.query_log(None).expect("read past poison");
    let uses: Vec<&str> = rows
        .iter()
        .filter_map(|row| row["declared_use"].as_str())
        .collect();
    assert_eq!(uses, vec!["first", "second"]);
}

#[test]
fn query_log_refuses_a_blank_record_and_a_free_text_session() {
    let temp = TempDir::new().expect("tempdir");
    let store = personal_store(&temp.path().join("personal"));
    // A control character fails the canonical text rule; this used to store "".
    let blank = store.log_query(None, &json!({"task": "line one\nline two"}));
    assert!(
        blank.is_err(),
        "a record that cannot be serialised is refused, not blanked"
    );
    let sentence = store.log_query(
        Some("Follow the recorded direction for this ticket"),
        &json!({"ok": true}),
    );
    assert!(
        sentence.is_err(),
        "a sentence is not a host session identifier"
    );
    assert!(store.query_log(None).expect("read").is_empty());
}

#[test]
fn status_survives_a_poisoned_query_log_and_signals_the_skip() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let config_home = home.join(".config");
    let personal = temp.path().join("personal");
    let store = personal_store(&personal);
    drop(store);
    poison(&personal, "", "");
    let config = config_home.join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n",
            personal.display()
        ),
    )
    .expect("write config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status_alone()
            .expect("git init")
            .success()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&repo)
        .args(["status", "--as-of", "2026-09-15T12:00:00.000Z", "--json"])
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run status");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "status must not fail on one bad row: {stderr}"
    );
    assert!(
        stderr.contains("unreadable-ledger-rows"),
        "the skip must be signalled, never silent: {stderr}"
    );
}

/// An isolated host world: HOME, a user config whose Personal root is under
/// the temp dir, and a Git repository to dispatch from.
struct HostWorld {
    home: std::path::PathBuf,
    config_home: std::path::PathBuf,
    personal: std::path::PathBuf,
    repo: std::path::PathBuf,
}

fn host_world(temp: &TempDir) -> HostWorld {
    let home = temp.path().join("home");
    let config_home = home.join(".config");
    let personal = temp.path().join("personal");
    fs::create_dir_all(&personal).expect("personal root");
    fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).expect("chmod personal");
    let config = config_home.join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n",
            personal.display()
        ),
    )
    .expect("write config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = temp.path().join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .status_alone()
            .expect("git init")
            .success()
    );
    HostWorld {
        home,
        config_home,
        personal,
        repo,
    }
}

/// The first observation row with `identity`, once a detached worker has
/// written it.
fn wait_for_observation(personal: &Path, identity: &str) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(text) = fs::read_to_string(personal.join("observations.jsonl"))
            && let Some(row) = text
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|row| row["source_identity"] == identity)
        {
            return row;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no observation with {identity} was written"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn dispatch(world: &HostWorld, event: &str, stdin: &[u8], json: bool) -> std::process::Output {
    use std::io::Write as _;
    let mut args = vec!["hooks", "dispatch", "claude", event];
    if json {
        args.push("--json");
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&world.repo)
        .args(&args)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", &world.config_home)
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn_alone()
        .expect("spawn dispatch");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write stdin");
    child.wait_with_output().expect("dispatch output")
}

#[test]
fn dispatch_accepts_host_envelopes_with_control_characters_and_floats() {
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    let base = json!({
        "session_id": "host-session-1",
        "transcript_path": "/nonexistent/transcript.jsonl",
        "cwd": world.repo.display().to_string(),
        "permission_mode": "bypassPermissions"
    });
    // Stop: the assistant's last message is prose with newlines, a tab and a
    // bidi control, exactly as the host sends it.
    let mut stop = base.clone();
    stop["hook_event_name"] = json!("Stop");
    stop["stop_hook_active"] = json!(false);
    stop["last_assistant_message"] = json!("Done.\n\n- one\n- two\ttabbed \u{202e}reversed");
    let output = dispatch(&world, "Stop", stop.to_string().as_bytes(), true);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "Stop refused: {stderr}");
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("Stop receipt");
    assert_eq!(receipt["checkpointed"], true, "{receipt}");
    assert_eq!(receipt["session_id"], "host-session-1");
    // Nothing was decided, so nothing is recorded.
    assert_eq!(receipt["checkpoint_recorded"], false, "{receipt}");
    assert!(!world.personal.join("session-checkpoints.jsonl").exists());

    // PreToolUse: a multi-line shell command, then an MCP tool whose input
    // carries a float and multi-line prose, as the host sends each of them.
    for (tool_name, tool_input) in [
        (
            "Bash",
            json!({"command": "echo a\necho b", "timeout": 600000}),
        ),
        (
            "mcp__kindex__link",
            json!({"weight": 0.8, "reason": "why\nbecause"}),
        ),
    ] {
        let mut pre = base.clone();
        pre["hook_event_name"] = json!("PreToolUse");
        pre["tool_name"] = json!(tool_name);
        pre["tool_use_id"] = json!("toolu_01");
        pre["tool_input"] = tool_input;
        let output = dispatch(&world, "PreToolUse", pre.to_string().as_bytes(), true);
        assert!(
            output.status.success(),
            "PreToolUse {tool_name} refused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // UserPromptSubmit in the host's non-JSON mode: the prompt goes to the
    // session's classification worker, whose observation carries the
    // session's identity; the stored prompt is the folded text and its digest
    // names that text. With nothing to add, the host gets no output.
    let raw_prompt = "first line\nsecond \u{202e}line";
    let mut prompt = base.clone();
    prompt["hook_event_name"] = json!("UserPromptSubmit");
    prompt["id"] = json!("evt-1");
    prompt["prompt"] = json!(raw_prompt);
    let output = dispatch(
        &world,
        "UserPromptSubmit",
        prompt.to_string().as_bytes(),
        false,
    );
    assert!(
        output.status.success(),
        "UserPromptSubmit refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "no evidence, no context noise: {:?}",
        output.stdout
    );
    let observation = wait_for_observation(&world.personal, "session:host-session-1");
    let folded = kinbase::json::fold_to_canonical_text(raw_prompt);
    assert_eq!(
        observation["content_digest"],
        kinbase::hash::sha256_bytes(folded.as_bytes())
    );

    // The remaining host events carry the same prose and pass too.
    for event in ["SessionStart", "SessionEnd", "PreCompact"] {
        let mut envelope = base.clone();
        envelope["hook_event_name"] = json!(event);
        envelope["last_assistant_message"] = json!("a\nb");
        envelope["trigger"] = json!("manual\n");
        let output = dispatch(&world, event, envelope.to_string().as_bytes(), true);
        assert!(
            output.status.success(),
            "{event} refused: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn dispatch_refuses_dirty_identifiers_and_paths_instead_of_folding_them() {
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    let clean_cwd = world.repo.display().to_string();
    for (field, value) in [
        ("session_id", "abc\ndef"),
        ("cwd", "/tmp/a\tb"),
        ("transcript_path", "/x\u{202e}y.jsonl"),
        ("id", "evt\r1"),
    ] {
        let mut stop = json!({
            "session_id": "host-session-2",
            "cwd": clean_cwd,
            "hook_event_name": "Stop",
            "last_assistant_message": "fine\nprose"
        });
        stop[field] = json!(value);
        let output = dispatch(&world, "Stop", stop.to_string().as_bytes(), false);
        assert_eq!(
            output.status.code(),
            Some(3),
            "dirty {field} must be refused"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(field),
            "the refusal names the field: {stderr:?}"
        );
    }
    assert!(
        !world.personal.join("session-checkpoints.jsonl").exists(),
        "nothing is checkpointed under a rewritten identity"
    );
}

#[test]
fn append_jsonl_refuses_a_record_that_is_not_canonical() {
    let temp = TempDir::new().expect("tempdir");
    let dir = temp.path().join("records");
    fs::create_dir_all(&dir).expect("records dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod records");
    let path = dir.join("ledger.jsonl");
    let refused = kinbase::store::append_jsonl(&path, &json!({"statement": "one\ntwo"}));
    assert!(
        refused.is_err(),
        "a non-canonical record is refused, not blanked"
    );
    assert!(!path.exists(), "nothing was appended: {path:?}");
    kinbase::store::append_jsonl(&path, &json!({"statement": "one two"}))
        .expect("canonical record");
    let text = fs::read_to_string(&path).expect("ledger");
    assert_eq!(text.lines().count(), 1);
    assert!(text.lines().all(|line| !line.trim().is_empty()));
}

#[test]
fn dispatch_refuses_a_malformed_envelope_and_says_so_on_stderr() {
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    let output = dispatch(&world, "Stop", b"not json at all", false);
    assert_eq!(
        output.status.code(),
        Some(3),
        "a malformed envelope is still refused"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("UNSUPPORTED_HOST_VERSION"),
        "the host surfaces stderr, so the reason must be there: {stderr:?}"
    );
    assert!(
        !world.personal.join("session-checkpoints.jsonl").exists(),
        "nothing is checkpointed from a refused envelope"
    );
}

#[test]
fn host_envelope_parser_folds_text_keeps_numbers_and_rejects_duplicates() {
    let value = kinbase::json::parse_host_envelope(
        "{\"a\":\"x\\ny\\u202ez\",\"n\":0.5,\"nested\":{\"k\\tv\":[\"p\\rq\"]}}".as_bytes(),
    )
    .expect("envelope parses");
    assert_eq!(value["a"], "x y z");
    assert_eq!(value["n"], 0.5);
    assert_eq!(value["nested"]["k v"][0], "p q");
    assert!(kinbase::json::parse_host_envelope(b"{\"a\":1,\"a\":2}").is_err());
    assert!(kinbase::json::parse_host_envelope(b"{\"a\":1} trailing").is_err());
    assert!(
        kinbase::json::parse_host_envelope(b"{\"k\\tv\":1,\"k\\nv\":2}").is_err(),
        "keys that fold to the same spelling are a duplicate"
    );
    let dirty = kinbase::json::parse_host_envelope(b"{\"cwd\":\"/a\\tb\",\"prompt\":\"x\\ny\"}");
    assert!(
        dirty.as_ref().is_err_and(|error| error.contains("cwd")),
        "an identifier is refused, not folded: {dirty:?}"
    );
    assert_eq!(
        kinbase::json::fold_to_canonical_text("no controls"),
        "no controls"
    );
}

#[test]
fn checkpoint_streams_only_this_sessions_records_from_shared_ledgers() {
    use std::io::Write as _;
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    let ledger = world.personal.join("observations.jsonl");
    // A quote in the id: escaped on disk, and the marker must spell it the same.
    let session = "host-session-3\"quoted";
    let record = |source: &str, id: &str| json!({"observation_id": id, "source_identity": source, "statement": "x"});
    // Through the canonical writer, as every real record is.
    for value in [
        record(&format!("session:{session}"), "obs_mine"),
        record("session:other", "obs_other"),
        record("source:issue_tracker:abc", "obs_bulk"),
        // The marker quoted inside another field is not this session's record.
        json!({
            "observation_id": "obs_quote",
            "source_identity": "source:x",
            "statement": format!("\"source_identity\":\"session:{session}\"")
        }),
    ] {
        kinbase::store::append_jsonl(&ledger, &value).expect("append");
    }
    // Then two lines no writer would produce: a foreign line that is not
    // UTF-8, and a truncated line carrying this session's marker.
    let mut raw = fs::OpenOptions::new()
        .append(true)
        .open(&ledger)
        .expect("open ledger");
    raw.write_all(b"{\"observation_id\":\"obs_bin\",\"source_identity\":\"session:other\",\"statement\":\"\xff\"}\n")
        .expect("binary line");
    // A large foreign line that is not UTF-8 must cost nothing to skip.
    let mut large = Vec::with_capacity(4 << 20);
    large.extend_from_slice(
        b"{\"observation_id\":\"obs_big\",\"source_identity\":\"session:other\",\"statement\":\"",
    );
    large.resize(4 << 20, 0xff);
    large.extend_from_slice(b"\"}\n");
    raw.write_all(&large).expect("large binary line");
    // Twenty truncated lines of this session's: skipped, counted, sampled.
    for index in 0..20 {
        raw.write_all(
            format!(
                "{{\"observation_id\":\"obs_bad{index}\",\"source_identity\":\"session:{}\",\n",
                session.replace('"', "\\\"")
            )
            .as_bytes(),
        )
        .expect("truncated line");
    }
    drop(raw);

    let stop = json!({
        "session_id": session,
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "Stop"
    });
    let output = dispatch(&world, "Stop", stop.to_string().as_bytes(), true);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let receipt: Value = serde_json::from_slice(&output.stdout).expect("receipt");
    assert_eq!(receipt["observation_count"], 1, "{receipt}");
    assert_eq!(receipt["atom_count"], 0, "{receipt}");
    assert!(
        stderr.contains("unreadable-ledger-rows") && stderr.contains("observations.jsonl"),
        "this session's truncated lines are skipped with a signal: {stderr:?}"
    );
    assert!(
        stderr.contains("\"skipped\":20"),
        "every skipped row is counted: {stderr:?}"
    );
    assert_eq!(
        stderr.matches("\"position\":").count(),
        8,
        "only the first samples are retained: {stderr:?}"
    );
    assert!(
        !stderr.contains("obs_") && !stderr.contains("personal"),
        "the signal carries neither record bytes nor the store's path: {stderr:?}"
    );
}

#[test]
fn a_host_hook_holds_a_candidate_it_cannot_place_and_never_exits_2() {
    use std::io::Write as _;
    // A session outside any Git worktree that has an automatic candidate for
    // a shared destination: this host has nowhere to put it. That is held,
    // not failed — the candidate waits for a later checkpoint and the hook
    // stays quiet. Exit 2 would tell the host to refuse to stop and fire Stop
    // again, so it is never used.
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    let outside = temp.path().join("not-a-repository");
    fs::create_dir_all(&outside).expect("outside dir");
    let canonical = "x";
    let candidate = json!({
        "admission_mode": "automatic",
        "candidate_id": "cand_probe",
        "canonical": canonical,
        "destination": "company:root",
        "payload_digest": kinbase::hash::sha256_text(canonical),
        "session_id": "host-session-4"
    });
    kinbase::store::append_jsonl(&world.personal.join("candidates.jsonl"), &candidate)
        .expect("candidate");
    let stop = json!({
        "session_id": "host-session-4",
        "cwd": outside.display().to_string(),
        "hook_event_name": "Stop",
        "stop_hook_active": false
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&outside)
        .args(["hooks", "dispatch", "claude", "Stop"])
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", &world.config_home)
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn_alone()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stop.to_string().as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(output.status.code(), Some(2), "{stderr}");
    assert!(
        !stderr.contains("REPO_UNCERTIFIED"),
        "an unplaceable candidate is not a refusal to report: {stderr}"
    );
    // Every candidate's outcome still reaches the channel the host shows, and
    // the checkpoint is still written.
    assert!(
        stderr.lines().any(|line| line
            == "admission cand_probe -> company:root: held (no store for it on this host yet)"),
        "{stderr}"
    );
    let checkpoints =
        fs::read_to_string(world.personal.join("session-checkpoints.jsonl")).expect("checkpoint");
    assert!(
        checkpoints.contains("\"candidate_id\":\"cand_probe\""),
        "{checkpoints}"
    );

    // The same refusal from an ordinary command still exits 2.
    let refused = kinbase::error::ContractError::user_action("REPO_UNCERTIFIED", "m", "r");
    assert_eq!(refused.exit(), 2);
    assert_eq!(refused.for_host_hook().exit(), 3);
}

#[test]
fn plan_refuses_a_host_outside_the_configured_range() {
    let temp = TempDir::new().expect("tempdir");
    let home = temp.path().join("home");
    let bin = temp.path().join("bin");
    let config = home.join(".config").join("kinbase");
    fs::create_dir_all(&config).expect("config dir");
    fs::create_dir_all(temp.path().join("personal")).expect("personal");
    fake_host(&bin, "claude", "claude 1.2.3");
    let write_config = |range: &str| {
        let path = config.join("config.toml");
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            format!(
                "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[hosts]\nclaude_version = \"{range}\"\n",
                temp.path().join("personal").display()
            ),
        )
        .expect("config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod config");
    };
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .current_dir(temp.path())
            .args(["hooks", "plan", "claude", "--json"])
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".state"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env_remove("KINBASE_COMPANY_URL")
            .output_alone()
            .expect("run hooks plan")
    };

    write_config(">=9.0.0");
    let refused = run();
    assert_eq!(refused.status.code(), Some(3));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(text.contains("UNSUPPORTED_HOST_VERSION"), "{text}");

    // A component past u64 is a configuration error, not a zero.
    write_config(">=18446744073709551616.0.0");
    let overflowed = run();
    assert!(!overflowed.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&overflowed.stdout),
        String::from_utf8_lossy(&overflowed.stderr)
    );
    assert!(text.contains("CONFIG_INVARIANT"), "{text}");

    write_config(">=1.2.0");
    let planned = run();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );
}

#[test]
fn session_end_does_not_read_the_checkpoint_ledger() {
    use std::io::{Read as _, Seek as _};
    let temp = TempDir::new().expect("tempdir");
    let world = host_world(&temp);
    // A sparse 64 GiB ledger costs no disk, but reading it through takes far
    // longer than the host's 1.5 s SessionEnd budget. Only a checkpoint that
    // never scans the ledger finishes in time.
    let ledger_path = world.personal.join("session-checkpoints.jsonl");
    let ledger = fs::File::create(&ledger_path).expect("ledger");
    fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o600)).expect("chmod ledger");
    let size = 64u64 << 30;
    // A filesystem without sparse files would allocate all 64 GiB; measure
    // free space rather than st_blocks, which some (gVisor) report as the
    // full length even for a hole.
    let free = || {
        let path =
            std::ffi::CString::new(world.personal.as_os_str().as_encoded_bytes()).expect("path");
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::statvfs(path.as_ptr(), &mut stat) },
            0,
            "statvfs"
        );
        stat.f_bavail as u64 * stat.f_frsize as u64
    };
    let free_before = free();
    ledger
        .set_len(size)
        .expect("sparse ledger (this filesystem may not support sparse files)");
    let consumed = free_before.saturating_sub(free());
    assert!(
        consumed < 1 << 30,
        "this filesystem does not support sparse files: the 64 GiB ledger consumed {consumed} bytes"
    );
    // A complete last line, so the checkpoint takes the plain append path
    // rather than the torn-tail repair.
    {
        use std::os::unix::fs::FileExt as _;
        ledger.write_at(b"\n", size - 1).expect("terminate ledger");
    }
    drop(ledger);
    // A candidate for the checkpoint to decide, so it has a record to append
    // to a ledger far too large for a hook to read or index.
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
                "candidate_id": "cand_end",
                "session_id": "host-session-end",
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
    let envelope = json!({
        "session_id": "host-session-end",
        "hook_event_name": "SessionEnd",
        "reason": "exit",
        "transcript_path": "/nonexistent/transcript.jsonl",
        "cwd": world.repo.display().to_string()
    });
    let stderr_path = temp.path().join("session-end.stderr");
    let started = std::time::Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&world.repo)
        .args(["hooks", "dispatch", "claude", "SessionEnd", "--json"])
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", &world.config_home)
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(fs::File::create(&stderr_path).expect("stderr file"))
        .spawn_alone()
        .expect("spawn dispatch");
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(envelope.to_string().as_bytes())
            .expect("write stdin");
    }
    let budget = std::time::Duration::from_millis(1500);
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if started.elapsed() > budget {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "SessionEnd still running after {budget:?}: {}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "SessionEnd refused ({status}): {}",
        fs::read_to_string(&stderr_path).unwrap_or_default()
    );
    // The checkpoint still landed at the end of the ledger, as its own line.
    let mut file = fs::File::open(&ledger_path).expect("reopen ledger");
    file.seek(std::io::SeekFrom::Start(size)).expect("seek");
    let mut tail = String::new();
    file.read_to_string(&mut tail).expect("tail");
    assert!(tail.starts_with('{'), "{tail}");
    assert!(
        tail.contains("\"session_id\":\"host-session-end\""),
        "{tail}"
    );
}
