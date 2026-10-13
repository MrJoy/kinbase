//! Known secrets from the user's env files become `$NAME` before Kinbase
//! writes, signs or prints them, and nothing a repository controls can turn
//! that off.
//!
//! Every value here is synthetic. The probes read no real env file: the
//! "profile" is a file this test writes under a temp dir.

mod support;

use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use support::SpawnAlone;
use tempfile::TempDir;

/// A synthetic secret; it must never reach a file Kinbase writes.
const SECRET: &str = "fake-tok-7Qz9-NOT-REAL";
const NAME: &str = "FAKE_API_TOKEN";

struct World {
    _temp: TempDir,
    root: PathBuf,
    home: PathBuf,
    repo: PathBuf,
    secrets: PathBuf,
}

fn world(repo_config: Option<&str>) -> World {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().canonicalize().expect("canonical temp");
    let home = root.join("home");
    let personal = root.join("personal");
    let secrets = root.join("secrets");
    for dir in [&personal, &secrets] {
        fs::create_dir_all(dir).expect("dir");
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    fs::write(
        secrets.join("profile"),
        format!("# synthetic\nexport {NAME}=\"{SECRET}\"\nexport EDITOR=vim-not-a-secret\n"),
    )
    .expect("profile");
    let config = home.join(".config").join("kinbase").join("config.toml");
    fs::create_dir_all(config.parent().expect("parent")).expect("config dir");
    fs::write(
        &config,
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[secret_mask]\nfiles = [\"{}\", \"{}\"]\n",
            personal.display(),
            secrets.join("profile").display(),
            secrets.join("absent").display(),
        ),
    )
    .expect("config");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("chmod config");
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("repo");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .env("HOME", &home)
            .status_alone()
            .expect("git")
            .success()
    );
    if let Some(text) = repo_config {
        fs::create_dir_all(repo.join(".kin")).expect(".kin");
        fs::write(repo.join(".kin").join("kinbase.toml"), text).expect("repo config");
    }
    World {
        _temp: temp,
        root,
        home,
        repo,
        secrets,
    }
}

fn kinbase(world: &World, args: &[&str], stdin: &[u8]) -> Output {
    use std::io::Write as _;
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .current_dir(&world.repo)
        .args(args)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", world.home.join(".config"))
        .env("XDG_STATE_HOME", world.home.join(".state"))
        .env_remove("KINBASE_COMPANY_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn_alone().expect("spawn kinbase");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("stdin");
    child.wait_with_output().expect("output")
}

/// Every file under `dir` but the synthetic env files, as bytes.
fn written(dir: &Path, skip: &Path, found: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.starts_with(skip) || path.ends_with(".git") {
            continue;
        }
        if path.is_dir() {
            written(&path, skip, found);
        } else if let Ok(bytes) = fs::read(&path) {
            found.push((path, bytes));
        }
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Nothing Kinbase wrote holds the secret, and something it wrote holds the
/// name in its place (a scan that found no write proves nothing).
fn assert_masked_at_rest(world: &World) {
    let mut files = Vec::new();
    written(&world.root, &world.secrets, &mut files);
    let leaked: Vec<&PathBuf> = files
        .iter()
        .filter(|(_, bytes)| contains(bytes, SECRET))
        .map(|(path, _)| path)
        .collect();
    assert!(leaked.is_empty(), "the secret was written to {leaked:?}");
    assert!(
        files
            .iter()
            .any(|(_, bytes)| contains(bytes, &format!("${NAME}"))),
        "no write carried the masked name; the probe is vacuous"
    );
}

fn prompt(world: &World, session: &str) -> Output {
    let envelope = json!({
        "session_id": session,
        "cwd": world.repo.display().to_string(),
        "hook_event_name": "UserPromptSubmit",
        "prompt": format!("Deploy with {SECRET} please; the token is {SECRET}.")
    });
    kinbase(
        world,
        &["hooks", "dispatch", "claude", "UserPromptSubmit", "--json"],
        envelope.to_string().as_bytes(),
    )
}

#[test]
fn a_prompt_is_masked_before_it_is_queued_or_answered() {
    let world = world(None);
    let output = prompt(&world, "mask-session-1");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the hook failed: {stderr}");
    // The missing reference file is reported once, by kind, and is not fatal.
    assert_eq!(
        stderr.matches("secret-mask-file-unreadable").count(),
        1,
        "{stderr}"
    );
    assert!(
        !contains(&output.stdout, SECRET),
        "the hook echoed the secret"
    );
    assert!(
        !contains(&output.stderr, SECRET),
        "stderr carried the secret"
    );
    assert_masked_at_rest(&world);
}

#[test]
fn a_projection_prints_and_logs_the_name_not_the_value() {
    let world = world(None);
    // An uncertified repository's trust context replays its recorded clock.
    let local = world.repo.join(".kin").join("local");
    fs::create_dir_all(&local).expect(".kin/local");
    fs::write(local.join("proof-clock"), "2026-09-01T00:00:00.000Z\n").expect("proof clock");
    let task = format!("Rotate {SECRET} before Friday");
    let output = kinbase(
        &world,
        &[
            "project",
            "--json",
            "--task",
            &task,
            "--decision",
            "rotate",
            "--as-of",
            "2026-09-01T00:00:00.000Z",
        ],
        b"",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "project failed: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !stdout.contains(SECRET),
        "the projection printed the secret"
    );
    assert!(stdout.contains(&format!("${NAME}")), "{stdout}");
    assert_masked_at_rest(&world);
}

#[test]
fn a_repository_cannot_turn_masking_off() {
    // A repository config naming `secret_mask` is refused outright: its key
    // set is closed, so it cannot set, narrow or disable the mask.
    let named = world(Some(
        "schema_version = \"kinbase-repo/1\"\nrepository_uuid_hint = \"00000000-0000-4000-8000-000000000001\"\nsafe_name = \"probe\"\ndomains = []\n\n[secret_mask]\nfiles = []\n",
    ));
    let status = kinbase(&named, &["status", "--json"], b"");
    assert!(!status.status.success(), "a repository named secret_mask");
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("unknown key `secret_mask`"),
        "{}",
        String::from_utf8_lossy(&status.stdout)
    );
    // A free-form local policy that says "off" means nothing to the mask.
    let policy = world(Some(
        "schema_version = \"kinbase-repo/1\"\nrepository_uuid_hint = \"00000000-0000-4000-8000-000000000002\"\nsafe_name = \"probe\"\ndomains = []\n\n[local_policy]\nsecret_mask = \"off\"\nsecret_mask_files = \"\"\n",
    ));
    let output = prompt(&policy, "mask-session-2");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_masked_at_rest(&policy);
}

/// The one in-process probe in this binary: it installs the process-wide
/// mask, so nothing else here may run in this process.
#[test]
fn an_event_is_masked_before_it_is_signed() {
    let world = world(None);
    // SAFETY: the only test in this binary that touches the process
    // environment; the others pass theirs to a child explicitly.
    unsafe {
        std::env::set_var("HOME", &world.home);
        std::env::set_var("XDG_CONFIG_HOME", world.home.join(".config"));
    }
    let user = kinbase::config::load_user_config()
        .expect("config loads")
        .expect("config exists");
    assert!(user.secret_mask.is_some());
    let key = kinbase::crypto::PrivateKey::generate();

    let mut fact: kinbase::model::FactEvent = serde_json::from_value(json!({
        "schema": kinbase::model::EVENT_SCHEMA,
        "event_id": "evt_mask_probe",
        "store_kind": "codebase",
        "authority_id": "repository-maintainer",
        "authority_scope": "repository",
        "fact_id": "fact_mask_probe",
        "logical_key": "probe/secret",
        "atom_kind": "observation",
        "scope": "repository",
        "statement": format!("CI reads {SECRET} from the vault"),
        "evidence_refs": [format!("https://ci.example.test/?token={SECRET}")],
        "asserted_at": "2026-09-01T00:00:00.000Z",
        "effective_from": "2026-09-01T00:00:00.000Z",
        "disposition": "current",
        "distortion": {"trigger": "deploy", "loss_if_absent": 5000, "rationale": format!("losing {SECRET} breaks deploys")},
        "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
        "company_refs": [],
        "authority_snapshot_cursor": "0",
        "signer": "",
        "signature": ""
    }))
    .expect("fact event");
    fact.sign(&key).expect("sign");
    let signed = kinbase::json::canonical_bytes(&fact.document());
    assert!(
        !contains(&signed, SECRET),
        "the secret entered a signed fact"
    );
    assert_eq!(fact.statement, format!("CI reads ${NAME} from the vault"));
    assert_eq!(
        fact.event_id, "evt_mask_probe",
        "an identifier was rewritten"
    );
    assert!(
        fact.verify_signature().is_some(),
        "the masked document does not verify"
    );
    assert_eq!(fact.digest(), kinbase::hash::sha256_bytes(&signed));

    let mut unknown = kinbase::model::UnknownEvent::new(
        "codebase",
        None,
        "repository-maintainer",
        "repository",
        "probe/unknown",
        "repository",
        "deploy",
        "maintainer",
        "maintainer",
        &format!("Is {SECRET} still valid?"),
        5000,
        "2026-09-01T00:00:00.000Z",
        "2026-09-08T00:00:00.000Z",
        "block_dependent_decision",
        "0",
    );
    unknown.sign(&key).expect("sign");
    let signed = kinbase::json::canonical_bytes(&unknown.document());
    assert!(
        !contains(&signed, SECRET),
        "the secret entered a signed unknown"
    );
    assert_eq!(unknown.question, format!("Is ${NAME} still valid?"));
    assert!(unknown.verify_signature().is_some());
}
