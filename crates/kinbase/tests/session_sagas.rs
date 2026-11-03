//! Session admissions and fan-out sagas as a user runs them.
//!
//! - A message holding hard-blocking material yields no candidate at all.
//! - Outside a certified repository a Codebase-routed atom is not an error.
//! - `status` closes only its own repository's overdue apologies, writes the
//!   terminal event at the repository root, and the orphaned claim is
//!   withdrawn by the reducer.

mod support;

use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use support::SpawnAlone;
use tempfile::TempDir;

fn private_write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("open private file");
    file.write_all(bytes).expect("write private file");
}

fn jsonl(values: &[Value]) -> Vec<u8> {
    values
        .iter()
        .map(|value| format!("{}\n", kinbase::json::canonical_text(value)))
        .collect::<String>()
        .into_bytes()
}

fn now() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

fn observe(temp: &Path, text: &str) -> Value {
    observe_with(temp, text, None)
}

/// `session observe` of one message, optionally under a user config whose
/// scanner registry lists `canary`.
fn observe_with(temp: &Path, text: &str, canary: Option<&str>) -> Value {
    let home = temp.join("home");
    let state = temp.join("state");
    let workdir = temp.join("work");
    for directory in [&home, &state, &workdir] {
        fs::create_dir_all(directory).expect("dir");
    }
    if let Some(canary) = canary {
        let config = home.join(".config/kinbase");
        let personal = temp.join("personal");
        fs::create_dir_all(&personal).expect("personal");
        private_write(
            &config.join("canaries.txt"),
            format!("{canary}\n").as_bytes(),
        );
        private_write(
            &config.join("config.toml"),
            format!(
                "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[scanner]\ncanary_file = \"{}\"\n",
                personal.display(),
                config.join("canaries.txt").display()
            )
            .as_bytes(),
        );
    }
    let event = temp.join("event.jsonl");
    fs::write(
        &event,
        jsonl(&[json!({"id": "m1", "role": "user", "text": text,
                       "observed_at": now(), "source_kind": "codex_jsonl"})]),
    )
    .expect("event");
    let output = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&workdir)
        .args(["session", "observe", "session-1", "--json", "--event"])
        .arg(&event)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_STATE_HOME", &state)
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run kinbase");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    serde_json::from_slice(&output.stdout).expect("observe JSON")
}

#[test]
fn a_message_with_a_secret_yields_no_candidate_at_all() {
    let clean = TempDir::new().expect("tempdir");
    let observed = observe(
        clean.path(),
        "The retry scheduler must cap backoff at 30 seconds.",
    );
    assert_eq!(observed["status"], "observed");
    assert!(
        observed["candidate_count"].as_u64().unwrap_or(0) >= 1,
        "{observed}"
    );

    let tainted = TempDir::new().expect("tempdir");
    let observed = observe(
        tainted.path(),
        "The retry scheduler must cap backoff at 30 seconds. My password: hunter2hunter2",
    );
    assert_eq!(observed["candidate_count"], 0, "{observed}");
    assert_eq!(observed["admissions"], json!([]));
    let atoms = fs::read_to_string(
        tainted
            .path()
            .join("state/kinbase/codebase-personal/atoms.jsonl"),
    )
    .expect("atoms ledger");
    for line in atoms.lines() {
        let atom: Value = serde_json::from_str(line).expect("atom");
        assert_eq!(atom["hard_blocked"], true, "{atom}");
        assert_eq!(atom["eligible_destinations"], json!([]), "{atom}");
    }
}

#[test]
fn a_registered_canary_blocks_the_whole_message() {
    let temp = TempDir::new().expect("tempdir");
    let observed = observe_with(
        temp.path(),
        "The retry scheduler must cap backoff at 30 seconds. Project kxbluefalcon41 ships Friday.",
        Some("kxbluefalcon41"),
    );
    assert_eq!(observed["candidate_count"], 0, "{observed}");
}

struct Certified {
    _temp: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    personal: PathBuf,
    repo: PathBuf,
    maintainer: PrivateKey,
}

const REPOSITORY: &str = "01234567-89ab-cdef-0123-456789abcdef";
const OTHER_REPOSITORY: &str = "fedcba98-7654-3210-fedc-ba9876543210";

fn certified() -> Certified {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path();
    let home = root.join("home");
    let config_home = root.join("config-home");
    let config = config_home.join("kinbase");
    let personal = root.join("personal");
    let repo = root.join("repository");
    for directory in [&home, &config, &personal] {
        fs::create_dir_all(directory).expect("dir");
    }
    let root_key = PrivateKey::generate();
    let maintainer = PrivateKey::generate();
    private_write(
        &config.join("root-public.key"),
        format!("{}\n", root_key.public().to_hex()).as_bytes(),
    );
    private_write(&config.join("facts.token"), b"facts-token\n");
    private_write(
        &config.join("maintainer.key"),
        format!("{}\n", maintainer.to_seed_text()).as_bytes(),
    );
    let quoted = |path: &Path| format!("\"{}\"", path.display());
    private_write(
        &config.join("config.toml"),
        format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = {}\n\n[company]\nurl = \"http://127.0.0.1:1\"\nfacts_token_file = {}\nroot_public_key_file = {}\ncache_root = {}\nmaintainer_key_file = {}\n",
            quoted(&personal),
            quoted(&config.join("facts.token")),
            quoted(&config.join("root-public.key")),
            quoted(&root.join("company-cache")),
            quoted(&config.join("maintainer.key")),
        )
        .as_bytes(),
    );
    let git = Command::new("git")
        .args(["init", "--initial-branch=main"])
        .arg(&repo)
        .output_alone()
        .expect("git init");
    assert!(git.status.success());
    fs::create_dir_all(repo.join("src")).expect("subdirectory");
    let certificate = root_key
        .sign_document(
            "repo-certificate",
            &json!({
                "schema": "kinbase-repo-certificate/1",
                "repository_uuid": REPOSITORY,
                "issued_at": "2026-09-07T12:00:00.000Z",
                "company_id": "company-test"
            }),
        )
        .expect("certificate");
    let certificate_file = root.join("certificate.json");
    private_write(
        &certificate_file,
        kinbase::json::canonical_text(&certificate).as_bytes(),
    );
    let init = Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(&repo)
        .args(["repo", "init", "--json", "--repo"])
        .arg(&repo)
        .arg("--certificate")
        .arg(&certificate_file)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config_home)
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("repo init");
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    Certified {
        _temp: temp,
        home,
        config_home,
        personal,
        repo,
        maintainer,
    }
}

fn status_from(world: &Certified, directory: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kinbase"))
        .current_dir(directory)
        .args(["status", "--json", "--repo"])
        .arg(directory)
        .env("HOME", &world.home)
        .env("XDG_CONFIG_HOME", &world.config_home)
        .env_remove("KINBASE_COMPANY_URL")
        .output_alone()
        .expect("run kinbase status")
}

/// A maintainer-signed Codebase claim, as a committed fan-out sibling
/// leaves it.
fn plant_orphan(world: &Certified) -> (String, String) {
    let statement = "The retry scheduler caps backoff at 30 seconds.";
    let fact_id = kinbase::model::fact_id("codebase", "host-session", statement);
    let logical_key = kinbase::model::logical_key("codebase", "host-session", &fact_id);
    let asserted_at = "2026-09-10T00:00:00.000Z";
    let event_id = kinbase::model::event_id(
        &fact_id,
        &kinbase::model::semantic_digest(statement),
        asserted_at,
        &world.maintainer.public().to_hex(),
    );
    let document = json!({
        "schema": kinbase::model::EVENT_SCHEMA,
        "event_id": event_id,
        "store_kind": "codebase",
        "authority_id": "repository-maintainer",
        "authority_scope": "host-session",
        "repository_id": REPOSITORY,
        "fact_id": fact_id,
        "logical_key": logical_key,
        "atom_kind": "constraint",
        "scope": "host-session",
        "statement": statement,
        "evidence_refs": ["cand_orphan"],
        "asserted_at": asserted_at,
        "effective_from": asserted_at,
        "disposition": "current",
        "distortion": {"trigger": "dependent decision", "loss_if_absent": 8000, "rationale": "test"},
        "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
        "company_refs": [], "authority_snapshot_cursor": "0", "confidence": 8000,
        "standing": "present", "provenance": "human"
    });
    let signed = world
        .maintainer
        .sign_document("fact-event", &document)
        .expect("sign");
    let event = kinbase::model::FactEvent::from_value(&signed).expect("event");
    kinbase::store::write_content_addressed_event(&world.repo.join(".kin"), &event)
        .expect("write event");
    (event_id, logical_key)
}

fn apology(id: &str, repository: &str, orphan: &str, logical_key: &str) -> Value {
    json!({
        "apology_id": id,
        "candidate_id": format!("cand_{id}"),
        "state": "awaiting_reconcile_or_abandon",
        "committed_destination": format!("codebase:{repository}"),
        "repository_uuid": repository,
        "response_due_at": "2026-09-11T00:00:00.000Z",
        "closing_authority": format!("maintainer-of-{id}"),
        "closing_authority_role": "repository-maintainer",
        "orphaned_event_id": orphan,
        "orphaned_logical_key": logical_key,
        "unknown_id": format!("unknown_{id}")
    })
}

fn events_under(root: &Path) -> Vec<Value> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(events_under(&path));
        } else if path
            .extension()
            .is_some_and(|extension| extension == "json")
            && let Ok(value) = serde_json::from_slice(&fs::read(&path).expect("read"))
        {
            found.push(value);
        }
    }
    found
}

#[test]
fn status_closes_only_its_own_overdue_apologies_at_the_repository_root() {
    let world = certified();
    let (orphan, logical_key) = plant_orphan(&world);
    private_write(
        &world.personal.join("apologies.jsonl"),
        &jsonl(&[
            apology("apology_here", REPOSITORY, &orphan, &logical_key),
            apology(
                "apology_elsewhere",
                OTHER_REPOSITORY,
                "event_x",
                "logical_x",
            ),
        ]),
    );

    // Company is deliberately unreachable: the report is still printed, with
    // the degraded-safe exit.
    let subdirectory = world.repo.join("src");
    let output = status_from(&world, &subdirectory);
    assert_eq!(
        output.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("orphan-abandonment-failed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !subdirectory.join(".kin").exists(),
        "a stray .kin tree was written in the subdirectory"
    );

    let terminal: Vec<Value> = events_under(&world.repo.join(".kin/events"))
        .into_iter()
        .filter(|event| event["disposition"] == "orphan_abandoned")
        .collect();
    assert_eq!(terminal.len(), 1, "{terminal:?}");
    assert_eq!(terminal[0]["repository_id"], REPOSITORY);
    assert_eq!(terminal[0]["apology_id"], "apology_here");
    assert_eq!(terminal[0]["parents"], json!([orphan]));

    let apologies = fs::read_to_string(world.personal.join("apologies.jsonl")).expect("apologies");
    let abandoned: Vec<String> = apologies
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("apology"))
        .filter(|record| record["state"] == "abandoned")
        .map(|record| record["apology_id"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(abandoned, ["apology_here"]);

    // The reducer withdraws the orphaned claim, and the report says so.
    let report: Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    let row = report["events"]
        .as_array()
        .expect("events")
        .iter()
        .find(|event| event["disposition"] == "orphan_abandoned")
        .expect("terminal event row")
        .clone();
    assert_eq!(
        row["unresponsive_closing_authority"],
        "maintainer-of-apology_here"
    );
    assert_eq!(row["fact_state"], "withdrawn", "{row}");
    // The saga ledger, not the event, says the saga was abandoned.
    assert_eq!(row["saga_state"], "abandoned", "{row}");
    assert_eq!(row["apology_id"], "apology_here", "{row}");
    assert!(
        report["facts"]
            .as_array()
            .expect("facts")
            .iter()
            .all(|fact| fact["event_id"] != json!(orphan) || fact["state"] != "current"),
        "the orphaned claim is still current"
    );
    // The other repository's apology is not this repository's to count.
    assert_eq!(report["pending_orphans"], 0);

    // A second report closes nothing twice.
    let again = status_from(&world, &world.repo);
    assert_eq!(again.status.code(), Some(3));
    let terminal = events_under(&world.repo.join(".kin/events"))
        .into_iter()
        .filter(|event| event["disposition"] == "orphan_abandoned")
        .count();
    assert_eq!(terminal, 1);
}
