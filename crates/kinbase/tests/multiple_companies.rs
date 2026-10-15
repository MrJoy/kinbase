//! One person, several Companies (`[companies.<name>]`, candidate amendment
//! 004). Each probe runs two real Company services and one launcher config
//! naming both, and asserts the property the feature exists for: a
//! repository is served by the one Company the evidence on this machine
//! points at, and anything less certain is a refusal that never shows one
//! organization's name, endpoint or knowledge to another's session.

mod support;

use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use support::SpawnAlone;
use tempfile::TempDir;

// Distinctive so the disclosure probe can look for them in hook output.
const ALPHA: &str = "zephyrcanary";
const BETA: &str = "quillcanary";

struct Service {
    child: Child,
    url: String,
    dir: PathBuf,
    company_id: String,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

fn start_company(base: &Path, name: &str) -> Service {
    let dir = base.join(format!("service-{name}"));
    private_dir(&dir);
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .unwrap()
        .port();
    let company_id = format!("cid-{name}");
    let config = dir.join("kinbased.toml");
    write_private(
        &config,
        format!(
            "schema_version = \"1\"\n\
             company_id = \"{company_id}\"\n\
             sqlite_path = \"{dir}/company.sqlite3\"\n\
             bind = \"127.0.0.1:{port}\"\n\
             root_key_file = \"{dir}/company-root.key\"\n\
             facts_token_file = \"{dir}/facts.token\"\n\
             admin_token_file = \"{dir}/admin.token\"\n\
             auth_failures_per_minute = 100\n\
             default_fact_freshness_seconds = 3600\n\
             candidate_lifetime_seconds = 900\n\
             clock_skew_seconds = 300\n\
             nonce_retention_seconds = 604800\n",
            dir = dir.display(),
        )
        .as_bytes(),
    );
    let isolated = |command: &mut Command| {
        command
            .env("HOME", &dir)
            .env("XDG_CONFIG_HOME", dir.join("config"))
            .env("XDG_STATE_HOME", dir.join("state"))
            .env_remove("KINBASE_COMPANY_URL");
    };
    let mut init = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    init.args(["company", "init", "--config"]).arg(&config);
    isolated(&mut init);
    let output = init.output_alone().unwrap();
    assert!(output.status.success(), "company init: {output:?}");
    let mut serve = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    serve
        .args(["company", "serve", "--json", "--config"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    isolated(&mut serve);
    let mut child = serve.spawn_alone().unwrap();
    let mut banner = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut banner)
        .unwrap();
    assert!(banner.contains("company-serving"), "banner: {banner}");
    Service {
        child,
        url: format!("http://127.0.0.1:{port}"),
        dir,
        company_id,
    }
}

struct World {
    temp: TempDir,
    alpha: Service,
    beta: Service,
    alpha_name: String,
    beta_name: String,
}

impl World {
    fn new() -> Self {
        Self::named(ALPHA, BETA)
    }

    fn named(alpha_name: &str, beta_name: &str) -> Self {
        let temp = TempDir::new().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let alpha = start_company(temp.path(), alpha_name);
        let beta = start_company(temp.path(), beta_name);
        let world = Self {
            temp,
            alpha,
            beta,
            alpha_name: alpha_name.to_owned(),
            beta_name: beta_name.to_owned(),
        };
        private_dir(&world.config_dir());
        private_dir(&world.temp.path().join("personal"));
        world.write_config("");
        world
    }

    fn config_dir(&self) -> PathBuf {
        self.temp.path().join("config-home").join("kinbase")
    }

    fn company_table(&self, name: &str, service: &Service, hints: &str) -> String {
        format!(
            "[companies.{name}]\n\
             url = \"{url}\"\n\
             facts_token_file = \"{dir}/facts.token\"\n\
             admin_token_file = \"{dir}/admin.token\"\n\
             root_public_key_file = \"{dir}/company-root.pub\"\n\
             cache_root = \"{cache}\"\n\
             discovery_hints = [{hints}]\n\n",
            url = service.url,
            dir = service.dir.display(),
            cache = self.temp.path().join(format!("cache-{name}")).display(),
        )
    }

    /// The named-form config: alpha owns `github.com/alpha-org/*`, beta owns
    /// `github.com/beta-org/**`. `extra` is appended verbatim.
    fn write_config(&self, extra: &str) {
        let body = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{personal}\"\n\n{a}{b}{extra}",
            personal = self.temp.path().join("personal").display(),
            a = self.company_table(
                &self.alpha_name,
                &self.alpha,
                "\"https://github.com/Alpha-Org/*\""
            ),
            b = self.company_table(
                &self.beta_name,
                &self.beta,
                "\"git@github.com:beta-org/**\""
            ),
        );
        write_private(&self.config_dir().join("config.toml"), body.as_bytes());
    }

    fn kinbase(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
        command.current_dir(cwd).args(args);
        self.isolate(&mut command);
        command.output_alone().unwrap()
    }

    fn isolate(&self, command: &mut Command) {
        command
            .env("HOME", self.temp.path())
            .env("XDG_CONFIG_HOME", self.temp.path().join("config-home"))
            .env("XDG_STATE_HOME", self.temp.path().join("state-home"))
            .env_remove("KINBASE_COMPANY_URL")
            .env_remove("KINBASE_CLIENT_KEY_FD");
    }

    fn repo(&self, name: &str, origin: &str) -> PathBuf {
        let repo = self.temp.path().join("repos").join(name);
        fs::create_dir_all(&repo).unwrap();
        for args in [
            vec!["init", "-q"],
            vec![
                "-c",
                "user.email=t@example.com",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "init",
            ],
            vec!["remote", "add", "origin", origin],
        ] {
            let mut git = Command::new("git");
            git.args(&args).current_dir(&repo);
            self.isolate(&mut git);
            let status = git.status_alone().unwrap();
            assert!(status.success(), "git {args:?}");
        }
        repo
    }

    /// `repo issue --company <name>` then `repo init`; returns the UUID.
    fn certify(&self, repo: &Path, name: &str) -> String {
        let issued = self.kinbase(
            repo,
            &["repo", "issue", "--repo", ".", "--company", name, "--json"],
        );
        assert!(issued.status.success(), "repo issue: {}", text(&issued));
        let receipt: Value = serde_json::from_slice(&issued.stdout).unwrap();
        let certificate = &receipt["certificate"];
        let uuid = certificate["repository_uuid"].as_str().unwrap().to_owned();
        let file = self.temp.path().join(format!("{uuid}.cert"));
        write_private(&file, kinbase::json::jcs_text(certificate).as_bytes());
        let init = self.kinbase(
            repo,
            &[
                "repo",
                "init",
                "--repo",
                ".",
                "--certificate",
                file.to_str().unwrap(),
            ],
        );
        assert!(init.status.success(), "repo init: {}", text(&init));
        uuid
    }

    fn status(&self, repo: &Path) -> (Option<i32>, Value) {
        let output = self.kinbase(repo, &["status", "--repo", ".", "--json"]);
        let value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
        (output.status.code(), value)
    }

    /// One hook event as the host runs it: no arguments beyond the event,
    /// the envelope naming the cwd, the process started somewhere else.
    fn hook(&self, repo: &Path, event: &str, json: bool) -> Output {
        self.hook_from(self.temp.path(), repo, event, json)
    }

    /// `hook` for a named session.
    fn hook_session(&self, repo: &Path, event: &str, session: &str) -> Output {
        self.hook_with(self.temp.path(), repo, event, true, session)
    }

    /// `hook`, with the host process started in `process_cwd`.
    fn hook_from(&self, process_cwd: &Path, repo: &Path, event: &str, json: bool) -> Output {
        self.hook_with(process_cwd, repo, event, json, "multi-company-probe")
    }

    fn hook_with(
        &self,
        process_cwd: &Path,
        repo: &Path,
        event: &str,
        json: bool,
        session: &str,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
        command
            .current_dir(process_cwd)
            .args(["hooks", "dispatch", "claude", event]);
        if json {
            command.arg("--json");
        }
        self.isolate(&mut command);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn_alone().unwrap();
        let envelope = serde_json::json!({
            "hook_event_name": event,
            "session_id": session,
            "cwd": repo.to_string_lossy()
        });
        child
            .stdin
            .take()
            .unwrap()
            .write_all(envelope.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Strings no hook output may carry while it is not serving `except`.
    fn canaries(&self, except: Option<&str>) -> Vec<String> {
        let mut canaries = Vec::new();
        for (name, service) in [
            (self.alpha_name.as_str(), &self.alpha),
            (self.beta_name.as_str(), &self.beta),
        ] {
            if Some(name) == except {
                continue;
            }
            canaries.push(name.to_owned());
            canaries.push(service.url.clone());
            canaries.push(service.company_id.clone());
        }
        canaries
    }
}

/// One host message observed in `repo` for session `session`.
fn observe(world: &World, repo: &Path, session: &str, message: &str) {
    let event = world.temp.path().join(format!("{session}.jsonl"));
    fs::write(
        &event,
        format!(
            "{}\n",
            serde_json::json!({"id": "m1", "role": "user", "text": message,
                "observed_at": kinbase::time::now_rfc3339_millis(), "source_kind": "codex_jsonl"})
        ),
    )
    .unwrap();
    let observed = world.kinbase(
        repo,
        &[
            "session",
            "observe",
            session,
            "--json",
            "--event",
            event.to_str().unwrap(),
        ],
    );
    assert!(observed.status.success(), "observe: {}", text(&observed));
}

/// The fork of `a_worktree_uuid_cannot_carry_...`: a beta-origin repository
/// carrying a UUID alpha holds.
fn fork_of_alpha(world: &World) -> PathBuf {
    let alpha_repo = world.repo("alpha-src", "git@github.com:alpha-org/src.git");
    world.certify(&alpha_repo, &world.alpha_name);
    let fork = world.repo("beta-fork", "git@github.com:beta-org/fork.git");
    fs::create_dir_all(fork.join(".kin")).unwrap();
    fs::copy(
        alpha_repo.join(".kin/kinbase.toml"),
        fork.join(".kin/kinbase.toml"),
    )
    .unwrap();
    fork
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string() + &String::from_utf8_lossy(&output.stderr)
}

/// The repository is uninitialized in these probes, so `status` still refuses
/// for its own reasons (no proof clock); what matters is that Company
/// selection is not among them.
fn not_a_selection_refusal(status: &Value) {
    let refusal = reason(status);
    assert!(
        refusal.is_none(),
        "Company selection refused ({refusal:?}): {status}"
    );
}

fn reason(status: &Value) -> Option<&str> {
    status["error"]["detail"]["reason"]
        .as_str()
        .or_else(|| status["detail"]["reason"].as_str())
}

#[test]
fn each_repository_is_served_by_the_company_its_evidence_names() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-one", "git@github.com:alpha-org/one.git");
    let beta_repo = world.repo("beta-one", "https://github.com/beta-org/team/one");
    world.certify(&alpha_repo, ALPHA);
    world.certify(&beta_repo, BETA);

    for (repo, service, name) in [
        (&alpha_repo, &world.alpha, ALPHA),
        (&beta_repo, &world.beta, BETA),
    ] {
        let (code, status) = world.status(repo);
        assert_eq!(code, Some(0), "status: {status}");
        assert_eq!(status["status"], "certified", "status: {status}");
        assert_eq!(status["company_url"], service.url.as_str());
        assert_eq!(status["company_selection"]["outcome"]["selected"], name);
        assert_eq!(status["company_selection"]["reason"], "held-certificate");
    }

    // The hook resolves from the envelope cwd, not from where it started,
    // and says nothing about the other Company.
    let hook = world.hook(&beta_repo, "SessionStart", true);
    assert!(hook.status.success(), "hook: {}", text(&hook));
    let output = text(&hook);
    for canary in world.canaries(Some(BETA)) {
        assert!(
            !output.contains(&canary),
            "{canary} reached the beta session: {output}"
        );
    }
}

#[test]
fn a_worktree_uuid_cannot_carry_one_companys_certificate_into_anothers_repository() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-src", "git@github.com:alpha-org/src.git");
    world.certify(&alpha_repo, ALPHA);
    // A beta repository seeded from alpha's: same .kin/kinbase.toml.
    let fork = world.repo("beta-fork", "git@github.com:beta-org/fork.git");
    fs::create_dir_all(fork.join(".kin")).unwrap();
    fs::copy(
        alpha_repo.join(".kin/kinbase.toml"),
        fork.join(".kin/kinbase.toml"),
    )
    .unwrap();

    let (code, status) = world.status(&fork);
    assert_eq!(code, Some(4), "a copied UUID was served: {status}");
    assert_eq!(
        reason(&status),
        Some("company-ambiguous"),
        "status: {status}"
    );

    // The host is never blocked, learns no Company, and the person is told.
    for json in [true, false] {
        let hook = world.hook(&fork, "SessionStart", json);
        assert!(hook.status.success(), "hook blocked: {}", text(&hook));
        let output = text(&hook);
        for canary in world.canaries(None) {
            assert!(!output.contains(&canary), "{canary} leaked: {output}");
        }
        assert!(
            output.contains("could not choose a Company"),
            "no notice: {output}"
        );
        if json {
            let response: Value = serde_json::from_slice(&hook.stdout).unwrap();
            assert_eq!(response["trusted_company_facts"], serde_json::json!([]));
            assert_eq!(response["certified"], Value::Null);
        } else {
            let response: Value = serde_json::from_slice(&hook.stdout).unwrap();
            assert!(
                response["systemMessage"]
                    .as_str()
                    .is_some_and(|message| message.contains("kinbase status")),
                "no human-visible message: {response}"
            );
        }
    }

    // Issuing from beta is refused while alpha holds the UUID; the
    // documented new-identity procedure then works.
    let refused = world.kinbase(
        &fork,
        &["repo", "issue", "--repo", ".", "--company", BETA, "--json"],
    );
    assert_eq!(refused.status.code(), Some(4), "issue: {}", text(&refused));
    assert!(
        text(&refused).contains("certified-elsewhere"),
        "{}",
        text(&refused)
    );
    fs::remove_file(fork.join(".kin/kinbase.toml")).unwrap();
    let uuid = world.certify(&fork, BETA);
    let (code, status) = world.status(&fork);
    assert_eq!(code, Some(0), "status: {status}");
    assert_eq!(status["repository_uuid"], uuid.as_str());
    assert_eq!(status["company_selection"]["outcome"]["selected"], BETA);
}

#[test]
fn two_companies_holding_one_uuid_is_a_refusal() {
    let world = World::new();
    let repo = world.repo("held-twice", "git@example.com:nobody/held-twice.git");
    let uuid = world.certify(&repo, ALPHA);
    // Beta's server certifies a UUID it did not mint when asked directly;
    // the launcher check is client-side, so drive the server past it.
    fs::remove_file(repo.join(".kin/kinbase.toml")).unwrap();
    let mut beta_only = world.company_table(BETA, &world.beta, "");
    beta_only = format!(
        "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n{beta_only}",
        world.temp.path().join("personal").display()
    );
    write_private(
        &world.config_dir().join("config.toml"),
        beta_only.as_bytes(),
    );
    fs::create_dir_all(repo.join(".kin")).unwrap();
    fs::write(
        repo.join(".kin/kinbase.toml"),
        format!(
            "schema_version = \"kinbase-repo/1\"\nrepository_uuid_hint = \"{uuid}\"\nsafe_name = \"held-twice\"\ndomains = []\n"
        ),
    )
    .unwrap();
    let issued = world.kinbase(
        &repo,
        &["repo", "issue", "--repo", ".", "--company", BETA, "--json"],
    );
    assert!(issued.status.success(), "{}", text(&issued));
    let receipt: Value = serde_json::from_slice(&issued.stdout).unwrap();
    assert_eq!(receipt["certificate"]["repository_uuid"], uuid.as_str());
    let file = world.temp.path().join("beta-copy.cert");
    write_private(
        &file,
        kinbase::json::jcs_text(&receipt["certificate"]).as_bytes(),
    );
    let init = world.kinbase(
        &repo,
        &[
            "repo",
            "init",
            "--repo",
            ".",
            "--certificate",
            file.to_str().unwrap(),
        ],
    );
    assert!(init.status.success(), "{}", text(&init));

    world.write_config("");
    let (code, status) = world.status(&repo);
    assert_eq!(code, Some(4), "two holders were served: {status}");
    assert_eq!(reason(&status), Some("company-ambiguous"));
    let hook = world.hook(&repo, "SessionStart", false);
    assert!(hook.status.success());
    for canary in world.canaries(None) {
        assert!(
            !text(&hook).contains(&canary),
            "{canary} leaked: {}",
            text(&hook)
        );
    }
}

#[test]
fn unreadable_evidence_refuses_rather_than_falls_through() {
    let world = World::new();
    let repo = world.repo("alpha-two", "git@github.com:alpha-org/two.git");
    world.certify(&repo, ALPHA);
    fs::remove_file(world.alpha.dir.join("company-root.pub")).unwrap();
    let (code, status) = world.status(&repo);
    assert_eq!(code, Some(4), "status: {status}");
    assert_eq!(
        reason(&status),
        Some("company-unverifiable"),
        "status: {status}"
    );
}

#[test]
fn a_repository_no_company_claims_runs_codebase_only_and_says_so() {
    let world = World::new();
    let repo = world.repo("elsewhere", "git@example.com:other/elsewhere.git");
    let (_, status) = world.status(&repo);
    not_a_selection_refusal(&status);
    let doctor = world.kinbase(&repo, &["doctor", "--repo", ".", "--json"]);
    let doctor: Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(
        doctor["company_selection"]["outcome"], "none",
        "doctor: {doctor}"
    );
    assert_eq!(
        doctor["company_selection"]["companies"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        doctor["company_selection"]["evidence"]["origin"],
        "example.com/other/elsewhere"
    );
    // A directory that is simply not company work stays quiet.
    let hook = world.hook(&repo, "SessionStart", false);
    assert!(hook.status.success());
    assert!(!text(&hook).contains("found no Company"), "{}", text(&hook));

    // One that was certified but no configured Company claims any more says so.
    fs::create_dir_all(repo.join(".kin")).unwrap();
    fs::write(
        repo.join(".kin/kinbase.toml"),
        "schema_version = \"kinbase-repo/1\"\nrepository_uuid_hint = \"0b1c2d3e-0000-4000-8000-000000000001\"\nsafe_name = \"elsewhere\"\ndomains = []\n",
    )
    .unwrap();
    let hook = world.hook(&repo, "SessionStart", false);
    assert!(hook.status.success());
    assert!(text(&hook).contains("found no Company"), "{}", text(&hook));
}

#[test]
fn converting_a_single_company_config_keeps_its_keys_or_stops() {
    let world = World::new();
    // The single form's default keys exist, as on a machine that used it.
    let legacy = world.config_dir().join("client.key");
    kinbase::crypto::PrivateKey::generate()
        .save_new(&legacy, "client key")
        .unwrap();
    let repo = world.repo("alpha-three", "git@github.com:alpha-org/three.git");
    let (code, status) = world.status(&repo);
    assert_eq!(
        code,
        Some(4),
        "a new identity was minted silently: {status}"
    );
    assert_eq!(
        reason(&status),
        Some("company-key-migration"),
        "status: {status}"
    );
    assert!(
        !world
            .config_dir()
            .join("companies")
            .join(ALPHA)
            .join("client.key")
            .exists(),
        "a per-Company key was minted"
    );
    world.write_config("");
    let named = format!(
        "{}client_key_file = \"{}\"\n",
        world.company_table(ALPHA, &world.alpha, "\"github.com/alpha-org/*\""),
        legacy.display()
    );
    let body = format!(
        "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n{named}{}",
        world.temp.path().join("personal").display(),
        world.company_table(BETA, &world.beta, "\"github.com/beta-org/**\"")
    );
    write_private(&world.config_dir().join("config.toml"), body.as_bytes());
    let (_, status) = world.status(&repo);
    not_a_selection_refusal(&status);
}

#[test]
fn one_maintainer_key_for_every_company_must_be_stated() {
    let world = World::new();
    let key = world.config_dir().join("me.key");
    world.write_config(&format!(
        "[identity]\nmaintainer_key_file = \"{}\"\n",
        key.display()
    ));
    let repo = world.repo("alpha-four", "git@github.com:alpha-org/four.git");
    let (code, status) = world.status(&repo);
    assert_eq!(code, Some(4), "status: {status}");
    assert_eq!(reason(&status), Some("identity-sharing-unconfirmed"));
    world.write_config(&format!(
        "[identity]\nmaintainer_key_file = \"{}\"\nshare_maintainer_key = true\n",
        key.display()
    ));
    let (_, status) = world.status(&repo);
    not_a_selection_refusal(&status);
}

#[test]
fn malformed_named_configs_are_refused_when_read() {
    let world = World::new();
    let repo = world.repo("any", "git@github.com:alpha-org/any.git");
    let personal = world.temp.path().join("personal");
    let alpha = world.company_table(ALPHA, &world.alpha, "");
    let cases = [
        (
            format!(
                "[company]\nurl = \"{}\"\nfacts_token_file = \"/x\"\nroot_public_key_file = \"/x\"\ncache_root = \"/x\"\n\n{alpha}",
                world.alpha.url
            ),
            "mutually exclusive",
        ),
        (
            alpha.replace(&format!("companies.{ALPHA}"), "companies.Bad_Name"),
            "Company name",
        ),
        (
            format!(
                "{alpha}{}",
                alpha.replace(&format!("companies.{ALPHA}"), "companies.twin")
            ),
            "share url",
        ),
    ];
    for (tables, expected) in cases {
        write_private(
            &world.config_dir().join("config.toml"),
            format!(
                "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n{tables}",
                personal.display()
            )
            .as_bytes(),
        );
        let output = world.kinbase(&repo, &["status", "--repo", "."]);
        assert_eq!(output.status.code(), Some(4), "{}", text(&output));
        assert!(
            text(&output).contains(expected),
            "expected {expected}: {}",
            text(&output)
        );
    }
}

#[test]
fn a_company_candidate_is_delivered_only_from_its_own_repository() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-cand", "git@github.com:alpha-org/cand.git");
    let beta_repo = world.repo("beta-cand", "git@github.com:beta-org/cand.git");
    world.certify(&alpha_repo, ALPHA);
    world.certify(&beta_repo, BETA);
    // Online status stores each Company's verified snapshot, whose
    // company_id a Company candidate is bound to.
    for repo in [&alpha_repo, &beta_repo] {
        let (code, status) = world.status(repo);
        assert_eq!(code, Some(0), "status: {status}");
    }
    let event = world.temp.path().join("event.jsonl");
    fs::write(
        &event,
        format!(
            "{}\n",
            serde_json::json!({"id": "m1", "role": "user",
                "text": "Company policy: every team must cap retry backoff at 30 seconds.",
                "observed_at": kinbase::time::now_rfc3339_millis(), "source_kind": "codex_jsonl"})
        ),
    )
    .unwrap();
    let observed = world.kinbase(
        &alpha_repo,
        &[
            "session",
            "observe",
            "cross-company",
            "--json",
            "--event",
            event.to_str().unwrap(),
        ],
    );
    assert!(observed.status.success(), "observe: {}", text(&observed));
    let candidates =
        fs::read_to_string(world.temp.path().join("personal/candidates.jsonl")).unwrap_or_default();
    let company: Vec<Value> = candidates
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|candidate| {
            candidate["destination"]
                .as_str()
                .is_some_and(|destination| destination.starts_with("company"))
        })
        .collect();
    assert!(
        !company.is_empty(),
        "no Company candidate was minted: {candidates}"
    );
    for candidate in &company {
        assert_eq!(
            candidate["destination"],
            format!("company:{}", world.alpha.company_id).as_str(),
            "candidate not bound to alpha: {candidate}"
        );
        assert!(candidate["repository_uuid"].is_string(), "{candidate}");
    }

    // The session stops in beta's repository: nothing it minted in alpha's
    // reaches beta's Company.
    let checkpoint = world.kinbase(
        &beta_repo,
        &["session", "checkpoint", "cross-company", "--json"],
    );
    let output = text(&checkpoint);
    for candidate in &company {
        let id = candidate["candidate_id"].as_str().unwrap();
        assert!(
            !output.contains(&format!(
                "{id} -> company:{}: admitted",
                world.alpha.company_id
            )),
            "delivered from the wrong repository: {output}"
        );
    }
    // Beta's whole store, database and journal, holds none of the statement.
    let mut beta_bytes = Vec::new();
    for entry in fs::read_dir(&world.beta.dir).unwrap().flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("company.sqlite3")
        {
            beta_bytes.extend(fs::read(entry.path()).unwrap());
        }
    }
    let statement = "cap retry backoff at 30 seconds";
    assert!(
        !beta_bytes
            .windows(statement.len())
            .any(|window| window == statement.as_bytes()),
        "alpha's candidate reached beta's Company store"
    );
}

#[test]
fn repositories_without_an_origin_get_distinct_identities() {
    let world = World::new();
    let mut uuids = Vec::new();
    for name in ["no-origin-one", "no-origin-two"] {
        let repo = world.repo(name, "placeholder");
        // No origin remote at all, as in a local-only repository.
        let mut git = Command::new("git");
        git.args(["remote", "remove", "origin"]).current_dir(&repo);
        world.isolate(&mut git);
        let status = git.status_alone().unwrap();
        assert!(status.success());
        let issued = world.kinbase(
            &repo,
            &["repo", "issue", "--repo", ".", "--company", ALPHA, "--json"],
        );
        assert!(issued.status.success(), "{}", text(&issued));
        let receipt: Value = serde_json::from_slice(&issued.stdout).unwrap();
        uuids.push(
            receipt["certificate"]["repository_uuid"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    assert_ne!(
        uuids[0], uuids[1],
        "two origin-less repositories share one identity"
    );
}

// ---- Review findings on PR #30, each reproduced before it was fixed. ----

#[test]
fn a_refused_status_still_reports_its_selection_evidence() {
    let world = World::new();
    let fork = fork_of_alpha(&world);
    let (code, status) = world.status(&fork);
    assert_eq!(code, Some(4));
    assert_eq!(
        status["company_selection"]["reason"], "company-ambiguous",
        "the refusal hid the evidence status exists to show: {status}"
    );
    assert!(
        status["company_selection"]["remediation"].is_string(),
        "{status}"
    );
}

#[test]
fn an_unreadable_cache_is_not_an_empty_one() {
    let world = World::new();
    let fork = fork_of_alpha(&world);
    // Alpha holds the fork's UUID, but its cache cannot be read: treating
    // that as "alpha holds nothing" would let beta's hint win.
    let cache = world
        .temp
        .path()
        .join(format!("cache-{}", world.alpha_name));
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o000)).unwrap();
    let (code, status) = world.status(&fork);
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, Some(4), "status: {status}");
    assert_eq!(
        reason(&status),
        Some("company-unverifiable"),
        "status: {status}"
    );
}

#[test]
fn a_hook_selects_from_its_envelope_before_reading_any_credentials() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-creds", "git@github.com:alpha-org/creds.git");
    let beta_repo = world.repo("beta-creds", "git@github.com:beta-org/creds.git");
    world.certify(&beta_repo, &world.beta_name);
    // Alpha's credentials are gone; the host started in alpha's repository
    // but the event is for beta's.
    fs::remove_file(world.alpha.dir.join("facts.token")).unwrap();
    let hook = world.hook_from(&alpha_repo, &beta_repo, "SessionStart", true);
    assert!(
        hook.status.success(),
        "a broken Company blocked another's session: {}",
        text(&hook)
    );
    let response: Value = serde_json::from_slice(&hook.stdout).unwrap();
    assert_eq!(response["status"], "verified", "{response}");
}

#[test]
fn a_checkpoint_admits_against_the_repository_the_host_named() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-stop", "git@github.com:alpha-org/stop.git");
    let elsewhere = world.repo("elsewhere-stop", "git@example.com:other/stop.git");
    world.certify(&alpha_repo, &world.alpha_name);
    let (code, status) = world.status(&alpha_repo);
    assert_eq!(code, Some(0), "status: {status}");
    observe(
        &world,
        &alpha_repo,
        "stop-here",
        "Company policy: every team must pin base images.",
    );
    // The host process started elsewhere; the Stop is for alpha's repository.
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .current_dir(&elsewhere)
        .args(["hooks", "dispatch", "claude", "Stop", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    world.isolate(&mut command);
    let mut child = command.spawn_alone().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::json!({"hook_event_name": "Stop", "session_id": "stop-here",
                "cwd": alpha_repo.to_string_lossy()})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let output = text(&child.wait_with_output().unwrap());
    assert!(
        output.contains(&format!("company:{}", world.alpha.company_id)),
        "the probe minted no alpha candidate: {output}"
    );
    assert!(
        !output.contains("came from another repository"),
        "a candidate from the named repository was held: {output}"
    );
}

#[test]
fn a_company_named_like_a_json_literal_is_still_scrubbed() {
    // Alpha is named `true`. Its candidate is held when the session stops in
    // beta's repository, and the held admission names alpha's company_id.
    let world = World::named("true", BETA);
    let alpha_repo = world.repo("alpha-literal", "git@github.com:alpha-org/literal.git");
    let beta_repo = world.repo("beta-literal", "git@github.com:beta-org/literal.git");
    world.certify(&alpha_repo, "true");
    world.certify(&beta_repo, BETA);
    for repo in [&alpha_repo, &beta_repo] {
        assert_eq!(world.status(repo).0, Some(0));
    }
    observe(
        &world,
        &alpha_repo,
        "literal",
        "Company policy: every team must pin base images.",
    );
    let hook = world.hook_session(&beta_repo, "Stop", "literal");
    let response: Value = serde_json::from_slice(&hook.stdout)
        .unwrap_or_else(|error| panic!("hook output is not JSON ({error}): {}", text(&hook)));
    let rendered = response.to_string();
    assert!(
        response["admissions"]
            .as_array()
            .is_some_and(|admissions| !admissions.is_empty()),
        "the probe held no alpha candidate: {rendered}"
    );
    assert!(
        !rendered.contains(&world.alpha.company_id) && !rendered.contains(&world.alpha.url),
        "alpha's identity reached beta's session: {rendered}"
    );
    assert_eq!(
        response["degraded"].as_bool().is_some(),
        true,
        "a JSON literal was rewritten: {rendered}"
    );
}

#[test]
fn scrubbing_happens_before_evidence_is_encoded_or_framed() {
    // Beta's repository is named like alpha, so alpha's name is in beta's
    // own repository-identity fact.
    let world = World::new();
    let beta_repo = world.repo(ALPHA, "git@github.com:beta-org/x.git");
    world.certify(&beta_repo, BETA);
    assert_eq!(world.status(&beta_repo).0, Some(0));

    let hook = world.hook(&beta_repo, "SessionStart", true);
    let response: Value = serde_json::from_slice(&hook.stdout).unwrap();
    use base64::Engine as _;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(response["envelope"].as_str().unwrap())
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&envelope).contains(ALPHA),
        "alpha's name survived in the encoded envelope"
    );

    let hook = world.hook(&beta_repo, "SessionStart", false);
    let document: Value = serde_json::from_slice(&hook.stdout).unwrap();
    let context = document["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(!context.contains(ALPHA), "alpha's name reached the context");
    // `<label>\n<length>\n<document>`: the length still frames the document.
    let mut parts = context.splitn(3, '\n');
    let (_, length, body) = (parts.next(), parts.next().unwrap(), parts.next().unwrap());
    assert_eq!(
        length.parse::<usize>().unwrap(),
        body.len(),
        "the frame length is stale"
    );
}

#[test]
fn service_commands_do_not_need_the_launchers_company_credentials() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-service", "git@github.com:alpha-org/service.git");
    // Alpha is selected here and its credentials are gone; `company init`
    // reads only its own service config.
    fs::remove_file(world.alpha.dir.join("facts.token")).unwrap();
    let dir = world.temp.path().join("service-third");
    private_dir(&dir);
    let config = dir.join("kinbased.toml");
    write_private(
        &config,
        format!(
            "schema_version = \"1\"\n\
             company_id = \"cid-third\"\n\
             sqlite_path = \"{dir}/company.sqlite3\"\n\
             bind = \"127.0.0.1:1\"\n\
             root_key_file = \"{dir}/company-root.key\"\n\
             facts_token_file = \"{dir}/facts.token\"\n\
             admin_token_file = \"{dir}/admin.token\"\n\
             auth_failures_per_minute = 100\n\
             default_fact_freshness_seconds = 3600\n\
             candidate_lifetime_seconds = 900\n\
             clock_skew_seconds = 300\n\
             nonce_retention_seconds = 604800\n",
            dir = dir.display(),
        )
        .as_bytes(),
    );
    let init = world.kinbase(
        &alpha_repo,
        &["company", "init", "--config", config.to_str().unwrap()],
    );
    assert!(
        init.status.success(),
        "company init failed on the launcher's credentials: {}",
        text(&init)
    );
}

#[test]
fn choosing_a_target_reads_no_more_of_the_certificate_than_repo_init_would() {
    let temp = TempDir::new().unwrap();
    let fifo = temp.path().join("certificate");
    let made = Command::new("mkfifo").arg(&fifo).status_alone().unwrap();
    assert!(made.success());
    let (sent, received) = std::sync::mpsc::channel();
    let path = fifo.clone();
    std::thread::spawn(move || {
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        let chunk = vec![b' '; 16 * 1024];
        let mut written = 0usize;
        while written < 8 << 20 {
            match file.write(&chunk) {
                Ok(count) => written += count,
                Err(_) => break,
            }
        }
        drop(file);
        sent.send(written).unwrap();
        // `repo init` may open the certificate again; it reads end of file.
        let _ = OpenOptions::new().write(true).open(&path);
    });
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .current_dir(temp.path())
        .args(["repo", "init", "--repo", ".", "--certificate"])
        .arg(&fifo)
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config-home"))
        .env("XDG_STATE_HOME", temp.path().join("state-home"))
        .env_remove("KINBASE_COMPANY_URL")
        .env_remove("KINBASE_CLIENT_KEY_FD")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn_alone().unwrap();
    let written = received
        .recv_timeout(std::time::Duration::from_secs(60))
        .unwrap_or(usize::MAX);
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        written < 1 << 20,
        "target selection read {written} certificate bytes past the 64 KiB ceiling"
    );
}

#[test]
fn a_held_candidate_keeps_its_company_id_out_of_another_companys_session() {
    let world = World::new();
    let alpha_repo = world.repo("alpha-held", "git@github.com:alpha-org/held.git");
    let beta_repo = world.repo("beta-held", "git@github.com:beta-org/held.git");
    world.certify(&alpha_repo, &world.alpha_name);
    world.certify(&beta_repo, &world.beta_name);
    observe(
        &world,
        &alpha_repo,
        "held",
        "Company policy: every team must pin base images.",
    );
    // Alpha's cache cannot be read, so its company_id is not known from
    // there; the held candidate still names it.
    let cache = world
        .temp
        .path()
        .join(format!("cache-{}", world.alpha_name));
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o000)).unwrap();
    let hook = world.hook_session(&beta_repo, "Stop", "held");
    fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
    let output = text(&hook);
    assert!(
        output.contains("candidate held"),
        "the probe held no alpha candidate: {output}"
    );
    assert!(
        !output.contains(&world.alpha.company_id),
        "alpha's company_id reached beta's session: {output}"
    );
}

#[test]
fn a_company_name_from_the_command_line_is_validated_before_it_is_echoed() {
    let world = World::new();
    let repo = world.repo("named-arg", "git@github.com:alpha-org/named-arg.git");
    let output = world.kinbase(
        &repo,
        &[
            "repo",
            "issue",
            "--repo",
            ".",
            "--company",
            "evil\u{1b}[2J\u{202e}",
        ],
    );
    let rendered = text(&output);
    assert_eq!(output.status.code(), Some(4), "{rendered}");
    assert!(
        !rendered.contains('\u{1b}') && !rendered.contains('\u{202e}'),
        "the raw argument reached the output: {rendered:?}"
    );
}

#[test]
fn a_refused_evidence_repository_is_refused_even_beside_an_unselected_one() {
    let world = World::new();
    let fork = fork_of_alpha(&world);
    let elsewhere = world.repo("elsewhere-project", "git@example.com:other/project.git");
    let output = world.kinbase(
        &elsewhere,
        &[
            "project",
            "--repo",
            ".",
            "--task",
            "t",
            "--decision",
            "d",
            "--evidence-repo",
            fork.to_str().unwrap(),
            "--json",
        ],
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap_or(Value::Null);
    assert_eq!(
        reason(&document),
        Some("company-ambiguous"),
        "an ambiguous evidence repository was read: {}",
        text(&output)
    );
}

#[test]
fn a_company_is_not_issued_a_repository_another_companys_hint_claims() {
    let world = World::new();
    let repo = world.repo("alpha-hinted", "git@github.com:alpha-org/hinted.git");
    // `repo init` would count alpha's hint beside beta's certificate and
    // refuse it, so beta must not be issued one.
    let refused = world.kinbase(
        &repo,
        &["repo", "issue", "--repo", ".", "--company", BETA, "--json"],
    );
    assert_eq!(refused.status.code(), Some(4), "issue: {}", text(&refused));
    assert!(
        text(&refused).contains("company-ambiguous"),
        "{}",
        text(&refused)
    );
    assert!(!repo.join(".kin/kinbase.toml").exists());
    // The Company the hint names is issued one, and it installs.
    world.certify(&repo, ALPHA);
    let (code, status) = world.status(&repo);
    assert_eq!(code, Some(0), "status: {status}");
    assert_eq!(status["company_selection"]["outcome"]["selected"], ALPHA);
}
