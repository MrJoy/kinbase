//! Who used the Company service, how, and how much, as a steward sees it:
//! requests reach a live `company serve` over HTTP, and `company usage`
//! reports them from the store.
//!
//! Two things have to hold besides the counts. A caller's path identifiers
//! and query text never reach the store, and a peer that presents no
//! credential cannot make the service write a usage row.

mod support;

use kinbase::company::client::Client;
use kinbase::config::TokenRecord;
use kinbase::crypto::PrivateKey;
use serde_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;
use support::SpawnAlone;
use tempfile::TempDir;

const TOKEN: &str = "facts-usage-report";
/// Planted in a path identifier and a query value of real requests.
const CANARY: &str = "Wilhelmina0xUSAGECANARY";

struct Service {
    temp: TempDir,
    child: Child,
    port: u16,
    root: PrivateKey,
    config: PathBuf,
    sqlite: PathBuf,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(temp: &Path, port: u16) -> (PathBuf, PathBuf) {
    let config_path = temp.join("kinbased.toml");
    let sqlite = temp.join("company.sqlite");
    let config = format!(
        r#"schema_version = "1"
company_id = "company-usage"
sqlite_path = "{db}"
bind = "127.0.0.1:{port}"
root_key_file = "{root_key}"
facts_token_file = "{token}"
auth_failures_per_minute = 1000
default_fact_freshness_seconds = 900
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 1300
record_usage = true
"#,
        db = sqlite.display(),
        root_key = temp.join("company-root.key").display(),
        token = temp.join("facts.token").display(),
    );
    kinbase::crypto::write_0600(&config_path, config.as_bytes(), "service config")
        .expect("write config");
    (config_path, sqlite)
}

impl Service {
    fn start() -> Self {
        let temp = TempDir::new().expect("temporary root");
        let root = PrivateKey::generate();
        root.save_new(&temp.path().join("company-root.key"), "Company root key")
            .expect("save root key");
        kinbase::crypto::write_0600(
            &temp.path().join("facts.token"),
            TOKEN.as_bytes(),
            "facts token",
        )
        .expect("write token");
        // A port the kernel just handed out and released; the service binds
        // it a moment later.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("free port")
            .port();
        let (config, sqlite) = write_config(temp.path(), port);
        let mut child = isolated(temp.path())
            .args(["company", "serve", "--config"])
            .arg(&config)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn_alone()
            .expect("start company service");
        let mut banner = String::new();
        BufReader::new(child.stdout.take().expect("service stdout"))
            .read_line(&mut banner)
            .expect("read banner");
        assert!(banner.contains("company-serving"), "banner: {banner}");
        Service {
            temp,
            child,
            port,
            root,
            config,
            sqlite,
        }
    }

    fn client(&self, key: PrivateKey) -> Client {
        Client::new(
            &format!("http://127.0.0.1:{}", self.port),
            TokenRecord {
                token: TOKEN.to_owned(),
            },
            key,
            Some(self.root.public()),
            self.temp.path().join("client-cache"),
            false,
        )
        .expect("client")
    }

    fn usage(&self, extra: &[&str]) -> Output {
        isolated(self.temp.path())
            .args(["company", "usage", "--config"])
            .arg(&self.config)
            .args(extra)
            .output_alone()
            .expect("run company usage")
    }
}

/// A kinbase command whose launcher sees only the temporary root.
fn isolated(temp: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kinbase"));
    command
        .env("HOME", temp)
        .env("XDG_CONFIG_HOME", temp.join("config"))
        .env("XDG_STATE_HOME", temp.join("state"));
    command
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "company usage failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("one JSON document on stdout")
}

/// One request carrying no credential at all, written straight onto the
/// socket: the client cannot be made to send one.
fn unauthenticated(port: u16, route: &str) {
    let address = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect(&address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let request = format!("GET {route} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).expect("write request");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    assert!(
        String::from_utf8_lossy(&response).contains(" 401 "),
        "an unauthenticated request was not refused"
    );
}

fn action<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["by_action"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["action"] == name)
        .unwrap_or_else(|| panic!("no {name} row in {report}"))
}

#[test]
fn the_report_counts_live_requests_by_principal_client_and_action() {
    let service = Service::start();
    let laptop = service.client(PrivateKey::generate());
    let desktop = service.client(PrivateKey::generate());

    laptop.status().expect("status");
    laptop.get_ok("/facts").expect("fact list");
    let missing = laptop
        .get(&format!("/facts/{CANARY}?decision={CANARY}"))
        .expect("fact detail answers");
    assert_eq!(missing.status, 404);
    desktop.get_ok("/facts").expect("fact list");
    unauthenticated(service.port, "/facts");
    unauthenticated(service.port, &format!("/facts/{CANARY}"));

    let all = report(&service.usage(&["--json"]));
    assert_eq!(all["status"], "company-usage");
    assert_eq!(all["recording"], true);
    assert_eq!(all["company_id"], "company-usage");
    assert_eq!(all["schema"], "kinbase-usage-report/1");
    let totals = &all["totals"];
    assert_eq!(totals["requests"], 4, "{all}");
    assert_eq!(totals["succeeded"], 3);
    assert_eq!(totals["refused"], 1);
    assert_eq!(totals["principals"], 1);
    assert_eq!(
        totals["clients"], 2,
        "two installations share one role token"
    );

    let principal = &all["by_principal"][0];
    assert_eq!(principal["principal_id"], "facts-principal");
    assert_eq!(principal["clients"], 2);
    assert_eq!(principal["actions"]["fact.list"], 2);
    assert_eq!(principal["actions"]["fact.read"], 1);
    assert_eq!(principal["actions"]["info.status"], 1);

    assert_eq!(action(&all, "fact.list")["requests"], 2);
    assert_eq!(action(&all, "fact.read")["refused"], 1);
    assert_eq!(all["by_client"].as_array().unwrap().len(), 2);
    let today = &all["by_window"][0];
    assert_eq!(today["requests"], 4);
    assert_eq!(
        today["window"].as_str().unwrap().len(),
        10,
        "a day window is named YYYY-MM-DD: {today}"
    );

    // A window that starts after every request holds none of them.
    let later = report(&service.usage(&["--json", "--since", "2999-01-01T00:00:00.000Z"]));
    assert_eq!(later["totals"]["requests"], 0);
    let hourly = report(&service.usage(&["--json", "--bucket", "hour"]));
    assert_eq!(hourly["window"]["bucket"], "hour");
    assert_eq!(hourly["by_window"][0]["window"].as_str().unwrap().len(), 13);

    let human = service.usage(&[]);
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(
        text.contains("requests: 4 (succeeded 3, refused 1, failed 0)"),
        "{text}"
    );
    assert!(text.contains("facts-principal"), "{text}");
    assert!(text.contains("fact.list"), "{text}");

    // Every byte the store holds, write-ahead log included. The positive
    // control is a row's own action name: a scan that cannot see that could
    // not have seen the canary either.
    let contains = |bytes: &[u8], needle: &str| {
        bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    };
    let mut control_seen = false;
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", service.sqlite.display()));
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        control_seen |= contains(&bytes, "/facts/{fact_id}");
        assert!(
            !contains(&bytes, CANARY),
            "a caller's path or query text reached {}",
            path.display()
        );
    }
    assert!(
        control_seen,
        "the scan never saw a usage row, so it proves nothing"
    );
}

#[test]
fn a_report_on_a_store_that_does_not_exist_refuses_and_creates_nothing() {
    let temp = TempDir::new().expect("temporary root");
    let (config, sqlite) = write_config(temp.path(), 8421);
    let output = isolated(temp.path())
        .args(["company", "usage", "--config"])
        .arg(&config)
        .arg("--json")
        .output_alone()
        .expect("run company usage");
    assert_eq!(output.status.code(), Some(4));
    let error: Value = serde_json::from_slice(&output.stdout).expect("typed error document");
    assert_eq!(error["error"]["code"], "CONFIG_INVARIANT");
    assert!(
        error["error"]["remediation"]
            .as_str()
            .unwrap()
            .contains("kinbase company init"),
        "{error}"
    );
    assert!(
        !sqlite.exists(),
        "the report created the store it reports on"
    );
}

#[test]
fn only_this_companys_store_is_read_and_the_report_writes_nothing() {
    let temp = TempDir::new().expect("temporary root");
    let (config, sqlite) = write_config(temp.path(), 8421);
    let usage = || {
        isolated(temp.path())
            .args(["company", "usage", "--config"])
            .arg(&config)
            .arg("--json")
            .output_alone()
            .expect("run company usage")
    };
    let refused = |output: Output| {
        assert_eq!(output.status.code(), Some(4));
        let error: Value = serde_json::from_slice(&output.stdout).expect("typed error document");
        assert_eq!(error["error"]["code"], "CONFIG_INVARIANT");
        error["error"]["message"].as_str().unwrap().to_owned()
    };
    let bytes = |path: &Path| std::fs::read(path).expect("read store file");

    // A file exists at sqlite_path, but `company init` never made it a store.
    std::fs::write(&sqlite, b"").expect("empty file");
    assert!(refused(usage()).contains("not this Company's initialized store"));
    std::fs::remove_file(&sqlite).expect("remove empty file");

    // Another SQLite file with a meta table of its own is refused untouched.
    let foreign = rusqlite::Connection::open(&sqlite).expect("foreign database");
    foreign
        .execute_batch("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);")
        .expect("foreign meta table");
    drop(foreign);
    let before = bytes(&sqlite);
    assert!(refused(usage()).contains("not this Company's initialized store"));
    assert_eq!(bytes(&sqlite), before, "the report wrote to a foreign file");
    std::fs::remove_file(&sqlite).expect("remove foreign file");

    // A store migrated before usage rows existed has no usage_events table;
    // the report reads that as no rows and leaves the table to `serve`.
    let db = kinbase::company::db::CompanyDb::open(&sqlite).expect("initialize store");
    db.set_meta("company_id", "company-usage")
        .expect("stamp company");
    db.connection
        .execute_batch("DROP TABLE usage_events")
        .expect("drop usage table");
    drop(db);
    let older = report(&usage());
    assert_eq!(older["totals"]["requests"], 0);
    let db = kinbase::company::db::CompanyDb::connect(&sqlite).expect("reopen store");
    assert!(
        !db.has_table("usage_events").unwrap(),
        "the report migrated"
    );

    // A service that never set record_usage says why its report is empty.
    let config_text = std::fs::read_to_string(&config).expect("read config");
    kinbase::crypto::write_0600(
        &config,
        config_text.replace("record_usage = true\n", "").as_bytes(),
        "service config",
    )
    .expect("rewrite config");
    let off = isolated(temp.path())
        .args(["company", "usage", "--config"])
        .arg(&config)
        .output_alone()
        .expect("run company usage");
    assert!(off.status.success());
    assert!(String::from_utf8_lossy(&off.stdout).contains("recording: off"));
}

#[test]
fn a_malformed_window_is_refused_before_the_store_is_read() {
    let temp = TempDir::new().expect("temporary root");
    let (config, _) = write_config(temp.path(), 8421);
    let output = isolated(temp.path())
        .args(["company", "usage", "--config"])
        .arg(&config)
        .args(["--json", "--since", "last tuesday"])
        .output_alone()
        .expect("run company usage");
    assert_eq!(output.status.code(), Some(4));
    let error: Value = serde_json::from_slice(&output.stdout).expect("typed error document");
    assert_eq!(error["error"]["code"], "CONFIG_INVARIANT");
    // The store does not exist either, and that refusal has the same code
    // and exit; only the message shows the window was what was refused.
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--since"),
        "{error}"
    );
}
