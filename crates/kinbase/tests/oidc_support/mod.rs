//! In-process OIDC provider, browser stub, and TLS gateway. Synthetic values only.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kinbase::crypto::PrivateKey;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead as _, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

use crate::support::SpawnAlone;

pub const EMAIL: &str = "ada@example.invalid";
pub const CLIENT_ID: &str = "client-synth";
pub const SECRET: &str = "csec-synth-4nW8-bT";
const CODE: &str = "code-synth-9pL3-aQ";
pub const FACTS: &str = "facts-synth-2mX6-cR";
pub const SEEDED_REFRESH: &str = "rfr-synth-7kQ2-mZ";
const ADMIN: &str = "admin-synth-8qY1-dS";
const PRIOR_REFRESH: &str = "prior-refresh-synth";
const PRIOR_ID: &str = "prior.id.token";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Off,
    Proxy,
    KeepAuth,
    Plain401,
    Untrusted,
    WrongName,
    Truncate,
    Reframe,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Length,
    Chunked,
    Eof,
}

#[derive(Clone, Default)]
pub struct Script {
    pub short_refresh: bool,
    pub omit_refresh: bool,
    pub omit_id: bool,
    pub omit_email: bool,
    pub omit_exp: bool,
    pub oauth_error: Option<String>,
    pub error_description: Option<String>,
    pub http_status: Option<u16>,
    pub non_json: bool,
    pub discovery_issuer: Option<String>,
    pub token_endpoint: Option<String>,
    pub offline_access: bool,
    pub hold_refresh: bool,
    pub refresh_only: bool,
}

#[derive(Clone, Default)]
pub struct View {
    pub refresh_calls: usize,
    pub accepts: usize,
    pub http_bytes: usize,
    pub forms: Vec<String>,
    pub authz: Vec<String>,
    pub facts_headers: Vec<String>,
    pub upstream_bodies: Vec<String>,
    pub latest_id: String,
    pub code_refresh: String,
    current_refresh: String,
    issued_ids: Vec<String>,
    issued_refresh: Vec<String>,
}

#[derive(Clone)]
pub struct Cfg {
    pub company: bool,
    pub certify: bool,
    pub issuer: bool,
    pub client_id: bool,
    pub secret: bool,
    pub issuer_override: Option<String>,
    pub allow_non_loopback: Option<bool>,
    pub company_url: Option<String>,
    pub gate: Gate,
    pub client_facts: String,
}

impl Cfg {
    pub fn oidc() -> Self {
        Self {
            company: true,
            certify: false,
            issuer: true,
            client_id: true,
            secret: false,
            issuer_override: None,
            allow_non_loopback: None,
            company_url: None,
            gate: Gate::Proxy,
            client_facts: FACTS.to_owned(),
        }
    }

    pub fn quiet(mut self) -> Self {
        self.company = false;
        self.gate = Gate::Off;
        self
    }

    pub fn at(mut self, url: &str) -> Self {
        self.company_url = Some(url.to_owned());
        self
    }

    pub fn issuer_is(mut self, issuer: &str) -> Self {
        self.issuer_override = Some(issuer.to_owned());
        self
    }

    pub fn allow(mut self) -> Self {
        self.allow_non_loopback = Some(true);
        self
    }

    pub fn parts(mut self, issuer: bool, client: bool, secret: bool) -> Self {
        self.issuer = issuer;
        self.client_id = client;
        self.secret = secret;
        self
    }

    pub fn certified(mut self) -> Self {
        self.certify = true;
        self
    }

    pub fn gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }

    pub fn facts(mut self, token: &str) -> Self {
        self.client_facts = token.to_owned();
        self
    }
}

struct Inner {
    view: Mutex<View>,
    script: Mutex<Script>,
    frame: Mutex<Frame>,
    argv_log: PathBuf,
    tls: Option<Arc<rustls::ServerConfig>>,
}

pub struct Rig {
    _tmp: TempDir,
    home: PathBuf,
    config_home: PathBuf,
    repo: PathBuf,
    state_home: PathBuf,
    client_tmp: PathBuf,
    bin: PathBuf,
    pub argv_log: PathBuf,
    pub http_log: PathBuf,
    cert_pem: PathBuf,
    provider: String,
    pub gateway: String,
    inner: Arc<Inner>,
    service: Mutex<Option<Child>>,
    root_key: PrivateKey,
}

impl Rig {
    pub fn boot(cfg: Cfg) -> Self {
        let tmp = TempDir::new().expect("temp");
        let root = tmp.path().to_path_buf();
        let home = root.join("home");
        let config_home = root.join("config");
        let state_home = root.join("state");
        let client_tmp = root.join("client-tmp");
        let repo = root.join("repo");
        let bin = root.join("bin");
        for dir in [&home, &config_home, &state_home, &client_tmp, &repo, &bin] {
            fs::create_dir_all(dir).expect("dir");
        }
        let argv_log = root.join("browser.argv");
        let mut view = View::default();
        view.current_refresh = SEEDED_REFRESH.to_owned();
        let inner = Arc::new(Inner {
            view: Mutex::new(view),
            script: Mutex::new(Script::default()),
            frame: Mutex::new(Frame::Length),
            argv_log: argv_log.clone(),
            tls: tls_identity(cfg.gate),
        });
        let root_key = PrivateKey::generate();
        let (service, upstream) = if cfg.company {
            let (child, port) = serve_company(&root, &root_key);
            (Some(child), format!("127.0.0.1:{port}"))
        } else {
            (None, String::new())
        };
        let gateway = if cfg.gate == Gate::Off {
            String::new()
        } else {
            let (listener, port) = bind_loopback();
            let scheme = if inner.tls.is_some() { "https" } else { "http" };
            accept(listener, {
                let inner = Arc::clone(&inner);
                let upstream = upstream.clone();
                let gate = cfg.gate;
                move |tcp| gateway_conn(tcp, gate, &upstream, &inner)
            });
            format!("{scheme}://127.0.0.1:{port}")
        };
        let (listener, port) = bind_loopback();
        let provider = format!("http://127.0.0.1:{port}");
        accept(listener, {
            let inner = Arc::clone(&inner);
            let origin = provider.clone();
            move |tcp| provider_conn(tcp, &origin, &inner)
        });
        let rig = Rig {
            argv_log,
            http_log: root.join("browser.http"),
            cert_pem: fixture("ca.pem"),
            home,
            config_home,
            repo,
            state_home,
            client_tmp,
            bin,
            provider,
            gateway,
            inner,
            service: Mutex::new(service),
            root_key,
            _tmp: tmp,
        };
        rig.write_browser("good");
        if cfg.certify {
            rig.write_config(&Cfg {
                company_url: Some("http://127.0.0.1:1".into()),
                ..cfg.clone()
            });
            rig.certify();
        } else {
            git_init(&rig.repo);
        }
        rig.write_config(&cfg);
        rig
    }

    pub fn script_mut(&self, f: impl FnOnce(&mut Script)) {
        f(&mut self.inner.script.lock().expect("script"));
    }

    pub fn set_frame(&self, frame: Frame) {
        *self.inner.frame.lock().expect("frame") = frame;
    }

    pub fn view(&self) -> View {
        self.inner.view.lock().expect("view").clone()
    }

    pub fn last_body(&self) -> String {
        self.view()
            .upstream_bodies
            .last()
            .cloned()
            .unwrap_or_default()
    }

    pub fn oidc_path(&self) -> PathBuf {
        self.config_home.join("kinbase").join("oidc.json")
    }

    pub fn write_bytes(&self, bytes: &[u8]) {
        private_write(&self.oidc_path(), bytes);
    }

    pub fn seed(&self, refresh: &str, ttl: u64) {
        let id = jwt(Some(epoch() + ttl), Some(EMAIL));
        self.write_bytes(
            format!(r#"{{"refresh_token":"{refresh}","id_token":"{id}"}}"#).as_bytes(),
        );
        let mut view = self.inner.view.lock().expect("view");
        view.current_refresh = refresh.to_owned();
        view.latest_id = id;
    }

    pub fn write_browser(&self, mode: &str) {
        let script = include_str!("../fixtures/oidc/browser.sh")
            .replace("@ARGV@", &self.argv_log.display().to_string())
            .replace("@HTTP@", &self.http_log.display().to_string())
            .replace("@CODE@", CODE)
            .replace("@MODE@", mode);
        for name in ["xdg-open", "open"] {
            let path = self.bin.join(name);
            fs::write(&path, &script).expect("browser");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        }
    }

    pub fn run(&self, args: &[&str], stdin: Option<&[u8]>) -> Output {
        let path = format!(
            "{}:{}",
            self.bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_kinbase"));
        cmd.current_dir(&self.repo)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env("TMPDIR", &self.client_tmp)
            .env("SSL_CERT_FILE", &self.cert_pem)
            .env("PATH", path)
            .env_remove("KINBASE_COMPANY_URL")
            .env_remove("SSL_CERT_DIR")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(bytes) = stdin {
            cmd.stdin(Stdio::piped());
            let mut child = cmd.spawn_alone().expect("spawn");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(bytes)
                .expect("stdin");
            child.wait_with_output().expect("wait")
        } else {
            cmd.output_alone().expect("run")
        }
    }

    pub fn login(&self, json_mode: bool) -> Output {
        let mut args = vec!["auth", "login"];
        if json_mode {
            args.push("--json");
        }
        self.run(&args, None)
    }

    pub fn status(&self) -> Output {
        let repo = self.repo.display().to_string();
        self.run(&["status", "--repo", &repo, "--json"], None)
    }

    pub fn issue(&self, url: &str) -> Output {
        let repo = self.repo.display().to_string();
        self.run(
            &["repo", "issue", "--repo", &repo, "--company", url, "--json"],
            None,
        )
    }

    pub fn session_start(&self) -> Output {
        let cwd = self.repo.display().to_string();
        self.run(
            &["hooks", "dispatch", "claude", "SessionStart", "--json"],
            Some(format!(r#"{{"cwd":"{cwd}"}}"#).as_bytes()),
        )
    }

    #[rustfmt::skip]
    pub fn scrub(&self, out: &Output) {
        let view = self.view();
        let mut raw = vec![view.latest_id, view.code_refresh, CODE.into(), FACTS.into(), SECRET.into(), SEEDED_REFRESH.into(), PRIOR_REFRESH.into(), PRIOR_ID.into()];
        raw.extend(view.issued_ids);
        raw.extend(view.issued_refresh);
        for form in &view.forms {
            raw.extend(form_get(form, "code_verifier"));
        }
        let mut needles = BTreeSet::new();
        for item in raw.into_iter().filter(|item| item.len() >= 8) {
            if item.contains('.') {
                needles.extend(item.split('.').filter(|seg| seg.len() >= 12).map(str::to_owned));
            }
            if item.len() >= 12 {
                needles.insert(item[..12].to_owned());
            }
            needles.insert(item);
        }
        let argv = fs::read_to_string(&self.argv_log).unwrap_or_default();
        let hay = format!("{}{}{argv}", stdout(out), stderr(out));
        assert!(clean(&needles, &hay), "output leaked a secret\n{}", stderr(out));
        for root in [&self.home, &self.config_home, &self.state_home, &self.client_tmp, &self.repo] {
            assert_files_clean(root, &needles);
        }
    }

    #[rustfmt::skip]
    fn write_config(&self, cfg: &Cfg) {
        let dir = self.config_home.join("kinbase");
        fs::create_dir_all(&dir).expect("config dir");
        let personal = self.home.join("personal");
        fs::create_dir_all(&personal).expect("personal");
        fs::set_permissions(&personal, fs::Permissions::from_mode(0o700)).ok();
        for (name, bytes) in [
            ("root-public.key", format!("{}\n", self.root_key.public().to_hex())),
            ("facts.token", cfg.client_facts.clone()),
            ("admin.token", ADMIN.to_owned()),
            ("client.secret", SECRET.to_owned()),
        ] {
            private_write(&dir.join(name), bytes.as_bytes());
        }
        for (name, label) in [("client.key", "client key"), ("maintainer.key", "maintainer key")] {
            let path = dir.join(name);
            if !path.exists() {
                PrivateKey::generate().save_new(&path, label).expect(label);
            }
        }
        let company_url = cfg.company_url.clone().unwrap_or_else(|| self.gateway.clone());
        let facts = dir.join("facts.token");
        let mut body = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"{}\"\n\n[company]\nurl = \"{company_url}\"\nfacts_token_file = \"{}\"\nroot_public_key_file = \"{}\"\ncache_root = \"{}\"\nclient_key_file = \"{}\"\nmaintainer_key_file = \"{}\"\nadmin_token_file = \"{}\"\n",
            personal.display(), facts.display(), dir.join("root-public.key").display(), self.home.join("cache").display(),
            dir.join("client.key").display(), dir.join("maintainer.key").display(), dir.join("admin.token").display(),
        );
        if cfg.allow_non_loopback == Some(true) {
            body.push_str("allow_non_loopback = true\n");
        }
        if cfg.issuer {
            let issuer = cfg.issuer_override.clone().unwrap_or_else(|| self.provider.clone());
            body.push_str(&format!("oidc_issuer = \"{issuer}\"\n"));
        }
        if cfg.client_id {
            body.push_str(&format!("oidc_client_id = \"{CLIENT_ID}\"\n"));
        }
        if cfg.secret {
            body.push_str(&format!("oidc_client_secret_file = \"{}\"\n", dir.join("client.secret").display()));
        }
        private_write(&dir.join("config.toml"), body.as_bytes());
    }

    #[rustfmt::skip]
    fn certify(&self) {
        git_init(&self.repo);
        let repository_uuid = "01234567-89ab-cdef-0123-456789abcdef";
        let unsigned = json!({"schema": "kinbase-repo-certificate/1", "repository_uuid": repository_uuid, "issued_at": "2026-09-08T12:00:00.000Z", "company_id": "company-test"});
        let signed = self.root_key.sign_document("repo-certificate", &unsigned).expect("sign certificate");
        let certificate = self._tmp.path().join("certificate.json");
        private_write(&certificate, kinbase::json::canonical_text(&signed).as_bytes());
        let repo = self.repo.display().to_string();
        let cert = certificate.display().to_string();
        let init = self.run(&["repo", "init", "--repo", &repo, "--certificate", &cert, "--json"], None);
        assert!(init.status.success(), "repo init: {}", stderr(&init));
        let mut event = packet_event(repository_uuid);
        event.sign(&self.root_key).expect("sign fact");
        let bytes = kinbase::json::canonical_bytes(&event.document());
        let digest = kinbase::hash::sha256_bytes(&bytes);
        let relative = format!("{}/{}/{}.json", &digest[..2], &digest[2..4], &digest[4..]);
        private_write(&self.repo.join(".kin/events").join(&relative), &bytes);
        let event_path = format!(".kin/events/{relative}");
        let add = git(&self.repo, &["add", ".gitattributes", ".kin/kinbase.toml", &event_path]);
        assert!(add.status.success(), "git add: {}", stderr(&add));
        let commit = git(&self.repo, &["commit", "-m", "certified corpus"]);
        assert!(commit.status.success(), "git commit: {}", stderr(&commit));
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(child) = self.service.lock().expect("service").as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn git(repo: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .current_dir(repo)
        .env("GIT_AUTHOR_NAME", "oidc")
        .env("GIT_AUTHOR_EMAIL", "oidc@example.invalid")
        .env("GIT_COMMITTER_NAME", "oidc")
        .env("GIT_COMMITTER_EMAIL", "oidc@example.invalid")
        .args(args)
        .output_alone()
        .expect("git")
}

fn git_init(repo: &Path) {
    let git = Command::new("git")
        .args(["init", "-q", "--initial-branch=main"])
        .current_dir(repo)
        .output_alone()
        .expect("git init");
    assert!(git.status.success(), "git init");
}

fn tls_identity(gate: Gate) -> Option<Arc<rustls::ServerConfig>> {
    let names = match gate {
        Gate::Untrusted => ("untrusted.crt.der", "untrusted.key.der"),
        Gate::WrongName => ("wrong-name.crt.der", "wrong-name.key.der"),
        Gate::Reframe | Gate::Off => return None,
        _ => ("gateway.crt.der", "gateway.key.der"),
    };
    Some(server_config(names.0, names.1))
}

fn server_config(cert: &str, key: &str) -> Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(fs::read(fixture(cert)).expect("cert"));
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        fs::read(fixture(key)).expect("key"),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls12")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("identity"),
    )
}

fn bind_loopback() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

fn accept(listener: TcpListener, on: impl Fn(TcpStream) + Send + Sync + 'static) {
    let on = Arc::new(on);
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(tcp) = incoming else { break };
            let on = Arc::clone(&on);
            thread::spawn(move || on(tcp));
        }
    });
}

fn gateway_conn(mut tcp: TcpStream, gate: Gate, upstream: &str, inner: &Inner) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    inner.view.lock().expect("view").accepts += 1;
    let Some(tls) = inner.tls.clone() else {
        plain_gate(&mut tcp, upstream, inner);
        return;
    };
    let Ok(mut conn) = rustls::ServerConnection::new(tls) else {
        return;
    };
    let req = read_http(&mut rustls::Stream::new(&mut conn, &mut tcp));
    note(inner, &req);
    if req.is_empty() {
        return;
    }
    if gate == Gate::Truncate {
        let raw = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"status\":\"certified\"}";
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let _ = stream.write_all(raw);
        let _ = stream.flush();
        return;
    }
    let response = tls_response(gate, upstream, inner, &req);
    {
        let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
        let _ = stream.write_all(&response);
        let _ = stream.flush();
    }
    conn.send_close_notify();
    while conn.wants_write() {
        if conn.write_tls(&mut tcp).is_err() {
            break;
        }
    }
}

fn tls_response(gate: Gate, upstream: &str, inner: &Inner, req: &[u8]) -> Vec<u8> {
    if gate == Gate::Plain401 || !bearer_ok(inner, req) {
        return plain_401();
    }
    let outbound = if gate == Gate::KeepAuth {
        req.to_vec()
    } else {
        strip_authorization(req)
    };
    let raw = forward(upstream, &outbound);
    record_upstream(inner, &raw);
    if raw.is_empty() { plain_401() } else { raw }
}

fn plain_gate(tcp: &mut TcpStream, upstream: &str, inner: &Inner) {
    let req = read_http(tcp);
    note(inner, &req);
    let frame = *inner.frame.lock().expect("frame");
    let raw = forward(upstream, &req);
    let (status, mut body) = split_response(&raw);
    record_upstream(inner, &raw);
    if body.first() == Some(&b'{') {
        body.splice(1..1, std::iter::repeat_n(b' ', 256 * 1024));
    }
    let _ = tcp.write_all(&reframe(&status, &body, frame));
}

fn record_upstream(inner: &Inner, raw: &[u8]) {
    let body = String::from_utf8_lossy(&split_response(raw).1).into_owned();
    inner.view.lock().expect("view").upstream_bodies.push(body);
}

fn provider_conn(mut tcp: TcpStream, base: &str, inner: &Inner) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(8)));
    let req = read_http(&mut tcp);
    if req.is_empty() {
        return;
    }
    let head = String::from_utf8_lossy(&req);
    let path = head
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/");
    if path.ends_with("/.well-known/openid-configuration") {
        discovery(&mut tcp, base, inner);
    } else if path.ends_with("/token") {
        token_endpoint(&mut tcp, &req, inner);
    } else {
        let _ = write_http(&mut tcp, 404, "text/plain", "nope");
    }
}

#[rustfmt::skip]
fn discovery(tcp: &mut TcpStream, base: &str, inner: &Inner) {
    let script = inner.script.lock().expect("script").clone();
    let issuer = script.discovery_issuer.clone().unwrap_or_else(|| base.to_owned());
    let token = script.token_endpoint.clone().unwrap_or_else(|| format!("{base}/token"));
    let mut scopes = vec!["openid".to_owned(), "email".to_owned()];
    if script.offline_access {
        scopes.push("offline_access".to_owned());
    }
    let body = json!({"issuer": issuer, "authorization_endpoint": format!("{base}/authorize?tenant=t"), "token_endpoint": token, "scopes_supported": scopes}).to_string();
    let _ = write_http(tcp, 200, "application/json", &body);
}

fn token_endpoint(tcp: &mut TcpStream, req: &[u8], inner: &Inner) {
    let head = String::from_utf8_lossy(req_head(req));
    let content_type = header(&head, "content-type").unwrap_or_default();
    let body = String::from_utf8_lossy(req_body(req)).into_owned();
    inner.view.lock().expect("view").forms.push(body.clone());
    if !content_type
        .to_ascii_lowercase()
        .starts_with("application/x-www-form-urlencoded")
    {
        let _ = write_http(
            tcp,
            415,
            "application/json",
            r#"{"error":"invalid_request"}"#,
        );
        return;
    }
    let refresh = form_get(&body, "grant_type").as_deref() == Some("refresh_token");
    let presented = form_get(&body, "refresh_token").unwrap_or_default();
    if refresh {
        inner.view.lock().expect("view").refresh_calls += 1;
    }
    let script = inner.script.lock().expect("script").clone();
    if refresh && script.hold_refresh {
        thread::sleep(Duration::from_secs(1));
    }
    if (!script.refresh_only || refresh) && fault_response(tcp, &script) {
        return;
    }
    if refresh && presented != inner.view.lock().expect("view").current_refresh {
        let _ = write_http(tcp, 400, "application/json", r#"{"error":"invalid_grant"}"#);
        return;
    }
    if !refresh && !code_grant_ok(&body, inner) {
        let _ = write_http(tcp, 400, "application/json", r#"{"error":"invalid_grant"}"#);
        return;
    }
    issue_token(tcp, inner, &script, refresh);
}

#[rustfmt::skip]
fn fault_response(tcp: &mut TcpStream, script: &Script) -> bool {
    if let Some(status) = script.http_status && (status >= 500 || status == 429) {
        let _ = write_http(tcp, status, "application/json", r#"{"error":"server_error"}"#);
        return true;
    }
    if script.non_json {
        let _ = write_http(tcp, 200, "text/plain", "not-json");
        return true;
    }
    if let Some(error) = &script.oauth_error {
        let mut doc = json!({"error": error});
        if let Some(desc) = &script.error_description {
            doc["error_description"] = json!(desc);
        }
        let _ = write_http(tcp, 400, "application/json", &doc.to_string());
        return true;
    }
    false
}

#[rustfmt::skip]
fn issue_token(tcp: &mut TcpStream, inner: &Inner, script: &Script, refresh: bool) {
    let apply = !script.refresh_only || refresh;
    let ttl = if refresh && !script.short_refresh { 3600 } else { 60 };
    let email = if apply && script.omit_email { None } else { Some(EMAIL) };
    let exp = if apply && script.omit_exp { None } else { Some(epoch() + ttl) };
    let id = if apply && script.omit_id { None } else { Some(jwt(exp, email)) };
    let mut doc = json!({});
    let mut view = inner.view.lock().expect("view");
    if let Some(id) = id {
        doc["id_token"] = json!(id);
        view.latest_id = id.clone();
        view.issued_ids.push(id);
    }
    if !(apply && script.omit_refresh) {
        let issued = format!("rfr-issued-{}-synth", view.issued_refresh.len());
        doc["refresh_token"] = json!(issued);
        view.current_refresh = issued.clone();
        if !refresh {
            view.code_refresh = issued.clone();
        }
        view.issued_refresh.push(issued);
    }
    drop(view);
    let _ = write_http(tcp, 200, "application/json", &doc.to_string());
}

fn note(inner: &Inner, req: &[u8]) {
    if req.is_empty() {
        return;
    }
    let mut view = inner.view.lock().expect("view");
    view.http_bytes += req.len();
    let head = String::from_utf8_lossy(req_head(req));
    if let Some(value) = header(&head, "authorization") {
        view.authz.push(value);
    }
    if let Some(value) = header(&head, "x-kinbase-token") {
        view.facts_headers.push(value);
    }
}

fn bearer_ok(inner: &Inner, req: &[u8]) -> bool {
    let head = String::from_utf8_lossy(req_head(req));
    let Some(token) =
        header(&head, "authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned))
    else {
        return false;
    };
    let latest = inner.view.lock().expect("view").latest_id.clone();
    !latest.is_empty() && token == latest && exp_future(&token)
}

fn exp_future(token: &str) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else {
        return false;
    };
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| v["exp"].as_u64())
        .is_some_and(|exp| exp > epoch())
}

fn strip_authorization(req: &[u8]) -> Vec<u8> {
    let end = header_end(req).unwrap_or(req.len());
    let head = String::from_utf8_lossy(&req[..end]);
    let mut out = head
        .split_inclusive("\r\n")
        .filter(|line| !line.to_ascii_lowercase().starts_with("authorization:"))
        .collect::<String>()
        .into_bytes();
    if end < req.len() {
        out.extend_from_slice(&req[end..]);
    }
    out
}

fn forward(upstream: &str, req: &[u8]) -> Vec<u8> {
    let Ok(mut tcp) = TcpStream::connect(upstream) else {
        return Vec::new();
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
    if tcp.write_all(req).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf);
    buf
}

fn reframe(status: &str, body: &[u8], frame: Frame) -> Vec<u8> {
    let status = if status.is_empty() {
        "HTTP/1.1 200 OK"
    } else {
        status
    };
    let framing = match frame {
        Frame::Length => format!("Content-Length: {}\r\n", body.len()),
        Frame::Chunked => "Transfer-Encoding: chunked\r\n".to_owned(),
        Frame::Eof => String::new(),
    };
    let mut out =
        format!("{status}\r\nContent-Type: application/json\r\n{framing}Connection: close\r\n\r\n")
            .into_bytes();
    if frame == Frame::Chunked {
        let _ = write!(out, "{:x}\r\n", body.len());
    }
    out.extend_from_slice(body);
    if frame == Frame::Chunked {
        out.extend_from_slice(b"\r\n0\r\n\r\n");
    }
    out
}

fn split_response(raw: &[u8]) -> (String, Vec<u8>) {
    let Some(end) = header_end(raw) else {
        return (String::new(), Vec::new());
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let status = head
        .lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_owned();
    let mut body = raw[end..].to_vec();
    if let Some(n) = header(&head, "content-length").and_then(|v| v.parse().ok())
        && body.len() > n
    {
        body.truncate(n);
    }
    (status, body)
}

fn plain_401() -> Vec<u8> {
    b"HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nnot-a-kinbase".to_vec()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/oidc")
        .join(name)
}

fn read_http(reader: &mut impl Read) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(end) = header_end(&buf) {
                    let head = String::from_utf8_lossy(&buf[..end]);
                    let need = header(&head, "content-length")
                        .and_then(|v| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    if buf.len() >= end + need {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    buf
}

fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn header(head: &str, name: &str) -> Option<String> {
    head.split("\r\n").find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn req_head(req: &[u8]) -> &[u8] {
    header_end(req).map(|n| &req[..n]).unwrap_or(req)
}

fn req_body(req: &[u8]) -> &[u8] {
    header_end(req).map(|n| &req[n..]).unwrap_or(b"")
}

fn write_http(
    sock: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    sock.write_all(
        format!(
            "HTTP/1.1 {status} x\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
}

fn pairs(input: &str) -> BTreeMap<String, String> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (url_decode(key), url_decode(value))
        })
        .collect()
}

pub fn form_get(body: &str, key: &str) -> Option<String> {
    pairs(body).remove(key)
}

pub fn url_decode(input: &str) -> String {
    let plus = input.replace('+', " ");
    let bytes = plus.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&plus[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn query(url: &str) -> BTreeMap<String, String> {
    url.split_once('?')
        .map(|(_, qs)| pairs(qs))
        .unwrap_or_default()
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn assert_code(output: &Output, code: &str) {
    let text = stdout(output);
    assert!(
        text.contains(&format!("\"code\":\"{code}\""))
            || text.contains(&format!("\"code\": \"{code}\""))
            || text.contains(&format!("{code}:")),
        "missing {code}\nstdout: {text}\nstderr: {}",
        stderr(output)
    );
    if code == "AUTHORITY_SCOPE_DENIED" || code == "CONFIG_INVARIANT" {
        assert_eq!(output.status.code(), Some(4), "{code}");
    }
}

pub fn login_url(output: &Output) -> String {
    for line in stderr(output).lines() {
        let line = line.trim();
        if line.starts_with("http://") || line.starts_with("https://") {
            return line.to_owned();
        }
        if let Ok(value) = serde_json::from_str::<Value>(line)
            && value["diagnostic"] == "login_url"
        {
            return value["detail"]["url"].as_str().unwrap_or("").to_owned();
        }
    }
    String::new()
}

pub fn mode_bits(path: &Path) -> u32 {
    fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

pub fn json_code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| {
            v["error"]["code"]
                .as_str()
                .or_else(|| v["code"].as_str())
                .map(str::to_owned)
        })
        .unwrap_or_default()
}

fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn jwt(exp: Option<u64>, email: Option<&str>) -> String {
    let mut payload = json!({});
    if let Some(exp) = exp {
        payload["exp"] = json!(exp);
    }
    if let Some(email) = email {
        payload["email"] = json!(email);
    }
    let body = b64(&serde_json::to_vec(&payload).expect("payload"));
    format!(
        "{}.{body}.{}",
        b64(br#"{"alg":"none","kid":"synthetic-oidc"}"#),
        b64(b"sig-synth-5tH7-eU-not-real-signature")
    )
}

fn private_write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("parent");
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("open");
    file.write_all(bytes).expect("write");
}

fn code_grant_ok(body: &str, inner: &Inner) -> bool {
    let text = fs::read_to_string(&inner.argv_log).unwrap_or_default();
    let url = text.lines().next_back().unwrap_or("");
    let q = query(url);
    let challenge = q.get("code_challenge").map(String::as_str).unwrap_or("");
    let redirect = q.get("redirect_uri").map(String::as_str).unwrap_or("");
    form_get(body, "grant_type").as_deref() == Some("authorization_code")
        && form_get(body, "client_id").as_deref() == Some(CLIENT_ID)
        && form_get(body, "code").as_deref() == Some(CODE)
        && form_get(body, "redirect_uri").as_deref() == Some(redirect)
        && !challenge.is_empty()
        && form_get(body, "code_verifier").is_some_and(|verifier| s256(&verifier) == challenge)
}

fn s256(verifier: &str) -> String {
    b64(&kinbase::hash::sha256_raw(verifier.as_bytes()))
}

fn serve_company(root: &Path, root_key: &PrivateKey) -> (Child, u16) {
    let root_path = root.join("company-root.key");
    let token_path = root.join("facts.token");
    let config_path = root.join("kinbased.toml");
    root_key
        .save_new(&root_path, "Company root key")
        .expect("root key");
    kinbase::crypto::write_0600(&token_path, FACTS.as_bytes(), "facts token").expect("token");
    // The picked port can be taken before the service binds it; pick again.
    for _ in 0..5 {
        let port = TcpListener::bind("127.0.0.1:0")
            .and_then(|l| l.local_addr())
            .expect("port")
            .port();
        let config = format!(
            "schema_version = \"1\"\ncompany_id = \"company-demo\"\nsqlite_path = \"{}\"\nbind = \"127.0.0.1:{port}\"\nroot_key_file = \"{}\"\nfacts_token_file = \"{}\"\nauth_failures_per_minute = 1000\ndefault_fact_freshness_seconds = 900\ncandidate_lifetime_seconds = 900\nclock_skew_seconds = 300\nnonce_retention_seconds = 1300\n",
            root.join("company.sqlite").display(),
            root_path.display(),
            token_path.display(),
        );
        kinbase::crypto::write_0600(&config_path, config.as_bytes(), "service config")
            .expect("cfg");
        let mut child = Command::new(env!("CARGO_BIN_EXE_kinbase"))
            .args(["company", "serve", "--config"])
            .arg(&config_path)
            .arg("--json")
            .env("HOME", root)
            .env("XDG_CONFIG_HOME", root.join("svc-config"))
            .env("XDG_STATE_HOME", root.join("svc-state"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn_alone()
            .expect("serve");
        let mut banner = String::new();
        std::io::BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut banner)
            .expect("banner");
        if banner.contains("company-serving") {
            return (child, port);
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    panic!("company serve never bound a port");
}

fn clean(needles: &BTreeSet<String>, hay: &str) -> bool {
    needles
        .iter()
        .all(|needle| needle.is_empty() || !hay.contains(needle.as_str()))
}

fn assert_files_clean(root: &Path, needles: &BTreeSet<String>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) != Some(".git") {
                assert_files_clean(&path, needles);
            }
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if matches!(
            name,
            "oidc.json" | "facts.token" | "admin.token" | "client.secret"
        ) {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            assert!(
                clean(needles, &String::from_utf8_lossy(&bytes)),
                "{} leaked a secret",
                path.display()
            );
        }
    }
}

#[rustfmt::skip]
fn packet_event(id: &str) -> kinbase::model::FactEvent {
    serde_json::from_value(json!({
        "schema": "kinbase-event/1", "event_id": "event_oidc_status", "store_kind": "codebase",
        "authority_id": "root-steward", "authority_scope": format!("codebase:{id}"),
        "repository_id": id, "fact_id": "fact_oidc_status", "logical_key": "logical_oidc_status",
        "atom_kind": "constraint", "scope": "oidc status corpus",
        "statement": "The oidc status corpus carries one certified canonical fact.",
        "evidence_refs": [], "asserted_at": "2026-09-08T12:00:00.000Z",
        "effective_from": "2026-09-08T12:00:00.000Z", "disposition": "approved",
        "distortion": {"trigger": "oidc status reaches the store", "loss_if_absent": 9000, "rationale": "oidc request proof"},
        "parents": [], "supersedes": [], "redundancy_with": [], "complements": [], "company_refs": [],
        "authority_snapshot_cursor": "0", "confidence": 9000,
        "standing": kinbase::model::default_standing_pub(),
        "provenance": kinbase::model::default_provenance_pub(), "signer": "", "signature": ""
    }))
    .expect("event")
}
