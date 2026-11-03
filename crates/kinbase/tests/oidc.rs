//! OIDC login, refresh, and company transport. Synthetic values only.

mod oidc_support;
mod support;

use oidc_support::*;
use serde_json::{Value, json};
use std::fs;
use std::process::Output;
use std::time::{Duration, Instant};

const PRIOR: &[u8] = br#"{"refresh_token":"prior-refresh-synth","id_token":"prior.id.token"}"#;
const DENIED: &str = "AUTHORITY_SCOPE_DENIED";
const DOWN: &str = "COMPANY_UNREACHABLE";
const BAD: &str = "CONFIG_INVARIANT";
const LOGIN: &str = "Run `kinbase auth login`";
const LOOP: &str = "http://127.0.0.1:9";
const HTTPS: &str = "https://idp.invalid/realms/t";
const ROUTABLE: &str = "http://192.0.2.1:9";
const ROUTABLE_TLS: &str = "https://192.0.2.1:9";

fn ok(out: &Output) {
    assert!(out.status.success(), "{}", stderr(out));
}

fn body(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).expect("json")
}

fn has(out: &Output, needle: &str) {
    assert!(stdout(out).contains(needle), "{}", stdout(out));
}

fn assert_authorize(url: &str, scope: &str) {
    let q = query(url);
    for (key, value) in [
        ("response_type", "code"),
        ("scope", scope),
        ("client_id", CLIENT_ID),
        ("code_challenge_method", "S256"),
        ("access_type", "offline"),
        ("prompt", "consent"),
        ("tenant", "t"),
    ] {
        assert_eq!(q.get(key).map(String::as_str), Some(value), "{url}");
    }
    for key in ["state", "code_challenge"] {
        assert!(q.get(key).is_some_and(|s| !s.is_empty()), "{key} {url}");
    }
    let redir = q.get("redirect_uri").map(String::as_str).unwrap_or("");
    assert!(redir.starts_with("http://127.0.0.1:"), "{redir}");
    assert!(redir.ends_with("/callback"), "{redir}");
}

fn assert_session(path: &std::path::Path) {
    assert_eq!(mode_bits(path), 0o600);
    let value: Value = serde_json::from_slice(&fs::read(path).expect("oidc.json")).expect("json");
    let mut keys: Vec<_> = value.as_object().expect("object").keys().cloned().collect();
    keys.sort();
    assert_eq!(keys, ["id_token", "refresh_token"]);
}

fn code_form(rig: &Rig) -> String {
    rig.view()
        .forms
        .into_iter()
        .find(|f| f.contains("authorization_code"))
        .expect("code grant")
}

fn saved_refresh(rig: &Rig) -> String {
    let value: Value =
        serde_json::from_slice(&fs::read(rig.oidc_path()).expect("oidc.json")).unwrap();
    value["refresh_token"].as_str().unwrap_or("").to_owned()
}

fn noop(_: &mut Script) {}

fn bare(issuer: &str) -> Cfg {
    Cfg::oidc().quiet().issuer_is(issuer)
}

fn rule(cfg: Cfg, login: bool, edit: fn(&mut Script), code: &str) {
    let url = cfg.company_url.clone().unwrap_or_default();
    let rig = Rig::boot(cfg);
    rig.script_mut(edit);
    let out = if login {
        rig.login(false)
    } else {
        rig.issue(&url)
    };
    assert_code(&out, code);
}

fn edit_failure(tag: &str, script: &mut Script) {
    match tag {
        "down" => script.token_endpoint = Some("http://127.0.0.1:1/token".into()),
        "502" => script.http_status = Some(502),
        "429" => script.http_status = Some(429),
        "busy" => script.oauth_error = Some("temporarily_unavailable".into()),
        "text" => script.non_json = true,
        "open" => script.token_endpoint = Some("http://10.1.2.3/token".into()),
        "mismatch" => script.discovery_issuer = Some("https://not-the-issuer.example".into()),
        "client" => {
            script.oauth_error = Some("invalid_client".into());
            script.error_description = Some("desc-synth-marker".into());
        }
        "bad" => script.oauth_error = Some("Not_Valid".into()),
        _ => {}
    }
}

fn keep(cfg: Cfg, tag: &str, code: &str, echo: &str, hidden: &str) {
    let rig = Rig::boot(cfg.certified());
    rig.seed(SEEDED_REFRESH, 60);
    let before = fs::read(rig.oidc_path()).unwrap();
    let seen = rig.view().http_bytes;
    rig.script_mut(|script| edit_failure(tag, script));
    let out = rig.status();
    assert_code(&out, code);
    assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);
    assert_eq!(rig.view().http_bytes, seen, "sent a company request");
    let text = stdout(&out) + &stderr(&out);
    assert!(echo.is_empty() || text.contains(echo), "{text}");
    assert!(hidden.is_empty() || !text.contains(hidden), "{text}");
    rig.scrub(&out);
}

fn held(rig: &Rig) -> (Output, Output) {
    rig.script_mut(|s| s.hold_refresh = true);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| rig.status());
        let second = scope.spawn(|| rig.status());
        (first.join().expect("first"), second.join().expect("second"))
    })
}

fn await_refresh(rig: &Rig) {
    let start = Instant::now();
    while rig.view().refresh_calls == 0 {
        if start.elapsed() >= Duration::from_secs(8) {
            panic!("refresh never reached the provider");
        }
        std::thread::yield_now();
    }
}

#[test]
fn login_then_request_refreshes_once_and_reaches_the_store() {
    let rig = Rig::boot(Cfg::oidc().certified());
    let plain = rig.login(false);
    ok(&plain);
    assert_eq!(stdout(&plain), format!("signed in as {EMAIL}\n"));
    assert_authorize(&login_url(&plain), "openid email");
    assert_eq!(rig.view().refresh_calls, 0);
    assert_session(&rig.oidc_path());
    let status = rig.status();
    ok(&status);
    assert_eq!(body(&status)["status"], "certified");
    assert_eq!(rig.view().refresh_calls, 1);
    let json_login = rig.login(true);
    ok(&json_login);
    assert_eq!(body(&json_login), json!({"signed_in_as": EMAIL}));
    let err = stderr(&json_login);
    let diag: Value = serde_json::from_str(
        err.lines()
            .find(|line| line.contains("login_url"))
            .expect("diagnostic"),
    )
    .expect("diagnostic json");
    assert_eq!(diag["diagnostic"], "login_url");
    assert_eq!(diag["detail"]["url"], login_url(&json_login));
    assert!(diag.get("at").is_some_and(|at| !at.is_null()));
}

#[test]
fn a_bad_callback_stores_nothing() {
    // mode, token-endpoint fault, login completes, marker in the callback response, error code
    let rows: &[(&str, fn(&mut Script), bool, &str, &str)] = &[
        ("bad-state", noop, true, "400", ""),
        ("missing-state", noop, true, "400", ""),
        ("error", noop, false, "", DENIED),
        ("no-code", noop, false, "", DENIED),
        (
            "good",
            |s| s.oauth_error = Some("invalid_grant".into()),
            false,
            "",
            DENIED,
        ),
        ("good", |s| s.http_status = Some(500), false, "", DOWN),
        ("other", noop, true, "404", ""),
        ("idle", noop, true, "", ""),
    ];
    for (mode, fault, completes, mark, code) in rows {
        let rig = Rig::boot(Cfg::oidc());
        rig.write_bytes(PRIOR);
        rig.write_browser(mode);
        rig.script_mut(*fault);
        let out = rig.login(false);
        if !mark.is_empty() {
            let http = fs::read_to_string(&rig.http_log).unwrap_or_default();
            assert!(http.contains(mark), "{mode} callback log:\n{http}");
        }
        if *completes {
            ok(&out);
            assert_eq!(stdout(&out), format!("signed in as {EMAIL}\n"));
        } else {
            assert_code(&out, code);
            assert_eq!(fs::read(rig.oidc_path()).expect("prior"), PRIOR, "{mode}");
            if *mode == "good" && *code == DENIED {
                has(&out, LOGIN);
            }
            rig.scrub(&out);
        }
    }
}

#[test]
fn login_needs_a_refresh_token_an_email_and_the_right_client_auth() {
    let refuse = |mutate: fn(&mut Script)| {
        let rig = Rig::boot(Cfg::oidc());
        rig.write_bytes(PRIOR);
        rig.script_mut(mutate);
        let out = rig.login(false);
        assert_code(&out, "AUTHORITY_SCOPE_DENIED");
        assert_eq!(fs::read(rig.oidc_path()).unwrap(), PRIOR);
        rig.scrub(&out);
    };
    refuse(|s| s.omit_refresh = true);
    refuse(|s| s.omit_email = true);
    let rig = Rig::boot(Cfg::oidc().parts(true, true, true));
    ok(&rig.login(false));
    assert_eq!(
        form_get(&code_form(&rig), "client_secret").as_deref(),
        Some(SECRET)
    );
    let rig = Rig::boot(Cfg::oidc());
    let out = rig.login(false);
    ok(&out);
    assert_eq!(form_get(&code_form(&rig), "client_secret"), None);
    assert_authorize(&login_url(&out), "openid email");
    let rig = Rig::boot(Cfg::oidc());
    rig.script_mut(|s| s.offline_access = true);
    let out = rig.login(false);
    ok(&out);
    assert_authorize(&login_url(&out), "openid email offline_access");
}

#[test]
fn no_token_reaches_argv_output_or_logs() {
    let rig = Rig::boot(Cfg::oidc().certified());
    let plain = rig.login(false);
    ok(&plain);
    rig.scrub(&plain);
    rig.scrub(&rig.status());
    rig.scrub(&rig.login(true));
    let rig = Rig::boot(Cfg::oidc().certified());
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| s.http_status = Some(500));
    rig.scrub(&rig.status());
}

#[test]
fn refresh_outcomes_follow_the_provider() {
    let rig = Rig::boot(Cfg::oidc().certified());
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| s.short_refresh = true);
    ok(&rig.status());
    let rotated = saved_refresh(&rig);
    assert_ne!(rotated, SEEDED_REFRESH);
    ok(&rig.status());
    let rig = Rig::boot(Cfg::oidc().certified());
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| {
        s.omit_refresh = true;
        s.short_refresh = true;
    });
    ok(&rig.status());
    assert_eq!(saved_refresh(&rig), SEEDED_REFRESH);
    ok(&rig.status());
    let rows: &[(&str, fn(&mut Script))] = &[
        ("invalid_grant", |s| {
            s.oauth_error = Some("invalid_grant".into())
        }),
        ("no_id", |s| s.omit_id = true),
        ("no_exp", |s| s.omit_exp = true),
    ];
    for (label, mutate) in rows {
        let rig = Rig::boot(Cfg::oidc().certified());
        rig.seed(SEEDED_REFRESH, 60);
        rig.script_mut(*mutate);
        let out = rig.status();
        assert_code(&out, DENIED);
        has(&out, LOGIN);
        assert!(!rig.oidc_path().exists(), "{label} kept the session");
        rig.scrub(&out);
    }
    let rig = Rig::boot(Cfg::oidc().certified());
    rig.seed(SEEDED_REFRESH, 60);
    rig.script_mut(|s| {
        s.hold_refresh = true;
        s.oauth_error = Some("invalid_grant".into());
        s.refresh_only = true;
    });
    std::thread::scope(|scope| {
        let status = scope.spawn(|| rig.status());
        await_refresh(&rig);
        let login = scope.spawn(|| rig.login(false));
        ok(&login.join().expect("login"));
        let _status = status.join().expect("status");
        assert_eq!(saved_refresh(&rig), rig.view().code_refresh);
    });
}

#[test]
fn refresh_failures_keep_the_session_and_send_nothing() {
    for (tag, code, echo, hidden) in [
        ("down", DOWN, "", ""),
        ("502", DOWN, "", ""),
        ("429", DOWN, "", ""),
        ("busy", DOWN, "", ""),
        ("text", DOWN, "", ""),
        ("open", BAD, "", ""),
        ("mismatch", BAD, "", ""),
        ("client", BAD, "invalid_client", "desc-synth-marker"),
        ("bad", BAD, "", "Not_Valid"),
    ] {
        keep(Cfg::oidc(), tag, code, echo, hidden);
    }
    keep(
        Cfg::oidc().issuer_is("http://127.0.0.1:1"),
        "",
        DOWN,
        "",
        "",
    );
}

#[test]
fn two_processes_refresh_once() {
    let rig = Rig::boot(Cfg::oidc().certified());
    rig.seed(SEEDED_REFRESH, 60);
    let (first, second) = held(&rig);
    ok(&first);
    ok(&second);
    assert_eq!(body(&first)["status"], "certified");
    assert_eq!(body(&second)["status"], "certified");
    assert_eq!(rig.view().refresh_calls, 1);
}

#[test]
fn requests_without_a_session_fail_before_connecting() {
    let rig = Rig::boot(Cfg::oidc().certified());
    let status = rig.status();
    assert_code(&status, DENIED);
    has(&status, LOGIN);
    let url = rig.gateway.clone();
    let issue = rig.issue(&url);
    assert_code(&issue, DENIED);
    has(&issue, LOGIN);
    assert_eq!(rig.view().accepts, 0);
}

#[test]
fn a_gateway_401_asks_for_login() {
    let rig = Rig::boot(Cfg::oidc().gate(Gate::Plain401));
    rig.seed(SEEDED_REFRESH, 3600);
    let before = fs::read(rig.oidc_path()).unwrap();
    let url = rig.gateway.clone();
    let out = rig.issue(&url);
    assert_code(&out, DENIED);
    has(&out, LOGIN);
    assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);
    rig.scrub(&out);
    let rig = Rig::boot(Cfg::oidc().facts("wrong-facts-synth-ZZ"));
    rig.seed(SEEDED_REFRESH, 3600);
    let before = fs::read(rig.oidc_path()).unwrap();
    let url = rig.gateway.clone();
    let out = rig.issue(&url);
    let stored = rig.last_body();
    let code = json_code(&stored);
    assert!(!code.is_empty(), "server body: {stored}");
    assert_code(&out, &code);
    if !stored.contains("kinbase auth login") {
        assert!(!stdout(&out).contains(LOGIN), "{}", stdout(&out));
    }
    assert_eq!(fs::read(rig.oidc_path()).unwrap(), before);
}

#[test]
fn the_store_reads_the_facts_token_from_its_own_header() {
    let rig = Rig::boot(Cfg::oidc().gate(Gate::KeepAuth).certified());
    ok(&rig.login(false));
    let status = rig.status();
    ok(&status);
    assert_eq!(body(&status)["status"], "certified");
    let rig = Rig::boot(
        Cfg::oidc()
            .parts(false, false, false)
            .gate(Gate::Reframe)
            .certified(),
    );
    let status = rig.status();
    ok(&status);
    assert_eq!(body(&status)["status"], "certified");
    let view = rig.view();
    assert!(
        !view.authz.is_empty()
            && view
                .authz
                .iter()
                .all(|header| header == &format!("Bearer {FACTS}")),
        "{:?}",
        view.authz
    );
    assert!(view.facts_headers.is_empty(), "{:?}", view.facts_headers);
}

#[test]
fn oidc_config_and_endpoint_rules() {
    let plain = || Cfg::oidc().quiet().parts(false, false, false);
    rule(bare(LOOP).at(LOOP), false, noop, DENIED);
    rule(bare(HTTPS).allow().at(ROUTABLE), false, noop, BAD);
    rule(bare(HTTPS).at(ROUTABLE_TLS), false, noop, BAD);
    rule(bare(HTTPS).allow().at(ROUTABLE_TLS), false, noop, DENIED);
    rule(
        bare("http://idp.invalid/realms/t").at(LOOP),
        true,
        noop,
        BAD,
    );
    rule(bare(HTTPS).at(LOOP), true, noop, DOWN);
    rule(Cfg::oidc(), true, |s| edit_failure("mismatch", s), BAD);
    rule(Cfg::oidc(), true, |s| edit_failure("open", s), BAD);
    for (issuer, client, secret) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        rule(
            Cfg::oidc()
                .quiet()
                .parts(issuer, client, secret)
                .issuer_is(HTTPS)
                .at(LOOP),
            true,
            noop,
            BAD,
        );
    }
    rule(plain().at(LOOP), true, noop, BAD);
    rule(plain().allow().at(ROUTABLE), false, noop, DOWN);
}

#[test]
fn an_untrusted_gateway_certificate_sends_no_token() {
    for gate in [Gate::Untrusted, Gate::WrongName] {
        let rig = Rig::boot(Cfg::oidc().gate(gate));
        rig.seed(SEEDED_REFRESH, 3600);
        let url = rig.gateway.clone();
        assert_code(&rig.issue(&url), DOWN);
        assert_eq!(rig.view().http_bytes, 0, "{url}");
    }
}

#[test]
fn chunked_and_unframed_responses_parse() {
    let mut cfg = Cfg::oidc().parts(false, false, false).gate(Gate::Reframe);
    cfg.certify = true;
    let rig = Rig::boot(cfg);
    let mut payloads: Vec<String> = Vec::new();
    for frame in [Frame::Chunked, Frame::Eof, Frame::Length] {
        rig.set_frame(frame);
        let out = rig.status();
        ok(&out);
        payloads.push(body(&out)["status"].as_str().unwrap_or("").into());
    }
    assert_eq!(payloads, vec!["certified".to_owned(); 3]);
    // Non-OIDC https is refused before the socket, so truncation needs a session.
    let rig = Rig::boot(Cfg::oidc().gate(Gate::Truncate));
    rig.seed(SEEDED_REFRESH, 3600);
    let url = rig.gateway.clone();
    assert_code(&rig.issue(&url), DOWN);
}

#[test]
fn session_start_without_a_session_asks_for_login() {
    let rig = Rig::boot(Cfg::oidc().certified());
    let out = rig.session_start();
    ok(&out);
    let value = body(&out);
    assert!(
        value.to_string().contains("run kinbase auth login"),
        "{value}"
    );
    assert_eq!(value["background_verification_started"], false);
    assert_eq!(value["company_refresh"]["started"], false);
    let rig = Rig::boot(
        bare(HTTPS)
            .allow()
            .at("https://company.invalid")
            .certified(),
    );
    rig.seed(SEEDED_REFRESH, 3600);
    let out = rig.session_start();
    ok(&out);
    let value = body(&out);
    assert_eq!(value["background_verification_started"], true);
    assert_eq!(value["company_refresh"]["started"], true);
    assert_eq!(value["company_state"], "unprobed");
}
