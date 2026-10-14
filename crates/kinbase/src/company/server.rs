//! `kinbased`: the loopback Company service (architecture §6, §7, §2).
//! Every accepted connection receives exactly one bounded typed JSON
//! response, including auth failures, malformed bodies, oversized bodies,
//! wrong Host/Origin/content type, and internal errors.

use super::db::CompanyDb;
use super::trust::{self, TrustState};
use crate::config::ServiceConfig;
use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use crate::http::{self, Request};
use crate::model::{CurrentFact, FactEvent};
use crate::reducer::{AdmittedEvent, ReducerInput, Verification};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub const FACTS_TOKEN_SCOPES: [&str; 2] = ["facts:read", "questions:write"];
pub const DIRECTORY_TOKEN_SCOPES: [&str; 2] = ["directory:read", "admin:issue"];
pub const AUTHORITY_TOKEN_SCOPES: [&str; 2] = ["answers:write", "questions:write"];
/// The failure-counter subject for a request presenting no known token.
const UNAUTHENTICATED_SUBJECT: &str = "unauthenticated";
pub const REQUEST_EXPIRY_MAX_SECONDS: i64 = 15 * 60;
pub const MAX_READ_ITEMS: usize = 500;
/// The ceiling on connections being served at once. Every accepted
/// connection costs a thread that waits out a five-second read timeout
/// before any credential is looked at, so on a routable bind a few thousand
/// silent sockets starve the real clients of threads. The ceiling keeps that
/// cost a property of the service rather than of the peer.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Connections being served right now. The process serves one listener, so
/// one counter is the whole population.
static LIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

/// Holds one place under [`MAX_CONCURRENT_CONNECTIONS`] for as long as it
/// lives. Releasing on drop is what gives the place back when a handler
/// panics or returns early: a leaked place is capacity lost until restart.
struct ConnectionSlot;

impl ConnectionSlot {
    /// `None` when the ceiling is already taken. The count rises in one
    /// compare-and-set, so two accepts cannot both claim the last place.
    fn acquire() -> Option<Self> {
        LIVE_CONNECTIONS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                (live < MAX_CONCURRENT_CONNECTIONS).then_some(live + 1)
            })
            .ok()
            .map(|_| ConnectionSlot)
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct ServiceState {
    pub config: ServiceConfig,
    pub root: PrivateKey,
    pub started_at: String,
}

type Handled = Result<(u16, Value), (u16, ContractError)>;

fn refuse(status: u16, error: ContractError) -> (u16, ContractError) {
    (status, error)
}

/// Run a destination write as one immediate SQLite transaction. Every side
/// effect in `work` commits together or rolls back together.
fn with_immediate_transaction<T>(
    db: &CompanyDb,
    work: impl FnOnce() -> Result<T, (u16, ContractError)>,
) -> Result<T, (u16, ContractError)> {
    db.connection
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(|error| {
            refuse(
                500,
                ContractError::internal(format!("begin transaction: {error}")),
            )
        })?;
    let result = work();
    match result {
        Ok(value) => db
            .connection
            .execute_batch("COMMIT")
            .map(|_| value)
            .map_err(|error| {
                let _ = db.connection.execute_batch("ROLLBACK");
                refuse(
                    500,
                    ContractError::internal(format!("commit transaction: {error}")),
                )
            }),
        Err(error) => {
            let _ = db.connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

/// The one indistinguishable auth refusal body (architecture §6).
fn auth_refusal() -> (u16, ContractError) {
    (
        401,
        ContractError::refused(
            "AUTHORITY_SCOPE_DENIED",
            "request not authorized",
            "Present a valid scoped bearer token, its bound client key, a fresh nonce and expiry, and a valid request signature.",
        ),
    )
}

pub struct AuthContext {
    pub token: super::db::TokenRow,
    pub client_key: String,
    pub principal_key: String,
}

fn now_minute() -> i64 {
    crate::time::now_utc().timestamp() / 60
}

fn now_hour() -> i64 {
    crate::time::now_utc().timestamp() / 3600
}

/// Register/refresh the token records from the token files (idempotent at
/// startup) and validate `facts_token_scopes`.
pub fn register_tokens(db: &CompanyDb, config: &ServiceConfig) -> Result<Value, ContractError> {
    // A role's file holds its one current token. Registering it retires
    // every other token of that role, and a role whose file is no longer
    // configured keeps none: rotating a file used to leave the previous
    // bearer token valid forever.
    // Every file is read before anything changes, and the registrations and
    // retirements commit together: a later unreadable file used to abort
    // startup after earlier roles had already lost their tokens.
    let mut loaded = Vec::new();
    for (path, label, role, scopes, authority_scopes, principal) in [
        (
            Some(&config.facts_token_file),
            "facts token",
            "facts",
            &FACTS_TOKEN_SCOPES[..],
            &config.facts_token_scopes[..],
            "facts-principal",
        ),
        (
            config.directory_token_file.as_ref(),
            "directory token",
            "directory",
            &DIRECTORY_TOKEN_SCOPES[..],
            &[][..],
            "directory-principal",
        ),
        (
            config.admin_token_file.as_ref(),
            "administrative token",
            "admin",
            &["admin:issue"][..],
            &[][..],
            "admin-principal",
        ),
        (
            config.authority_token_file.as_ref(),
            "authority token",
            "authority",
            &AUTHORITY_TOKEN_SCOPES[..],
            &[][..],
            "authority-principal",
        ),
    ] {
        let record = path
            .map(|path| crate::config::TokenRecord::load(path, label))
            .transpose()?;
        loaded.push((record, role, scopes, authority_scopes, principal));
    }
    let (roles, retired) = with_immediate_transaction(db, || {
        let mut roles = Vec::new();
        let mut retired = 0usize;
        for (record, role, scopes, authority_scopes, principal) in &loaded {
            let Some(record) = record else {
                retired += db
                    .retire_tokens_with_role(role)
                    .map_err(|error| refuse(500, error))?;
                continue;
            };
            db.register_token(&record.token, role, scopes, authority_scopes, principal)
                .map_err(|error| refuse(500, error))?;
            retired += db
                .retire_other_tokens(role, &record.token)
                .map_err(|error| refuse(500, error))?;
            roles.push(*role);
        }
        Ok((roles, retired))
    })
    .map_err(|(_, error)| error)?;
    Ok(json!({
        "roles": roles,
        "facts_token_scopes_configured": !config.facts_token_scopes.is_empty(),
        "retired_token_count": retired
    }))
}

pub fn serve(
    config: ServiceConfig,
    root: PrivateKey,
    json_output: bool,
) -> Result<(), ContractError> {
    let db = CompanyDb::open(&config.sqlite_path)?;
    db.set_meta("company_id", &config.company_id)?;
    db.set_meta("root_public_key", &root.public().to_hex())?;
    register_tokens(&db, &config)?;
    drop(db);
    let listener = TcpListener::bind(config.bind).map_err(|error| {
        ContractError::unreachable(format!(
            "cannot bind the declared loopback address ({})",
            error.kind()
        ))
    })?;
    let state = Arc::new(ServiceState {
        config,
        root,
        started_at: crate::time::now_rfc3339_millis(),
    });
    let banner = json!({
        "status": "company-serving",
        "bind": state.config.bind.to_string(),
        "company_id": state.config.company_id,
        "root_public_key": state.root.public().to_hex(),
        "started_at": state.started_at
    });
    if json_output {
        println!("{}", crate::json::canonical_text(&banner));
    } else {
        println!("status: company-serving");
        println!("bind: {}", state.config.bind);
    }
    // A service whose database has been deleted is serving nothing and should
    // say so by exiting. Without this a `serve` outlives its own state forever:
    // one acceptance run left 3,800 orphaned daemons holding ports and memory,
    // each one pointed at a temporary directory that no longer existed. The
    // check is cheap, it is the service's own liveness rather than a caller's,
    // and it never fires for a real deployment whose database stays put.
    let watched = state.config.sqlite_path.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if !watched.exists() {
                eprintln!(
                    "company store {} no longer exists; exiting rather than serving a store that is gone",
                    watched.display()
                );
                std::process::exit(0);
            }
        }
    });
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // The place is claimed on the accept thread, before the worker
        // exists. Claiming it inside the worker would hand every peer a
        // thread first and leave the ceiling decorative.
        let Some(slot) = ConnectionSlot::acquire() else {
            refuse_over_ceiling(stream);
            continue;
        };
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let _slot = slot;
            handle_connection(stream, state)
        });
    }
    Ok(())
}

/// The typed refusal for a connection over the ceiling, written from the
/// accept thread. The socket goes non-blocking first: a peer advertising no
/// receive window would otherwise hold the accept loop for a whole write
/// timeout per connection, which is the starvation the ceiling exists to
/// stop. A refusal that does not fit the send buffer goes with the socket.
fn refuse_over_ceiling(mut stream: TcpStream) {
    let error = ContractError::limit(
        "the service is already serving its ceiling of concurrent connections",
        json!({"refused_count": 1, "omitted_count": 1, "ceiling": MAX_CONCURRENT_CONNECTIONS}),
    );
    let _ = stream.set_nonblocking(true);
    let _ = http::respond(&mut stream, 503, &http::error_body(&error));
}

fn handle_connection(mut stream: TcpStream, state: Arc<ServiceState>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    let request = match http::read_request(&stream, crate::model::MAX_EVENT_BYTES * 4) {
        Ok(request) => request,
        Err(http::ReadError::Empty) => return,
        Err(http::ReadError::Bad(status, error)) => {
            let _ = http::respond(&mut stream, status, &http::error_body(&error));
            return;
        }
    };
    // Rendering the refusal happens inside the guard as well: a panic there
    // closed the connection with no response at all, which the client
    // reports as an outage.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match handle(&state, &request) {
            Ok(answer) => answer,
            Err((status, error)) => (status, http::error_body(&error)),
        }
    }));
    // The fallback's message is constant ASCII, so rendering it cannot panic;
    // it keeps the whole typed envelope (remediation, retryable, evidence).
    let (status, body) = outcome.unwrap_or_else(|_| {
        (
            500,
            http::error_body(&ContractError::internal(
                "request handler failed; evidence preserved in the service audit",
            )),
        )
    });
    let _ = http::respond(&mut stream, status, &body);
}

fn handle(state: &ServiceState, request: &Request) -> Handled {
    let host = request.header("host").unwrap_or_default();
    // A Host that must be loopback is a DNS-rebinding guard for a service on the
    // operator's own machine. On a non-loopback bind the Host is the Service
    // name, so keeping the check there refuses every request; the two move together.
    if !host_is_loopback(host) && !state.config.allow_non_loopback {
        return Err(refuse(
            403,
            ContractError::refused(
                "CONFIG_INVARIANT",
                "Host header is not the loopback endpoint",
                "Address the service by its loopback bind address.",
            ),
        ));
    }
    if request.header("origin").is_some() {
        return Err(refuse(
            403,
            ContractError::refused(
                "CONFIG_INVARIANT",
                "Origin-bearing requests are refused",
                "Do not send an Origin header; browser contexts are not clients.",
            ),
        ));
    }
    if !request.body.is_empty() || request.method == "POST" {
        let content_type = request
            .header("content-type")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.starts_with("application/json") {
            return Err(refuse(
                415,
                ContractError::refused(
                    "CONFIG_INVARIANT",
                    "bodies must be application/json",
                    "Send canonical JSON with Content-Type: application/json.",
                ),
            ));
        }
    }
    // The store opens before the credential is examined because
    // authentication reads it: the token record, the per-subject failure
    // counters and the request nonce all live here.
    let db = CompanyDb::connect(&state.config.sqlite_path).map_err(|error| refuse(500, error))?;
    let now = crate::time::now_rfc3339_millis();
    let route = normalize_route(&request.route);
    if route == "/status"
        && request.method == "GET"
        && request.header("authorization").is_none()
        && request.header("x-kinbase-signature").is_none()
    {
        // Unauthenticated status is refused like every other read.
        db.record_auth_failure(now_minute(), UNAUTHENTICATED_SUBJECT)
            .map_err(|error| refuse(500, error))?;
        return Err(auth_refusal());
    }
    let auth = authenticate(&db, state, request, &now)?;
    // Periodic obligations run behind authentication, never in front of it.
    // They prune nonces, retire lapsed manifest observations and sign
    // fact-events with the Company root key; running them on arrival meant an
    // unauthenticated peer drove SQLite writes and root-key signatures by
    // connecting, which on a routable bind is anyone who can reach the port.
    maintenance(&db, state, &now).map_err(|error| refuse(500, error))?;
    let parsed_body: Option<Value> = if request.body.is_empty() {
        None
    } else {
        Some(
            crate::json::parse_strict_value(&request.body).map_err(|error| {
                refuse(
                    400,
                    ContractError::invariant(format!(
                        "body is not canonical strict JSON ({error})"
                    )),
                )
            })?,
        )
    };
    let trust_state = trust::load(&db, &state.root.public()).map_err(|error| refuse(500, error))?;
    match (request.method.as_str(), route.as_str()) {
        ("GET", "/status") => status(&db, state, &auth, &trust_state),
        ("GET", "/facts") => facts(&db, state, &auth, &trust_state, request, &now),
        ("POST", "/facts") => admit_fact(&db, state, &auth, &trust_state, parsed_body, &now),
        ("GET", "/snapshot") => snapshot(&db, state, &auth, &trust_state, request, &now),
        ("GET", "/events") => events(&db, state, &auth, &trust_state, request),
        ("POST", "/authority-registry") => {
            publish_registry(&db, &auth, &trust_state, parsed_body, &now)
        }
        ("GET", "/authority-registry") => authority_registry(&db, &auth),
        ("POST", "/directory") => {
            directory_write(&db, state, &auth, &trust_state, parsed_body, &now)
        }
        ("POST", "/questions") => post_question(&db, state, &auth, &trust_state, parsed_body, &now),
        ("GET", "/questions") => {
            require_scope(&auth, "facts:read")?;
            let questions = db
                .questions(request.query.get("authority_id").map(String::as_str))
                .map_err(|error| refuse(500, error))?;
            Ok((
                200,
                json!({"questions": questions, "count": questions.len()}),
            ))
        }
        ("POST", "/answers") => post_answer(&db, state, &auth, &trust_state, parsed_body, &now),
        ("GET", "/answers") => {
            require_scope(&auth, "facts:read")?;
            let question_id = request
                .query
                .get("question_id")
                .cloned()
                .unwrap_or_default();
            let answers = db
                .answers_for_question(&question_id)
                .map_err(|error| refuse(500, error))?;
            Ok((200, json!({"answers": answers})))
        }
        ("POST", "/unknowns") => post_unknown(&db, &auth, &trust_state, parsed_body, &now),
        ("GET", "/unknowns") => {
            require_scope(&auth, "facts:read")?;
            let unknowns = db
                .unknowns(request.query.get("status").map(String::as_str))
                .map_err(|error| refuse(500, error))?;
            Ok((200, json!({"unknowns": unknowns})))
        }
        ("POST", "/certificates") => {
            issue_certificate(&db, state, &auth, &trust_state, parsed_body, &now)
        }
        ("GET", "/certificates") => {
            require_scope(&auth, "facts:read")?;
            let hint = request.query.get("hint").cloned().unwrap_or_default();
            let certificates = if hint.is_empty() {
                db.all_certificates().map_err(|error| refuse(500, error))?
            } else {
                db.certificates_for_hint(&hint)
                    .map_err(|error| refuse(500, error))?
            };
            Ok((200, json!({"certificates": certificates})))
        }
        ("POST", "/manifests") => post_manifest(&db, &auth, &trust_state, parsed_body, &now),
        ("POST", "/revocations") => steward_event(
            &db,
            &auth,
            &trust_state,
            parsed_body,
            "revocation",
            "revocation",
            &now,
        ),
        ("GET", "/revocations") => revocations(&db, &auth),
        ("POST", "/rotations") => steward_event(
            &db,
            &auth,
            &trust_state,
            parsed_body,
            "rotation",
            "rotation",
            &now,
        ),
        ("POST", "/tokens") => issue_token(&db, &auth, parsed_body, &now),
        ("GET", "/steward-queue") => {
            require_scope(&auth, "admin:issue")?;
            Ok((
                200,
                json!({"queue": db.steward_queue().map_err(|error| refuse(500, error))?}),
            ))
        }
        ("GET", path) if path.starts_with("/questions/") => {
            require_scope(&auth, "facts:read")?;
            let id = path.trim_start_matches("/questions/");
            match db.question(id).map_err(|error| refuse(500, error))? {
                Some(mut question) => {
                    question["answers"] = Value::Array(
                        db.answers_for_question(id)
                            .map_err(|error| refuse(500, error))?,
                    );
                    Ok((200, question))
                }
                None => Err(refuse(404, ContractError::invariant("question not found"))),
            }
        }
        ("GET", path) if path.starts_with("/directory/") => {
            require_scope(&auth, "directory:read")?;
            let id = path.trim_start_matches("/directory/");
            match db.directory(id, &now).map_err(|error| refuse(500, error))? {
                Some(entry) => Ok((200, entry)),
                None => Err(refuse(
                    404,
                    ContractError::invariant("directory entry not found or past retention"),
                )),
            }
        }
        ("GET", path) if path.starts_with("/certificates/") => {
            require_scope(&auth, "facts:read")?;
            let id = path.trim_start_matches("/certificates/");
            match db.certificate(id).map_err(|error| refuse(500, error))? {
                // Hand back exactly what was signed; the read-time annotations
                // would otherwise land in the caller's verification preimage.
                Some(certificate) => Ok((200, super::db::signed_certificate(&certificate))),
                None => Err(refuse(
                    404,
                    ContractError::invariant("certificate not found"),
                )),
            }
        }
        ("GET", path) if path.starts_with("/manifests/") => {
            require_scope(&auth, "facts:read")?;
            let id = path.trim_start_matches("/manifests/");
            let branch = request
                .query
                .get("branch")
                .cloned()
                .unwrap_or_else(|| "main".to_owned());
            match db
                .latest_manifest_observation(id, &branch)
                .map_err(|error| refuse(500, error))?
            {
                Some(observation) => Ok((200, observation)),
                None => Err(refuse(
                    404,
                    ContractError::invariant(
                        "no manifest observation for that repository and branch",
                    ),
                )),
            }
        }
        ("GET", path) if path.starts_with("/facts/") => {
            fact_detail(&db, state, &auth, &trust_state, path, request, &now)
        }
        _ => Err(refuse(404, ContractError::invariant("no such endpoint"))),
    }
}

fn normalize_route(route: &str) -> String {
    let mut route = route.to_owned();
    if let Some(rest) = route.strip_prefix("/v1") {
        route = rest.to_owned();
    }
    if let Some(rest) = route.strip_prefix("/company") {
        route = rest.to_owned();
    }
    if route.is_empty() {
        route = "/".to_owned();
    }
    route.trim_end_matches('/').to_owned().replace("//", "/")
}

fn host_is_loopback(host: &str) -> bool {
    let host = host.trim();
    let name = host.rsplit_once(':').map(|(name, _)| name).unwrap_or(host);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    name == "localhost"
        || name
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

fn authenticate(
    db: &CompanyDb,
    state: &ServiceState,
    request: &Request,
    now: &str,
) -> Result<AuthContext, (u16, ContractError)> {
    let minute = now_minute();
    let bearer = request
        .header("authorization")
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|token| !token.is_empty());
    let token = match bearer {
        Some(bearer) => db.token(bearer).map_err(|error| refuse(500, error))?,
        None => None,
    };
    // Failures are counted per subject: the presented token, or one bucket
    // for requests presenting none the service holds. A single global
    // counter checked before credentials let any local process lock every
    // client out for the rest of the minute.
    let subject = token
        .as_ref()
        .map(|token| token.digest.clone())
        .unwrap_or_else(|| UNAUTHENTICATED_SUBJECT.to_owned());
    let failures = db
        .auth_failures(minute, &subject)
        .map_err(|error| refuse(500, error))?;
    if failures >= state.config.auth_failures_per_minute {
        return Err(refuse(
            429,
            ContractError::limit(
                "authentication failure ceiling reached for this minute",
                json!({"refused_count": 1, "omitted_count": 1, "ceiling": state.config.auth_failures_per_minute}),
            ),
        ));
    }
    let fail = |db: &CompanyDb| -> (u16, ContractError) {
        let _ = db.record_auth_failure(minute, &subject);
        auth_refusal()
    };
    let Some(token) = token else {
        return Err(fail(db));
    };
    let nonce = request
        .header("x-kinbase-nonce")
        .unwrap_or_default()
        .to_owned();
    let expires_at = request
        .header("x-kinbase-expires-at")
        .unwrap_or_default()
        .to_owned();
    let client_key = request
        .header("x-kinbase-client-key")
        .unwrap_or_default()
        .to_owned();
    let signature = request
        .header("x-kinbase-signature")
        .unwrap_or_default()
        .to_owned();
    if nonce.is_empty()
        || expires_at.is_empty()
        || client_key.is_empty()
        || signature.is_empty()
        || nonce.len() > 128
    {
        return Err(fail(db));
    }
    let Ok(expires) = crate::time::parse_rfc3339_millis(&expires_at) else {
        return Err(fail(db));
    };
    let now_dt = crate::time::parse_rfc3339_millis(now).unwrap_or_else(|_| crate::time::now_utc());
    // R-14: the request expiry is a receipt-time claim. More than the
    // configured skew bound ahead of or behind the proof clock is quarantined
    // as CLOCK_SKEW; an expiry within the bound but already past is an
    // ordinary expired request.
    let skew_seconds = expires.signed_duration_since(now_dt).num_seconds();
    let skew_bound = state.config.clock_skew_seconds.max(0);
    if skew_seconds.abs() > skew_bound {
        let _ = db.record_auth_failure(minute, &subject);
        let direction = if skew_seconds > 0 { "ahead" } else { "behind" };
        let _ = db.audit(
            "request-clock-skew",
            &json!({"client_key": client_key, "direction": direction, "skew_seconds": skew_seconds, "bound_seconds": skew_bound, "expires_at": expires_at, "proof_clock": now}),
        );
        return Err((
            401,
            ContractError::refused(
                "AUTHORITY_SCOPE_DENIED",
                format!(
                    "request expiry claim is {} seconds {direction} of the proof clock; quarantined as CLOCK_SKEW until the owner supplies a corrected receipt time",
                    skew_seconds.abs()
                ),
                "Correct the client clock or the request expiry; receipt-time claims must lie within the five-minute skew bound.",
            )
            .with_detail(json!({
                "disposition": "CLOCK_SKEW",
                "direction": direction,
                "skew_seconds": skew_seconds,
                "bound_seconds": skew_bound,
                "field": "expires_at"
            })),
        ));
    }
    if expires <= now_dt || skew_seconds > REQUEST_EXPIRY_MAX_SECONDS {
        return Err(fail(db));
    }
    let Ok(key) = PublicKey::from_hex(&client_key) else {
        return Err(fail(db));
    };
    let signed = json!({
        "method": request.method,
        "path": request.path,
        "body_sha256": crate::hash::sha256_bytes(&request.body),
        "nonce": nonce,
        "expires_at": expires_at
    });
    let bytes = crate::json::canonical_bytes(&signed);
    if !key.verify("receipt", &bytes, &signature) {
        return Err(fail(db));
    }
    let client_hex = key.to_hex();
    if !db
        .consume_request_nonce(&client_hex, &nonce, &expires_at, now)
        .map_err(|error| refuse(500, error))?
    {
        return Err(fail(db));
    }
    db.record_token_client_pair(&token.digest, &client_hex, now)
        .map_err(|error| refuse(500, error))?;
    let rate = db
        .bump_request_rate(&client_hex, minute)
        .map_err(|error| refuse(500, error))?;
    if rate > state.config.requests_per_minute {
        return Err(refuse(
            429,
            ContractError::limit(
                "request rate ceiling exceeded for this client key",
                json!({"refused_count": 1, "omitted_count": 1, "ceiling": state.config.requests_per_minute}),
            ),
        ));
    }
    Ok(AuthContext {
        principal_key: format!("{}:{}", token.principal_id, &client_hex[..16]),
        token,
        client_key: client_hex,
    })
}

fn require_scope(auth: &AuthContext, scope: &str) -> Result<(), (u16, ContractError)> {
    if auth.token.has_scope(scope) {
        Ok(())
    } else {
        Err(auth_refusal_403())
    }
}

fn auth_refusal_403() -> (u16, ContractError) {
    let (_, error) = auth_refusal();
    (403, error)
}

/// Exact authority-scope membership: configured list, else (C6) exactly the
/// scopes present in the admitted registry.
fn readable_scopes(auth: &AuthContext, trust_state: &TrustState) -> BTreeSet<String> {
    if !auth.token.authority_scopes.is_empty() {
        return auth.token.authority_scopes.iter().cloned().collect();
    }
    if auth.token.role == "facts" {
        return trust_state
            .registry
            .iter()
            .filter_map(|entry| crate::json::get_str(entry, "scope").map(str::to_owned))
            .collect();
    }
    BTreeSet::new()
}

/// Whether a reader may see a derived Unknown: every authority scope whose
/// evidence it came from is readable. Its `scope` is the evidence's subject
/// scope, which is not an authority scope whenever the two differ.
fn unknown_readable(unknown: &crate::reducer::DerivedUnknown, readable: &BTreeSet<String>) -> bool {
    if unknown.authority_scopes.is_empty() {
        return readable.contains(&unknown.scope);
    }
    unknown
        .authority_scopes
        .iter()
        .all(|scope| readable.contains(scope))
}

fn charge_read(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    count: usize,
    bytes: usize,
) -> Result<(), (u16, ContractError)> {
    let (total_count, total_bytes) = db
        .add_read_volume(&auth.principal_key, now_hour(), count as i64, bytes as i64)
        .map_err(|error| refuse(500, error))?;
    if total_count > state.config.read_volume_per_hour
        || total_bytes > state.config.read_bytes_per_hour
    {
        return Err(refuse(
            429,
            ContractError::limit(
                "per-principal hourly read volume ceiling exceeded",
                json!({"refused_count": count, "omitted_count": count, "count_ceiling": state.config.read_volume_per_hour, "bytes_ceiling": state.config.read_bytes_per_hour}),
            ),
        ));
    }
    Ok(())
}

/// Reduce the Company event log into the current view.
pub fn current_view(
    db: &CompanyDb,
    trust_state: &TrustState,
    as_of: &str,
) -> Result<crate::reducer::CurrentView, ContractError> {
    let mut admitted = Vec::new();
    let mut tombstones = Vec::new();
    for (cursor, payload, verification) in db.events_of_kind("fact-event")? {
        let Ok(event) = FactEvent::from_value(&payload) else {
            continue;
        };
        let verification = match verification.as_str() {
            "verified" => Verification::Verified,
            "wrong-scope" => Verification::WrongScope,
            "revoked" => Verification::Revoked,
            "signature-invalid" => Verification::SignatureInvalid,
            _ => Verification::Unverified,
        };
        if let Some(action) = crate::model::action_of(&event) {
            if matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
                let targets = lifecycle_targets(db, &event);
                let (authorized, _) = lifecycle_authorized(trust_state, &event, action, &targets);
                for target in event.parents.iter().chain(event.supersedes.iter()) {
                    tombstones.push(crate::reducer::Tombstone {
                        kind: action.to_owned(),
                        target_event_id: target.clone(),
                        signer_authorized: verification == Verification::Verified && authorized,
                        reason_code: event.statement.clone(),
                        tombstone_id: event.event_id.clone(),
                    });
                }
                continue;
            }
        }
        let signer = event.signer.clone();
        admitted.push(AdmittedEvent {
            event,
            verification,
            store_cursor: cursor.to_string(),
            origin_trust: None,
            reachable: None,
            source_identity: Some(signer),
            environment_registered: None,
        });
    }
    let mut unknowns = Vec::new();
    for (_, payload, _) in db.events_of_kind("unknown-event")? {
        if let Ok(unknown) = crate::model::UnknownEvent::from_value(&payload) {
            unknowns.push(unknown);
        }
    }
    let input = ReducerInput {
        store_kind: "company".to_owned(),
        events: admitted,
        unknowns,
        tombstones,
        revocations: trust_state.observed_revocations(),
        as_of: as_of.to_owned(),
        authority_cursor: trust_state.cursor.to_string(),
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid: true,
        authority_owner_by_scope: trust_state.authority_owner_by_scope(),
        steward_authority_id: trust_state.steward_authority_id(),
    };
    Ok(crate::reducer::reduce(&input))
}

/// Resolve the events a lifecycle action names (parents and supersedes) to
/// `(event_id, logical_key, authority_scope)` from the admitted log.
fn lifecycle_targets(db: &CompanyDb, event: &FactEvent) -> Vec<(String, String, String)> {
    let named: Vec<&String> = event
        .parents
        .iter()
        .chain(event.supersedes.iter())
        .collect();
    if named.is_empty() {
        return Vec::new();
    }
    let mut targets = Vec::new();
    for (_, payload, _) in db.events_of_kind("fact-event").unwrap_or_default() {
        let event_id = crate::json::get_str(&payload, "event_id").unwrap_or_default();
        let fact_id = crate::json::get_str(&payload, "fact_id").unwrap_or_default();
        if named
            .iter()
            .any(|id| id.as_str() == event_id || id.as_str() == fact_id)
        {
            targets.push((
                event_id.to_owned(),
                crate::json::get_str(&payload, "logical_key")
                    .unwrap_or_default()
                    .to_owned(),
                crate::json::get_str(&payload, "authority_scope")
                    .unwrap_or_default()
                    .to_owned(),
            ));
        }
    }
    targets
}

/// Whether the signer of a lifecycle action holds the authority the action
/// requires. `misextraction` is an approver-owned claim about bytes versus
/// evidence, so any verified signer may issue it; `never_true` and
/// `support_withdrawn` are semantic withdrawals reserved for the Company
/// steward or the registered owner of the withdrawn fact's exact scope.
fn lifecycle_authorized(
    trust_state: &TrustState,
    event: &FactEvent,
    action: &str,
    targets: &[(String, String, String)],
) -> (bool, Option<String>) {
    let target_scope = targets.first().map(|(_, _, scope)| scope.clone());
    if action == "misextraction" {
        return (true, target_scope);
    }
    if trust_state.is_steward(&event.signer) {
        return (true, target_scope);
    }
    let Some(scope) = target_scope.clone() else {
        return (false, None);
    };
    let owns_scope = trust_state
        .entries_for_key(&event.signer)
        .iter()
        .any(|entry| crate::json::get_str(entry, "scope") == Some(scope.as_str()));
    (owns_scope, target_scope)
}

/// Lifecycle admissions and refusals as the Company records them: admitted
/// withdrawal events (with the authority outcome the reducer applied) plus
/// audited refusals, so a client can report who was allowed to withdraw what.
fn lifecycle_admissions(
    db: &CompanyDb,
    trust_state: &TrustState,
    readable: &BTreeSet<String>,
) -> Vec<Value> {
    let mut rows = Vec::new();
    for (cursor, payload, verification) in db.events_of_kind("fact-event").unwrap_or_default() {
        let Ok(event) = FactEvent::from_value(&payload) else {
            continue;
        };
        let Some(action) = crate::model::action_of(&event) else {
            continue;
        };
        if !matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
            continue;
        }
        let targets = lifecycle_targets(db, &event);
        let (authorized, target_scope) =
            lifecycle_authorized(trust_state, &event, action, &targets);
        if !readable.contains(&event.authority_scope)
            && !target_scope
                .as_deref()
                .is_some_and(|scope| readable.contains(scope))
        {
            continue;
        }
        let accepted = verification == "verified" && authorized;
        rows.push(json!({
            "action": action,
            "event_id": event.event_id,
            "cursor": cursor.to_string(),
            "authority_id": event.authority_id,
            "authority_scope": event.authority_scope,
            "logical_key": targets.first().map(|(_, key, _)| key.clone()).unwrap_or_else(|| event.logical_key.clone()),
            "target_event_ids": targets.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(),
            "target_scope": target_scope,
            "accepted": accepted,
            "refusal_code": if accepted { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) },
            "asserted_at": event.asserted_at,
            "reason_code": event.statement
        }));
    }
    for record in db.audit_records("lifecycle-refusal").unwrap_or_default() {
        let visible = ["authority_scope", "target_scope"].iter().any(|key| {
            crate::json::get_str(&record, key).is_some_and(|scope| readable.contains(scope))
        });
        if !visible {
            continue;
        }
        let mut row = record.clone();
        row["accepted"] = Value::Bool(false);
        if row.get("refusal_code").is_none() {
            row["refusal_code"] = Value::String("AUTHORITY_WRONG_SCOPE".to_owned());
        }
        rows.push(row);
    }
    rows
}

/// Parent bindings of every current fact, resolved to the parent's logical
/// key, so a client holding other stores can reopen dependent decisions when
/// a parent fact loses its last support anywhere.
fn fact_parents(
    db: &CompanyDb,
    view: &crate::reducer::CurrentView,
    sent_ids: &BTreeSet<String>,
) -> Value {
    let mut by_event: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for (_, payload, _) in db.events_of_kind("fact-event").unwrap_or_default() {
        let event_id = crate::json::get_str(&payload, "event_id").unwrap_or_default();
        let logical_key = crate::json::get_str(&payload, "logical_key").unwrap_or_default();
        let parents = crate::json::get_array(&payload, "parents")
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        by_event.insert(event_id.to_owned(), (logical_key.to_owned(), parents));
    }
    let mut map = serde_json::Map::new();
    for fact in view
        .facts
        .iter()
        .filter(|fact| sent_ids.contains(&fact.fact_id))
    {
        let Some((_, parents)) = by_event.get(&fact.event_id) else {
            continue;
        };
        if parents.is_empty() {
            continue;
        }
        let resolved: Vec<Value> = parents
            .iter()
            .map(|parent| {
                json!({
                    "event_id": parent,
                    "logical_key": by_event.get(parent).map(|(key, _)| key.clone()).unwrap_or_default()
                })
            })
            .collect();
        map.insert(fact.fact_id.clone(), Value::Array(resolved));
    }
    Value::Object(map)
}

fn status(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
) -> Handled {
    require_scope(auth, "facts:read")?;
    let cursor = db.cursor().map_err(|error| refuse(500, error))?;
    // Company's own lifecycle events (observation expiry, orphan abandonment,
    // ...): the events it emits on its own clock, without client activity.
    let lifecycle_events: Vec<Value> = db
        .events_of_kind("fact-event")
        .map_err(|error| refuse(500, error))?
        .into_iter()
        .filter(|(_, document, _)| {
            crate::json::get_str(document, "disposition")
                .is_some_and(|disposition| crate::model::ACTION_DISPOSITIONS.contains(&disposition))
        })
        .map(|(cursor, document, _)| {
            json!({
                "cursor": cursor.to_string(),
                "event_id": crate::json::get_str(&document, "event_id"),
                "atom_kind": crate::json::get_str(&document, "atom_kind"),
                "disposition": crate::json::get_str(&document, "disposition"),
                "logical_key": crate::json::get_str(&document, "logical_key"),
                "statement": crate::json::get_str(&document, "statement"),
                "asserted_at": crate::json::get_str(&document, "asserted_at"),
                "observation_status": crate::json::get_str(&document, "observation_status")
            })
        })
        .collect();
    let open_unknowns = db
        .unknowns(Some("open"))
        .map_err(|error| refuse(500, error))?;
    Ok((
        200,
        json!({
            "status": "ok",
            "events": lifecycle_events,
            "unknowns": open_unknowns,
            "company_id": state.config.company_id,
            "bind": state.config.bind.to_string(),
            "cursor": cursor.to_string(),
            "authority_cursor": trust_state.authority_cursor.clone(),
            "service_cursor": cursor.to_string(),
            "revocation_cursor": db.revocation_cursor().map_err(|error| refuse(500, error))?,
            "token_role": auth.token.role,
            "token_scopes": auth.token.scopes,
            "authority_scopes": readable_scopes(auth, trust_state).into_iter().collect::<Vec<_>>(),
            "client_key_bound": false,
            "client_keys_seen": db.token_client_key_count(&auth.token.digest).map_err(|error| refuse(500, error))?,
            "registry_entries": trust_state.registry.len(),
            "started_at": state.started_at,
            "metrics": db.metrics().map_err(|error| refuse(500, error))?
        }),
    ))
}

fn facts(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    request: &Request,
    now: &str,
) -> Handled {
    require_scope(auth, "facts:read")?;
    let scope = request.query.get("scope").cloned().unwrap_or_default();
    let readable = readable_scopes(auth, trust_state);
    let as_of = request
        .query
        .get("as_of")
        .cloned()
        .unwrap_or_else(|| now.to_owned());
    let view = current_view(db, trust_state, &as_of).map_err(|error| refuse(500, error))?;
    let selected: Vec<Value> = view
        .facts
        .iter()
        .filter(|fact| {
            if scope.is_empty() {
                readable.contains(&fact.authority_scope)
            } else {
                fact.authority_scope == scope
            }
        })
        .map(|fact| {
            let mut value = crate::model::value_of(fact);
            value["semantic_digest"] =
                Value::String(crate::model::semantic_digest(&fact.statement));
            value["digest_alg_version"] =
                Value::String(crate::model::DIGEST_ALG_VERSION.to_owned());
            value
        })
        .collect();
    if !scope.is_empty() && !readable.contains(&scope) {
        return Err(refuse(
            403,
            ContractError::refused(
                "AUTHORITY_SCOPE_DENIED",
                "token lacks the exact canonical authority scope",
                "Issue a least-privilege exact-scope token; empty and wildcard-like sets grant nothing.",
            ),
        ));
    }
    let denied_count = view
        .facts
        .iter()
        .filter(|fact| !readable.contains(&fact.authority_scope))
        .count();
    // Every admitted event carries the Company's evaluation at this cursor,
    // not only the keys that reduce to a current fact: a superseded, retracted,
    // expired, conflicting or lower-authority head is published with that
    // status, so a reader sees why a key has no current statement and every
    // admission visibly changes the published view (Helland: the transaction
    // record is immutable; the evaluation is recomputed, never rewritten).
    let mut selected = selected;
    let current_event_ids: BTreeSet<String> = view
        .facts
        .iter()
        .map(|fact| fact.event_id.clone())
        .collect();
    let mut payloads: BTreeMap<String, Value> = BTreeMap::new();
    for (_, payload, _) in db.events_of_kind("fact-event").unwrap_or_default() {
        if let Some(event_id) = crate::json::get_str(&payload, "event_id") {
            payloads.insert(event_id.to_owned(), payload);
        }
    }
    for trace in &view.traces {
        let mut evaluated: Vec<(String, &str, String)> = Vec::new();
        for event_id in &trace.admitted_event_ids {
            if current_event_ids.contains(event_id) {
                continue;
            }
            let disposition = payloads
                .get(event_id)
                .and_then(|payload| crate::json::get_str(payload, "disposition"))
                .unwrap_or_default();
            let status = if trace.conflict_event_ids.contains(event_id) {
                "conflict"
            } else if trace.expired_event_ids.contains(event_id) {
                "expired"
            } else if trace.negative_evidence_event_ids.contains(event_id) {
                "negative"
            } else if matches!(disposition, "retracted" | "withdrawn") {
                "retracted"
            } else if trace
                .steps
                .iter()
                .any(|step| step.step == 2 && step.event_ids.contains(event_id))
            {
                "superseded"
            } else {
                "withheld"
            };
            evaluated.push((event_id.clone(), status, String::new()));
        }
        for rejected in &trace.rejected {
            if let Some(event_id) = crate::json::get_str(rejected, "event_id") {
                let reason = crate::json::get_str(rejected, "reason")
                    .unwrap_or_default()
                    .to_owned();
                evaluated.push((event_id.to_owned(), "rejected", reason));
            }
        }
        for (event_id, status, reason) in evaluated {
            let Some(payload) = payloads.get(&event_id) else {
                continue;
            };
            let authority_scope =
                crate::json::get_str(payload, "authority_scope").unwrap_or_default();
            if scope.is_empty() {
                if !readable.contains(authority_scope) {
                    continue;
                }
            } else if authority_scope != scope {
                continue;
            }
            let statement = crate::json::get_str(payload, "statement").unwrap_or_default();
            selected.push(json!({
                "fact_id": payload.get("fact_id").cloned().unwrap_or(Value::Null),
                "event_id": event_id,
                "logical_key": trace.logical_key,
                "statement": statement,
                "status": status,
                "state": trace.state,
                "disposition": payload.get("disposition").cloned().unwrap_or(Value::Null),
                "atom_kind": payload.get("atom_kind").cloned().unwrap_or(Value::Null),
                "authority_id": payload.get("authority_id").cloned().unwrap_or(Value::Null),
                "authority_scope": authority_scope,
                "store_kind": "company",
                "asserted_at": payload.get("asserted_at").cloned().unwrap_or(Value::Null),
                "effective_until": payload.get("effective_until").cloned().unwrap_or(Value::Null),
                "semantic_digest": crate::model::semantic_digest(statement),
                "digest_alg_version": crate::model::DIGEST_ALG_VERSION,
                "unknown_id": trace.unknown_id,
                "reason": reason,
                "trust": "withheld"
            }));
        }
    }
    // Paged, because a reader that cannot enumerate the whole set cannot tell a
    // fact that does not exist from one it was not shown. Without `after` the
    // response silently stopped at 500 and a client correcting its own
    // publication superseded nothing beyond that point -- the failure is
    // invisible from the caller's side, which is what makes it dangerous.
    // `after` is the `logical_key` of the last fact already read; ordering is
    // by logical_key so the page boundary is stable across calls.
    selected.sort_by(|left, right| {
        crate::json::get_str(left, "logical_key")
            .unwrap_or_default()
            .cmp(crate::json::get_str(right, "logical_key").unwrap_or_default())
    });
    let after = request.query.get("after").cloned().unwrap_or_default();
    if !after.is_empty() {
        let start = selected
            .iter()
            .position(|fact| {
                crate::json::get_str(fact, "logical_key").unwrap_or_default() > after.as_str()
            })
            .unwrap_or(selected.len());
        selected.drain(..start);
    }
    let truncated = selected.len() > MAX_READ_ITEMS;
    let remaining = selected.len().saturating_sub(MAX_READ_ITEMS);
    let facts: Vec<Value> = selected.into_iter().take(MAX_READ_ITEMS).collect();
    // Charge the page served, as /events does. Charging the whole selection on
    // every page made one full read of the 10k-fact corpus cost ~20x its size
    // and exhaust the hourly budget mid-read.
    let bytes: usize = facts
        .iter()
        .map(|fact| crate::json::canonical_bytes(fact).len())
        .sum();
    charge_read(db, state, auth, facts.len().max(1), bytes)?;
    let next_after = if truncated {
        facts
            .last()
            .and_then(|fact| crate::json::get_str(fact, "logical_key"))
            .unwrap_or_default()
            .to_owned()
    } else {
        String::new()
    };
    Ok((
        200,
        json!({
            "facts": facts,
            "denied_count": denied_count,
            "omitted_count": remaining,
            // Present and non-empty exactly when more pages remain; pass it back
            // as `?after=` to continue.
            "next_after": next_after,
            "as_of": as_of,
            "authority_cursor": trust_state.cursor.to_string(),
            "unknowns": view.unknowns.iter().filter(|u| unknown_readable(u, &readable) && (scope.is_empty() || u.scope == scope || u.authority_scopes.contains(&scope))).map(crate::model::value_of).collect::<Vec<_>>()
        }),
    ))
}

fn fact_detail(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    path: &str,
    request: &Request,
    now: &str,
) -> Handled {
    require_scope(auth, "facts:read")?;
    let rest = path.trim_start_matches("/facts/");
    let (fact_id, sub) = rest.split_once('/').unwrap_or((rest, ""));
    let readable = readable_scopes(auth, trust_state);
    if sub == "digest" || sub == "versions" {
        // P-8 historical digest lookup: version-bound digest plus current head.
        let alg = request
            .query
            .get("alg")
            .cloned()
            .unwrap_or_else(|| crate::model::DIGEST_ALG_VERSION.to_owned());
        if alg != crate::model::DIGEST_ALG_VERSION {
            return Err(refuse(
                400,
                ContractError::degraded(
                    "DIGEST_ALGORITHM_UNSUPPORTED",
                    format!("digest algorithm {alg} is not published by this Company"),
                    "Upgrade the adapter; do not recompute with a guessed algorithm.",
                ),
            ));
        }
        let versions = db
            .fact_versions(fact_id)
            .map_err(|error| refuse(500, error))?;
        let requested = request.query.get("version").cloned();
        let historical = requested.as_ref().and_then(|version| {
            versions
                .iter()
                .find(|item| crate::json::get_str(item, "version") == Some(version.as_str()))
                .cloned()
        });
        let head = versions.last().cloned();
        charge_read(db, state, auth, 1, 256)?;
        return Ok((
            200,
            json!({
                "fact_id": fact_id,
                "requested_version": requested,
                "historical": historical.clone(),
                "retained": historical.as_ref().is_some_and(|item| item.get("retained") == Some(&Value::Bool(true))),
                "current_head": head,
                "version_count": versions.len(),
                "digest_alg_version": crate::model::DIGEST_ALG_VERSION
            }),
        ));
    }
    let view = current_view(db, trust_state, now).map_err(|error| refuse(500, error))?;
    let Some(fact) = view.facts.iter().find(|fact| fact.fact_id == fact_id) else {
        return Err(refuse(
            404,
            ContractError::invariant("fact not found in the current view"),
        ));
    };
    if !readable.contains(&fact.authority_scope) {
        return Err(refuse(
            403,
            ContractError::refused(
                "AUTHORITY_SCOPE_DENIED",
                "token lacks the exact canonical authority scope",
                "Issue a least-privilege exact-scope token; empty and wildcard-like sets grant nothing.",
            ),
        ));
    }
    let mut value = crate::model::value_of(fact);
    value["semantic_digest"] = Value::String(crate::model::semantic_digest(&fact.statement));
    value["digest_alg_version"] = Value::String(crate::model::DIGEST_ALG_VERSION.to_owned());
    charge_read(
        db,
        state,
        auth,
        1,
        crate::json::canonical_bytes(&value).len(),
    )?;
    Ok((
        200,
        json!({"fact": value, "versions": db.fact_versions(fact_id).map_err(|error| refuse(500, error))?}),
    ))
}

/// Admit a fact event (architecture §2 admission order): parse once; verify
/// canonical bytes, domain, signature, scope, and revocation cursor; then
/// the idempotent destination transaction keyed by content digest.
fn admit_fact(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    let body = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a fact-event body is required"),
        )
    })?;
    let (document, approval) = if body.get("schema").is_some() {
        // A fact-event names itself. An empty event_id was admitted once and
        // then blocked every later empty-id post as a digest mismatch.
        if crate::json::get_str(&body, "event_id").unwrap_or_default().trim().is_empty() {
            return Err(refuse(
                400,
                ContractError::invariant(
                    "a fact-event must carry a non-empty event_id derived from its own bytes",
                ),
            ));
        }
        (body.clone(), None)
    } else if let Some(event) = body.get("event") {
        (event.clone(), body.get("approval_token").cloned())
    } else if body.get("company_id").is_some() && body.get("statement").is_some() {
        (
            company_fact_document_to_event(&body, state, now)
                .map_err(|error| refuse(400, error))?,
            None,
        )
    } else {
        return Err(refuse(
            400,
            ContractError::invariant(
                "body is neither a kinbase-event/1 document nor a Company fact document",
            ),
        ));
    };
    let bytes = crate::json::canonical_bytes(&document);
    if bytes.len() > crate::model::MAX_EVENT_BYTES {
        return Err(refuse(
            413,
            ContractError::limit(
                "shared event exceeds the 64 KiB ceiling",
                json!({"refused_count": 1, "omitted_count": 1, "bytes": bytes.len()}),
            ),
        ));
    }
    let event = FactEvent::parse(&bytes).map_err(|error| {
        refuse(
            400,
            ContractError::integrity(
                "DIGEST_MISMATCH",
                format!("event does not parse as a canonical kinbase-event/1 document ({error})"),
                "Send the exact canonical signed event bytes.",
            ),
        )
    })?;
    if event.store_kind != "company" {
        return Err(refuse(
            400,
            ContractError::refused(
                "FOREIGN_REPO_EVENTS",
                "only company store events are admitted by the Company service",
                "Send codebase events to the repository store.",
            ),
        ));
    }
    let digest = crate::hash::sha256_bytes(&bytes);
    // Path-exists fast path (architecture §3, V-4 replay): bytes Company
    // already admitted are answered with the historical receipt, and only to
    // the client that admitted them. Nothing is re-admitted or projected,
    // and a revocation observed since is reported on the receipt rather than
    // refusing history that was valid when it was made. A new event under a
    // revoked key still refuses below.
    if let Some(existing_cursor) = db
        .event_cursor(&event.event_id)
        .map_err(|error| refuse(500, error))?
    {
        let existing = db
            .all_events(existing_cursor - 1, 1)
            .map_err(|error| refuse(500, error))?;
        let existing_digest = existing
            .first()
            .and_then(|record| record.get("payload"))
            .map(|payload| crate::json::digest(payload))
            .unwrap_or_default();
        if existing_digest == digest {
            let record = db
                .nonce_record("company", &digest)
                .map_err(|error| refuse(500, error))?;
            let same_client = record
                .as_ref()
                .and_then(|record| crate::json::get_str(record, "client_key"))
                == Some(auth.client_key.as_str());
            if !same_client {
                return Err(refuse(
                    409,
                    ContractError::refused(
                        "APPROVAL_REPLAY",
                        "a historical receipt is returned only to the original scoped client",
                        "Use the original client's receipt; replayed bytes are never re-admitted.",
                    ),
                ));
            }
            db.bump("retry_receipt_returned")
                .map_err(|error| refuse(500, error))?;
            let (revocation_observed, support_withdrawn) =
                replay_projection(db, trust_state, &event);
            let mut receipt =
                receipt_for(&event, &digest, existing_cursor, "committed", "duplicate");
            receipt["retry"] = Value::Bool(true);
            receipt["historical_receipt"] = Value::Bool(true);
            receipt["readmitted"] = Value::Bool(false);
            receipt["projected"] = Value::Bool(false);
            receipt["receipt_scope_restricted"] = Value::Bool(true);
            receipt["revocation_observed"] = Value::Bool(revocation_observed);
            receipt["support_withdrawn"] = Value::Bool(support_withdrawn);
            receipt["projection_state"] = Value::String(if support_withdrawn {
                "support_withdrawn".to_owned()
            } else {
                "historical".to_owned()
            });
            receipt["state_changed"] = Value::Bool(false);
            receipt["ambient_clock_read"] = Value::Bool(false);
            return Ok((200, receipt));
        }
    }
    let verification = trust_state.verify_fact_signer(&event);
    // Lifecycle withdrawals (architecture "SessionCandidate ... misextraction"):
    // an approver may only assert the evidence/byte mismatch; the semantic
    // `never_true` withdrawal is admissible only from the subject-matter
    // authority of the withdrawn fact. The refusal is a recorded admission
    // outcome, never a silent drop.
    if verification == Verification::Verified {
        if let Some(action) = crate::model::action_of(&event) {
            let targets = lifecycle_targets(db, &event);
            let (authorized, target_scope) =
                lifecycle_authorized(trust_state, &event, action, &targets);
            if !authorized {
                let refusal = ContractError::refused(
                    "AUTHORITY_WRONG_SCOPE",
                    format!(
                        "a {action} withdrawal must be signed by the subject-matter authority of the withdrawn fact ({}); {} owns only {}",
                        target_scope.as_deref().unwrap_or("unresolved scope"),
                        event.authority_id,
                        event.authority_scope
                    ),
                    "Ask the registered authority for the fact's exact scope (or the Company steward) to sign the withdrawal; an approver may only issue a misextraction notice.",
                );
                let _ = db.audit(
                    "lifecycle-refusal",
                    &json!({
                        "action": action,
                        "event_id": event.event_id,
                        "authority_id": event.authority_id,
                        "authority_scope": event.authority_scope,
                        "logical_key": targets.first().map(|(_, key, _)| key.clone()).unwrap_or_else(|| event.logical_key.clone()),
                        "target_event_ids": targets.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(),
                        "target_scope": target_scope,
                        "refusal_code": "AUTHORITY_WRONG_SCOPE",
                        "asserted_at": event.asserted_at,
                        "recorded_at": now
                    }),
                );
                return Err(refuse(403, refusal));
            }
        }
    }
    // A repository maintainer may request an exception, but only a Company
    // steward may relax Company-owned architecture. Signature failures retain
    // their integrity attribution.
    if crate::model::action_of(&event) == Some("relaxation")
        && verification == Verification::Verified
        && !trust_state.is_steward(&event.signer)
    {
        return Err(refuse(
            403,
            ContractError::refused(
                "AUTHORITY_WRONG_SCOPE",
                "a relaxation is Company-owned; a repository maintainer may submit an exception_request but cannot mint it",
                "Ask the Company steward to admit a relaxation scoped to this repository.",
            ),
        ));
    }
    let (status_code, admission_status, verification_text) = match verification {
        Verification::Verified => (201, "committed", "verified"),
        Verification::SignatureInvalid => {
            return Err(refuse(
                400,
                ContractError::integrity(
                    "SIGNATURE_INVALID",
                    "fact-event signature failed",
                    "Quarantine the bytes and contact the named owner; never resign locally.",
                ),
            ));
        }
        Verification::Revoked => {
            // Architecture §2: a pre-revocation committed retry may return
            // its historical receipt to its original scoped client, but is
            // never re-admitted and its projection is recalculated under the
            // current revocation state.
            if let Some(existing_cursor) = db
                .event_cursor(&event.event_id)
                .map_err(|error| refuse(500, error))?
            {
                let existing_digest = db
                    .all_events(existing_cursor - 1, 1)
                    .map_err(|error| refuse(500, error))?
                    .first()
                    .and_then(|record| record.get("payload"))
                    .map(|payload| crate::json::digest(payload))
                    .unwrap_or_default();
                let same_client = db
                    .nonce_record("company", &digest)
                    .map_err(|error| refuse(500, error))?
                    .as_ref()
                    .and_then(|record| crate::json::get_str(record, "client_key"))
                    == Some(auth.client_key.as_str());
                if existing_digest == digest && same_client {
                    let mut receipt =
                        receipt_for(&event, &digest, existing_cursor, "committed", "historical");
                    let (revocation_observed, support_withdrawn) =
                        replay_projection(db, trust_state, &event);
                    receipt["historical_receipt"] = Value::Bool(true);
                    receipt["readmitted"] = Value::Bool(false);
                    receipt["revocation_observed"] = Value::Bool(revocation_observed);
                    receipt["support_withdrawn"] = Value::Bool(support_withdrawn);
                    receipt["receipt_scope_restricted"] = Value::Bool(true);
                    receipt["projection_state"] = Value::String(if support_withdrawn {
                        "support_withdrawn".to_owned()
                    } else {
                        "current".to_owned()
                    });
                    let _ = db.audit(
                        "historical-receipt",
                        &json!({"event_id": event.event_id, "digest": digest, "revoked_key": event.signer}),
                    );
                    return Ok((200, receipt));
                }
            }
            return Err(refuse(
                403,
                ContractError::refused(
                    "AUTHORITY_WRONG_SCOPE",
                    "signer key is revoked at the current authority cursor",
                    "Rotate to an authorized key; post-revocation events refuse.",
                ),
            ));
        }
        Verification::WrongScope | Verification::Unverified | Verification::Foreign => {
            // Approved contribution from a non-steward: steward review queue.
            if approval.is_some() && auth.token.has_scope("questions:write") {
                (202, "pending-steward-review", "pending")
            } else {
                return Err(refuse(
                    403,
                    ContractError::refused(
                        "AUTHORITY_WRONG_SCOPE",
                        "signer does not own the exact authority scope of this fact",
                        "Resolve the registered authority for the scope; role prestige cannot widen scope.",
                    ),
                ));
            }
        }
    };
    // Destination admission is one idempotent SQLite transaction. The nonce is
    // reserved first; event append, version/relaxation writes, receipt, audit,
    // and metrics either all commit or all roll back.
    let nonce = approval
        .as_ref()
        .and_then(|token| crate::json::get_str(token, "nonce").map(str::to_owned))
        .unwrap_or_else(|| digest.clone());
    let expires_at = crate::time::plus_seconds(now, state.config.nonce_retention_seconds)
        .unwrap_or_else(|_| now.to_owned());
    let reserved_receipt = json!({"schema": crate::model::RECEIPT_SCHEMA, "destination": "company", "status": "reserved"});
    let transaction: Result<(u16, Value), (u16, ContractError)> = (|| {
        db.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| {
                refuse(
                    500,
                    ContractError::internal(format!("begin fact admission: {error}")),
                )
            })?;
        let inserted_nonce = db
            .connection
            .execute(
                "INSERT OR IGNORE INTO nonces(destination, nonce, payload_digest, client_key, authority_scope, receipt, consumed_at, expires_at) VALUES ('company', ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![nonce, digest, auth.client_key, event.authority_scope, crate::json::canonical_text(&reserved_receipt), now, expires_at],
            )
            .map_err(|error| refuse(500, ContractError::internal(format!("reserve fact nonce: {error}"))))?;
        if inserted_nonce == 0 {
            let record = db
                .nonce_record("company", &nonce)
                .map_err(|error| refuse(500, error))?;
            let same_bytes = record
                .as_ref()
                .and_then(|record| crate::json::get_str(record, "payload_digest"))
                == Some(digest.as_str());
            let same_client = record
                .as_ref()
                .and_then(|record| crate::json::get_str(record, "client_key"))
                == Some(auth.client_key.as_str());
            if same_bytes && same_client {
                let mut receipt = record
                    .and_then(|record| record.get("receipt").cloned())
                    .unwrap_or(Value::Null);
                if !receipt.is_object() {
                    receipt = json!({"schema": crate::model::RECEIPT_SCHEMA, "destination": "company", "status": "committed"});
                }
                // A submission that waited for a steward: committed once the
                // event is in the log; admitted now (below) when its signer
                // has since become an authority for the scope; otherwise
                // still waiting, as the stored receipt says.
                let awaiting_steward =
                    crate::json::get_str(&receipt, "status") == Some("pending-steward-review");
                let admitted_since = awaiting_steward
                    && db
                        .event_cursor(&event.event_id)
                        .map_err(|error| refuse(500, error))?
                        .is_some();
                let admit_now =
                    awaiting_steward && !admitted_since && admission_status == "committed";
                if !admit_now {
                    // Path-exists fast path: the original scoped client
                    // replays bytes Company already admitted. It receives the
                    // historical receipt for that admission and nothing is
                    // re-admitted or projected; a revocation observed since is
                    // reported on it.
                    db.bump("retry_receipt_returned")
                        .map_err(|error| refuse(500, error))?;
                    if admitted_since {
                        receipt["status"] = Value::String("committed".to_owned());
                        receipt["steward_admitted"] = Value::Bool(true);
                    }
                    let (revocation_observed, support_withdrawn) =
                        replay_projection(db, trust_state, &event);
                    receipt["retry"] = Value::Bool(true);
                    receipt["historical_receipt"] = Value::Bool(true);
                    receipt["readmitted"] = Value::Bool(false);
                    receipt["projected"] = Value::Bool(false);
                    receipt["receipt_scope_restricted"] = Value::Bool(true);
                    receipt["revocation_observed"] = Value::Bool(revocation_observed);
                    receipt["support_withdrawn"] = Value::Bool(support_withdrawn);
                    receipt["projection_state"] = Value::String(if support_withdrawn {
                        "support_withdrawn".to_owned()
                    } else {
                        "historical".to_owned()
                    });
                    return Ok((200, receipt));
                }
            } else {
                return Err(refuse(
                    409,
                    ContractError::refused(
                        "APPROVAL_REPLAY",
                        "consumed nonce reused with nonmatching bytes, destination, or client",
                        "Use the original receipt or create and review a new candidate.",
                    ),
                ));
            }
        }

        if let Some(existing_cursor) = db
            .event_cursor(&event.event_id)
            .map_err(|error| refuse(500, error))?
        {
            let existing = db
                .all_events(existing_cursor - 1, 1)
                .map_err(|error| refuse(500, error))?;
            let existing_digest = existing
                .first()
                .and_then(|record| record.get("payload"))
                .map(|payload| crate::json::digest(payload))
                .unwrap_or_default();
            if existing_digest != digest {
                return Err(refuse(
                    409,
                    ContractError::integrity(
                        "DIGEST_MISMATCH",
                        "event_id already admitted with different canonical bytes",
                        "Use a fresh event_id derived from the content digest.",
                    ),
                ));
            }
            let mut receipt =
                receipt_for(&event, &digest, existing_cursor, "committed", "duplicate");
            let (revocation_observed, support_withdrawn) =
                replay_projection(db, trust_state, &event);
            receipt["historical_receipt"] = Value::Bool(true);
            receipt["readmitted"] = Value::Bool(false);
            receipt["revocation_observed"] = Value::Bool(revocation_observed);
            receipt["support_withdrawn"] = Value::Bool(support_withdrawn);
            receipt["projection_state"] = Value::String(if support_withdrawn {
                "support_withdrawn".to_owned()
            } else {
                "current".to_owned()
            });
            db.connection
                .execute(
                    "UPDATE nonces SET receipt=?2 WHERE destination='company' AND nonce=?1",
                    rusqlite::params![nonce, crate::json::canonical_text(&receipt)],
                )
                .map_err(|error| {
                    refuse(
                        500,
                        ContractError::internal(format!("store historical receipt: {error}")),
                    )
                })?;
            return Ok((200, receipt));
        }

        let cursor = if admission_status == "committed" {
            let transaction_cursor = db
                .append_event(
                    &event.event_id,
                    "fact-event",
                    "fact-event",
                    &document,
                    &event.signer,
                    verification_text,
                    Some(&auth.client_key),
                )
                .map_err(|error| refuse(500, error))?;
            match transaction_cursor {
                Some(cursor) => {
                    db.record_fact_version(
                        &event.fact_id,
                        &event.semantic_digest(),
                        &event.event_id,
                        cursor,
                    )
                    .map_err(|error| refuse(500, error))?;
                    if crate::model::action_of(&event) == Some("relaxation") {
                        db.insert_relaxation(&document, cursor)
                            .map_err(|error| refuse(500, error))?;
                    }
                    cursor
                }
                None => db
                    .event_cursor(&event.event_id)
                    .map_err(|error| refuse(500, error))?
                    .unwrap_or(0),
            }
        } else {
            db.queue_for_steward(
                &event.event_id,
                &document,
                approval.as_ref().unwrap_or(&Value::Null),
                &auth.client_key,
            )
            .map_err(|error| refuse(500, error))?;
            0
        };
        if admission_status == "committed" {
            db.resolve_steward_queue(&event.event_id)
                .map_err(|error| refuse(500, error))?;
        }
        let mut receipt = receipt_for(&event, &digest, cursor, admission_status, "new");
        receipt["state_changed"] = Value::Bool(admission_status == "committed");
        receipt["ambient_clock_read"] = Value::Bool(false);
        db.connection
            .execute(
                "UPDATE nonces SET receipt=?2 WHERE destination='company' AND nonce=?1",
                rusqlite::params![nonce, crate::json::canonical_text(&receipt)],
            )
            .map_err(|error| {
                refuse(
                    500,
                    ContractError::internal(format!("store fact receipt: {error}")),
                )
            })?;
        db.audit("fact-admission", &json!({"event_id": event.event_id, "digest": digest, "status": admission_status, "scope": event.authority_scope}))
            .map_err(|error| refuse(500, error))?;
        db.bump(if admission_status == "committed" {
            "facts_admitted"
        } else {
            "facts_queued"
        })
        .map_err(|error| refuse(500, error))?;
        Ok((status_code, receipt))
    })();
    let result = match transaction {
        Ok(result) => match db.connection.execute_batch("COMMIT") {
            Ok(()) => Ok(result),
            Err(error) => {
                let _ = db.connection.execute_batch("ROLLBACK");
                Err(refuse(
                    500,
                    ContractError::internal(format!("commit fact admission: {error}")),
                ))
            }
        },
        Err(error) => {
            let _ = db.connection.execute_batch("ROLLBACK");
            Err(error)
        }
    };
    result
}
fn replay_projection(db: &CompanyDb, trust_state: &TrustState, event: &FactEvent) -> (bool, bool) {
    let revocation_observed = trust_state.is_revoked_in(&event.signer, &event.authority_scope);
    if !revocation_observed {
        return (false, false);
    }
    let independent_support = db
        .events_of_kind("fact-event")
        .ok()
        .into_iter()
        .flatten()
        .filter(|(_, payload, _)| {
            payload.get("event_id").and_then(Value::as_str) != Some(event.event_id.as_str())
                && payload.get("logical_key").and_then(Value::as_str)
                    == Some(event.logical_key.as_str())
                && payload
                    .get("signer")
                    .and_then(Value::as_str)
                    .is_some_and(|signer| {
                        !trust_state.is_revoked_in(
                            signer,
                            payload
                                .get("authority_scope")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        )
                    })
        })
        .count();
    (true, independent_support == 0)
}

fn receipt_for(
    event: &FactEvent,
    digest: &str,
    cursor: i64,
    status: &str,
    admission: &str,
) -> Value {
    json!({
        "schema": crate::model::RECEIPT_SCHEMA,
        "destination": "company",
        "status": status,
        "admission": admission,
        "event_id": event.event_id,
        "fact_id": event.fact_id,
        "event_digest": digest,
        "authority_scope": event.authority_scope,
        "semantic_digest": event.semantic_digest(),
        "digest_alg_version": crate::model::DIGEST_ALG_VERSION,
        "cursor": cursor.to_string(),
        "committed_at": crate::time::now_rfc3339_millis()
    })
}

/// Convert the interface-contract §3.5 Company fact document into a
/// FactEvent with the ratified field set (signature carried through: the
/// document's own signature is verified as the fact-event message type).
fn company_fact_document_to_event(
    document: &Value,
    state: &ServiceState,
    now: &str,
) -> Result<Value, ContractError> {
    let signer = crate::json::get_str(document, "signer").unwrap_or_default();
    let statement = crate::json::get_str(document, "statement").unwrap_or_default();
    let fact_id = crate::json::get_str(document, "fact_id").unwrap_or_default();
    let version = document.get("version").and_then(Value::as_i64).unwrap_or(1);
    let expected_digest = crate::model::semantic_digest(statement);
    let supplied_digest = crate::json::get_str(document, "semantic_digest").unwrap_or_default();
    if !supplied_digest.is_empty() && supplied_digest != expected_digest {
        return Err(ContractError::integrity(
            "DIGEST_MISMATCH",
            "semantic_digest does not match the published digest algorithm over the statement",
            "Recompute sha256(JCS({\"statement\"})) with kinbase-digest/1.",
        ));
    }
    let alg = crate::json::get_str(document, "digest_alg_version")
        .unwrap_or(crate::model::DIGEST_ALG_VERSION);
    if alg != crate::model::DIGEST_ALG_VERSION {
        return Err(ContractError::degraded(
            "DIGEST_ALGORITHM_UNSUPPORTED",
            format!("digest algorithm {alg} is unknown"),
            "Use kinbase-digest/1.",
        ));
    }
    let criticality = crate::json::get_str(document, "company_criticality").unwrap_or("advisory");
    let valid_from = crate::json::get_str(document, "valid_from")
        .unwrap_or(now)
        .to_owned();
    let mut event = json!({
        "schema": crate::model::EVENT_SCHEMA,
        "event_id": format!("evt_{}", &crate::hash::sha256_text(&format!("{fact_id}\0{version}\0{statement}"))[..24]),
        "store_kind": "company",
        "authority_id": "company-steward",
        "authority_scope": crate::json::get_str(document, "authority_scope").unwrap_or("company:root"),
        "fact_id": fact_id,
        "logical_key": crate::json::get_str(document, "logical_key").unwrap_or(fact_id),
        "atom_kind": if crate::model::criticality_is_safety(criticality) { "constraint" } else { "decision" },
        "scope": crate::json::get_str(document, "authority_scope").unwrap_or("company:root"),
        "statement": statement,
        "evidence_refs": [format!("company-fact-document:{fact_id}:v{version}")],
        "asserted_at": valid_from,
        "effective_from": valid_from,
        "effective_until": document.get("valid_until").cloned().unwrap_or(Value::Null),
        "disposition": "accepted",
        "distortion": {"trigger": "company architecture reference", "loss_if_absent": if crate::model::criticality_is_safety(criticality) { 9000 } else { 3000 }, "rationale": format!("Company criticality {criticality}")},
        "parents": [],
        "supersedes": [],
        "redundancy_with": [],
        "complements": [],
        "company_refs": [],
        "authority_snapshot_cursor": version.to_string(),
        "confidence": 9000,
        "unresolved_uncertainty": null,
        "company_criticality": criticality,
        "fact_version": version.to_string(),
        "semantic_digest": expected_digest,
        "digest_alg_version": alg,
        "company_id": crate::json::get_str(document, "company_id").unwrap_or(&state.config.company_id)
    });
    if let Some(map) = event.as_object_mut() {
        if map.get("effective_until") == Some(&Value::Null) {
            map.remove("effective_until");
        }
    }
    // The document's own steward signature authorizes the conversion; the
    // converted event is re-signed by the root key it was verified against.
    let key = PublicKey::verify_document("fact-event", document).ok_or_else(|| {
        ContractError::integrity(
            "SIGNATURE_INVALID",
            "Company fact document signature failed",
            "Sign the document with the steward root key as message type fact-event.",
        )
    })?;
    if key.to_hex() != state.root.public().to_hex() && key.to_hex() != signer {
        return Err(ContractError::refused(
            "AUTHORITY_WRONG_SCOPE",
            "Company fact document is not steward-signed",
            "Only the Company steward may publish Company facts.",
        ));
    }
    if key.to_hex() != state.root.public().to_hex() {
        return Err(ContractError::refused(
            "AUTHORITY_WRONG_SCOPE",
            "Company fact document signer is not the steward root key",
            "Only the Company steward may publish Company facts.",
        ));
    }
    state.root.sign_document("fact-event", &event)
}

fn authority_registry(db: &CompanyDb, auth: &AuthContext) -> Handled {
    require_scope(auth, "facts:read")?;
    let mut latest: Option<(i64, Value)> = None;
    for (cursor, document, verification) in db
        .events_of_kind("registry")
        .map_err(|error| refuse(500, error))?
    {
        if verification == "verified"
            && latest
                .as_ref()
                .is_none_or(|(existing, _)| cursor > *existing)
        {
            latest = Some((cursor, document));
        }
    }
    let (cursor, document) = latest.ok_or_else(|| {
        refuse(
            404,
            ContractError::degraded(
                "CACHE_EXPIRED",
                "no signed authority registry document has been published",
                "Ask the Company steward to publish the registry; authority is withheld rather than assumed absent.",
            ),
        )
    })?;
    let entries = document
        .get("entries")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    Ok((
        200,
        json!({
            "registry": document,
            "entries": entries,
            "cursor": cursor.to_string(),
            "authority_cursor": crate::json::get_str(&document, "authority_cursor").map(str::to_owned).unwrap_or_else(|| cursor.to_string())
        }),
    ))
}

fn revocations(db: &CompanyDb, auth: &AuthContext) -> Handled {
    require_scope(auth, "facts:read")?;
    let documents = db
        .events_of_message_type("revocation")
        .map_err(|error| refuse(500, error))?
        .into_iter()
        .filter(|(_, document, verification)| {
            verification == "verified" && crate::json::get_str(document, "revoked_key").is_some()
        })
        .map(|(_, document, _)| document)
        .collect::<Vec<_>>();
    Ok((
        200,
        json!({
            "revocations": documents,
            "revocation_cursor": db.revocation_cursor().map_err(|error| refuse(500, error))?
        }),
    ))
}

fn snapshot(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    request: &Request,
    now: &str,
) -> Handled {
    require_scope(auth, "facts:read")?;
    let client_nonce = request.query.get("nonce").cloned().unwrap_or_default();
    if client_nonce.is_empty() || client_nonce.len() > 128 {
        return Err(refuse(
            400,
            ContractError::invariant("a fresh client nonce is required for a signed snapshot"),
        ));
    }
    let readable = readable_scopes(auth, trust_state);
    let view = current_view(db, trust_state, now).map_err(|error| refuse(500, error))?;
    // A repository asks for its own direction, not the company's entire corpus.
    // A ruling that governs `example/sync` is not direction for `booking`:
    // shipping it anyway made the snapshot grow with the estate until it passed
    // the client's body ceiling and no repository could refresh at all, and in
    // the meantime it filled every projection with other services' rulings. A
    // fact that governs nothing in particular is company-wide and always sent.
    let repository = request.query.get("repository").cloned().unwrap_or_default();
    // Ownership rulings say where work lands. A ticket in one repository
    // that edits paths in another needs the other's rulings, so they are
    // delivered to every repository whatever they govern; there are few and
    // the brief matches them by path.
    let governs_this_repository = |fact: &CurrentFact| -> bool {
        repository.is_empty()
            || fact.governs_paths.is_empty()
            || fact.logical_key.starts_with("ownership/")
            || fact.governs_paths.iter().any(|path| path == &repository)
    };
    let readable_facts: Vec<&CurrentFact> = view
        .facts
        .iter()
        .filter(|fact| readable.contains(&fact.authority_scope))
        .collect();
    let facts: Vec<Value> = readable_facts
        .iter()
        .filter(|fact| governs_this_repository(fact))
        .map(|fact| crate::model::value_of(*fact))
        .collect();
    // Stated, never silent: a fact withheld because it governs somewhere else
    // is reported by count, and `GET /facts` still serves the whole set.
    let facts_elsewhere_count = readable_facts.len() - facts.len();
    // Facts the token may not read are counted, never described: their ids,
    // scopes and sizes were an oracle for guessed statements (architecture
    // §2, §6). Unknowns, traces, parents and lifecycle rows follow the same
    // readable scopes as the facts.
    let denied_count = view
        .facts
        .iter()
        .filter(|fact| !readable.contains(&fact.authority_scope))
        .count();
    let unknowns: Vec<Value> = view
        .unknowns
        .iter()
        .filter(|unknown| unknown_readable(unknown, &readable))
        .map(crate::model::value_of)
        .collect();
    // The admitted event set behind the view, so a client reducer can reduce
    // Company and Codebase evidence for one logical key from immutable
    // signed events (architecture §6: the reducer is a pure function of the
    // admitted event set). Company remains the authority for its own current
    // view; the events are the inputs it reduced, not a second opinion.
    let events_since = request
        .query
        .get("events_since")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    let (mut events, events_omitted_count, events_sealed_cursor) =
        snapshot_events(db, &readable, events_since).map_err(|error| refuse(500, error))?;
    // A partial window is one the client must not reduce over -- it would drop
    // the supersession that retired a head -- so it falls back to the derived
    // `facts`. Sending it anyway is a third of a megabyte the reader is
    // contractually required to ignore, and it was the difference between a
    // snapshot that fits the body ceiling and one that does not.
    if events_omitted_count > 0 {
        events.clear();
    }
    // The version index answers "what else has been said about this fact", so it
    // covers the facts actually sent and not the ones withheld as another
    // repository's business.
    // Everything derived from the view is scoped the same way the view is: a
    // repository that is not sent a fact has no use for that fact's version
    // history or its reduction trace, and shipping them anyway put the response
    // back over the body ceiling from a different direction.
    let sent_ids: BTreeSet<String> = facts
        .iter()
        .filter_map(|fact| crate::json::get_str(fact, "fact_id").map(str::to_owned))
        .collect();
    let sent_keys: BTreeSet<&str> = facts
        .iter()
        .filter_map(|fact| crate::json::get_str(fact, "logical_key"))
        .chain(
            view.unknowns
                .iter()
                .filter(|unknown| unknown_readable(unknown, &readable))
                .map(|unknown| unknown.logical_key.as_str()),
        )
        .collect();
    let mut fact_versions = fact_versions_index(db, &view).map_err(|error| refuse(500, error))?;
    if let Some(map) = fact_versions.as_object_mut() {
        // Only the facts sent: the index named every fact in every scope.
        map.retain(|fact_id, _| sent_ids.contains(fact_id.as_str()));
        // A client needs to know a fact has been revised and what the newest
        // revisions were, not every revision ever made. Four republications of
        // 563 claims put 315 KiB of superseded history into every snapshot.
        for versions in map.values_mut() {
            if let Some(list) = versions.as_array_mut() {
                if list.len() > FACT_VERSIONS_KEPT {
                    let start = list.len() - FACT_VERSIONS_KEPT;
                    list.drain(..start);
                }
            }
        }
    }
    let bytes: usize = facts
        .iter()
        .chain(events.iter())
        .map(|item| crate::json::canonical_bytes(item).len())
        .sum();
    charge_read(db, state, auth, facts.len().max(1), bytes)?;
    let snapshot = json!({
        "schema": "kinbase-snapshot/1",
        "company_id": state.config.company_id,
        "cursor": trust_state.cursor.to_string(),
        "authority_cursor": trust_state.authority_cursor.clone(),
        "service_cursor": trust_state.cursor.to_string(),
        "revocation_cursor": db.revocation_cursor().map_err(|error| refuse(500, error))?,
        "client_nonce": client_nonce,
        "issued_at": now,
        "revocation_valid_until": crate::time::plus_seconds(now, state.config.revocation_freshness_seconds).unwrap_or_default(),
        "fact_valid_until": crate::time::plus_seconds(now, state.config.default_fact_freshness_seconds).unwrap_or_default(),
        "facts": facts,
        "facts_scope": if repository.is_empty() { String::new() } else { format!("repository:{repository}") },
        "facts_governing_elsewhere_count": facts_elsewhere_count,
        "events": events,
        // Stated, never silent: a client that needs the omitted history pages
        // `GET /events?since=<events_sealed_cursor>` for it.
        "events_omitted_count": events_omitted_count,
        "events_since": events_since,
        "events_sealed_cursor": events_sealed_cursor,
        "denied_count": denied_count,
        "unknowns": unknowns,
        "registry": trust_state.public_registry(),
        "revocations": trust_state.revocations,
        "scope_revocations": trust_state.scope_revocations,
        "relaxations": db.relaxations().map_err(|error| refuse(500, error))?,
        "certificates": db.all_certificates().map_err(|error| refuse(500, error))?,
        "fact_versions": fact_versions,
        "lifecycle_admissions": lifecycle_admissions(db, trust_state, &readable),
        // Every revocation ever recorded, including keys the steward later
        // republished: a later epoch authorizes new events, but facts asserted
        // before the revocation remain historical (architecture §3).
        "revocation_history": db
            .events_of_kind("revocation")
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, _, verification)| verification == "verified")
            .filter_map(|(cursor, payload, _)| {
                let key = crate::json::get_str(&payload, "revoked_key")?.to_owned();
                Some(json!({
                    "revoked_key": key,
                    "cursor": crate::json::get_str(&payload, "authority_cursor")
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| cursor.to_string()),
                    "effective_at": crate::json::get_str(&payload, "effective_at").unwrap_or_default(),
                    "governing": trust_state.revocations.iter().any(|r| r.revoked_key == crate::json::get_str(&payload, "revoked_key").unwrap_or_default())
                }))
            })
            .collect::<Vec<_>>(),
        "fact_parents": fact_parents(db, &view, &sent_ids),
        "traces": view.traces.iter().filter(|trace| sent_keys.contains(trace.logical_key.as_str())).map(|trace| json!({
            "logical_key": trace.logical_key,
            "state": trace.state,
            "admitted_event_ids": trace.admitted_event_ids,
            "current_fact_id": trace.current_fact_id,
            "unknown_id": trace.unknown_id
        })).collect::<Vec<_>>()
    });
    let signed = state
        .root
        .sign_document("receipt", &snapshot)
        .map_err(|error| refuse(500, error))?;
    db.bump("snapshots").map_err(|error| refuse(500, error))?;
    Ok((200, signed))
}

/// The immutable admitted `fact-event` documents whose authority scope the
/// token may read, each with the store cursor and the verification recorded
/// at admission. Unknown events ride along so a client sees the same Unknown
/// queue Company reduced.
/// How many admitted events one snapshot carries. The snapshot's `facts` are
/// Company's current view and are always complete; `events` are the inputs that
/// view reduced, and an append-only log has no upper bound. The reference deployment's Company
/// store reached 1.7 MB and the client's body ceiling refused every refresh --
/// the cache froze at the last snapshot that happened to fit, which is the worst
/// possible failure because it looks like nothing is wrong. Older events stay
/// reachable through `GET /events?since=`, which has always paged.
const SNAPSHOT_EVENT_LIMIT: usize = 400;
/// And a byte budget, which is the ceiling that actually binds. The client
/// refuses a response over `MAX_BODY_BYTES * 4` (1 MiB); the rest of the
/// snapshot -- the current view, certificates, registry, revocation history --
/// is what a client needs to establish trust and must always fit, so the event
/// window gets what is left rather than the other way round. A count limit
/// alone let 400 multi-kilobyte architecture statements blow the body ceiling.
const SNAPSHOT_EVENT_BYTES: usize = 384 * 1024;
/// Newest revisions of a fact carried in a snapshot. `GET /facts/<id>` serves
/// the rest.
const FACT_VERSIONS_KEPT: usize = 3;

fn snapshot_events(
    db: &CompanyDb,
    readable: &BTreeSet<String>,
    since: i64,
) -> Result<(Vec<Value>, usize, String), ContractError> {
    let mut selected: Vec<(i64, Value, usize)> = Vec::new();
    let mut omitted = 0usize;
    for kind in ["fact-event", "unknown-event"] {
        for (cursor, payload, verification) in db.events_of_kind(kind)? {
            let scope = crate::json::get_str(&payload, "authority_scope").unwrap_or_default();
            if !readable.contains(scope) {
                continue;
            }
            if cursor <= since {
                // Already sealed by this client at an earlier refresh.
                continue;
            }
            let record = json!({
                "cursor": cursor.to_string(),
                "kind": kind,
                "verification": verification,
                "document": payload
            });
            // Size it once, here. Measuring in a second pass re-serialized every
            // record on every snapshot request, which a soak test that polls the
            // endpoint feels immediately.
            let size = crate::json::canonical_bytes(&record).len();
            selected.push((cursor, record, size));
        }
    }
    // Newest first, so a truncated window carries the most recent history
    // rather than whichever kind sorted first.
    selected.sort_by(|left, right| right.0.cmp(&left.0));
    if selected.len() > SNAPSHOT_EVENT_LIMIT {
        omitted = selected.len() - SNAPSHOT_EVENT_LIMIT;
        selected.truncate(SNAPSHOT_EVENT_LIMIT);
    }
    let mut spent = 0usize;
    let mut kept = 0usize;
    for (_, _, size) in &selected {
        if kept > 0 && spent + size > SNAPSHOT_EVENT_BYTES {
            break;
        }
        spent += size;
        kept += 1;
    }
    if kept < selected.len() {
        omitted += selected.len() - kept;
        selected.truncate(kept);
    }
    // The client may seal up to the oldest event it actually received; anything
    // older was omitted and must still be reachable from `/events`.
    let sealed = selected
        .iter()
        .map(|(cursor, _, _)| *cursor)
        .min()
        .map(|cursor| (cursor - 1).max(since))
        .unwrap_or(since);
    selected.sort_by_key(|(cursor, _, _)| *cursor);
    Ok((
        selected.into_iter().map(|(_, value, _)| value).collect(),
        omitted,
        sealed.to_string(),
    ))
}

fn fact_versions_index(
    db: &CompanyDb,
    view: &crate::reducer::CurrentView,
) -> Result<Value, ContractError> {
    let mut map = serde_json::Map::new();
    for fact in &view.facts {
        map.insert(
            fact.fact_id.clone(),
            Value::Array(db.fact_versions(&fact.fact_id)?),
        );
    }
    Ok(Value::Object(map))
}

/// The admitted event log, paged. A facts reader receives the bodies of
/// events in scopes it may read (this is where a snapshot's omitted history
/// is paged from); everything else, and everything the administrative
/// issuance capability sees, is metadata with a payload digest: issuance
/// cannot read fact bodies (architecture §6).
fn events(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    request: &Request,
) -> Handled {
    let reads_facts = auth.token.has_scope("facts:read");
    if !reads_facts {
        require_scope(auth, "admin:issue")?;
    }
    let readable = if reads_facts {
        readable_scopes(auth, trust_state)
    } else {
        BTreeSet::new()
    };
    let since = request
        .query
        .get("since")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0);
    // SQLite reads a negative LIMIT as no limit at all.
    let limit = request
        .query
        .get("limit")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    let mut rows = db
        .all_events(since, limit)
        .map_err(|error| refuse(500, error))?;
    for row in &mut rows {
        let scope = row
            .get("payload")
            .and_then(|payload| crate::json::get_str(payload, "authority_scope"))
            .unwrap_or_default()
            .to_owned();
        if readable.contains(&scope) {
            continue;
        }
        if let Some(Value::Object(map)) = Some(&mut *row)
            && let Some(payload) = map.remove("payload")
        {
            map.insert(
                "payload_digest".to_owned(),
                Value::String(crate::json::digest(&payload)),
            );
            map.insert("payload_withheld".to_owned(), Value::Bool(true));
        }
    }
    // Event bodies are fact reads, under the same per-principal budget as
    // /facts and /snapshot; a reader refused there was served here.
    if reads_facts {
        let bytes: usize = rows
            .iter()
            .filter_map(|row| row.get("payload"))
            .map(|payload| crate::json::canonical_bytes(payload).len())
            .sum();
        charge_read(db, state, auth, rows.len().max(1), bytes)?;
    }
    Ok((200, json!({"events": rows})))
}

fn publish_registry(
    db: &CompanyDb,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    let _ = auth;
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a registry document body is required"),
        )
    })?;
    if crate::json::get_str(&document, "schema") != Some(crate::model::REGISTRY_SCHEMA) {
        return Err(refuse(
            400,
            ContractError::invariant(
                "registry document schema must be kinbase-authority-registry/1",
            ),
        ));
    }
    trust::verify_steward_document(trust_state, "authority-registry-entry", &document).map_err(
        |error| {
            refuse(
                if error.code == "SIGNATURE_INVALID" {
                    400
                } else {
                    403
                },
                error,
            )
        },
    )?;
    let entries = crate::json::get_array(&document, "entries").ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("registry document lacks entries"),
        )
    })?;
    for entry in entries {
        for field in ["authority_id", "scope", "public_key"] {
            if crate::json::get_str(entry, field)
                .unwrap_or_default()
                .is_empty()
            {
                return Err(refuse(
                    400,
                    ContractError::invariant(format!("registry entry lacks {field}")),
                ));
            }
        }
        let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
        if scope.contains('*') || scope.contains('%') || scope.contains('?') {
            return Err(refuse(
                400,
                ContractError::invariant(
                    "registry scopes are exact strings; wildcards do not exist",
                ),
            ));
        }
        if entry.get("email").is_some()
            || entry.get("private_key").is_some()
            || entry.get("contact").is_some()
        {
            return Err(refuse(
                400,
                ContractError::integrity(
                    "PERSONAL_TAINT_BLOCKED",
                    "registry entries may not carry directory/contact data or private keys",
                    "Publish contact data through the directory endpoint and keep private keys out of the registry.",
                ),
            ));
        }
        PublicKey::from_hex(crate::json::get_str(entry, "public_key").unwrap_or_default())
            .map_err(|_| {
                refuse(
                    400,
                    ContractError::invariant(
                        "registry entry public_key is not a 64-hex Ed25519 key",
                    ),
                )
            })?;
    }
    let digest = crate::json::digest(&document);
    let event_id = format!("registry_{}", &digest[..40]);
    let published_cursor = crate::json::get_str(&document, "authority_cursor")
        .unwrap_or_default()
        .to_owned();
    if published_cursor.is_empty() {
        return Err(refuse(
            400,
            ContractError::invariant(
                "registry document lacks authority_cursor; a publication must say where it stands",
            ),
        ));
    }
    let outcome = with_immediate_transaction(db, || {
        // Publication only moves the registry forward. A registry document is
        // a steward's statement at one authority cursor, and its signature stays
        // valid forever: any token holder could fetch an old one and post it
        // again, and every entry added since came back as an R-10 revocation.
        // Decided here, inside the write transaction, against the service's own
        // record rather than the trust state read before the request.
        let latest = trust::published_registry(db).map_err(|error| refuse(500, error))?;
        let current = latest
            .as_ref()
            .map(|(_, cursor)| cursor.clone())
            .unwrap_or_default();
        if let Some(existing) = db
            .event_cursor(&event_id)
            .map_err(|error| refuse(500, error))?
        {
            // Identity, not cursor equality: the document posted again is the
            // one the service holds as current.
            if latest.as_ref().is_some_and(|(row, _)| *row == existing) {
                // The current document, posted again: the same receipt, no effects.
                return Ok((
                    200,
                    registry_receipt(db, &digest, entries.len(), existing, &published_cursor)?,
                ));
            }
            return Err(refuse(
                409,
                ContractError::refused(
                    "APPROVAL_REPLAY",
                    "this registry document was published before and has been superseded",
                    "Publish a newly signed registry at a newer authority_cursor.",
                ),
            ));
        }
        if !current.is_empty()
            && crate::reducer::cursor_order(&published_cursor, &current)
                != std::cmp::Ordering::Greater
        {
            return Err(refuse(
                409,
                ContractError::refused(
                    "APPROVAL_REPLAY",
                    format!(
                        "registry authority_cursor {published_cursor} does not advance past the published {current}"
                    ),
                    "Publish a newly signed registry at a newer authority_cursor.",
                ),
            ));
        }
        let previous_entries = db.registry_entries().map_err(|error| refuse(500, error))?;
        let cursor = match db
            .append_event(
                &event_id,
                "authority-registry-entry",
                "registry",
                &document,
                crate::json::get_str(&document, "signer").unwrap_or_default(),
                "verified",
                None,
            )
            .map_err(|error| refuse(500, error))?
        {
            Some(cursor) => cursor,
            None => db
                .event_cursor(&event_id)
                .map_err(|error| refuse(500, error))?
                .unwrap_or(0),
        };
        // R-10: republication at a strictly newer cursor without an entry is
        // that entry's revocation. The vanished key is recorded as a signed
        // revocation event with its own cursor and effective time, so every
        // client observing this cursor runs the architecture §3 cascade.
        let published: BTreeSet<(String, String)> = entries
            .iter()
            .map(|entry| {
                (
                    crate::json::get_str(entry, "authority_id")
                        .unwrap_or_default()
                        .to_owned(),
                    crate::json::get_str(entry, "scope")
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
            .collect();
        let mut revoked_count = 0usize;
        for existing in db.registry_entries().map_err(|error| refuse(500, error))? {
            if crate::json::get_str(&existing, "status") != Some("active") {
                continue;
            }
            let identity = (
                crate::json::get_str(&existing, "authority_id")
                    .unwrap_or_default()
                    .to_owned(),
                crate::json::get_str(&existing, "scope")
                    .unwrap_or_default()
                    .to_owned(),
            );
            if published.contains(&identity) {
                continue;
            }
            let public_key = crate::json::get_str(&existing, "public_key")
                .unwrap_or_default()
                .to_owned();
            let mut retired = existing.clone();
            retired["status"] = Value::String("revoked".to_owned());
            db.upsert_registry_entry(&retired, cursor)
                .map_err(|error| refuse(500, error))?;
            revoked_count += 1;
            // Revocations name keys, not scopes. A key the new document still
            // lists under another scope stays authorized there (as the loop
            // below already holds); revoking it here withdrew it everywhere.
            if entries
                .iter()
                .any(|published| crate::json::get_str(published, "public_key") == Some(&public_key))
            {
                continue;
            }
            let revocation = json!({
                "schema": "kinbase-revocation/1",
                "revoked_key": public_key,
                "revoked_authority_id": identity.0,
                "scope": identity.1,
                "cursor": cursor.to_string(),
                "authority_cursor": crate::json::get_str(&document, "authority_cursor").unwrap_or_default(),
                "effective_at": now,
                "reason": "registry republication omitted the entry (R-10)",
                "signer": crate::json::get_str(&document, "signer").unwrap_or_default()
            });
            let revocation_id = format!("revocation_{}", &crate::json::digest(&revocation)[..40]);
            db.append_event(
                &revocation_id,
                "revocation",
                "revocation",
                &revocation,
                crate::json::get_str(&document, "signer").unwrap_or_default(),
                "verified",
                None,
            )
            .map_err(|error| refuse(500, error))?;
        }
        if revoked_count > 0 {
            db.set_meta("revocation_cursor", &cursor.to_string())
                .map_err(|error| refuse(500, error))?;
        }
        for entry in entries {
            let mut entry = entry.clone();
            if entry.get("status").is_none() {
                entry["status"] = Value::String("active".to_owned());
            }
            db.upsert_registry_entry(&entry, cursor)
                .map_err(|error| refuse(500, error))?;
        }
        // R-10: the steward republishing the registry without an entry (or
        // with a rotated key) is the revocation event; the cursor at which
        // the entry vanished is the revocation cursor, and the §3 cascade
        // runs from it.
        let listed = |entry: &Value| {
            entries.iter().any(|published| {
                crate::json::get_str(published, "authority_id")
                    == crate::json::get_str(entry, "authority_id")
                    && crate::json::get_str(published, "scope")
                        == crate::json::get_str(entry, "scope")
            })
        };
        let mut revoked_keys: BTreeSet<String> = BTreeSet::new();
        let mut revoked_scopes: BTreeSet<(String, String)> = BTreeSet::new();
        for entry in &previous_entries {
            if crate::json::get_str(entry, "status") != Some("active") {
                continue;
            }
            let key = crate::json::get_str(entry, "public_key").unwrap_or_default();
            let rotated = entries.iter().any(|published| {
                crate::json::get_str(published, "authority_id")
                    == crate::json::get_str(entry, "authority_id")
                    && crate::json::get_str(published, "scope")
                        == crate::json::get_str(entry, "scope")
                    && crate::json::get_str(published, "public_key") != Some(key)
            });
            if listed(entry) && !rotated {
                continue;
            }
            if !listed(entry) {
                db.mark_registry_entry_revoked(
                    crate::json::get_str(entry, "authority_id").unwrap_or_default(),
                    crate::json::get_str(entry, "scope").unwrap_or_default(),
                    cursor,
                )
                .map_err(|error| refuse(500, error))?;
            }
            // A key still listed under another exact scope stays authorized
            // there; only a key no published entry carries is revoked. What
            // it warranted in the scope it lost is withdrawn all the same:
            // otherwise a dropped scope kept every fact it had admitted current.
            let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
            let still_listed = entries
                .iter()
                .any(|published| crate::json::get_str(published, "public_key") == Some(key));
            let still_in_scope = entries.iter().any(|published| {
                crate::json::get_str(published, "public_key") == Some(key)
                    && crate::json::get_str(published, "scope") == Some(scope)
            });
            if !still_listed {
                revoked_keys.insert(key.to_owned());
            } else if !still_in_scope {
                revoked_scopes.insert((key.to_owned(), scope.to_owned()));
            }
        }
        for key in &revoked_keys {
            let revocation = json!({
                "schema": crate::model::REVOCATION_SCHEMA,
                "revoked_key": key,
                "authority_cursor": published_cursor,
                "effective_at": now,
                "derived_from": event_id,
                "reason": "entry absent from the steward-republished authority registry"
            });
            let revocation_id = format!(
                "revocation_{}",
                &crate::hash::sha256_text(&format!("{key}\0{published_cursor}"))[..40]
            );
            let revocation_cursor = db
                .append_event(
                    &revocation_id,
                    "revocation",
                    "revocation",
                    &revocation,
                    crate::json::get_str(&document, "signer").unwrap_or_default(),
                    "verified",
                    None,
                )
                .map_err(|error| refuse(500, error))?
                .unwrap_or(cursor);
            revocation_cascade(
                db,
                key,
                None,
                revocation_cursor,
                &published_cursor,
                now,
                &digest,
            )?;
        }
        for (key, scope) in &revoked_scopes {
            let revocation = json!({
                "schema": crate::model::REVOCATION_SCHEMA,
                "revoked_key": key,
                "revoked_scope": scope,
                "authority_cursor": published_cursor,
                "effective_at": now,
                "derived_from": event_id,
                "reason": "entry absent from the steward-republished authority registry; the key stays registered under other scopes"
            });
            let revocation_id = format!(
                "revocation_{}",
                &crate::hash::sha256_text(&format!("{key}\0{scope}\0{published_cursor}"))[..40]
            );
            let revocation_cursor = db
                .append_event(
                    &revocation_id,
                    "revocation",
                    "revocation",
                    &revocation,
                    crate::json::get_str(&document, "signer").unwrap_or_default(),
                    "verified",
                    None,
                )
                .map_err(|error| refuse(500, error))?
                .unwrap_or(cursor);
            revocation_cascade(
                db,
                key,
                Some(scope),
                revocation_cursor,
                &published_cursor,
                now,
                &digest,
            )?;
        }
        db.audit(
            "registry-published",
            &json!({"digest": digest, "entries": entries.len(), "cursor": cursor, "revoked": revoked_count, "revoked_keys": revoked_keys.len(), "revoked_scopes": revoked_scopes.len()}),
        )
        .map_err(|error| refuse(500, error))?;
        Ok((
            201,
            registry_receipt(db, &digest, entries.len(), cursor, &published_cursor)?,
        ))
    });
    if let Err((_, error)) = &outcome
        && error.code == "APPROVAL_REPLAY"
    {
        // A refused replay is itself worth knowing about; the transaction
        // that decided it has rolled back, so the record is written after.
        let _ = db.audit(
            "registry-publication-refused",
            &json!({"digest": digest, "authority_cursor": published_cursor, "reason": error.message}),
        );
    }
    outcome
}

/// The receipt of one registry publication, read back from the row that
/// recorded it, so a retry of the current document answers with the bytes the
/// first post did rather than a receipt stamped with the retry's own clock.
fn registry_receipt(
    db: &CompanyDb,
    digest: &str,
    entries: usize,
    cursor: i64,
    authority_cursor: &str,
) -> Result<Value, (u16, ContractError)> {
    let recorded_at = db
        .all_events(cursor - 1, 1)
        .map_err(|error| refuse(500, error))?
        .first()
        .and_then(|row| crate::json::get_str(row, "recorded_at"))
        .unwrap_or_default()
        .to_owned();
    Ok(json!({
        "schema": crate::model::RECEIPT_SCHEMA,
        "status": "published",
        "registry_digest": digest,
        "entries": entries,
        "cursor": cursor.to_string(),
        "authority_cursor": authority_cursor,
        "recorded_at": recorded_at
    }))
}

fn directory_write(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    require_scope(auth, "admin:issue")?;
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a directory document is required"),
        )
    })?;
    trust::verify_steward_document(trust_state, "authority-registry-entry", &document)
        .map_err(|error| refuse(403, error))?;
    let authority_id = crate::json::get_str(&document, "authority_id").unwrap_or_default();
    let retention = crate::time::plus_seconds(now, state.config.directory_retention_seconds)
        .unwrap_or_default();
    db.upsert_directory(
        authority_id,
        crate::json::get_str(&document, "display_name").unwrap_or_default(),
        crate::json::get_str(&document, "contact").unwrap_or_default(),
        &retention,
    )
    .map_err(|error| refuse(500, error))?;
    Ok((
        201,
        json!({"status": "recorded", "authority_id": authority_id, "retention_until": retention}),
    ))
}

fn post_question(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    require_scope(auth, "questions:write")?;
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a question document is required"),
        )
    })?;
    let scope = crate::json::get_str(&document, "authority_scope")
        .or(crate::json::get_str(&document, "scope"))
        .unwrap_or_default()
        .to_owned();
    let question_text = crate::json::get_str(&document, "question")
        .unwrap_or_default()
        .to_owned();
    if scope.is_empty() || question_text.is_empty() {
        return Err(refuse(
            400,
            ContractError::invariant("a question requires authority_scope and question"),
        ));
    }
    let authority = trust_state
        .authority_for_scope(&scope)
        .map_err(|error| refuse(409, error))?
        .ok_or_else(|| {
            refuse(
                404,
                ContractError::degraded(
                    "UNKNOWN_OWNER_UNRESOLVED",
                    format!("no registered authority owns the exact scope {scope}"),
                    "The Company steward must register an authority for the scope; a Company-steward Unknown was opened.",
                ),
            )
        });
    let authority = match authority {
        Ok(authority) => authority,
        Err((status, error)) => {
            // Registry gap becomes a Company-steward Unknown.
            let unknown = json!({
                "unknown_id": format!("unknown_registry_{}", &crate::hash::sha256_text(&scope)[..24]),
                "scope": scope,
                "owner_identity": "company-steward",
                "owner_role": "company-steward",
                "status": "open",
                "question": format!("Register exactly one authority for scope {scope}"),
                "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
                "kind": "registry"
            });
            db.upsert_unknown(&unknown, "registry")
                .map_err(|error| refuse(500, error))?;
            return Err((status, error));
        }
    };
    let authority_id = crate::json::get_str(&authority, "authority_id")
        .unwrap_or_default()
        .to_owned();
    if let Some(supplied) = crate::json::get_str(&document, "authority_id") {
        if supplied != authority_id {
            return Err(refuse(
                403,
                ContractError::refused(
                    "AUTHORITY_WRONG_SCOPE",
                    "supplied authority does not own the exact scope",
                    "Address the registered authority for the scope.",
                ),
            ));
        }
    }
    let question_id = crate::json::get_str(&document, "question_id")
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "question_{}",
                &crate::hash::sha256_text(&format!("{scope}\0{question_text}\0{now}"))[..24]
            )
        });
    let due = crate::json::get_str(&document, "response_due_at")
        .map(str::to_owned)
        .unwrap_or_else(|| crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default());
    let stored = json!({
        "schema": crate::model::QUESTION_SCHEMA,
        "question_id": question_id,
        "unknown_id": document.get("unknown_id").cloned().unwrap_or(Value::Null),
        "authority_id": authority_id,
        "authority_scope": scope,
        "question_kind": crate::json::get_str(&document, "question_kind").unwrap_or("architecture"),
        "decision": document.get("decision").cloned().unwrap_or(Value::Null),
        "evidence_examined": document.get("evidence_examined").cloned().unwrap_or(Value::Array(Vec::new())),
        "remaining_alternatives": document.get("remaining_alternatives").cloned().unwrap_or(Value::Array(Vec::new())),
        "distortion_if_wrong": document.get("distortion_if_wrong").cloned().unwrap_or(Value::Null),
        "question": question_text,
        "task_id": document.get("task_id").cloned().unwrap_or(Value::Null),
        "created_at": now,
        "response_due_at": due,
        "expiry_policy": crate::model::normalize_policy(crate::json::get_str(&document, "expiry_policy").unwrap_or("block_dependent_decision"))
    });
    let delivery = json!({"channel": authority.get("channel").cloned().unwrap_or(Value::Null), "status": "queued", "queued_at": now});
    let _ = state;
    with_immediate_transaction(db, || {
        let inserted = db
            .insert_question(&stored, &auth.client_key, &delivery)
            .map_err(|error| refuse(500, error))?;
        if !inserted {
            let existing = db
                .question(&question_id)
                .map_err(|error| refuse(500, error))?;
            return Ok((
                200,
                json!({"status": "already-queued", "question": existing}),
            ));
        }
        db.append_event(
            &format!("question_event_{question_id}"),
            "question",
            "question",
            &stored,
            &auth.client_key,
            "verified",
            None,
        )
        .map_err(|error| refuse(500, error))?;
        db.bump("questions").map_err(|error| refuse(500, error))?;
        Ok((
            201,
            json!({
                "status": "queued",
                "question_id": question_id,
                "authority_id": authority_id,
                "authority_scope": stored["authority_scope"],
                "channel": authority.get("channel").cloned().unwrap_or(Value::Null),
                "response_due_at": stored["response_due_at"]
            }),
        ))
    })
}

fn post_answer(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    // Architecture §6: the ordinary facts token (which may write questions)
    // cannot post an answer; only an answer-scoped token can.
    if !auth.token.has_scope("answers:write") {
        return Err(auth_refusal_403());
    }
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("an answer document is required"),
        )
    })?;
    let question_id = crate::json::get_str(&document, "question_id")
        .unwrap_or_default()
        .to_owned();
    let question = db
        .question(&question_id)
        .map_err(|error| refuse(500, error))?
        .ok_or_else(|| refuse(404, ContractError::invariant("question not found")))?;
    let scope = crate::json::get_str(&question, "authority_scope")
        .unwrap_or_default()
        .to_owned();
    let authority = trust_state
        .authority_for_scope(&scope)
        .map_err(|error| refuse(409, error))?
        .ok_or_else(|| {
            refuse(
                409,
                ContractError::degraded(
                    "UNKNOWN_OWNER_UNRESOLVED",
                    "no registered authority owns the question scope",
                    "The Company steward must repair the registry.",
                ),
            )
        })?;
    let expected_key = crate::json::get_str(&authority, "public_key").unwrap_or_default();
    let expected_id = crate::json::get_str(&authority, "authority_id").unwrap_or_default();
    // The registry signer must have produced the signature (C26: key file is informational).
    let key = PublicKey::verify_document("answer", &document).ok_or_else(|| {
        refuse(
            400,
            ContractError::integrity(
                "SIGNATURE_INVALID",
                "answer signature failed",
                "Quarantine the answer and contact the named authority.",
            ),
        )
    })?;
    if key.to_hex() != expected_key {
        db.bump("answers_refused_wrong_scope")
            .map_err(|error| refuse(500, error))?;
        return Err(refuse(
            403,
            ContractError::refused(
                "AUTHORITY_WRONG_SCOPE",
                "answer signer does not own the exact question scope",
                "Route the answer through the registered in-scope authority; role prestige cannot widen scope.",
            ),
        ));
    }
    if let Some(supplied) = crate::json::get_str(&document, "authority_id") {
        if supplied != expected_id {
            return Err(refuse(
                403,
                ContractError::refused(
                    "AUTHORITY_WRONG_SCOPE",
                    "answer names another authority",
                    "Use the registered authority id for the scope.",
                ),
            ));
        }
    }
    let answer_text = crate::json::get_str(&document, "answer").unwrap_or_default();
    if answer_text.is_empty() {
        return Err(refuse(
            400,
            ContractError::invariant("answer text is required"),
        ));
    }
    if crate::scanner::hard_blocked(answer_text) {
        return Err(refuse(
            403,
            ContractError::integrity(
                "PERSONAL_TAINT_BLOCKED",
                "hard-blocking material reached Company admission",
                "Keep the source private; provide a minimized answer.",
            ),
        ));
    }
    if document.get("contains_code") == Some(&Value::Bool(true)) || looks_like_code(answer_text) {
        return Err(refuse(
            400,
            ContractError::refused(
                "CONFIG_INVARIANT",
                "answers carry fact and rationale only, never code or a solution",
                "Remove code from the answer.",
            ),
        ));
    }
    with_immediate_transaction(db, || {
        let existing = db
            .answers_for_question(&question_id)
            .map_err(|error| refuse(500, error))?;
        let parents: Vec<String> = crate::json::get_array(&document, "parents")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let mut supersedes: Option<String> = None;
        let mut conflict = false;
        if !existing.is_empty() {
            let prior_ids: Vec<String> = existing
                .iter()
                .filter_map(|answer| crate::json::get_str(answer, "answer_id").map(str::to_owned))
                .collect();
            if let Some(parent) = parents.iter().find(|parent| {
                prior_ids.iter().any(|id| {
                    id == *parent || parent.ends_with(id.as_str()) || id.ends_with(parent.as_str())
                })
            }) {
                supersedes = Some(parent.clone());
            } else if parents.iter().any(|parent| parent.contains('#')) {
                // "<qid>#1" style parent references the first answer.
                supersedes = prior_ids.first().cloned();
            } else {
                conflict = true;
            }
        }
        let answer_id = crate::json::get_str(&document, "answer_id")
            .map(str::to_owned)
            .unwrap_or_else(|| format!("answer_{}", &crate::json::digest(&document)[..24]));
        let mut stored = document.clone();
        stored["answer_id"] = Value::String(answer_id.clone());
        stored["authority_scope"] = Value::String(scope.clone());
        stored["authority_id"] = Value::String(expected_id.to_owned());
        if stored.get("answered_at").is_none() {
            stored["answered_at"] = Value::String(now.to_owned());
        }
        let cursor = db
            .append_event(
                &format!("answer_event_{answer_id}"),
                "answer",
                "answer",
                &stored,
                &key.to_hex(),
                "verified",
                None,
            )
            .map_err(|error| refuse(500, error))?
            .unwrap_or(0);
        db.insert_answer(&stored, cursor, supersedes.as_deref())
            .map_err(|error| refuse(500, error))?;
        // The admitted answer is a Company observation and fact event closing the Unknown.
        let rationale = crate::json::get_str(&document, "rationale").unwrap_or_default();
        let mut fact = json!({
            "schema": crate::model::EVENT_SCHEMA,
            "event_id": format!("evt_answer_{}", &answer_id.trim_start_matches("answer_")[..24.min(answer_id.trim_start_matches("answer_").len())]),
            "store_kind": "company",
            "authority_id": expected_id,
            "authority_scope": scope,
            "fact_id": crate::model::fact_id("company", &scope, answer_text),
            "logical_key": crate::json::get_str(&question, "logical_key").map(str::to_owned).unwrap_or_else(|| crate::model::logical_key("company", &scope, &question_id)),
            "atom_kind": "decision",
            "scope": scope,
            "statement": answer_text,
            "evidence_refs": [question_id.clone(), answer_id.clone()],
            "asserted_at": now,
            "effective_from": now,
            "disposition": "accepted",
            "distortion": {"trigger": crate::json::get_str(&question, "decision").unwrap_or("dependent decision"), "loss_if_absent": 9000, "rationale": rationale},
            "parents": supersedes.iter().cloned().collect::<Vec<_>>(),
            "supersedes": [],
            "redundancy_with": [],
            "complements": [],
            "company_refs": [],
            "authority_snapshot_cursor": cursor.to_string(),
            "confidence": 9800,
            "unresolved_uncertainty": null
        });
        if let Some(prior) = supersedes.as_ref().and_then(|id| {
            existing.iter().find(|answer| {
                crate::json::get_str(answer, "answer_id") == Some(id.as_str()) || id.contains('#')
            })
        }) {
            let prior_id = crate::json::get_str(prior, "answer_id").unwrap_or_default();
            fact["supersedes"] = json!([format!(
                "evt_answer_{}",
                &prior_id.trim_start_matches("answer_")
                    [..24.min(prior_id.trim_start_matches("answer_").len())]
            )]);
        }
        let signed_fact = state
            .root
            .sign_document("fact-event", &fact)
            .map_err(|error| refuse(500, error))?;
        let fact_event = FactEvent::from_value(&signed_fact)
            .map_err(|error| refuse(500, ContractError::internal(error)))?;
        let fact_cursor = db
            .append_event(
                &fact_event.event_id,
                "fact-event",
                "fact-event",
                &signed_fact,
                &fact_event.signer,
                if conflict { "verified" } else { "verified" },
                Some(&key.to_hex()),
            )
            .map_err(|error| refuse(500, error))?
            .unwrap_or(cursor);
        db.record_fact_version(
            &fact_event.fact_id,
            &fact_event.semantic_digest(),
            &fact_event.event_id,
            fact_cursor,
        )
        .map_err(|error| refuse(500, error))?;
        let status = if conflict { "conflict" } else { "answered" };
        db.set_question_status(&question_id, status)
            .map_err(|error| refuse(500, error))?;
        if let Some(unknown_id) = crate::json::get_str(&question, "unknown_id") {
            if let Some(mut unknown) = db.unknown(unknown_id).map_err(|error| refuse(500, error))? {
                unknown["status"] = Value::String(if conflict {
                    "open".to_owned()
                } else {
                    "closed".to_owned()
                });
                unknown["closure_evidence"] =
                    json!([answer_id.clone(), fact_event.event_id.clone()]);
                db.upsert_unknown(&unknown, "answer")
                    .map_err(|error| refuse(500, error))?;
            }
        }
        db.bump("answers").map_err(|error| refuse(500, error))?;
        Ok((
            201,
            json!({
                "status": status,
                "answer_id": answer_id,
                "question_id": question_id,
                "authority_id": expected_id,
                "fact_id": fact_event.fact_id,
                "closure_event_id": fact_event.event_id,
                "cursor": fact_cursor.to_string(),
                "supersedes": supersedes,
                "conflict": conflict
            }),
        ))
    })
}

fn looks_like_code(text: &str) -> bool {
    let markers = [
        "```", "def ", "class ", "fn ", "import ", "#include", "return ", "=> {", ");", "};",
    ];
    let hits = markers
        .iter()
        .filter(|marker| text.contains(*marker))
        .count();
    hits >= 2
}

fn post_unknown(
    db: &CompanyDb,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    require_scope(auth, "questions:write")?;
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("an unknown-event document is required"),
        )
    })?;
    let unknown = crate::model::UnknownEvent::from_value(&document).map_err(|error| {
        refuse(
            400,
            ContractError::invariant(format!("unknown-event does not parse ({error})")),
        )
    })?;
    let signer = unknown.verify_signature().ok_or_else(|| {
        refuse(
            400,
            ContractError::integrity(
                "SIGNATURE_INVALID",
                "unknown-event signature failed",
                "Sign the Unknown with the client key.",
            ),
        )
    })?;
    let _ = trust_state;
    db.append_event(
        &unknown.event_id,
        "unknown-event",
        "unknown-event",
        &document,
        &signer.to_hex(),
        "verified",
        Some(&auth.client_key),
    )
    .map_err(|error| refuse(500, error))?;
    let mut record = document.clone();
    record["unknown_id"] = Value::String(unknown.fact_id.clone());
    db.upsert_unknown(
        &record,
        crate::json::get_str(&document, "kind").unwrap_or("client"),
    )
    .map_err(|error| refuse(500, error))?;
    Ok((
        201,
        json!({"status": "recorded", "unknown_id": unknown.fact_id, "response_due_at": unknown.response_due_at, "recorded_at": now}),
    ))
}

fn issue_certificate(
    db: &CompanyDb,
    state: &ServiceState,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    require_scope(auth, "admin:issue")?;
    let request = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a certificate request is required"),
        )
    })?;
    // An empty hint names no repository; matching on it would hand one
    // origin-less repository another's certificate.
    let hint = crate::json::get_str(&request, "discovery_hint")
        .filter(|hint| !hint.trim().is_empty())
        .map(str::to_owned);
    let repository_uuid = crate::json::get_str(&request, "repository_uuid")
        .map(str::to_owned)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if let Some(hint) = &hint {
        let existing = db
            .certificates_for_hint(hint)
            .map_err(|error| refuse(500, error))?;
        if let Some(certificate) = existing.first() {
            if crate::json::get_str(certificate, "repository_uuid")
                != Some(repository_uuid.as_str())
                && request.get("lineage_parent_uuid").is_none()
            {
                return Ok((
                    200,
                    json!({
                        "status": "existing",
                        "certificate": super::db::signed_certificate(certificate),
                        "certificate_digest": crate::json::digest(&super::db::signed_certificate(certificate)),
                    }),
                ));
            }
        }
    }
    let mut document = json!({
        "schema": crate::model::CERTIFICATE_SCHEMA,
        "repository_uuid": repository_uuid,
        "issued_at": now,
        "company_id": state.config.company_id
    });
    if let Some(parent) = request.get("lineage_parent_uuid") {
        document["lineage_parent_uuid"] = parent.clone();
    }
    let signed = state
        .root
        .sign_document("repo-certificate", &document)
        .map_err(|error| refuse(500, error))?;
    let event_id = format!("certificate_{repository_uuid}");
    let cursor = db
        .append_event(
            &event_id,
            "repo-certificate",
            "certificate",
            &signed,
            &state.root.public().to_hex(),
            "verified",
            None,
        )
        .map_err(|error| refuse(500, error))?
        .unwrap_or(trust_state.cursor);
    db.upsert_certificate(&signed, hint.as_deref(), cursor)
        .map_err(|error| refuse(500, error))?;
    Ok((
        201,
        json!({"status": "issued", "certificate": signed, "certificate_digest": crate::json::digest(&signed), "cursor": cursor.to_string()}),
    ))
}

fn post_manifest(
    db: &CompanyDb,
    _auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    now: &str,
) -> Handled {
    // Ruling C6: no token scope is demanded, but the manifest signer itself
    // must be the active registered maintainer for codebase:<repository_uuid>.
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant("a manifest document is required"),
        )
    })?;
    if crate::json::get_str(&document, "schema") != Some(crate::model::MANIFEST_SCHEMA) {
        return Err(refuse(
            400,
            ContractError::invariant("manifest schema must be kinbase-manifest/1"),
        ));
    }
    let key = PublicKey::verify_document("manifest", &document).ok_or_else(|| {
        refuse(
            400,
            ContractError::integrity(
                "SIGNATURE_INVALID",
                "manifest signature failed",
                "Sign the manifest with the registered maintainer key.",
            ),
        )
    })?;
    let repository_uuid = crate::json::get_str(&document, "repository_uuid")
        .unwrap_or_default()
        .to_owned();
    let maintainer_scope = format!("codebase:{repository_uuid}");
    let registered_maintainer = trust_state.registry.iter().any(|entry| {
        crate::json::get_str(entry, "scope") == Some(maintainer_scope.as_str())
            && crate::json::get_str(entry, "public_key") == Some(key.to_hex().as_str())
            && crate::json::get_str(entry, "status") == Some("active")
    });
    if !registered_maintainer {
        return Err(refuse(
            403,
            ContractError::refused(
                "AUTHORITY_WRONG_SCOPE",
                "manifest signer is not the registered maintainer for this codebase",
                "Register the exact maintainer key with scope codebase:<uuid>.",
            ),
        ));
    }
    let branch = crate::json::get_str(&document, "branch")
        .unwrap_or("main")
        .to_owned();
    let count = crate::json::get_u64(&document, "event_count").unwrap_or(0) as i64;
    let revision = crate::json::get_str(&document, "observed_default_branch_revision")
        .unwrap_or_default()
        .to_owned();
    let rollback =
        document.get("rollback_event").is_some() || document.get("rewrite_event").is_some();
    let digest = crate::json::digest(&document);
    let transaction: Result<(u16, Value), (u16, ContractError)> = (|| {
        db.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| {
                refuse(
                    500,
                    ContractError::internal(format!("begin manifest admission: {error}")),
                )
            })?;
        let latest = db
            .latest_manifest_observation(&repository_uuid, &branch)
            .map_err(|error| refuse(500, error))?;
        if let Some(latest) = &latest {
            if latest
                .get("observed_default_branch_revision")
                .and_then(Value::as_str)
                == Some(revision.as_str())
            {
                return Ok((
                    200,
                    json!({
                        "status": "existing",
                        "observation_id": latest.get("observation_id").cloned().unwrap_or(Value::Null),
                        "manifest_digest": latest.get("manifest_digest").cloned().unwrap_or(Value::Null),
                        "recorded_at": latest.get("observed_at").cloned().unwrap_or(Value::Null)
                    }),
                ));
            }
            let prior = latest
                .get("event_count")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            if count < prior
                && !rollback
                && crate::json::get_str(latest, "status") == Some("current")
            {
                return Err(refuse(
                    409,
                    ContractError::refused(
                        "MANIFEST_HEAD_REGRESSION",
                        format!(
                            "published reachable lineage lowers the event count from {prior} to {count} without a signed rewrite event"
                        ),
                        "Supply a maintainer-signed rollback/rewrite event (atom_kind rollback_exception) or correct the publication.",
                    ),
                ));
            }
        }
        let cursor = db
            .append_event(
                &format!("manifest_{digest}"),
                "manifest",
                "manifest-observation",
                &document,
                &key.to_hex(),
                "verified",
                None,
            )
            .map_err(|error| refuse(500, error))?
            .unwrap_or(trust_state.cursor);
        let id = db
            .insert_manifest_observation(&document, cursor)
            .map_err(|error| refuse(500, error))?;
        db.audit("manifest-recorded", &json!({"digest": digest, "repository_uuid": repository_uuid, "branch": branch, "revision": revision}))
            .map_err(|error| refuse(500, error))?;
        Ok((
            201,
            json!({"status": "recorded", "observation_id": id, "manifest_digest": digest, "cursor": cursor.to_string(), "recorded_at": now}),
        ))
    })();
    let result = match transaction {
        Ok(result) => match db.connection.execute_batch("COMMIT") {
            Ok(()) => Ok(result),
            Err(error) => {
                let _ = db.connection.execute_batch("ROLLBACK");
                Err(refuse(
                    500,
                    ContractError::internal(format!("commit manifest admission: {error}")),
                ))
            }
        },
        Err(error) => {
            let _ = db.connection.execute_batch("ROLLBACK");
            Err(error)
        }
    };
    result
}
fn steward_event(
    db: &CompanyDb,
    auth: &AuthContext,
    trust_state: &TrustState,
    body: Option<Value>,
    message_type: &str,
    kind: &str,
    now: &str,
) -> Handled {
    require_scope(auth, "admin:issue")?;
    let document = body.ok_or_else(|| {
        refuse(
            400,
            ContractError::invariant(format!("a {kind} document is required")),
        )
    })?;
    trust::verify_steward_document(trust_state, message_type, &document)
        .map_err(|error| refuse(403, error))?;
    let digest = crate::json::digest(&document);
    let event_id = format!("{kind}_{}", &digest[..40]);
    with_immediate_transaction(db, || {
        let cursor = db
            .append_event(
                &event_id,
                message_type,
                kind,
                &document,
                crate::json::get_str(&document, "signer").unwrap_or_default(),
                "verified",
                None,
            )
            .map_err(|error| refuse(500, error))?
            .unwrap_or(trust_state.cursor);
        if kind == "revocation" {
            let revoked = crate::json::get_str(&document, "revoked_key").unwrap_or_default();
            revocation_cascade(db, revoked, None, cursor, &cursor.to_string(), now, &digest)?;
        }
        Ok((
            201,
            json!({"status": "recorded", "kind": kind, "cursor": cursor.to_string(), "digest": digest}),
        ))
    })
}

/// Compromise response (architecture §3): advance the revocation cursor,
/// enumerate the facts the revoked key warranted, emit destination-owned
/// apology Unknowns, and record the immutable unreachable-clone residual.
fn revocation_cascade(
    db: &CompanyDb,
    revoked: &str,
    scope: Option<&str>,
    cursor: i64,
    authority_cursor: &str,
    now: &str,
    digest: &str,
) -> Result<(), (u16, ContractError)> {
    db.set_meta("revocation_cursor", &cursor.to_string())
        .map_err(|error| refuse(500, error))?;
    let mut affected = 0usize;
    for (_, payload, verification) in db
        .events_of_kind("fact-event")
        .map_err(|error| refuse(500, error))?
    {
        if verification == "verified"
            && crate::json::get_str(&payload, "signer") == Some(revoked)
            && scope.is_none_or(|scope| {
                crate::json::get_str(&payload, "authority_scope") == Some(scope)
            })
        {
            affected += 1;
            let fact_id = crate::json::get_str(&payload, "fact_id").unwrap_or_default();
            let unknown = json!({
                "unknown_id": format!("unknown_apology_{}", &crate::hash::sha256_text(&format!("{revoked}\0{fact_id}"))[..24]),
                "scope": crate::json::get_str(&payload, "authority_scope").unwrap_or_default(),
                "owner_identity": "company-steward",
                "owner_role": "company-steward",
                "status": "open",
                "question": format!("Fact {fact_id} was warranted by a key revoked at authority cursor {authority_cursor}; does an independently admissible support still establish it?"),
                "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
                "affected_fact_id": fact_id,
                "kind": "apology"
            });
            db.upsert_unknown(&unknown, "apology")
                .map_err(|error| refuse(500, error))?;
        }
    }
    let mut residual = json!({
        "schema": "kinbase-unreachable-clone-residual/1",
        "revoked_key": revoked,
        "cursor": cursor.to_string(),
        "authority_cursor": authority_cursor,
        "affected_fact_count": affected,
        "max_offline_revocation_freshness_seconds": 900,
        "statement": "unknown clones may keep projecting until they sync or their revocation freshness window expires"
    });
    let residual_key = match scope {
        Some(scope) => {
            residual["revoked_scope"] = Value::String(scope.to_owned());
            format!("{revoked}\0{scope}\0{digest}")
        }
        None => format!("{revoked}\0{digest}"),
    };
    db.append_event(
        &format!(
            "residual_{}",
            &crate::hash::sha256_text(&residual_key)[..32]
        ),
        "revocation",
        "unreachable_clone_residual",
        &residual,
        "company-service",
        "verified",
        None,
    )
    .map_err(|error| refuse(500, error))?;
    Ok(())
}

fn issue_token(db: &CompanyDb, auth: &AuthContext, body: Option<Value>, now: &str) -> Handled {
    require_scope(auth, "admin:issue")?;
    let request =
        body.ok_or_else(|| refuse(400, ContractError::invariant("a token request is required")))?;
    let scopes: Vec<String> = crate::json::get_array(&request, "scopes")
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let authority_scopes: Vec<String> = crate::json::get_array(&request, "authority_scopes")
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if scopes
        .iter()
        .chain(authority_scopes.iter())
        .any(|scope| scope.is_empty() || scope.contains('*') || scope.contains('%'))
    {
        return Err(refuse(
            400,
            ContractError::invariant(
                "scopes are exact strings; wildcard and empty entries are refused",
            ),
        ));
    }
    if scopes.iter().any(|scope| scope == "admin:issue") && authority_scopes.iter().any(|_| true) {
        return Err(refuse(
            400,
            ContractError::invariant("administrative issuance cannot carry fact body read scopes"),
        ));
    }
    let token = format!("facts-{}", &crate::crypto::random_token()[..40]);
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    db.register_token(
        &token,
        "issued",
        &scope_refs,
        &authority_scopes,
        crate::json::get_str(&request, "principal_id").unwrap_or("issued-principal"),
    )
    .map_err(|error| refuse(500, error))?;
    Ok((
        201,
        json!({"status": "issued", "token": token, "scopes": scopes, "authority_scopes": authority_scopes, "issued_at": now}),
    ))
}

/// Periodic obligations executed on request arrival: manifest observation
/// expiry, orphan deadlines, nonce pruning.
fn maintenance(db: &CompanyDb, state: &ServiceState, now: &str) -> Result<(), ContractError> {
    db.prune_nonces(now)?;
    for expired in db.expire_manifest_observations(now)? {
        let repository = crate::json::get_str(&expired, "repository_uuid").unwrap_or_default();
        let event = json!({
            "schema": crate::model::EVENT_SCHEMA,
            "event_id": format!("evt_obsexp_{}", &crate::hash::sha256_text(&format!("{repository}\0{}", expired.get("observation_id").and_then(Value::as_i64).unwrap_or(0)))[..24]),
            "store_kind": "company",
            "authority_id": "company-service",
            "authority_scope": "company:root",
            "fact_id": format!("fact_obsexp_{}", &crate::hash::sha256_text(repository)[..24]),
            "logical_key": format!("manifest-observation:{repository}"),
            "atom_kind": "observation_expired",
            "scope": "company:root",
            "statement": format!("The maintainer-published manifest observation for repository {repository} lapsed at {} without replacement; it is retired to historical-only status.", crate::json::get_str(&expired, "fresh_until").unwrap_or_default()),
            "evidence_refs": [format!("manifest-observation:{}", expired.get("observation_id").and_then(Value::as_i64).unwrap_or(0))],
            "asserted_at": now,
            "effective_from": now,
            "disposition": "manifest_observation_expired",
            "distortion": {"trigger": "codebase completeness check", "loss_if_absent": 7000, "rationale": "an expired publication cannot accuse a clone"},
            "parents": [],
            "supersedes": [],
            "redundancy_with": [],
            "complements": [],
            "company_refs": [],
            "authority_snapshot_cursor": db.cursor()?.to_string(),
            "confidence": 10000,
            "unresolved_uncertainty": null,
            "observation_status": "historical-only"
        });
        let signed = state.root.sign_document("fact-event", &event)?;
        db.append_event(
            crate::json::get_str(&signed, "event_id").unwrap_or_default(),
            "fact-event",
            "fact-event",
            &signed,
            &state.root.public().to_hex(),
            "verified",
            None,
        )?;
        let unknown = json!({
            "unknown_id": format!("unknown_publication_{}", &crate::hash::sha256_text(repository)[..24]),
            "scope": "company:root",
            "owner_identity": "company-steward",
            "owner_role": "company-steward",
            "status": "open",
            "question": format!("The manifest publication pipeline for repository {repository} lapsed; republish or retire the repository."),
            "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
            "kind": "publication"
        });
        db.upsert_unknown(&unknown, "publication")?;
    }
    // Orphan deadlines: apology Unknowns past response_due_at become orphan_abandoned.
    for unknown in db.unknowns(Some("open"))? {
        if crate::json::get_str(&unknown, "kind") != Some("apology")
            && crate::json::get_str(&unknown, "kind") != Some("orphan")
        {
            continue;
        }
        let due = crate::json::get_str(&unknown, "response_due_at").unwrap_or_default();
        if due.is_empty() || due > now {
            continue;
        }
        let unknown_id = crate::json::get_str(&unknown, "unknown_id")
            .unwrap_or_default()
            .to_owned();
        let closing = crate::json::get_str(&unknown, "owner_identity")
            .unwrap_or("company-steward")
            .to_owned();
        let event = json!({
            "schema": crate::model::EVENT_SCHEMA,
            "event_id": format!("evt_orphan_{}", &crate::hash::sha256_text(&unknown_id)[..24]),
            "store_kind": "company",
            "authority_id": "company-service",
            "authority_scope": crate::json::get_str(&unknown, "scope").unwrap_or("company:root"),
            "fact_id": format!("fact_orphan_{}", &crate::hash::sha256_text(&unknown_id)[..24]),
            "logical_key": format!("orphan:{unknown_id}"),
            "atom_kind": "orphan_abandoned",
            "scope": crate::json::get_str(&unknown, "scope").unwrap_or("company:root"),
            "statement": format!("Closing authority {closing} did not act on {unknown_id} by {due}; the orphaned claim stays withdrawn and this saga is terminally closed."),
            "evidence_refs": [unknown_id.clone()],
            "asserted_at": now,
            "effective_from": now,
            "disposition": "orphan_abandoned",
            "distortion": {"trigger": "fan-out divergence", "loss_if_absent": 8000, "rationale": "an orphan cannot remain ownerless forever"},
            "parents": [unknown_id.clone()],
            "supersedes": [],
            "redundancy_with": [],
            "complements": [],
            "company_refs": [],
            "authority_snapshot_cursor": db.cursor()?.to_string(),
            "confidence": 10000,
            "unresolved_uncertainty": null,
            "unresponsive_closing_authority": closing
        });
        let signed = state.root.sign_document("fact-event", &event)?;
        db.append_event(
            crate::json::get_str(&signed, "event_id").unwrap_or_default(),
            "fact-event",
            "fact-event",
            &signed,
            &state.root.public().to_hex(),
            "verified",
            None,
        )?;
        let mut closed = unknown.clone();
        closed["status"] = Value::String("abandoned".to_owned());
        db.upsert_unknown(
            &closed,
            crate::json::get_str(&unknown, "kind").unwrap_or("apology"),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod packet03_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn admits_a_registered_architect_fact_event_and_publishes_semantic_digests() {
        let temp = tempfile::tempdir().unwrap();
        let root_key = PrivateKey::generate();
        let architect_key = PrivateKey::generate();
        let token = "facts-packet03";
        let root_path = temp.path().join("company-root.key");
        let token_path = temp.path().join("facts.token");
        let config_path = temp.path().join("kinbased.toml");
        root_key.save_new(&root_path, "Company root key").unwrap();
        crate::crypto::write_0600(&token_path, token.as_bytes(), "facts token").unwrap();
        let config = format!(
            r#"schema_version = "1"
company_id = "company-demo"
sqlite_path = "{db}"
bind = "127.0.0.1:0"
root_key_file = "{root_key}"
facts_token_file = "{token}"
auth_failures_per_minute = 100
default_fact_freshness_seconds = 900
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 1300
"#,
            db = temp.path().join("company.sqlite").display(),
            root_key = root_path.display(),
            token = token_path.display(),
        );
        crate::crypto::write_0600(&config_path, config.as_bytes(), "service config").unwrap();
        let config = crate::config::load_service_config(&config_path).unwrap();
        let db = CompanyDb::open(&config.sqlite_path).unwrap();
        db.set_meta("company_id", &config.company_id).unwrap();
        register_tokens(&db, &config).unwrap();
        let auth = AuthContext {
            token: db.token(token).unwrap().unwrap(),
            client_key: "aa".repeat(32),
            principal_key: "packet03-principal".to_owned(),
        };
        let state = ServiceState {
            config,
            root: root_key.clone(),
            started_at: crate::time::now_rfc3339_millis(),
        };
        let now = crate::time::now_rfc3339_millis();
        let trust = trust::load(&db, &root_key.public()).unwrap();
        let registry = root_key
            .sign_document(
                "authority-registry-entry",
                &json!({
                    "schema": crate::model::REGISTRY_SCHEMA,
                    "authority_cursor": "1000",
                    "entries": [
                        {
                            "authority_id": "company-steward",
                            "scope": "company:root",
                            "public_key": root_key.public().to_hex(),
                            "channel": "company:root",
                            "capabilities": ["publish"]
                        },
                        {
                            "authority_id": "chief-architect-1",
                            "scope": "architecture:scheduling",
                            "public_key": architect_key.public().to_hex(),
                            "channel": "process:architecture-answer",
                            "capabilities": ["answer", "supersede"]
                        }
                    ]
                }),
            )
            .unwrap();
        assert_eq!(
            publish_registry(&db, &auth, &trust, Some(registry), &now)
                .unwrap()
                .0,
            201
        );
        let trust = trust::load(&db, &root_key.public()).unwrap();

        let fact = architect_key
            .sign_document(
                "fact-event",
                &json!({
                    "schema": crate::model::EVENT_SCHEMA,
                    "event_id": "evt_000000000001",
                    "store_kind": "company",
                    "authority_id": "chief-architect-1",
                    "authority_scope": "architecture:scheduling",
                    "fact_id": "fact_000000000001",
                    "logical_key": "architecture:scheduling",
                    "atom_kind": "constraint",
                    "scope": "architecture:scheduling",
                    "statement": "The scheduler must bound queue wait time.",
                    "evidence_refs": [],
                    "asserted_at": "2025-01-01T00:00:00.000Z",
                    "effective_from": "2025-01-01T00:00:00.000Z",
                    "disposition": "accepted",
                    "distortion": {
                        "trigger": "deadline",
                        "loss_if_absent": "safety_critical",
                        "rationale": "A missed deadline can strand dependent work."
                    },
                    "parents": [],
                    "supersedes": [],
                    "redundancy_with": [],
                    "complements": [],
                    "company_refs": [],
                    "authority_snapshot_cursor": "1000",
                    "confidence": "high",
                    "unresolved_uncertainty": ""
                }),
            )
            .unwrap();
        let request = Request {
            method: "POST".to_owned(),
            path: "/facts".to_owned(),
            route: "/facts".to_owned(),
            query: BTreeMap::new(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: None,
        };
        let (status, receipt) = admit_fact(&db, &state, &auth, &trust, Some(fact), &now).unwrap();
        assert_eq!(status, 201);
        assert_eq!(receipt["status"], "committed");
        assert_eq!(
            receipt["semantic_digest"],
            crate::model::semantic_digest("The scheduler must bound queue wait time.")
        );
        assert_eq!(
            receipt["digest_alg_version"],
            crate::model::DIGEST_ALG_VERSION
        );

        let (_, listed) = facts(&db, &state, &auth, &trust, &request, &now).unwrap();
        let item = listed["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item.get("fact_id").and_then(Value::as_str) == Some("fact_000000000001"))
            .cloned()
            .unwrap();
        assert_eq!(item["semantic_digest"], receipt["semantic_digest"]);
        assert_eq!(item["digest_alg_version"], crate::model::DIGEST_ALG_VERSION);
    }

    #[test]
    fn pre_revocation_replay_projection_withdraws_only_a_sole_support() {
        let temp = tempfile::tempdir().unwrap();
        let root_key = PrivateKey::generate();
        let architect_key = PrivateKey::generate();
        let db = CompanyDb::open(&temp.path().join("company.sqlite")).unwrap();
        let now = crate::time::now_rfc3339_millis();

        let fact_document = architect_key
            .sign_document(
                "fact-event",
                &json!({
                    "schema": crate::model::EVENT_SCHEMA,
                    "event_id": "evt_packet10_replay",
                    "store_kind": "company",
                    "authority_id": "chief-architect-1",
                    "authority_scope": "architecture:scheduling",
                    "fact_id": "fact_packet10_replay",
                    "logical_key": "architecture:scheduling",
                    "atom_kind": "constraint",
                    "scope": "architecture:scheduling",
                    "statement": "The scheduler must bound queue wait time.",
                    "evidence_refs": [],
                    "asserted_at": now,
                    "effective_from": now,
                    "disposition": "accepted",
                    "distortion": {"trigger": "deadline", "loss_if_absent": 8000, "rationale": "test"},
                    "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
                    "company_refs": [], "authority_snapshot_cursor": "0", "confidence": 8000,
                    "unresolved_uncertainty": null
                }),
            )
            .unwrap();
        let event = FactEvent::parse(&crate::json::canonical_bytes(&fact_document)).unwrap();
        db.append_event(
            &event.event_id,
            "fact-event",
            "fact-event",
            &fact_document,
            &event.signer,
            "verified",
            None,
        )
        .unwrap();
        let trust = trust::load(&db, &root_key.public()).unwrap();
        assert_eq!(replay_projection(&db, &trust, &event), (false, false));

        let revocation = root_key
            .sign_document(
                "revocation",
                &json!({"revoked_key": architect_key.public().to_hex(), "effective_at": now}),
            )
            .unwrap();
        db.append_event(
            "rev_packet10_replay",
            "revocation",
            "revocation",
            &revocation,
            &root_key.public().to_hex(),
            "verified",
            None,
        )
        .unwrap();
        let trust = trust::load(&db, &root_key.public()).unwrap();
        assert_eq!(replay_projection(&db, &trust, &event), (true, true));

        let second_document = root_key
            .sign_document(
                "fact-event",
                &json!({
                    "schema": crate::model::EVENT_SCHEMA,
                    "event_id": "evt_packet10_second",
                    "store_kind": "company",
                    "authority_id": "company-steward",
                    "authority_scope": "architecture:scheduling",
                    "fact_id": "fact_packet10_second",
                    "logical_key": "architecture:scheduling",
                    "atom_kind": "constraint",
                    "scope": "architecture:scheduling",
                    "statement": "A second independent scheduler bound remains current.",
                    "evidence_refs": [], "asserted_at": now, "effective_from": now,
                    "disposition": "accepted",
                    "distortion": {"trigger": "deadline", "loss_if_absent": 8000, "rationale": "test"},
                    "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
                    "company_refs": [], "authority_snapshot_cursor": "0", "confidence": 8000,
                    "unresolved_uncertainty": null
                }),
            )
            .unwrap();
        db.append_event(
            "evt_packet10_second",
            "fact-event",
            "fact-event",
            &second_document,
            &root_key.public().to_hex(),
            "verified",
            None,
        )
        .unwrap();
        assert_eq!(replay_projection(&db, &trust, &event), (true, false));
    }
}

#[cfg(test)]
mod packet11_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn signed_request(
        key: &PrivateKey,
        nonce: &str,
        expires_at: &str,
        signature: Option<&str>,
    ) -> Request {
        let body = Vec::new();
        let signed = json!({
            "method": "GET",
            "path": "/status",
            "body_sha256": crate::hash::sha256_bytes(&body),
            "nonce": nonce,
            "expires_at": expires_at
        });
        let signature = signature.map(str::to_owned).unwrap_or_else(|| {
            key.sign("receipt", &crate::json::canonical_bytes(&signed))
                .unwrap()
        });
        Request {
            method: "GET".to_owned(),
            path: "/status".to_owned(),
            route: "/status".to_owned(),
            query: BTreeMap::new(),
            headers: vec![
                (
                    "authorization".to_owned(),
                    "Bearer facts-packet11".to_owned(),
                ),
                ("x-kinbase-nonce".to_owned(), nonce.to_owned()),
                ("x-kinbase-expires-at".to_owned(), expires_at.to_owned()),
                ("x-kinbase-client-key".to_owned(), key.public().to_hex()),
                ("x-kinbase-signature".to_owned(), signature),
            ],
            body,
            peer: None,
        }
    }

    #[test]
    fn r17_allows_two_client_keys_for_one_token_and_throttles_bad_signatures() {
        let temp = tempfile::tempdir().unwrap();
        let root_key = PrivateKey::generate();
        let first = PrivateKey::generate();
        let second = PrivateKey::generate();
        let token_path = temp.path().join("facts.token");
        crate::crypto::write_0600(&token_path, b"facts-packet11", "facts token").unwrap();
        let config = ServiceConfig {
            allow_non_loopback: false,
            path: temp.path().join("kinbased.toml"),
            company_id: "packet11".to_owned(),
            sqlite_path: temp.path().join("company.sqlite"),
            bind: "127.0.0.1:0".parse().unwrap(),
            root_key_file: temp.path().join("root.key"),
            facts_token_file: token_path,
            directory_token_file: None,
            admin_token_file: None,
            authority_token_file: None,
            auth_failures_per_minute: 10,
            default_fact_freshness_seconds: 900,
            candidate_lifetime_seconds: 900,
            clock_skew_seconds: 300,
            nonce_retention_seconds: 1300,
            read_volume_per_hour: 2_000,
            read_bytes_per_hour: 64 * 1024 * 1024,
            requests_per_minute: 600,
            revocation_freshness_seconds: 900,
            directory_retention_seconds: 365 * 24 * 3600,
            facts_token_scopes: Vec::new(),
        };
        let db = CompanyDb::open(&config.sqlite_path).unwrap();
        register_tokens(&db, &config).unwrap();
        let state = ServiceState {
            config,
            root: root_key,
            started_at: crate::time::now_rfc3339_millis(),
        };
        let now = crate::time::now_rfc3339_millis();
        let expires_at = crate::time::plus_seconds(&now, 60).unwrap();
        let first_auth = authenticate(
            &db,
            &state,
            &signed_request(&first, "nonce-a", &expires_at, None),
            &now,
        )
        .unwrap();
        let second_auth = authenticate(
            &db,
            &state,
            &signed_request(&second, "nonce-b", &expires_at, None),
            &now,
        )
        .unwrap();
        assert_ne!(first_auth.client_key, second_auth.client_key);
        assert_ne!(first_auth.principal_key, second_auth.principal_key);
        assert_eq!(
            db.token_client_key_count(&first_auth.token.digest).unwrap(),
            2
        );

        for index in 0..10 {
            let nonce = format!("bad-{index}");
            let request = signed_request(&first, &nonce, &expires_at, Some(&"00".repeat(64)));
            let Err((status, _)) = authenticate(&db, &state, &request, &now) else {
                panic!("bad signature was accepted");
            };
            assert_eq!(status, 401);
        }
        let request = signed_request(&first, "bad-eleventh", &expires_at, Some(&"00".repeat(64)));
        let Err((status, error)) = authenticate(&db, &state, &request, &now) else {
            panic!("failure ceiling was not enforced");
        };
        assert_eq!(status, 429);
        assert_eq!(error.detail.as_ref().unwrap()["omitted_count"], 1);
    }
}

#[cfg(test)]
mod auth_subject_tests {
    use super::*;
    use crate::crypto::PrivateKey;

    fn service(temp: &std::path::Path) -> (CompanyDb, ServiceState) {
        let token_path = temp.join("facts.token");
        crate::crypto::write_0600(&token_path, b"facts-subject", "facts token").unwrap();
        let config = ServiceConfig {
            allow_non_loopback: false,
            path: temp.join("kinbased.toml"),
            company_id: "subject".to_owned(),
            sqlite_path: temp.join("company.sqlite"),
            bind: "127.0.0.1:0".parse().unwrap(),
            root_key_file: temp.join("root.key"),
            facts_token_file: token_path,
            directory_token_file: None,
            admin_token_file: None,
            authority_token_file: None,
            auth_failures_per_minute: 3,
            default_fact_freshness_seconds: 900,
            candidate_lifetime_seconds: 900,
            clock_skew_seconds: 300,
            nonce_retention_seconds: 1300,
            read_volume_per_hour: 2_000,
            read_bytes_per_hour: 64 * 1024 * 1024,
            requests_per_minute: 600,
            revocation_freshness_seconds: 900,
            directory_retention_seconds: 365 * 24 * 3600,
            facts_token_scopes: Vec::new(),
        };
        let db = CompanyDb::open(&config.sqlite_path).unwrap();
        register_tokens(&db, &config).unwrap();
        let state = ServiceState {
            config,
            root: PrivateKey::generate(),
            started_at: crate::time::now_rfc3339_millis(),
        };
        (db, state)
    }

    fn request(bearer: &str, key: &PrivateKey, nonce: &str, expires_at: &str) -> Request {
        let signed = json!({
            "method": "GET",
            "path": "/status",
            "body_sha256": crate::hash::sha256_bytes(b""),
            "nonce": nonce,
            "expires_at": expires_at
        });
        let signature = key
            .sign("receipt", &crate::json::canonical_bytes(&signed))
            .unwrap();
        Request {
            method: "GET".to_owned(),
            path: "/status".to_owned(),
            route: "/status".to_owned(),
            query: BTreeMap::new(),
            headers: vec![
                ("authorization".to_owned(), format!("Bearer {bearer}")),
                ("x-kinbase-nonce".to_owned(), nonce.to_owned()),
                ("x-kinbase-expires-at".to_owned(), expires_at.to_owned()),
                ("x-kinbase-client-key".to_owned(), key.public().to_hex()),
                ("x-kinbase-signature".to_owned(), signature),
            ],
            body: Vec::new(),
            peer: None,
        }
    }

    #[test]
    fn failures_without_a_token_never_lock_out_a_valid_one() {
        let temp = tempfile::tempdir().unwrap();
        let (db, state) = service(temp.path());
        let key = PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let expires_at = crate::time::plus_seconds(&now, 60).unwrap();
        for index in 0..5 {
            let flood = request("guess", &key, &format!("flood-{index}"), &expires_at);
            let Err((status, _)) = authenticate(&db, &state, &flood, &now) else {
                panic!("a guessed token was accepted");
            };
            assert_eq!(status, if index < 3 { 401 } else { 429 });
        }
        let valid = request("facts-subject", &key, "valid", &expires_at);
        assert!(authenticate(&db, &state, &valid, &now).is_ok());
    }

    #[test]
    fn the_facts_token_cannot_post_an_answer() {
        let temp = tempfile::tempdir().unwrap();
        let (db, state) = service(temp.path());
        let key = PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let expires_at = crate::time::plus_seconds(&now, 60).unwrap();
        let auth = authenticate(&db, &state, &request("facts-subject", &key, "n", &expires_at), &now)
            .expect("facts token");
        assert!(auth.token.has_scope("questions:write"));
        let trust_state = trust::load(&db, &state.root.public()).unwrap();
        let Err((status, _)) = post_answer(
            &db,
            &state,
            &auth,
            &trust_state,
            Some(json!({"question_id": "q-1", "answer": "yes"})),
            &now,
        ) else {
            panic!("the facts token posted an answer");
        };
        assert_eq!(status, 403);
    }
}

#[cfg(test)]
mod scope_and_token_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    struct Service {
        temp: tempfile::TempDir,
        db: CompanyDb,
        state: ServiceState,
        root: PrivateKey,
        config_path: std::path::PathBuf,
    }

    fn write_config(temp: &std::path::Path, extra: &str) -> std::path::PathBuf {
        let config_path = temp.join("kinbased.toml");
        let config = format!(
            r#"schema_version = "1"
company_id = "company-demo"
sqlite_path = "{db}"
bind = "127.0.0.1:0"
root_key_file = "{root_key}"
facts_token_file = "{token}"
auth_failures_per_minute = 100
default_fact_freshness_seconds = 900
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 1300
{extra}
"#,
            db = temp.join("company.sqlite").display(),
            root_key = temp.join("company-root.key").display(),
            token = temp.join("facts.token").display(),
        );
        let _ = std::fs::remove_file(&config_path);
        crate::crypto::write_0600(&config_path, config.as_bytes(), "service config").unwrap();
        config_path
    }

    fn service(extra: &str) -> Service {
        let temp = tempfile::tempdir().unwrap();
        let root = PrivateKey::generate();
        root.save_new(&temp.path().join("company-root.key"), "Company root key")
            .unwrap();
        crate::crypto::write_0600(
            &temp.path().join("facts.token"),
            b"facts-one",
            "facts token",
        )
        .unwrap();
        let config_path = write_config(temp.path(), extra);
        let config = crate::config::load_service_config(&config_path).unwrap();
        let db = CompanyDb::open(&config.sqlite_path).unwrap();
        db.set_meta("company_id", &config.company_id).unwrap();
        register_tokens(&db, &config).unwrap();
        let state = ServiceState {
            config,
            root: root.clone(),
            started_at: crate::time::now_rfc3339_millis(),
        };
        Service {
            temp,
            db,
            state,
            root,
            config_path,
        }
    }

    fn auth(service: &Service, token: &str) -> AuthContext {
        AuthContext {
            token: service.db.token(token).unwrap().unwrap(),
            client_key: "cc".repeat(32),
            principal_key: "scope-principal".to_owned(),
        }
    }

    #[test]
    fn a_rotated_token_file_retires_the_previous_token() {
        let service = service("");
        assert!(service.db.token("facts-one").unwrap().is_some());
        let token_path = service.temp.path().join("facts.token");
        std::fs::remove_file(&token_path).unwrap();
        crate::crypto::write_0600(&token_path, b"facts-two", "facts token").unwrap();
        let summary = register_tokens(&service.db, &service.state.config).unwrap();
        assert!(
            service.db.token("facts-one").unwrap().is_none(),
            "old token still valid"
        );
        assert!(service.db.token("facts-two").unwrap().is_some());
        assert_eq!(summary["retired_token_count"], 1);
    }

    #[test]
    fn a_role_whose_file_is_removed_keeps_no_token() {
        let service = service("");
        let admin_path = service.temp.path().join("admin.token");
        crate::crypto::write_0600(&admin_path, b"admin-one", "administrative token").unwrap();
        let config_path = write_config(
            service.temp.path(),
            &format!("admin_token_file = \"{}\"", admin_path.display()),
        );
        let with_admin = crate::config::load_service_config(&config_path).unwrap();
        register_tokens(&service.db, &with_admin).unwrap();
        assert!(service.db.token("admin-one").unwrap().is_some());
        register_tokens(&service.db, &service.state.config).unwrap();
        assert!(service.db.token("admin-one").unwrap().is_none());
        assert_eq!(config_path, service.config_path);
    }

    fn fact(key: &PrivateKey, id: &str, authority: &str, scope: &str, statement: &str) -> Value {
        key.sign_document(
            "fact-event",
            &json!({
                "schema": crate::model::EVENT_SCHEMA,
                "event_id": format!("evt_{id}"),
                "store_kind": "company",
                "authority_id": authority,
                "authority_scope": scope,
                "fact_id": format!("fact_{id}"),
                "logical_key": scope,
                "atom_kind": "constraint",
                "scope": scope,
                "statement": statement,
                "evidence_refs": [],
                "asserted_at": "2025-01-01T00:00:00.000Z",
                "effective_from": "2025-01-01T00:00:00.000Z",
                "disposition": "accepted",
                "distortion": {"trigger": "deadline", "loss_if_absent": "safety_critical", "rationale": "test"},
                "parents": [], "supersedes": [], "redundancy_with": [], "complements": [],
                "company_refs": [], "authority_snapshot_cursor": "1000",
                "confidence": "high", "unresolved_uncertainty": ""
            }),
        )
        .unwrap()
    }

    #[test]
    fn a_token_sees_only_what_its_scopes_allow() {
        let service = service("facts_token_scopes = [\"architecture:scheduling\"]");
        let steward = auth(&service, "facts-one");
        let scheduling = PrivateKey::generate();
        let payments = PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let registry = service
            .root
            .sign_document(
                "authority-registry-entry",
                &json!({
                    "schema": crate::model::REGISTRY_SCHEMA,
                    "authority_cursor": "1000",
                    "entries": [
                        {"authority_id": "scheduling-architect", "scope": "architecture:scheduling",
                         "public_key": scheduling.public().to_hex(), "channel": "process:architecture-answer",
                         "capabilities": ["answer"]},
                        {"authority_id": "payments-architect", "scope": "architecture:payments",
                         "public_key": payments.public().to_hex(), "channel": "process:architecture-answer",
                         "capabilities": ["answer"]}
                    ]
                }),
            )
            .unwrap();
        publish_registry(&service.db, &steward, &trust, Some(registry), &now).unwrap();
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        for document in [
            fact(
                &scheduling,
                "sched",
                "scheduling-architect",
                "architecture:scheduling",
                "The scheduler bounds queue wait time.",
            ),
            fact(
                &payments,
                "pay",
                "payments-architect",
                "architecture:payments",
                "Refunds settle within three days.",
            ),
        ] {
            let event = FactEvent::parse(&crate::json::canonical_bytes(&document)).unwrap();
            service
                .db
                .append_event(
                    &event.event_id,
                    "fact-event",
                    "fact-event",
                    &document,
                    &event.signer,
                    "verified",
                    None,
                )
                .unwrap();
        }
        let reader = auth(&service, "facts-one");
        let mut query = BTreeMap::new();
        query.insert("nonce".to_owned(), "nonce-scope-test".to_owned());
        let request = Request {
            method: "GET".to_owned(),
            path: "/snapshot".to_owned(),
            route: "/snapshot".to_owned(),
            query,
            headers: Vec::new(),
            body: Vec::new(),
            peer: None,
        };
        let (_, snapshot) =
            super::snapshot(&service.db, &service.state, &reader, &trust, &request, &now).unwrap();
        let text = snapshot.to_string();
        assert!(
            snapshot.get("denied").is_none(),
            "denied facts are not described"
        );
        assert_eq!(snapshot["denied_count"], 1);
        assert!(
            !text.contains("fact_pay"),
            "the unreadable fact id leaked: {text}"
        );
        assert!(
            !text.contains("architecture:payments\",\"state"),
            "a trace for the unreadable key leaked"
        );
        assert!(text.contains("fact_sched"));

        let (_, events) =
            super::events(&service.db, &service.state, &reader, &trust, &request).unwrap();
        let rows = events["events"].as_array().unwrap();
        let payments_row = rows
            .iter()
            .find(|row| row["event_id"] == "evt_pay")
            .unwrap();
        assert!(payments_row.get("payload").is_none());
        assert_eq!(payments_row["payload_withheld"], true);
        let scheduling_row = rows
            .iter()
            .find(|row| row["event_id"] == "evt_sched")
            .unwrap();
        assert!(scheduling_row.get("payload").is_some());
    }

    #[test]
    fn the_issuance_capability_reads_no_event_bodies() {
        let service = service("");
        let admin_path = service.temp.path().join("admin.token");
        crate::crypto::write_0600(&admin_path, b"admin-two", "administrative token").unwrap();
        let config_path = write_config(
            service.temp.path(),
            &format!("admin_token_file = \"{}\"", admin_path.display()),
        );
        let config = crate::config::load_service_config(&config_path).unwrap();
        register_tokens(&service.db, &config).unwrap();
        let key = PrivateKey::generate();
        let document = fact(
            &key,
            "body",
            "someone",
            "architecture:scheduling",
            "Secret body.",
        );
        let event = FactEvent::parse(&crate::json::canonical_bytes(&document)).unwrap();
        service
            .db
            .append_event(
                &event.event_id,
                "fact-event",
                "fact-event",
                &document,
                &event.signer,
                "verified",
                None,
            )
            .unwrap();
        let admin = auth(&service, "admin-two");
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let request = Request {
            method: "GET".to_owned(),
            path: "/events".to_owned(),
            route: "/events".to_owned(),
            query: BTreeMap::new(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: None,
        };
        let (_, events) =
            super::events(&service.db, &service.state, &admin, &trust, &request).unwrap();
        assert!(!events.to_string().contains("Secret body."));
        assert_eq!(events["events"][0]["payload_withheld"], true);
    }

    #[test]
    fn an_unreadable_token_file_changes_no_registration() {
        let service = service("");
        let admin_path = service.temp.path().join("admin.token");
        crate::crypto::write_0600(&admin_path, b"admin-one", "administrative token").unwrap();
        let config_path = write_config(
            service.temp.path(),
            &format!("admin_token_file = \"{}\"", admin_path.display()),
        );
        let with_admin = crate::config::load_service_config(&config_path).unwrap();
        register_tokens(&service.db, &with_admin).unwrap();

        let token_path = service.temp.path().join("facts.token");
        std::fs::remove_file(&token_path).unwrap();
        crate::crypto::write_0600(&token_path, b"facts-two", "facts token").unwrap();
        std::fs::remove_file(&admin_path).unwrap();
        assert!(register_tokens(&service.db, &with_admin).is_err());
        assert!(service.db.token("facts-one").unwrap().is_some());
        assert!(service.db.token("facts-two").unwrap().is_none());
        assert!(service.db.token("admin-one").unwrap().is_some());
    }

    fn append(service: &Service, document: &Value) {
        let event = FactEvent::parse(&crate::json::canonical_bytes(document)).unwrap();
        service
            .db
            .append_event(
                &event.event_id,
                "fact-event",
                "fact-event",
                document,
                &event.signer,
                "verified",
                None,
            )
            .unwrap();
    }

    fn get(path: &str, query: &[(&str, &str)]) -> Request {
        Request {
            method: "GET".to_owned(),
            path: path.to_owned(),
            route: path.to_owned(),
            query: query
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect(),
            headers: Vec::new(),
            body: Vec::new(),
            peer: None,
        }
    }

    #[test]
    fn event_reads_are_bounded_and_charged() {
        let service =
            service("facts_token_scopes = [\"architecture:scheduling\"]\nread_volume_per_hour = 3");
        let key = PrivateKey::generate();
        for n in 0..3 {
            append(
                &service,
                &fact(
                    &key,
                    &format!("n{n}"),
                    "scheduling-architect",
                    "architecture:scheduling",
                    &format!("Queue rule {n}."),
                ),
            );
        }
        let reader = auth(&service, "facts-one");
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let (_, events) = super::events(
            &service.db,
            &service.state,
            &reader,
            &trust,
            &get("/events", &[("limit", "-1")]),
        )
        .unwrap();
        assert_eq!(events["events"].as_array().unwrap().len(), 1);
        let (_, events) = super::events(
            &service.db,
            &service.state,
            &reader,
            &trust,
            &get("/events", &[("limit", "2")]),
        )
        .unwrap();
        assert_eq!(events["events"].as_array().unwrap().len(), 2);
        let (status, error) = super::events(
            &service.db,
            &service.state,
            &reader,
            &trust,
            &get("/events", &[("limit", "2")]),
        )
        .unwrap_err();
        assert_eq!(status, 429);
        assert_eq!(error.code, "LIMIT_EXCEEDED");
    }

    #[test]
    fn a_conflict_unknown_follows_its_authority_scope() {
        let service = service("facts_token_scopes = [\"architecture:scheduling\"]");
        let steward = auth(&service, "facts-one");
        let architect = PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let registry = service
            .root
            .sign_document(
                "authority-registry-entry",
                &json!({
                    "schema": crate::model::REGISTRY_SCHEMA,
                    "authority_cursor": "1000",
                    "entries": [
                        {"authority_id": "scheduling-architect", "scope": "architecture:scheduling",
                         "public_key": architect.public().to_hex(), "channel": "process:architecture-answer",
                         "capabilities": ["answer"]}
                    ]
                }),
            )
            .unwrap();
        publish_registry(&service.db, &steward, &trust, Some(registry), &now).unwrap();
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        // Two rulings on one key, about the repository rather than the
        // authority's own scope.
        for (id, statement) in [
            ("left", "Queue wait is bounded at five seconds."),
            ("right", "Queue wait is bounded at thirty seconds."),
        ] {
            let mut document = fact(
                &architect,
                id,
                "scheduling-architect",
                "architecture:scheduling",
                statement,
            );
            let map = document.as_object_mut().unwrap();
            map.insert("scope".to_owned(), json!("repository"));
            map.insert("logical_key".to_owned(), json!("scheduling/queue-wait"));
            let unsigned = Value::Object(map.clone());
            append(
                &service,
                &architect.sign_document("fact-event", &unsigned).unwrap(),
            );
        }
        let view = current_view(&service.db, &trust, &now).unwrap();
        let conflict = view
            .unknowns
            .iter()
            .find(|unknown| unknown.kind == "conflict")
            .expect("the reducer derives a conflict Unknown");
        assert_eq!(conflict.scope, "repository");
        assert_eq!(conflict.authority_scopes, ["architecture:scheduling"]);

        let reader = auth(&service, "facts-one");
        let request = get("/snapshot", &[("nonce", "nonce-conflict-test")]);
        let (_, snapshot) =
            super::snapshot(&service.db, &service.state, &reader, &trust, &request, &now).unwrap();
        let unknowns = snapshot["unknowns"].as_array().unwrap();
        assert!(
            unknowns.iter().any(|unknown| unknown["kind"] == "conflict"),
            "the conflict Unknown was dropped: {unknowns:?}"
        );
        assert!(
            unknowns
                .iter()
                .all(|unknown| unknown.get("authority_scopes").is_none())
        );
        assert!(
            snapshot.to_string().contains("scheduling/queue-wait"),
            "the conflict key's trace was dropped"
        );
    }

    #[test]
    fn an_approved_proposal_waits_for_a_steward_and_is_admitted_once_authorized() {
        let service = service("");
        let steward = auth(&service, "facts-one");
        let proposer = PrivateKey::generate();
        let now = crate::time::now_rfc3339_millis();
        let document = fact(
            &proposer,
            "proposal",
            "repository-maintainer",
            "company:root",
            "Refunds settle within two days.",
        );
        let submission =
            json!({"event": document, "approval_token": {"schema": "kinbase-approval/1"}});
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let (status, receipt) = admit_fact(
            &service.db,
            &service.state,
            &steward,
            &trust,
            Some(submission.clone()),
            &now,
        )
        .unwrap();
        assert_eq!(
            (status, receipt["status"].as_str()),
            (202, Some("pending-steward-review"))
        );
        let (_, replay) = admit_fact(
            &service.db,
            &service.state,
            &steward,
            &trust,
            Some(submission.clone()),
            &now,
        )
        .unwrap();
        assert_eq!(replay["status"], "pending-steward-review");

        // The steward authorizes the proposer for the scope.
        let registry = service
            .root
            .sign_document(
                "authority-registry-entry",
                &json!({
                    "schema": crate::model::REGISTRY_SCHEMA,
                    "authority_cursor": "1000",
                    "entries": [
                        {"authority_id": "repository-maintainer", "scope": "company:root",
                         "public_key": proposer.public().to_hex(), "channel": "process:architecture-answer",
                         "capabilities": ["answer"]}
                    ]
                }),
            )
            .unwrap();
        publish_registry(&service.db, &steward, &trust, Some(registry), &now).unwrap();
        let trust = trust::load(&service.db, &service.root.public()).unwrap();
        let (status, admitted) = admit_fact(
            &service.db,
            &service.state,
            &steward,
            &trust,
            Some(submission.clone()),
            &now,
        )
        .unwrap();
        assert_eq!(
            (status, admitted["status"].as_str()),
            (201, Some("committed")),
            "{admitted}"
        );
        let (_, historical) = admit_fact(
            &service.db,
            &service.state,
            &steward,
            &trust,
            Some(submission),
            &now,
        )
        .unwrap();
        assert_eq!(historical["status"], "committed");
        assert_eq!(historical["historical_receipt"], true);
    }
}
