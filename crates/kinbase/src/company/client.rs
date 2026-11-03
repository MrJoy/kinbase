//! Company client: signed, nonce-bearing loopback requests with the 250 ms
//! connection budget, typed `COMPANY_UNREACHABLE`, and helpers for every
//! endpoint the CLI uses.

use crate::config::{TokenRecord, UserConfig};
use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use crate::http::{self, Response};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A snapshot is a reduction over the whole Company event log, so it costs
/// what the log costs: 2.5 s against one deployment's 2,720 events and rising.
/// At 1,500 ms -- a bound sized for proof fixtures -- every repository in the
/// estate reported COMPANY_UNREACHABLE against a service that was answering
/// perfectly well, which reads as an outage rather than as the ceiling it is.
/// At ~12k facts a snapshot outgrew 20 s as well, so `[company]
/// snapshot_timeout_seconds` overrides this default for snapshot reads instead
/// of a rebuild.
pub const DEFAULT_READ_TIMEOUT_SECONDS: u64 = 20;

/// A root-verified answer to a snapshot refresh.
pub enum SnapshotRefresh {
    /// The whole snapshot, to store in place of the cached one.
    Snapshot(Value),
    /// A signed receipt that the offered content is still Company's answer.
    Unchanged(Value),
}

pub struct Client {
    pub scheme: http::Scheme,
    pub host: String,
    pub port: u16,
    pub base_path: String,
    pub token: TokenRecord,
    pub key: PrivateKey,
    pub root: Option<PublicKey>,
    pub cache_root: PathBuf,
    pub read_timeout: Duration,
    /// How long a snapshot read waits. Only snapshots cost what the whole log
    /// costs, so only they get a deployment's raised budget.
    pub snapshot_timeout: Duration,
    pub oidc: Option<crate::oidc::Config>,
    pub gateway_key: Option<String>,
    pub bytes_sent: std::cell::Cell<u64>,
}

impl Client {
    pub fn new(
        url: &str,
        token: TokenRecord,
        key: PrivateKey,
        root: Option<PublicKey>,
        cache_root: PathBuf,
        allow_non_loopback: bool,
    ) -> Result<Self, ContractError> {
        Self::from_user_config(url, token, key, root, cache_root, allow_non_loopback, None)
    }

    pub(crate) fn from_user_config(
        url: &str,
        token: TokenRecord,
        key: PrivateKey,
        root: Option<PublicKey>,
        cache_root: PathBuf,
        allow_non_loopback: bool,
        user: Option<&UserConfig>,
    ) -> Result<Self, ContractError> {
        let oidc = user.map(UserConfig::oidc).transpose()?.flatten();
        let gateway_key = user
            .and_then(|user| user.company.as_ref())
            .and_then(|company| company.gateway_api_key_file.as_deref())
            .map(|path| TokenRecord::load(path, "company gateway API key"))
            .transpose()?
            .map(|record| record.token);
        let (scheme, host, port, base_path) =
            http::parse_url(url, allow_non_loopback, oidc.is_some() || gateway_key.is_some())?;
        Ok(Self {
            scheme,
            host,
            port,
            base_path,
            token,
            key,
            root,
            cache_root,
            read_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECONDS),
            snapshot_timeout: Duration::from_secs(DEFAULT_READ_TIMEOUT_SECONDS),
            oidc,
            gateway_key,
            bytes_sent: std::cell::Cell::new(0),
        })
    }

    /// The configured snapshot budget, for clients built from a user config.
    /// Every other request keeps the default: the same client posts checkpoint
    /// facts and Unknowns from host hooks, and a hook pays its wait every turn.
    pub fn with_snapshot_timeout_seconds(mut self, seconds: u64) -> Self {
        self.snapshot_timeout = Duration::from_secs(seconds);
        self
    }

    fn nonce(&self) -> String {
        request_nonce()
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Response, ContractError> {
        self.request_within(method, path, body, self.read_timeout)
    }

    fn request_within(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        read_timeout: Duration,
    ) -> Result<Response, ContractError> {
        let id_token = self
            .oidc
            .as_ref()
            .map(crate::oidc::fresh_id_token)
            .transpose()
            .map_err(ContractError::with_oidc_token_failure)?;
        let full_path = format!("{}{}", self.base_path, path);
        let body_bytes = body.map(crate::json::canonical_bytes).unwrap_or_default();
        let nonce = self.nonce();
        let expires_at = crate::time::plus_seconds(&crate::time::now_rfc3339_millis(), 60)
            .map_err(ContractError::internal)?;
        let signed = json!({
            "method": method,
            "path": full_path,
            "body_sha256": crate::hash::sha256_bytes(&body_bytes),
            "nonce": nonce,
            "expires_at": expires_at
        });
        let signature = self
            .key
            .sign("receipt", &crate::json::canonical_bytes(&signed))?;
        let authorization = match (&self.gateway_key, id_token.as_deref()) {
            (Some(key), _) => format!("ApiKey {key}"),
            (None, Some(id_token)) => format!("Bearer {id_token}"),
            (None, None) => format!("Bearer {}", self.token.token),
        };
        let mut headers = vec![
            ("Authorization".to_owned(), authorization),
            ("X-Kinbase-Nonce".to_owned(), nonce),
            ("X-Kinbase-Expires-At".to_owned(), expires_at),
            (
                "X-Kinbase-Client-Key".to_owned(),
                self.key.public().to_hex(),
            ),
            ("X-Kinbase-Signature".to_owned(), signature),
        ];
        if self.oidc.is_some() || self.gateway_key.is_some() {
            headers.insert(1, ("X-Kinbase-Token".to_owned(), self.token.token.clone()));
        }
        self.bytes_sent
            .set(self.bytes_sent.get() + body_bytes.len() as u64 + 256);
        http::request(
            self.scheme,
            &self.host,
            self.port,
            method,
            &full_path,
            &headers,
            &body_bytes,
            read_timeout,
        )
    }

    pub fn get(&self, path: &str) -> Result<Response, ContractError> {
        self.request("GET", path, None)
    }

    pub fn post(&self, path: &str, body: &Value) -> Result<Response, ContractError> {
        self.request("POST", path, Some(body))
    }

    /// GET returning the typed error for non-2xx.
    pub fn get_ok(&self, path: &str) -> Result<Value, ContractError> {
        let response = self.get(path)?;
        if response.status >= 300 {
            return Err(error_from_response(&response, self.oidc.is_some()));
        }
        Ok(response.body)
    }

    pub fn post_ok(&self, path: &str, body: &Value) -> Result<Value, ContractError> {
        let response = self.post(path, body)?;
        if response.status >= 300 {
            return Err(error_from_response(&response, self.oidc.is_some()));
        }
        Ok(response.body)
    }

    pub fn status(&self) -> Result<Value, ContractError> {
        self.get_ok("/status")
    }

    /// Refresh the snapshot a repository needs: company-wide direction plus
    /// the rulings that govern this repository. Asking for everything is how
    /// the response outgrew the body ceiling and froze every cache in the
    /// estate. `known` offers the content digest of the snapshot already held;
    /// Company answers with the whole snapshot, or with a signed receipt that
    /// the offered content is still its answer. Both are root-verified and
    /// must echo this request's fresh nonce.
    pub fn refresh_for(
        &self,
        repository_uuid: &str,
        known: Option<&str>,
    ) -> Result<SnapshotRefresh, ContractError> {
        let nonce = crate::crypto::random_token();
        let mut path = if repository_uuid.is_empty() {
            format!("/snapshot?nonce={nonce}")
        } else {
            format!("/snapshot?nonce={nonce}&repository={repository_uuid}")
        };
        // Only a well-formed digest reaches the query string.
        let known = known.filter(|digest| super::cache::is_content_digest(digest));
        if let Some(known) = known {
            path.push_str(&format!("&known={known}"));
        }
        let response = self.request_within("GET", &path, None, self.snapshot_timeout)?;
        if response.status >= 300 {
            return Err(error_from_response(&response, self.oidc.is_some()));
        }
        let snapshot = response.body;
        let root = self.root.as_ref().ok_or_else(|| {
            ContractError::invariant("a Company root public key is required to verify snapshots")
        })?;
        let signer = PublicKey::verify_document("receipt", &snapshot).ok_or_else(|| {
            ContractError::integrity(
                "SIGNATURE_INVALID",
                "Company snapshot signature failed",
                "Quarantine the snapshot and contact the Company steward.",
            )
        })?;
        if signer != *root {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                "Company snapshot is not signed by the configured root key",
                "Verify the root public key in the user config.",
            ));
        }
        if crate::json::get_str(&snapshot, "client_nonce") != Some(nonce.as_str()) {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                "Company snapshot does not echo the fresh client nonce (replay)",
                "Refresh again; a replayed snapshot cannot rebuild trust.",
            ));
        }
        if crate::json::get_str(&snapshot, "schema")
            == Some(super::server::SNAPSHOT_UNCHANGED_SCHEMA)
        {
            if known.is_none() || crate::json::get_str(&snapshot, "content_digest") != known {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    "Company's unchanged receipt names content this client did not offer",
                    "Refresh again without a known digest to fetch the full snapshot.",
                ));
            }
            return Ok(SnapshotRefresh::Unchanged(snapshot));
        }
        Ok(SnapshotRefresh::Snapshot(snapshot))
    }

    /// Fetch and root-verify the latest steward-signed authority registry.
    pub fn authority_registry(&self) -> Result<Value, ContractError> {
        let response = self.get_ok("/v1/authority-registry")?;
        let registry = response.get("registry").cloned().ok_or_else(|| {
            ContractError::integrity("SIGNATURE_INVALID", "authority-registry response lacks its signed document", "Refresh from the configured Company endpoint; do not reconstruct trust from partial state.")
        })?;
        let root = self.root.as_ref().ok_or_else(|| {
            ContractError::invariant(
                "a Company root public key is required to verify the authority registry",
            )
        })?;
        let signer =
            PublicKey::verify_document("authority-registry-entry", &registry).ok_or_else(|| {
                ContractError::integrity(
                    "SIGNATURE_INVALID",
                    "authority registry signature failed",
                    "Quarantine the response and contact the Company steward.",
                )
            })?;
        if signer != *root {
            return Err(ContractError::integrity(
                "SIGNATURE_INVALID",
                "authority registry is not signed by the configured root key",
                "Verify the root public key in the user config before accepting authority.",
            ));
        }
        Ok(response)
    }

    /// Fetch and root-verify signed revocation documents and their cursor.
    pub fn revocations(&self) -> Result<Value, ContractError> {
        let response = self.get_ok("/v1/revocations")?;
        let documents = response
            .get("revocations")
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let root = self.root.as_ref().ok_or_else(|| {
            ContractError::invariant("a Company root public key is required to verify revocations")
        })?;
        for document in documents.as_array().cloned().unwrap_or_default() {
            let signer = PublicKey::verify_document("revocation", &document).ok_or_else(|| {
                ContractError::integrity(
                    "SIGNATURE_INVALID",
                    "revocation signature failed",
                    "Quarantine the revocation snapshot and contact the Company steward.",
                )
            })?;
            if signer != *root {
                return Err(ContractError::integrity(
                    "SIGNATURE_INVALID",
                    "revocation is not signed by the configured root key",
                    "Verify the root public key in the user config before changing trust.",
                ));
            }
        }
        Ok(response)
    }

    pub fn post_fact(&self, event: &Value) -> Result<Value, ContractError> {
        self.post_ok("/facts", event)
    }

    pub fn post_question(&self, question: &Value) -> Result<Value, ContractError> {
        self.post_ok("/questions", question)
    }

    pub fn post_answer(&self, answer: &Value) -> Result<Value, ContractError> {
        self.post_ok("/answers", answer)
    }

    pub fn post_unknown(&self, unknown: &Value) -> Result<Value, ContractError> {
        self.post_ok("/unknowns", unknown)
    }

    pub fn post_manifest(&self, manifest: &Value) -> Result<Value, ContractError> {
        self.post_ok("/manifests", manifest)
    }

    pub fn certificates_for_hint(&self, hint: &str) -> Result<Vec<Value>, ContractError> {
        let encoded: String = hint
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        let body = self.get_ok(&format!("/certificates?hint={encoded}"))?;
        Ok(crate::json::get_array(&body, "certificates")
            .cloned()
            .unwrap_or_default())
    }

    pub fn fact_digest(
        &self,
        fact_id: &str,
        version: &str,
        alg: &str,
    ) -> Result<Value, ContractError> {
        self.get_ok(&format!(
            "/facts/{fact_id}/digest?version={version}&alg={alg}"
        ))
    }

    pub fn question(&self, question_id: &str) -> Result<Value, ContractError> {
        self.get_ok(&format!("/questions/{question_id}"))
    }
}

/// Map a non-2xx response to the typed error it carried (or a bounded
/// substitute when the body was not a taxonomy error).
pub fn error_from_response(response: &Response, oidc: bool) -> ContractError {
    if let Some(error) = response.body.get("error") {
        if let Ok(mut parsed) = serde_json::from_value::<ContractError>(error.clone()) {
            if crate::error::CODES.contains(&parsed.code.as_str()) {
                parsed.exit_override = None;
                if oidc && response.status == 401 && parsed.code == "AUTHORITY_SCOPE_DENIED" {
                    return parsed.with_oidc_token_failure();
                }
                return parsed;
            }
        }
    }
    if oidc && response.status == 401 {
        return ContractError::refused(
            "AUTHORITY_SCOPE_DENIED",
            "OIDC gateway refused the session",
            "Run `kinbase auth login`",
        )
        .with_oidc_token_failure();
    }
    match response.status {
        401 | 403 => ContractError::refused(
            "AUTHORITY_SCOPE_DENIED",
            "Company refused the request as unauthorized",
            "Issue a least-privilege exact-scope token bound to this client key.",
        ),
        404 => ContractError::invariant("Company endpoint or object not found"),
        409 => ContractError::refused(
            "APPROVAL_REPLAY",
            "Company reported a conflicting prior commit",
            "Use the original receipt or create a new candidate.",
        ),
        413 | 429 => ContractError::limit(
            format!("Company refused with status {}", response.status),
            json!({"refused_count": 1, "omitted_count": 1}),
        ),
        500..=599 => {
            ContractError::unreachable(format!("Company answered with status {}", response.status))
        }
        status => ContractError::invariant(format!("Company answered with status {status}")),
    }
}

/// Post a delivery to an authority channel URL (questions ask): a plain
/// signed POST with the question document; channels are loopback only.
pub fn deliver_to_channel(
    channel: &str,
    body: &Value,
    key: &PrivateKey,
) -> Result<Response, ContractError> {
    let (scheme, host, port, path) = http::parse_url(channel, false, false)?;
    if scheme != http::Scheme::Http {
        return Err(ContractError::invariant(
            "authority channel must use loopback http://",
        ));
    }
    let bytes = crate::json::canonical_bytes(body);
    let signature = key.sign("question", &bytes)?;
    let headers = vec![
        ("X-Kinbase-Client-Key".to_owned(), key.public().to_hex()),
        ("X-Kinbase-Signature".to_owned(), signature),
    ];
    let path = if path.is_empty() {
        "/".to_owned()
    } else {
        path
    };
    http::request(
        scheme,
        &host,
        port,
        "POST",
        &path,
        &headers,
        &bytes,
        Duration::from_secs(5),
    )
}

/// A request nonce unique across processes: several processes share one
/// client key, and the time-plus-counter nonce collided between them, so the
/// service refused one of the requests as a replay.
fn request_nonce() -> String {
    let sequence = SEQUENCE.fetch_add(1, Ordering::SeqCst);
    format!(
        "{}{:03}-{:016x}",
        crate::time::now_utc().timestamp_millis(),
        sequence % 1000,
        rand::random::<u64>()
    )
}

#[cfg(test)]
mod nonce_tests {
    #[test]
    fn nonces_differ_even_with_the_same_time_and_counter() {
        let nonces: std::collections::BTreeSet<String> =
            (0..1000).map(|_| super::request_nonce()).collect();
        assert_eq!(nonces.len(), 1000);
        // Two processes share the time and counter prefix; the suffix differs.
        let (left, right) = (super::request_nonce(), super::request_nonce());
        let suffix = |nonce: &str| nonce.split_once('-').map(|(_, rest)| rest.to_owned());
        assert_ne!(suffix(&left), suffix(&right));
        assert!(left.len() <= 128);
    }
}

#[cfg(test)]
mod snapshot_timeout_tests {
    use super::{Client, DEFAULT_READ_TIMEOUT_SECONDS};
    use crate::config::TokenRecord;
    use crate::crypto::PrivateKey;
    use std::time::{Duration, Instant};

    /// A Service that accepts and then reduces for longer than the client
    /// waits is the failure a growing store produces: a snapshot read gives up
    /// at its configured budget, not at a bound compiled into the binary, and
    /// no other request inherits that budget.
    #[test]
    fn a_snapshot_waits_for_its_configured_budget_and_nothing_else_does() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            // Answer nothing until the client has given up.
            let _ = finished.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });
        let cache = std::env::temp_dir().join(format!("kinbase-snapshot-timeout-{port}"));
        let client = Client::new(
            &format!("http://127.0.0.1:{port}"),
            TokenRecord {
                token: "facts".to_owned(),
            },
            PrivateKey::generate(),
            None,
            cache,
            false,
        )
        .expect("client")
        .with_snapshot_timeout_seconds(1);
        assert_eq!(client.snapshot_timeout, Duration::from_secs(1));
        assert_eq!(
            client.read_timeout,
            Duration::from_secs(DEFAULT_READ_TIMEOUT_SECONDS)
        );
        let started = Instant::now();
        let Err(error) = client.refresh_for("", None) else {
            panic!("no answer within the budget must be an error");
        };
        let waited = started.elapsed();
        assert_eq!(error.code, "COMPANY_UNREACHABLE");
        assert!(
            waited >= Duration::from_millis(900) && waited < Duration::from_secs(3),
            "waited {waited:?}"
        );
        let _ = done.send(());
        holder.join().expect("holder");
    }
}

#[cfg(test)]
mod gateway_key_tests {
    use super::Client;
    use crate::config::TokenRecord;
    use crate::crypto::PrivateKey;
    use std::io::{Read, Write};

    /// The gateway authenticates the caller on `Authorization: ApiKey` and
    /// strips it; the store still needs the facts token, so both are sent and
    /// no bearer reaches the gateway.
    #[test]
    fn a_gateway_key_is_sent_as_an_api_key_beside_the_facts_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
            String::from_utf8_lossy(&head).to_lowercase()
        });
        let mut client = Client::new(
            &format!("http://127.0.0.1:{port}"),
            TokenRecord { token: "facts-token".to_owned() },
            PrivateKey::generate(),
            None,
            std::env::temp_dir().join(format!("kinbase-gateway-key-{port}")),
            false,
        )
        .expect("client");
        client.gateway_key = Some("adapt-key".to_owned());
        client.get("/v1/status").expect("request");
        let head = server.join().expect("server");
        assert!(head.contains("\r\nauthorization: apikey adapt-key\r\n"), "{head}");
        assert!(head.contains("\r\nx-kinbase-token: facts-token\r\n"), "{head}");
        assert!(!head.contains("bearer"), "{head}");
    }

    /// A key file is copied into a header, so a line break inside it could
    /// add headers of its own; it is refused like a malformed facts token.
    #[test]
    fn a_key_file_with_a_line_break_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("gateway.key");
        std::fs::write(&path, "adapt-key\r\nX-Injected: 1\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(TokenRecord::load(&path, "company gateway API key").is_err());
        std::fs::write(&path, "adapt-key\n").expect("write");
        assert_eq!(TokenRecord::load(&path, "company gateway API key").expect("load").token, "adapt-key");
    }
}
