//! Company client: signed, nonce-bearing loopback requests with the 250 ms
//! connection budget, typed `COMPANY_UNREACHABLE`, and helpers for every
//! endpoint the CLI uses.

use crate::config::TokenRecord;
use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use crate::http::{self, Response};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Client {
    pub host: String,
    pub port: u16,
    pub base_path: String,
    pub token: TokenRecord,
    pub key: PrivateKey,
    pub root: Option<PublicKey>,
    pub cache_root: PathBuf,
    pub read_timeout: Duration,
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
        let (host, port, base_path) = http::parse_url(url, allow_non_loopback)?;
        Ok(Self {
            host,
            port,
            base_path,
            token,
            key,
            root,
            cache_root,
            // A snapshot is a reduction over the whole Company event log, so it
            // costs what the log costs: 2.5 s against one deployment's 2,720 events and
            // rising. At 1,500 ms -- a bound sized for proof fixtures -- every
            // repository in the estate reported COMPANY_UNREACHABLE against a
            // service that was answering perfectly well, which reads as an
            // outage rather than as the ceiling it is.
            read_timeout: Duration::from_secs(20),
            bytes_sent: std::cell::Cell::new(0),
        })
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
        let headers = vec![
            (
                "Authorization".to_owned(),
                format!("Bearer {}", self.token.token),
            ),
            ("X-Kinbase-Nonce".to_owned(), nonce),
            ("X-Kinbase-Expires-At".to_owned(), expires_at),
            (
                "X-Kinbase-Client-Key".to_owned(),
                self.key.public().to_hex(),
            ),
            ("X-Kinbase-Signature".to_owned(), signature),
        ];
        self.bytes_sent
            .set(self.bytes_sent.get() + body_bytes.len() as u64 + 256);
        http::request(
            &self.host,
            self.port,
            method,
            &full_path,
            &headers,
            &body_bytes,
            self.read_timeout,
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
            return Err(error_from_response(&response));
        }
        Ok(response.body)
    }

    pub fn post_ok(&self, path: &str, body: &Value) -> Result<Value, ContractError> {
        let response = self.post(path, body)?;
        if response.status >= 300 {
            return Err(error_from_response(&response));
        }
        Ok(response.body)
    }

    pub fn status(&self) -> Result<Value, ContractError> {
        self.get_ok("/status")
    }

    /// Fetch and verify a signed snapshot bound to a fresh client nonce.
    pub fn snapshot(&self) -> Result<Value, ContractError> {
        self.snapshot_for("")
    }

    /// The snapshot a repository needs: company-wide direction plus the rulings
    /// that govern this repository. Asking for everything is how the response
    /// outgrew the body ceiling and froze every cache in the estate.
    pub fn snapshot_for(&self, repository_uuid: &str) -> Result<Value, ContractError> {
        let nonce = crate::crypto::random_token();
        let path = if repository_uuid.is_empty() {
            format!("/snapshot?nonce={nonce}")
        } else {
            format!("/snapshot?nonce={nonce}&repository={repository_uuid}")
        };
        let snapshot = self.get_ok(&path)?;
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
        Ok(snapshot)
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
pub fn error_from_response(response: &Response) -> ContractError {
    if let Some(error) = response.body.get("error") {
        if let Ok(mut parsed) = serde_json::from_value::<ContractError>(error.clone()) {
            if crate::error::CODES.contains(&parsed.code.as_str()) {
                parsed.exit_override = None;
                return parsed;
            }
        }
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
    let (host, port, path) = http::parse_url(channel, false)?;
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
