//! Company / Kinbase service commands: `company init` (steward preview and
//! key/token/schema creation), `company serve` (loopback HTTP service; schema
//! self-initializes per Validator ruling R-2), and steward helpers that sign
//! and publish documents with the root key.

pub mod cache;
pub mod client;
pub mod db;
pub mod reduction;
pub mod server;
pub mod trust;
pub mod view_cache;

use crate::config::{ServiceConfig, load_service_config};
use crate::crypto::PrivateKey;
use crate::error::ContractError;
use serde_json::{Value, json};
use std::path::Path;

/// Load the root signing key: 32 raw seed bytes or 64-hex, mode 0600; the
/// `.pub` sibling is created when absent (never a private replacement).
pub fn load_root_key(config: &ServiceConfig) -> Result<PrivateKey, ContractError> {
    let key = PrivateKey::load(&config.root_key_file, "Company root key")?;
    let public_path = std::path::PathBuf::from(format!(
        "{}.pub",
        config
            .root_key_file
            .to_string_lossy()
            .trim_end_matches(".key")
    ));
    let alt_public =
        std::path::PathBuf::from(format!("{}.pub", config.root_key_file.to_string_lossy()));
    if !public_path.exists() && !alt_public.exists() {
        key.public()
            .save_new(&public_path, "Company root public key")?;
    }
    Ok(key)
}

fn ensure_token_file(path: &Path, prefix: &str, role: &str) -> Result<bool, ContractError> {
    if path.exists() {
        crate::config::TokenRecord::load(path, role)?;
        return Ok(false);
    }
    let token = format!("{prefix}{}", &crate::crypto::random_token()[..40]);
    crate::crypto::write_new_0600(path, token.as_bytes(), role)?;
    Ok(true)
}

pub fn init(config_path: &Path, json_output: bool) -> Result<(), ContractError> {
    let config = load_service_config(config_path)?;
    let mut created = Vec::new();
    let mut existing = Vec::new();
    if !config.root_key_file.exists() {
        let key = PrivateKey::generate();
        key.save_new(&config.root_key_file, "Company root key")?;
        created.push(config.root_key_file.to_string_lossy().into_owned());
    } else {
        existing.push(config.root_key_file.to_string_lossy().into_owned());
    }
    let root = load_root_key(&config)?;
    for (path, prefix, role) in [
        (Some(&config.facts_token_file), "facts-", "facts token"),
        (
            config.directory_token_file.as_ref(),
            "dir-",
            "directory token",
        ),
        (
            config.admin_token_file.as_ref(),
            "admin-",
            "administrative token",
        ),
        (
            config.authority_token_file.as_ref(),
            "auth-",
            "authority token",
        ),
    ] {
        if let Some(path) = path {
            if ensure_token_file(path, prefix, role)? {
                created.push(path.to_string_lossy().into_owned());
            } else {
                existing.push(path.to_string_lossy().into_owned());
            }
        }
    }
    let db = db::CompanyDb::open(&config.sqlite_path)?;
    db.set_meta("company_id", &config.company_id)?;
    db.set_meta("root_public_key", &root.public().to_hex())?;
    let tokens = server::register_tokens(&db, &config)?;
    let result = json!({
        "status": "company-initialized",
        "company_id": config.company_id,
        "sqlite_path": config.sqlite_path.to_string_lossy(),
        "bind": config.bind.to_string(),
        "root_public_key": root.public().to_hex(),
        "certificate_subject": format!("Company {} steward root {}", config.company_id, root.public().to_hex()),
        "created_paths": created,
        "existing_paths": existing,
        "token_roles": tokens,
        "facts_token_scopes": config.facts_token_scopes,
        "facts_token_capabilities": server::FACTS_TOKEN_SCOPES,
        "nonce_retention_seconds": config.nonce_retention_seconds,
        "candidate_lifetime_seconds": config.candidate_lifetime_seconds,
        "clock_skew_seconds": config.clock_skew_seconds,
        "trust_on_first_use": false
    });
    crate::output::emit(&result, json_output);
    Ok(())
}

pub fn serve(config_path: &Path, json_output: bool) -> Result<(), ContractError> {
    let config = load_service_config(config_path)?;
    let root = load_root_key(&config)?;
    crate::config::TokenRecord::load(&config.facts_token_file, "facts token")?;
    server::serve(config, root, json_output)
}

/// Steward report over the service's usage rows. It runs beside the store
/// rather than over HTTP: who used the service is not a fact any client
/// token is scoped to read.
pub fn usage(
    config_path: &Path,
    since: Option<&str>,
    until: Option<&str>,
    bucket: crate::usage::Bucket,
    json_output: bool,
) -> Result<(), ContractError> {
    let config = load_service_config(config_path)?;
    let window = crate::usage::Window::parse(since, until)?;
    // A report must not be the thing that creates the store it reports on.
    //
    // spec/cli.md's first-run table answers "requested store uninitialized"
    // with exit 2, but the closed taxonomy has no exit-2 code for a Company
    // store (REPO_UNCERTIFIED names the Codebase one), and `ContractError::new`
    // turns a code paired with the wrong exit into RUN_INTEGRITY_FAILED. This
    // stays CONFIG_INVARIANT (exit 4) until the taxonomy gains a code; the
    // gap is raised as a spec defect rather than papered over here.
    let uninitialized = |message: &str| {
        ContractError::refused(
            "CONFIG_INVARIANT",
            message,
            format!(
                "Run `kinbase company init --config {}` first; no store was created.",
                config_path.display()
            ),
        )
    };
    if !config.sqlite_path.exists() {
        return Err(uninitialized(
            "the Company store named by sqlite_path does not exist",
        ));
    }
    // Read-only: the report runs beside a live service, against whatever
    // file sqlite_path names, and writes to neither.
    let db = db::CompanyDb::connect_read_only(&config.sqlite_path)?;
    // A store is this Company's once `company init` or `serve` has stamped
    // its company_id; any other SQLite file, meta table or not, is refused.
    let company_id = if db.has_table("meta")? {
        db.meta("company_id")?
    } else {
        None
    };
    if company_id.as_deref() != Some(config.company_id.as_str()) {
        return Err(uninitialized(
            "the file named by sqlite_path is not this Company's initialized store",
        ));
    }
    let mut report = crate::usage::report(&db, &window, bucket)?;
    report["status"] = json!("company-usage");
    report["company_id"] = json!(config.company_id);
    // Recording is off unless the service config sets it; an empty report
    // from a service that was never recording says so.
    report["recording"] = json!(config.record_usage);
    if json_output {
        crate::output::emit(&report, true);
    } else {
        print!("{}", crate::usage::render_human(&report));
    }
    Ok(())
}

/// Steward helper: sign a JSON document with the Company root key as one of
/// the closed message types and print it.
pub fn sign(
    config_path: &Path,
    message_type: &str,
    document_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let config = load_service_config(config_path)?;
    let root = load_root_key(&config)?;
    let bytes = crate::paths::read_bounded(document_path, 1024 * 1024, "document")?;
    let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::invariant(format!("document is not canonical JSON ({error})"))
    })?;
    let signed = root.sign_document(message_type, &document)?;
    crate::output::emit(&signed, json_output);
    Ok(())
}

/// Steward helper: publish a signed document to the running service using
/// the administrative token (falls back to the facts token for endpoints
/// that accept it).
pub fn publish(
    config_path: &Path,
    endpoint: &str,
    document_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let config = load_service_config(config_path)?;
    let bytes = crate::paths::read_bounded(document_path, 1024 * 1024, "document")?;
    let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::invariant(format!("document is not canonical JSON ({error})"))
    })?;
    let token_path = config
        .admin_token_file
        .as_ref()
        .unwrap_or(&config.facts_token_file);
    let token = crate::config::TokenRecord::load(token_path, "administrative token")?;
    let client_key = PrivateKey::load_or_generate(
        &crate::paths::config_dir().join("steward-client.key"),
        "steward client key",
    )?;
    let client = client::Client::new(
        &format!("http://{}", config.bind),
        token,
        client_key,
        None,
        crate::paths::config_dir().join("steward-cache"),
        config.allow_non_loopback,
    )?;
    let response = client.post(endpoint, &document)?;
    let mut result = json!({"status": response.status, "response": response.body});
    if response.status >= 400 {
        result["error"] = response.body.get("error").cloned().unwrap_or(Value::Null);
    }
    if response.status >= 400 {
        return Err(client::error_from_response(&response, false).with_output_document(result));
    }
    crate::output::emit(&result, json_output);
    Ok(())
}
