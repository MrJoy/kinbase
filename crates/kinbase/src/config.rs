//! Launcher-only user configuration and the derived shared-process
//! configuration (cli.md "Configuration", architecture §1 and §6).
//!
//! Only the launcher reads the whole user config. `SharedConfig` is the
//! immutable configuration handed to shared projector/writer work: it holds
//! no Personal path, descriptor, environment value, or serialized parent
//! config, and the type system is the first enforcement of that
//! non-possession (there is no accessor from `SharedConfig` to Personal).

use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use crate::paths;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const USER_CONFIG_SCHEMA: &str = "1";
pub const SERVICE_CONFIG_SCHEMA: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalConfig {
    pub data_root: PathBuf,
    /// The Personal store's Kindex (product.md: Personal is Kindex). Optional:
    /// without it host transcripts stay in the private journal and there is no recall.
    pub kindex: Option<PersonalKindexConfig>,
}

/// Kindex run as a pinned executable over `data_root`, the Personal Kindex
/// graph. Only the launcher and Personal worker run it; nothing it reads or
/// returns enters a shared store or projection.
/// One processor authorized for historical Personal-store text: the exact
/// provider, model, account and retention mode (threat-model.md, model-provider
/// boundary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedProcessor {
    pub provider: String,
    pub model: String,
    /// The variable holding the account's API key; Kindex's config names it.
    pub key_env: String,
    /// SHA-256 of that key: the authorization covers this account alone.
    pub key_sha256: String,
    /// The retention mode the account is under, as authorized.
    pub retention: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalKindexConfig {
    pub executable: PathBuf,
    pub executable_sha256: String,
    /// A Kindex config file (providers, `ask:` settings), passed as `--config`.
    pub config: Option<PathBuf>,
    pub timeout_seconds: u64,
    /// Run Kindex's digest pass (directives, summaries) after each hand-off.
    pub digest: bool,
    /// How long a transcript handed to Kindex is kept, counted from the
    /// transcript's last change; a `.retention` sidecar beside the transcript
    /// overrides it. Past it the conversation, and everything Kindex derived
    /// from it, is removed. `None`: the private raw-session default (24 hours).
    pub retention_seconds: Option<i64>,
    /// The off-machine processors explicitly authorized to receive
    /// Personal-store text from Kindex: its LLM (digest, recall) and its
    /// embedding provider. A host's provider relationship does not cover
    /// historical Personal recall (threat-model.md); empty means Kindex may run
    /// only locally. Kindex is given the credential of each, and no other
    /// environment.
    pub processors: Vec<AuthorizedProcessor>,
    /// Send the team facts a read-only projection releases along with a
    /// recall question. Off unless named: they go to the same processor.
    pub team_knowledge: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanyConfig {
    pub url: String,
    pub oidc_issuer: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret_file: Option<PathBuf>,
    /// A gateway API key for a caller that cannot sign in through a browser
    /// (an agent sandbox). Sent as `Authorization: ApiKey <key>`; the gateway
    /// checks and strips it, and the store still checks the facts token.
    pub gateway_api_key_file: Option<PathBuf>,
    pub facts_token_file: PathBuf,
    pub root_public_key_file: PathBuf,
    pub cache_root: PathBuf,
    pub admin_token_file: Option<PathBuf>,
    pub directory_token_file: Option<PathBuf>,
    pub authority_token_file: Option<PathBuf>,
    pub client_key_file: PathBuf,
    pub maintainer_key_file: PathBuf,
    /// Mirrors the service flag: set only where the endpoint is reached over a
    /// network whose isolation is enforced somewhere other than the interface.
    pub allow_non_loopback: bool,
    /// How long a snapshot read waits for the service to answer. A snapshot
    /// costs what the Company log costs, so a growing store outgrows any fixed
    /// bound; a deployment raises this instead of shipping a new binary. Other
    /// requests keep the default: hooks post through the same client.
    pub snapshot_timeout_seconds: u64,
}

/// The processors a `[classifier]` may send session text to: `local` (the
/// deterministic provider, or a model the loopback Ollama runs on this
/// machine), `agy` (the Antigravity CLI's service) and `ollama-cloud` (a model
/// the local Ollama forwards to ollama.com). A provider that sends text off
/// the machine runs only when its processor is named here.
pub const PROCESSOR_SCOPES: [&str; 3] = ["local", "agy", "ollama-cloud"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifierConfig {
    pub model: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub processor_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostsConfig {
    pub codex_version: String,
    pub claude_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerConfig {
    pub canary_file: Option<PathBuf>,
    pub forbidden_identifier_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConfig {
    pub path: PathBuf,
    pub personal: PersonalConfig,
    pub company: Option<CompanyConfig>,
    pub classifier: Option<ClassifierConfig>,
    /// `[secret_mask]`: known secrets masked before anything is written,
    /// signed or printed (`crate::secret_mask`). `None` is off; only this
    /// file can turn it on.
    pub secret_mask: Option<crate::secret_mask::SecretMaskConfig>,
    pub hosts: HostsConfig,
    pub scanner: ScannerConfig,
    pub principal_id: String,
    pub host_instance_id: String,
}

/// Which product mode the launcher resolved (cli.md: missing config selects
/// Codebase-only mode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Full,
    CodebaseOnly,
}

/// A bearer token as stored in a mode-0600 token file: the bare token bytes
/// with an optional trailing newline (Validator ruling R-3). Capability
/// scopes and the client-key binding are service-side records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenRecord {
    pub token: String,
}

impl TokenRecord {
    pub fn load(path: &Path, role: &str) -> Result<Self, ContractError> {
        let text = crate::crypto::read_private_text(path, role)?;
        let token = text.trim().to_owned();
        if token.is_empty() || token.len() > 512 || !token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                format!("{role} file does not hold a bare bearer token"),
                "Reissue the token file through `kinbase company init`; contents are never printed.",
            ));
        }
        Ok(Self { token })
    }
}

/// Everything a shared (non-Personal) process may hold. Constructed only by
/// the launcher from a `UserConfig`; carries no Personal field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedConfig {
    pub mode: Mode,
    pub principal_id: String,
    pub host_instance_id: String,
    pub company: Option<SharedCompanyAccess>,
    pub classifier: Option<SharedClassifier>,
    pub hosts: SharedHosts,
    pub canary_digests: Vec<String>,
    /// Digests, like the canaries': a shared process holds no raw registered
    /// value.
    pub forbidden_identifier_digests: Vec<String>,
    /// The word counts registered values span (see `scanner::Registry`).
    pub registry_digest_word_counts: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedCompanyAccess {
    pub url: String,
    pub facts_token: TokenRecord,
    pub admin_token: Option<TokenRecord>,
    pub directory_token: Option<TokenRecord>,
    pub authority_token: Option<TokenRecord>,
    pub root_public_key: String,
    pub cache_root: PathBuf,
    /// Present when the key already existed (or arrived by descriptor);
    /// otherwise the key is minted by the first command that signs with it.
    pub client_private_seed: Option<String>,
    pub maintainer_private_seed: Option<String>,
    pub client_key_file: PathBuf,
    pub maintainer_key_file: PathBuf,
    /// Carried through so a shared process applies the same endpoint rule the
    /// launcher was configured with, rather than re-deciding it.
    pub allow_non_loopback: bool,
    /// Carried through for the same reason: the shared process reads the
    /// snapshots, so it must wait as long as the launcher was configured to.
    #[serde(default = "default_snapshot_timeout_seconds")]
    pub snapshot_timeout_seconds: u64,
}

fn default_snapshot_timeout_seconds() -> u64 {
    crate::company::client::DEFAULT_READ_TIMEOUT_SECONDS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedClassifier {
    pub model: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub args: Vec<String>,
    pub timeout_seconds: u64,
    pub processor_scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedHosts {
    pub codex_version: String,
    pub claude_version: String,
}

impl SharedCompanyAccess {
    pub fn root_key(&self) -> Result<PublicKey, ContractError> {
        PublicKey::from_hex(&self.root_public_key)
    }
    /// The request-signing key, minted on first Company contact.
    pub fn client_key(&self) -> Result<PrivateKey, ContractError> {
        match &self.client_private_seed {
            Some(seed) => PrivateKey::from_seed_text(seed),
            None => PrivateKey::load_or_generate(&self.client_key_file, "client key"),
        }
    }
    /// The repository maintainer's signing key, for the commands that sign
    /// as the maintainer; minted by the first of them, never by a read.
    pub fn maintainer_key(&self) -> Result<PrivateKey, ContractError> {
        match &self.maintainer_private_seed {
            Some(seed) => PrivateKey::from_seed_text(seed),
            None => PrivateKey::load_or_generate(&self.maintainer_key_file, "maintainer key"),
        }
    }
    /// The maintainer's public key if one exists; a read never mints one.
    pub fn existing_maintainer_public_key(&self) -> Option<String> {
        match &self.maintainer_private_seed {
            Some(seed) => PrivateKey::from_seed_text(seed).ok(),
            None => self
                .maintainer_key_file
                .exists()
                .then(|| PrivateKey::load(&self.maintainer_key_file, "maintainer key").ok())
                .flatten(),
        }
        .map(|key| key.public().to_hex())
    }
}

pub fn user_config_path() -> PathBuf {
    paths::config_dir().join("config.toml")
}

/// A host version range: `>=X.Y.Z` or an exact `X.Y.Z` (one to four numeric
/// parts). A malformed or wrong-typed value used to become `>=0.0.0`
/// silently.
fn host_version_range(section: &toml::Table, key: &str) -> Result<String, ContractError> {
    let Some(value) = section.get(key) else {
        return Ok(">=0.0.0".to_owned());
    };
    let text = value
        .as_str()
        .ok_or_else(|| config_error(format!("hosts.{key} must be a string")))?
        .trim();
    let version = text.strip_prefix(">=").unwrap_or(text).trim();
    let parts: Vec<&str> = version.split('.').collect();
    // Each part must be a number the comparator can hold; a part past u64
    // compared as zero and let every host through.
    if parts.len() > 4
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || part.parse::<u64>().is_err()
        })
    {
        return Err(config_error(format!(
            "hosts.{key} must be `>=X.Y.Z` or an exact `X.Y.Z` version"
        )));
    }
    Ok(text.to_owned())
}

/// A TOML parse failure as its position and rule, never the source line:
/// the toml crate's own text quotes the offending line, which may hold a
/// secret the user put in their config.
pub fn toml_error_text(text: &str, error: &toml::de::Error) -> String {
    match error.span() {
        Some(span) => {
            let before = &text.as_bytes()[..span.start.min(text.len())];
            let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
            let column = before
                .iter()
                .rev()
                .take_while(|byte| **byte != b'\n')
                .count()
                + 1;
            format!("line {line}, column {column}: {}", error.message())
        }
        None => error.message().to_owned(),
    }
}

fn config_error(message: impl Into<String>) -> ContractError {
    ContractError::refused(
        "CONFIG_INVARIANT",
        message,
        "Correct the named configuration value; no state was changed.",
    )
}

fn closed_keys(table: &toml::Table, allowed: &[&str], section: &str) -> Result<(), ContractError> {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(config_error(format!(
                "unknown key `{key}` in {section}; unknown keys fail closed"
            )));
        }
    }
    Ok(())
}

fn required_str<'a>(
    table: &'a toml::Table,
    key: &str,
    section: &str,
) -> Result<&'a str, ContractError> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| config_error(format!("{section}.{key} is required")))
}

fn optional_path(
    table: &toml::Table,
    key: &str,
    section: &str,
) -> Result<Option<PathBuf>, ContractError> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => {
            let text = value
                .as_str()
                .ok_or_else(|| config_error(format!("{section}.{key} must be a string path")))?;
            absolute(text, &format!("{section}.{key}")).map(Some)
        }
    }
}

/// One `[[personal.kindex_processors]]` entry. Every field is required: the
/// authorization names the exact provider, model, account and retention mode.
fn authorized_processor(value: &toml::Value) -> Result<AuthorizedProcessor, ContractError> {
    let fields = ["provider", "model", "key_env", "key_sha256", "retention"];
    let table = value.as_table().ok_or_else(|| {
        config_error("personal.kindex_processors entries must be tables with provider, model, key_env, key_sha256 and retention")
    })?;
    closed_keys(table, &fields, "[[personal.kindex_processors]]")?;
    let field = |name: &str| -> Result<String, ContractError> {
        table
            .get(name)
            .and_then(toml::Value::as_str)
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_whitespace))
            .map(str::to_owned)
            .ok_or_else(|| config_error(format!("personal.kindex_processors entries need {name} (text without spaces)")))
    };
    let key_env = field("key_env")?;
    if !(key_env.len() > "_API_KEY".len()
        && key_env.ends_with("_API_KEY")
        && key_env.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        return Err(config_error("personal.kindex_processors key_env must be a variable ending in _API_KEY"));
    }
    let key_sha256 = field("key_sha256")?;
    if key_sha256.len() != 64 || !key_sha256.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
        return Err(config_error("personal.kindex_processors key_sha256 must be the key's SHA-256 in lowercase hex"));
    }
    Ok(AuthorizedProcessor {
        provider: field("provider")?,
        model: field("model")?,
        key_env,
        key_sha256,
        retention: field("retention")?,
    })
}

fn personal_kindex(table: &toml::Table) -> Result<Option<PersonalKindexConfig>, ContractError> {
    // The Personal Kindex is for testing only: a normal build refuses its keys
    // rather than ignore them.
    if !cfg!(feature = "personal-recall") {
        if let Some(key) = table.keys().find(|key| key.starts_with("kindex_")) {
            return Err(config_error(format!(
                "personal.{key} needs a kinbase built with the personal-recall feature, which is for testing only"
            )));
        }
        return Ok(None);
    }
    let Some(executable) = optional_path(table, "kindex_executable", "personal")? else {
        for key in ["kindex_executable_sha256", "kindex_config", "kindex_timeout_seconds", "kindex_digest", "kindex_retention_seconds", "kindex_processors", "kindex_team_knowledge"] {
            if table.contains_key(key) {
                return Err(config_error(format!("personal.{key} requires personal.kindex_executable")));
            }
        }
        return Ok(None);
    };
    let executable_sha256 = required_str(table, "kindex_executable_sha256", "personal")?.to_owned();
    if !crate::hash::is_sha256(&executable_sha256) {
        return Err(config_error(
            "personal.kindex_executable_sha256 must be a lowercase 64-hex digest",
        ));
    }
    let timeout_seconds = match table.get("kindex_timeout_seconds") {
        None => 900,
        Some(value) => value
            .as_integer()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| config_error("personal.kindex_timeout_seconds must be a positive integer"))?
            as u64,
    };
    let digest = match table.get("kindex_digest") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| config_error("personal.kindex_digest must be true or false"))?,
    };
    let retention_seconds = match table.get("kindex_retention_seconds") {
        None => None,
        Some(value) => Some(
            value
                .as_integer()
                .filter(|seconds| *seconds > 0)
                .ok_or_else(|| config_error("personal.kindex_retention_seconds must be a positive integer"))?,
        ),
    };
    let processors = match table.get("kindex_processors") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .ok_or_else(|| config_error("personal.kindex_processors must be an array of tables"))?
            .iter()
            .map(authorized_processor)
            .collect::<Result<_, _>>()?,
    };
    let team_knowledge = match table.get("kindex_team_knowledge") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| config_error("personal.kindex_team_knowledge must be true or false"))?,
    };
    Ok(Some(PersonalKindexConfig {
        executable,
        executable_sha256,
        config: optional_path(table, "kindex_config", "personal")?,
        timeout_seconds,
        digest,
        retention_seconds,
        processors,
        team_knowledge,
    }))
}

fn absolute(text: &str, field: &str) -> Result<PathBuf, ContractError> {
    let path = PathBuf::from(text);
    if !path.is_absolute() {
        return Err(config_error(format!("{field} must be an absolute path")));
    }
    Ok(path)
}

/// Enforce cli.md's file rules for a config/token/key path: regular file,
/// no symlink, mode not broader than 0600.
pub fn enforce_private_file(path: &Path, role: &str) -> Result<(), ContractError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| ContractError::unreadable(role, &error))?;
    if metadata.file_type().is_symlink() {
        return Err(config_error(format!("{role} file is a symlink")));
    }
    if !metadata.is_file() {
        return Err(config_error(format!("{role} path is not a regular file")));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ContractError::broad_mode(role, path, mode));
    }
    Ok(())
}

/// Load the launcher-only user config. `Ok(None)` is Codebase-only mode.
pub fn load_user_config() -> Result<Option<UserConfig>, ContractError> {
    let path = user_config_path();
    if !path.exists() && std::fs::symlink_metadata(&path).is_err() {
        crate::secret_mask::configure(None);
        return Ok(None);
    }
    enforce_private_file(&path, "user config")?;
    let text = std::fs::read_to_string(&path)
        .map_err(|error| ContractError::unreadable("user config", &error))?;
    let user = parse_user_config(&path, &text)?;
    // The mask is installed by reading the user config and by nothing else:
    // a repository's config, the environment and the process cwd cannot
    // turn it on, off or narrower.
    crate::secret_mask::configure(user.secret_mask.as_ref());
    Ok(Some(user))
}

pub fn parse_user_config(path: &Path, text: &str) -> Result<UserConfig, ContractError> {
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        config_error(format!(
            "user config is not valid TOML ({})",
            toml_error_text(text, &error)
        ))
    })?;
    closed_keys(
        &table,
        &[
            "schema_version",
            "personal",
            "company",
            "classifier",
            "hosts",
            "scanner",
            "identity",
            "secret_mask",
        ],
        "user config",
    )?;
    if table.get("schema_version").and_then(toml::Value::as_str) != Some(USER_CONFIG_SCHEMA) {
        return Err(config_error("user config schema_version must be \"1\""));
    }
    let personal_table = table
        .get("personal")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| config_error("[personal] is required"))?;
    closed_keys(
        personal_table,
        &[
            "data_root",
            "kindex_executable",
            "kindex_executable_sha256",
            "kindex_config",
            "kindex_timeout_seconds",
            "kindex_digest",
            "kindex_retention_seconds",
            "kindex_processors",
            "kindex_team_knowledge",
        ],
        "[personal]",
    )?;
    let data_root = absolute(
        required_str(personal_table, "data_root", "personal")?,
        "personal.data_root",
    )?;
    let kindex = personal_kindex(personal_table)?;
    let config_dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(paths::config_dir);

    let company = match table.get("company") {
        None => None,
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[company] must be a table"))?;
            closed_keys(
                section,
                &[
                    "url",
                    "facts_token_file",
                    "root_public_key_file",
                    "cache_root",
                    "admin_token_file",
                    "directory_token_file",
                    "authority_token_file",
                    "client_key_file",
                    "maintainer_key_file",
                    "allow_non_loopback",
                    "snapshot_timeout_seconds",
                    "oidc_issuer",
                    "oidc_client_id",
                    "oidc_client_secret_file",
                    "gateway_api_key_file",
                ],
                "[company]",
            )?;
            let url = required_str(section, "url", "company")?.to_owned();
            let allow_non_loopback = optional_bool(section, "allow_non_loopback", "company")?;
            let optional_text = |key: &str| {
                section
                    .get(key)
                    .map(|_| required_str(section, key, "company").map(str::to_owned))
                    .transpose()
            };
            let oidc_issuer = optional_text("oidc_issuer")?;
            let oidc_client_id = optional_text("oidc_client_id")?;
            let oidc_client_secret_file =
                optional_path(section, "oidc_client_secret_file", "company")?;
            if oidc_issuer.is_some() != oidc_client_id.is_some()
                || (oidc_issuer.is_none() && oidc_client_secret_file.is_some())
            {
                return Err(config_error(
                    "company OIDC needs both oidc_issuer and oidc_client_id",
                ));
            }
            let gateway_api_key_file = optional_path(section, "gateway_api_key_file", "company")?;
            if oidc_issuer.is_some() && gateway_api_key_file.is_some() {
                return Err(config_error(
                    "company takes one gateway credential: OIDC or gateway_api_key_file",
                ));
            }
            let gateway = oidc_issuer.is_some() || gateway_api_key_file.is_some();
            validate_loopback_url(&url, allow_non_loopback, gateway)?;
            if gateway_api_key_file.is_some() {
                crate::oidc::validate_provider_url(&url)?;
            }
            if let Some(issuer) = &oidc_issuer {
                crate::oidc::validate_provider_url(issuer)?;
                crate::oidc::validate_provider_url(&url)?;
            }
            let snapshot_timeout_seconds = match section.get("snapshot_timeout_seconds") {
                None => default_snapshot_timeout_seconds(),
                Some(value) => value
                    .as_integer()
                    .filter(|seconds| (1..=600).contains(seconds))
                    .and_then(|seconds| u64::try_from(seconds).ok())
                    .ok_or_else(|| {
                        config_error(
                            "company.snapshot_timeout_seconds must be an integer within 1..=600",
                        )
                    })?,
            };
            Some(CompanyConfig {
                url,
                oidc_issuer,
                oidc_client_id,
                oidc_client_secret_file,
                gateway_api_key_file,
                allow_non_loopback,
                snapshot_timeout_seconds,
                facts_token_file: absolute(
                    required_str(section, "facts_token_file", "company")?,
                    "company.facts_token_file",
                )?,
                root_public_key_file: absolute(
                    required_str(section, "root_public_key_file", "company")?,
                    "company.root_public_key_file",
                )?,
                cache_root: absolute(
                    required_str(section, "cache_root", "company")?,
                    "company.cache_root",
                )?,
                admin_token_file: optional_path(section, "admin_token_file", "company")?,
                directory_token_file: optional_path(section, "directory_token_file", "company")?,
                authority_token_file: optional_path(section, "authority_token_file", "company")?,
                client_key_file: optional_path(section, "client_key_file", "company")?
                    .unwrap_or_else(|| config_dir.join("client.key")),
                maintainer_key_file: optional_path(section, "maintainer_key_file", "company")?
                    .unwrap_or_else(|| config_dir.join("maintainer.key")),
            })
        }
    };

    let classifier = match table.get("classifier") {
        None => None,
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[classifier] must be a table"))?;
            closed_keys(
                section,
                &[
                    "model",
                    "executable",
                    "executable_sha256",
                    "args",
                    "timeout_seconds",
                    "processor_scope",
                ],
                "[classifier]",
            )?;
            let model = match section.get("model") {
                None => "deterministic".to_owned(),
                Some(value) => value
                    .as_str()
                    .ok_or_else(|| config_error("classifier.model must be a string"))?
                    .to_owned(),
            };
            if !model.starts_with("deterministic")
                && !model.starts_with("ollama:")
                && !model.starts_with("agy:")
            {
                return Err(config_error(
                    "classifier.model must be \"deterministic\", \"ollama:<name>\" or \"agy:<name>\"",
                ));
            }
            let executable = absolute(
                required_str(section, "executable", "classifier")?,
                "classifier.executable",
            )?;
            let digest = required_str(section, "executable_sha256", "classifier")?.to_owned();
            if !crate::hash::is_sha256(&digest) {
                return Err(config_error(
                    "classifier.executable_sha256 must be a lowercase 64-hex digest",
                ));
            }
            let args = section
                .get("args")
                .map(|value| {
                    value
                        .as_array()
                        .ok_or_else(|| config_error("classifier.args must be an array of strings"))?
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| config_error("classifier.args must be strings"))
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
                .unwrap_or_default();
            let timeout_seconds = section
                .get("timeout_seconds")
                .and_then(toml::Value::as_integer)
                .ok_or_else(|| config_error("classifier.timeout_seconds is required"))?;
            if !(1..=600).contains(&timeout_seconds) {
                return Err(config_error(
                    "classifier.timeout_seconds must be within 1..=600",
                ));
            }
            let processor_scope = match section.get("processor_scope") {
                None => "local".to_owned(),
                Some(value) => value
                    .as_str()
                    .filter(|scope| PROCESSOR_SCOPES.contains(scope))
                    .ok_or_else(|| {
                        config_error(format!(
                            "classifier.processor_scope must be one of {}",
                            PROCESSOR_SCOPES
                                .iter()
                                .map(|scope| format!("\"{scope}\""))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?
                    .to_owned(),
            };
            Some(ClassifierConfig {
                model,
                executable,
                executable_sha256: digest,
                args,
                timeout_seconds: timeout_seconds as u64,
                processor_scope,
            })
        }
    };

    let hosts = match table.get("hosts") {
        None => HostsConfig {
            codex_version: ">=0.0.0".to_owned(),
            claude_version: ">=0.0.0".to_owned(),
        },
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[hosts] must be a table"))?;
            closed_keys(section, &["codex_version", "claude_version"], "[hosts]")?;
            HostsConfig {
                codex_version: host_version_range(section, "codex_version")?,
                claude_version: host_version_range(section, "claude_version")?,
            }
        }
    };

    let scanner = match table.get("scanner") {
        None => ScannerConfig {
            canary_file: None,
            forbidden_identifier_file: None,
        },
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[scanner] must be a table"))?;
            closed_keys(
                section,
                &["canary_file", "forbidden_identifier_file"],
                "[scanner]",
            )?;
            ScannerConfig {
                canary_file: optional_path(section, "canary_file", "scanner")?,
                forbidden_identifier_file: optional_path(
                    section,
                    "forbidden_identifier_file",
                    "scanner",
                )?,
            }
        }
    };

    let (principal_id, host_instance_id, identity_maintainer_key) = match table.get("identity") {
        None => (default_principal(), default_host_instance(), None),
        Some(value) => {
            let section = value
                .as_table()
                .ok_or_else(|| config_error("[identity] must be a table"))?;
            closed_keys(
                section,
                &["principal_id", "host_instance_id", "maintainer_key_file"],
                "[identity]",
            )?;
            (
                section
                    .get("principal_id")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(default_principal),
                section
                    .get("host_instance_id")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(default_host_instance),
                // Ruling R-18: the repository maintainer's signing key reaches the
                // product through `[identity] maintainer_key_file`; it takes
                // precedence over the legacy `[company]` location.
                optional_path(section, "maintainer_key_file", "identity")?,
            )
        }
    };
    let company = match (company, identity_maintainer_key) {
        (Some(mut company), Some(path)) => {
            company.maintainer_key_file = path;
            Some(company)
        }
        (company, _) => company,
    };

    Ok(UserConfig {
        path: path.to_path_buf(),
        personal: PersonalConfig { data_root, kindex },
        company,
        classifier,
        secret_mask: match table.get("secret_mask") {
            None => None,
            Some(value) => Some(secret_mask_section(value)?),
        },
        hosts,
        scanner,
        principal_id,
        host_instance_id,
    })
}

/// `[secret_mask]`: the env files whose values are masked, which names in
/// them are secrets, and the shortest value worth masking.
fn secret_mask_section(
    value: &toml::Value,
) -> Result<crate::secret_mask::SecretMaskConfig, ContractError> {
    let section = value
        .as_table()
        .ok_or_else(|| config_error("[secret_mask] must be a table"))?;
    closed_keys(section, &["files", "keys", "min_length"], "[secret_mask]")?;
    let strings = |key: &str| -> Result<Option<Vec<String>>, ContractError> {
        let Some(value) = section.get(key) else {
            return Ok(None);
        };
        let malformed = || config_error(format!("secret_mask.{key} must be an array of strings"));
        value
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or_else(malformed))
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    };
    // There is no default file: a table that names none masks nothing.
    let files = strings("files")?
        .unwrap_or_default()
        .iter()
        .map(|file| {
            // `~/` is the user's home, as the shell reads the same file.
            let expanded = match file.strip_prefix("~/") {
                Some(rest) => paths::home_dir().join(rest).to_string_lossy().into_owned(),
                None => file.clone(),
            };
            absolute(&expanded, "secret_mask.files")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keys = strings("keys")?;
    if keys
        .as_ref()
        .is_some_and(|keys| keys.iter().any(|key| key.trim_matches('*').is_empty()))
    {
        return Err(config_error(
            "secret_mask.keys holds an empty selector; name a variable or a fragment of one",
        ));
    }
    let min_length = match section.get("min_length") {
        None => crate::secret_mask::DEFAULT_MIN_LENGTH,
        Some(value) => value
            .as_integer()
            .filter(|length| *length >= 1)
            .and_then(|length| usize::try_from(length).ok())
            .ok_or_else(|| config_error("secret_mask.min_length must be a positive integer"))?,
    };
    Ok(crate::secret_mask::SecretMaskConfig {
        files,
        keys,
        min_length,
    })
}

fn default_principal() -> String {
    std::env::var("KINBASE_PRINCIPAL")
        .unwrap_or_else(|_| std::env::var("USER").unwrap_or_else(|_| "local-principal".to_owned()))
}

/// A present value that is not a boolean is malformed configuration, not a
/// false. Reading `allow_non_loopback = "true"` as off refuses the bind while
/// the file says otherwise, which is the hardest kind of mistake to see.
fn optional_bool(
    table: &toml::value::Table,
    key: &str,
    section: &str,
) -> Result<bool, ContractError> {
    match table.get(key) {
        None => Ok(false),
        Some(toml::Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(config_error(format!(
            "{section}.{key} must be a boolean, true or false, unquoted"
        ))),
    }
}

fn default_host_instance() -> String {
    std::env::var("KINBASE_HOST_INSTANCE").unwrap_or_else(|_| {
        let host = std::fs::read_to_string("/etc/hostname")
            .ok()
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "local-host".to_owned());
        format!("host_{}", &crate::hash::sha256_text(&host)[..16])
    })
}

pub fn validate_loopback_url(
    url: &str,
    allow_non_loopback: bool,
    oidc: bool,
) -> Result<(), ContractError> {
    let scheme = if oidc {
        "http:// or https://"
    } else {
        "http://"
    };
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://").filter(|_| oidc))
        .ok_or_else(|| config_error(format!("company.url must be an {scheme} URL")))?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(authority);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback && !allow_non_loopback {
        return Err(config_error(
            "company.url must name a loopback endpoint unless company.allow_non_loopback is set",
        ));
    }
    Ok(())
}

impl UserConfig {
    pub fn oidc_configured(&self) -> bool {
        self.company
            .as_ref()
            .is_some_and(|company| company.oidc_issuer.is_some())
    }

    /// Either gateway credential admits the https gateway URL.
    pub fn gateway_configured(&self) -> bool {
        self.oidc_configured()
            || self
                .company
                .as_ref()
                .is_some_and(|company| company.gateway_api_key_file.is_some())
    }

    pub fn oidc(&self) -> Result<Option<crate::oidc::Config>, ContractError> {
        let Some(company) = &self.company else {
            return Ok(None);
        };
        let (Some(issuer), Some(client_id)) = (&company.oidc_issuer, &company.oidc_client_id)
        else {
            return Ok(None);
        };
        let client_secret = company
            .oidc_client_secret_file
            .as_ref()
            .map(|path| crate::crypto::read_private_text(path, "OIDC client secret"))
            .transpose()?
            .map(|secret| secret.trim().to_owned());
        Ok(Some(crate::oidc::Config {
            issuer: issuer.clone(),
            client_id: client_id.clone(),
            client_secret,
            session_path: self.path.with_file_name("oidc.json"),
        }))
    }

    /// Derive the immutable shared-process configuration. Reads every token
    /// and key file under the cli.md file rules; contents are held in memory
    /// only. The Personal data root is deliberately not representable here.
    pub fn shared(&self) -> Result<SharedConfig, ContractError> {
        let _ = self.oidc()?;
        let company = match &self.company {
            None => None,
            Some(company) => {
                let facts_token = TokenRecord::load(&company.facts_token_file, "facts token")?;
                let admin_token = company
                    .admin_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "administrative token"))
                    .transpose()?;
                let directory_token = company
                    .directory_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "directory token"))
                    .transpose()?;
                let authority_token = company
                    .authority_token_file
                    .as_ref()
                    .map(|path| TokenRecord::load(path, "authority token"))
                    .transpose()?;
                let root_public_key =
                    PublicKey::load(&company.root_public_key_file, "Company root public key")?;
                // Loading the configuration creates nothing: the cache
                // directory is made by its first write, and a key by the
                // first command that signs with it. `hooks plan`, `doctor`
                // and an offline `status` minted both keys before.
                if company.cache_root.exists() {
                    paths::ensure_private_dir(&company.cache_root, "Company cache root")?;
                }
                let client_key = match std::env::var("KINBASE_CLIENT_KEY_FD") {
                    Ok(fd) => {
                        let fd: i32 = fd.parse().map_err(|_| {
                            config_error("KINBASE_CLIENT_KEY_FD must be an integer")
                        })?;
                        Some(PrivateKey::load_fd(fd, "client key")?)
                    }
                    Err(_) => existing_key(&company.client_key_file, "client key")?,
                };
                let maintainer_key = existing_key(&company.maintainer_key_file, "maintainer key")?;
                Some(SharedCompanyAccess {
                    url: company.url.clone(),
                    allow_non_loopback: company.allow_non_loopback,
                    snapshot_timeout_seconds: company.snapshot_timeout_seconds,
                    facts_token,
                    admin_token,
                    directory_token,
                    authority_token,
                    root_public_key: root_public_key.to_hex(),
                    cache_root: company.cache_root.clone(),
                    client_private_seed: client_key.map(|key| key.to_seed_text()),
                    maintainer_private_seed: maintainer_key.map(|key| key.to_seed_text()),
                    client_key_file: company.client_key_file.clone(),
                    maintainer_key_file: company.maintainer_key_file.clone(),
                })
            }
        };
        let canaries = match &self.scanner.canary_file {
            None => Vec::new(),
            Some(path) => load_registry_lines(path, "canary registry")?,
        };
        let forbidden_identifiers = match &self.scanner.forbidden_identifier_file {
            None => Vec::new(),
            Some(path) => load_registry_lines(path, "forbidden identifier registry")?,
        };
        let registry_digest_word_counts =
            crate::scanner::registered_word_counts(canaries.iter().chain(&forbidden_identifiers))
                .into_iter()
                .collect();
        let canary_digests = canaries
            .iter()
            .map(|value| crate::scanner::canary_digest(value))
            .collect();
        let forbidden_identifier_digests = forbidden_identifiers
            .iter()
            .map(|value| crate::scanner::identifier_digest(value))
            .collect();
        Ok(SharedConfig {
            mode: Mode::Full,
            principal_id: self.principal_id.clone(),
            host_instance_id: self.host_instance_id.clone(),
            company,
            classifier: self.classifier.as_ref().map(|classifier| SharedClassifier {
                model: classifier.model.clone(),
                executable: classifier.executable.clone(),
                executable_sha256: classifier.executable_sha256.clone(),
                args: classifier.args.clone(),
                timeout_seconds: classifier.timeout_seconds,
                processor_scope: classifier.processor_scope.clone(),
            }),
            hosts: SharedHosts {
                codex_version: self.hosts.codex_version.clone(),
                claude_version: self.hosts.claude_version.clone(),
            },
            canary_digests,
            forbidden_identifier_digests,
            registry_digest_word_counts,
        })
    }
}

fn existing_key(path: &Path, role: &str) -> Result<Option<PrivateKey>, ContractError> {
    if path.exists() {
        PrivateKey::load(path, role).map(Some)
    } else {
        Ok(None)
    }
}

fn load_registry_lines(path: &Path, role: &str) -> Result<Vec<String>, ContractError> {
    let text = crate::crypto::read_private_text(path, role)?;
    let mut set = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        set.insert(line.to_owned());
    }
    Ok(set.into_iter().collect())
}

/// Codebase-only shared configuration (no user config present).
pub fn codebase_only_shared() -> SharedConfig {
    SharedConfig {
        mode: Mode::CodebaseOnly,
        principal_id: default_principal(),
        host_instance_id: default_host_instance(),
        company: None,
        classifier: None,
        hosts: SharedHosts {
            codex_version: ">=0.0.0".to_owned(),
            claude_version: ">=0.0.0".to_owned(),
        },
        canary_digests: Vec::new(),
        forbidden_identifier_digests: Vec::new(),
        registry_digest_word_counts: Vec::new(),
    }
}

/// Service configuration (`kinbased.toml`).
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub path: PathBuf,
    pub company_id: String,
    pub sqlite_path: PathBuf,
    pub bind: std::net::SocketAddr,
    /// Set only by a deployment whose isolation comes from the network rather
    /// than from the loopback interface. Relaxes the bind and Host checks
    /// together: enforcing Host against loopback on a routable bind refuses
    /// every request, so the two cannot move independently.
    pub allow_non_loopback: bool,
    pub root_key_file: PathBuf,
    pub facts_token_file: PathBuf,
    pub directory_token_file: Option<PathBuf>,
    pub admin_token_file: Option<PathBuf>,
    pub authority_token_file: Option<PathBuf>,
    pub auth_failures_per_minute: i64,
    pub default_fact_freshness_seconds: i64,
    pub candidate_lifetime_seconds: i64,
    pub clock_skew_seconds: i64,
    pub nonce_retention_seconds: i64,
    pub read_volume_per_hour: i64,
    pub read_bytes_per_hour: i64,
    pub requests_per_minute: i64,
    pub revocation_freshness_seconds: i64,
    pub directory_retention_seconds: i64,
    /// Whether the service writes a usage row per authenticated request. Off
    /// unless set: a row names the principal and a stable client
    /// fingerprint, which spec/product.md P-3 keeps out of Company logs until
    /// a ruling admits them.
    pub record_usage: bool,
    /// How long a usage row is kept. At least a day: the store refuses to
    /// delete a younger row.
    pub usage_retention_seconds: i64,
    /// Exact canonical authority scopes granted to the facts token issued
    /// from `facts_token_file`; empty grants nothing.
    pub facts_token_scopes: Vec<String>,
}

pub fn load_service_config(path: &Path) -> Result<ServiceConfig, ContractError> {
    enforce_private_file(path, "service config")?;
    let text = std::fs::read_to_string(path)
        .map_err(|error| ContractError::unreadable("service config", &error))?;
    let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
        config_error(format!(
            "service config is not valid TOML ({})",
            toml_error_text(&text, &error)
        ))
    })?;
    closed_keys(
        &table,
        &[
            "schema_version",
            "company_id",
            "sqlite_path",
            "bind",
            "allow_non_loopback",
            "root_key_file",
            "facts_token_file",
            "directory_token_file",
            "admin_token_file",
            "authority_token_file",
            "auth_failures_per_minute",
            "default_fact_freshness_seconds",
            "candidate_lifetime_seconds",
            "clock_skew_seconds",
            "nonce_retention_seconds",
            "read_volume_per_hour",
            "read_bytes_per_hour",
            "requests_per_minute",
            "revocation_freshness_seconds",
            "directory_retention_seconds",
            "record_usage",
            "usage_retention_seconds",
            "facts_token_scopes",
        ],
        "service config",
    )?;
    if table.get("schema_version").and_then(toml::Value::as_str) != Some(SERVICE_CONFIG_SCHEMA) {
        return Err(config_error("service config schema_version must be \"1\""));
    }
    let integer = |key: &str, default: Option<i64>, minimum: i64| -> Result<i64, ContractError> {
        let value = match table.get(key) {
            Some(value) => value
                .as_integer()
                .ok_or_else(|| config_error(format!("{key} must be an integer")))?,
            None => default.ok_or_else(|| config_error(format!("{key} is required")))?,
        };
        if value < minimum {
            return Err(config_error(format!("{key} must be at least {minimum}")));
        }
        Ok(value)
    };
    let bind_text = required_str(&table, "bind", "service")?;
    let bind: std::net::SocketAddr = bind_text
        .parse()
        .map_err(|_| config_error("bind must be an IP:port address"))?;
    let allow_non_loopback = optional_bool(&table, "allow_non_loopback", "service")?;
    if !bind.ip().is_loopback() && !allow_non_loopback {
        return Err(config_error(
            "bind must be a loopback address unless allow_non_loopback is set",
        ));
    }
    let lifetime = integer("candidate_lifetime_seconds", None, 1)?;
    let skew = integer("clock_skew_seconds", None, 0)?;
    let retention = integer("nonce_retention_seconds", None, 1)?;
    if retention <= lifetime + skew {
        return Err(config_error(
            "nonce_retention_seconds must be strictly greater than candidate_lifetime_seconds + clock_skew_seconds",
        ));
    }
    Ok(ServiceConfig {
        path: path.to_path_buf(),
        company_id: required_str(&table, "company_id", "service")?.to_owned(),
        sqlite_path: absolute(required_str(&table, "sqlite_path", "service")?, "sqlite_path")?,
        bind,
        allow_non_loopback,
        root_key_file: absolute(required_str(&table, "root_key_file", "service")?, "root_key_file")?,
        facts_token_file: absolute(required_str(&table, "facts_token_file", "service")?, "facts_token_file")?,
        directory_token_file: optional_path(&table, "directory_token_file", "service")?,
        admin_token_file: optional_path(&table, "admin_token_file", "service")?,
        authority_token_file: optional_path(&table, "authority_token_file", "service")?,
        auth_failures_per_minute: integer("auth_failures_per_minute", None, 1)?,
        default_fact_freshness_seconds: integer("default_fact_freshness_seconds", None, 1)?,
        candidate_lifetime_seconds: lifetime,
        clock_skew_seconds: skew,
        nonce_retention_seconds: retention,
        read_volume_per_hour: integer("read_volume_per_hour", Some(2_000), 1)?,
        read_bytes_per_hour: integer("read_bytes_per_hour", Some(64 * 1024 * 1024), 1)?,
        requests_per_minute: integer("requests_per_minute", Some(600), 1)?,
        revocation_freshness_seconds: integer("revocation_freshness_seconds", Some(900), 1)?,
        directory_retention_seconds: integer("directory_retention_seconds", Some(365 * 24 * 3600), 1)?,
        record_usage: optional_bool(&table, "record_usage", "service")?,
        usage_retention_seconds: integer("usage_retention_seconds", Some(30 * 24 * 3600), 24 * 3600)?,
        facts_token_scopes: table
            .get("facts_token_scopes")
            .map(|value| {
                value
                    .as_array()
                    .ok_or_else(|| config_error("facts_token_scopes must be an array of strings"))?
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .filter(|scope| {
                                !scope.is_empty()
                                    && !scope.contains('*')
                                    && !scope.contains('%')
                                    && !scope.contains('?')
                                    && !scope.contains('[')
                                    && !scope.ends_with(':')
                                    && !scope.contains('\0')
                            })
                            .ok_or_else(|| config_error("facts_token_scopes entries must be exact non-empty scope strings; wildcard, prefix, glob, and empty entries are refused"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod processor_scope_tests {
    use super::*;

    fn classifier_config(extra: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n\
             [classifier]\nexecutable = \"/opt/example/bin/classifier\"\n\
             executable_sha256 = \"{}\"\ntimeout_seconds = 20\n{extra}\n",
            "0".repeat(64)
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    fn scope_of(extra: &str) -> String {
        classifier_config(extra)
            .expect("config parses")
            .classifier
            .expect("classifier section")
            .processor_scope
    }

    #[test]
    fn processor_scope_is_a_closed_vocabulary() {
        assert_eq!(scope_of("model = \"agy:default\""), "local");
        assert_eq!(
            scope_of("model = \"agy:default\"\nprocessor_scope = \"agy\""),
            "agy"
        );
        assert_eq!(
            scope_of("processor_scope = \"ollama-cloud\""),
            "ollama-cloud"
        );
        for bad in [
            "processor_scope = \"cloud\"",
            "processor_scope = \"\"",
            "processor_scope = 1",
            "processor_scope = [\"agy\"]",
            "model = 7",
        ] {
            let error = classifier_config(bad).expect_err(bad);
            assert_eq!(error.code, "CONFIG_INVARIANT", "{bad}");
        }
    }
}

#[cfg(test)]
mod host_range_tests {
    use super::*;

    fn hosts(extra: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n[hosts]\n{extra}\n"
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    #[test]
    fn a_toml_error_names_its_place_not_its_line() {
        let text = "schema_version = \"1\"\ntoken = \"sk-live-SECRET\" oops\n";
        let error = parse_user_config(Path::new("/private/example/config.toml"), text)
            .expect_err("invalid TOML");
        assert!(error.message.contains("line 2"), "{}", error.message);
        assert!(!error.message.contains("SECRET"), "{}", error.message);
    }

    #[test]
    fn a_host_range_is_a_version_or_a_minimum() {
        let config =
            hosts("claude_version = \">=2.1.0\"\ncodex_version = \"0.40.1\"").expect("parses");
        assert_eq!(config.hosts.claude_version, ">=2.1.0");
        assert_eq!(config.hosts.codex_version, "0.40.1");
        assert_eq!(hosts("").expect("parses").hosts.codex_version, ">=0.0.0");
        for bad in [
            "claude_version = \"latest\"",
            "claude_version = \">=2.x\"",
            "claude_version = \"~2.1\"",
            "claude_version = 2",
            "codex_version = \">=1.2.3.4.5\"",
        ] {
            assert_eq!(hosts(bad).expect_err(bad).code, "CONFIG_INVARIANT", "{bad}");
        }
    }
}

#[cfg(all(test, not(feature = "personal-recall")))]
mod personal_recall_build_tests {
    use super::*;

    #[test]
    fn a_normal_build_refuses_the_personal_kindex_keys() {
        let text = "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\nkindex_executable = \"/opt/example/bin/kin\"\n";
        let error = parse_user_config(Path::new("/private/example/config.toml"), text)
            .expect_err("refused");
        assert!(error.message.contains("personal-recall"), "{}", error.message);
        let plain = "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n";
        let config = parse_user_config(Path::new("/private/example/config.toml"), plain).expect("parses");
        assert!(config.personal.kindex.is_none());
    }
}

#[cfg(test)]
mod secret_mask_config_tests {
    use super::*;

    fn parse(section: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n{section}"
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    #[test]
    fn an_absent_table_is_off_and_a_present_one_is_read_whole() {
        assert!(parse("").unwrap().secret_mask.is_none());
        let config = parse(
            "[secret_mask]\nfiles = [\"/private/example/env\", \"~/.profile\"]\nkeys = [\"github\", \"AWS_*_KEY\"]\nmin_length = 12\n",
        )
        .unwrap()
        .secret_mask
        .unwrap();
        assert_eq!(config.files[0], Path::new("/private/example/env"));
        assert!(config.files[1].is_absolute() && config.files[1].ends_with(".profile"));
        assert_eq!(config.keys.as_deref().unwrap(), ["github", "AWS_*_KEY"]);
        assert_eq!(config.min_length, 12);
        // No default file: a table that names none masks nothing.
        let empty = parse("[secret_mask]\n").unwrap().secret_mask.unwrap();
        assert!(empty.files.is_empty() && empty.keys.is_none());
        assert_eq!(empty.min_length, crate::secret_mask::DEFAULT_MIN_LENGTH);
    }

    #[test]
    fn a_malformed_table_is_refused_when_read() {
        for section in [
            "[secret_mask]\nfiles = [\"relative/env\"]\n",
            "[secret_mask]\nfiles = \"/private/example/env\"\n",
            "[secret_mask]\nkeys = [\"*\"]\n",
            "[secret_mask]\nmin_length = 0\n",
            "[secret_mask]\nmin_length = \"8\"\n",
            "[secret_mask]\nenabled = false\n",
            "secret_mask = \"off\"\n",
        ] {
            assert!(parse(section).is_err(), "accepted: {section}");
        }
    }
}

#[cfg(test)]
mod company_snapshot_timeout_tests {
    use super::*;

    fn company(extra: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n\
             [company]\nurl = \"http://127.0.0.1:8421\"\n\
             facts_token_file = \"/private/example/kinbase/facts.token\"\n\
             root_public_key_file = \"/private/example/kinbase/root-public.key\"\n\
             cache_root = \"/private/example/kinbase/cache\"\n{extra}\n"
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    fn timeout_of(extra: &str) -> u64 {
        company(extra)
            .expect("config parses")
            .company
            .expect("company section")
            .snapshot_timeout_seconds
    }

    #[test]
    fn the_snapshot_budget_defaults_and_a_deployment_can_raise_it() {
        assert_eq!(
            timeout_of(""),
            crate::company::client::DEFAULT_READ_TIMEOUT_SECONDS
        );
        assert_eq!(timeout_of("snapshot_timeout_seconds = 90"), 90);
        assert_eq!(timeout_of("snapshot_timeout_seconds = 600"), 600);
    }

    #[test]
    fn a_snapshot_budget_outside_its_range_is_refused() {
        for bad in [
            "snapshot_timeout_seconds = 0",
            "snapshot_timeout_seconds = -5",
            "snapshot_timeout_seconds = 601",
            "snapshot_timeout_seconds = \"90\"",
            "snapshot_timeout_seconds = 1.5",
        ] {
            assert_eq!(
                company(bad).expect_err(bad).code,
                "CONFIG_INVARIANT",
                "{bad}"
            );
        }
    }

    #[test]
    fn shared_access_written_before_the_field_existed_keeps_the_default() {
        let access = SharedCompanyAccess {
            url: "http://127.0.0.1:8421".to_owned(),
            facts_token: TokenRecord {
                token: "facts".to_owned(),
            },
            admin_token: None,
            directory_token: None,
            authority_token: None,
            root_public_key: String::new(),
            cache_root: PathBuf::from("/private/example/kinbase/cache"),
            client_private_seed: None,
            maintainer_private_seed: None,
            client_key_file: PathBuf::from("/private/example/kinbase/client.key"),
            maintainer_key_file: PathBuf::from("/private/example/kinbase/maintainer.key"),
            allow_non_loopback: false,
            snapshot_timeout_seconds: 90,
        };
        let mut value = serde_json::to_value(&access).expect("serializes");
        assert_eq!(value["snapshot_timeout_seconds"], 90);
        value
            .as_object_mut()
            .expect("object")
            .remove("snapshot_timeout_seconds");
        let older: SharedCompanyAccess = serde_json::from_value(value).expect("deserializes");
        assert_eq!(
            older.snapshot_timeout_seconds,
            crate::company::client::DEFAULT_READ_TIMEOUT_SECONDS
        );
    }
}

#[cfg(test)]
mod gateway_api_key_tests {
    use super::*;

    fn company(extra: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n[company]\nfacts_token_file = \"/private/example/facts.token\"\nroot_public_key_file = \"/private/example/root.pub\"\ncache_root = \"/private/example/cache\"\n{extra}"
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    #[test]
    fn a_gateway_api_key_admits_the_https_gateway_and_nothing_looser() {
        let key = "gateway_api_key_file = \"/private/example/gateway.key\"\n";
        let gateway = "url = \"https://kinbase.example.com\"\nallow_non_loopback = true\n";
        let config = company(&format!("{gateway}{key}")).unwrap().company.unwrap();
        assert_eq!(
            config.gateway_api_key_file.as_deref(),
            Some(Path::new("/private/example/gateway.key"))
        );
        // Without a gateway credential, https stays refused, as on main.
        assert!(company(gateway).is_err());
        // One credential: an API key or OIDC, not both.
        assert!(company(&format!(
            "{gateway}{key}oidc_issuer = \"https://accounts.google.com\"\noidc_client_id = \"client\"\n"
        ))
        .is_err());
        // A routable plaintext URL would send the key in the clear.
        assert!(company(&format!(
            "url = \"http://kinbase.example.com\"\nallow_non_loopback = true\n{key}"
        ))
        .is_err());
    }
}
