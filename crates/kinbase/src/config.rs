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
}

/// One `[companies.<name>]` entry: a Company among several, chosen per
/// repository by `crate::selection`. The name lives only in the user config;
/// no worktree byte, certificate or hook output carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedCompany {
    pub name: String,
    /// Patterns over the normalized origin URL (`repository::normalize_hint`),
    /// stored normalized. They only discover; the certificate is the trust.
    pub discovery_hints: Vec<String>,
    pub config: CompanyConfig,
    /// The key paths were defaulted under `config_dir/companies/<name>/`
    /// rather than named in the file.
    pub client_key_defaulted: bool,
    pub maintainer_key_defaulted: bool,
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
    /// The Company this invocation uses: the single `[company]`, or the one
    /// `crate::selection` resolved from `companies` for the invocation's
    /// repository. Everything downstream reads only this.
    pub company: Option<CompanyConfig>,
    /// Every `[companies.<name>]` entry; empty under the single form.
    pub companies: Vec<NamedCompany>,
    /// `[identity] maintainer_key_file` is set.
    pub identity_maintainer_key: bool,
    /// `[identity] share_maintainer_key = true`.
    pub share_maintainer_key: bool,
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
            .ok_or_else(|| {
                config_error(format!(
                    "personal.kindex_processors entries need {name} (text without spaces)"
                ))
            })
    };
    let key_env = field("key_env")?;
    if !(key_env.len() > "_API_KEY".len()
        && key_env.ends_with("_API_KEY")
        && key_env
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
    {
        return Err(config_error(
            "personal.kindex_processors key_env must be a variable ending in _API_KEY",
        ));
    }
    let key_sha256 = field("key_sha256")?;
    if key_sha256.len() != 64
        || !key_sha256
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(config_error(
            "personal.kindex_processors key_sha256 must be the key's SHA-256 in lowercase hex",
        ));
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
        for key in [
            "kindex_executable_sha256",
            "kindex_config",
            "kindex_timeout_seconds",
            "kindex_digest",
            "kindex_retention_seconds",
            "kindex_processors",
            "kindex_team_knowledge",
        ] {
            if table.contains_key(key) {
                return Err(config_error(format!(
                    "personal.{key} requires personal.kindex_executable"
                )));
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
            .ok_or_else(|| {
                config_error("personal.kindex_timeout_seconds must be a positive integer")
            })? as u64,
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
                .ok_or_else(|| {
                    config_error("personal.kindex_retention_seconds must be a positive integer")
                })?,
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
    let mut user = parse_user_config(&path, &text)?;
    // The mask is installed by reading the user config and by nothing else:
    // a repository's config, the environment and the process cwd cannot
    // turn it on, off or narrower.
    crate::secret_mask::configure(user.secret_mask.as_ref());
    // Under the named form `company` becomes the one Company this
    // invocation's target resolves to; under the single form it stays as read.
    crate::selection::apply(&mut user);
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
            "companies",
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
            closed_keys(section, &COMPANY_KEYS, "[company]")?;
            Some(company_section(section, "company", &config_dir)?)
        }
    };
    let companies = match table.get("companies") {
        None => Vec::new(),
        Some(value) => named_companies(value, &config_dir)?,
    };
    if company.is_some() && !companies.is_empty() {
        return Err(config_error(
            "[company] and [companies.<name>] are mutually exclusive; move the single Company under a name",
        ));
    }

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

    let (principal_id, host_instance_id, identity_maintainer_key, share_maintainer_key) =
        match table.get("identity") {
            None => (default_principal(), default_host_instance(), None, false),
            Some(value) => {
                let section = value
                    .as_table()
                    .ok_or_else(|| config_error("[identity] must be a table"))?;
                closed_keys(
                    section,
                    &[
                        "principal_id",
                        "host_instance_id",
                        "maintainer_key_file",
                        "share_maintainer_key",
                    ],
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
                    // Under the named form, one maintainer key presented to several
                    // organizations lets them correlate the person; that is a
                    // choice the file states, not a side effect of R-18.
                    optional_bool(section, "share_maintainer_key", "identity")?,
                )
            }
        };
    let company = match (company, identity_maintainer_key.clone()) {
        (Some(mut company), Some(path)) => {
            company.maintainer_key_file = path;
            Some(company)
        }
        (company, _) => company,
    };
    // `[identity] maintainer_key_file` names one person's key; with several
    // Companies it applies to all of them only with `share_maintainer_key`
    // (`crate::selection` refuses otherwise).
    let companies = companies
        .into_iter()
        .map(|mut named| {
            if let Some(path) = &identity_maintainer_key {
                named.config.maintainer_key_file = path.clone();
                named.maintainer_key_defaulted = false;
            }
            named
        })
        .collect();

    Ok(UserConfig {
        path: path.to_path_buf(),
        personal: PersonalConfig { data_root, kindex },
        company,
        identity_maintainer_key: identity_maintainer_key.is_some(),
        share_maintainer_key,
        companies,
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

const COMPANY_KEYS: [&str; 10] = [
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
];

/// One Company's keys, read the same way under `[company]` and under
/// `[companies.<name>]`; `label` is how messages name the section.
fn company_section(
    section: &toml::Table,
    label: &str,
    key_dir: &Path,
) -> Result<CompanyConfig, ContractError> {
    let url = required_str(section, "url", label)?.to_owned();
    let allow_non_loopback = optional_bool(section, "allow_non_loopback", label)?;
    validate_loopback_url(&url, allow_non_loopback)?;
    Ok(CompanyConfig {
        url,
        allow_non_loopback,
        facts_token_file: absolute(
            required_str(section, "facts_token_file", label)?,
            &format!("{label}.facts_token_file"),
        )?,
        root_public_key_file: absolute(
            required_str(section, "root_public_key_file", label)?,
            &format!("{label}.root_public_key_file"),
        )?,
        cache_root: absolute(
            required_str(section, "cache_root", label)?,
            &format!("{label}.cache_root"),
        )?,
        admin_token_file: optional_path(section, "admin_token_file", label)?,
        directory_token_file: optional_path(section, "directory_token_file", label)?,
        authority_token_file: optional_path(section, "authority_token_file", label)?,
        client_key_file: optional_path(section, "client_key_file", label)?
            .unwrap_or_else(|| key_dir.join("client.key")),
        maintainer_key_file: optional_path(section, "maintainer_key_file", label)?
            .unwrap_or_else(|| key_dir.join("maintainer.key")),
    })
}

/// `[companies.<name>]` tables. Each Company keeps its own cache, root and
/// endpoint: two entries sharing one would let one organization's state
/// answer for another's, so the overlap is refused here rather than guessed
/// at per repository.
fn named_companies(
    value: &toml::Value,
    config_dir: &Path,
) -> Result<Vec<NamedCompany>, ContractError> {
    let table = value
        .as_table()
        .ok_or_else(|| config_error("[companies] must be a table of [companies.<name>] tables"))?;
    if table.is_empty() {
        return Err(config_error("[companies] names no Company"));
    }
    let mut companies: Vec<NamedCompany> = Vec::new();
    for (name, value) in table {
        if !valid_company_name(name) {
            return Err(config_error(format!(
                "Company name `{name}` must be 1-32 characters of a-z, 0-9 and '-', starting with a letter or digit"
            )));
        }
        let label = format!("companies.{name}");
        let section = value
            .as_table()
            .ok_or_else(|| config_error(format!("[{label}] must be a table")))?;
        let mut allowed = COMPANY_KEYS.to_vec();
        allowed.push("discovery_hints");
        closed_keys(section, &allowed, &format!("[{label}]"))?;
        let key_dir = config_dir.join("companies").join(name);
        let config = company_section(section, &label, &key_dir)?;
        plain_path(&config.cache_root, &format!("{label}.cache_root"))?;
        plain_path(
            &config.root_public_key_file,
            &format!("{label}.root_public_key_file"),
        )?;
        let discovery_hints = match section.get("discovery_hints") {
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .ok_or_else(|| {
                    config_error(format!(
                        "{label}.discovery_hints must be an array of strings"
                    ))
                })?
                .iter()
                .map(|pattern| {
                    pattern
                        .as_str()
                        .ok_or_else(|| {
                            config_error(format!(
                                "{label}.discovery_hints must be an array of strings"
                            ))
                        })
                        .and_then(|pattern| normalize_hint_pattern(pattern, &label))
                })
                .collect::<Result<Vec<_>, _>>()?,
        };
        for other in &companies {
            let conflict =
                if other.config.url.trim_end_matches('/') == config.url.trim_end_matches('/') {
                    Some("url")
                } else if paths_overlap(&other.config.cache_root, &config.cache_root) {
                    Some("cache_root")
                } else if same_path(
                    &other.config.root_public_key_file,
                    &config.root_public_key_file,
                ) {
                    Some("root_public_key_file")
                } else {
                    None
                };
            if let Some(field) = conflict {
                return Err(config_error(format!(
                    "[companies.{}] and [{label}] share {field}; each Company needs its own",
                    other.name
                )));
            }
        }
        companies.push(NamedCompany {
            name: name.clone(),
            discovery_hints,
            client_key_defaulted: section.get("client_key_file").is_none(),
            maintainer_key_defaulted: section.get("maintainer_key_file").is_none(),
            config,
        });
    }
    Ok(companies)
}

pub(crate) fn valid_company_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
}

/// A discovery pattern in the form origins are compared in: the same
/// normalization `repository::normalize_hint` applies to the origin URL, so
/// `git@github.com:Acme/*` and `https://github.com/acme/*` mean one thing.
fn normalize_hint_pattern(pattern: &str, label: &str) -> Result<String, ContractError> {
    let normalized = crate::repository::normalize_hint(pattern);
    if normalized.is_empty()
        || normalized
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(config_error(format!(
            "{label}.discovery_hints holds an empty or malformed pattern"
        )));
    }
    if normalized.contains("***") {
        return Err(config_error(format!(
            "{label}.discovery_hints pattern `{normalized}` uses `***`; use `*` within a segment or `**` across segments"
        )));
    }
    Ok(normalized)
}

/// Match a normalized origin against a normalized pattern: `*` is any run
/// within one path segment, `**` any run across segments, all else literal.
pub fn hint_matches(pattern: &str, origin: &str) -> bool {
    fn go(pattern: &[u8], origin: &[u8]) -> bool {
        match pattern {
            [] => origin.is_empty(),
            [b'*', b'*', rest @ ..] => (0..=origin.len()).any(|skip| go(rest, &origin[skip..])),
            [b'*', rest @ ..] => {
                let segment = origin
                    .iter()
                    .position(|&b| b == b'/')
                    .unwrap_or(origin.len());
                (0..=segment).any(|skip| go(rest, &origin[skip..]))
            }
            [first, rest @ ..] => origin.first() == Some(first) && go(rest, &origin[1..]),
        }
    }
    go(pattern.as_bytes(), origin.as_bytes())
}

/// The path a Company's file or directory will resolve to once it exists:
/// the deepest existing ancestor canonicalized (so symlinks and case are
/// resolved), then the components not created yet. `..` was refused when the
/// config was read, so the remainder is plain names.
fn comparable(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (
            existing.file_name().map(|name| name.to_os_string()),
            existing.parent(),
        ) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent.to_path_buf();
            }
            _ => break,
        }
    }
    let mut resolved = existing.canonicalize().unwrap_or(existing);
    for name in rest.into_iter().rev() {
        resolved.push(name);
    }
    resolved
}

/// Company paths are compared for overlap before they exist; a `.` or `..`
/// component would let two spellings of one directory compare as two.
fn plain_path(path: &Path, field: &str) -> Result<(), ContractError> {
    use std::path::Component;
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(config_error(format!(
            "{field} must not contain `.` or `..` components"
        )));
    }
    Ok(())
}

fn same_path(left: &Path, right: &Path) -> bool {
    comparable(left) == comparable(right)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    let (left, right) = (comparable(left), comparable(right));
    left.starts_with(&right) || right.starts_with(&left)
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

pub fn validate_loopback_url(url: &str, allow_non_loopback: bool) -> Result<(), ContractError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| config_error("company.url must be an http:// URL"))?;
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
    /// Derive the immutable shared-process configuration. Reads every token
    /// and key file under the cli.md file rules; contents are held in memory
    /// only. The Personal data root is deliberately not representable here.
    pub fn shared(&self) -> Result<SharedConfig, ContractError> {
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
                    // One descriptor carries one key; with several Companies
                    // it would sign for whichever one this repository selects.
                    Ok(_) if !self.companies.is_empty() => {
                        return Err(config_error(
                            "KINBASE_CLIENT_KEY_FD carries one client key and is refused with [companies.<name>]",
                        ));
                    }
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
        assert!(
            error.message.contains("personal-recall"),
            "{}",
            error.message
        );
        let plain =
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n";
        let config =
            parse_user_config(Path::new("/private/example/config.toml"), plain).expect("parses");
        assert!(config.personal.kindex.is_none());
    }
}

mod named_company_tests {
    use super::*;

    fn named(hints: &str) -> Result<UserConfig, ContractError> {
        let text = format!(
            "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n\
             [companies.alpha]\nurl = \"http://127.0.0.1:8421\"\nfacts_token_file = \"/private/a/facts\"\n\
             root_public_key_file = \"/private/a/root.pub\"\ncache_root = \"/private/a/cache\"\n\
             discovery_hints = [{hints}]\n"
        );
        parse_user_config(Path::new("/private/example/config.toml"), &text)
    }

    #[test]
    fn hints_are_compared_in_the_form_origins_are() {
        let config =
            named("\"https://GitHub.com/Acme/*\", \"git@gitlab.acme.example:platform/**\"")
                .expect("parses");
        let hints = &config.companies[0].discovery_hints;
        assert_eq!(hints[0], "github.com/acme/*");
        assert_eq!(hints[1], "gitlab.acme.example/platform/**");
        let origin = |remote: &str| crate::repository::normalize_hint(remote);
        assert!(hint_matches(
            &hints[0],
            &origin("git@github.com:acme/api.git")
        ));
        assert!(!hint_matches(
            &hints[0],
            &origin("git@github.com:acme/team/api.git")
        ));
        assert!(hint_matches(
            &hints[1],
            &origin("https://gitlab.acme.example/platform/team/api")
        ));
        assert!(!hint_matches(
            &hints[0],
            &origin("git@github.com:acme-labs/api.git")
        ));
    }

    #[test]
    fn named_keys_default_per_company_and_identity_sharing_is_recorded() {
        let config = named("").expect("parses");
        let alpha = &config.companies[0];
        assert!(alpha.client_key_defaulted && alpha.maintainer_key_defaulted);
        assert_eq!(
            alpha.config.client_key_file,
            Path::new("/private/example/companies/alpha/client.key")
        );
        assert!(
            config.company.is_none(),
            "the named form selects later, per repository"
        );
    }

    #[test]
    fn two_spellings_of_one_cache_root_are_refused() {
        let text = |root_a: &str, root_b: &str| {
            format!(
                "schema_version = \"1\"\n\n[personal]\ndata_root = \"/private/example/kindex\"\n\n\
                 [companies.alpha]\nurl = \"http://127.0.0.1:8421\"\nfacts_token_file = \"/private/a/facts\"\n\
                 root_public_key_file = \"/private/a/root.pub\"\ncache_root = \"{root_a}\"\n\n\
                 [companies.beta]\nurl = \"http://127.0.0.1:8422\"\nfacts_token_file = \"/private/b/facts\"\n\
                 root_public_key_file = \"/private/b/root.pub\"\ncache_root = \"{root_b}\"\n"
            )
        };
        let parse =
            |text: String| parse_user_config(Path::new("/private/example/config.toml"), &text);
        let aliased = parse(text(
            "/tmp/kinbase-org/a/../cache",
            "/tmp/kinbase-org/cache",
        ));
        assert!(aliased.is_err_and(|error| error.message.contains("`..`")));
        let nested = parse(text(
            "/tmp/kinbase-org/cache",
            "/tmp/kinbase-org/cache/inner",
        ));
        assert!(nested.is_err_and(|error| error.message.contains("share cache_root")));
        assert!(parse(text("/tmp/kinbase-org/a", "/tmp/kinbase-org/b")).is_ok());
    }

    #[test]
    fn a_malformed_hint_is_refused() {
        assert!(named("\"github.com/acme/***\"").is_err());
        assert!(named("\"  \"").is_err());
        assert!(named("42").is_err());
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
