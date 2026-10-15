//! The launcher (architecture §1, §6; cli.md "Configuration"): resolves the
//! user config from `${XDG_CONFIG_HOME:-~/.config}/kinbase/config.toml`
//! only, attests inherited descriptors before any side effect, opens the
//! Personal store for Personal work, and derives the shared configuration
//! that carries no Personal capability.

use crate::company::cache::Cache;
use crate::company::client::Client;
use crate::config::{Mode, SharedConfig, UserConfig};
use crate::crypto::PublicKey;
use crate::error::ContractError;
use crate::private::PrivateStore;
use serde_json::{Value, json};
use std::path::PathBuf;

#[derive(Clone)]
pub struct Launcher {
    pub mode: Mode,
    pub user: Option<UserConfig>,
    pub shared: SharedConfig,
    pub fd_attestation: Value,
    pub company_env_present: bool,
    /// How `shared.company` was chosen (`crate::selection`).
    pub selection: crate::selection::Outcome,
}

pub struct CompanyAccess {
    pub client: Client,
    pub cache: Cache,
    pub root: PublicKey,
    pub url: String,
}

impl Launcher {
    /// Load configuration and attest descriptors. Any inherited Personal or
    /// non-allowlisted descriptor refuses here, before shared work.
    pub fn load() -> Result<Self, ContractError> {
        let mut user = crate::config::load_user_config()?;
        let selection = match user.as_mut() {
            Some(user) => crate::selection::apply(user),
            None => crate::selection::Outcome::Single,
        };
        let personal_root = user.as_ref().map(|user| user.personal.data_root.clone());
        let fd_attestation = crate::sandbox::attest_descriptors(personal_root.as_deref())?;
        let shared = match &user {
            Some(user) => user.shared()?,
            None => crate::config::codebase_only_shared(),
        };
        let company_env_present = std::env::var_os("KINBASE_COMPANY_URL").is_some();
        Ok(Self {
            mode: shared.mode,
            user,
            shared,
            fd_attestation,
            company_env_present,
            selection,
        })
    }

    /// What `status` and `doctor` say about Company selection under the
    /// named form (terminal output: it names Companies). `None` under the
    /// single form, whose output stays as it was.
    pub fn selection_report(&self, repo: Option<&std::path::Path>) -> Option<Value> {
        let user = self
            .user
            .as_ref()
            .filter(|user| !user.companies.is_empty())?;
        let companies: Vec<Value> = user
            .companies
            .iter()
            .map(|company| {
                let config = &company.config;
                json!({
                    "name": company.name,
                    "url": config.url,
                    "cache_root": config.cache_root.to_string_lossy(),
                    "company_id": crate::selection::cached_company_id(&config.cache_root),
                    "discovery_hints": company.discovery_hints,
                    "files": {
                        "root_public_key": config.root_public_key_file.exists(),
                        "facts_token": config.facts_token_file.exists(),
                        "admin_token": config.admin_token_file.as_ref().map(|path| path.exists()),
                        "client_key": config.client_key_file.exists(),
                        "maintainer_key": config.maintainer_key_file.exists(),
                        "cache": config.cache_root.join(crate::company::cache::CACHE_FILE).exists()
                    }
                })
            })
            .collect();
        let (outcome, reason, remediation) = match &self.selection {
            crate::selection::Outcome::Selected { name, reason } => {
                (json!({"selected": name}), *reason, None)
            }
            crate::selection::Outcome::Unselected => (
                Value::String("none".to_owned()),
                "no-evidence",
                Some("Add a discovery_hints pattern matching this repository's origin, or run `kinbase repo issue --company <name> --repo .`.".to_owned()),
            ),
            crate::selection::Outcome::Refused(refusal) => (
                Value::String("refused".to_owned()),
                refusal.reason,
                Some(refusal.remediation.clone()),
            ),
            crate::selection::Outcome::Single => (Value::Null, "single", None),
        };
        let evidence = repo.map(|repo| crate::selection::gather(&user.companies, repo).to_value());
        Some(json!({
            "form": "named",
            "companies": companies,
            "outcome": outcome,
            "reason": reason,
            "remediation": remediation,
            "evidence": evidence
        }))
    }

    /// `scrub_for_hook` applied to every string inside a JSON value, so a
    /// Company named like a JSON literal (`true`, `null`) can neither break
    /// the document nor be skipped.
    pub fn scrub_value_for_hook(&self, value: &mut Value) {
        fn walk(scrubber: &crate::selection::Scrubber, value: &mut Value) {
            match value {
                Value::String(text) => *text = scrubber.scrub(text),
                Value::Array(items) => items.iter_mut().for_each(|item| walk(scrubber, item)),
                Value::Object(map) => map.values_mut().for_each(|item| walk(scrubber, item)),
                _ => {}
            }
        }
        if let Some(scrubber) = self.hook_scrubber() {
            walk(&scrubber, value);
        }
    }

    /// Several Companies are configured (`[companies.<name>]`).
    pub fn named_form(&self) -> bool {
        self.user
            .as_ref()
            .is_some_and(|user| !user.companies.is_empty())
    }

    /// The refusal this invocation's Company selection ended in, if any.
    pub fn selection_refusal(&self) -> Option<ContractError> {
        match &self.selection {
            crate::selection::Outcome::Refused(refusal) => Some(refusal.error()),
            _ => None,
        }
    }

    /// The namespace for Personal-store keys whose meaning is Company-local
    /// (revocation watermarks: a cursor is one Company's counter). `None`
    /// under the single form keeps today's keys byte for byte.
    pub fn company_key_scope(&self) -> Option<String> {
        if !self.named_form() {
            return None;
        }
        let access = self.shared.company.as_ref()?;
        crate::selection::cached_company_id(&access.cache_root)
    }

    /// Text bound for a hook's output, with every other configured Company's
    /// name, URL, cache path and cached company_id replaced (named form only).
    pub fn scrub_for_hook(&self, text: &str) -> String {
        match self.hook_scrubber() {
            Some(scrubber) => scrubber.scrub(text),
            None => text.to_owned(),
        }
    }

    fn hook_scrubber(&self) -> Option<crate::selection::Scrubber> {
        let user = self
            .user
            .as_ref()
            .filter(|user| !user.companies.is_empty())?;
        let selected = match &self.selection {
            crate::selection::Outcome::Selected { name, .. } => Some(name.as_str()),
            _ => None,
        };
        Some(crate::selection::Scrubber::new(user, selected))
    }

    pub fn principal_id(&self) -> &str {
        &self.shared.principal_id
    }

    pub fn host_instance_id(&self) -> &str {
        &self.shared.host_instance_id
    }

    /// The private store for Personal provenance: the configured Personal
    /// data root, or the host-wide state store in Codebase-only mode.
    pub fn private_store(&self) -> Result<PrivateStore, ContractError> {
        match &self.user {
            Some(user) => PrivateStore::open_personal(&user.personal.data_root),
            None => PrivateStore::open_core(),
        }
    }

    /// The serialized prompt-budget Core store (host-wide).
    pub fn core_store(&self) -> Result<PrivateStore, ContractError> {
        PrivateStore::open_core()
    }

    pub fn personal_root(&self) -> Option<PathBuf> {
        self.user
            .as_ref()
            .map(|user| user.personal.data_root.clone())
    }

    /// Raw canary/identifier registry for the private routing path.
    pub fn scanner_registry(&self) -> Result<crate::scanner::Registry, ContractError> {
        let Some(user) = &self.user else {
            return Ok(crate::scanner::Registry::default());
        };
        let canaries = match &user.scanner.canary_file {
            Some(path) => read_lines(path, "canary registry")?,
            None => Vec::new(),
        };
        let identifiers = match &user.scanner.forbidden_identifier_file {
            Some(path) => read_lines(path, "forbidden identifier registry")?,
            None => Vec::new(),
        };
        Ok(crate::scanner::Registry::from_values(canaries, identifiers))
    }

    /// Company access from the configured endpoint only (C28: an
    /// environment-supplied endpoint is `PROCESSOR_UNAUTHORIZED` and
    /// receives zero bytes).
    pub fn company(&self) -> Result<Option<CompanyAccess>, ContractError> {
        if self.company_env_present {
            return Err(ContractError::new(
                "PROCESSOR_UNAUTHORIZED",
                "KINBASE_COMPANY_URL names a processor outside the configured authorization; no bytes were sent",
                "Configure the Company endpoint in the launcher user config; the environment cannot supply a processor.",
                false,
                crate::error::ExitCode::IntegrityFailure,
            )
            .with_detail(json!({"bytes_sent": 0, "shared_work_performed": false})));
        }
        let Some(access) = &self.shared.company else {
            return Ok(None);
        };
        let root = access.root_key()?;
        let cache = Cache::open(&access.cache_root)?;
        let client = Client::new(
            &access.url,
            access.facts_token.clone(),
            access.client_key()?,
            Some(root.clone()),
            access.cache_root.clone(),
            access.allow_non_loopback,
        )?;
        Ok(Some(CompanyAccess {
            client,
            cache,
            root,
            url: access.url.clone(),
        }))
    }

    /// Company cache only (no network), for offline/degraded reads. A cache
    /// that does not exist yet reads as cold and is not created by reading.
    pub fn company_cache(&self) -> Result<Option<(Cache, PublicKey)>, ContractError> {
        let Some(access) = &self.shared.company else {
            return Ok(None);
        };
        Ok(Some((
            Cache::open_for_read(&access.cache_root)?,
            access.root_key()?,
        )))
    }

    /// Company cache for a command that records something in it.
    pub fn company_cache_for_write(&self) -> Result<Option<(Cache, PublicKey)>, ContractError> {
        let Some(access) = &self.shared.company else {
            return Ok(None);
        };
        Ok(Some((Cache::open(&access.cache_root)?, access.root_key()?)))
    }

    pub fn company_port(&self) -> Option<u16> {
        self.shared
            .company
            .as_ref()
            .and_then(|access| {
                crate::http::parse_url(&access.url, access.allow_non_loopback).ok()
            })
            .map(|(_, port, _)| port)
    }

    /// Capability report for `doctor` (cli.md: every process reports its
    /// granted capability names, and the doctor must show that shared
    /// processes lack Personal). `processes` enumerates exactly the shared
    /// processes the launcher runs from the derived shared configuration;
    /// the launcher itself and the Personal worker are reported separately
    /// under `personal_processes` because they hold the Personal capability
    /// by design and are never part of the shared writer/projector graph.
    pub fn capability_report(&self) -> Value {
        let shared_names: Vec<&str> = {
            let mut names = vec!["codebase:read", "codebase:write"];
            if self.shared.company.is_some() {
                names.push("company:read");
                names.push("company:write");
            }
            names
        };
        let personal_root = self.personal_root();
        let shared_mentions_personal =
            serialized_shared_config_mentions_personal(&self.shared, personal_root.as_deref());
        json!({
            "processes": [
                {
                    "role": "shared-writer",
                    "granted_capabilities": shared_names,
                    "holds_personal_capability": false,
                    "personal_root_in_serialized_config": shared_mentions_personal
                },
                {
                    "role": "shared-projector",
                    "granted_capabilities": shared_names,
                    "holds_personal_capability": false,
                    "personal_root_in_serialized_config": shared_mentions_personal
                }
            ],
            "personal_processes": [
                {
                    "role": "launcher",
                    "granted_capabilities": ["config:read", "personal:open", "shared-config:derive", "sandbox:launch"],
                    "holds_personal_capability": self.user.is_some(),
                    "personal_root_in_serialized_config": false
                },
                {
                    "role": "personal-worker",
                    "granted_capabilities": ["personal:read", "personal:write", "extract", "route", "scan"],
                    "holds_personal_capability": self.user.is_some(),
                    "personal_root_in_serialized_config": false
                }
            ],
            "mode": self.mode,
            "fd_attestation": self.fd_attestation
        })
    }

    pub fn shared_config_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.shared).unwrap_or_default()
    }
}

fn serialized_shared_config_mentions_personal(
    shared: &SharedConfig,
    personal_root: Option<&std::path::Path>,
) -> bool {
    let Some(root) = personal_root else {
        return false;
    };
    let text = serde_json::to_string(shared).unwrap_or_default();
    text.contains(&root.to_string_lossy().to_string())
}

fn read_lines(path: &std::path::Path, role: &str) -> Result<Vec<String>, ContractError> {
    let text = crate::crypto::read_private_text(path, role)?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}
