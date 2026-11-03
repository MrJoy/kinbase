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
use std::sync::OnceLock;

#[derive(Clone)]
pub struct Launcher {
    pub mode: Mode,
    pub user: Option<UserConfig>,
    pub shared: SharedConfig,
    pub fd_attestation: Value,
    pub company_env_present: bool,
}

pub struct CompanyAccess {
    pub client: Client,
    pub cache: Cache,
    pub root: PublicKey,
    pub url: String,
}

impl Launcher {
    /// Load configuration and attest descriptors. Any inherited Personal or
    /// non-allowlisted descriptor refuses here, before shared work. The first
    /// load in a process attests; later loads reuse that launch-time record.
    pub fn load() -> Result<Self, ContractError> {
        let user = crate::config::load_user_config()?;
        let personal_root = user.as_ref().map(|user| user.personal.data_root.clone());
        // Inherited descriptors are fixed at launch. A later load in the same
        // process would also see descriptors the process opened itself (macOS
        // keeps two open after loading the native TLS roots), so attest once.
        static ATTESTATION: OnceLock<Value> = OnceLock::new();
        let fd_attestation = match ATTESTATION.get() {
            Some(attestation) => attestation.clone(),
            None => {
                let attestation = crate::sandbox::attest_descriptors(personal_root.as_deref())?;
                ATTESTATION.get_or_init(|| attestation).clone()
            }
        };
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
        })
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
        let client = Client::from_user_config(
            &access.url,
            access.facts_token.clone(),
            access.client_key()?,
            Some(root.clone()),
            access.cache_root.clone(),
            access.allow_non_loopback,
            self.user.as_ref(),
        )?
        .with_snapshot_timeout_seconds(access.snapshot_timeout_seconds);
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
                crate::http::parse_url(
                    &access.url,
                    access.allow_non_loopback,
                    self.user.as_ref().is_some_and(UserConfig::oidc_configured),
                )
                .ok()
            })
            .map(|(_, _, port, _)| port)
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

#[cfg(test)]
mod tests {
    use super::Launcher;

    // Runs the loads in a fresh child of this test binary, under a temp HOME and
    // XDG dirs, so sibling tests' descriptors and the live config play no part.
    #[test]
    fn a_later_load_ignores_descriptors_the_process_opened() {
        if std::env::var_os("KINBASE_RELOAD_PROBE").is_some() {
            // A sibling test can leak a descriptor into this child mid-spawn; start
            // clean, as a launch would.
            for fd in 3..1024 {
                // SAFETY: closing integer descriptors has no memory-safety preconditions.
                unsafe { libc::close(fd) };
            }
            Launcher::load().expect("first load at a clean start");
            let _open = std::fs::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
                .expect("open Cargo.toml");
            if let Err(error) = Launcher::load() {
                panic!("second load: {error}");
            }
            return;
        }
        let home = tempfile::tempdir().expect("temp HOME");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", "launcher::tests::a_later_load_ignores_descriptors_the_process_opened", "--test-threads=1"])
            .env("KINBASE_RELOAD_PROBE", "1")
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the probe");
        assert!(output.status.success(), "{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    }
}
