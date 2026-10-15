//! Company selection for the named form (`[companies.<name>]`, candidate
//! amendment 004). The launcher resolves at most one Company per invocation
//! from the repository the invocation acts on, and derives today's
//! single-Company configuration from it; nothing downstream sees more than
//! one Company. Selection only narrows: whenever the evidence on this machine
//! does not point at exactly one configured Company the answer is a refusal,
//! never a pick, because a wrong pick sends one organization's knowledge into
//! another organization's session.
//!
//! Evidence comes from configured Companies only:
//! - a Company *holds* a repository when its cache keeps a certificate for the
//!   UUID in `.kin/kinbase.toml` that verifies against its own root;
//! - its `discovery_hints` match the repository's normalized `origin`;
//! - its cache already pins that origin.
//!
//! The UUID is worktree bytes and a certificate binds no origin, so a copied
//! `.kin/` must not outvote the origin: every kind of evidence adds a
//! candidate and none overrides another.

use crate::config::{CompanyConfig, NamedCompany, UserConfig};
use crate::crypto::PublicKey;
use crate::error::ContractError;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// What an invocation acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A repository path: `--repo`, the hook envelope `cwd`, or the process
    /// cwd.
    Repo(PathBuf),
    /// `repo issue --company <name>` for a repository.
    Named { name: String, repo: PathBuf },
    /// `repo init`: the certificate being installed is one more holder.
    Install { repo: PathBuf, certificate: Value },
}

/// The outcome the launcher derived its configuration from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The single `[company]` form, or no Company configured at all.
    Single,
    /// The named form selected this Company.
    Selected { name: String, reason: &'static str },
    /// The named form found no Company for this target.
    Unselected,
    /// The named form refused to choose.
    Refused(Refusal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// `detail.reason`: company-ambiguous, certified-elsewhere,
    /// company-unverifiable, company-unknown, company-key-migration,
    /// identity-sharing-unconfirmed.
    pub reason: &'static str,
    /// Terminal text: may name Companies and paths. Never reaches a hook.
    pub message: String,
    pub remediation: String,
    pub detail: Value,
}

impl Refusal {
    pub fn error(&self) -> ContractError {
        ContractError::refused(
            "CONFIG_INVARIANT",
            self.message.clone(),
            self.remediation.clone(),
        )
        .with_detail(self.detail.clone())
    }
}

/// The diagnosis `doctor --repo` and `status` show for a repository.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    pub repository_uuid: Option<String>,
    pub origin: Option<String>,
    pub holders: Vec<String>,
    pub hint_matches: Vec<String>,
    pub pin_claims: Vec<String>,
    pub unreadable: Vec<String>,
}

impl Evidence {
    fn candidates(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .holders
            .iter()
            .chain(&self.hint_matches)
            .chain(&self.pin_claims)
            .cloned()
            .collect();
        all.sort();
        all.dedup();
        all
    }

    pub fn to_value(&self) -> Value {
        json!({
            "repository_uuid": self.repository_uuid,
            "origin": self.origin,
            "holders": self.holders,
            "hint_matches": self.hint_matches,
            "pin_claims": self.pin_claims,
            "unreadable": self.unreadable,
        })
    }
}

static TARGET: Mutex<Option<Target>> = Mutex::new(None);
static RESOLVED: Mutex<Option<(Target, Outcome, Evidence)>> = Mutex::new(None);

/// Name what this invocation acts on. Called by the CLI once arguments are
/// parsed and by hook dispatch once the envelope names its `cwd`; until then
/// the process cwd is the target.
pub fn set_target(target: Target) {
    if let Ok(mut slot) = TARGET.lock() {
        *slot = Some(target);
    }
}

pub fn target() -> Target {
    TARGET
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .unwrap_or_else(|| {
            Target::Repo(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
        })
}

/// Narrow `user` to the Company this invocation's target resolves to:
/// `user.company` becomes that Company (or stays empty). The outcome is
/// cached per target, since `store::store_root` reloads the config on every
/// call and the evidence costs a `git` call and a cache read.
pub fn apply(user: &mut UserConfig) -> Outcome {
    if user.companies.is_empty() {
        return Outcome::Single;
    }
    let target = target();
    let cached = RESOLVED
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .filter(|(resolved_for, _, _)| *resolved_for == target);
    let (outcome, _) = match cached {
        Some((_, outcome, evidence)) => (outcome, evidence),
        None => {
            let (outcome, evidence) = resolve(user, &target);
            if let Ok(mut slot) = RESOLVED.lock() {
                *slot = Some((target.clone(), outcome.clone(), evidence.clone()));
            }
            (outcome, evidence)
        }
    };
    user.company = match &outcome {
        Outcome::Selected { name, .. } => user
            .companies
            .iter()
            .find(|company| &company.name == name)
            .map(|company| company.config.clone()),
        _ => None,
    };
    outcome
}

/// Resolve a target against every configured Company. Public for `doctor`,
/// which reports the evidence alongside the outcome.
pub fn resolve(user: &UserConfig, target: &Target) -> (Outcome, Evidence) {
    match target {
        Target::Repo(repo) => {
            let evidence = gather(&user.companies, repo);
            (decide(user, &evidence, None), evidence)
        }
        Target::Named { name, repo } => {
            let evidence = gather(&user.companies, repo);
            if !user.companies.iter().any(|company| &company.name == name) {
                let configured: Vec<&str> = user
                    .companies
                    .iter()
                    .map(|company| company.name.as_str())
                    .collect();
                // `--company` is raw command-line text; only a well-formed
                // name is echoed, never control or bidi characters.
                let message = if crate::config::valid_company_name(name) {
                    format!("no configured Company is named `{name}`")
                } else {
                    "`--company` is not a valid Company name (1-32 characters of a-z, 0-9 and '-')"
                        .to_owned()
                };
                return (
                    Outcome::Refused(Refusal {
                        reason: "company-unknown",
                        message,
                        remediation: format!(
                            "Pass one of the configured names: {}.",
                            configured.join(", ")
                        ),
                        detail: json!({"reason": "company-unknown"}),
                    }),
                    evidence,
                );
            }
            if let Some(refusal) = unreadable(&evidence) {
                return (Outcome::Refused(refusal), evidence);
            }
            let elsewhere: Vec<String> = evidence
                .holders
                .iter()
                .chain(&evidence.pin_claims)
                .filter(|other| *other != name)
                .cloned()
                .collect();
            if !elsewhere.is_empty() {
                return (
                    Outcome::Refused(Refusal {
                        reason: "certified-elsewhere",
                        message: format!(
                            "this repository is already certified or pinned by Company {}",
                            quoted(&elsewhere)
                        ),
                        remediation: new_identity_remediation(name),
                        detail: json!({"reason": "certified-elsewhere", "evidence": evidence.to_value()}),
                    }),
                    evidence,
                );
            }
            // `repo init` counts every hint beside the certificate (S-03), so
            // a certificate issued past another Company's hint would only be
            // refused when installed.
            let hinted: Vec<String> = evidence
                .hint_matches
                .iter()
                .filter(|other| *other != name)
                .cloned()
                .collect();
            if !hinted.is_empty() {
                return (
                    Outcome::Refused(Refusal {
                        reason: "company-ambiguous",
                        message: format!(
                            "the discovery hints of Company {} match this repository's origin",
                            quoted(&hinted)
                        ),
                        remediation: format!(
                            "If this repository belongs to Company `{name}`, narrow the other Company's discovery_hints in the user config so they no longer match its origin, then issue again."
                        ),
                        detail: json!({"reason": "company-ambiguous", "evidence": evidence.to_value()}),
                    }),
                    evidence,
                );
            }
            (checked(user, name, "named"), evidence)
        }
        Target::Install { repo, certificate } => {
            let mut evidence = gather(&user.companies, repo);
            let signer = PublicKey::verify_document("repo-certificate", certificate);
            let mut signers = Vec::new();
            for company in &user.companies {
                match PublicKey::load(
                    &company.config.root_public_key_file,
                    "Company root public key",
                ) {
                    Ok(root) if Some(&root) == signer.as_ref() => {
                        signers.push(company.name.clone())
                    }
                    Ok(_) => {}
                    Err(_) => evidence.unreadable.push(company.name.clone()),
                }
            }
            // A root that could not be read might be the signer's: say that,
            // not that no Company signed.
            if let Some(refusal) = unreadable(&evidence) {
                return (Outcome::Refused(refusal), evidence);
            }
            if signers.len() != 1 {
                return (
                    Outcome::Refused(Refusal {
                        reason: "company-ambiguous",
                        message: if signers.is_empty() {
                            "no configured Company root verifies this certificate".to_owned()
                        } else {
                            format!("Companies {} share the certificate's root", quoted(&signers))
                        },
                        remediation: "Install a certificate issued by one configured Company (`kinbase repo issue --company <name>`).".to_owned(),
                        detail: json!({"reason": "company-ambiguous"}),
                    }),
                    evidence,
                );
            }
            evidence.holders.push(signers[0].clone());
            evidence.holders.sort();
            evidence.holders.dedup();
            (decide(user, &evidence, Some("certificate")), evidence)
        }
    }
}

fn decide(user: &UserConfig, evidence: &Evidence, reason: Option<&'static str>) -> Outcome {
    if let Some(refusal) = unreadable(evidence) {
        return Outcome::Refused(refusal);
    }
    let candidates = evidence.candidates();
    match candidates.as_slice() {
        [] => Outcome::Unselected,
        [only] => {
            let reason = reason.unwrap_or(if evidence.holders.contains(only) {
                "held-certificate"
            } else if evidence.pin_claims.contains(only) {
                "pinned-origin"
            } else {
                "discovery-hint"
            });
            checked(user, only, reason)
        }
        several => Outcome::Refused(Refusal {
            reason: "company-ambiguous",
            message: format!(
                "Companies {} each have a claim on this repository (holders: {}; discovery hints: {}; pinned origin: {})",
                quoted(several),
                list(&evidence.holders),
                list(&evidence.hint_matches),
                list(&evidence.pin_claims)
            ),
            remediation: "If this worktree was copied or forked from another organization's repository, give it its own identity: delete .kin/kinbase.toml, then run `kinbase repo issue --company <name> --repo .` and `kinbase repo init`. If a discovery hint is too broad, narrow it in the user config.".to_owned(),
            detail: json!({"reason": "company-ambiguous", "evidence": evidence.to_value()}),
        }),
    }
}

/// Selecting a Company also checks the identity it would present: a
/// defaulted per-Company key must not be minted beside the single-form key a
/// converted configuration still has, and a shared maintainer key must be a
/// stated choice.
fn checked(user: &UserConfig, name: &str, reason: &'static str) -> Outcome {
    let Some(company) = user.companies.iter().find(|company| company.name == name) else {
        return Outcome::Unselected;
    };
    if let Some(refusal) = key_migration(user, company) {
        return Outcome::Refused(refusal);
    }
    if let Some(refusal) = identity_sharing(user) {
        return Outcome::Refused(refusal);
    }
    Outcome::Selected {
        name: name.to_owned(),
        reason,
    }
}

fn key_migration(user: &UserConfig, company: &NamedCompany) -> Option<Refusal> {
    let config_dir = user.path.parent()?;
    for (defaulted, path, legacy, field) in [
        (
            company.client_key_defaulted,
            &company.config.client_key_file,
            config_dir.join("client.key"),
            "client_key_file",
        ),
        (
            company.maintainer_key_defaulted,
            &company.config.maintainer_key_file,
            config_dir.join("maintainer.key"),
            "maintainer_key_file",
        ),
    ] {
        if defaulted && !path.exists() && legacy.exists() {
            return Some(Refusal {
                reason: "company-key-migration",
                message: format!(
                    "Company `{}` would mint a new key at {} while the single-form key {} exists",
                    company.name,
                    path.display(),
                    legacy.display()
                ),
                remediation: format!(
                    "If `{}` is the Company that key was registered with, add `{field} = \"{}\"` to [companies.{}]; otherwise name a new path explicitly.",
                    company.name,
                    legacy.display(),
                    company.name
                ),
                detail: json!({"reason": "company-key-migration", "field": field}),
            });
        }
    }
    None
}

fn identity_sharing(user: &UserConfig) -> Option<Refusal> {
    if user.companies.len() < 2 || !user.identity_maintainer_key || user.share_maintainer_key {
        return None;
    }
    Some(Refusal {
        reason: "identity-sharing-unconfirmed",
        message: "[identity] maintainer_key_file would present one maintainer key to every configured Company".to_owned(),
        remediation: "Set `share_maintainer_key = true` under [identity] to present one key to every Company, or move the path to each [companies.<name>] maintainer_key_file.".to_owned(),
        detail: json!({"reason": "identity-sharing-unconfirmed"}),
    })
}

fn unreadable(evidence: &Evidence) -> Option<Refusal> {
    if evidence.unreadable.is_empty() {
        return None;
    }
    Some(Refusal {
        reason: "company-unverifiable",
        message: format!(
            "could not read the certificate evidence of Company {}; choosing among the rest could pick the wrong organization",
            quoted(&evidence.unreadable)
        ),
        remediation: "Run `kinbase doctor --repo .` to see which root key, cache or certificate is unreadable, and repair it.".to_owned(),
        detail: json!({"reason": "company-unverifiable", "evidence": evidence.to_value()}),
    })
}

fn new_identity_remediation(name: &str) -> String {
    format!(
        "A repository that was copied, forked or moved needs its own identity: delete .kin/kinbase.toml, then run `kinbase repo issue --company {name} --repo .` and `kinbase repo init`."
    )
}

/// Collect evidence for a repository from every configured Company.
pub fn gather(companies: &[NamedCompany], repo: &Path) -> Evidence {
    let mut evidence = Evidence::default();
    let Ok(repository) = crate::codebase::Repository::discover(repo) else {
        return evidence;
    };
    evidence.repository_uuid = repository.uuid_hint().map(str::to_owned);
    evidence.origin = crate::codebase::git(&repository.root, &["remote", "get-url", "origin"])
        .ok()
        .map(|remote| crate::repository::normalize_hint(&remote))
        .filter(|origin| !origin.is_empty());
    for company in companies {
        if let Some(origin) = &evidence.origin
            && company
                .discovery_hints
                .iter()
                .any(|pattern| crate::config::hint_matches(pattern, origin))
        {
            evidence.hint_matches.push(company.name.clone());
        }
        match cache_evidence(
            &company.config,
            evidence.repository_uuid.as_deref(),
            evidence.origin.as_deref(),
        ) {
            Ok((holds, pins)) => {
                if holds {
                    evidence.holders.push(company.name.clone());
                }
                if pins {
                    evidence.pin_claims.push(company.name.clone());
                }
            }
            Err(()) => evidence.unreadable.push(company.name.clone()),
        }
    }
    evidence
}

/// Whether this Company's cache holds a verifying certificate for `uuid`
/// and whether it pins `origin`. Read-only: another Company's cache is
/// evidence here, never something to repair or create.
fn cache_evidence(
    company: &CompanyConfig,
    uuid: Option<&str>,
    origin: Option<&str>,
) -> Result<(bool, bool), ()> {
    let mut holds = false;
    if let Some(uuid) = uuid {
        let path = company
            .cache_root
            .join("repositories")
            .join(uuid)
            .join("certificate.json");
        // `exists()` reads a permission error as absence, and an absent
        // certificate lets another Company win; only NotFound is absence.
        if present(&path)? {
            let root = PublicKey::load(&company.root_public_key_file, "Company root public key")
                .map_err(|_| ())?;
            let bytes = std::fs::read(&path).map_err(|_| ())?;
            let certificate = crate::json::parse_strict_value(&bytes).map_err(|_| ())?;
            holds = PublicKey::verify_document("repo-certificate", &certificate)
                .is_some_and(|signer| signer == root)
                && certificate.get("repository_uuid").and_then(Value::as_str) == Some(uuid);
        }
    }
    let pins = match origin {
        Some(origin) => cache_pins(&company.cache_root, origin)?,
        None => false,
    };
    Ok((holds, pins))
}

fn cache_pins(cache_root: &Path, origin: &str) -> Result<bool, ()> {
    let path = cache_root.join(crate::company::cache::CACHE_FILE);
    if !present(&path)? {
        return Ok(false);
    }
    let connection = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ())?;
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pins WHERE hint = ?1",
            [origin],
            |row| row.get(0),
        )
        .map_err(|_| ())?;
    Ok(count > 0)
}

/// Whether `path` exists, where any answer but yes or NotFound (a
/// permission error, an unreadable parent) is unreadable evidence.
fn present(path: &Path) -> Result<bool, ()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(()),
    }
}

fn cached_snapshot(cache_root: &Path) -> Option<Value> {
    let path = cache_root.join(crate::company::cache::CACHE_FILE);
    let connection = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let bytes: Vec<u8> = connection
        .query_row("SELECT bytes FROM snapshot WHERE id = 1", [], |row| {
            row.get(0)
        })
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The verified snapshot's company_id in a Company's cache, read-only.
/// `store_snapshot` writes the snapshot row before its meta rows, so a crash
/// between them leaves a verified snapshot with no `company_id` row; the
/// snapshot itself still names its Company.
pub fn cached_company_id(cache_root: &Path) -> Option<String> {
    let path = cache_root.join(crate::company::cache::CACHE_FILE);
    if !path.exists() {
        return None;
    }
    let connection = rusqlite::Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    connection
        .query_row(
            "SELECT value FROM meta WHERE key = 'company_id'",
            [],
            |row| row.get(0),
        )
        .ok()
        .or_else(|| {
            cached_snapshot(cache_root)?
                .get("company_id")?
                .as_str()
                .map(str::to_owned)
        })
        .filter(|value: &String| !value.is_empty())
}

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name| format!("`{name}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn list(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

/// The text hook output may carry about selection: code constants only.
/// Company names, ids, URLs and paths stay on the user's terminal.
pub const HOOK_REFUSED_NOTICE: &str = "CONFIG_INVARIANT: Kinbase could not choose a Company for this repository, so no Company or trusted Codebase facts were loaded; run `kinbase status` in this repository";
pub const HOOK_UNSELECTED_NOTICE: &str = "Kinbase found no Company for this repository; no Company facts were loaded; run `kinbase doctor --repo .` to see why";

/// Replace every other configured Company's name, URL, cache path and cached
/// company_id in text bound for a hook's output. Hook output reaches the coding session and its
/// model provider; under the named form a Company's existence is itself
/// confidential to the other organizations. Gathered once, so a hook
/// response is scrubbed value by value without reopening every Company's
/// cache for each string.
pub struct Scrubber {
    needles: Vec<String>,
    selected_id: Option<String>,
}

impl Scrubber {
    pub fn new(user: &UserConfig, selected: Option<&str>) -> Self {
        let mut needles: Vec<String> = Vec::new();
        let mut selected_id = None;
        // The selected Company's own facts may name it; every other Company
        // is what this session must not learn of.
        for company in &user.companies {
            if Some(company.name.as_str()) == selected {
                selected_id = cached_company_id(&company.config.cache_root);
                continue;
            }
            needles.push(company.config.url.trim_end_matches('/').to_owned());
            needles.push(company.config.cache_root.display().to_string());
            if let Some(id) = cached_company_id(&company.config.cache_root) {
                needles.push(id);
            }
            needles.push(company.name.clone());
        }
        // Longest first, so a URL is replaced before a name inside it.
        needles.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
        needles.dedup();
        Self {
            needles,
            selected_id,
        }
    }

    pub fn scrub(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for needle in &self.needles {
            text = replace_word(&text, needle);
        }
        replace_bound_destinations(&text, self.selected_id.as_deref())
    }
}

/// Replace the company_id in every `company:<id>` destination other than the
/// selected Company's. A held candidate names the Company it is bound to,
/// and that Company's cache may be unreadable (`company-unverifiable`), so
/// its id cannot be known as a needle; the destination's shape is enough.
fn replace_bound_destinations(text: &str, selected_id: Option<&str>) -> String {
    const PREFIX: &str = "company:";
    let ends_id = |c: char| c.is_whitespace() || "\"'`,;()[]{}<>".contains(c);
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(PREFIX) {
        let before = rest[..at]
            .chars()
            .next_back()
            .or_else(|| out.chars().next_back());
        out.push_str(&rest[..at + PREFIX.len()]);
        rest = &rest[at + PREFIX.len()..];
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            continue;
        }
        let length = rest.find(ends_id).unwrap_or(rest.len());
        let id = &rest[..length];
        if id.is_empty() || id == "root" || Some(id) == selected_id {
            continue;
        }
        out.push_str("[company]");
        rest = &rest[length..];
    }
    out.push_str(rest);
    out
}

/// Replace `needle` where it stands as a whole token: a Company named `api`
/// must not turn "rapid" into "r[company]d".
fn replace_word(text: &str, needle: &str) -> String {
    if needle.is_empty() {
        return text.to_owned();
    }
    let word = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(needle) {
        let before = rest[..at].chars().next_back();
        let after = rest[at + needle.len()..].chars().next();
        out.push_str(&rest[..at]);
        if before.is_some_and(word) || after.is_some_and(word) {
            out.push_str(needle);
        } else {
            out.push_str("[company]");
        }
        rest = &rest[at + needle.len()..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::{cached_company_id, replace_bound_destinations, replace_word};

    #[test]
    fn a_snapshot_whose_meta_rows_were_lost_still_names_its_company() {
        // `store_snapshot` writes the snapshot row before its meta rows; a
        // crash between them leaves no `company_id` row.
        let temp = tempfile::TempDir::new().unwrap();
        let root = temp.path().join("cache");
        std::fs::create_dir_all(&root).unwrap();
        let connection =
            rusqlite::Connection::open(root.join(crate::company::cache::CACHE_FILE)).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE snapshot(id INTEGER PRIMARY KEY, bytes BLOB, digest TEXT, stored_at TEXT);
                 CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);",
            )
            .unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"company_id": "cid-a"})).unwrap();
        connection
            .execute(
                "INSERT INTO snapshot(id, bytes, digest, stored_at) VALUES (1, ?1, '', '')",
                [bytes],
            )
            .unwrap();
        assert_eq!(cached_company_id(&root).as_deref(), Some("cid-a"));
    }

    #[test]
    fn scrubbing_replaces_every_bound_destination_but_the_selected_one() {
        assert_eq!(
            replace_bound_destinations(
                "destination: company:cid-a, then company:cid-b",
                Some("cid-b")
            ),
            "destination: company:[company], then company:cid-b"
        );
        assert_eq!(
            replace_bound_destinations("company:root mycompany:cid-a company:", None),
            "company:root mycompany:cid-a company:"
        );
        assert_eq!(
            replace_bound_destinations("company:cid-a", None),
            "company:[company]"
        );
    }

    #[test]
    fn scrubbing_replaces_whole_tokens_only() {
        assert_eq!(
            replace_word("api serves rapid api-v2 (api)", "api"),
            "[company] serves rapid api-v2 ([company])"
        );
        assert_eq!(
            replace_word("see http://127.0.0.1:8421/x", "http://127.0.0.1:8421"),
            "see [company]/x"
        );
    }
}
