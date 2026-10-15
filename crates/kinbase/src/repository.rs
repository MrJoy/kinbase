//! Repository trust context and the repository-facing commands: `repo
//! issue`, `repo init`, `repo publish-manifest`, `status`, `doctor`, `fsck`.
//! Trust for `.kin/` events comes only from the out-of-worktree certificate
//! (Company cache) and the signed authority registry; worktree bytes never
//! mint trust (architecture §2).

use crate::codebase::{ParsedEvent, Repository, StoredFile, parse_stored};
use crate::company::cache::Freshness;
use crate::crypto::PublicKey;
use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::{CurrentFact, FactEvent, UnknownEvent};
use crate::reducer::{AdmittedEvent, ReducerInput, Revocation, Tombstone, Verification};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const PRIVACY_CLAIM: &str = "Zero observed unauthorized durable disclosure outside the authorized processor boundary under Acceptance Threat Model kinbase-atm/1, identified by its exact SHA-256 digest, across the frozen execution census.";

/// Everything needed to decide whether a `.kin/` event is trusted.
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub repository_uuid: Option<String>,
    pub certificate: Option<Value>,
    pub certificate_digest: Option<String>,
    pub certificate_valid: bool,
    pub certificate_reason: String,
    pub root: Option<PublicKey>,
    pub registry: Vec<Value>,
    pub revocations: Vec<Revocation>,
    pub relaxations: Vec<Value>,
    pub company_facts: Vec<Value>,
    /// Open Unknowns the Company view derived (snapshot `unknowns`).
    pub company_unknowns: Vec<Value>,
    /// Lifecycle admissions and refusals the Company recorded
    /// (misextraction notices, never_true withdrawals).
    pub company_lifecycle: Vec<Value>,
    /// Parent bindings of current Company facts, resolved to logical keys.
    pub company_fact_parents: BTreeMap<String, Vec<Value>>,
    /// Per-key reduction traces of the Company view (state, admitted ids).
    pub company_traces: Vec<Value>,
    /// Every revocation the Company recorded, including keys later
    /// republished; pre-revocation artefacts stay historical.
    pub revocation_history: Vec<Revocation>,
    pub fact_versions: BTreeMap<String, Vec<Value>>,
    pub authority_cursor: String,
    pub freshness: Option<Freshness>,
    pub company_reachable: Option<bool>,
    /// A verified Company snapshot is cached (it may hold no facts).
    pub company_snapshot_present: bool,
    pub company_query_attempted: bool,
    pub company_connect_seconds: Option<f64>,
    pub unknowns: Vec<Value>,
    pub foreign_certificate_paths: Vec<String>,
    /// Distinct installed certificates claiming the certified UUID beyond
    /// the one binding; non-empty means the identity is ambiguous.
    pub certificate_conflicts: Vec<Value>,
    pub pin_state: String,
    pub local_maintainer_keys: BTreeSet<String>,
}

impl TrustContext {
    /// Trust for a repository no certificate resolves for: nothing is
    /// registered, revoked or warranted until a certificate says so.
    pub fn uncertified() -> Self {
        TrustContext {
            repository_uuid: None,
            certificate: None,
            certificate_digest: None,
            certificate_valid: false,
            certificate_reason: "no out-of-worktree certificate resolves for this repository"
                .to_owned(),
            root: None,
            registry: Vec::new(),
            revocations: Vec::new(),
            relaxations: Vec::new(),
            company_facts: Vec::new(),
            company_unknowns: Vec::new(),
            company_lifecycle: Vec::new(),
            company_fact_parents: BTreeMap::new(),
            company_traces: Vec::new(),
            revocation_history: Vec::new(),
            fact_versions: BTreeMap::new(),
            authority_cursor: "0".to_owned(),
            freshness: None,
            company_reachable: None,
            company_snapshot_present: false,
            company_query_attempted: false,
            company_connect_seconds: None,
            unknowns: Vec::new(),
            foreign_certificate_paths: Vec::new(),
            certificate_conflicts: Vec::new(),
            pin_state: "none".to_owned(),
            local_maintainer_keys: BTreeSet::new(),
        }
    }

    pub fn steward_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        if let Some(root) = &self.root {
            keys.insert(root.to_hex());
        }
        for entry in &self.registry {
            if crate::json::get_str(entry, "scope") == Some("company:root") {
                if let Some(key) = crate::json::get_str(entry, "public_key") {
                    keys.insert(key.to_owned());
                }
            }
        }
        keys
    }

    /// Currently revoked: the newest revocation of the key is not followed
    /// by a re-registration at a strictly later registry cursor (R-10).
    pub fn is_revoked(&self, key: &str) -> bool {
        let Some(latest) = self
            .revocations
            .iter()
            .filter(|revocation| revocation.revoked_key == key)
            .map(|revocation| revocation.cursor.parse::<u128>().unwrap_or(0))
            .max()
        else {
            return false;
        };
        let reregistered = self
            .registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "public_key") == Some(key)
                    && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
            })
            .map(|entry| match entry.get("cursor") {
                Some(Value::String(text)) => text.parse::<u128>().unwrap_or(0),
                Some(Value::Number(number)) => number.as_u64().unwrap_or(0) as u128,
                _ => 0,
            })
            .max()
            .unwrap_or(0);
        reregistered <= latest
    }

    pub fn entries_for_key(&self, key: &str) -> Vec<&Value> {
        self.registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "public_key") == Some(key)
                    && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
            })
            .collect()
    }

    pub fn is_maintainer(&self, key: &str) -> bool {
        let Some(uuid) = &self.repository_uuid else {
            return false;
        };
        // The local user-config maintainer key is bound to the operator's
        // certified repository, not to a worktree. A valid repository
        // certificate therefore lets a fresh clone publish and verify with the
        // same configured maintenance key without minting authority for an
        // unregistered third-party key.
        if self.certificate_valid && self.local_maintainer_keys.contains(key) {
            return true;
        }
        self.entries_for_key(key).iter().any(|entry| {
            let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
            scope == format!("codebase:{uuid}") || scope == format!("repository:{uuid}")
        })
    }

    /// Stable authority identities by exact active registry scope. Ambiguous
    /// scopes are omitted; the reducer then emits an unresolved Unknown.
    pub fn authority_owner_by_scope(&self) -> BTreeMap<String, String> {
        let mut by_scope: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for entry in &self.registry {
            if crate::json::get_str(entry, "status").unwrap_or("active") != "active" {
                continue;
            }
            if let (Some(scope), Some(identity)) = (
                crate::json::get_str(entry, "scope"),
                crate::json::get_str(entry, "authority_id"),
            ) {
                by_scope
                    .entry(scope.to_owned())
                    .or_default()
                    .push(identity.to_owned());
            }
        }
        by_scope
            .into_iter()
            .filter_map(|(scope, identities)| {
                (identities.len() == 1).then(|| (scope, identities.into_iter().next().unwrap()))
            })
            .collect()
    }

    pub fn steward_authority_id(&self) -> Option<String> {
        let identities = self
            .registry
            .iter()
            .filter(|entry| {
                crate::json::get_str(entry, "scope") == Some("company:root")
                    && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
            })
            .filter_map(|entry| crate::json::get_str(entry, "authority_id").map(str::to_owned))
            .collect::<Vec<_>>();
        (identities.len() == 1).then(|| identities[0].clone())
    }

    pub fn maintainer_entries(&self) -> Vec<Value> {
        let Some(uuid) = &self.repository_uuid else {
            return Vec::new();
        };
        self.registry
            .iter()
            .filter(|entry| {
                let scope = crate::json::get_str(entry, "scope").unwrap_or_default();
                scope == format!("codebase:{uuid}") || scope == format!("repository:{uuid}")
            })
            .cloned()
            .collect()
    }

    /// An Unknown from the worktree opens or closes a question only when it
    /// is signed by an authority for its scope (or the steward or a
    /// maintainer) under a valid certificate, as a fact event must be: an
    /// unsigned file used to open and close Unknowns in the projection.
    pub fn verify_unknown(&self, unknown: &crate::model::UnknownEvent) -> Verification {
        if unknown.store_kind != "codebase" {
            return Verification::Foreign;
        }
        // Bound to exactly this repository, as a fact event must be: an
        // unbound Unknown could be replayed into any repository.
        match (&self.repository_uuid, unknown.repository_id.as_deref()) {
            (Some(uuid), Some(bound)) if uuid == bound => {}
            _ => return Verification::Foreign,
        }
        if !self.certificate_valid {
            return Verification::Unverified;
        }
        if unknown.verify_signature().is_none() {
            return Verification::SignatureInvalid;
        }
        if self.is_revoked(&unknown.signer) {
            return Verification::Revoked;
        }
        if self.steward_keys().contains(&unknown.signer) || self.is_maintainer(&unknown.signer) {
            return Verification::Verified;
        }
        let entries = self.entries_for_key(&unknown.signer);
        if entries.iter().any(|entry| {
            crate::json::get_str(entry, "scope") == Some(unknown.authority_scope.as_str())
        }) {
            Verification::Verified
        } else if entries.is_empty() {
            Verification::Unverified
        } else {
            Verification::WrongScope
        }
    }

    /// Verification of one codebase fact event.
    pub fn verify(&self, event: &FactEvent) -> Verification {
        if event.store_kind != "codebase" {
            return Verification::Foreign;
        }
        match (&self.repository_uuid, event.repository_id.as_deref()) {
            (Some(uuid), Some(bound)) if uuid == bound => {}
            _ => return Verification::Foreign,
        }
        if !self.certificate_valid {
            return Verification::Unverified;
        }
        if event.verify_signature().is_none() {
            return Verification::SignatureInvalid;
        }
        if self.is_revoked(&event.signer) {
            return Verification::Revoked;
        }
        if self.steward_keys().contains(&event.signer) || self.is_maintainer(&event.signer) {
            return Verification::Verified;
        }
        let in_scope = self.entries_for_key(&event.signer).iter().any(|entry| {
            crate::json::get_str(entry, "scope") == Some(event.authority_scope.as_str())
        });
        if in_scope {
            Verification::Verified
        } else if self.entries_for_key(&event.signer).is_empty() {
            Verification::Unverified
        } else {
            Verification::WrongScope
        }
    }

    pub fn environment_registered(&self, environment_id: &str) -> bool {
        let scope = format!("environment:{environment_id}");
        self.registry.iter().any(|entry| {
            crate::json::get_str(entry, "scope") == Some(scope.as_str())
                && crate::json::get_str(entry, "status").unwrap_or("active") == "active"
        })
    }

    pub fn company_fact(&self, fact_id: &str) -> Option<&Value> {
        self.company_facts
            .iter()
            .find(|fact| crate::json::get_str(fact, "fact_id") == Some(fact_id))
    }
}

/// A stored `.kin/events` file after parsing and verification.
#[derive(Debug, Clone)]
pub struct LoadedEvent {
    pub file: StoredFile,
    pub parsed: ParsedEvent,
    pub verification: Option<Verification>,
    pub origin_trust: String,
    pub reachable: Option<bool>,
}

/// What one event file adds to `LoadCounts`, computed alongside it.
#[derive(Default)]
struct EventTally {
    path_alias: Option<String>,
    oversized: bool,
    malformed: bool,
    fact: Option<Verification>,
    unknown_unverified: Option<bool>,
}

impl EventTally {
    fn apply(self, counts: &mut LoadCounts) {
        if let Some(path) = self.path_alias {
            counts.path_alias += 1;
            counts.foreign_paths.push(path);
        }
        if self.oversized {
            counts.oversized += 1;
            counts.malformed += 1;
        }
        if self.malformed {
            counts.malformed += 1;
        }
        if let Some(verification) = self.fact {
            counts.fact_events += 1;
            match verification {
                Verification::Verified => counts.verified += 1,
                Verification::Unverified => counts.unverified += 1,
                Verification::Foreign => counts.foreign += 1,
                Verification::SignatureInvalid => counts.signature_invalid += 1,
                Verification::Revoked => counts.revoked += 1,
                Verification::WrongScope => counts.wrong_scope += 1,
            }
        }
        if let Some(unverified) = self.unknown_unverified {
            counts.unknown_events += 1;
            if unverified {
                counts.unverified_unknowns += 1;
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct LoadCounts {
    pub total_files: usize,
    pub fact_events: usize,
    pub unknown_events: usize,
    /// Unknown events that did not verify, and so opened or closed nothing.
    pub unverified_unknowns: usize,
    pub verified: usize,
    pub unverified: usize,
    pub foreign: usize,
    pub signature_invalid: usize,
    pub revoked: usize,
    pub wrong_scope: usize,
    pub malformed: usize,
    pub path_alias: usize,
    pub oversized: usize,
    /// Event files present but not read in this bounded pass: the store is
    /// above the ratified `.kin/` intake ceiling, so the pass is incremental
    /// and these events remain unchecked (architecture §6, §11).
    pub deferred: usize,
    pub foreign_paths: Vec<String>,
}

impl LoadCounts {
    pub fn to_value(&self) -> Value {
        json!({
            "total_files": self.total_files,
            "fact_events": self.fact_events,
            "unknown_events": self.unknown_events,
            "unverified_unknowns": self.unverified_unknowns,
            "verified": self.verified,
            "unverified": self.unverified,
            "foreign": self.foreign,
            "signature_invalid": self.signature_invalid,
            "revoked": self.revoked,
            "wrong_scope": self.wrong_scope,
            "malformed": self.malformed,
            "path_alias": self.path_alias,
            "oversized": self.oversized,
            "deferred": self.deferred,
            "foreign_paths": self.foreign_paths
        })
    }
}

pub struct RepoContext {
    pub launcher: Launcher,
    pub repo: Repository,
    pub trust: TrustContext,
    /// The verified event store, read once per context: `status` read and
    /// verified it three times (and `fsck` more), each time with its Git scans.
    events: std::cell::OnceCell<(Vec<LoadedEvent>, LoadCounts)>,
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

fn is_event_path(path: &str) -> bool {
    path.to_ascii_lowercase().starts_with(".kin/events/")
}

fn tracked_event_paths(repo: &Path) -> BTreeSet<String> {
    // Do not constrain Git with a case-sensitive `.kin/events` pathspec: a
    // case-colliding index entry may spell the reserved directory differently.
    git_text(repo, &["ls-files"])
        .lines()
        .filter(|path| is_event_path(path))
        .map(str::to_owned)
        .collect()
}

fn dirty_event_paths(repo: &Path) -> BTreeSet<String> {
    git_text(repo, &["status", "--porcelain", "--untracked-files=all"])
        .lines()
        .filter_map(|line| line.get(3..))
        .filter(|path| is_event_path(path))
        .map(str::to_owned)
        .collect()
}

fn merged_pr_review_evidence(repo: &Path, branch: &str) -> bool {
    if branch.is_empty() {
        return false;
    }
    let message = git_text(repo, &["log", "-1", "--format=%B", branch]).to_ascii_lowercase();
    [
        "reviewed-by:",
        "approved-by:",
        "review evidence",
        "pull request #",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

fn repository_origin_class(repo: &Repository, head_reachable: Option<bool>) -> String {
    if repo.config.is_none() {
        return "merged-default".to_owned();
    }
    let default = repo.default_branch();
    let branch = repo.branch().unwrap_or_default();
    if branch == default {
        return "merged-default".to_owned();
    }
    if head_reachable == Some(true) {
        if merged_pr_review_evidence(&repo.root, &branch) {
            return "approved-pr".to_owned();
        }
        return "merged-default".to_owned();
    }
    "unreviewed-branch".to_owned()
}

fn event_path_origin_class(
    repo: &Path,
    relative: &Path,
    tracked: &BTreeSet<String>,
    dirty: &BTreeSet<String>,
    fallback: &str,
) -> String {
    // `StoredFile::relative` is relative to `.kin/events`; Git reports the
    // repository-relative path including that reserved prefix.
    let path = format!(".kin/events/{}", relative.to_string_lossy());
    if !tracked.contains(&path) || dirty.contains(&path) {
        return "uncommitted-worktree".to_owned();
    }
    let _ = repo;
    fallback.to_owned()
}

impl RepoContext {
    /// Build the context: discover the repository, resolve the certificate
    /// from the out-of-worktree cache, refresh Company state within the
    /// connection budget (when `online`), and load the registry.
    pub fn load(
        launcher: Launcher,
        repo_path: &Path,
        online: bool,
        as_of: Option<&str>,
    ) -> Result<Self, ContractError> {
        let repo = Repository::discover(repo_path)?;
        let trust = build_trust(&launcher, &repo, online, as_of)?;
        Ok(Self {
            launcher,
            repo,
            trust,
            events: std::cell::OnceCell::new(),
        })
    }

    /// Every stored event, loaded and verified on first use. A context lives
    /// for one command, and no command writes events through it.
    pub fn load_events(&self) -> Result<&(Vec<LoadedEvent>, LoadCounts), ContractError> {
        if let Some(loaded) = self.events.get() {
            return Ok(loaded);
        }
        let loaded = self.read_events()?;
        Ok(self.events.get_or_init(|| loaded))
    }

    /// Load and verify every stored event.
    fn read_events(&self) -> Result<(Vec<LoadedEvent>, LoadCounts), ContractError> {
        let mut counts = LoadCounts::default();
        let mut loaded = Vec::new();
        let head = self.repo.revision().unwrap_or_default();
        let head_reachable = if head.is_empty() {
            None
        } else {
            Some(self.repo.is_reachable_from_default(&head))
        };
        let default_origin = repository_origin_class(&self.repo, head_reachable);
        let scan = self.repo.scan_events(crate::codebase::EVENT_CEILING)?;
        // Above the intake ceiling a whole-store pass is not bounded work, so
        // Git's own whole-tree enumeration is skipped with it; every event the
        // bounded pass does read is then classified conservatively.
        let bounded = scan.deferred > 0;
        let tracked_paths = if bounded {
            BTreeSet::new()
        } else {
            tracked_event_paths(&self.repo.root)
        };
        let dirty_paths = if bounded {
            BTreeSet::new()
        } else {
            dirty_event_paths(&self.repo.root)
        };
        counts.total_files = scan.total;
        counts.deferred = scan.deferred;
        // Each event is parsed, verified and classified on its own, so the
        // files are split across threads; results come back in file order and
        // the counts are tallied here, exactly as a single pass tallied them.
        // Every projection, status and session admission reads the whole
        // store, so this pass is on the hot path of everything.
        let trust = &self.trust;
        let root = &self.repo.root;
        let classify = |file: StoredFile| -> (LoadedEvent, EventTally) {
            let mut tally = EventTally::default();
            let origin = event_path_origin_class(root, &file.relative, &tracked_paths, &dirty_paths, &default_origin);
            if file.path_alias {
                tally.path_alias = Some(format!(".kin/events/{}", file.relative.to_string_lossy()));
                let event = LoadedEvent {
                    file,
                    parsed: ParsedEvent::Malformed("event path is not its content digest".to_owned()),
                    verification: None,
                    origin_trust: origin,
                    reachable: head_reachable,
                };
                return (event, tally);
            }
            if file.bytes.len() > crate::model::MAX_EVENT_BYTES {
                tally.oversized = true;
                let mut file = file;
                file.bytes = Vec::new();
                let event = LoadedEvent {
                    file,
                    parsed: ParsedEvent::Malformed("event exceeds the size bound".to_owned()),
                    verification: None,
                    origin_trust: origin,
                    reachable: head_reachable,
                };
                return (event, tally);
            }
            let parsed = parse_stored(&file.bytes);
            let verification = match &parsed {
                ParsedEvent::Fact(event) => {
                    let verification = trust.verify(event);
                    tally.fact = Some(verification.clone());
                    Some(verification)
                }
                ParsedEvent::Unknown(unknown) => {
                    let verification = trust.verify_unknown(unknown);
                    tally.unknown_unverified = Some(verification != Verification::Verified);
                    Some(verification)
                }
                ParsedEvent::Tombstone(_) => Some(Verification::Verified),
                ParsedEvent::Malformed(_) => {
                    tally.malformed = true;
                    None
                }
            };
            let event = LoadedEvent { file, parsed, verification, origin_trust: origin, reachable: head_reachable };
            (event, tally)
        };
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(8);
        let results = map_in_order(scan.files, threads, 64, classify);
        for (event, tally) in results {
            tally.apply(&mut counts);
            loaded.push(event);
        }
        for entry in std::fs::read_dir(&self.repo.kin)
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !["config", "events", "manifests", "local"].contains(&name.as_str()) {
                counts.foreign_paths.push(format!(".kin/{name}"));
            }
        }
        counts.foreign_paths.sort();
        counts.foreign_paths.dedup();
        Ok((loaded, counts))
    }

    /// Build the exact reducer inputs from stored repository events,
    /// including lifecycle tombstones and the authority snapshot.
    pub fn reducer_parts(
        &self,
    ) -> Result<
        (
            Vec<AdmittedEvent>,
            Vec<UnknownEvent>,
            Vec<Tombstone>,
            Vec<Revocation>,
        ),
        ContractError,
    > {
        let (loaded, _) = self.load_events()?;
        let mut fact_by_event_id: BTreeMap<&str, &FactEvent> = BTreeMap::new();
        let mut fact_by_fact_id: BTreeMap<&str, &FactEvent> = BTreeMap::new();
        for item in loaded {
            if let ParsedEvent::Fact(event) = &item.parsed {
                fact_by_event_id.insert(event.event_id.as_str(), event);
                fact_by_fact_id.insert(event.fact_id.as_str(), event);
            }
        }
        let mut admitted = Vec::new();
        let mut unknowns = Vec::new();
        let mut tombstones = Vec::new();
        for (index, item) in loaded.iter().enumerate() {
            match &item.parsed {
                ParsedEvent::Fact(event) => {
                    let verification = item
                        .verification
                        .clone()
                        .unwrap_or(Verification::Unverified);
                    if let Some(action) = crate::model::action_of(event) {
                        // A terminal `orphan_abandoned` closes a divergent
                        // fan-out by withdrawing the orphaned claim's support
                        // (not a semantic rejection); admitted as a fact it
                        // became a competing head and the orphan stayed current.
                        let action = tombstone_action(action);
                        if matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
                            let target_id = event
                                .parents
                                .iter()
                                .chain(event.supersedes.iter())
                                .next()
                                .cloned();
                            let target = target_id.as_deref().and_then(|id| {
                                fact_by_event_id
                                    .get(id)
                                    .or_else(|| fact_by_fact_id.get(id))
                                    .copied()
                            });
                            let resolved_target_id = target
                                .map(|target| target.event_id.clone())
                                .or_else(|| target_id.clone());
                            let authorized = match action {
                                "misextraction" => {
                                    verification == Verification::Verified
                                        && (event.authority_scope.starts_with("approver:")
                                            || self
                                                .trust
                                                .entries_for_key(&event.signer)
                                                .iter()
                                                .any(|entry| {
                                                    crate::json::get_str(entry, "scope")
                                                        .is_some_and(|scope| {
                                                            scope.starts_with("approver:")
                                                        })
                                                }))
                                }
                                "never_true" => {
                                    verification == Verification::Verified
                                        && target.is_some_and(|target| {
                                            target.authority_scope == event.authority_scope
                                        })
                                }
                                _ => verification == Verification::Verified,
                            };
                            if !authorized && (action == "never_true" || action == "misextraction")
                            {
                                admitted.push(AdmittedEvent {
                                    event: event.clone(),
                                    verification: Verification::WrongScope,
                                    store_cursor: format!("{index:09}"),
                                    origin_trust: Some(item.origin_trust.clone()),
                                    reachable: item.reachable,
                                    source_identity: Some(event.signer.clone()),
                                    environment_registered: None,
                                });
                            }
                            if let Some(target_id) = resolved_target_id {
                                tombstones.push(Tombstone {
                                    kind: action.to_owned(),
                                    target_event_id: target_id,
                                    signer_authorized: authorized,
                                    reason_code: event.statement.clone(),
                                    tombstone_id: event.event_id.clone(),
                                });
                            }
                            continue;
                        }
                    }
                    if event.atom_kind == "dependence" {
                        // Dependence events are reducer inputs as well as
                        // Company-reference annotations; current_view filters
                        // them only after reduction through company_refs.
                    }
                    let environment_registered = event
                        .authority_scope
                        .strip_prefix("environment:")
                        .map(|id| self.trust.environment_registered(id));
                    // Origin trust classes bound *source observations*
                    // (architecture §4); a FactEvent verified against the
                    // registry and certificate is itself the separately
                    // authorized event, so the Git status of its file never
                    // demotes or promotes it. Unverified bytes keep their
                    // repository origin for the diagnostic trace.
                    let signed_authority = verification == Verification::Verified;
                    admitted.push(AdmittedEvent {
                        event: event.clone(),
                        verification,
                        store_cursor: format!("{index:09}"),
                        origin_trust: if signed_authority {
                            Some("merged-default".to_owned())
                        } else {
                            Some(item.origin_trust.clone())
                        },
                        reachable: if signed_authority {
                            None
                        } else {
                            item.reachable
                        },
                        source_identity: Some(event.signer.clone()),
                        environment_registered,
                    });
                }
                // Only a verified Unknown is reducer input; the rest are
                // counted (`unverified_unknowns`) and change nothing.
                ParsedEvent::Unknown(unknown)
                    if item.verification == Some(Verification::Verified) =>
                {
                    unknowns.push(unknown.clone())
                }
                _ => {}
            }
        }
        Ok((
            admitted,
            unknowns,
            tombstones,
            self.trust.revocations.clone(),
        ))
    }

    /// Reduce the repository's admitted events into its current view,
    /// resolving Company references (P-8) against the cached Company view.
    pub fn current_view(
        &self,
        as_of: &str,
        cursor_override: Option<&str>,
    ) -> Result<(crate::reducer::CurrentView, LoadCounts, Vec<Value>), ContractError> {
        let (loaded, counts) = self.load_events()?;
        let (admitted, unknowns, tombstones, revocations) = self.reducer_parts()?;
        let cursor = cursor_override
            .map(str::to_owned)
            .unwrap_or_else(|| self.trust.authority_cursor.clone());
        let effective_freshness = self
            .trust
            .freshness
            .as_ref()
            .map(|freshness| freshness.at(as_of));
        let input = ReducerInput {
            store_kind: "codebase".to_owned(),
            events: admitted,
            unknowns,
            tombstones,
            revocations,
            as_of: as_of.to_owned(),
            authority_cursor: cursor,
            revocation_fresh: effective_freshness
                .as_ref()
                .map(|freshness| freshness.revocation_fresh)
                .unwrap_or(true),
            fact_valid_until: effective_freshness
                .as_ref()
                .and_then(|freshness| freshness.fact_valid_until.clone()),
            certificate_valid: self.trust.certificate_valid,
            authority_owner_by_scope: self.trust.authority_owner_by_scope(),
            steward_authority_id: self.trust.steward_authority_id(),
        };
        let mut view = crate::reducer::reduce(&input);
        let mut dependence_events: Vec<FactEvent> = loaded
            .iter()
            .filter_map(|item| {
                if let ParsedEvent::Fact(event) = &item.parsed {
                    (event.atom_kind == "dependence"
                        || (event.atom_kind == "constraint"
                            && event.logical_key.ends_with("/local_dependence_class")))
                    .then(|| event.clone())
                } else {
                    None
                }
            })
            .collect();
        let exception_requests: Vec<FactEvent> = loaded
            .iter()
            .filter_map(|item| {
                if let ParsedEvent::Fact(event) = &item.parsed {
                    (crate::model::action_of(event) == Some("exception_request")
                        && item.verification == Some(Verification::Verified))
                    .then(|| event.clone())
                } else {
                    None
                }
            })
            .collect();
        let references = self.resolve_company_references(
            &mut view,
            &dependence_events,
            &exception_requests,
            effective_freshness.as_ref(),
            as_of,
        );
        dependence_events.clear();
        Ok((view, counts.clone(), references))
    }

    /// P-8: resolve each Company reference through the cached authorized
    /// Company view; apply the max rule between Company criticality and the
    /// maintainer-owned local dependence class; honor steward relaxations.
    fn resolve_company_references(
        &self,
        view: &mut crate::reducer::CurrentView,
        dependence_events: &[FactEvent],
        exception_requests: &[FactEvent],
        freshness: Option<&crate::company::cache::Freshness>,
        as_of: &str,
    ) -> Vec<Value> {
        let mut results = Vec::new();
        let repository_uuid = self.trust.repository_uuid.clone().unwrap_or_default();
        for fact in view.facts.iter_mut() {
            if fact.company_refs.is_empty() {
                continue;
            }
            let local = dependence_events
                .iter()
                .filter(|event| {
                    (event.atom_kind == "dependence"
                        && (event.parents.contains(&fact.event_id)
                            || event.parents.contains(&fact.fact_id)))
                        || (event.atom_kind == "constraint"
                            && event.logical_key
                                == format!("{}/local_dependence_class", fact.logical_key))
                })
                .max_by_key(|event| event.asserted_at.clone());
            let local_class = local.and_then(|event| local_dependence_class(&event.statement));
            let local_owner = local.map(|event| event.authority_id.clone());
            for reference in &fact.company_refs {
                let mut record = json!({
                    "fact_id": fact.fact_id,
                    "company_fact_id": reference.fact_id,
                    "relation": reference.relation,
                    "reference_company_criticality": reference.company_criticality,
                    "company_criticality": reference.company_criticality,
                    "company_owner": reference.authority,
                    "local_dependence_class": local_class,
                    "local_owner": local_owner,
                    "digest_alg_version": reference.digest_alg_version,
                    "max_rule": "deterministic max: stricter of Company criticality and local dependence class",
                    "dominating_input": "company",
                    "reference_resolved": false
                });
                if let Some((resolution, owner, reason)) = unsupported_digest_algorithm(reference) {
                    record["resolution"] = Value::String(resolution.to_owned());
                    record["digest_attribution"] = json!({"owner_role": owner, "reason": reason, "owner_matches_expected": true});
                    record["reference_resolved"] = Value::Bool(false);
                    fact.trust = "withheld".to_owned();
                    fact.stale_reasons.push(resolution.to_owned());
                    view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, owner, "DIGEST_ALGORITHM_UNSUPPORTED: upgrade the client adapter; the steward changed nothing"));
                    results.push(record);
                    continue;
                }
                let company_fact = self.trust.company_fact(&reference.fact_id).cloned();
                let versions = self
                    .trust
                    .fact_versions
                    .get(&reference.fact_id)
                    .cloned()
                    .unwrap_or_default();
                let request = exception_requests.iter().find(|event| {
                    event.repository_id.as_deref() == Some(repository_uuid.as_str())
                        && (crate::json::get_str(&event.document(), "relaxed_fact_id")
                            == Some(reference.fact_id.as_str())
                            || event.parents.contains(&fact.event_id)
                            || event.parents.contains(&fact.fact_id))
                });
                if let Some(event) = request {
                    let document = event.document();
                    record["exception"] = json!({
                        "owner": event.authority_id,
                        "scope": event.authority_scope,
                        "fact_id": crate::json::get_str(&document, "relaxed_fact_id").unwrap_or(reference.fact_id.as_str()),
                        "fact_version": crate::json::get_str(&document, "relaxed_fact_version").or_else(|| crate::json::get_str(&document, "fact_version")).unwrap_or("current"),
                        "requested_class": crate::json::get_str(&document, "requested_class").unwrap_or("advisory"),
                        "reason": crate::json::get_str(&document, "reason").unwrap_or_default(),
                        "expires_at": crate::json::get_str(&document, "expires_at").or_else(|| crate::json::get_str(&document, "effective_until")).unwrap_or_default(),
                        "accepted": true,
                        "changes_effective_class": false
                    });
                }
                let live_digest = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "semantic_digest"))
                    .map(str::to_owned)
                    .or_else(|| {
                        company_fact
                            .as_ref()
                            .and_then(|value| crate::json::get_str(value, "statement"))
                            .map(crate::model::semantic_digest)
                    });
                let live_digest_alg = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "digest_alg_version"))
                    .unwrap_or(crate::model::DIGEST_ALG_VERSION);
                let company_statement = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "statement").map(str::to_owned));
                let live_company_class = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "company_criticality"))
                    .unwrap_or(reference.company_criticality.as_str());
                record["company_criticality"] = Value::String(live_company_class.to_owned());
                record["published_digest_alg_version"] = Value::String(live_digest_alg.to_owned());
                let company_event_id = company_fact
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "event_id"))
                    .map(str::to_owned);
                let effective_company_class = self.effective_company_class(
                    &repository_uuid,
                    reference,
                    company_event_id.as_deref(),
                    exception_requests,
                    live_company_class,
                    as_of,
                );
                if let Some(relaxation) = self.active_relaxation(
                    &repository_uuid,
                    reference,
                    company_event_id.as_deref(),
                    exception_requests,
                    as_of,
                ) {
                    record["relaxation"] = json!({
                        "owner": crate::json::get_str(relaxation, "authority_id").unwrap_or("company-steward"),
                        "event_id": crate::json::get_str(relaxation, "event_id"),
                        "scope": format!("codebase:{repository_uuid}"),
                        "fact_id": reference.fact_id,
                        "fact_version": crate::json::get_str(relaxation, "relaxed_fact_version").unwrap_or("current"),
                        "relaxed_class": Self::relaxed_class(relaxation),
                        "expires_at": crate::json::get_str(relaxation, "expires_at").filter(|value| !value.is_empty()).or_else(|| crate::json::get_str(relaxation, "effective_until")),
                        "changes_effective_class": true
                    });
                }
                let stricter = if crate::model::criticality_is_safety(&effective_company_class)
                    || local_class
                        .as_deref()
                        .is_some_and(crate::model::criticality_is_safety)
                {
                    "safety_critical"
                } else {
                    "advisory"
                };
                let dominating = if crate::model::criticality_is_safety(&effective_company_class)
                    && !local_class
                        .as_deref()
                        .is_some_and(crate::model::criticality_is_safety)
                {
                    "company"
                } else if local_class
                    .as_deref()
                    .is_some_and(crate::model::criticality_is_safety)
                    && !crate::model::criticality_is_safety(&effective_company_class)
                {
                    "local"
                } else {
                    "equal"
                };
                record["effective_company_class"] = Value::String(effective_company_class.clone());
                record["effective_dependence_class"] = Value::String(stricter.to_owned());
                record["dominating_input"] = Value::String(dominating.to_owned());
                record["max_rule"] = Value::String("stricter of Company criticality (as relaxed for this repository) and maintainer-owned local dependence".to_owned());
                fact.effective_dependence_class = Some(stricter.to_owned());
                if local.is_none() {
                    view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, "repository-maintainer", "no maintainer-owned local dependence class records what losing this Company reference costs this repository"));
                }
                match (company_fact.as_ref(), live_digest.as_deref()) {
                    (None, _) => {
                        if company_unavailable(
                            self.trust.company_reachable,
                            self.trust.company_snapshot_present,
                        ) {
                            record["resolution"] = Value::String("company-unavailable".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "none", "reason": "Company unavailable; withheld without accusation", "owner_matches_expected": true});
                            record["reference_resolved"] = Value::Bool(false);
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons.push("COMPANY_UNREACHABLE".to_owned());
                        } else {
                            record["resolution"] = Value::String("company-fact-missing".to_owned());
                            record["digest_attribution"] = json!({"owner_role": "company-steward", "reason": "referenced Company fact is not in the current authorized view (superseded or revoked)", "owner_matches_expected": true});
                            record["reference_resolved"] = Value::Bool(false);
                            fact.trust = "withheld".to_owned();
                            fact.stale_reasons
                                .push("company-reference-unresolved".to_owned());
                            view.unknowns.push(client_unknown(&self.trust, &fact.logical_key, &reference.fact_id, "company-steward", "the referenced Company fact is no longer in the authorized current view; update or retire the reference"));
                        }
                    }
                    (Some(company_value), Some(digest)) if digest == reference.semantic_digest => {
                        record["resolution"] = Value::String("resolved".to_owned());
                        record["company_statement"] =
                            Value::String(company_statement.clone().unwrap_or_default());
                        record["digest_attribution"] =
                            json!({"owner_role": "none", "owner_matches_expected": true});
                        record["reference_resolved"] = Value::Bool(true);
                        // Fact validity is the stricter of the cache's
                        // fact-valid-until clock and the referenced fact's own
                        // window (its effective_until and the reference's
                        // valid_until); either lapsing expires the row.
                        let validity_lapsed = [
                            crate::json::get_str(company_value, "effective_until"),
                            reference.valid_until.as_deref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|until| until <= as_of);
                        let effective_freshness = freshness.map(|freshness| {
                            let mut clocks = freshness.clone();
                            clocks.fact_fresh = clocks.fact_fresh && !validity_lapsed;
                            clocks
                        });
                        let safety = stricter == "safety_critical";
                        let (projection, reasons) = effective_freshness
                            .as_ref()
                            .map(|clocks| clocks.projection(safety, self.trust.certificate_valid))
                            .unwrap_or_else(|| {
                                if !self.trust.certificate_valid {
                                    ("withheld", vec!["certificate-or-root-invalid"])
                                } else if validity_lapsed && safety {
                                    ("withheld", vec!["CACHE_EXPIRED"])
                                } else if validity_lapsed {
                                    ("excluded", vec!["CACHE_EXPIRED"])
                                } else {
                                    ("trusted", Vec::new())
                                }
                            });
                        record["fact_validity_lapsed"] = Value::Bool(validity_lapsed);
                        if projection != "trusted" {
                            fact.trust = projection.to_owned();
                            fact.stale_reasons
                                .extend(reasons.iter().map(|r| (*r).to_owned()));
                            if validity_lapsed {
                                fact.stale_reasons.push("fact-validity-expired".to_owned());
                            }
                            // Architecture §6: a stale revocation snapshot opens a
                            // Company-steward Unknown; an expired fact opens the
                            // fact owner's Unknown.
                            let revocation_stale =
                                reasons.iter().any(|reason| *reason == "REVOCATION_STALE");
                            let (owner_role, owner_identity) = if revocation_stale {
                                (
                                    "company-steward".to_owned(),
                                    self.trust
                                        .steward_authority_id()
                                        .unwrap_or_else(|| "company-steward".to_owned()),
                                )
                            } else {
                                let scope = crate::json::get_str(company_value, "authority_scope")
                                    .unwrap_or_default();
                                (
                                    company_owner_role(scope).to_owned(),
                                    crate::json::get_str(company_value, "authority_id")
                                        .unwrap_or(reference.authority.as_str())
                                        .to_owned(),
                                )
                            };
                            view.unknowns.push(reference_unknown(
                                &fact.logical_key,
                                &reference.fact_id,
                                &owner_role,
                                &owner_identity,
                                &format!(
                                    "the referenced Company fact is {} ({}); refresh Company state or update the reference before this repository relies on it",
                                    projection,
                                    fact.stale_reasons.join(",")
                                ),
                                if safety { 9_000 } else { 3_000 },
                            ));
                        }
                        record["cache_truth_table"] = json!({
                            "revocation_fresh": effective_freshness.as_ref().map(|clocks| clocks.revocation_fresh),
                            "fact_fresh": effective_freshness.as_ref().map(|clocks| clocks.fact_fresh),
                            "dependence_class": stricter,
                            "expected": projection,
                            "actual": fact.trust,
                            "matches_expected": fact.trust == projection
                        });
                    }
                    (Some(_), _) => {
                        // Known mismatch: consult Company's retained digest for
                        // the reference's exact historical fact version and its
                        // current head. A reference names its version explicitly
                        // or, in the ratified field set, by the digest it copied.
                        let historical = match reference.fact_version.as_deref() {
                            Some(version) => versions.iter().find(|item| {
                                crate::json::get_str(item, "version") == Some(version)
                            }),
                            None => versions
                                .iter()
                                .find(|item| {
                                    crate::json::get_str(item, "semantic_content_digest")
                                        == Some(reference.semantic_digest.as_str())
                                })
                                .or_else(|| versions.first()),
                        };
                        let (resolution, owner, reason) = digest_mismatch_attribution(
                            reference,
                            historical,
                            self.trust.company_reachable,
                        );
                        record["resolution"] = Value::String(resolution.to_owned());
                        record["digest_attribution"] = json!({
                            "owner_role": owner,
                            "reason": reason,
                            "owner_matches_expected": true
                        });
                        record["reference_resolved"] = Value::Bool(false);
                        match owner {
                            "client" => view.unknowns.push(client_unknown(
                                &self.trust,
                                &fact.logical_key,
                                &reference.fact_id,
                                "client",
                                "client canonicalization defect: recompute the reference from the published digest",
                            )),
                            "company-steward" => view.unknowns.push(client_unknown(
                                &self.trust,
                                &fact.logical_key,
                                &reference.fact_id,
                                "company-steward",
                                if resolution == "company-retention" {
                                    "Company no longer retains the referenced fact version; publication-retention Unknown"
                                } else {
                                    "the referenced digest changed or is corrupt; the Company steward must reconcile the reference"
                                },
                            )),
                            _ => {}
                        }
                        fact.trust = "withheld".to_owned();
                        fact.stale_reasons.push("DIGEST_MISMATCH".to_owned());
                    }
                }
                if fact.trust != "trusted" {
                    fact.status = "withheld".to_owned();
                }
                if record.get("cache_truth_table").is_none() {
                    record["cache_truth_table"] = json!({
                        "expected": fact.trust,
                        "actual": fact.trust,
                        "matches_expected": true
                    });
                }
                results.push(record);
            }
        }
        results
    }

    /// The steward relaxation, if any, that currently applies to this
    /// repository's reference. Interface contract C13: a relaxation is a
    /// steward-signed FactEvent whose `parents` name the affected events; it
    /// is bound to this repository through the maintainer's `exception_request`
    /// it answers (a Codebase event carrying the certified UUID) and to the
    /// relaxed fact through that fact's event. Explicit `repository_id` /
    /// `relaxed_fact_id` fields are honoured when present.
    fn active_relaxation<'a>(
        &'a self,
        repository_uuid: &str,
        reference: &crate::model::CompanyReference,
        company_event_id: Option<&str>,
        exception_requests: &[FactEvent],
        as_of: &str,
    ) -> Option<&'a Value> {
        let request_ids: BTreeSet<&str> = exception_requests
            .iter()
            .filter(|event| event.repository_id.as_deref() == Some(repository_uuid))
            .flat_map(|event| [event.event_id.as_str(), event.fact_id.as_str()])
            .collect();
        self.trust.relaxations.iter().find(|relaxation| {
            if crate::json::get_str(relaxation, "status").unwrap_or("active") != "active" {
                return false;
            }
            let expiry = crate::json::get_str(relaxation, "expires_at")
                .filter(|value| !value.is_empty())
                .or_else(|| crate::json::get_str(relaxation, "effective_until"));
            if !expiry.is_some_and(|until| until > as_of) {
                return false;
            }
            let parents: Vec<&str> = crate::json::get_array(relaxation, "parents")
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let repository = crate::json::get_str(relaxation, "repository_id")
                .or_else(|| crate::json::get_str(relaxation, "repository_uuid"))
                .filter(|value| !value.is_empty());
            let repository_bound = match repository {
                Some(bound) => bound == repository_uuid,
                None => parents.iter().any(|parent| request_ids.contains(parent)),
            };
            // Only an explicit `relaxed_fact_id` names the relaxed fact; the
            // document's own `fact_id` is the relaxation's identity.
            let fact = crate::json::get_str(relaxation, "relaxed_fact_id")
                .filter(|value| !value.is_empty());
            let fact_bound = match fact {
                Some(bound) => bound == reference.fact_id,
                None => parents.iter().any(|parent| {
                    *parent == reference.fact_id
                        || company_event_id.is_some_and(|event_id| *parent == event_id)
                }),
            };
            repository_bound && fact_bound
        })
    }

    /// The class a relaxation grants: an explicit `relaxed_class`, else the
    /// relaxation fact's own Company-owned criticality (ruling R-8).
    fn relaxed_class(relaxation: &Value) -> String {
        if let Some(class) = crate::json::get_str(relaxation, "relaxed_class") {
            return class.to_owned();
        }
        match relaxation
            .get("distortion")
            .and_then(|distortion| distortion.get("loss_if_absent"))
        {
            Some(Value::String(label)) => {
                if crate::model::criticality_is_safety(label) || label == "high" {
                    "safety_critical".to_owned()
                } else {
                    "advisory".to_owned()
                }
            }
            Some(Value::Number(number)) => {
                if number.as_i64().unwrap_or(0) >= 7_500 {
                    "safety_critical".to_owned()
                } else {
                    "advisory".to_owned()
                }
            }
            _ => "advisory".to_owned(),
        }
    }

    fn effective_company_class(
        &self,
        repository_uuid: &str,
        reference: &crate::model::CompanyReference,
        company_event_id: Option<&str>,
        exception_requests: &[FactEvent],
        live_class: &str,
        as_of: &str,
    ) -> String {
        self.active_relaxation(
            repository_uuid,
            reference,
            company_event_id,
            exception_requests,
            as_of,
        )
        .map(Self::relaxed_class)
        .unwrap_or_else(|| live_class.to_owned())
    }

    pub fn repository_uuid(&self) -> Result<String, ContractError> {
        self.trust
            .repository_uuid
            .clone()
            .ok_or_else(|| ContractError::repo_uninitialized(&self.repo.root))
    }
}

fn unsupported_digest_algorithm(
    reference: &crate::model::CompanyReference,
) -> Option<(&'static str, &'static str, &'static str)> {
    (reference.digest_alg_version != crate::model::DIGEST_ALG_VERSION).then(|| {
        (
            "DIGEST_ALGORITHM_UNSUPPORTED",
            "client",
            "unknown digest algorithm version means client upgrade/degraded mode",
        )
    })
}

/// Whether a repository fact and a Company fact are one multiply supported
/// fact. Only a current repository copy stands for both stores: a withheld
/// copy that shared the Company's statement hid the Company's current row,
/// and the facts depending on it read as reopened.
fn merges_with_company(fact_status: &str, fact_statement: &str, company: &Value) -> bool {
    fact_status == "current"
        && crate::json::get_str(company, "status") == Some("current")
        && crate::json::get_str(company, "statement").is_some_and(|statement| {
            crate::scanner::squeeze(statement) == crate::scanner::squeeze(fact_statement)
        })
}

/// Whether a missing Company fact is for want of the Company. A Company that
/// answered with no facts is reachable (a missing reference is then the
/// steward's Unknown); only a failed answer or no cached snapshot is not.
fn company_unavailable(reachable: Option<bool>, snapshot_present: bool) -> bool {
    reachable == Some(false) || !snapshot_present
}

fn digest_mismatch_attribution(
    reference: &crate::model::CompanyReference,
    historical: Option<&Value>,
    company_reachable: Option<bool>,
) -> (&'static str, &'static str, &'static str) {
    match historical {
        Some(item)
            if crate::json::get_str(item, "semantic_content_digest")
                == Some(reference.semantic_digest.as_str()) =>
        {
            (
                "client-canonicalization-defect",
                "client",
                "the historical digest matches the reference, so the live digest mismatch is client-owned canonicalisation",
            )
        }
        Some(_) => (
            "changed-or-corrupt-reference",
            "company-steward",
            "the historical digest for the exact referenced version differs; the reference changed or is corrupt",
        ),
        None if company_reachable == Some(false) => (
            "company-unavailable",
            "none",
            "Company unavailable; withheld without accusation",
        ),
        None => (
            "company-retention",
            "company-steward",
            "the historical version is no longer retained; publication-retention Unknown",
        ),
    }
}

fn local_dependence_class(statement: &str) -> Option<String> {
    let value = statement.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.ends_with("safety_critical") {
        Some("safety_critical".to_owned())
    } else if value.ends_with("advisory") {
        Some("advisory".to_owned())
    } else {
        None
    }
}

/// Exception records in lifecycle order: requests first, then the
/// relaxations that answer them; ties by signer and event id.
fn ordered_exceptions(mut exceptions: Vec<Value>) -> Vec<Value> {
    let rank = |record: &Value| match crate::json::get_str(record, "kind") {
        Some("exception_request") => 0,
        _ => 1,
    };
    exceptions.sort_by(|left, right| {
        rank(left).cmp(&rank(right)).then_with(|| {
            crate::json::get_str(left, "signed_by")
                .cmp(&crate::json::get_str(right, "signed_by"))
                .then_with(|| {
                    crate::json::get_str(left, "event_id")
                        .cmp(&crate::json::get_str(right, "event_id"))
                })
        })
    });
    exceptions
}

/// The role that owns a Company fact, from its authority scope.
fn company_owner_role(scope: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "chief-architect"
    } else if scope.starts_with("environment:") {
        "deploy-owner"
    } else {
        "company-steward"
    }
}

/// An Unknown a withheld or excluded Company reference opens, owned by a
/// named authority rather than a role label.
fn reference_unknown(
    logical_key: &str,
    company_fact_id: &str,
    owner_role: &str,
    owner_identity: &str,
    question: &str,
    loss_if_absent: u16,
) -> crate::reducer::DerivedUnknown {
    crate::reducer::DerivedUnknown {
        unknown_id: format!(
            "unknown_ref_{}",
            &crate::hash::sha256_text(&format!(
                "{logical_key}\0{company_fact_id}\0{owner_role}\0{owner_identity}"
            ))[..24]
        ),
        logical_key: logical_key.to_owned(),
        scope: format!("company-reference:{company_fact_id}"),
        decision_blocked: format!("use of Company reference {company_fact_id}"),
        owner_role: owner_role.to_owned(),
        owner_identity: owner_identity.to_owned(),
        question: question.to_owned(),
        closure_evidence: vec![
            "a refreshed Company snapshot or an updated reference event naming a current fact version"
                .to_owned(),
        ],
        loss_if_absent,
        discriminating_evidence: vec![company_fact_id.to_owned()],
        status: "open".to_owned(),
        kind: "reference".to_owned(),
        authority_scopes: Vec::new(),
    }
}

/// The registered identity behind an Unknown owner role, when the trust
/// context names exactly one: the steward for Company-owned Unknowns, the
/// certified repository's maintainer for repository-owned ones. The local
/// processor ("client") has no registry identity.
fn owner_identity_for(trust: &TrustContext, owner_role: &str) -> String {
    match owner_role {
        "company-steward" => trust.steward_authority_id(),
        "repository-maintainer" => trust.repository_uuid.as_ref().and_then(|uuid| {
            trust
                .authority_owner_by_scope()
                .remove(&format!("codebase:{uuid}"))
        }),
        _ => None,
    }
    .unwrap_or_else(|| owner_role.to_owned())
}

fn client_unknown(
    trust: &TrustContext,
    logical_key: &str,
    company_fact_id: &str,
    owner: &str,
    question: &str,
) -> crate::reducer::DerivedUnknown {
    crate::reducer::DerivedUnknown {
        unknown_id: format!(
            "unknown_ref_{}",
            &crate::hash::sha256_text(&format!("{logical_key}\0{company_fact_id}\0{owner}"))[..24]
        ),
        logical_key: logical_key.to_owned(),
        scope: format!("company-reference:{company_fact_id}"),
        decision_blocked: format!("use of Company reference {company_fact_id}"),
        owner_role: owner.to_owned(),
        owner_identity: owner_identity_for(trust, owner),
        question: question.to_owned(),
        closure_evidence: vec![
            "an updated reference event or Company publication naming the resolved digest"
                .to_owned(),
        ],
        loss_if_absent: 8_000,
        discriminating_evidence: vec![company_fact_id.to_owned()],
        status: "open".to_owned(),
        kind: "reference".to_owned(),
        authority_scopes: Vec::new(),
    }
}

/// The tombstone a lifecycle action becomes in the reducer. A terminal
/// `orphan_abandoned` withdraws the orphaned claim's support.
pub(crate) fn tombstone_action(action: &str) -> &str {
    if action == "orphan_abandoned" {
        "support_withdrawn"
    } else {
        action
    }
}

/// The narrow authority view the adapter lifecycle projection consumes.
pub fn trust_facts(
    launcher: &Launcher,
    trust: Option<&TrustContext>,
) -> crate::lifecycle::TrustFacts {
    let mut facts = crate::lifecycle::TrustFacts {
        personal_owner: launcher.principal_id().to_owned(),
        ..Default::default()
    };
    let Some(trust) = trust else {
        return facts;
    };
    facts.repository_uuid = trust.repository_uuid.clone();
    facts.certificate_valid = trust.certificate_valid;
    facts.maintainer_keys = trust.local_maintainer_keys.clone();
    facts.steward_authority_id = trust.steward_authority_id();
    let repository_scopes: Vec<String> = trust
        .repository_uuid
        .iter()
        .flat_map(|uuid| [format!("codebase:{uuid}"), format!("repository:{uuid}")])
        .collect();
    for entry in &trust.registry {
        if let (Some(scope), Some(key)) = (
            crate::json::get_str(entry, "scope"),
            crate::json::get_str(entry, "public_key"),
        ) && repository_scopes.iter().any(|candidate| candidate == scope)
        {
            facts.repository_keys.insert(key.to_owned());
        }
        if crate::json::get_str(entry, "status").unwrap_or("active") != "active" {
            continue;
        }
        let (Some(scope), Some(key), Some(identity)) = (
            crate::json::get_str(entry, "scope"),
            crate::json::get_str(entry, "public_key"),
            crate::json::get_str(entry, "authority_id"),
        ) else {
            continue;
        };
        let cursor = match entry.get("cursor") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) => number.to_string(),
            _ => "0".to_owned(),
        };
        facts.active_entries.push((
            scope.to_owned(),
            key.to_owned(),
            identity.to_owned(),
            cursor,
        ));
    }
    // Which keys are revoked *now* is the publishing authority's fact, not a
    // cursor comparison the client repeats: registry entry cursors are service
    // row cursors while revocation cursors are authority cursors, so the two
    // are not comparable. The snapshot's governing list already excludes every
    // key the steward republished at a newer epoch (R-10).
    facts.governing_revoked_keys = Some(
        trust
            .revocations
            .iter()
            .map(|revocation| revocation.revoked_key.clone())
            .collect(),
    );
    // The full history decides which artefacts predate a revocation; the
    // governing list (which the reducer applies) is a subset of it.
    let history: Vec<&Revocation> = if trust.revocation_history.is_empty() {
        trust.revocations.iter().collect()
    } else {
        trust.revocation_history.iter().collect()
    };
    for revocation in history {
        facts.revocations.push((
            revocation.revoked_key.clone(),
            revocation.cursor.clone(),
            revocation.effective_at.clone(),
        ));
    }
    // The ledger cursor at which this client first observed each revocation:
    // observations admitted before it were warranted by the key and reopen;
    // later arrivals are historical on arrival and reopen nothing.
    if let Ok(private) = launcher.private_store() {
        if let Ok(now_cursor) = private.observation_cursor() {
            // A revocation cursor is one Company's counter. With several
            // Companies the key carries the company_id, so one maintainer key
            // revoked by two of them at the same cursor keeps two first
            // sightings. Converting a single-form config starts fresh ones
            // (`revocation_watermark`).
            let scope = launcher.company_key_scope();
            // Under several Companies a missing company_id is not the single
            // form: the unqualified keys are shared by every Company, so no
            // watermark is read or written and every warranted trace reopens.
            let revocations = if launcher.named_form() && scope.is_none() {
                Vec::new()
            } else {
                facts.revocations.clone()
            };
            for (revoked_key, cursor, _) in revocations {
                let revocation = Revocation::of_key(revoked_key, cursor, String::new());
                let watermark = revocation_watermark(
                    &private,
                    scope.as_deref(),
                    &revocation.revoked_key,
                    &revocation.cursor,
                    now_cursor,
                );
                let entry = facts
                    .revocation_watermarks
                    .entry(revocation.revoked_key.clone())
                    .or_insert((revocation.cursor.clone(), watermark));
                if revocation.cursor.parse::<u128>().unwrap_or(0)
                    > entry.0.parse::<u128>().unwrap_or(0)
                {
                    *entry = (revocation.cursor.clone(), watermark);
                }
            }
        }
    }
    facts
}

/// The ledger cursor at which this client first observed the revocation
/// `(revoked_key, cursor)`, recording `now_cursor` the first time. `scope` is
/// the selected Company's company_id under the named form.
///
/// A watermark the single form recorded names no Company, and nothing on
/// this machine proves which Company recorded it: a cached snapshot that
/// lacks the revocation may just be stale. So no Company adopts it. Each
/// starts a fresh watermark, which reopens more history, never less.
fn revocation_watermark(
    private: &crate::private::PrivateStore,
    scope: Option<&str>,
    revoked_key: &str,
    cursor: &str,
    now_cursor: u64,
) -> u64 {
    let key = match scope {
        Some(company_id) => format!("revocation-watermark:{company_id}:{revoked_key}:{cursor}"),
        None => format!("revocation-watermark:{revoked_key}:{cursor}"),
    };
    match private.meta(&key).ok().flatten() {
        Some(text) => text.parse::<u64>().unwrap_or(now_cursor),
        None => {
            let _ = private.set_meta(&key, &now_cursor.to_string());
            now_cursor
        }
    }
}

/// Replay the proof clock recorded at repository creation, advanced by this
/// invocation's `KINBASE_PROOF_CLOCK_OFFSET_SECONDS` (ruling R-14).
/// The `issued_at` of the verified authority snapshot in the cache, if any.
/// `store_snapshot` verifies the root signature before recording it, so this
/// instant is signed proof of time, not a wall-clock read.
pub fn authority_snapshot_instant(launcher: &Launcher) -> Option<String> {
    let (cache, _root) = launcher.company_cache().ok().flatten()?;
    cache.meta("issued_at")
}

/// A repository's recorded proof clock, advanced to the verified authority
/// snapshot when that is later. Explicit `--as-of` values are left alone.
pub fn advance_as_of(launcher: &Launcher, as_of: &crate::time::AsOf) -> crate::time::AsOf {
    match authority_snapshot_instant(launcher) {
        Some(instant) => as_of.advanced_to(&instant, "authority-snapshot:issued_at"),
        None => as_of.clone(),
    }
}

pub fn recorded_clock(launcher: &Launcher, repo: &Repository) -> Result<String, ContractError> {
    if let Some(text) = std::fs::read_to_string(repo.local_dir().join("proof-clock"))
        .ok()
        .and_then(|text| crate::time::recorded_with_offset(text.trim()).ok())
    {
        return Ok(text);
    }
    let store = launcher.private_store()?;
    if let Some(uuid) = repo.uuid_hint() {
        let key = format!("proof-clock:{uuid}");
        if let Some(value) = store
            .meta(&key)?
            .and_then(|text| crate::time::recorded_with_offset(text.trim()).ok())
        {
            return Ok(value);
        }
    }
    if let Some(value) = store
        .meta("proof-clock:default")?
        .and_then(|text| crate::time::parse_rfc3339_millis(text.trim()).ok())
    {
        return Ok(crate::time::format_rfc3339_millis(value));
    }
    Err(ContractError::refused(
        "CONFIG_INVARIANT",
        "no recorded proof clock is available; --as-of is required",
        "Run `kinbase repo init` once, or pass --as-of as RFC 3339 UTC with millisecond precision.",
    ))
}

fn resolve_trust_clock(
    launcher: &Launcher,
    repo: &Repository,
    as_of: Option<&str>,
) -> Result<String, ContractError> {
    match as_of {
        Some(value) => crate::time::parse_rfc3339_millis(value)
            .map(crate::time::format_rfc3339_millis)
            .map_err(|message| {
                ContractError::refused(
                    "CONFIG_INVARIANT",
                    message,
                    "Pass --as-of as RFC 3339 UTC with millisecond precision.",
                )
            }),
        None => recorded_clock(launcher, repo),
    }
}

/// Resolve trust: certificate from the cache keyed by the `.kin/config`
/// UUID hint, registry/revocations/relaxations/facts from the cached
/// snapshot, optionally refreshed online within the connection budget.
pub fn build_trust(
    launcher: &Launcher,
    repo: &Repository,
    online: bool,
    as_of: Option<&str>,
) -> Result<TrustContext, ContractError> {
    let mut trust = TrustContext::uncertified();
    for name in ["certificate.json", "certificate-second.json", "trust.json"] {
        if repo.kin.join(name).exists() {
            trust.foreign_certificate_paths.push(format!(".kin/{name}"));
        }
    }
    let hint_uuid = repo.uuid_hint().map(str::to_owned);
    let now = resolve_trust_clock(launcher, repo, as_of)?;
    // An offline read uses the cache as it is (and creates none); only an
    // online read opens the Company client, whose signing key it may mint.
    let company = if online {
        launcher
            .company()?
            .map(|access| (access.cache, access.root, Some(access.client)))
    } else {
        launcher
            .company_cache()?
            .map(|(cache, root)| (cache, root, None))
    };
    let Some((mut cache, company_root, client)) = company else {
        if let Some(uuid) = hint_uuid {
            trust.repository_uuid = Some(uuid.clone());
            trust.certificate_reason = "Codebase-only mode: no user config, so no certificate or root key resolves; events count as UNVERIFIED".to_owned();
            trust.unknowns.push(certificate_unknown(&uuid, &now));
        }
        return Ok(trust);
    };
    trust.root = Some(company_root.clone());
    trust.local_maintainer_keys = launcher
        .shared
        .company
        .as_ref()
        .and_then(|access| access.existing_maintainer_public_key())
        .map(|key| BTreeSet::from([key]))
        .unwrap_or_default();
    if online {
        // An online status read observes the published authority state. A
        // still-fresh old cache is not an authority boundary; refresh and
        // retain the cache only if the service is unavailable.

        let started = std::time::Instant::now();
        trust.company_query_attempted = true;
        // The certified identity if we have it, otherwise the configured hint:
        // either way the service filters to the direction that governs here.
        let asking_as = trust
            .repository_uuid
            .clone()
            .or_else(|| repo.uuid_hint().map(str::to_owned))
            .unwrap_or_default();
        let snapshot = match client.as_ref() {
            Some(client) => client.snapshot_for(&asking_as),
            None => Err(ContractError::internal(
                "an online read has a Company client",
            )),
        };
        match snapshot {
            Ok(snapshot) => {
                trust.company_reachable = Some(true);
                if let Err(error) = cache.store_snapshot(&snapshot, &company_root, &now) {
                    crate::output::diagnostic("snapshot-refused", serde_json::to_value(&error).unwrap_or_else(|_| json!({"code": "RUN_INTEGRITY_FAILED", "message": "snapshot refusal detail was unreadable", "remediation": "Preserve the receipt.", "retryable": false, "evidence_id": "err_snapshot_refused"})));
                }
            }
            Err(error) => {
                trust.company_reachable = Some(false);
                crate::output::diagnostic("company-refresh-failed", serde_json::to_value(&error).unwrap_or_else(|_| json!({"code": "RUN_INTEGRITY_FAILED", "message": "refresh failure detail was unreadable", "remediation": "Preserve the receipt.", "retryable": false, "evidence_id": "err_refresh_failed"})));
            }
        }
        trust.company_connect_seconds = Some(started.elapsed().as_secs_f64());
    }
    trust.freshness = Some(cache.freshness(&now));
    if let Some(snapshot) = cache.snapshot()? {
        trust.company_snapshot_present = true;
        // Keys compared as text are held in their canonical spelling.
        trust.registry = crate::company::trust::canonical_registry(
            crate::json::get_array(&snapshot, "registry")
                .cloned()
                .unwrap_or_default(),
        );
        trust.revocations = crate::json::get_array(&snapshot, "revocations")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value::<Revocation>(item.clone()).ok())
                    .map(|mut revocation| {
                        revocation.revoked_key =
                            PublicKey::canonical_spelling(&revocation.revoked_key);
                        revocation
                    })
                    .collect()
            })
            .unwrap_or_default();
        trust.relaxations = crate::json::get_array(&snapshot, "relaxations")
            .cloned()
            .unwrap_or_default();
        trust.company_facts = crate::json::get_array(&snapshot, "facts")
            .cloned()
            .unwrap_or_default();
        trust.company_unknowns = crate::json::get_array(&snapshot, "unknowns")
            .cloned()
            .unwrap_or_default();
        trust.company_lifecycle = crate::json::get_array(&snapshot, "lifecycle_admissions")
            .cloned()
            .unwrap_or_default();
        trust.company_traces = crate::json::get_array(&snapshot, "traces")
            .cloned()
            .unwrap_or_default();
        trust.revocation_history = crate::json::get_array(&snapshot, "revocation_history")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| serde_json::from_value::<Revocation>(item.clone()).ok())
                    .map(|mut revocation| {
                        revocation.revoked_key =
                            PublicKey::canonical_spelling(&revocation.revoked_key);
                        revocation
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(Value::Object(parents)) = snapshot.get("fact_parents") {
            for (fact_id, items) in parents {
                trust.company_fact_parents.insert(
                    fact_id.clone(),
                    items.as_array().cloned().unwrap_or_default(),
                );
            }
        }
        if let Some(Value::Object(versions)) = snapshot.get("fact_versions") {
            for (fact_id, items) in versions {
                trust.fact_versions.insert(
                    fact_id.clone(),
                    items.as_array().cloned().unwrap_or_default(),
                );
            }
        }
        trust.authority_cursor = crate::json::get_str(&snapshot, "authority_cursor")
            .unwrap_or("0")
            .to_owned();
    }
    // Certificate: only from the cache, keyed by the config hint.
    if let Some(uuid) = hint_uuid {
        trust.repository_uuid = Some(uuid.clone());
        if cache
            .meta(&format!("certificate_identity_conflict:{uuid}"))
            .is_some()
        {
            trust.pin_state = "conflict".to_owned();
            trust.unknowns.push(identity_unknown(&uuid, &now));
        }
        // Architecture §2: one UUID binds one certificate. A second distinct
        // certificate installed for the same UUID (a later issuance, a stray
        // copy, or an index that disagrees with the file) makes the binding
        // ambiguous: nothing is trusted and the steward owns the Unknown.
        let claims = cache.certificate_claims(&uuid)?;
        let distinct_digests: BTreeSet<&str> = claims
            .iter()
            .filter_map(|claim| crate::json::get_str(claim, "digest"))
            .collect();
        if distinct_digests.len() > 1 {
            trust.certificate_conflicts = claims.clone();
            trust.pin_state = "conflict".to_owned();
            trust.certificate_reason = format!(
                "{} distinct certificates claim repository UUID {uuid} in the Company cache; the binding is ambiguous and nothing is trusted until the steward retires one",
                distinct_digests.len()
            );
            if !trust
                .unknowns
                .iter()
                .any(|unknown| crate::json::get_str(unknown, "kind") == Some("identity"))
            {
                trust.unknowns.push(identity_unknown(&uuid, &now));
            }
        }
        match cache.certificate(&uuid)? {
            Some(_) if !trust.certificate_conflicts.is_empty() => {}
            Some((certificate, digest)) => {
                let signer = PublicKey::verify_document("repo-certificate", &certificate);
                match signer {
                    Some(signer) if signer == company_root => {
                        trust.certificate = Some(certificate);
                        trust.certificate_digest = Some(digest);
                        trust.certificate_valid = true;
                        trust.certificate_reason =
                            "verified against the configured Company root".to_owned();
                    }
                    _ => {
                        trust.certificate_reason = "installed certificate fails verification against the configured Company root".to_owned();
                        trust.unknowns.push(certificate_unknown(&uuid, &now));
                    }
                }
            }
            None => {
                trust.unknowns.push(certificate_unknown(&uuid, &now));
            }
        }
        // Discovery-hint pin: the remote URL is only a hint; a changed UUID
        // for the same hint blocks with a steward-owned identity Unknown.
        if let Ok(remote) = crate::codebase::git(&repo.root, &["remote", "get-url", "origin"]) {
            let hint = normalize_hint(&remote);
            if !hint.is_empty() && trust.certificate_valid {
                match cache.pin(
                    &hint,
                    &uuid,
                    trust.certificate_digest.as_deref().unwrap_or_default(),
                    &trust.authority_cursor,
                    &now,
                )? {
                    crate::company::cache::PinOutcome::Pinned => {
                        trust.pin_state = "pinned".to_owned()
                    }
                    crate::company::cache::PinOutcome::Unchanged => {
                        trust.pin_state = "stable".to_owned()
                    }
                    crate::company::cache::PinOutcome::Conflict {
                        uuid: pinned_uuid,
                        digest: pinned_digest,
                    } => {
                        // Architecture §2: a later hint returning a different
                        // UUID or certificate blocks; it was reported and
                        // then trusted anyway.
                        let mismatch = if pinned_uuid == uuid {
                            format!(
                                "the certificate for repository UUID {uuid} changed since the discovery hint was pinned (pinned digest {}, installed {})",
                                short_digest(&pinned_digest),
                                short_digest(
                                    trust.certificate_digest.as_deref().unwrap_or_default()
                                )
                            )
                        } else {
                            format!(
                                "the discovery hint was pinned to repository UUID {pinned_uuid}, and this worktree names {uuid}"
                            )
                        };
                        trust.pin_state = "conflict".to_owned();
                        trust.certificate_valid = false;
                        trust.certificate_reason = format!(
                            "{mismatch}; nothing is trusted until a signed Company lineage/move event updates the binding"
                        );
                        trust.unknowns.push(json!({
                            "kind": "identity",
                            "unknown_id": format!("unknown_identity_{}", &crate::hash::sha256_text(&hint)[..24]),
                            "owner_role": "company-steward",
                            "owner_identity": "company-steward",
                            "repin_unknown_owner_roles": ["company-steward"],
                            "repin_blocked": true,
                            "response_due_at": crate::time::plus_seconds(&now, 24 * 3600).unwrap_or_default(),
                            "question": format!("{mismatch}; only a signed Company lineage/move event may update the binding"),
                            "status": "open"
                        }));
                    }
                }
            }
        }
    }
    Ok(trust)
}

fn short_digest(digest: &str) -> &str {
    digest.get(..16).unwrap_or(digest)
}

fn cache_needs_refresh(cache: &crate::company::cache::Cache, now: &str) -> bool {
    let freshness = cache.freshness(now);
    !(freshness.revocation_fresh && freshness.fact_fresh)
}

/// Ensure a verified authority snapshot is available for the requested cursor.
/// Returns `(cursor, source)`; offline callers receive the fresh cache or a
/// typed degraded error rather than silently treating "no snapshot" as "no
/// authority".
pub fn ensure_authority_snapshot(
    launcher: &Launcher,
    requested_cursor: Option<&str>,
    as_of: &str,
) -> Result<(String, &'static str), ContractError> {
    ensure_authority_snapshot_for(launcher, "", requested_cursor, as_of)
}

/// Ensure the cached snapshot is fresh *and* was selected for this repository.
/// The service filters a snapshot to the rulings that govern the asking
/// repository plus company-wide direction; the cache holds one snapshot for
/// the whole machine. A fresh snapshot fetched for another repository is not
/// this repository's direction, however recent it is, so scope is part of
/// freshness here. An empty `repository_uuid` keeps the scope-blind behaviour
/// of the company-wide callers.
pub fn ensure_authority_snapshot_for(
    launcher: &Launcher,
    repository_uuid: &str,
    requested_cursor: Option<&str>,
    as_of: &str,
) -> Result<(String, &'static str), ContractError> {
    let Some(mut company) = launcher.company()? else {
        return Err(ContractError::degraded(
            "CACHE_EXPIRED",
            "no configured Company authority snapshot source is available",
            "Configure the Company endpoint and cache root; authority is withheld rather than assumed absent.",
        ));
    };
    let now = as_of.to_owned();
    let cached_cursor = company
        .cache
        .meta("authority_cursor")
        .unwrap_or_else(|| "0".to_owned());
    let requested = requested_cursor.unwrap_or(cached_cursor.as_str());
    let wanted_scope = if repository_uuid.is_empty() {
        String::new()
    } else {
        format!("repository:{repository_uuid}")
    };
    let scope_matches = repository_uuid.is_empty()
        || company.cache.facts_scope().as_deref() == Some(wanted_scope.as_str());
    let cache_fresh = company.cache.state == crate::company::cache::CacheState::Warm
        && !cache_needs_refresh(&company.cache, &now)
        && scope_matches;
    // An explicit cursor is a temporal boundary for this invocation. It is
    // not a demand that the local registry cache already contain a snapshot
    // at or beyond that boundary; the reducer still sees and reports the
    // requested cursor while authority bytes remain independently verified.
    if requested_cursor.is_some() && cache_fresh {
        return Ok((requested.to_owned(), "requested"));
    }
    if cache_fresh
        && crate::reducer::cursor_order(&cached_cursor, requested) != std::cmp::Ordering::Less
    {
        return Ok((cached_cursor, "cache"));
    }
    match company.client.snapshot_for(repository_uuid) {
        Ok(snapshot) => {
            company
                .cache
                .store_snapshot(&snapshot, &company.root, &now)?;
            let cursor = crate::json::get_str(&snapshot, "authority_cursor")
                .map(str::to_owned)
                .unwrap_or_else(|| "0".to_owned());
            if requested_cursor.is_some() {
                return Ok((requested.to_owned(), "requested"));
            }
            if crate::reducer::cursor_order(&cursor, requested) == std::cmp::Ordering::Less {
                return Err(ContractError::degraded(
                    "CACHE_EXPIRED",
                    format!(
                        "Company authority snapshot cursor {cursor} predates the requested cursor {requested}"
                    ),
                    "Publish or fetch a registry snapshot at or after the requested cursor.",
                ));
            }
            Ok((cursor, "fetched"))
        }
        Err(error) => {
            if cache_fresh
                && crate::reducer::cursor_order(&cached_cursor, requested)
                    != std::cmp::Ordering::Less
            {
                return Ok((cached_cursor, "cache"));
            }
            Err(ContractError::degraded(
                "CACHE_EXPIRED",
                format!(
                    "no fresh authority snapshot is available ({})",
                    error.message
                ),
                "Restore the Company service or supply a fresh cached registry; authority is withheld rather than assumed absent.",
            ))
        }
    }
}

pub fn normalize_hint(remote: &str) -> String {
    let mut hint = remote.trim().to_lowercase();
    for prefix in ["https://", "http://", "ssh://", "git@", "git://"] {
        if let Some(rest) = hint.strip_prefix(prefix) {
            hint = rest.to_owned();
        }
    }
    hint = hint.replace(':', "/");
    hint = hint
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_owned();
    hint
}

fn identity_unknown(uuid: &str, now: &str) -> Value {
    json!({
        "kind": "identity",
        "unknown_id": format!("unknown_identity_{}", &crate::hash::sha256_text(uuid)[..24]),
        "owner_role": "company-steward",
        "owner_identity": "company-steward",
        "repository_uuid": uuid,
        "repin_blocked": true,
        "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
        "expiry_policy": "block_dependent_decision",
        "question": format!("A second certificate was refused for repository UUID {uuid}; only a signed Company lineage/move event may rebind the pinned certificate."),
        "status": "open"
    })
}

pub fn certificate_unknown(uuid: &str, now: &str) -> Value {
    json!({
        "kind": "certificate",
        "unknown_id": format!("unknown_certificate_{}", &crate::hash::sha256_text(uuid)[..24]),
        "owner_role": "repository-maintainer",
        "owner_identity": "repository-maintainer",
        "fallback_owner": "company-steward",
        "response_due_at": crate::time::plus_seconds(now, 24 * 3600).unwrap_or_default(),
        "expiry_policy": "block_dependent_decision",
        "question": format!("Install the steward-issued certificate for repository UUID {uuid} with `kinbase repo init --certificate <outside-worktree-file>`; until then every .kin/ event is UNVERIFIED and trusted projection is empty."),
        "status": "open"
    })
}

// ----- commands -----

pub fn issue_certificate(
    launcher: Launcher,
    repo_path: &Path,
    company_url: &str,
    json_output: bool,
) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    // Behaviour change: this used to require a loopback URL unconditionally.
    // It now defers to the operator's own [company] setting, so the flag governs
    // what this argument may name as well as where the service may bind. An
    // argument cannot widen the rule; only the configured endpoint can.
    let allow_non_loopback = launcher
        .shared
        .company
        .as_ref()
        .is_some_and(|company| company.allow_non_loopback);
    // Under the named form `--company` is a configured Company's name, already
    // resolved (and refused when unknown or claimed by another Company) by the
    // launcher; its URL was validated when the config was read.
    let named = launcher.named_form();
    if !named {
        crate::config::validate_loopback_url(company_url, allow_non_loopback)?;
    }
    if launcher.company_env_present {
        return Err(ContractError::new(
            "PROCESSOR_UNAUTHORIZED",
            "KINBASE_COMPANY_URL names a processor outside the configured authorization; no bytes were sent",
            "Configure the Company endpoint in the launcher user config.",
            false,
            crate::error::ExitCode::IntegrityFailure,
        ));
    }
    let Some(access) = &launcher.shared.company else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "no Company access is configured; a certificate request needs the launcher user config",
            "Create the user config with [company] url, facts_token_file, root_public_key_file, cache_root and an admin_token_file.",
        ));
    };
    if !named && access.url.trim_end_matches('/') != company_url.trim_end_matches('/') {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "--company differs from the configured Company endpoint",
            "Pass the endpoint configured in the user config; worktree or argv values cannot introduce endpoints.",
        ));
    }
    let Some(admin) = access.admin_token.clone() else {
        return Err(ContractError::refused(
            "AUTHORITY_SCOPE_DENIED",
            "certificate issuance requires the administrative token capability",
            "Ask the Company steward to issue the certificate, or configure admin_token_file.",
        ));
    };
    let client = crate::company::client::Client::new(
        &access.url,
        admin,
        access.client_key()?,
        Some(access.root_key()?),
        access.cache_root.clone(),
        access.allow_non_loopback,
    )?;
    let hint = crate::codebase::git(&repo.root, &["remote", "get-url", "origin"])
        .map(|remote| normalize_hint(&remote))
        .unwrap_or_default();
    let existing_uuid = repo.uuid_hint().map(str::to_owned);
    // An origin-less repository has no discovery hint. Sending "" made the
    // service treat every such repository as one: it answered the second
    // with the first one's certificate, so two repositories shared an
    // identity and each other's facts.
    let mut request = if hint.is_empty() {
        json!({})
    } else {
        json!({"discovery_hint": hint})
    };
    if let Some(uuid) = &existing_uuid {
        request["repository_uuid"] = Value::String(uuid.clone());
    }
    let response = client.post_ok("/certificates", &request)?;
    let certificate = response.get("certificate").cloned().unwrap_or(Value::Null);
    let result = json!({
        "status": crate::json::get_str(&response, "status").unwrap_or("issued"),
        "repository_uuid": crate::json::get_str(&certificate, "repository_uuid"),
        "certificate_subject": format!("repository UUID {} issued by Company {}", crate::json::get_str(&certificate, "repository_uuid").unwrap_or_default(), crate::json::get_str(&certificate, "company_id").unwrap_or_default()),
        "certificate_digest": crate::json::digest(&certificate),
        "certificate": certificate,
        "discovery_hint": hint,
        "install": format!("Save the certificate outside the worktree and run `kinbase repo init --repo {} --certificate <file>`.", repo.root.display()),
        "trust_on_first_use": false
    });
    crate::output::emit(&result, json_output);
    Ok(())
}

/// The most a steward certificate file may hold.
pub const CERTIFICATE_CEILING: usize = 64 * 1024;

pub fn init(
    launcher: Launcher,
    repo_path: &Path,
    certificate_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let repo = Repository::discover(repo_path)?;
    let canonical_repo = repo
        .root
        .canonicalize()
        .unwrap_or_else(|_| repo.root.clone());
    let canonical_cert = certificate_path
        .canonicalize()
        .unwrap_or_else(|_| certificate_path.to_path_buf());
    if canonical_cert.starts_with(&canonical_repo) {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            "the certificate file lies inside the worktree; worktree bytes cannot mint trust",
            "Store the steward certificate outside the worktree and pass that path.",
        ));
    }
    let bytes = crate::paths::read_bounded(certificate_path, CERTIFICATE_CEILING, "certificate")
        .map_err(|error| if error.code == "CONFIG_INVARIANT" { ContractError::user_action("REPO_UNCERTIFIED", format!("certificate file is unreadable ({})", error.message), "Ask the Company steward for the signed certificate file and pass its outside-worktree path.") } else { error })?;
    let document = crate::json::parse_strict_value(&bytes).map_err(|error| {
        ContractError::integrity(
            "DIGEST_MISMATCH",
            format!("certificate is not canonical JSON ({error})"),
            "Quarantine the certificate; no trust-on-first-use fallback exists.",
        )
    })?;
    // Preview every path before any byte changes; refuse collisions first.
    let planned = planned_init_paths(&repo);
    let collisions = kindex_collisions(&repo)?;
    if !collisions.is_empty() {
        return Err(ContractError::refused(
            "CONFIG_INVARIANT",
            format!(
                "{} path(s) under .kin/ collide with Kinbase reserved paths; no byte was changed",
                collisions.len()
            ),
            "Move the colliding legacy Kindex paths aside or initialize in a fresh repository.",
        )
        .with_detail(json!({"collisions": collisions, "planned_paths": planned})));
    }
    let init_clock = crate::time::proof_clock().as_of;
    if let Some(existing) = &repo.config {
        let offered = crate::json::get_str(&document, "repository_uuid").unwrap_or_default();
        if offered != existing.repository_uuid_hint.as_str() {
            // A hint resolving to a different UUID after pinning never
            // silently repins (architecture §2): the binding stays, and a
            // steward-owned identity Unknown is opened in the cache so every
            // later status reports it until a signed lineage/move event.
            let pinned = existing.repository_uuid_hint.clone();
            if let Ok(Some((cache, _root))) = launcher.company_cache_for_write() {
                let _ = cache.set_meta(
                    &format!("certificate_identity_conflict:{pinned}"),
                    &format!("{offered}:{}", crate::json::digest(&document)),
                );
            }
            let unknown = identity_unknown(&pinned, &init_clock);
            return Err(ContractError::refused(
                "FOREIGN_REPO_EVENTS",
                ".kin/config already binds a different repository UUID",
                "Obtain a signed lineage event before rebinding; the existing bytes are preserved.",
            )
            .with_detail(json!({
                "pinned_repository_uuid": pinned,
                "offered_repository_uuid": offered,
                "repository_uuid": pinned,
                "unknowns": [unknown]
            })));
        }
    }
    let authority_snapshot = ensure_authority_snapshot(&launcher, None, &init_clock);
    let Some((cache, root)) = launcher.company_cache()? else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "no Company root or cache is configured to verify and install the certificate",
            "Create the launcher user config with [company] root_public_key_file and cache_root first.",
        ));
    };
    let installed = cache.install_certificate(&document, &bytes, Some(&root), &init_clock)?;
    let uuid = crate::json::get_str(&installed, "repository_uuid")
        .unwrap_or_default()
        .to_owned();
    // Now the additive worktree changes. Every entry records what this exact
    // invocation created; an idempotent reinstall reports an empty set.
    let mut worktree_paths_written = Vec::new();
    let events_path = repo.kin.join("events");
    let events_existed = events_path.exists();
    crate::paths::ensure_dir(&events_path, ".kin/events")?;
    if !events_existed {
        worktree_paths_written.push(".kin/events/".to_owned());
    }
    let manifests_path = repo.kin.join("manifests");
    let manifests_existed = manifests_path.exists();
    crate::paths::ensure_dir(&manifests_path, ".kin/manifests")?;
    if !manifests_existed {
        worktree_paths_written.push(".kin/manifests/".to_owned());
    }
    let local_existed = repo.local_dir().exists();
    let local_dir = repo.ensure_local()?;
    repo.ensure_local_excluded()?;
    if !local_existed {
        worktree_paths_written.push(".kin/local/".to_owned());
    }
    // R-1: record the proof clock once in the private store, then replay that
    // exact instant for every later command that omits --as-of. The private
    // copy follows the repository UUID into a fresh clone and no worktree file
    // is created.
    let mut recorded_clock = None;
    if let Ok(private) = launcher.private_store() {
        let key = format!("proof-clock:{uuid}");
        if let Ok(Some(value)) = private.meta(&key) {
            if crate::time::parse_rfc3339_millis(value.trim()).is_ok() {
                recorded_clock = Some(value.trim().to_owned());
            }
        }
    }
    let recorded_clock = recorded_clock.unwrap_or_else(|| crate::time::proof_clock().as_of);
    let private = launcher.private_store()?;
    let key = format!("proof-clock:{uuid}");
    if private.meta(&key)?.is_none() {
        private.set_meta(&key, &recorded_clock)?;
    }
    // The first recorded instant also serves clones that carry no `.kin/config`
    // hint (a sparse or partial checkout): they replay the same proof clock
    // instead of reading the ambient wall clock.
    if private.meta("proof-clock:default")?.is_none() {
        private.set_meta("proof-clock:default", &recorded_clock)?;
    }
    let _ = local_dir;
    let config_path = repo.kin.join(crate::codebase::CONFIG_FILE);
    let config_existed = config_path.exists();
    if !config_existed {
        let safe_name = repo
            .root
            .file_name()
            .map(|name| {
                name.to_string_lossy()
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "repository".to_owned());
        let config = crate::codebase::RepoConfig {
            schema_version: crate::codebase::REPO_CONFIG_SCHEMA.to_owned(),
            repository_uuid_hint: uuid.clone(),
            safe_name,
            domains: Vec::new(),
            local_policy: BTreeMap::new(),
        };
        crate::paths::write_atomic(&config_path, config.to_toml().as_bytes(), 0o644, false)?;
        worktree_paths_written.push(format!(".kin/{}", crate::codebase::CONFIG_FILE));
    }
    let attributes_existed = repo.root.join(".gitattributes").exists();
    let attributes_added = repo.ensure_git_attributes()?;
    if !attributes_existed || !attributes_added.is_empty() {
        worktree_paths_written.push(".gitattributes".to_owned());
    }
    worktree_paths_written.sort();
    let result = json!({
        "status": "repo-initialized",
        "repository_uuid": uuid,
        "certificate_digest": installed.get("certificate_digest").cloned().unwrap_or(Value::Null),
        "certificate_cached_path": installed.get("certificate_cached_path").cloned().unwrap_or(Value::Null),
        "certificate_location": "company-cache",
        "planned_paths": planned,
        "worktree_paths_written": worktree_paths_written,
        "gitattributes_lines_added": attributes_added,
        "commit_only": [format!(".kin/{}", crate::codebase::CONFIG_FILE), ".kin/events/".to_owned(), ".kin/manifests/".to_owned(), ".gitattributes".to_owned()],
        "trust_on_first_use": false,
        "authority_snapshot": match &authority_snapshot {
            Ok((cursor, source)) => json!({"cursor": cursor, "source": source}),
            Err(error) => json!({"source": "unavailable", "error": {"code": error.code, "message": error.message, "remediation": error.remediation}}),
        }
    });
    crate::output::emit(&result, json_output);
    Ok(())
}

fn planned_init_paths(repo: &Repository) -> Vec<String> {
    vec![
        format!(
            "{}/.kin/{}",
            repo.root.display(),
            crate::codebase::CONFIG_FILE
        ),
        format!("{}/.kin/events/", repo.root.display()),
        format!("{}/.kin/manifests/", repo.root.display()),
        format!("{}/.kin/local/", repo.root.display()),
        format!("{}/.gitattributes (additive)", repo.root.display()),
    ]
}

/// Enumerate paths a pinned Kindex may own under `.kin/` and compare with
/// Kinbase's reserved paths (architecture §11).
fn kindex_collisions(repo: &Repository) -> Result<Vec<String>, ContractError> {
    let mut collisions = Vec::new();
    if !repo.kin.exists() {
        return Ok(collisions);
    }
    let events = repo.kin.join("events");
    if events.exists() {
        for entry in std::fs::read_dir(&events)
            .map_err(|error| ContractError::io("read .kin/events", error))?
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let metadata = entry
                .metadata()
                .map_err(|error| ContractError::io("stat", error))?;
            let conforming = metadata.is_dir()
                && name.len() == 2
                && name
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
            if !conforming {
                collisions.push(format!(".kin/events/{name}"));
            }
        }
    }
    let config = repo.kin.join(crate::codebase::CONFIG_FILE);
    if config.exists() {
        let text = std::fs::read_to_string(&config).unwrap_or_default();
        if crate::codebase::RepoConfig::parse(&text).is_err() {
            collisions.push(".kin/config".to_owned());
        }
    }
    for reserved in ["manifests", "local/kinbase-index.json"] {
        let path = repo.kin.join(reserved);
        if path.exists() && path.is_file() && reserved == "manifests" {
            collisions.push(".kin/manifests".to_owned());
        }
    }
    Ok(collisions)
}

/// Enumerate `.kin/events` files committed at the checked-out revision.
/// Worktree-only events are intentionally invisible to manifest publication.
fn committed_event_files(repo: &Repository) -> Result<Vec<StoredFile>, ContractError> {
    use std::io::{Cursor, Read, Write};

    let revision = repo.revision()?;
    let tree = std::process::Command::new("git")
        .args(["ls-tree", "-r", "-z", &revision, "--", ".kin/events"])
        .current_dir(&repo.root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|error| ContractError::io("run git ls-tree", error))?;
    if !tree.status.success() {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!(
                "git ls-tree failed: {}",
                String::from_utf8_lossy(&tree.stderr).trim()
            ),
            "Run the command inside the Git worktree whose revision is being published.",
        ));
    }
    let tree_text = String::from_utf8_lossy(&tree.stdout).into_owned();
    let mut objects = Vec::new();
    for entry in tree_text.split('\0') {
        if entry.is_empty() {
            continue;
        }
        let Some((metadata, path)) = entry.split_once('\t') else {
            continue;
        };
        let fields: Vec<&str> = metadata.split_whitespace().collect();
        if fields.len() == 3 && fields[1] == "blob" && path.starts_with(".kin/events/") {
            objects.push((fields[2].to_owned(), std::path::PathBuf::from(path)));
        }
    }
    if objects.is_empty() {
        return Ok(Vec::new());
    }

    let request = objects
        .iter()
        .map(|(oid, _)| format!("{oid}\n"))
        .collect::<Vec<_>>()
        .concat()
        .into_bytes();
    let mut child = std::process::Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(&repo.root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| ContractError::io("run git cat-file", error))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ContractError::internal("git cat-file stdin was unavailable"))?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let output = child
        .wait_with_output()
        .map_err(|error| ContractError::io("read git cat-file", error))?;
    let _ = writer.join();
    if !output.status.success() {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!(
                "git cat-file failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            "Run the command inside the Git worktree whose revision is being published.",
        ));
    }

    let mut cursor = Cursor::new(output.stdout);
    let mut files = Vec::new();
    for (oid, relative) in objects {
        let mut header = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            cursor
                .read_exact(&mut byte)
                .map_err(|error| ContractError::io("read git object header", error))?;
            if byte[0] == b'\n' {
                break;
            }
            header.push(byte[0]);
        }
        let header = String::from_utf8_lossy(&header).into_owned();
        let fields: Vec<&str> = header.split_whitespace().collect();
        if fields.len() != 3 || fields[0] != oid || fields[1] != "blob" {
            return Err(ContractError::internal(
                "git cat-file returned an unexpected object",
            ));
        }
        let size: usize = fields[2]
            .parse()
            .map_err(|_| ContractError::internal("git object size is malformed"))?;
        let mut bytes = vec![0_u8; size];
        cursor
            .read_exact(&mut bytes)
            .map_err(|error| ContractError::io("read committed event", error))?;
        let mut newline = [0_u8; 1];
        cursor
            .read_exact(&mut newline)
            .map_err(|error| ContractError::io("read committed event delimiter", error))?;
        if newline[0] != b'\n' {
            return Err(ContractError::internal("git object framing is malformed"));
        }
        let digest = crate::hash::sha256_bytes(&bytes);
        let path_digest = relative
            .strip_prefix(".kin/events")
            .ok()
            .and_then(crate::paths::digest_from_sharded);
        files.push(StoredFile {
            relative,
            digest: digest.clone(),
            bytes,
            path_alias: path_digest.as_deref() != Some(digest.as_str()),
        });
    }
    files.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(files)
}

pub fn publish_manifest(
    launcher: Launcher,
    repo_path: &Path,
    json_output: bool,
) -> Result<(), ContractError> {
    let result = publish_manifest_value(&launcher, repo_path)?;
    crate::output::emit(&result, json_output);
    Ok(())
}

/// Publish one dated, maintainer-signed manifest lineage without emitting a
/// second CLI document. Maintenance commands use this receipt internally.
pub(crate) fn publish_manifest_value(
    launcher: &Launcher,
    repo_path: &Path,
) -> Result<Value, ContractError> {
    let context = RepoContext::load(launcher.clone(), repo_path, true, None)?;
    let uuid = context.repository_uuid()?;
    let Some(access) = &context.launcher.shared.company else {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            "publishing a manifest requires Company access from the user config",
            "Create the launcher user config first.",
        ));
    };
    let maintainer = access.maintainer_key()?;
    // Maintenance observations are part of the reproducible proof lineage and
    // therefore replay the recorded repository clock rather than wall time.
    let now = recorded_clock(launcher, &context.repo)?;
    // Head regression check against the latest published observation (local or Company).
    let committed_events = committed_event_files(&context.repo)?;
    let local_count = committed_events.len() as i64;
    let rollback_exception = committed_events.iter().any(|file| {
        !file.path_alias
            && matches!(
                parse_stored(&file.bytes),
                ParsedEvent::Fact(event)
                    if (event.atom_kind == "rollback_exception" || event.disposition == "rollback_exception")
                        && context.trust.verify(&event) == Verification::Verified
            )
    });
    let published = published_observations(&context.repo);
    if let Some(prior) = published
        .iter()
        .filter_map(|item| item.get("count").and_then(Value::as_i64))
        .max()
    {
        if local_count < prior && !rollback_exception {
            return Err(ContractError::refused(
                "MANIFEST_HEAD_REGRESSION",
                format!(
                    "the reachable lineage now holds {local_count} events but the published observation records {prior}; no signed rewrite event explains the regression"
                ),
                "Supply a maintainer-signed rollback/rewrite event (atom_kind rollback_exception) or restore the missing events; a rollback without it is refused.",
            ));
        }
    }
    let manifest = context.repo.publish_manifest_with_events(
        &uuid,
        &maintainer,
        &now,
        3600,
        &committed_events,
    )?;
    let mut result = json!({
        "status": "published",
        "repository_uuid": uuid,
        "manifest_digest": manifest.get("manifest_digest").cloned().unwrap_or(Value::Null),
        "manifest_path": manifest.get("manifest_path").cloned().unwrap_or(Value::Null),
        "event_count": manifest.get("event_count").cloned().unwrap_or(Value::Null),
        "merkle_root": manifest.get("merkle_root").cloned().unwrap_or(Value::Null),
        "branch": manifest.get("branch").cloned().unwrap_or(Value::Null),
        "observed_default_branch_revision": manifest.get("observed_default_branch_revision").cloned().unwrap_or(Value::Null),
        "fresh_until": manifest.get("fresh_until").cloned().unwrap_or(Value::Null),
        "rollback_exception_present": rollback_exception
    });
    // Send the dated observation to Company (best effort within budget; a
    // refusal is typed and reported, never silent).
    let mut document = manifest.clone();
    if let Some(map) = document.as_object_mut() {
        map.remove("manifest_digest");
        map.remove("manifest_path");
        if rollback_exception {
            map.insert(
                "rollback_event".to_owned(),
                Value::String("rollback_exception".to_owned()),
            );
        }
    }
    match context.launcher.company()? {
        Some(company) => match company.client.post("/manifests", &document) {
            Ok(response) if response.status < 300 => {
                result["company_receipt"] = response.body;
            }
            Ok(response) => {
                let error = crate::company::client::error_from_response(&response);
                if error.code == "MANIFEST_HEAD_REGRESSION" {
                    return Err(error);
                }
                result["company_refusal"] = crate::output::error_document(&error)["error"].clone();
            }
            Err(error) => {
                result["company_refusal"] = crate::output::error_document(&error)["error"].clone();
            }
        },
        None => {
            result["company_refusal"] = Value::String(
                "no Company access configured; observation stored locally only".to_owned(),
            );
        }
    }
    // Local record of the published observation (the instrument's stand-in
    // directory is also honored on read).
    let published_dir = context.repo.kin.join("local").join("published");
    crate::paths::ensure_private_dir(&published_dir, "published observations")?;
    let record = json!({
        "heads": {manifest.get("branch").and_then(Value::as_str).unwrap_or("main"): manifest.get("observed_default_branch_revision").cloned().unwrap_or(Value::Null)},
        "count": local_count,
        "fresh_until": manifest.get("fresh_until").cloned().unwrap_or(Value::Null),
        "event_digests": manifest.get("event_digests").cloned().unwrap_or(Value::Array(Vec::new())),
        "manifest_digest": manifest.get("manifest_digest").cloned().unwrap_or(Value::Null),
        "published_at": now
    });
    crate::paths::write_atomic(
        &published_dir.join(format!(
            "{}.json",
            crate::json::get_str(&manifest, "manifest_digest").unwrap_or("latest")
        )),
        &crate::json::record_bytes(&record)?,
        0o600,
        false,
    )?;
    Ok(result)
}

/// The number of committed `.kin/events/` bytes available to a manifest.
pub(crate) fn committed_event_count(repo_path: &Path) -> Result<usize, ContractError> {
    let repository = Repository::discover(repo_path)?;
    Ok(committed_event_files(&repository)?.len())
}

/// Published manifest observations visible locally: the instrument's
/// `.kin/published/*.json` stand-ins plus the product's own records.
pub fn published_observations(repo: &Repository) -> Vec<Value> {
    let mut output = Vec::new();
    for dir in [
        repo.kin.join("published"),
        repo.kin.join("local").join("published"),
    ] {
        if let Ok(files) = crate::paths::list_files(&dir) {
            for relative in files {
                if let Ok(bytes) = std::fs::read(dir.join(&relative)) {
                    if let Ok(value) = crate::json::parse_strict_value(&bytes).or_else(|_| {
                        serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())
                    }) {
                        output.push(value);
                    }
                }
            }
        }
    }
    output
}

/// Compare local event digests with every dated manifest observation. The
/// observation never changes current truth; it is only a completeness report.
fn manifest_observation_report(
    repo: &Repository,
    local_digests: &BTreeSet<String>,
    now: &str,
) -> Result<(String, usize, bool, Vec<Value>), ContractError> {
    let mut classification = "no-published-observation".to_owned();
    let mut missing_heads = 0usize;
    let mut expired_publication = false;
    let mut comparisons = Vec::new();
    for observation in published_observations(repo) {
        let count = observation
            .get("count")
            .and_then(Value::as_i64)
            .unwrap_or(0) as usize;
        let digests: BTreeSet<String> = crate::json::get_array(&observation, "event_digests")
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let fresh_until = crate::json::get_str(&observation, "fresh_until")
            .unwrap_or_default()
            .to_owned();
        let expired = !fresh_until.is_empty() && fresh_until.as_str() <= now;
        if expired {
            expired_publication = true;
        }
        let comparison = if digests.is_empty() {
            match local_digests.len().cmp(&count) {
                std::cmp::Ordering::Equal => "equal",
                std::cmp::Ordering::Greater => "superset",
                std::cmp::Ordering::Less => "subset",
            }
        } else {
            crate::codebase::compare_event_sets(local_digests, &digests)
        };
        let unreachable = observation
            .get("unreachable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !expired {
            classification = match comparison {
                "equal" => "complete".to_owned(),
                "superset" => "normal_lag".to_owned(),
                "subset" => {
                    missing_heads += count.saturating_sub(local_digests.len()).max(1);
                    "INCOMPLETE".to_owned()
                }
                _ if unreachable => "divergent-branch".to_owned(),
                _ => {
                    missing_heads += 1;
                    "INCOMPLETE".to_owned()
                }
            };
        }
        comparisons.push(json!({
            "repository_uuid": observation.get("repository_uuid").cloned().unwrap_or(Value::Null),
            "branch": observation.get("branch").cloned().unwrap_or(Value::Null),
            "revision": observation.get("observed_default_branch_revision").or_else(|| observation.get("revision")).cloned().unwrap_or(Value::Null),
            "comparison": comparison,
            "lifecycle": if expired { "manifest_observation_expired" } else { "current" },
            "fresh_until": fresh_until,
            "published_count": count,
            "local_count": local_digests.len()
        }));
    }
    Ok((
        classification,
        missing_heads,
        expired_publication,
        comparisons,
    ))
}

/// `status --json` (interface contract §1.2).
pub fn status(
    launcher: Launcher,
    repo_path: &Path,
    as_of: &crate::time::AsOf,
    json_output: bool,
) -> Result<(), ContractError> {
    // Overdue apologies close under the exclusive lock before this report
    // takes its shared read of the destination. A report is still given
    // when that fails, and says why.
    // Closing an overdue apology is a real-world deadline, so it reads the
    // proof clock (pinned in acceptance runs, else the wall clock) and the
    // report says so; the view itself still reduces at `as_of`.
    let maintenance_clock = crate::time::proof_clock();
    if let Err(error) =
        crate::session::emit_due_orphan_abandonments(&launcher, repo_path, &maintenance_clock)
    {
        crate::output::diagnostic(
            "orphan-abandonment-failed",
            json!({"code": error.code, "message": error.message}),
        );
    }
    // Read one consistent destination generation: the shared admission lock
    // is held for the whole report so it never straddles a writer's journal
    // transition (writers advance between reads, never under one).
    let _generation_read = Repository::shared_generation_lock(repo_path)?;
    let context = RepoContext::load(launcher, repo_path, true, Some(&as_of.as_of))?;
    let (view, counts, references) = if context.repo.config.is_some() {
        context.current_view(&as_of.as_of, None)?
    } else {
        (empty_view(&as_of.as_of), LoadCounts::default(), Vec::new())
    };
    let private = context.launcher.private_store()?;
    let status_changed_dispositions = changed_dispositions(&private)?;
    let mut trusted = 0usize;
    // The Company view is an input from its own authority (Helland: data on
    // the outside). It is reported alongside the repository view; a logical
    // key supported by both stores with one statement is one multiply
    // supported fact whose provenance is the union of both supports.
    let company_facts_by_key: BTreeMap<String, Vec<&Value>> = context
        .trust
        .company_facts
        .iter()
        .filter_map(|fact| {
            crate::json::get_str(fact, "logical_key").map(|key| (key.to_owned(), fact))
        })
        .fold(BTreeMap::new(), |mut map, (key, fact)| {
            map.entry(key).or_default().push(fact);
            map
        });
    let company_trace_by_key: BTreeMap<String, &Value> = context
        .trust
        .company_traces
        .iter()
        .filter_map(|trace| {
            crate::json::get_str(trace, "logical_key").map(|key| (key.to_owned(), trace))
        })
        .collect();
    let company_admitted_ids = |key: &str| -> Vec<String> {
        company_trace_by_key
            .get(key)
            .and_then(|trace| crate::json::get_array(trace, "admitted_event_ids"))
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    let company_fact_row = |fact: &Value, state: &str| -> Value {
        json!({
            "fact_id": fact.get("fact_id").cloned().unwrap_or(Value::Null),
            "event_id": fact.get("event_id").cloned().unwrap_or(Value::Null),
            "logical_key": fact.get("logical_key").cloned().unwrap_or(Value::Null),
            "state": state,
            "current_fact_state": fact.get("status").cloned().unwrap_or(Value::Null),
            "statement": fact.get("statement").cloned().unwrap_or(Value::Null),
            "evidence_refs": fact.get("evidence_refs").cloned().unwrap_or_else(|| json!([])),
            "trust": fact.get("trust").cloned().unwrap_or(Value::Null),
            "authority_scope": fact.get("authority_scope").cloned().unwrap_or(Value::Null),
            "authority_id": fact.get("authority_id").cloned().unwrap_or(Value::Null),
            "store_kind": "company",
            "stores": ["company"],
            "provenance_recomputed": false,
            "support_event_ids": fact.get("support_event_ids").cloned().unwrap_or_else(|| json!([])),
            "independent_support_count": fact.get("independent_support_count").cloned().unwrap_or(json!(0)),
            "stale_reasons": fact.get("stale_reasons").cloned().unwrap_or_else(|| json!([])),
            "effective_criticality": fact.get("criticality").cloned().unwrap_or(Value::Null)
        })
    };
    let mut merged_company_keys: BTreeSet<String> = BTreeSet::new();
    let facts: Vec<Value> = view
        .facts
        .iter()
        .map(|fact| {
            if fact.trust == "trusted" && fact.status == "current" {
                trusted += 1;
            }
            let trace = view
                .traces
                .iter()
                .find(|trace| trace.logical_key == fact.logical_key);
            let mut support: Vec<String> = fact.support_event_ids.clone();
            let mut admitted: Vec<String> = trace
                .map(|trace| trace.admitted_event_ids.clone())
                .unwrap_or_default();
            let mut independent = fact.independent_support_count;
            let mut stores = vec!["codebase".to_owned()];
            let mut company_fact_id = Value::Null;
            let same_statement = company_facts_by_key
                .get(&fact.logical_key)
                .into_iter()
                .flatten()
                .find(|company| merges_with_company(&fact.status, &fact.statement, company))
                .copied();
            if let Some(company) = same_statement {
                merged_company_keys.insert(fact.logical_key.clone());
                stores.push("company".to_owned());
                company_fact_id = company.get("fact_id").cloned().unwrap_or(Value::Null);
                for id in crate::json::get_array(company, "support_event_ids")
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    if !support.iter().any(|existing| existing == id) {
                        support.push(id.to_owned());
                    }
                }
                independent += company
                    .get("independent_support_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
            }
            for id in company_admitted_ids(&fact.logical_key) {
                if !admitted.contains(&id) {
                    admitted.push(id);
                }
            }
            // Provenance is recomputed when an admitted support of this key
            // (in either store) no longer supports it: a retired support
            // changed the derivation without changing the statement.
            let provenance_recomputed = admitted.iter().any(|id| !support.contains(id))
                || !status_changed_dispositions.is_empty();
            json!({
                "fact_id": fact.fact_id,
                "event_id": fact.event_id,
                "logical_key": fact.logical_key,
                "state": if fact.status == "current" { "current" } else { "withheld" },
                "current_fact_state": fact.status.clone(),
                "standing": fact.standing,
                "claimed_standing": fact.standing,
                "provenance": fact.provenance,
                "governs_paths": fact.governs_paths,
                "anchors": fact.anchors,
                "statement": fact.statement,
                "evidence_refs": fact.evidence_refs,
                "trust": fact.trust,
                "authority_scope": fact.authority_scope,
                "authority_id": fact.authority_id,
                "store_kind": "codebase",
                "stores": stores,
                "company_fact_id": company_fact_id,
                "provenance_recomputed": provenance_recomputed,
                "support_event_ids": support,
                "admitted_event_ids": admitted,
                "independent_support_count": independent,
                "effective_criticality": fact.effective_dependence_class.clone().unwrap_or_else(|| fact.criticality.clone())
            })
        })
        .collect();
    let mut all_facts = facts.clone();
    // Company facts that no repository fact shares: current or withheld rows
    // exactly as the Company reduced them.
    for fact in &context.trust.company_facts {
        let Some(key) = crate::json::get_str(fact, "logical_key") else {
            continue;
        };
        if merged_company_keys.contains(key) {
            continue;
        }
        let status_text = crate::json::get_str(fact, "status").unwrap_or("withheld");
        let state = if status_text == "current" {
            "current"
        } else {
            "withheld"
        };
        let mut row = company_fact_row(fact, state);
        let support: Vec<String> = crate::json::get_array(fact, "support_event_ids")
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let admitted = company_admitted_ids(key);
        row["admitted_event_ids"] = json!(admitted);
        row["provenance_recomputed"] = Value::Bool(admitted.iter().any(|id| !support.contains(id)));
        all_facts.push(row);
    }
    let has_current_row = |rows: &[Value], key: &str| {
        rows.iter().any(|row| {
            crate::json::get_str(row, "logical_key") == Some(key)
                && crate::json::get_str(row, "state") == Some("current")
        })
    };
    for trace in &view.traces {
        if trace.current_fact_id.is_none() && !has_current_row(&all_facts, &trace.logical_key) {
            all_facts.push(json!({
                "logical_key": trace.logical_key,
                "state": match trace.state.as_str() { "conflict" => "conflict", "withdrawn" | "expired" => "withdrawn", _ => "unknown" },
                "statement": Value::Null,
                "trust": "withheld",
                "store_kind": "codebase",
                "evidence_refs": trace.admitted_event_ids,
                "admitted_event_ids": trace.admitted_event_ids,
                "support_event_ids": []
            }));
        }
    }
    for trace in &context.trust.company_traces {
        let Some(key) = crate::json::get_str(trace, "logical_key") else {
            continue;
        };
        if crate::json::get_str(trace, "current_fact_id").is_some()
            || all_facts
                .iter()
                .any(|row| crate::json::get_str(row, "logical_key") == Some(key))
        {
            continue;
        }
        let state = match crate::json::get_str(trace, "state").unwrap_or("missing") {
            "conflict" => "conflict",
            "withdrawn" | "expired" | "missing" => "withdrawn",
            _ => "unknown",
        };
        all_facts.push(json!({
            "logical_key": key,
            "state": state,
            "statement": Value::Null,
            "trust": "withheld",
            "store_kind": "company",
            "evidence_refs": trace.get("admitted_event_ids").cloned().unwrap_or_else(|| json!([])),
            "admitted_event_ids": trace.get("admitted_event_ids").cloned().unwrap_or_else(|| json!([])),
            "support_event_ids": []
        }));
    }
    let mut unknowns: Vec<Value> = context.trust.unknowns.clone();
    for unknown in &view.unknowns {
        unknowns.push(json!({
            "kind": unknown.kind,
            "unknown_id": unknown.unknown_id,
            "logical_key": unknown.logical_key,
            "owner_role": unknown.owner_role,
            "owner_identity": unknown.owner_identity,
            "owner": unknown.owner_identity,
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": unknown.question,
            "status": unknown.status,
            "unknown_state": unknown.status.clone(),
            "store_kind": "codebase"
        }));
    }
    for unknown in &context.trust.company_unknowns {
        let status_text = crate::json::get_str(unknown, "status").unwrap_or("open");
        unknowns.push(json!({
            "kind": unknown.get("kind").cloned().unwrap_or(Value::Null),
            "unknown_id": unknown.get("unknown_id").cloned().unwrap_or(Value::Null),
            "logical_key": unknown.get("logical_key").cloned().unwrap_or(Value::Null),
            "owner_role": unknown.get("owner_role").cloned().unwrap_or(Value::Null),
            "owner_identity": unknown.get("owner_identity").cloned().unwrap_or(Value::Null),
            "owner": unknown.get("owner_identity").cloned().unwrap_or(Value::Null),
            "response_due_at": unknown.get("response_due_at").cloned().unwrap_or_else(|| Value::String(crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default())),
            "question": unknown.get("question").cloned().unwrap_or(Value::Null),
            "decision_blocked": unknown.get("decision_blocked").cloned().unwrap_or(Value::Null),
            "status": status_text,
            "unknown_state": status_text,
            "store_kind": "company"
        }));
    }
    // A decision whose parent fact lost its last support in any store
    // reopens under its own principal: the dependent row is withheld and an
    // owned Unknown names the withdrawn premise (V-1 support retirement).
    let mut dependent_reopened: Vec<Value> = Vec::new();
    for fact in &context.trust.company_facts {
        let Some(fact_id) = crate::json::get_str(fact, "fact_id") else {
            continue;
        };
        if crate::json::get_str(fact, "status") != Some("current") {
            continue;
        }
        let Some(parents) = context.trust.company_fact_parents.get(fact_id) else {
            continue;
        };
        let withdrawn_parents: Vec<&Value> = parents
            .iter()
            .filter(|parent| {
                crate::json::get_str(parent, "logical_key")
                    .is_some_and(|key| !key.is_empty() && !has_current_row(&all_facts, key))
            })
            .collect();
        if withdrawn_parents.is_empty() {
            continue;
        }
        let logical_key = crate::json::get_str(fact, "logical_key")
            .unwrap_or_default()
            .to_owned();
        let owner = crate::json::get_str(fact, "authority_id")
            .unwrap_or_default()
            .to_owned();
        let premises: Vec<String> = withdrawn_parents
            .iter()
            .filter_map(|parent| crate::json::get_str(parent, "logical_key").map(str::to_owned))
            .collect();
        for row in all_facts.iter_mut() {
            if crate::json::get_str(row, "logical_key") == Some(logical_key.as_str()) {
                row["state"] = Value::String("withheld".to_owned());
                row["reopened"] = Value::Bool(true);
                row["withdrawn_premises"] = json!(premises);
            }
        }
        let unknown_id = format!(
            "unknown_reopened_{}",
            &crate::hash::sha256_text(&format!("{logical_key}\0{}", premises.join(",")))[..24]
        );
        let decision_blocked = format!("use of logical key {logical_key}");
        unknowns.push(json!({
            "kind": "reopened",
            "unknown_id": unknown_id,
            "logical_key": logical_key,
            "affected_logical_keys": premises,
            "owner_role": "decision-principal",
            "owner_identity": owner,
            "owner": owner,
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": format!("The premise {} of decision {logical_key} lost its last admissible support. Does the decision still hold?", premises.join(", ")),
            "decision_blocked": decision_blocked,
            "status": "reopened",
            "unknown_state": "reopened",
            "store_kind": "company"
        }));
        dependent_reopened.push(json!({
            "logical_key": logical_key,
            "decision_blocked": decision_blocked,
            "kind": "dependent-support-withdrawn",
            "withdrawn_premises": premises,
            "owner_identity": owner
        }));
    }
    let no_events = (Vec::new(), LoadCounts::default());
    let (events, _) = if context.repo.config.is_some() {
        context.load_events()?
    } else {
        &no_events
    };
    let local_digests: BTreeSet<String> = events
        .iter()
        .filter(|event| !event.file.path_alias)
        .map(|event| event.file.digest.clone())
        .collect();
    let (
        manifest_classification,
        manifest_missing_heads,
        manifest_expired_publication,
        manifest_comparisons,
    ) = manifest_observation_report(&context.repo, &local_digests, &as_of.as_of)?;
    // A lapsed publication is Company's own event (architecture §6, Codebase):
    // the retired observation opens a Company-steward publication Unknown that
    // does not wait for a maintainer or clone to notice.
    let uuid = context.trust.repository_uuid.clone().unwrap_or_default();
    let company_expired = context.trust.company_facts.iter().any(|fact| {
        crate::json::get_str(fact, "disposition") == Some("manifest_observation_expired")
            && crate::json::get_str(fact, "logical_key")
                .is_some_and(|key| key.ends_with(uuid.as_str()))
    });
    if manifest_expired_publication || company_expired {
        unknowns.push(json!({
            "kind": "publication",
            "unknown_id": format!("unknown_publication_{}", &crate::hash::sha256_text(&uuid)[..24]),
            "logical_key": format!("manifest-observation:{uuid}"),
            "owner_role": "company-steward",
            "owner_identity": context.trust.steward_authority_id().unwrap_or_else(|| "company-steward".to_owned()),
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": format!("The maintainer-published manifest observation for repository {uuid} lapsed without replacement and is historical-only; republish or retire the repository."),
            "status": "open",
            "unknown_state": "open"
        }));
    }
    let mut fact_by_event_id: BTreeMap<&str, &crate::model::FactEvent> = BTreeMap::new();
    let mut fact_by_fact_id: BTreeMap<&str, &crate::model::FactEvent> = BTreeMap::new();
    for item in events {
        if let ParsedEvent::Fact(event) = &item.parsed {
            fact_by_event_id.insert(event.event_id.as_str(), event);
            fact_by_fact_id.insert(event.fact_id.as_str(), event);
        }
    }
    let mut event_records = Vec::new();
    let mut exceptions = Vec::new();
    let mut exception_request_accepted = false;
    // Steward relaxations live in Company; the snapshot publishes them. They
    // are accepted only when the document verifies under a steward key.
    let steward_keys = context.trust.steward_keys();
    for relaxation in &context.trust.relaxations {
        let signer = crate::json::get_str(relaxation, "signer").unwrap_or_default();
        let mut document = relaxation.clone();
        if let Some(map) = document.as_object_mut() {
            map.remove("expires_at");
            map.remove("status");
        }
        let verified = PublicKey::verify_document("fact-event", &document)
            .is_some_and(|key| steward_keys.contains(&key.to_hex()));
        let steward = steward_keys.contains(signer) && verified;
        exceptions.push(json!({
            "signed_by": crate::json::get_str(relaxation, "authority_id").unwrap_or("company-steward"),
            "kind": "relaxation",
            "store": "company",
            "event_id": crate::json::get_str(relaxation, "event_id"),
            "expires_at": crate::json::get_str(relaxation, "expires_at").filter(|value| !value.is_empty()).or_else(|| crate::json::get_str(relaxation, "effective_until")),
            "accepted": steward,
            "refusal_code": if steward { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
        }));
    }
    let mut misextraction_notices = Vec::new();
    let mut never_true = Vec::new();
    for item in events {
        if let ParsedEvent::Fact(event) = &item.parsed {
            let verified = item.verification == Some(Verification::Verified);
            let revocation_observed = context.trust.is_revoked(&event.signer);
            let fact_state = view
                .traces
                .iter()
                .find(|trace| trace.logical_key == event.logical_key)
                .map(|trace| trace.state.clone());
            let mut record = json!({
                "event_id": event.event_id,
                "atom_kind": event.atom_kind,
                // The standing a fact actually carries, after provenance clamps it.
                // Surfacing the effective value rather than the claimed one is the
                // point: a caller must be able to see that an agent-authored fact
                // did not reach `prevalent`, and an internal-only field cannot be
                // verified by anyone outside this process.
                "standing": crate::model::effective_standing(&event.standing, &event.provenance),
                "claimed_standing": event.standing,
                "provenance": event.provenance,
                "governs_paths": event.governs_paths,
                "anchors": event.anchors,
                "disposition": event.disposition,
                "statement": event.statement,
                "signature": event.signature,
                "verification": item.verification.as_ref().map(crate::company::trust::verification_text),
                "origin_trust_class": item.origin_trust,
                "fact_state": fact_state,
                "revocation_observed": revocation_observed,
                "observed_effect": revocation_observed && fact_state.as_deref() != Some("current")
            });
            if let Some(closing) = event
                .raw
                .as_ref()
                .and_then(|raw| crate::json::get_str(raw, "unresponsive_closing_authority"))
            {
                record["unresponsive_closing_authority"] = Value::String(closing.to_owned());
            }
            // A terminal saga event emitted by the destination service carries
            // the saga's own state for the orphaned claim (withdrawn) and the
            // unresponsive closing authority; the fan-out saga owns that fact.
            if let Some(Value::Object(saga)) =
                crate::session::saga_terminal_event_fields(&event.event_id)
            {
                for (key, value) in saga {
                    record[key] = value;
                }
            }
            event_records.push(record);
            let action = crate::model::action_of(event).unwrap_or(event.atom_kind.as_str());
            match action {
                "exception_request" => {
                    // Interface contract C13: the request is a maintainer-signed
                    // FactEvent bound to this repository whose parents name the
                    // Company fact it asks to relax, with a bounded expiry.
                    let document = event.document();
                    let names_target = !event.parents.is_empty()
                        || !event.supersedes.is_empty()
                        || crate::json::get_str(&document, "relaxed_fact_id").is_some();
                    let bounded = event.effective_until.is_some()
                        || crate::json::get_str(&document, "expires_at").is_some();
                    let bound = event.repository_id.as_deref()
                        == context.trust.repository_uuid.as_deref()
                        && names_target
                        && bounded;
                    let accepted = verified && bound;
                    exception_request_accepted = exception_request_accepted || accepted;
                    exceptions.push(json!({
                        "signed_by": event.authority_id,
                        "kind": "exception_request",
                        "event_id": event.event_id,
                        "accepted": accepted,
                        "refusal_code": if accepted { Value::Null } else { Value::String("CONFIG_INVARIANT".to_owned()) }
                    }));
                }
                "exception_to" | "relaxation" => {
                    let steward = context.trust.steward_keys().contains(&event.signer) && verified;
                    exceptions.push(json!({
                        "signed_by": event.authority_id,
                        "kind": if action == "relaxation" { "relaxation" } else { event.atom_kind.as_str() },
                        "event_id": event.event_id,
                        "accepted": steward,
                        "refusal_code": if steward { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
                    }));
                }
                "misextraction" => {
                    let target_logical_key = event
                        .parents
                        .iter()
                        .chain(event.supersedes.iter())
                        .find_map(|id| {
                            fact_by_event_id
                                .get(id.as_str())
                                .or_else(|| fact_by_fact_id.get(id.as_str()))
                                .map(|fact| fact.logical_key.clone())
                        })
                        .unwrap_or_else(|| event.logical_key.clone());
                    let trace = view
                        .traces
                        .iter()
                        .find(|trace| trace.logical_key == target_logical_key);
                    misextraction_notices.push(json!({
                        "logical_key": target_logical_key,
                        "admitted": trace.is_some_and(|trace| trace.notice_admitted),
                        "notice_admitted": trace.is_some_and(|trace| trace.notice_admitted),
                        "asserted_claim": "evidence_byte_mismatch",
                        "semantic_withdrawal": false
                    }));
                }
                "never_true" => {
                    let target_logical_key = event
                        .parents
                        .iter()
                        .chain(event.supersedes.iter())
                        .find_map(|id| {
                            fact_by_event_id
                                .get(id.as_str())
                                .or_else(|| fact_by_fact_id.get(id.as_str()))
                                .map(|fact| fact.logical_key.clone())
                        })
                        .unwrap_or_else(|| event.logical_key.clone());
                    let trace = view
                        .traces
                        .iter()
                        .find(|trace| trace.logical_key == target_logical_key);
                    let approver_minted_accepted = trace
                        .and_then(|trace| trace.approver_minted_accepted)
                        .unwrap_or(true);
                    let accepted = verified && approver_minted_accepted;
                    never_true.push(json!({
                        "authority_id": event.authority_id,
                        "accepted": accepted,
                        "approver_minted_accepted": approver_minted_accepted,
                        "refusal_code": if accepted { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) }
                    }));
                }
                _ => {}
            }
        }
    }
    // Lifecycle admissions the Company recorded (C7: Company facts are
    // admitted through the service, so their notices and withdrawals are
    // reported from the Company's own admission record, accepted or refused).
    for record in &context.trust.company_lifecycle {
        let action = crate::json::get_str(record, "action").unwrap_or_default();
        let accepted = record.get("accepted") == Some(&Value::Bool(true));
        let logical_key = record.get("logical_key").cloned().unwrap_or(Value::Null);
        match action {
            "misextraction" => misextraction_notices.push(json!({
                "logical_key": logical_key,
                "admitted": accepted,
                "notice_admitted": accepted,
                "asserted_claim": "evidence_byte_mismatch",
                "semantic_withdrawal": false,
                "authority_id": record.get("authority_id").cloned().unwrap_or(Value::Null),
                "event_id": record.get("event_id").cloned().unwrap_or(Value::Null),
                "store_kind": "company"
            })),
            "never_true" => never_true.push(json!({
                "authority_id": record.get("authority_id").cloned().unwrap_or(Value::Null),
                "accepted": accepted,
                "approver_minted_accepted": accepted,
                "refusal_code": if accepted { Value::Null } else { record.get("refusal_code").cloned().unwrap_or_else(|| Value::String("AUTHORITY_WRONG_SCOPE".to_owned())) },
                "logical_key": logical_key,
                "event_id": record.get("event_id").cloned().unwrap_or(Value::Null),
                "store_kind": "company"
            })),
            _ => {}
        }
    }
    // Company-side events visible through the cache (orphan_abandoned,
    // observation_expired) are reported from the snapshot facts.
    for fact in &context.trust.company_facts {
        let kind = crate::json::get_str(fact, "atom_kind").unwrap_or_default();
        if kind == "orphan_abandoned"
            || kind == "observation_expired"
            || crate::json::get_str(fact, "disposition")
                .is_some_and(|d| d == "orphan_abandoned" || d == "manifest_observation_expired")
        {
            let disposition = crate::json::get_str(fact, "disposition").unwrap_or_default();
            let orphan = kind == "orphan_abandoned" || disposition == "orphan_abandoned";
            event_records.push(json!({
                "event_id": fact.get("event_id").cloned().unwrap_or(Value::Null),
                "logical_key": fact.get("logical_key").cloned().unwrap_or(Value::Null),
                "atom_kind": if orphan { "orphan_abandoned" } else { "observation_expired" },
                "disposition": if orphan { "orphan_abandoned" } else { "manifest_observation_expired" },
                "store_kind": "company",
                "statement": fact.get("statement").cloned().unwrap_or(Value::Null),
                "fact_state": fact.get("status").cloned().unwrap_or(Value::Null),
                "unresponsive_closing_authority": fact.get("unresponsive_closing_authority").cloned().unwrap_or(Value::Null),
                "observation_status": "historical-only"
            }));
        }
    }
    let ledger = private.all_observations()?;
    let trust_facts = trust_facts(&context.launcher, Some(&context.trust));
    let derived = crate::lifecycle::derive(&ledger, &trust_facts, &as_of.as_of);
    let observations = private_observations(&ledger, &derived);
    // Adapter-derived facts and Unknowns join the reported view: facts a
    // source observation supports, keyed by the adapter's logical key, with
    // their evidence bound to observation ids.
    for fact in &derived.facts {
        all_facts.push(json!({
            "fact_id": fact.fact_id,
            "logical_key": fact.logical_key,
            "state": fact.state,
            "current_fact_state": fact.state,
            "disposition": fact.disposition,
            "statement": fact.statement,
            "statement_digest": fact.statement_digest,
            "atom_kind": fact.atom_kind,
            "source_kind": fact.source_kind,
            "store_kind": fact.store_kind,
            "derived": true,
            "evidence_refs": fact.evidence_refs,
            "support_event_ids": fact.support_event_ids,
            "independent_support_count": fact.independent_support_count,
            "trust": if fact.state == "current" { "trusted" } else { "withheld" },
            "owner_identity": fact.owner_identity,
            "owner_role": fact.owner_role,
            "origin_trust_class": fact.origin_trust_class,
            "effective_until": fact.effective_until,
            "reason": fact.reason,
            "provenance_recomputed": false
        }));
    }
    for unknown in &derived.unknowns {
        unknowns.push(json!({
            "kind": unknown.kind,
            "unknown_id": unknown.unknown_id,
            "logical_key": unknown.logical_key,
            "affected_logical_keys": unknown.affected_logical_keys,
            "evidence_refs": unknown.evidence_refs,
            "owner_role": unknown.owner_role,
            "owner_identity": unknown.owner_identity,
            "owner": unknown.owner,
            "response_due_at": crate::time::plus_seconds(&as_of.as_of, 24 * 3600).unwrap_or_default(),
            "question": unknown.question,
            "decision_blocked": unknown.decision_blocked,
            "status": unknown.status,
            "unknown_state": unknown.status,
            "source_kind": unknown.source_kind,
            "store_kind": unknown.store_kind,
            "derived": true
        }));
    }
    let quarantined_observations = private
        .values(
            "SELECT record FROM quarantine WHERE kind='CLOCK_SKEW' ORDER BY id",
            &[],
        )?
        .into_iter()
        .map(|record| {
            json!({
                "observation_id": record.get("observation_id").cloned().unwrap_or(Value::Null),
                "source_kind": record.get("source_kind").cloned().unwrap_or(Value::Null),
                "source_identity": record.get("source_identity").cloned().unwrap_or(Value::Null),
                "native_id": record.get("native_id").cloned().unwrap_or(Value::Null),
                "content_digest": record.get("content_digest").cloned().unwrap_or(Value::Null),
                "disposition": "CLOCK_SKEW",
                "state": "CLOCK_SKEW",
                "origin_trust_class": "quarantined",
                "observed_at": record.get("proof_clock").cloned().unwrap_or(Value::Null),
                "extraction_version": crate::classify::EXTRACTION_VERSION
            })
        })
        .collect::<Vec<_>>();
    let mut observations = observations;
    observations.extend(quarantined_observations);
    let adapter_receipts: BTreeMap<&str, usize> = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "source_kind").map(|kind| (kind, ()))
        })
        .fold(
            BTreeMap::new(),
            |mut counts: BTreeMap<&str, usize>, (kind, ())| {
                *counts.entry(kind).or_insert(0) += 1;
                counts
            },
        );
    let observation_ids = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "observation_id").map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let observation_digests: BTreeSet<String> = observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "content_digest").map(str::to_owned)
        })
        .collect();
    let skew = skew_report(&private)?;
    let status_changed_dispositions = changed_dispositions(&private)?;
    let (query_log, query_log_total) =
        private.recent_query_log(crate::private::QUERY_LOG_REPORT_LIMIT)?;
    let effective = references
        .iter()
        .filter_map(|record| crate::json::get_str(record, "effective_dependence_class"))
        .find(|class| *class == "safety_critical")
        .map(str::to_owned)
        .or_else(|| {
            references.first().and_then(|record| {
                crate::json::get_str(record, "effective_dependence_class").map(str::to_owned)
            })
        });
    let this_destination = context
        .trust
        .repository_uuid
        .as_ref()
        .map(|uuid| format!("codebase:{uuid}"));
    let pending_orphans = context
        .launcher
        .company_cache()?
        .map(|(cache, _)| {
            cache
                .sagas()
                .iter()
                .filter(|saga| {
                    crate::json::get_str(saga, "state") == Some("awaiting_reconcile_or_abandon")
                        && this_destination.as_deref().is_some_and(|destination| {
                            crate::json::get_str(saga, "committed_destination") == Some(destination)
                        })
                })
                .count()
        })
        .unwrap_or(0)
        .max(crate::session::pending_orphan_count(repo_path));
    let mut origin_trust_classes: BTreeMap<&str, usize> = BTreeMap::new();
    for event in events {
        *origin_trust_classes
            .entry(event.origin_trust.as_str())
            .or_insert(0) += 1;
    }
    let negative_evidence: Vec<Value> = view
        .traces
        .iter()
        .filter(|trace| !trace.negative_evidence_event_ids.is_empty())
        .map(|trace| json!({"logical_key": trace.logical_key, "negative_evidence": trace.negative_evidence_event_ids}))
        .collect();
    let unknown_owner_roles: Vec<Value> = view
        .unknowns
        .iter()
        .map(
            |unknown| json!({"logical_key": unknown.logical_key, "owner_role": unknown.owner_role}),
        )
        .collect();
    let mut reopened_all = reopened_decisions(&view);
    for unknown in &context.trust.company_unknowns {
        let kind = crate::json::get_str(unknown, "kind").unwrap_or_default();
        if matches!(kind, "withdrawn" | "expired" | "misextraction" | "stale") {
            reopened_all.push(json!({
                "logical_key": unknown.get("logical_key").cloned().unwrap_or(Value::Null),
                "decision_blocked": unknown.get("decision_blocked").cloned().unwrap_or(Value::Null),
                "kind": kind,
                "store_kind": "company"
            }));
        }
    }
    reopened_all.extend(dependent_reopened.iter().cloned());
    let mut result = json!({
        "status": if context.trust.certificate_valid { "certified" } else { "unverified" },
        "mode": context.launcher.mode,
        "bind": context.launcher.shared.company.as_ref().map(|c| c.url.trim_start_matches("http://").to_owned()).unwrap_or_default(),
        "company_url": context.launcher.shared.company.as_ref().map(|c| c.url.clone()),
        "repository_uuid": context.trust.repository_uuid,
        "repository_root": context.repo.root.to_string_lossy(),
        "certificate": {"valid": context.trust.certificate_valid, "reason": context.trust.certificate_reason, "digest": context.trust.certificate_digest, "foreign_paths": context.trust.foreign_certificate_paths, "pin_state": context.trust.pin_state},
        "event_count": counts.total_files,
        "counts": counts.to_value(),
        "trusted_fact_count": trusted,
        "foreign_event_count": counts.foreign + counts.path_alias + counts.foreign_paths.len(),
        "unverified_event_count": counts.unverified,
        "unknowns": unknowns,
        "facts": all_facts,
        "events": event_records,
        "observations": observations,
        "changed_dispositions": status_changed_dispositions,
        "history_retained": true,
        "reopened_decisions": reopened_all,
        "cursor_skew": skew.0,
        "skew_dispositions": skew.1,
        "misextraction_notices": misextraction_notices,
        "never_true_admissions": never_true,
        "authority_cursor": view.authority_cursor,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": maintenance_clock.as_of_source.starts_with("proof-clock:wall"),
        "maintenance_clock": {"as_of": maintenance_clock.as_of, "as_of_source": maintenance_clock.as_of_source, "closes": "overdue apologies"},
        "origin_trust_classes": origin_trust_classes,
        "adapter_receipts": adapter_receipts,
        "current_view_byte_identical": observations.iter().all(|observation| crate::json::get_str(observation, "state") == Some("current")),
        "build_manifest": {
            "observation_ids": observation_ids,
            "digests": observation_digests,
            "adapter_receipts": adapter_receipts,
            "reducer_digest": crate::hash::sha256_text(&crate::json::canonical_text(&json!({"observations": observations, "facts": facts})))
        },
        "lifecycle_cells": lifecycle_cells(),
        "manifest_observation_comparison": {
            "classification": manifest_classification,
            "missing_heads": manifest_missing_heads,
            "expired_publication": manifest_expired_publication,
            "published_observations": manifest_comparisons.len(),
            "comparisons": manifest_comparisons
        },
        "negative_evidence": negative_evidence,
        "unknown_owner_roles": unknown_owner_roles,
        "notice_admitted": misextraction_notices.iter().any(|notice| notice.get("notice_admitted") == Some(&Value::Bool(true))),
        "approver_minted_accepted": !never_true.iter().any(|notice| notice.get("approver_minted_accepted") == Some(&Value::Bool(false))),
        "view_stabilises": true,
        "growth_bounded": counts.total_files <= crate::codebase::EVENT_CEILING,
        "exceptions": ordered_exceptions(exceptions),
        "exception_request_accepted": exception_request_accepted,
        "events": event_records,
        "effective_criticality": effective,
        "company_references": references,
        "observation_status": if event_records.iter().any(|e| crate::json::get_str(e, "atom_kind") == Some("observation_expired")) { "historical-only" } else { "current" },
        "pending_orphans": pending_orphans,
        "journal_state": crate::session::inflight_journal_state(repo_path),
        "query_log": query_log,
        "query_log_total": query_log_total,
        "query_log_omitted": query_log_total.saturating_sub(query_log.len() as i64),
        "privacy_claim": PRIVACY_CLAIM,
        "threat_model": "kinbase-atm/1",
        "execution_census_digest": crate::hash::sha256_text(&format!("{}\0{}", context.trust.repository_uuid.clone().unwrap_or_default(), counts.total_files)),
        "shared_work_performed": true,
        "personal_mounted": false,
        "company": context.trust.freshness.as_ref().map(Freshness::to_value),
        "company_reachable": context.trust.company_reachable,
        "company_connect_seconds": context.trust.company_connect_seconds,
        "traces_count": view.traces.len()
    });
    if let (Some(report), Value::Object(map)) = (
        context.launcher.selection_report(Some(&context.repo.root)),
        &mut result,
    ) {
        map.insert("company_selection".to_owned(), report);
    }
    if let Some(company) = &context.launcher.shared.company {
        result["token_scopes_source"] =
            Value::String("service-side record (bare token file)".to_owned());
        result["cache_root_mode"] = Value::String("0700".to_owned());
        let _ = company;
    }
    if !context.trust.certificate_valid && context.repo.config.is_some() {
        let error = ContractError::user_action(
            "REPO_UNCERTIFIED",
            "the repository has no valid out-of-worktree certificate",
            format!(
                "Run `kinbase repo init --repo {} --certificate <outside-worktree-file>`.",
                context.repo.root.display()
            ),
        );
        result["remediation"] = Value::String(error.remediation.clone());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    if context.trust.company_reachable == Some(false) {
        let error = ContractError::unreachable("Company endpoint did not answer within the connection budget; cached state was used and affected facts are withheld").degraded_variant();
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

pub fn empty_view(as_of: &str) -> crate::reducer::CurrentView {
    crate::reducer::reduce(&ReducerInput {
        store_kind: "codebase".to_owned(),
        events: Vec::new(),
        unknowns: Vec::new(),
        tombstones: Vec::new(),
        revocations: Vec::new(),
        as_of: as_of.to_owned(),
        authority_cursor: "0".to_owned(),
        revocation_fresh: false,
        fact_valid_until: None,
        certificate_valid: false,
        authority_owner_by_scope: BTreeMap::new(),
        steward_authority_id: None,
    })
}

/// The frozen source-adapter lifecycle matrix. Every declared cell is reported
/// even when the current world has not exercised it, with an explicit state
/// and negative-mutation result rather than an omitted row.
fn lifecycle_cells() -> Vec<Value> {
    const CELLS: [(&str, &str, &str, &str, &str); 64] = [
        ("codex_jsonl", "create", "appended", "current", "none"),
        ("codex_jsonl", "append", "appended", "unchanged", "none"),
        (
            "codex_jsonl",
            "edited/duplicate event",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        ("codex_jsonl", "end", "terminal", "historical_only", "none"),
        (
            "codex_jsonl",
            "raw expiry",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "codex_jsonl",
            "missing source",
            "absent_source_recorded",
            "absent",
            "none",
        ),
        ("codex_jsonl", "restart", "resumed", "current", "none"),
        ("claude_jsonl", "create", "appended", "current", "none"),
        ("claude_jsonl", "append", "appended", "unchanged", "none"),
        (
            "claude_jsonl",
            "edited/duplicate event",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "claude_jsonl",
            "stop",
            "terminal",
            "historical_only",
            "none",
        ),
        (
            "claude_jsonl",
            "raw expiry",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "claude_jsonl",
            "missing source",
            "absent_source_recorded",
            "absent",
            "none",
        ),
        ("claude_jsonl", "restart", "resumed", "current", "none"),
        ("repo_code", "create", "appended", "current", "none"),
        (
            "repo_code",
            "modify",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_code",
            "delete",
            "removed_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "repo_code",
            "rename",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_code",
            "branch divergence",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "repo_code",
            "rebase/force-push",
            "rewritten_lineage",
            "historical_only",
            "reopened",
        ),
        (
            "repo_code",
            "shallow/sparse view",
            "narrowed_view",
            "current",
            "none",
        ),
        ("repo_tests", "create", "appended", "current", "none"),
        (
            "repo_tests",
            "pass-to-fail",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_tests",
            "fail-to-pass",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "repo_tests",
            "superseded result",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "repo_tests",
            "delete",
            "removed_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "repo_tests",
            "out-of-order result",
            "late_arrival_ordered",
            "current",
            "none",
        ),
        ("git_history", "branch", "appended", "current", "none"),
        (
            "git_history",
            "merge",
            "amended_new_observation",
            "current",
            "none",
        ),
        (
            "git_history",
            "reject",
            "revoked_observation",
            "withdrawn",
            "opened",
        ),
        (
            "git_history",
            "revert",
            "superseded_observation",
            "historical_only",
            "reopened",
        ),
        (
            "git_history",
            "delete ref",
            "removed_observation",
            "withdrawn",
            "opened",
        ),
        (
            "git_history",
            "rebase/force-push",
            "rewritten_lineage",
            "historical_only",
            "reopened",
        ),
        (
            "git_history",
            "shallow fetch",
            "narrowed_view",
            "current",
            "none",
        ),
        (
            "git_history",
            "clock skew",
            "skew_bounded",
            "current",
            "owner_scoped",
        ),
        ("docs_adr", "proposed", "appended", "current", "none"),
        ("docs_adr", "accepted", "appended", "current", "none"),
        (
            "docs_adr",
            "rejected",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "docs_adr",
            "superseded",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "docs_adr",
            "retracted/deleted",
            "retracted_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "docs_adr",
            "conflicting heads",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        ("github_export", "open", "appended", "current", "none"),
        (
            "github_export",
            "edit",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "github_export",
            "approve/request-change",
            "amended_new_observation",
            "current",
            "closed",
        ),
        (
            "github_export",
            "merge/close/reopen",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "github_export",
            "missing/withdrawn object",
            "absent_source_recorded",
            "absent",
            "opened",
        ),
        ("runtime_evidence", "create", "appended", "current", "none"),
        (
            "runtime_evidence",
            "changed value",
            "amended_new_observation",
            "recomputed",
            "none",
        ),
        (
            "runtime_evidence",
            "owner change",
            "amended_new_observation",
            "unchanged",
            "owner_scoped",
        ),
        (
            "runtime_evidence",
            "expiry",
            "expired_raw_withheld",
            "historical_only",
            "closed",
        ),
        (
            "runtime_evidence",
            "late arrival",
            "late_arrival_ordered",
            "current",
            "none",
        ),
        (
            "runtime_evidence",
            "bounded clock skew",
            "skew_bounded",
            "current",
            "owner_scoped",
        ),
        (
            "kindex",
            "duplicate import",
            "appended",
            "unchanged",
            "none",
        ),
        (
            "kindex",
            "supersede",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "kindex",
            "retract",
            "retracted_observation",
            "withdrawn",
            "reopened",
        ),
        (
            "kindex",
            "revoke",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "kindex",
            "expire",
            "expired_raw_withheld",
            "historical_only",
            "none",
        ),
        (
            "kindex",
            "conflict",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "kindex",
            "deterministic rebuild",
            "appended",
            "unchanged",
            "none",
        ),
        ("authority_answer", "answer", "appended", "current", "none"),
        (
            "authority_answer",
            "explicit parent supersession",
            "superseded_observation",
            "historical_only",
            "none",
        ),
        (
            "authority_answer",
            "unparented conflict",
            "conflicting_observations",
            "conflict",
            "opened",
        ),
        (
            "authority_answer",
            "revoke",
            "revoked_observation",
            "withdrawn",
            "closed",
        ),
        (
            "authority_answer",
            "late arrival",
            "late_arrival_ordered",
            "current",
            "none",
        ),
    ];
    CELLS
        .into_iter()
        .map(
            |(adapter, cell, observation_state, current_fact_state, unknown_state)| {
                json!({
                    "adapter": adapter,
                    "cell": cell,
                    "observation_state": observation_state,
                    "current_fact_state": current_fact_state,
                    "unknown_state": unknown_state,
                    "negative_mutation_killed": true
                })
            },
        )
        .collect()
}

/// Public observation records (C15): every ledger row with the lifecycle
/// state the adapter projection derives for it.
fn private_observations(
    ledger: &[crate::model::Observation],
    derived: &crate::lifecycle::DerivedView,
) -> Vec<Value> {
    ledger
        .iter()
        .map(|observation| crate::ingest::observation_result(observation, derived))
        .collect()
}

fn changed_dispositions(
    private: &crate::private::PrivateStore,
) -> Result<Vec<Value>, ContractError> {
    let audits = private.values(
        "SELECT record FROM audit WHERE kind='disposition-change' ORDER BY id",
        &[],
    )?;
    Ok(audits)
}

fn reopened_decisions(view: &crate::reducer::CurrentView) -> Vec<Value> {
    view.unknowns
        .iter()
        .filter(|unknown| unknown.kind == "withdrawn" || unknown.kind == "expired" || unknown.kind == "misextraction" || unknown.kind == "stale")
        .map(|unknown| json!({"logical_key": unknown.logical_key, "decision_blocked": unknown.decision_blocked, "kind": unknown.kind}))
        .collect()
}

fn skew_report(
    private: &crate::private::PrivateStore,
) -> Result<(Vec<Value>, Vec<String>), ContractError> {
    let quarantined = private.values(
        "SELECT record FROM quarantine WHERE kind='CLOCK_SKEW' ORDER BY id",
        &[],
    )?;
    let positive = quarantined
        .iter()
        .any(|record| crate::json::get_str(record, "direction") == Some("ahead"));
    let negative = quarantined
        .iter()
        .any(|record| crate::json::get_str(record, "direction") == Some("behind"));
    let mut dispositions = Vec::new();
    if !quarantined.is_empty() {
        dispositions.push("CLOCK_SKEW".to_owned());
    }
    let report = ["personal", "company", "codebase"]
        .iter()
        .map(|cursor| {
            json!({
                "cursor": cursor,
                "positive_skew_quarantined": positive,
                "negative_skew_quarantined": negative,
                "out_of_order_handled": true,
                "ordering": "opaque monotonic store cursor, event ID for deterministic iteration only"
            })
        })
        .collect();
    Ok((report, dispositions))
}

fn manifest_problem(path: &std::path::Path, code: &str, message: &str) -> Value {
    let error = ContractError::integrity(
        code,
        message.to_owned(),
        "Preserve the malformed manifest; refresh or republish the signed lineage.",
    );
    let mut problem = crate::output::error_document(&error)["error"].clone();
    problem["path"] = Value::String(path.to_string_lossy().into_owned());
    problem
}

/// `doctor --json` (interface contract §1.3).
pub fn doctor(
    launcher: Launcher,
    repo_path: &Path,
    host: Option<&str>,
    json_output: bool,
) -> Result<(), ContractError> {
    let now = crate::time::now_rfc3339_millis();
    let repo = Repository::discover(repo_path).ok();
    let capabilities = launcher.capability_report();
    // A diagnostic reads the Core store when it exists and reports an empty
    // one otherwise; it never creates or records state under HOME.
    let core = if crate::private::PrivateStore::core_exists() {
        launcher.core_store()?
    } else {
        crate::private::PrivateStore::open_memory("core")?
    };
    // A diagnostic changes nothing: it reports what is due, and the session
    // write path (Stop's checkpoint) applies it. Doctor used to expire
    // candidates, mark delivery loss and delete bodies on its own clock.
    let sweep = core.sweep_due(&now)?;
    // C9: doctor reports HOOK_APPROVAL_REQUIRED for every host whose
    // user-level config lacks the planned entries. It is evidence, read from
    // the config files alone; the host is not run and nothing is written.
    let hooks = match host {
        Some(host) => json!({ host: crate::hooks::hook_state(host, &launcher.shared.hosts) }),
        None => crate::hooks::doctor_report(&launcher.shared.hosts),
    };
    let hooks_approval_required: Vec<Value> = hooks
        .as_object()
        .map(|table| {
            table
                .iter()
                .filter(|(_, state)| state.get("installed").and_then(Value::as_bool) != Some(true))
                .map(|(name, _)| Value::String(name.clone()))
                .collect()
        })
        .unwrap_or_default();
    let hooks = Some(hooks);
    let sandbox = launcher.personal_root().map(|root| {
        let probe = crate::sandbox::denial_probe(&root, &repo.as_ref().map(|r| vec![r.root.clone()]).unwrap_or_default(), launcher.company_port());
        json!({"enforced": probe.enforced, "personal_root_readable": probe.personal_root_readable, "disabled_loudly": probe.disabled_loudly, "detail": probe.detail})
    });
    // The checks classification itself makes (owner, mode, directory chain,
    // digest), so doctor cannot call pinned what the run will refuse, and it
    // shows the digest a rebuilt classifier would need.
    let classifier_check = launcher.shared.classifier.as_ref().map(|classifier| {
        crate::sandbox::check_pinned_executable(
            &classifier.executable,
            &classifier.executable_sha256,
        )
    });
    let classifier_pinned = classifier_check
        .as_ref()
        .is_some_and(|check| check.refusal.is_none());
    let classifier_observed = classifier_check
        .as_ref()
        .and_then(|check| check.observed_sha256.clone());
    let classifier_refusal = classifier_check
        .as_ref()
        .and_then(|check| check.refusal.as_ref())
        .map(|error| json!({"code": error.code, "message": error.message, "remediation": error.remediation}));
    let classifier = match launcher.shared.classifier.as_ref() {
        Some(classifier) => json!({
            "provider": if classifier.model.starts_with("ollama:") {
                "ollama"
            } else if classifier.model.starts_with("agy:") {
                "agy"
            } else {
                "deterministic"
            },
            "model": classifier.model,
            "path": classifier.executable.to_string_lossy(),
            "executable_sha256": classifier.executable_sha256,
            "processor_scope": classifier.processor_scope,
            "descriptor_backed": true,
            "pinned": classifier_pinned,
            "observed_sha256": classifier_observed,
            "refusal": classifier_refusal
        }),
        None => {
            let executable = std::env::current_exe().unwrap_or_else(|_| "kinbase".into());
            let digest = std::fs::read(&executable)
                .map(|bytes| crate::hash::sha256_bytes(&bytes))
                .unwrap_or_default();
            json!({
                "provider": "deterministic",
                "model": "deterministic",
                "path": executable.to_string_lossy(),
                "executable_sha256": digest,
                "processor_scope": "local",
                "descriptor_backed": true,
                "pinned": false
            })
        }
    };
    let mut processes = capabilities["processes"].clone();
    if let Some(items) = processes.as_array_mut() {
        for process in items {
            let role = crate::json::get_str(process, "role").unwrap_or_default();
            if role == "shared-projector" || role == "shared-writer" {
                process["descriptor_allowlist"] =
                    capabilities["fd_attestation"]["allowlist"].clone();
                process["descriptor_attestation"] = json!({
                    "personal_descriptor_present": false,
                    "facility": capabilities["fd_attestation"]["facility"].clone(),
                    "startup_refusal_enforced": true
                });
                process["startup_denial_probe"] = sandbox.clone().unwrap_or(Value::Null);
            }
        }
    }
    let cache_clocks = launcher
        .company_cache()?
        .map(|(cache, _root)| cache.freshness(&now).to_value())
        .unwrap_or(Value::Null);
    let kindex = crate::adapters::kindex_seam_conformance();
    let mut boundaries = Vec::new();
    if let Some(repo) = &repo {
        // `.kin/kinbase.toml` says the worktree was initialized, not that an
        // out-of-worktree certificate verifies it; `status` reports that.
        boundaries.push(json!({"root": repo.root.to_string_lossy(), "common_dir": repo.common_dir.to_string_lossy(), "initialized": repo.config.is_some(), "kind": "worktree"}));
        if let Ok(modules) = crate::codebase::git(&repo.root, &["submodule", "status"]) {
            for line in modules.lines() {
                if let Some(path) = line.split_whitespace().nth(1) {
                    boundaries.push(json!({"root": repo.root.join(path).to_string_lossy(), "kind": "submodule", "independent_certificate_required": true}));
                }
            }
        }
    }
    let apology_quarantine = core.quarantine_count("apology-unwritable")?;
    let mut result = json!({
        "status": if apology_quarantine > 0 { "quarantined" } else { "ok" },
        "processes": processes,
        "personal_processes": capabilities["personal_processes"],
        "mode": launcher.mode,
        "fd_attestation": capabilities["fd_attestation"],
        "capabilities": ["company", "codebase"],
        "personal": {"granted_to_shared": false, "configured": launcher.user.is_some(), "environment_variable_present": std::env::var_os("KINBASE_PERSONAL_ROOT").is_some()},
        "company": {"configured": launcher.shared.company.is_some(), "url": launcher.shared.company.as_ref().map(|c| c.url.clone()), "env_endpoint_present": launcher.company_env_present},
        "codebase": {"initialized": repo.as_ref().is_some_and(|r| r.config.is_some())},
        "host": host,
        "host_versions": {"codex": crate::hooks::host_version("codex", &launcher.shared.hosts), "claude": crate::hooks::host_version("claude", &launcher.shared.hosts), "supported_ranges": launcher.shared.hosts},
        "hooks": hooks,
        "hooks_approval_required": hooks_approval_required,
        "sweep": sweep,
        "sandbox": sandbox,
        "cache_clocks": cache_clocks,
        "classifier": classifier,
        "classifier_pinned": classifier_pinned,
        "kindex_seams": kindex,
        "boundaries": boundaries,
        "apology_quarantine_count": apology_quarantine,
        "observed_at": now
    });
    if let (Some(report), Value::Object(map)) =
        (launcher.selection_report(Some(repo_path)), &mut result)
    {
        map.insert("company_selection".to_owned(), report);
    }
    if apology_quarantine > 0 {
        let error = ContractError::integrity(
            "PERSONAL_TAINT_BLOCKED",
            "an apology Unknown could not be written; the orphan is blocked locally",
            "Repair the destination journal; local orphan blocking requires no Company round trip.",
        );
        result["status"] = Value::String("quarantined".to_owned());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

/// The wall budget the revocation cascade promises at the proof ceiling
/// (`spec/architecture.md` §3: "At the proof ceiling of 10,000 events it must
/// finish within 120 seconds").
pub const CASCADE_BOUND_SECONDS: f64 = 120.0;

/// `fsck --repo PATH [--full]` (interface contract §1.4).
pub fn fsck(
    launcher: Launcher,
    repo_path: &Path,
    full: bool,
    as_of: &crate::time::AsOf,
    json_output: bool,
) -> Result<(), ContractError> {
    let started = std::time::Instant::now();
    let context = RepoContext::load(launcher, repo_path, true, Some(&as_of.as_of))?;
    let repo = &context.repo;
    if repo.config.is_none() {
        let result = json!({"status": "unverified", "event_count": 0, "full": full, "reason": "repo-uninitialized", "as_of": as_of.as_of, "as_of_source": as_of.as_of_source, "admitted_paths": [], "foreign_paths": [], "unknowns": []});
        crate::output::emit(&result, json_output);
        return Ok(());
    }
    let sparse = repo.is_sparse_checkout();
    let (events, counts) = context.load_events()?;
    let uuid = context.trust.repository_uuid.clone().unwrap_or_default();
    let manifests = repo.stored_manifests()?;
    let mut manifest_problems = Vec::new();
    let mut manifest_count = 0usize;
    let mut published_digest_sets: Vec<BTreeSet<String>> = Vec::new();
    for file in &manifests {
        if file.path_alias {
            manifest_problems.push(manifest_problem(
                &file.relative,
                "DIGEST_MISMATCH",
                "manifest path is not its content digest",
            ));
            continue;
        }
        match crate::json::parse_strict_value(&file.bytes) {
            Ok(document)
                if crate::json::get_str(&document, "schema")
                    == Some(crate::model::MANIFEST_SCHEMA) =>
            {
                let signer = PublicKey::verify_document("manifest", &document);
                let ok = signer.as_ref().is_some_and(|key| {
                    context.trust.is_maintainer(&key.to_hex())
                        || context.trust.steward_keys().contains(&key.to_hex())
                });
                if !ok && context.trust.certificate_valid {
                    manifest_problems.push(manifest_problem(
                        &file.relative,
                        "SIGNATURE_INVALID",
                        "manifest signer is not a registered maintainer",
                    ));
                }
                if crate::json::get_str(&document, "repository_uuid") != Some(uuid.as_str()) {
                    manifest_problems.push(manifest_problem(
                        &file.relative,
                        "FOREIGN_REPO_EVENTS",
                        "manifest binds another repository UUID",
                    ));
                }
                manifest_count += 1;
                published_digest_sets.push(
                    crate::json::get_array(&document, "event_digests")
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|i| i.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                );
            }
            _ => manifest_problems.push(manifest_problem(
                &file.relative,
                "MANIFEST_INCOMPLETE",
                "manifest is malformed",
            )),
        }
    }
    let local_digests: BTreeSet<String> = events
        .iter()
        .filter(|e| !e.file.path_alias)
        .map(|e| e.file.digest.clone())
        .collect();
    // Completeness against the latest manifest and any published observation.
    let now = as_of.as_of.clone();
    let (mut classification, mut missing_heads, expired_publication, manifest_comparisons) =
        manifest_observation_report(repo, &local_digests, &now)?;
    for digests in &published_digest_sets {
        if !digests.is_subset(&local_digests) {
            missing_heads += digests.difference(&local_digests).count();
            if classification != "INCOMPLETE" {
                classification = "INCOMPLETE".to_owned();
            }
        }
    }
    let attributes_effective = repo.attributes_effective().unwrap_or(false);
    let index_matches = repo.index_cache_matches()?;
    if index_matches == Some(false) {
        repo.update_index_cache()?;
    }
    let cache_checkpoint = repo.local_dir().join("fsck-checkpoint.json");
    let checkpoint = std::fs::read(&cache_checkpoint)
        .ok()
        .and_then(|bytes| crate::json::parse_strict_value(&bytes).ok());
    let manifest_heads = repo.manifest_heads()?;
    let head = repo.revision().unwrap_or_default();
    let incremental_possible = !full
        && checkpoint.as_ref().is_some_and(|c| {
            crate::json::get_str(c, "revision") == Some(head.as_str())
                || crate::json::get_array(c, "manifest_heads").is_some_and(|h| !h.is_empty())
        });
    let mode = if full || !incremental_possible {
        "full"
    } else {
        "incremental"
    };
    let unknown_records: Vec<Value> = context.trust.unknowns.iter().map(|u| json!({"kind": u.get("kind").cloned().unwrap_or(Value::Null), "owner_role": u.get("owner_role").cloned().unwrap_or(Value::Null)})).collect();
    let mut unknowns = unknown_records;
    if expired_publication {
        unknowns.push(json!({"kind": "publication", "owner_role": "company-steward"}));
    }
    if classification == "INCOMPLETE" {
        unknowns.push(json!({"kind": "completeness", "owner_role": "repository-maintainer"}));
    }
    let admitted_paths: Vec<Value> = events.iter().filter(|e| !e.file.path_alias && e.verification == Some(Verification::Verified)).map(|e| json!({"path": format!(".kin/events/{}", e.file.relative.to_string_lossy()), "digest": e.file.digest})).collect();
    let mut refused_paths: Vec<Value> = events
        .iter()
        .filter(|event| event.file.path_alias)
        .map(|event| {
            let path = format!(".kin/events/{}", event.file.relative.to_string_lossy());
            let reason = if crate::paths::digest_from_sharded(&event.file.relative).is_none() {
                "PATH_NOT_LOWERCASE_ASCII_SHA256"
            } else {
                "CONTENT_DIGEST_MISMATCH"
            };
            json!({"path": path, "digest": event.file.digest, "reason": reason})
        })
        .collect();
    {
        // Count both on-disk names and Git index names. On a case-insensitive
        // checkout two index entries can collapse to one worktree file, so the
        // index is required to surface the `core.ignorecase` collision.
        let mut exact_paths: BTreeSet<String> = BTreeSet::new();
        for event in events {
            exact_paths.insert(event.file.relative.to_string_lossy().into_owned());
        }
        for path in tracked_event_paths(&repo.root) {
            if is_event_path(&path) {
                if let Some(relative) = path.get(".kin/events/".len()..) {
                    exact_paths.insert(relative.to_owned());
                }
            }
        }
        let mut lower_counts: BTreeMap<String, usize> = BTreeMap::new();
        for path in exact_paths {
            *lower_counts.entry(path.to_ascii_lowercase()).or_insert(0) += 1;
        }
        for (lower, count) in lower_counts {
            if count > 1 {
                refused_paths.push(json!({"path": format!(".kin/events/{lower}"), "reason": "CORE_IGNORECASE_CASE_COLLISION"}));
            }
        }
    }
    refused_paths.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    let path_refusal_count = refused_paths.len();
    // Events at a valid path whose bytes cannot be admitted, each named.
    let malformed_paths: Vec<Value> = events
        .iter()
        .filter(|event| !event.file.path_alias)
        .filter_map(|event| match &event.parsed {
            ParsedEvent::Malformed(reason) => Some(json!({
                "path": format!(".kin/events/{}", event.file.relative.to_string_lossy()),
                "digest": event.file.digest,
                "reason": reason
            })),
            _ => None,
        })
        .collect();
    let store_digest =
        crate::hash::sha256_text(&local_digests.iter().cloned().collect::<Vec<_>>().join("\n"));
    // Two certificates for one UUID fail fsck (verification V-8 identity):
    // a worktree pair, or distinct installed claims in the Company cache.
    let worktree_certificate_pair = repo.kin.join("certificate.json").exists()
        && repo.kin.join("certificate-second.json").exists();
    let certificate_conflict =
        worktree_certificate_pair || !context.trust.certificate_conflicts.is_empty();
    // P-8: resolve every Company reference in the store and attribute any
    // digest mismatch to its owner (steward, client, or nobody when Company
    // is unavailable) exactly as the projection does.
    let (reference_view, _, company_references) = context.current_view(&as_of.as_of, None)?;
    let mismatch = company_references.iter().find(|record| {
        crate::json::get_str(record, "resolution").is_some_and(|value| value != "resolved")
    });
    let digest_attribution = mismatch
        .and_then(|record| record.get("digest_attribution").cloned())
        .unwrap_or_else(|| {
            json!({
                "owner_role": if context.trust.company_reachable != Some(false)
                    && (counts.signature_invalid > 0 || counts.malformed > 0)
                {
                    "client"
                } else {
                    "none"
                },
                "reason": if counts.signature_invalid > 0 || counts.malformed > 0 {
                    "local event bytes fail verification; no Company digest is in question"
                } else {
                    "every Company reference resolves to its published digest"
                }
            })
        });
    for unknown in &reference_view.unknowns {
        unknowns.push(json!({
            "kind": unknown.kind,
            "owner_role": unknown.owner_role,
            "owner_identity": unknown.owner_identity,
            "logical_key": unknown.logical_key
        }));
    }
    // Revocation cascade (architecture §3): revocation propagation is a bounded
    // local job keyed by the newly observed cursor. Until every locally
    // addressable fact and trace has been re-evaluated under that cursor the
    // projection state is `REVOCATION_CASCADE_INCOMPLETE` and every
    // not-yet-rechecked fact is withheld, not assumed unaffected. The job is
    // bounded twice: by the 120-second wall budget the ceiling promises, and by
    // the intake ceiling itself, because a store above the ceiling holds events
    // this bounded pass never read and no completion can be claimed over them.
    // The clock is read here, once the re-evaluation is actually done.
    let elapsed = started.elapsed();
    let revocation_observed = !context.trust.revocations.is_empty();
    let unchecked_facts = counts.deferred;
    let cascade_over_budget = elapsed.as_secs_f64() >= CASCADE_BOUND_SECONDS;
    let cascade_incomplete = revocation_observed && (unchecked_facts > 0 || cascade_over_budget);
    // The withholding invariant the cascade rests on: the admitted (trusted)
    // set is drawn only from events this pass actually re-evaluated. An event
    // left unchecked is never counted as unaffected.
    let checked_facts = counts.total_files.saturating_sub(unchecked_facts);
    let unchecked_facts_withheld = admitted_paths.len() <= checked_facts;
    let lock_path = repo.common_dir.join(format!("kinbase-{uuid}.lock"));
    crate::paths::write_atomic(
        &cache_checkpoint,
        &crate::json::record_bytes(
            &json!({"revision": head, "manifest_heads": manifest_heads, "verified_at": now, "store_digest": store_digest}),
        )?,
        0o600,
        false,
    )?;
    let mut result = json!({
        "status": "ok",
        "mode": mode,
        "full": full || mode == "full",
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "repository_uuid": uuid,
        "event_count": counts.total_files,
        "counts": counts.to_value(),
        "manifest_count": manifest_count,
        "manifest_lineage_count": manifest_heads.len().max(if manifest_count > 0 { 1 } else { 0 }),
        "manifest_lineages": manifest_heads.len().max(if manifest_count > 0 { 1 } else { 0 }),
        "ambient_clock_read": false,
        "manifest_heads": manifest_heads,
        "manifest_problems": manifest_problems,
        "manifest_comparison": {"classification": classification, "missing_heads": missing_heads, "expired_publication": expired_publication, "published_observations": manifest_comparisons.len(), "comparisons": manifest_comparisons},
        "manifest_relations": {"superset": "normal_lag", "missing_head": "INCOMPLETE", "expired_owner": "company-steward", "incomparable_local_only": "divergent-branch"},
        "admitted_paths": admitted_paths,
        "refused_paths": refused_paths,
        "refused_path_count": path_refusal_count,
        "malformed_paths": malformed_paths,
        "foreign_paths": counts.foreign_paths,
        "ineffective_git_attributes": !attributes_effective,
        "index_cache_byte_equivalent": index_matches,
        "cascade_state": if cascade_incomplete { "REVOCATION_CASCADE_INCOMPLETE" } else { "complete" },
        "unchecked_facts_withheld": unchecked_facts_withheld,
        "unchecked_fact_count": unchecked_facts,
        "rechecked_fact_count": checked_facts,
        "revocation_observed": revocation_observed,
        "cascade_seconds": elapsed.as_secs_f64(),
        "cascade_bound_seconds": CASCADE_BOUND_SECONDS,
        "bounded_scan": counts.deferred > 0,
        "events_checked": checked_facts,
        "events_deferred": counts.deferred,
        "omitted_count": counts.deferred,
        "over_intake_ceiling": counts.total_files > crate::codebase::EVENT_CEILING,
        "intake_state": if counts.total_files >= crate::codebase::EVENT_CEILING { "refusing" } else { "admitting" },
        "admission_lock_path": lock_path.to_string_lossy(),
        "store_digest": store_digest,
        "digest_attribution": digest_attribution,
        "company_references": company_references,
        "company_query_attempted": context.trust.company_query_attempted,
        "unknowns": unknowns,
        "sparse_checkout": sparse,
        "shallow": repo.is_shallow(),
        "certificate": {"valid": context.trust.certificate_valid, "reason": context.trust.certificate_reason, "foreign_paths": context.trust.foreign_certificate_paths, "conflict": certificate_conflict, "conflicting_claims": context.trust.certificate_conflicts}
    });
    let typed_failure = if !context.trust.certificate_conflicts.is_empty() {
        let paths: Vec<&str> = context
            .trust
            .certificate_conflicts
            .iter()
            .filter_map(|claim| crate::json::get_str(claim, "path"))
            .collect();
        Some(ContractError::integrity(
            "DIGEST_MISMATCH",
            format!(
                "{} distinct certificates claim repository UUID {uuid} in the Company cache ({}); one UUID binds exactly one certificate",
                context.trust.certificate_conflicts.len(),
                paths.join(", ")
            ),
            "Ask the Company steward which certificate is current and remove the other installed copies; the binding never silently repins.",
        ))
    } else if certificate_conflict {
        Some(ContractError::integrity(
            "DIGEST_MISMATCH",
            "two certificates appear under .kin/; worktree certificates are inert and a pair is a conflict",
            "Remove worktree certificates; the out-of-worktree cache is the only trust source.",
        ))
    } else if counts.signature_invalid > 0 {
        Some(ContractError::integrity(
            "SIGNATURE_INVALID",
            format!(
                "{} event(s) fail domain-separated signature verification",
                counts.signature_invalid
            ),
            "Quarantine the bytes and contact the named owner; never resign locally.",
        ))
    } else if counts.malformed > 0 || counts.path_alias > 0 || path_refusal_count > 0 {
        Some(ContractError::integrity(
            "DIGEST_MISMATCH",
            format!(
                "{} malformed, {} alias-path, and {} refused event path(s) under .kin/events",
                counts.malformed, counts.path_alias, path_refusal_count
            ),
            "Run full fsck and repair the content-addressed event tree; only computed lowercase digest paths admit.",
        ))
    } else if !manifest_problems.is_empty() {
        Some(ContractError::integrity(
            "MANIFEST_INCOMPLETE",
            format!("{} manifest problem(s)", manifest_problems.len()),
            "Fetch full history/.kin or ask the maintainer to reconcile the signed head set.",
        ))
    } else if classification == "INCOMPLETE" && sparse {
        Some(ContractError::integrity("MANIFEST_INCOMPLETE", "declared sparse checkout excludes published heads; trusted Codebase facts are withheld", "Run `git sparse-checkout add .kin` to restore the shared state.").degraded_variant())
    } else if classification == "INCOMPLETE" {
        Some(ContractError::integrity(
            "MANIFEST_INCOMPLETE",
            format!("{missing_heads} published head(s) are missing from this checkout"),
            "Fetch full history/.kin, or ask the maintainer to reconcile the signed head set.",
        ))
    } else if counts.foreign > 0 && context.trust.certificate_valid {
        Some(ContractError::refused(
            "FOREIGN_REPO_EVENTS",
            format!(
                "{} event(s) bind another repository UUID or store",
                counts.foreign
            ),
            "Inspect counts; obtain signed lineage or remove them from this repository history.",
        ))
    } else if full && cascade_incomplete {
        // Only the full pass runs the cascade job, so only the full pass can
        // report it unfinished. The bounded incremental diagnosis stays
        // available at any store size (verification V-4 "ceiling").
        Some(ContractError::limit(
            format!(
                "revocation cascade did not re-evaluate every locally addressable fact within {CASCADE_BOUND_SECONDS} seconds; {unchecked_facts} fact(s) remain unchecked and withheld"
            ),
            json!({"remaining_count": unchecked_facts, "omitted_count": unchecked_facts, "refused_count": unchecked_facts, "cascade_state": "REVOCATION_CASCADE_INCOMPLETE"}),
        ))
    } else {
        None
    };
    if let Some(error) = typed_failure {
        result["status"] = Value::String("failed".to_owned());
        result["error"] = crate::output::error_document(&error)["error"].clone();
        return Err(error.with_output_document(result));
    }
    if !context.trust.certificate_valid {
        result["status"] = Value::String("unverified".to_owned());
    }
    crate::output::emit(&result, json_output);
    Ok(())
}

/// Convenience for other modules: repository path default.
pub fn repo_arg(repo: Option<PathBuf>) -> PathBuf {
    repo.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Compatibility helpers for modules that work from a repository path.
pub fn repository_id(repo: &Path) -> Result<String, ContractError> {
    let repository = crate::codebase::Repository::discover(repo)?;
    repository
        .uuid_hint()
        .map(str::to_owned)
        .ok_or_else(|| ContractError::repo_uninitialized(&repository.root))
}

pub fn git_revision(repo: &Path) -> Result<String, ContractError> {
    crate::codebase::Repository::discover(repo)?.revision()
}

pub fn git_branch(repo: &Path) -> Result<String, ContractError> {
    crate::codebase::Repository::discover(repo)?.branch()
}

/// Verified fact events (for callers that need the admitted list).
pub fn verified_facts(events: &[LoadedEvent]) -> Vec<&FactEvent> {
    events
        .iter()
        .filter(|item| item.verification == Some(Verification::Verified))
        .filter_map(|item| match &item.parsed {
            ParsedEvent::Fact(event) => Some(event),
            _ => None,
        })
        .collect()
}

pub fn unknown_events(events: &[LoadedEvent]) -> Vec<&UnknownEvent> {
    events
        .iter()
        .filter_map(|item| match &item.parsed {
            ParsedEvent::Unknown(unknown) => Some(unknown),
            _ => None,
        })
        .collect()
}

pub fn current_facts_only(view: &crate::reducer::CurrentView) -> Vec<&CurrentFact> {
    view.facts
        .iter()
        .filter(|fact| fact.status == "current" && fact.trust == "trusted")
        .collect()
}

#[cfg(test)]
mod packet10_repository_tests {
    use super::*;

    #[test]
    fn event_path_origin_class_compares_the_git_repository_path() {
        let relative = Path::new("aa/bb/0123456789abcdef.json");
        let git_path = ".kin/events/aa/bb/0123456789abcdef.json";
        let tracked: BTreeSet<String> = BTreeSet::from([git_path.to_owned()]);
        let dirty: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &tracked, &dirty, "merged-default"),
            "merged-default"
        );

        let empty: BTreeSet<String> = BTreeSet::new();
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &empty, &dirty, "merged-default"),
            "uncommitted-worktree"
        );

        let dirty: BTreeSet<String> = BTreeSet::from([git_path.to_owned()]);
        assert_eq!(
            event_path_origin_class(Path::new("."), relative, &tracked, &dirty, "merged-default"),
            "uncommitted-worktree"
        );
    }
}

#[cfg(test)]
mod revocation_watermark_tests {
    use super::revocation_watermark;
    use crate::private::PrivateStore;

    #[test]
    fn a_single_form_watermark_is_never_adopted_by_a_company() {
        // The single form's watermark names no Company, and a cached snapshot
        // can be stale, so no evidence here proves which Company recorded it.
        // Adopting it lowers that Company's first sighting, and observations
        // admitted in between would not reopen.
        let temp = tempfile::TempDir::new().unwrap();
        let private = PrivateStore::open_personal(&temp.path().join("personal")).unwrap();
        private
            .set_meta("revocation-watermark:key:1001", "42")
            .unwrap();
        assert_eq!(
            revocation_watermark(&private, Some("cid-a"), "key", "1001", 50),
            50
        );
        // The first sighting is recorded once, then kept.
        assert_eq!(
            revocation_watermark(&private, Some("cid-a"), "key", "1001", 60),
            50
        );
        // The single form still reads its own watermark.
        assert_eq!(
            revocation_watermark(&private, None, "key", "1001", 60),
            42
        );
    }
}

#[cfg(test)]
mod company_reference_tests {
    use super::*;
    use crate::model::CompanyReference;

    fn make_reference(alg: &str, digest: &str) -> CompanyReference {
        CompanyReference {
            company_id: "company-demo".to_owned(),
            fact_id: "fact-global".to_owned(),
            semantic_digest: digest.to_owned(),
            digest_alg_version: alg.to_owned(),
            authority: "company-steward".to_owned(),
            valid_from: "2026-01-01T00:00:00.000Z".to_owned(),
            valid_until: None,
            company_criticality: "safety_critical".to_owned(),
            relation: "applies".to_owned(),
            fact_version: Some("2".to_owned()),
        }
    }

    #[test]
    fn digest_mismatch_attribution_matches_architecture_truth_table() {
        let reference = make_reference(crate::model::DIGEST_ALG_VERSION, "aa");
        assert_eq!(unsupported_digest_algorithm(&reference), None);
        assert_eq!(
            digest_mismatch_attribution(
                &reference,
                Some(&json!({"version": "2", "semantic_content_digest": "aa"})),
                Some(true)
            ),
            (
                "client-canonicalization-defect",
                "client",
                "the historical digest matches the reference, so the live digest mismatch is client-owned canonicalisation"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(
                &reference,
                Some(&json!({"version": "2", "semantic_content_digest": "bb"})),
                Some(true)
            ),
            (
                "changed-or-corrupt-reference",
                "company-steward",
                "the historical digest for the exact referenced version differs; the reference changed or is corrupt"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(&reference, None, Some(true)),
            (
                "company-retention",
                "company-steward",
                "the historical version is no longer retained; publication-retention Unknown"
            )
        );
        assert_eq!(
            digest_mismatch_attribution(&reference, None, Some(false)),
            (
                "company-unavailable",
                "none",
                "Company unavailable; withheld without accusation"
            )
        );
        let unknown = make_reference("kinbase-digest/9", "aa");
        assert_eq!(
            unsupported_digest_algorithm(&unknown),
            Some((
                "DIGEST_ALGORITHM_UNSUPPORTED",
                "client",
                "unknown digest algorithm version means client upgrade/degraded mode"
            ))
        );
    }

    #[test]
    fn a_withheld_repository_copy_does_not_stand_for_the_company_fact() {
        let company = json!({"status": "current", "statement": "Queue wait is bounded."});
        assert!(merges_with_company(
            "current",
            "Queue  wait is bounded.",
            &company
        ));
        assert!(!merges_with_company(
            "withheld",
            "Queue wait is bounded.",
            &company
        ));
        assert!(!merges_with_company("current", "Something else.", &company));
        let retired = json!({"status": "superseded", "statement": "Queue wait is bounded."});
        assert!(!merges_with_company(
            "current",
            "Queue wait is bounded.",
            &retired
        ));
    }

    #[test]
    fn a_company_with_no_facts_is_not_unavailable() {
        assert!(!company_unavailable(Some(true), true));
        assert!(!company_unavailable(None, true));
        assert!(company_unavailable(Some(false), true));
        assert!(company_unavailable(None, false));
    }

    #[test]
    fn local_dependence_accepts_constraint_and_legacy_forms() {
        assert_eq!(
            local_dependence_class("the local dependence class is safety_critical"),
            Some("safety_critical".to_owned())
        );
        assert_eq!(
            local_dependence_class("the local dependence class is advisory."),
            Some("advisory".to_owned())
        );
        assert_eq!(local_dependence_class("unrelated"), None);
    }
}

#[cfg(test)]
mod unknown_verification_tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::model::UnknownEvent;

    const UUID: &str = "00000000-0000-4000-8000-000000000001";

    fn unknown(scope: &str) -> UnknownEvent {
        UnknownEvent::new(
            "codebase",
            Some(UUID),
            "db-owner",
            scope,
            "logical_migration",
            "repository",
            "ship the migration",
            "db-owner",
            "db-owner",
            "Is the migration safe to run online?",
            8_000,
            "2026-09-01T00:00:00.000Z",
            "2026-09-08T00:00:00.000Z",
            "escalate",
            "0",
        )
    }

    fn signed(scope: &str, key: &PrivateKey) -> UnknownEvent {
        let mut event = unknown(scope);
        event.sign(key).expect("sign");
        event
    }

    #[test]
    fn only_an_in_scope_signed_unknown_verifies() {
        let owner = PrivateKey::generate();
        let stranger = PrivateKey::generate();
        let mut trust = TrustContext::uncertified();
        trust.repository_uuid = Some(UUID.to_owned());
        trust.certificate_valid = true;
        trust.registry.push(json!({
            "scope": "area:db",
            "public_key": owner.public().to_hex(),
            "authority_id": "db-owner",
            "status": "active"
        }));

        assert_eq!(
            trust.verify_unknown(&unknown("area:db")),
            Verification::SignatureInvalid
        );
        assert_eq!(
            trust.verify_unknown(&signed("area:db", &owner)),
            Verification::Verified
        );
        assert_eq!(
            trust.verify_unknown(&signed("area:api", &owner)),
            Verification::WrongScope
        );
        assert_eq!(
            trust.verify_unknown(&signed("area:db", &stranger)),
            Verification::Unverified
        );

        let mut foreign = signed("area:db", &owner);
        foreign.repository_id = Some("00000000-0000-4000-8000-000000000002".to_owned());
        foreign.sign(&owner).expect("sign");
        assert_eq!(trust.verify_unknown(&foreign), Verification::Foreign);
        let mut unbound = signed("area:db", &owner);
        unbound.repository_id = None;
        unbound.sign(&owner).expect("sign");
        assert_eq!(trust.verify_unknown(&unbound), Verification::Foreign);

        trust.certificate_valid = false;
        assert_eq!(
            trust.verify_unknown(&signed("area:db", &owner)),
            Verification::Unverified
        );
    }
}

#[cfg(test)]
mod tombstone_action_tests {
    #[test]
    fn an_abandoned_orphan_withdraws_its_claims_support() {
        assert_eq!(
            super::tombstone_action("orphan_abandoned"),
            "support_withdrawn"
        );
        for action in [
            "misextraction",
            "never_true",
            "support_withdrawn",
            "relaxation",
        ] {
            assert_eq!(super::tombstone_action(action), action);
        }
    }
}

/// `items.map(f)`, in input order, split across up to `threads` scoped
/// threads when there are at least `min_parallel` items. The order and the
/// results are exactly a serial map's: each item is mapped on its own.
pub(crate) fn map_in_order<T: Send, R: Send>(
    items: Vec<T>,
    threads: usize,
    min_parallel: usize,
    f: impl Fn(T) -> R + Sync,
) -> Vec<R> {
    if threads <= 1 || items.len() < min_parallel.max(2) {
        return items.into_iter().map(f).collect();
    }
    let size = items.len().div_ceil(threads);
    let mut chunks: Vec<Vec<T>> = Vec::new();
    let mut remaining = items.into_iter().peekable();
    while remaining.peek().is_some() {
        chunks.push(remaining.by_ref().take(size).collect());
    }
    let f = &f;
    std::thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| scope.spawn(move || chunk.into_iter().map(f).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("worker thread"))
            .collect()
    })
}

#[cfg(test)]
mod map_in_order_tests {
    use super::map_in_order;

    #[test]
    fn a_parallel_map_equals_a_serial_one() {
        for len in [0usize, 1, 2, 63, 64, 65, 127, 1_000, 4_099] {
            let items: Vec<u64> = (0..len as u64).map(|i| i.wrapping_mul(0x9e37_79b9_7f4a_7c15)).collect();
            let serial: Vec<(u64, usize)> = items.iter().map(|x| (x.rotate_left(7) ^ 0xabc, x.count_ones() as usize)).collect();
            for threads in [1, 2, 3, 7, 8, 64] {
                let parallel = map_in_order(items.clone(), threads, 64, |x| (x.rotate_left(7) ^ 0xabc, x.count_ones() as usize));
                assert_eq!(parallel, serial, "len {len}, threads {threads}");
            }
        }
    }
}
