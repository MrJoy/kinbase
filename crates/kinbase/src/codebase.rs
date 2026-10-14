//! The Codebase store (architecture §6 "Codebase", §2 admission, §11
//! repository compatibility): one signed event per content-addressed path
//! under `.kin/events/`, parent-linked manifests under `.kin/manifests/`, a
//! recoverable journal plus an exclusive OS file lock in Git's common
//! directory, and a deterministic `fsck`.

use crate::error::ContractError;
use crate::model::{FactEvent, UnknownEvent};
use crate::paths;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const REPO_CONFIG_SCHEMA: &str = "kinbase-repo/1";
pub const EVENT_CEILING: usize = 10_000;
pub const BYTES_CEILING: u64 = 128 * 1024 * 1024;
pub const GIT_ATTRIBUTES: [&str; 2] = [
    ".kin/events/** -text -diff -merge",
    ".kin/manifests/** -text -diff -merge",
];
/// Paths Kinbase reserves under `.kin/`; a pinned-Kindex inventory that
/// collides with one refuses `repo init` (architecture §11).
/// Paths inside `.kin/` that belong to Kinbase.
///
/// `config` is deliberately absent: that file is Kindex's, in YAML, and reserving it
/// is what made Kinbase refuse to initialise in 87 repositories of one deployment. The two
/// products share this directory by design, so each claims only its own names.
pub const RESERVED_PATHS: [&str; 4] = [
    CONFIG_FILE,
    "events",
    "manifests",
    "local/kinbase-index.json",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoConfig {
    pub schema_version: String,
    pub repository_uuid_hint: String,
    pub safe_name: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub local_policy: BTreeMap<String, String>,
}

impl RepoConfig {
    pub fn parse(text: &str) -> Result<Self, ContractError> {
        let table: toml::Table = text.parse().map_err(|error: toml::de::Error| {
            ContractError::integrity(
                "DIGEST_MISMATCH",
                format!(
                    ".kin/config is not valid TOML ({})",
                    crate::config::toml_error_text(text, &error)
                ),
                "Quarantine the malformed config; no trust-on-first-use fallback exists.",
            )
        })?;
        for key in table.keys() {
            if ![
                "schema_version",
                "repository_uuid_hint",
                "safe_name",
                "domains",
                "local_policy",
            ]
            .contains(&key.as_str())
            {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!(
                        ".kin/config contains unknown key `{key}`; it cannot name roots, keys, authorities, or endpoints"
                    ),
                    "Remove the key; unknown keys fail closed.",
                ));
            }
        }
        let schema = table
            .get("schema_version")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        if schema != REPO_CONFIG_SCHEMA {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                format!(".kin/config schema_version {schema:?} is incompatible"),
                "Preserve the bytes; an incompatible schema blocks and is never overwritten.",
            ));
        }
        let hint = table
            .get("repository_uuid_hint")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        if uuid::Uuid::parse_str(hint).is_err() {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                ".kin/config repository_uuid_hint is not a UUID",
                "Reinstall the steward-issued certificate with `kinbase repo init`.",
            ));
        }
        let safe_name = table
            .get("safe_name")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        if safe_name.is_empty()
            || !safe_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                ".kin/config safe_name must be a non-empty ASCII identifier",
                "Correct the safe name.",
            ));
        }
        let Some(domain_values) = table.get("domains").and_then(toml::Value::as_array) else {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                ".kin/config domains is required and must be an array of strings",
                "Correct the repository config; missing keys fail closed.",
            ));
        };
        let mut domains = Vec::new();
        for item in domain_values {
            let Some(domain) = item.as_str() else {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    ".kin/config domains contains a non-string entry",
                    "Every domain must be an exact string; malformed config bytes are preserved.",
                ));
            };
            domains.push(domain.to_owned());
        }
        let local_policy_values = table.get("local_policy");
        if local_policy_values.is_some_and(|value| !value.is_table()) {
            return Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                ".kin/config local_policy must be a table with string values",
                "Correct the repository config; malformed config bytes are preserved.",
            ));
        }
        let mut local_policy: BTreeMap<String, String> = BTreeMap::new();
        if let Some(items) = local_policy_values.and_then(toml::Value::as_table) {
            for (key, value) in items {
                let Some(value) = value.as_str() else {
                    return Err(ContractError::integrity(
                        "DIGEST_MISMATCH",
                        format!(".kin/config local_policy.{key} is not a string"),
                        "Every local policy value must be an exact string.",
                    ));
                };
                local_policy.insert(key.clone(), value.to_owned());
            }
        }
        for value in local_policy
            .values()
            .chain(std::iter::once(&safe_name.to_owned()))
        {
            if value.starts_with('/') || value.contains("http://") || value.contains("https://") {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    ".kin/config values cannot name absolute paths or endpoints",
                    "Remove the offending hint; worktree bytes cannot introduce trust roots.",
                ));
            }
        }
        Ok(Self {
            schema_version: schema.to_owned(),
            repository_uuid_hint: hint.to_owned(),
            safe_name: safe_name.to_owned(),
            domains,
            local_policy,
        })
    }

    pub fn to_toml(&self) -> String {
        let mut text = format!(
            "schema_version = {:?}\nrepository_uuid_hint = {:?}\nsafe_name = {:?}\ndomains = [",
            self.schema_version, self.repository_uuid_hint, self.safe_name
        );
        text.push_str(
            &self
                .domains
                .iter()
                .map(|domain| format!("{domain:?}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        text.push_str("]\n");
        if !self.local_policy.is_empty() {
            text.push_str("[local_policy]\n");
            for (key, value) in &self.local_policy {
                text.push_str(&format!("{key} = {value:?}\n"));
            }
        }
        text
    }
}

/// A repository resolved through Git's common directory.
#[derive(Debug, Clone)]
pub struct Repository {
    pub root: PathBuf,
    pub kin: PathBuf,
    pub common_dir: PathBuf,
    pub config: Option<RepoConfig>,
}

/// The product only reads Git state. `GIT_OPTIONAL_LOCKS=0` keeps every read
/// (notably `status --porcelain`) from opportunistically refreshing the index
/// under `.git/index.lock`, so a background verifier never races the user's
/// own Git operations.
/// A worktree's top level and common Git directory, as `git rev-parse`
/// reports them from `start`. Asked once per path per process: a session
/// observation discovers the repository for every admission, and each answer
/// cost two Git processes. Where a worktree lives does not change while one
/// command runs; `.kin/config` and `HEAD` are still read fresh every time.
///
/// The cache is keyed by the resolved path, so a symlink retargeted to another
/// repository is looked up afresh, and the common directory is stored resolved
/// and absolute, never relative to a path that may since point elsewhere. An
/// answer is reused only while it still holds (see `still_holds`).
fn worktree_location(start: &Path) -> Result<(String, String), ContractError> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static KNOWN: OnceLock<Mutex<HashMap<PathBuf, (String, String)>>> = OnceLock::new();
    let known = KNOWN.get_or_init(|| Mutex::new(HashMap::new()));
    let key = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    if let Some(found) = known.lock().ok().and_then(|map| map.get(&key).cloned()) {
        if still_holds(&key, Path::new(&found.0)) {
            return Ok(found);
        }
    }
    let root = git(&key, &["rev-parse", "--show-toplevel"])?;
    let common = git(&key, &["rev-parse", "--git-common-dir"])?;
    let common = if Path::new(&common).is_absolute() {
        PathBuf::from(&common)
    } else {
        key.join(&common)
    };
    let common = common.canonicalize().unwrap_or(common);
    let found = (root, common.to_string_lossy().into_owned());
    if let Ok(mut map) = known.lock() {
        map.insert(key, found.clone());
    }
    Ok(found)
}

/// A remembered worktree root still holds for `start` while the root keeps its
/// `.git` and no directory from `start` up to it has gained one (a nested
/// `git init`, or a new worktree): a few `stat` calls instead of two Git
/// processes.
fn still_holds(start: &Path, root: &Path) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    if std::fs::symlink_metadata(root.join(".git")).is_err() {
        return false;
    }
    for dir in start.ancestors() {
        if dir == root {
            return true;
        }
        if std::fs::symlink_metadata(dir.join(".git")).is_ok() {
            return false;
        }
    }
    false
}

pub fn git(repo: &Path, args: &[&str]) -> Result<String, ContractError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|error| ContractError::io("run git", error))?;
    if !output.status.success() {
        return Err(ContractError::user_action(
            "REPO_UNCERTIFIED",
            format!(
                "git {} failed: {}",
                args.first().unwrap_or(&""),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
            "Run the command inside a Git worktree; an ordinary non-repository Personal session may continue.",
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn git_ok(repo: &Path, args: &[&str]) -> bool {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// Kinbase's own config file inside `.kin/`.
///
/// Kindex already owns `.kin/config`, in YAML, and 87 of the 159 repositories at
/// one deployment carry one. Both products are part of the same family and are meant to
/// share the directory, so kinbase takes a distinct filename rather than fighting
/// over a shared one -- reading a sibling product's YAML as a malformed kinbase
/// config produced a quarantine error that told nobody what was actually wrong.
///
/// A repository initialised before this change still has its TOML at `.kin/config`,
/// so that path is honoured when the new one is absent and the bytes parse.
pub const CONFIG_FILE: &str = "kinbase.toml";

/// The config path to read, preferring ours and falling back to the legacy name
/// only when it is genuinely a kinbase config.
fn config_path_for(kin: &std::path::Path) -> Option<std::path::PathBuf> {
    let ours = kin.join(CONFIG_FILE);
    if ours.exists() {
        return Some(ours);
    }
    let legacy = kin.join("config");
    if legacy.exists()
        && std::fs::read_to_string(&legacy)
            .ok()
            .is_some_and(|text| RepoConfig::parse(&text).is_ok())
    {
        return Some(legacy);
    }
    None
}

impl Repository {
    /// Resolve the worktree root and Git common directory; linked worktrees
    /// share the common directory (and therefore the certified UUID).
    pub fn discover(path: &Path) -> Result<Self, ContractError> {
        let start = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| ContractError::io("current dir", error))?
                .join(path)
        };
        if !start.exists() {
            return Err(ContractError::user_action(
                "REPO_UNCERTIFIED",
                "the repository path does not exist",
                "Pass an existing Git worktree with --repo.",
            ));
        }
        let (root, common) = worktree_location(&start)?;
        let root = PathBuf::from(root);
        // Git reports a relative common directory relative to where it ran
        // (`../.git` from a subdirectory), not to the top level.
        let common_dir = if Path::new(&common).is_absolute() {
            PathBuf::from(common)
        } else {
            start.join(common)
        };
        let common_dir = common_dir.canonicalize().unwrap_or(common_dir);
        let kin = root.join(".kin");
        paths::reject_symlink(&kin, ".kin")?;
        let config = if let Some(path) = config_path_for(&kin) {
            paths::reject_symlink(&path, ".kin/config")?;
            let text = std::fs::read_to_string(&path).map_err(|error| {
                ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!(".kin/config bytes are unreadable ({})", error.kind()),
                    "Quarantine the malformed config; contents are never printed and no fallback exists.",
                )
            })?;
            Some(RepoConfig::parse(&text)?)
        } else {
            None
        };
        Ok(Self {
            root,
            kin,
            common_dir,
            config,
        })
    }

    pub fn uuid_hint(&self) -> Option<&str> {
        self.config
            .as_ref()
            .map(|config| config.repository_uuid_hint.as_str())
    }

    /// Take the shared (reader) admission lock for a report over `path`
    /// without spawning Git: the worktree root and Git's common directory are
    /// resolved from `.git` the way Git itself records them (a `.git` file
    /// names the worktree's gitdir, whose `commondir` file names the common
    /// directory). Returns `None` when the path is not an initialized
    /// Kinbase repository, so uninitialized worktrees are never locked.
    pub fn shared_generation_lock(path: &Path) -> Result<Option<AdmissionLock>, ContractError> {
        let start = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| ContractError::io("current dir", error))?
                .join(path)
        };
        let mut root = start.clone();
        loop {
            if root.join(".git").exists() {
                break;
            }
            let Some(parent) = root.parent() else {
                return Ok(None);
            };
            root = parent.to_path_buf();
        }
        let Some(config_path) = config_path_for(&root.join(".kin")) else {
            return Ok(None);
        };
        let Ok(text) = std::fs::read_to_string(&config_path) else {
            return Ok(None);
        };
        let Ok(config) = RepoConfig::parse(&text) else {
            return Ok(None);
        };
        let dot_git = root.join(".git");
        let gitdir = if dot_git.is_dir() {
            dot_git
        } else {
            let pointer = std::fs::read_to_string(&dot_git).unwrap_or_default();
            let Some(target) = pointer.trim().strip_prefix("gitdir:") else {
                return Ok(None);
            };
            let target = target.trim();
            if Path::new(target).is_absolute() {
                PathBuf::from(target)
            } else {
                root.join(target)
            }
        };
        let common_dir = match std::fs::read_to_string(gitdir.join("commondir")) {
            Ok(pointer) => {
                let pointer = pointer.trim();
                if Path::new(pointer).is_absolute() {
                    PathBuf::from(pointer)
                } else {
                    gitdir.join(pointer)
                }
            }
            Err(_) => gitdir,
        };
        let common_dir = common_dir.canonicalize().unwrap_or(common_dir);
        let repository = Self {
            root: root.clone(),
            kin: root.join(".kin"),
            common_dir,
            config: Some(config),
        };
        let uuid = repository
            .uuid_hint()
            .map(str::to_owned)
            .unwrap_or_default();
        repository.admission_lock_shared(&uuid).map(Some)
    }

    pub fn require_initialized(&self) -> Result<&RepoConfig, ContractError> {
        self.config
            .as_ref()
            .ok_or_else(|| ContractError::repo_uninitialized(&self.root))
    }

    pub fn revision(&self) -> Result<String, ContractError> {
        git(&self.root, &["rev-parse", "HEAD"])
    }

    pub fn branch(&self) -> Result<String, ContractError> {
        git(&self.root, &["rev-parse", "--abbrev-ref", "HEAD"])
    }

    pub fn default_branch(&self) -> String {
        git(
            &self.root,
            &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        )
        .map(|value| value.trim_start_matches("origin/").to_owned())
        .or_else(|_| git(&self.root, &["config", "--get", "init.defaultBranch"]))
        .ok()
        .filter(|value| {
            !value.is_empty()
                && git_ok(
                    &self.root,
                    &[
                        "rev-parse",
                        "--verify",
                        "--quiet",
                        &format!("refs/heads/{value}"),
                    ],
                )
        })
        .or_else(|| {
            ["main", "master"]
                .into_iter()
                .find(|name| {
                    git_ok(
                        &self.root,
                        &[
                            "rev-parse",
                            "--verify",
                            "--quiet",
                            &format!("refs/heads/{name}"),
                        ],
                    )
                })
                .map(str::to_owned)
        })
        .unwrap_or_else(|| self.branch().unwrap_or_else(|_| "HEAD".to_owned()))
    }

    pub fn default_branch_revision(&self) -> Result<String, ContractError> {
        let branch = self.default_branch();
        git(&self.root, &["rev-parse", &branch]).or_else(|_| self.revision())
    }

    pub fn is_reachable_from_default(&self, revision: &str) -> bool {
        let default = self.default_branch();
        git_ok(
            &self.root,
            &["merge-base", "--is-ancestor", revision, &default],
        )
    }

    /// Origin trust class for a path (architecture §4): canonicalize and
    /// contain first, then classify from the committed path history. Dirtiness
    /// can only demote the exact dirty path, never promote another origin.
    pub fn origin_trust(&self, path: &Path) -> String {
        let Ok(root) = self.root.canonicalize() else {
            return "uncommitted-worktree".to_owned();
        };
        let Ok(canonical) = path.canonicalize() else {
            return "uncommitted-worktree".to_owned();
        };
        let Ok(relative) = canonical.strip_prefix(&root) else {
            return "uncommitted-worktree".to_owned();
        };
        let relative = relative.to_string_lossy();
        if !git_ok(
            &self.root,
            &["ls-files", "--error-unmatch", "--", &relative],
        ) {
            return "uncommitted-worktree".to_owned();
        }
        let dirty = git(&self.root, &["status", "--porcelain", "--", &relative])
            .map(|output| !output.is_empty())
            .unwrap_or(true);
        if dirty {
            return "uncommitted-worktree".to_owned();
        }
        let last_path_commit =
            git(&self.root, &["log", "-1", "--format=%H", "--", &relative]).unwrap_or_default();
        if last_path_commit.trim().is_empty() {
            return "uncommitted-worktree".to_owned();
        }
        if git_ok(
            &self.root,
            &[
                "merge-base",
                "--is-ancestor",
                last_path_commit.trim(),
                &self.default_branch(),
            ],
        ) {
            return "merged-default".to_owned();
        }
        let merged_pr_refs = git(
            &self.root,
            &[
                "for-each-ref",
                "--format=%(refname)",
                "refs/pull/*/merge",
                "refs/remotes/pull/*/merge",
            ],
        )
        .unwrap_or_default();
        if merged_pr_refs
            .lines()
            .map(str::trim)
            .filter(|reference| !reference.is_empty())
            .any(|reference| {
                git_ok(
                    &self.root,
                    &[
                        "merge-base",
                        "--is-ancestor",
                        last_path_commit.trim(),
                        reference,
                    ],
                )
            })
        {
            return "merged-pull".to_owned();
        }
        "unreviewed-branch".to_owned()
    }

    pub fn is_sparse_checkout(&self) -> bool {
        let sparse = git(&self.root, &["config", "--get", "core.sparseCheckout"])
            .map(|value| value == "true")
            .unwrap_or(false);
        sparse && !self.kin.join("events").exists()
    }

    pub fn is_shallow(&self) -> bool {
        self.common_dir.join("shallow").exists()
    }

    /// Effective Git attributes for the event and manifest trees.
    pub fn attributes_effective(&self) -> Result<bool, ContractError> {
        for probe in [
            ".kin/events/aa/bb/probe.json",
            ".kin/manifests/aa/bb/probe.json",
        ] {
            let output = git(
                &self.root,
                &["check-attr", "text", "diff", "merge", "--", probe],
            )?;
            let unset = output
                .lines()
                .filter(|line| line.ends_with(": unset"))
                .count();
            if unset != 3 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn ensure_git_attributes(&self) -> Result<Vec<String>, ContractError> {
        let path = self.root.join(".gitattributes");
        paths::reject_symlink(&path, ".gitattributes")?;
        let mut text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut added = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            for rule in GIT_ATTRIBUTES {
                let pattern = rule.split_whitespace().next().unwrap_or_default();
                if trimmed.starts_with(pattern) && trimmed != rule {
                    return Err(ContractError::refused(
                        "CONFIG_INVARIANT",
                        format!(
                            ".gitattributes already carries a contradictory rule for {pattern}"
                        ),
                        "Reconcile the existing .gitattributes rule manually; repo init never replaces the file.",
                    ));
                }
            }
        }
        for rule in GIT_ATTRIBUTES {
            if !text.lines().any(|line| line.trim() == rule) {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(rule);
                text.push('\n');
                added.push(rule.to_owned());
            }
        }
        if !added.is_empty() {
            paths::write_atomic(&path, text.as_bytes(), 0o644, false)?;
        }
        Ok(added)
    }

    /// Ignore `.kin/local/` through the common directory's info/exclude so no
    /// tracked file is added beyond config/events/manifests/.gitattributes.
    pub fn ensure_local_excluded(&self) -> Result<(), ContractError> {
        let info = self.common_dir.join("info");
        paths::ensure_dir(&info, "git info directory")?;
        let exclude = info.join("exclude");
        let mut text = std::fs::read_to_string(&exclude).unwrap_or_default();
        if !text.lines().any(|line| line.trim() == ".kin/local/") {
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(".kin/local/\n");
            paths::write_atomic(&exclude, text.as_bytes(), 0o644, false)?;
        }
        Ok(())
    }

    pub fn local_dir(&self) -> PathBuf {
        self.kin.join("local")
    }

    pub fn ensure_local(&self) -> Result<PathBuf, ContractError> {
        let local = self.local_dir();
        paths::ensure_private_dir(&local, ".kin/local")?;
        Ok(local)
    }

    // ----- events -----

    /// One bounded pass over `.kin/events/`: at most `EVENT_CEILING` events
    /// are read and digested. Above the ceiling the surplus is counted and
    /// deferred, never silently treated as checked.
    pub fn stored_events(&self) -> Result<Vec<StoredFile>, ContractError> {
        Ok(self.scan_events(EVENT_CEILING)?.files)
    }

    /// The same pass with the deferral counts the caller needs to report a
    /// bounded diagnosis (architecture §6 bounded storage behaviour).
    pub fn scan_events(&self, limit: usize) -> Result<EventScan, ContractError> {
        stored_files_bounded(&self.kin.join("events"), limit)
    }

    /// How many event files the store holds, counted without reading bytes.
    /// `capped` marks the answer as a lower bound once `cap` is passed.
    pub fn count_events_capped(&self, cap: usize) -> Result<(usize, bool), ContractError> {
        paths::count_files_capped(&self.kin.join("events"), cap)
    }

    pub fn stored_manifests(&self) -> Result<Vec<StoredFile>, ContractError> {
        stored_files(&self.kin.join("manifests"))
    }

    pub fn total_event_bytes(&self) -> u64 {
        paths::total_file_bytes(&self.kin.join("events")).unwrap_or(0)
    }

    /// Intake ceiling check (architecture §11, verification limits).
    ///
    /// The count is taken first and stops as soon as the ceiling is passed, so
    /// a store already over the ceiling refuses before any event byte is read
    /// or any tree is materialized. Byte totals come from directory metadata.
    pub fn check_intake_ceiling(
        &self,
        incoming: usize,
        incoming_bytes: u64,
    ) -> Result<(), ContractError> {
        let headroom = EVENT_CEILING.saturating_sub(incoming);
        let (count, capped) = self.count_events_capped(headroom)?;
        let bytes = if capped {
            0
        } else {
            paths::total_file_bytes(&self.kin.join("events"))?
        };
        let over_count = capped || count + incoming > EVENT_CEILING;
        if over_count || bytes + incoming_bytes > BYTES_CEILING {
            // What the ceiling stop omits: the events beyond the ceiling when
            // the count binds (a lower bound once the walk short-circuited),
            // otherwise the whole refused batch.
            let omitted = if over_count {
                (count + incoming).saturating_sub(EVENT_CEILING).max(1)
            } else {
                incoming.max(1)
            };
            return Err(ContractError::limit(
                "the .kin/ intake ceiling of 10,000 events / 128 MiB would be crossed",
                json!({
                    "event_count": count,
                    "event_count_is_lower_bound": capped,
                    "event_bytes": bytes,
                    "incoming_count": incoming,
                    "incoming_bytes": incoming_bytes,
                    "refused_count": omitted,
                    "omitted_count": omitted,
                    "ceiling_events": EVENT_CEILING,
                    "ceiling_bytes": BYTES_CEILING
                }),
            ));
        }
        Ok(())
    }

    /// Exclusive repository-scoped admission lock in Git's common directory,
    /// keyed by certified repository UUID.
    pub fn admission_lock(&self, repository_uuid: &str) -> Result<AdmissionLock, ContractError> {
        self.acquire_admission_lock(repository_uuid, libc::LOCK_EX)
    }

    /// Shared (reader) form of the same lock: a consistent read of one
    /// destination generation (journal, events, index, receipts) never
    /// overlaps a writer's transition, and readers never block each other.
    pub fn admission_lock_shared(
        &self,
        repository_uuid: &str,
    ) -> Result<AdmissionLock, ContractError> {
        self.acquire_admission_lock(repository_uuid, libc::LOCK_SH)
    }

    fn acquire_admission_lock(
        &self,
        repository_uuid: &str,
        operation: libc::c_int,
    ) -> Result<AdmissionLock, ContractError> {
        let path = self
            .common_dir
            .join(format!("kinbase-{repository_uuid}.lock"));
        let turnstile_path = self
            .common_dir
            .join(format!("kinbase-{repository_uuid}.turnstile.lock"));
        let open = |path: &Path| {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(path)
                .map_err(|error| ContractError::io("open admission lock", error))
        };
        let file = open(&path)?;
        let turnstile = open(&turnstile_path)?;
        let configured = self
            .config
            .as_ref()
            .and_then(|config| config.local_policy.get("admission_lock_timeout_seconds"))
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| {
                std::env::var("KINBASE_ADMISSION_LOCK_TIMEOUT_SECONDS")
                    .ok()
                    .and_then(|value| value.parse().ok())
            });
        let timeout_seconds = configured.unwrap_or(30).min(300);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
        let timed_out = |what: &str| {
            let error = std::io::Error::last_os_error();
            ContractError::limit(
                format!("{what} was not acquired within {timeout_seconds}s ({error})"),
                json!({
                    "timeout_seconds": timeout_seconds,
                    "retryable": true,
                    "refused_count": 1,
                    "omitted_count": 1,
                    "remediation": "Retry after the holder commits or releases the lock; increase the bounded timeout if the holder is known healthy."
                }),
            )
        };
        // The turnstile is held only while waiting for the lock itself. A
        // waiter therefore blocks every later arrival, including a writer
        // coming back for its next journal generation, so a reader that
        // arrives mid-transaction reads the next consistent generation
        // instead of being starved by a long saga.
        loop {
            // SAFETY: flock on descriptors we own. The nonblocking form plus
            // a bounded deadline prevents an abandoned common-dir lock from
            // making every linked worktree wait forever.
            let result =
                unsafe { libc::flock(turnstile.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err(timed_out("admission lock turnstile"));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), operation | libc::LOCK_NB) };
            if result == 0 {
                // SAFETY: releasing the turnstile descriptor we hold.
                unsafe {
                    libc::flock(turnstile.as_raw_fd(), libc::LOCK_UN);
                }
                return Ok(AdmissionLock { _file: file, path });
            }
            if std::time::Instant::now() >= deadline {
                unsafe {
                    libc::flock(turnstile.as_raw_fd(), libc::LOCK_UN);
                }
                return Err(timed_out("admission lock"));
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// Admit one already-verified canonical event buffer through the
    /// journaled state machine. Returns the receipt (existing receipt when
    /// the exact event was already admitted).
    pub fn admit_event(
        &self,
        repository_uuid: &str,
        canonical: &[u8],
        kind: &str,
        receipt_extra: Value,
    ) -> Result<Value, ContractError> {
        if canonical.len() > crate::model::MAX_EVENT_BYTES {
            return Err(ContractError::limit(
                "shared event exceeds the 64 KiB ceiling",
                json!({"bytes": canonical.len(), "ceiling_bytes": crate::model::MAX_EVENT_BYTES, "refused_count": 1, "omitted_count": 1}),
            ));
        }
        let digest = crate::hash::sha256_bytes(canonical);
        let relative = paths::sharded_relative(&digest)?;
        let local = self.ensure_local()?;
        let journal_dir = local.join("journal");
        paths::ensure_private_dir(&journal_dir, "journal")?;
        let receipts_dir = local.join("receipts");
        paths::ensure_private_dir(&receipts_dir, "receipts")?;
        let _lock = self.admission_lock(repository_uuid)?;
        self.recover_journal(repository_uuid)?;
        let receipt_path = receipts_dir
            .join(repository_uuid)
            .join(format!("{digest}.json"));
        if receipt_path.exists() {
            let bytes = std::fs::read(&receipt_path)
                .map_err(|error| ContractError::io("read receipt", error))?;
            if let Ok(mut existing) = crate::json::parse_strict_value(&bytes) {
                let expected_destination = format!("codebase:{repository_uuid}");
                let stored_destination =
                    crate::json::get_str(&existing, "destination").unwrap_or_default();
                let stored_repository =
                    crate::json::get_str(&existing, "repository_uuid").unwrap_or_default();
                if stored_destination != expected_destination
                    || stored_repository != repository_uuid
                {
                    return Err(ContractError::integrity(
                        "DIGEST_MISMATCH",
                        format!(
                            "receipt lookup for digest {digest} is bound to {stored_destination}/{stored_repository}, not {expected_destination}/{repository_uuid}"
                        ),
                        "Do not reuse a receipt across repositories or destinations; run fsck if the local receipt store moved.",
                    ));
                }
                let event_value = crate::json::parse_strict_value(canonical).ok();
                let signer = event_value
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "signer"))
                    .map(str::to_owned);
                let logical_key = event_value
                    .as_ref()
                    .and_then(|value| crate::json::get_str(value, "logical_key"))
                    .map(str::to_owned);
                let revoked_signers: Vec<&str> = receipt_extra
                    .get("revoked_signers")
                    .and_then(Value::as_array)
                    .map(|items| items.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let revocation_key = receipt_extra
                    .get("revocation")
                    .and_then(|value| value.get("revoked_key"))
                    .and_then(Value::as_str);
                let revocation_observed = receipt_extra.get("revocation_observed")
                    == Some(&Value::Bool(true))
                    || signer
                        .as_deref()
                        .is_some_and(|signer| revoked_signers.contains(&signer))
                    || signer
                        .as_deref()
                        .zip(revocation_key)
                        .is_some_and(|(signer, key)| signer == key);
                let sole_support = logical_key.as_deref().is_some_and(|logical_key| {
                    self.stored_events()
                        .map(|events| {
                            events
                                .iter()
                                .filter(|file| {
                                    matches!(
                                        crate::codebase::parse_stored(&file.bytes),
                                        ParsedEvent::Fact(event) if event.logical_key == logical_key
                                    )
                                })
                                .count()
                                <= 1
                        })
                        .unwrap_or(true)
                });
                let support_withdrawn = revocation_observed && sole_support;
                existing["historical_receipt"] = Value::Bool(true);
                existing["readmitted"] = Value::Bool(false);
                existing["revocation_observed"] = Value::Bool(revocation_observed);
                existing["support_withdrawn"] = Value::Bool(support_withdrawn);
                existing["projection_state"] = Value::String(if support_withdrawn {
                    "support_withdrawn".to_owned()
                } else {
                    "current".to_owned()
                });
                return Ok(existing);
            }
        }
        self.check_intake_ceiling(1, canonical.len() as u64)?;
        let generation = next_generation(&journal_dir)?;
        let journal_path = journal_dir.join(format!("{generation:012}.json"));
        let final_path = paths::contained(&self.kin.join("events"), &relative)?;
        let staging = local.join("staging");
        paths::ensure_private_dir(&staging, "staging")?;
        let staged = staging.join(format!("{digest}.json"));
        let mut entry = json!({
            "schema": "kinbase-journal/1",
            "generation": generation,
            "repository_uuid": repository_uuid,
            "digest": digest,
            "kind": kind,
            "relative_path": relative.to_string_lossy(),
            "state": "staged",
            "updated_at": crate::time::now_rfc3339_millis()
        });
        paths::write_atomic(&staged, canonical, 0o600, false)?;
        paths::write_atomic(
            &journal_path,
            &crate::json::record_bytes(&entry)?,
            0o600,
            false,
        )?;
        // renamed
        let created = paths::write_atomic(&final_path, canonical, 0o644, true)?;
        std::fs::remove_file(&staged)
            .map_err(|error| ContractError::io("remove staged event after rename", error))?;
        entry["state"] = Value::String("renamed".to_owned());
        entry["created"] = Value::Bool(created);
        paths::write_atomic(
            &journal_path,
            &crate::json::record_bytes(&entry)?,
            0o600,
            false,
        )?;
        // indexed
        self.update_index_cache()?;
        entry["state"] = Value::String("indexed".to_owned());
        paths::write_atomic(
            &journal_path,
            &crate::json::record_bytes(&entry)?,
            0o600,
            false,
        )?;
        // receipted
        let mut receipt = json!({
            "schema": crate::model::RECEIPT_SCHEMA,
            "destination": format!("codebase:{repository_uuid}"),
            "repository_uuid": repository_uuid,
            "status": "committed",
            "event_digest": digest,
            "event_path": format!(".kin/events/{}", relative.to_string_lossy()),
            "kind": kind,
            "created": created,
            "historical_receipt": false,
            "readmitted": true,
            "revocation_observed": false,
            "support_withdrawn": false,
            "projection_state": "current",
            "committed_at": crate::time::now_rfc3339_millis(),
            "journal_generation": generation
        });
        if let Value::Object(extra) = receipt_extra {
            for (key, value) in extra {
                receipt[key] = value;
            }
        }
        paths::write_atomic(
            &receipt_path,
            &crate::json::record_bytes(&receipt)?,
            0o600,
            false,
        )?;
        entry["state"] = Value::String("receipted".to_owned());
        paths::write_atomic(
            &journal_path,
            &crate::json::record_bytes(&entry)?,
            0o600,
            false,
        )?;
        entry["state"] = Value::String("done".to_owned());
        paths::write_atomic(
            &journal_path,
            &crate::json::record_bytes(&entry)?,
            0o600,
            false,
        )?;
        Ok(receipt)
    }

    /// Replay every incomplete journal entry (crash recovery). A `prepared`
    /// entry whose staged bytes are gone is rolled back; every later state is
    /// completed forward.
    pub fn recover_journal(&self, repository_uuid: &str) -> Result<Vec<Value>, ContractError> {
        let local = self.local_dir();
        let journal_dir = local.join("journal");
        if !journal_dir.exists() {
            return Ok(Vec::new());
        }
        let mut replayed = Vec::new();
        for relative in paths::list_files(&journal_dir)? {
            let path = journal_dir.join(&relative);
            let bytes =
                std::fs::read(&path).map_err(|error| ContractError::io("read journal", error))?;
            let Ok(mut entry) = crate::json::parse_strict_value(&bytes) else {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!(
                        "journal entry {} is not canonical JSON",
                        relative.to_string_lossy()
                    ),
                    "Preserve the journal bytes and repair the destination explicitly; recovery never ignores a malformed marker.",
                ));
            };
            let state = crate::json::get_str(&entry, "state")
                .unwrap_or_default()
                .to_owned();
            if state == "done" {
                continue;
            }
            if crate::json::get_str(&entry, "repository_uuid").unwrap_or_default()
                != repository_uuid
            {
                return Err(ContractError::refused(
                    "FOREIGN_REPO_EVENTS",
                    format!(
                        "journal entry {} belongs to another repository",
                        relative.to_string_lossy()
                    ),
                    "Preserve the foreign journal and repair this repository explicitly; recovery never adopts another identity.",
                ));
            }
            if !["staged", "prepared", "renamed", "indexed", "receipted"].contains(&state.as_str())
            {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!(
                        "journal entry {} has unknown state {state:?}",
                        relative.to_string_lossy()
                    ),
                    "Preserve the journal bytes; the closed recovery state machine refuses an unknown transition.",
                ));
            }
            let digest = crate::json::get_str(&entry, "digest")
                .unwrap_or_default()
                .to_owned();
            let rel =
                PathBuf::from(crate::json::get_str(&entry, "relative_path").unwrap_or_default());
            let final_path = paths::contained(&self.kin.join("events"), &rel)?;
            let staged = local.join("staging").join(format!("{digest}.json"));
            let receipt_path = local
                .join("receipts")
                .join(repository_uuid)
                .join(format!("{digest}.json"));
            let mut action = "completed";
            if state == "staged" || state == "prepared" {
                if staged.exists() {
                    let staged_bytes = std::fs::read(&staged)
                        .map_err(|error| ContractError::io("read staged", error))?;
                    if crate::hash::sha256_bytes(&staged_bytes) == digest {
                        paths::write_atomic(&final_path, &staged_bytes, 0o644, true)?;
                    } else {
                        action = "rolled-back";
                    }
                    std::fs::remove_file(&staged)
                        .map_err(|error| ContractError::io("remove stale staged event", error))?;
                } else if !final_path.exists() {
                    action = "rolled-back";
                }
            } else if !final_path.exists() {
                return Err(ContractError::integrity(
                    "DIGEST_MISMATCH",
                    format!(
                        "journal entry {} claims {state} but the content-addressed event is absent",
                        relative.to_string_lossy()
                    ),
                    "Preserve the journal and event tree; recovery never invents admitted bytes.",
                ));
            }
            if action == "completed" {
                self.update_index_cache()?;
                if !receipt_path.exists() {
                    let receipt = json!({
                        "schema": crate::model::RECEIPT_SCHEMA,
                        "destination": format!("codebase:{repository_uuid}"),
                        "repository_uuid": repository_uuid,
                        "status": "committed",
                        "event_digest": digest,
                        "event_path": format!(".kin/events/{}", rel.to_string_lossy()),
                        "kind": crate::json::get_str(&entry, "kind").unwrap_or("fact-event"),
                        "recovered": true,
                        "committed_at": crate::time::now_rfc3339_millis(),
                        "journal_generation": entry.get("generation").cloned().unwrap_or(Value::Null)
                    });
                    paths::write_atomic(
                        &receipt_path,
                        &crate::json::record_bytes(&receipt)?,
                        0o600,
                        false,
                    )?;
                }
            }
            entry["state"] = Value::String("done".to_owned());
            entry["recovery"] = Value::String(action.to_owned());
            paths::write_atomic(&path, &crate::json::record_bytes(&entry)?, 0o600, false)?;
            replayed.push(json!({"generation": entry.get("generation").cloned().unwrap_or(Value::Null), "digest": digest, "from_state": state, "action": action}));
        }
        Ok(replayed)
    }

    /// The reducer-owned compatibility cache `.kin/local/kinbase-index.json`
    /// (a sorted list of event digests and byte counts).
    pub fn update_index_cache(&self) -> Result<(), ContractError> {
        let files = self.stored_events()?;
        let index = index_value(&files);
        let path = self.local_dir().join("kinbase-index.json");
        paths::write_atomic(&path, &crate::json::record_bytes(&index)?, 0o600, false)?;
        Ok(())
    }

    pub fn index_cache_matches(&self) -> Result<Option<bool>, ContractError> {
        let path = self.local_dir().join("kinbase-index.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes =
            std::fs::read(&path).map_err(|error| ContractError::io("read index cache", error))?;
        let files = self.stored_events()?;
        Ok(Some(
            bytes == crate::json::canonical_bytes(&index_value(&files)),
        ))
    }

    // ----- manifests -----

    /// Build, sign, and store a parent-linked manifest over the current
    /// event set. Returns the signed manifest document.
    pub fn publish_manifest(
        &self,
        repository_uuid: &str,
        signer: &crate::crypto::PrivateKey,
        observed_at: &str,
        fresh_seconds: i64,
    ) -> Result<Value, ContractError> {
        let events = self.stored_events()?;
        self.publish_manifest_with_events(
            repository_uuid,
            signer,
            observed_at,
            fresh_seconds,
            &events,
        )
    }

    /// Build, sign, and store a manifest over an explicitly supplied event
    /// set. The repository command uses the files committed at the checked-out
    /// revision rather than mutable worktree contents.
    pub fn publish_manifest_with_events(
        &self,
        repository_uuid: &str,
        signer: &crate::crypto::PrivateKey,
        observed_at: &str,
        fresh_seconds: i64,
        events: &[StoredFile],
    ) -> Result<Value, ContractError> {
        let leaves: Vec<Vec<u8>> = events.iter().map(|file| file.bytes.clone()).collect();
        // Serialize linked-worktree publication on the common-dir lock. The
        // lock remains held through the atomic manifest write, so concurrent
        // publishers observe one parent head and form one lineage.
        let _lock = self.admission_lock(repository_uuid)?;
        let heads = self.manifest_heads()?;
        let clock_skew =
            crate::time::receipt_clock_skew(observed_at, &crate::time::now_rfc3339_millis());
        let branch = self.branch()?;
        let revision = self.default_branch_revision()?;
        let mut manifest = json!({
            "schema": crate::model::MANIFEST_SCHEMA,
            "repository_uuid": repository_uuid,
            "branch": branch,
            "observed_default_branch_revision": revision,
            "manifest_head_set": heads,
            "event_count": events.len(),
            "event_digests": events.iter().map(|file| file.digest.clone()).collect::<Vec<_>>(),
            "merkle_root": merkle_root(&leaves),
            "observed_at": observed_at,
            "fresh_until": crate::time::plus_seconds(observed_at, fresh_seconds).map_err(ContractError::internal)?
        });
        if let Some((direction, seconds)) = clock_skew {
            manifest["disposition"] = Value::String("CLOCK_SKEW".to_owned());
            manifest["quarantined"] = Value::Bool(true);
            manifest["skew_direction"] = Value::String(direction.to_owned());
            manifest["skew_seconds"] = Value::from(seconds);
        }
        let signed = signer.sign_document("manifest", &manifest)?;
        let bytes = crate::json::record_bytes(&signed)?;
        let digest = crate::hash::sha256_bytes(&bytes);
        let relative = paths::sharded_relative(&digest)?;
        let path = paths::contained(&self.kin.join("manifests"), &relative)?;
        paths::write_atomic(&path, &bytes, 0o644, true)?;
        // The lineage register in Git's common directory holds a content-
        // addressed copy of every manifest any linked worktree of this
        // repository published, so every worktree computes the same heads
        // under the same lock. It is a cache of the signed artefacts, never a
        // second authority: a copy either matches its digest or is ignored.
        let register = self.lineage_register_dir();
        paths::ensure_private_dir(&register, "manifest lineage register")?;
        let register_path = paths::contained(&register, &relative)?;
        paths::write_atomic(&register_path, &bytes, 0o600, false)?;
        let mut result = signed;
        result["manifest_digest"] = Value::String(digest);
        result["manifest_path"] =
            Value::String(format!(".kin/manifests/{}", relative.to_string_lossy()));
        Ok(result)
    }

    /// Where this repository's worktrees register the manifests they publish.
    pub fn lineage_register_dir(&self) -> PathBuf {
        self.common_dir.join("kinbase").join("manifests")
    }

    /// Manifests known to this repository's lineage: those stored in this
    /// worktree plus the register copies published from any linked worktree,
    /// deduplicated by content digest and limited to copies whose path is
    /// their digest.
    pub fn lineage_manifests(&self) -> Result<Vec<StoredFile>, ContractError> {
        let mut manifests = self.stored_manifests()?;
        let mut seen: BTreeSet<String> = manifests
            .iter()
            .filter(|file| !file.path_alias)
            .map(|file| file.digest.clone())
            .collect();
        let register = self.lineage_register_dir();
        if register.is_dir() {
            for file in stored_files(&register)? {
                if file.path_alias || !seen.insert(file.digest.clone()) {
                    continue;
                }
                manifests.push(file);
            }
        }
        Ok(manifests)
    }

    /// Manifest heads: lineage manifests not referenced as a parent by any
    /// other lineage manifest.
    pub fn manifest_heads(&self) -> Result<Vec<String>, ContractError> {
        let manifests = self.lineage_manifests()?;
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        let mut all: BTreeSet<String> = BTreeSet::new();
        for file in &manifests {
            if file.path_alias {
                continue;
            }
            all.insert(file.digest.clone());
            if let Ok(value) = crate::json::parse_strict_value(&file.bytes) {
                if let Some(parents) = crate::json::get_array(&value, "manifest_head_set") {
                    for parent in parents {
                        if let Some(parent) = parent.as_str() {
                            referenced.insert(parent.to_owned());
                        }
                    }
                }
            }
        }
        Ok(all.difference(&referenced).cloned().collect())
    }
}

pub struct AdmissionLock {
    _file: std::fs::File,
    pub path: PathBuf,
}

impl Drop for AdmissionLock {
    fn drop(&mut self) {
        // SAFETY: releasing a lock on a descriptor we still own.
        unsafe {
            libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn next_generation(journal_dir: &Path) -> Result<u64, ContractError> {
    let mut max = 0u64;
    for relative in paths::list_files(journal_dir)? {
        if let Some(stem) = relative.file_stem().and_then(|stem| stem.to_str()) {
            if let Ok(value) = stem.parse::<u64>() {
                max = max.max(value);
            }
        }
    }
    Ok(max + 1)
}

/// One regular file under `.kin/events` or `.kin/manifests` with its path
/// digest (from the sharded path) and content digest.
#[derive(Debug, Clone)]
pub struct StoredFile {
    pub relative: PathBuf,
    pub digest: String,
    pub bytes: Vec<u8>,
    pub path_alias: bool,
}

/// One bounded pass over a store directory: the files actually read and
/// digested, plus the total the directory holds.
///
/// A store at or below the ratified `.kin/` intake ceiling is read whole.
/// Above it the pass is incremental by construction (architecture §6 bounded
/// storage behaviour, §11 ceilings): the surplus is counted, never read, and
/// is reported as deferred so no caller can mistake an unread event for a
/// checked one.
#[derive(Debug, Clone, Default)]
pub struct EventScan {
    pub files: Vec<StoredFile>,
    pub total: usize,
    pub deferred: usize,
}

fn stored_files_bounded(root: &Path, limit: usize) -> Result<EventScan, ContractError> {
    let relatives = paths::list_files(root)?;
    let total = relatives.len();
    let mut output = Vec::new();
    for relative in relatives.into_iter().take(limit) {
        let path = root.join(&relative);
        let bytes =
            std::fs::read(&path).map_err(|error| ContractError::io("read stored file", error))?;
        let content_digest = crate::hash::sha256_bytes(&bytes);
        let path_digest = paths::digest_from_sharded(&relative);
        let path_alias = path_digest.as_deref() != Some(content_digest.as_str());
        output.push(StoredFile {
            relative,
            digest: content_digest,
            bytes,
            path_alias,
        });
    }
    output.sort_by(|left, right| left.relative.cmp(&right.relative));
    let deferred = total.saturating_sub(output.len());
    Ok(EventScan {
        files: output,
        total,
        deferred,
    })
}

fn stored_files(root: &Path) -> Result<Vec<StoredFile>, ContractError> {
    Ok(stored_files_bounded(root, EVENT_CEILING)?.files)
}

fn index_value(files: &[StoredFile]) -> Value {
    json!({
        "schema": "kinbase-index/1",
        "event_count": files.len(),
        "events": files.iter().map(|file| json!({"digest": file.digest, "bytes": file.bytes.len()})).collect::<Vec<_>>()
    })
}

pub fn merkle_root(leaves: &[Vec<u8>]) -> String {
    if leaves.is_empty() {
        return crate::hash::sha256_bytes(&[]);
    }
    let mut level: Vec<[u8; 32]> = leaves
        .iter()
        .map(|leaf| crate::hash::sha256_raw(leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(crate::hash::sha256_raw(&[left, right].concat()));
        }
        level = next;
    }
    crate::hash::hex_string(&level[0])
}

/// Parsed content of a stored event file.
#[derive(Debug, Clone)]
pub enum ParsedEvent {
    Fact(FactEvent),
    Unknown(UnknownEvent),
    Tombstone(Value),
    Malformed(String),
}

pub fn parse_stored(bytes: &[u8]) -> ParsedEvent {
    let Ok(value) = crate::json::parse_strict_value(bytes) else {
        return ParsedEvent::Malformed("not canonical JSON".to_owned());
    };
    match crate::json::get_str(&value, "schema") {
        Some(crate::model::EVENT_SCHEMA) => match FactEvent::parse(bytes) {
            Ok(event) => ParsedEvent::Fact(event),
            Err(error) => ParsedEvent::Malformed(error),
        },
        Some(crate::model::UNKNOWN_SCHEMA) => match UnknownEvent::parse(bytes) {
            Ok(event) => ParsedEvent::Unknown(event),
            Err(error) => ParsedEvent::Malformed(error),
        },
        Some(crate::model::TOMBSTONE_SCHEMA) => ParsedEvent::Tombstone(value),
        _ => ParsedEvent::Malformed("unsupported schema".to_owned()),
    }
}

/// Manifest comparison against a published observation (architecture §6):
/// equal, strict superset (normal lag), strict subset (INCOMPLETE), or
/// incomparable.
pub fn compare_event_sets(local: &BTreeSet<String>, published: &BTreeSet<String>) -> &'static str {
    if local == published {
        "equal"
    } else if local.is_superset(published) {
        "superset"
    } else if local.is_subset(published) {
        "subset"
    } else {
        "incomparable"
    }
}

#[cfg(test)]
mod worktree_location_tests {
    use super::*;

    fn init(dir: &Path) {
        let out = Command::new("git")
            .args(["init", "-q"])
            .arg(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn a_retargeted_repository_symlink_is_looked_up_afresh() {
        let base = tempfile::tempdir().unwrap();
        let (a, b) = (base.path().join("a"), base.path().join("b"));
        for dir in [&a, &b] {
            std::fs::create_dir(dir).unwrap();
            init(dir);
        }
        let link = base.path().join("repo");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        let (root_a, common_a) = worktree_location(&link).unwrap();
        assert_eq!(Path::new(&root_a).canonicalize().unwrap(), a.canonicalize().unwrap());
        assert!(Path::new(&common_a).is_absolute());
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&b, &link).unwrap();
        let (root_b, common_b) = worktree_location(&link).unwrap();
        assert_eq!(Path::new(&root_b).canonicalize().unwrap(), b.canonicalize().unwrap());
        assert!(Path::new(&common_b).starts_with(b.canonicalize().unwrap()), "{common_b}");
    }

    #[test]
    fn a_repository_initialized_inside_a_known_one_is_found() {
        let base = tempfile::tempdir().unwrap();
        let outer = base.path().join("outer");
        let inner = outer.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        init(&outer);
        let (root, _) = worktree_location(&inner).unwrap();
        assert_eq!(Path::new(&root).canonicalize().unwrap(), outer.canonicalize().unwrap());
        init(&inner);
        let (root, common) = worktree_location(&inner).unwrap();
        assert_eq!(Path::new(&root).canonicalize().unwrap(), inner.canonicalize().unwrap());
        assert!(Path::new(&common).starts_with(inner.canonicalize().unwrap()), "{common}");
    }
}
