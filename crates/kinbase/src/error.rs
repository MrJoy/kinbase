//! Closed error taxonomy from `spec/cli.md` "Error contract".
//!
//! Every failure that leaves a command is a `ContractError` carrying the five
//! documented fields. The exit code is a pure function of the code so no call
//! site can pair a code with a foreign exit. Codes outside the closed table
//! cannot be constructed: `ContractError::new` maps an unknown code to the
//! internal-failure code and records the defect in the message.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExitCode {
    Ok = 0,
    UserActionRequired = 2,
    DegradedSafe = 3,
    Refused = 4,
    IntegrityFailure = 5,
    DependencyUnavailable = 6,
    InternalFailure = 70,
}

/// The closed proof-version taxonomy, exactly as ratified.
pub const CODES: [&str; 27] = [
    "COMPANY_UNREACHABLE",
    "CACHE_EXPIRED",
    "REVOCATION_STALE",
    "REPO_UNCERTIFIED",
    "FOREIGN_REPO_EVENTS",
    "SIGNATURE_INVALID",
    "DIGEST_MISMATCH",
    "DIGEST_ALGORITHM_UNSUPPORTED",
    "MANIFEST_INCOMPLETE",
    "MANIFEST_HEAD_REGRESSION",
    "LIMIT_EXCEEDED",
    "APPROVAL_EXPIRED",
    "APPROVAL_REPLAY",
    "AUTHORITY_WRONG_SCOPE",
    "AUTHORITY_SCOPE_DENIED",
    "UNKNOWN_OWNER_UNRESOLVED",
    "PERSONAL_TAINT_BLOCKED",
    "HOOK_APPROVAL_REQUIRED",
    "UNSUPPORTED_HOST_VERSION",
    "UNSUPPORTED_KINDEX_VERSION",
    "PROCESSOR_UNAUTHORIZED",
    "MODEL_FINGERPRINT_CHANGED",
    "ORACLE_LEAKAGE",
    "SCORER_UNCALIBRATED",
    "RUN_CENSUS_MISSING",
    "CONFIG_INVARIANT",
    "RUN_INTEGRITY_FAILED",
];

/// Exit code for a taxonomy code. `COMPANY_UNREACHABLE` and
/// `MANIFEST_INCOMPLETE` carry a documented alternate exit (3) that callers
/// select through [`ContractError::degraded_variant`].
pub fn exit_for(code: &str) -> i32 {
    match code {
        "COMPANY_UNREACHABLE" => 6,
        "CACHE_EXPIRED"
        | "REVOCATION_STALE"
        | "DIGEST_ALGORITHM_UNSUPPORTED"
        | "UNKNOWN_OWNER_UNRESOLVED"
        | "UNSUPPORTED_HOST_VERSION"
        | "UNSUPPORTED_KINDEX_VERSION" => 3,
        "REPO_UNCERTIFIED" | "APPROVAL_EXPIRED" | "HOOK_APPROVAL_REQUIRED" => 2,
        "FOREIGN_REPO_EVENTS"
        | "MANIFEST_HEAD_REGRESSION"
        | "LIMIT_EXCEEDED"
        | "APPROVAL_REPLAY"
        | "AUTHORITY_WRONG_SCOPE"
        | "AUTHORITY_SCOPE_DENIED"
        | "CONFIG_INVARIANT" => 4,
        "SIGNATURE_INVALID"
        | "DIGEST_MISMATCH"
        | "PERSONAL_TAINT_BLOCKED"
        | "PROCESSOR_UNAUTHORIZED"
        | "MANIFEST_INCOMPLETE" => 5,
        _ => 70,
    }
}

/// Ratified `retryable` flag per code; `None` means conditional
/// (`LIMIT_EXCEEDED`), where the call site decides.
pub fn retryable_for(code: &str) -> Option<bool> {
    match code {
        "COMPANY_UNREACHABLE"
        | "CACHE_EXPIRED"
        | "REVOCATION_STALE"
        | "UNKNOWN_OWNER_UNRESOLVED" => Some(true),
        "LIMIT_EXCEEDED" => None,
        _ => Some(false),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractError {
    pub code: String,
    pub message: String,
    pub remediation: String,
    pub retryable: bool,
    pub evidence_id: String,
    /// Documented alternate exit for codes with two exits; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_override: Option<i32>,
    /// Structured, privacy-minimized detail (counts, ids, digests). Never
    /// file contents, secrets, or transcript bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
    /// Command-owned JSON document to emit at the top-level error boundary.
    /// This preserves richer command envelopes (status/fsck diagnostics) while
    /// keeping stdout to exactly one JSON line on failure.
    #[serde(skip)]
    pub output_document: Option<serde_json::Value>,
    #[serde(skip)]
    oidc_token_failure: bool,
}

impl ContractError {
    pub fn new(
        code: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
        retryable: bool,
        exit: ExitCode,
    ) -> Self {
        let message = message.into();
        let remediation = remediation.into();
        let known = CODES.contains(&code);
        let consistent = known && exit_for(code) == exit as i32;
        let (code, message, remediation) = if consistent {
            (code.to_owned(), message, remediation)
        } else {
            (
                "RUN_INTEGRITY_FAILED".to_owned(),
                format!(
                    "implementation defect: error code {code} was constructed with exit {} (original message: {message})",
                    exit as i32
                ),
                "Preserve the receipt and report the implementation defect; no product pass."
                    .to_owned(),
            )
        };
        let retryable = retryable_for(&code).unwrap_or(retryable);
        let evidence_source = format!("{code}\0{message}\0{remediation}\0{retryable}");
        let evidence_id = format!("err_{}", &crate::hash::sha256_text(&evidence_source)[..16]);
        Self {
            code,
            message,
            remediation,
            retryable,
            evidence_id,
            exit_override: None,
            detail: None,
            output_document: None,
            oidc_token_failure: false,
        }
    }

    pub(crate) fn with_oidc_token_failure(mut self) -> Self {
        self.oidc_token_failure = true;
        self
    }

    pub(crate) fn is_oidc_token_failure(&self) -> bool {
        self.oidc_token_failure
    }

    /// Attach the complete command document for the top-level boundary.
    pub fn with_output_document(mut self, document: serde_json::Value) -> Self {
        self.output_document = Some(document);
        self
    }

    /// Attach structured detail (ids, counts). The caller is responsible for
    /// keeping it free of protected bytes.
    pub fn with_detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = Some(detail);
        self
    }

    /// `COMPANY_UNREACHABLE` on a safe cached read and `MANIFEST_INCOMPLETE`
    /// on a declared sparse checkout exit 3 instead of their primary exit.
    pub fn degraded_variant(mut self) -> Self {
        if self.code == "COMPANY_UNREACHABLE" || self.code == "MANIFEST_INCOMPLETE" {
            self.exit_override = Some(3);
        }
        self
    }

    /// The same error as a coding host's hook returns it. A host reads exit 2
    /// from a hook as "block": PreToolUse refuses the tool, UserPromptSubmit
    /// drops the prompt, Stop refuses to stop and fires again. Kinbase holds
    /// no host permission capability (architecture section 9), and an
    /// ordinary non-repository session may continue (cli.md), so a hook
    /// never exits 2: a user-action refusal leaves as degraded-safe (3), with
    /// its code and message unchanged.
    pub fn for_host_hook(mut self) -> Self {
        if self.exit() == ExitCode::UserActionRequired as i32 {
            self.exit_override = Some(ExitCode::DegradedSafe as i32);
        }
        self
    }

    pub fn exit(&self) -> i32 {
        self.exit_override.unwrap_or_else(|| exit_for(&self.code))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(
            "RUN_INTEGRITY_FAILED",
            message,
            "Preserve evidence and rerun after repairing the failure; no product pass.",
            false,
            ExitCode::InternalFailure,
        )
    }

    pub fn refused(code: &str, message: impl Into<String>, remediation: impl Into<String>) -> Self {
        Self::new(code, message, remediation, false, ExitCode::Refused)
    }

    pub fn invariant(message: impl Into<String>) -> Self {
        Self::new(
            "CONFIG_INVARIANT",
            message,
            "Correct the named value or input; no state was changed.",
            false,
            ExitCode::Refused,
        )
    }

    pub fn limit(message: impl Into<String>, detail: serde_json::Value) -> Self {
        Self::new(
            "LIMIT_EXCEEDED",
            message,
            "Reduce one bounded input or obtain a new ratified budget; nothing was truncated silently.",
            false,
            ExitCode::Refused,
        )
        .with_detail(detail)
    }

    pub fn integrity(
        code: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(
            code,
            message,
            remediation,
            false,
            ExitCode::IntegrityFailure,
        )
    }

    pub fn degraded(
        code: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(code, message, remediation, true, ExitCode::DegradedSafe)
    }

    pub fn user_action(
        code: &str,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self::new(
            code,
            message,
            remediation,
            false,
            ExitCode::UserActionRequired,
        )
    }

    pub fn unreachable(message: impl Into<String>) -> Self {
        Self::new(
            "COMPANY_UNREACHABLE",
            message,
            "Restore the Company endpoint or continue with the named facts withheld.",
            true,
            ExitCode::DependencyUnavailable,
        )
    }

    /// The Codebase store has not been initialized: exit 2 with the exact
    /// `repo init` command (cli.md "requested store uninitialized"). Without
    /// an installed out-of-tree certificate the repository is uncertified.
    pub fn repo_uninitialized(repo: &Path) -> Self {
        Self::user_action(
            "REPO_UNCERTIFIED",
            "the repository has no initialized .kin/ store or installed certificate",
            format!(
                "Run `kinbase repo issue --repo {0} --company <url>` then `kinbase repo init --repo {0} --certificate <outside-worktree-file>`.",
                repo.display()
            ),
        )
    }

    /// Unreadable token/key/config file: exit 4 with the path role only.
    pub fn unreadable(role: &str, error: &std::io::Error) -> Self {
        Self::refused(
            "CONFIG_INVARIANT",
            format!("{role} file is unreadable ({})", error.kind()),
            format!(
                "Restore the {role} file at its configured path with mode 0600; contents are never printed."
            ),
        )
    }

    /// Token/key file mode broader than 0600: exit 4 with chmod remediation.
    pub fn broad_mode(role: &str, path: &Path, mode: u32) -> Self {
        Self::refused(
            "CONFIG_INVARIANT",
            format!("{role} file mode {:o} is broader than 0600", mode & 0o777),
            format!(
                "Run `chmod 0600 {}` and retry; file contents are never printed.",
                path.display()
            ),
        )
    }

    /// I/O failure while touching a declared root or artifact.
    pub fn io(context: &str, error: std::io::Error) -> Self {
        Self::internal(format!("{context}: {} ({})", error.kind(), error))
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ContractError {}

pub type Result<T, E = ContractError> = std::result::Result<T, E>;

#[cfg(test)]
mod exit_agreement_tests {
    use super::*;

    /// Every taxonomy code a call site passes to a typed constructor must be
    /// one that constructor's exit carries; a mismatch is silently rewritten
    /// to RUN_INTEGRITY_FAILED at run time.
    #[test]
    fn every_literal_code_agrees_with_its_constructor_exit() {
        let constructors = [
            ("ContractError::refused(", ExitCode::Refused as i32),
            (
                "ContractError::integrity(",
                ExitCode::IntegrityFailure as i32,
            ),
            ("ContractError::degraded(", ExitCode::DegradedSafe as i32),
            (
                "ContractError::user_action(",
                ExitCode::UserActionRequired as i32,
            ),
        ];
        let exits = [
            (
                "ExitCode::UserActionRequired",
                ExitCode::UserActionRequired as i32,
            ),
            ("ExitCode::DegradedSafe", ExitCode::DegradedSafe as i32),
            ("ExitCode::Refused", ExitCode::Refused as i32),
            (
                "ExitCode::IntegrityFailure",
                ExitCode::IntegrityFailure as i32,
            ),
            (
                "ExitCode::DependencyUnavailable",
                ExitCode::DependencyUnavailable as i32,
            ),
            (
                "ExitCode::InternalFailure",
                ExitCode::InternalFailure as i32,
            ),
        ];
        let mut mismatches = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src"
        ))];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                for entry in std::fs::read_dir(&path).expect("source dir").flatten() {
                    stack.push(entry.path());
                }
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source");
            let literal = |from: &str| -> Option<String> {
                let rest = from.trim_start().strip_prefix('"')?;
                let code: String = rest.chars().take_while(|c| *c != '"').collect();
                (!code.is_empty() && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'))
                    .then_some(code)
            };
            for (constructor, exit) in constructors {
                for (at, _) in text.match_indices(constructor) {
                    if let Some(code) = literal(&text[at + constructor.len()..])
                        && CODES.contains(&code.as_str())
                        && exit_for(&code) != exit
                    {
                        mismatches.push(format!("{}: {constructor}\"{code}\"", path.display()));
                    }
                }
            }
            for (at, _) in text.match_indices("ContractError::new(") {
                let call = &text[at + "ContractError::new(".len()..];
                let Some(code) = literal(call) else { continue };
                let window: String = call.chars().take(800).collect();
                let Some((name, exit)) = exits
                    .iter()
                    .filter_map(|(name, exit)| {
                        window.find(name).map(|position| (position, name, exit))
                    })
                    .min_by_key(|(position, _, _)| *position)
                    .map(|(_, name, exit)| (name, exit))
                else {
                    continue;
                };
                if CODES.contains(&code.as_str()) && exit_for(&code) != *exit {
                    mismatches.push(format!("{}: new(\"{code}\", .., {name})", path.display()));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "code/exit mismatches: {mismatches:#?}"
        );
    }
}
