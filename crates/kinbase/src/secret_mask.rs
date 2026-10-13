//! Known-secret masking: a secret value read from a file the user names
//! becomes `$NAME` before anything Kinbase writes, signs or prints carries it.
//!
//! The user names one or more shell env files in their own config:
//!
//! ```toml
//! [secret_mask]
//! files = ["~/.profile"]
//! keys = ["OPENAI_API_KEY", "github", "AWS_*_KEY"]   # optional
//! min_length = 8                                     # optional
//! ```
//!
//! Every `[export ]NAME=VALUE` line whose NAME a key selector picks yields a
//! known secret, and every occurrence of VALUE becomes `$NAME`, which is safe
//! to keep. The same semantics as Kindex's and signet-eval's `secret_mask`.
//!
//! Only the user config sets this. A repository's `.kin/kinbase.toml` has a
//! closed key set and cannot name it, and no environment variable turns it
//! on, off or narrower: an absent `[secret_mask]` is the only way off.
//!
//! This module never logs, returns in an error, or prints a secret value; a
//! diagnostic names the reference file and the failure kind only.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Name fragments selected when `keys` is omitted: case-insensitive
/// substrings of the variable name.
pub const DEFAULT_KEY_PATTERNS: [&str; 17] = [
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASS",
    "PW",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "SID",
    "DSN",
    "WEBHOOK",
    "COOKIE",
    "CLIENT_ID",
    "ACCOUNT_ID",
    "API",
];

/// Values shorter than this are not masked: a short value is more often a
/// flag or a port than a secret, and masking it would rewrite ordinary text.
pub const DEFAULT_MIN_LENGTH: usize = 8;

/// Keys whose values are identifiers, digests, timestamps or closed
/// vocabulary rather than prose. Masking never rewrites them: an identifier
/// is validated, never folded (REVIEW.md), and a signature or digest that
/// changed would no longer verify.
const IDENTITY_KEYS: [&str; 34] = [
    "schema",
    "id",
    "event_id",
    "fact_id",
    "session_id",
    "candidate_id",
    "observation_id",
    "native_id",
    "unit_id",
    "signer",
    "signature",
    "store_kind",
    "authority_id",
    "authority_scope",
    "repository_id",
    "repository_uuid",
    "logical_key",
    "parents",
    "supersedes",
    "redundancy_with",
    "complements",
    "asserted_at",
    "effective_from",
    "effective_until",
    "observed_at",
    "timestamp",
    "disposition",
    "atom_kind",
    "standing",
    "provenance",
    "authority_snapshot_cursor",
    "cwd",
    "transcript_path",
    "hook_event_name",
];

/// `[secret_mask]` from the user config. Absent means masking is off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMaskConfig {
    pub files: Vec<PathBuf>,
    /// `None` selects `DEFAULT_KEY_PATTERNS`.
    pub keys: Option<Vec<String>>,
    pub min_length: usize,
}

/// Whether `pattern` selects `name`: case-insensitive, `*` matches any run
/// of characters, and the pattern may match anywhere in the name. A full
/// name therefore selects itself, in any case.
fn selector_matches(pattern: &str, name: &str) -> bool {
    fn go(pattern: &[u8], name: &[u8]) -> bool {
        match pattern {
            [] => true,
            [b'*', rest @ ..] => (0..=name.len()).any(|skip| go(rest, &name[skip..])),
            [first, rest @ ..] => {
                name.first()
                    .is_some_and(|byte| byte.eq_ignore_ascii_case(first))
                    && go(rest, &name[1..])
            }
        }
    }
    if pattern.trim_matches('*').is_empty() {
        return false;
    }
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    (0..name.len()).any(|start| go(pattern, &name[start..]))
}

/// Whether a variable named `name` holds a secret under `keys`
/// (`DEFAULT_KEY_PATTERNS` when `None`).
pub fn key_selected(name: &str, keys: Option<&[String]>) -> bool {
    match keys {
        Some(keys) => keys.iter().any(|key| selector_matches(key, name)),
        None => DEFAULT_KEY_PATTERNS
            .iter()
            .any(|key| selector_matches(key, name)),
    }
}

/// `NAME` and the raw text after `=` on one `[export ]NAME=VALUE` line.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let mut line = line.trim_start();
    if let Some(rest) = line.strip_prefix("export")
        && rest.starts_with(char::is_whitespace)
    {
        line = rest.trim_start();
    }
    let (name, value) = line.split_once('=')?;
    let mut bytes = name.bytes();
    let first = bytes.next()?;
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    Some((name, value))
}

/// The literal value of `raw`: matching surrounding quotes stripped, or an
/// unquoted value with a trailing ` #comment` dropped. `None` for a quoted
/// value that never closes or is followed by more than a comment: it is not
/// one literal, and guessing would mask the wrong bytes.
fn literal(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(quote) = raw.chars().next().filter(|c| *c == '\'' || *c == '"') {
        let inner = &raw[1..];
        let end = inner.find(quote)?;
        let rest = inner[end + 1..].trim_start();
        if !rest.is_empty() && !rest.starts_with('#') {
            return None;
        }
        return Some(&inner[..end]);
    }
    let cut = raw
        .char_indices()
        .find(|(at, c)| c.is_whitespace() && raw[at + c.len_utf8()..].starts_with('#'))
        .map(|(at, _)| at)
        .unwrap_or(raw.len());
    Some(raw[..cut].trim_end())
}

/// `(name, value)` pairs in file order for every selected, literal value.
/// A value holding `$` or a backtick is an expansion this file cannot
/// resolve, and a value shorter than `min_length` is not masked.
pub fn parse_env_text(
    text: &str,
    keys: Option<&[String]>,
    min_length: usize,
) -> Vec<(String, String)> {
    text.lines()
        .filter_map(assignment)
        .filter(|(name, _)| key_selected(name, keys))
        .filter_map(|(name, raw)| Some((name, literal(raw)?)))
        .filter(|(_, value)| !value.contains(['$', '`']) && value.chars().count() >= min_length)
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

/// A value as it appears inside a JSON string, with non-ASCII escaped
/// (`ascii`) or kept.
fn json_escaped(value: &str, ascii: bool) -> String {
    let quoted = serde_json::to_string(value).unwrap_or_default();
    let inner = &quoted[1..quoted.len().saturating_sub(1).max(1)];
    if !ascii {
        return inner.to_owned();
    }
    let mut out = String::with_capacity(inner.len());
    for c in inner.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    out
}

/// `(value, name)` replacements, longest value first. The first name in file
/// order owns a value several names share. A value's JSON-escaped spellings
/// map to the same name, so text that already went through a serializer is
/// masked too.
pub fn build_table(pairs: &[(String, String)]) -> Vec<(String, String)> {
    fn claim(owner: &mut Vec<(String, String)>, value: String, name: &str) {
        if !owner.iter().any(|(known, _)| *known == value) {
            owner.push((value, name.to_owned()));
        }
    }
    let mut owner: Vec<(String, String)> = Vec::new();
    for (name, value) in pairs {
        claim(&mut owner, value.clone(), name);
    }
    for (_, value) in pairs {
        let name = owner
            .iter()
            .find(|(known, _)| known == value)
            .map(|(_, name)| name.clone())
            .unwrap_or_default();
        for ascii in [false, true] {
            let escaped = json_escaped(value, ascii);
            if escaped != *value {
                claim(&mut owner, escaped, &name);
            }
        }
    }
    // A stable sort keeps file order among equal lengths.
    owner.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
    owner
}

/// Every occurrence of each known value replaced with `$NAME`.
pub fn mask_text(text: &str, table: &[(String, String)]) -> String {
    let mut text = text.to_owned();
    for (value, name) in table {
        if text.contains(value.as_str()) {
            text = text.replace(value.as_str(), &format!("${name}"));
        }
    }
    text
}

/// `(value, name)` replacements, longest value first (`build_table`).
pub type Table = Arc<Vec<(String, String)>>;

/// What one reference file contributed, keyed by its mtime and size.
#[derive(Default)]
struct FileState {
    stamp: Option<(std::time::SystemTime, u64)>,
    read: bool,
    pairs: Vec<(String, String)>,
    warned: bool,
}

/// Known secrets from the configured files, re-read when a file's
/// modification time or size changes.
pub struct SecretMask {
    config: SecretMaskConfig,
    state: Mutex<(Vec<FileState>, Table)>,
}

impl SecretMask {
    pub fn new(config: SecretMaskConfig) -> Self {
        let files = config.files.iter().map(|_| FileState::default()).collect();
        Self {
            config,
            state: Mutex::new((files, Arc::new(Vec::new()))),
        }
    }

    /// The replacement table, refreshed from any file that changed.
    pub fn table(&self) -> Table {
        let Ok(mut guard) = self.state.lock() else {
            return Arc::new(Vec::new());
        };
        let (files, table) = &mut *guard;
        let mut changed = false;
        for (path, file) in self.config.files.iter().zip(files.iter_mut()) {
            let stamp = std::fs::metadata(path)
                .ok()
                .map(|meta| (meta.modified().unwrap_or(std::time::UNIX_EPOCH), meta.len()));
            if file.read && file.stamp == stamp {
                continue;
            }
            file.read = true;
            file.stamp = stamp;
            changed = true;
            match std::fs::read(path) {
                Ok(bytes) => {
                    file.warned = false;
                    file.pairs = parse_env_text(
                        &String::from_utf8_lossy(&bytes),
                        self.config.keys.as_deref(),
                        self.config.min_length,
                    );
                }
                Err(error) => {
                    file.pairs.clear();
                    if !file.warned {
                        file.warned = true;
                        warn_unreadable(path, &error);
                    }
                }
            }
        }
        if changed {
            let pairs: Vec<(String, String)> = files
                .iter()
                .flat_map(|file| file.pairs.iter().cloned())
                .collect();
            *table = Arc::new(build_table(&pairs));
        }
        Arc::clone(table)
    }

    /// Distinct names with at least one masked value, in file order.
    pub fn names(&self) -> Vec<String> {
        self.table();
        let Ok(guard) = self.state.lock() else {
            return Vec::new();
        };
        let mut names: Vec<String> = Vec::new();
        for (name, _) in guard.0.iter().flat_map(|file| file.pairs.iter()) {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        names
    }
}

/// The diagnostic names the file and the failure kind, never its bytes.
fn warn_unreadable(path: &Path, error: &std::io::Error) {
    crate::output::diagnostic(
        "secret-mask-file-unreadable",
        serde_json::json!({
            "file": path.to_string_lossy(),
            "reason": format!("{:?}", error.kind()),
            "effect": "no values are masked from this file until it can be read"
        }),
    );
}

static ACTIVE: Mutex<Option<Arc<SecretMask>>> = Mutex::new(None);

/// Install the process-wide mask from the user config (`None` turns it
/// off). The same settings keep the existing mask and its parsed cache, since
/// one invocation reads the user config several times.
pub fn configure(config: Option<&SecretMaskConfig>) {
    let Ok(mut active) = ACTIVE.lock() else {
        return;
    };
    match config {
        None => *active = None,
        Some(config) => {
            if active.as_ref().is_some_and(|mask| mask.config == *config) {
                return;
            }
            *active = Some(Arc::new(SecretMask::new(config.clone())));
        }
    }
}

/// The installed mask, if masking is on.
pub fn active() -> Option<Arc<SecretMask>> {
    ACTIVE.lock().ok().and_then(|active| active.clone())
}

/// The installed mask's replacement table, refreshed from changed files;
/// `None` when masking is off or nothing is known. A caller masking many
/// values takes it once and uses `mask_text` / `mask_value_with`, rather
/// than re-checking every file per value.
pub fn active_table() -> Option<Table> {
    active()
        .map(|mask| mask.table())
        .filter(|table| !table.is_empty())
}

/// `text` with every known secret replaced; unchanged when masking is off.
pub fn mask_str(text: &str) -> String {
    match active_table() {
        Some(table) => mask_text(text, &table),
        None => text.to_owned(),
    }
}

/// Every string value inside `value` masked, except the values of identity
/// keys (`IDENTITY_KEYS`). Returns whether anything changed.
pub fn mask_value(value: &mut Value) -> bool {
    match active_table() {
        Some(table) => mask_value_with(value, &table),
        None => false,
    }
}

/// `mask_value` with a table already in hand.
pub fn mask_value_with(value: &mut Value, table: &[(String, String)]) -> bool {
    match value {
        Value::String(text) => {
            let masked = mask_text(text, table);
            let changed = masked != *text;
            *text = masked;
            changed
        }
        Value::Array(items) => items.iter_mut().fold(false, |changed, item| {
            mask_value_with(item, table) | changed
        }),
        Value::Object(map) => {
            let mut changed = false;
            for (key, item) in map.iter_mut() {
                if IDENTITY_KEYS.contains(&key.as_str()) {
                    continue;
                }
                changed |= mask_value_with(item, table);
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| key.to_string()).collect()
    }

    #[test]
    fn a_line_is_an_optional_export_then_name_equals_value() {
        let text = "\
export OPENAI_API_KEY=sk-fake-0123456789
  export   GITHUB_TOKEN=\"ghp_fakefakefake\"
STRIPE_SECRET='sk_test_fakefake' # test account
DB_PASSWORD=hunter2hunter2 # trailing comment
WEBHOOK_URL=https://hooks.example.test/T0/B0#anchor
1BAD_KEY=startswithdigit1
BAD-KEY=hasahyphen12345
exportAPI_KEY=notanexportline
";
        let pairs = parse_env_text(text, None, DEFAULT_MIN_LENGTH);
        assert_eq!(
            pairs,
            vec![
                ("OPENAI_API_KEY".to_owned(), "sk-fake-0123456789".to_owned()),
                ("GITHUB_TOKEN".to_owned(), "ghp_fakefakefake".to_owned()),
                ("STRIPE_SECRET".to_owned(), "sk_test_fakefake".to_owned()),
                ("DB_PASSWORD".to_owned(), "hunter2hunter2".to_owned()),
                (
                    "WEBHOOK_URL".to_owned(),
                    "https://hooks.example.test/T0/B0#anchor".to_owned()
                ),
                ("exportAPI_KEY".to_owned(), "notanexportline".to_owned()),
            ]
        );
    }

    #[test]
    fn expansions_short_values_and_broken_quotes_are_skipped() {
        let text = "\
API_KEY=$OTHER_KEY_VALUE
AUTH_TOKEN=`cat /fake/token/file`
SECRET_SHORT=short
QUOTED_TOKEN=\"never closes
JOINED_TOKEN=\"abcdefgh\"tail
SPACED_SECRET=\"  padded value  \"
";
        let pairs = parse_env_text(text, None, DEFAULT_MIN_LENGTH);
        assert_eq!(
            pairs,
            vec![("SPACED_SECRET".to_owned(), "  padded value  ".to_owned())]
        );
        assert_eq!(
            parse_env_text("SECRET_SHORT=short\n", None, 5),
            vec![("SECRET_SHORT".to_owned(), "short".to_owned())]
        );
    }

    #[test]
    fn selectors_are_case_insensitive_names_or_globbed_fragments() {
        // The defaults: a documented list of name fragments.
        for name in ["OPENAI_API_KEY", "github_token", "Db_Passwd", "SENTRY_DSN"] {
            assert!(key_selected(name, None), "{name}");
        }
        for name in ["HOME", "EDITOR", "LANG"] {
            assert!(!key_selected(name, None), "{name}");
        }
        // A full name selects itself in any case.
        let full = owned(&["openai_api_key"]);
        assert!(key_selected("OPENAI_API_KEY", Some(&full)));
        assert!(!key_selected("GITHUB_TOKEN", Some(&full)));
        // A fragment selects any name containing it; `*` spans a run.
        let partial = owned(&["github", "AWS_*_KEY"]);
        assert!(key_selected("MY_GITHUB_PAT", Some(&partial)));
        assert!(key_selected("AWS_SECRET_ACCESS_KEY", Some(&partial)));
        assert!(!key_selected("AWS_REGION", Some(&partial)));
        // A bare `*` selects nothing rather than everything.
        assert!(!key_selected("ANYTHING", Some(&owned(&["*"]))));
        // An explicit list replaces the defaults.
        assert!(!key_selected("GITHUB_TOKEN", Some(&owned(&["OPENAI"]))));
    }

    #[test]
    fn every_occurrence_becomes_the_name_longest_value_first() {
        let pairs = vec![
            ("SHORT_TOKEN".to_owned(), "abcd1234".to_owned()),
            ("LONG_TOKEN".to_owned(), "abcd1234-extended".to_owned()),
            ("FIRST_KEY".to_owned(), "shared-value-99".to_owned()),
            ("SECOND_KEY".to_owned(), "shared-value-99".to_owned()),
        ];
        let table = build_table(&pairs);
        assert_eq!(
            mask_text(
                "abcd1234-extended then abcd1234, and shared-value-99 twice: shared-value-99",
                &table
            ),
            "$LONG_TOKEN then $SHORT_TOKEN, and $FIRST_KEY twice: $FIRST_KEY"
        );
    }

    #[test]
    fn a_value_is_masked_in_its_json_escaped_spelling_too() {
        let pairs = vec![("QUOTE_SECRET".to_owned(), "pa\"ss\\wörd-1".to_owned())];
        let table = build_table(&pairs);
        let serialized =
            serde_json::to_string(&serde_json::json!({"t": "pa\"ss\\wörd-1"})).unwrap();
        assert_eq!(mask_text(&serialized, &table), "{\"t\":\"$QUOTE_SECRET\"}");
        assert_eq!(
            mask_text("{\"t\":\"pa\\\"ss\\\\w\\u00f6rd-1\"}", &table),
            "{\"t\":\"$QUOTE_SECRET\"}"
        );
    }

    #[test]
    fn identity_keys_are_never_rewritten() {
        let table = build_table(&[("API_TOKEN".to_owned(), "tok-0123456789".to_owned())]);
        let mut record = serde_json::json!({
            "event_id": "tok-0123456789",
            "statement": "uses tok-0123456789",
            "evidence_refs": ["https://x.test/?t=tok-0123456789"],
            "tok-0123456789": {"session_id": "tok-0123456789", "text": "tok-0123456789"}
        });
        assert!(mask_value_with(&mut record, &table));
        assert_eq!(record["event_id"], "tok-0123456789");
        assert_eq!(record["statement"], "uses $API_TOKEN");
        assert_eq!(record["evidence_refs"][0], "https://x.test/?t=$API_TOKEN");
        assert_eq!(record["tok-0123456789"]["session_id"], "tok-0123456789");
        assert_eq!(record["tok-0123456789"]["text"], "$API_TOKEN");
    }

    #[test]
    fn a_changed_file_is_reread_and_a_missing_one_masks_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("profile");
        std::fs::write(&file, "export API_TOKEN=first-fake-value\n").unwrap();
        let mask = SecretMask::new(SecretMaskConfig {
            files: vec![file.clone(), temp.path().join("absent")],
            keys: None,
            min_length: DEFAULT_MIN_LENGTH,
        });
        assert_eq!(mask_text("first-fake-value", &mask.table()), "$API_TOKEN");
        // A different size changes the stamp even within one mtime tick.
        std::fs::write(&file, "export API_TOKEN=second-fake-value-longer\n").unwrap();
        let table = mask.table();
        assert_eq!(mask_text("first-fake-value", &table), "first-fake-value");
        assert_eq!(mask_text("second-fake-value-longer", &table), "$API_TOKEN");
        assert_eq!(mask.names(), vec!["API_TOKEN".to_owned()]);
        // Removing the file empties its contribution; nothing panics.
        std::fs::remove_file(&file).unwrap();
        assert!(mask.table().is_empty());
    }
}
