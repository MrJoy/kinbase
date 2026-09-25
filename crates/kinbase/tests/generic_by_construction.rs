//! Kinbase is a generic tool. No deployment's identity belongs in it.
//!
//! This exists because the violation arrived the way violations of this kind
//! always do — one honest sentence at a time. Nobody set out to put a company's
//! name in a generic tool. A comment explaining *why* a threshold is 87 is a
//! good comment, and naming the estate it was measured on felt like precision
//! rather than leakage. Thirty-two references accumulated that way, and one had
//! stopped being a comment: a production predicate branched on whether a
//! statement contained a particular company's name, so the tool behaved
//! differently for that company's text than for anyone else's.
//!
//! Two distinct harms, which is why the probe is worth its weight:
//!
//! 1. **Behaviour.** A generic tool that branches on a target token is not
//!    generic. It is a bespoke tool wearing a generic name, and the difference
//!    only shows up for the second user.
//! 2. **Disclosure.** Measurements are the useful part of those comments and
//!    should stay: "87 repositories", "83,655 facts", "148,004 commits" all
//!    justify the constants they sit beside. Attributing them to a named estate
//!    publishes that estate's size, shape, and which of its services are
//!    weakest, in a repository anyone can read.
//!
//! The rule this encodes: **keep the measurement, drop the owner.**
//!
//! ## What "generic" can and cannot mean here
//!
//! "No mention of the organisation" is not achievable and not the goal: the
//! repository's own URL contains its owner, and a project may name the
//! organisation behind it. `LICENSE`, `README.md` and `docs/` do exactly that
//! and are excused by path. What is enforced is narrower and is the part that
//! actually matters — **no operational data, no estate shape, no PII, and no
//! developer-local paths**, anywhere, in any file type.
//!
//! An earlier version of this probe scanned only `crates/**/*.rs`. That covered
//! the one *behavioural* violation but 19 of the 28 files needing repair were
//! Markdown, JSON, Python and HTML, and the PII class had no token at all. A
//! guard that misses the category the operator actually complained about is
//! worse than no guard, because it reports clean.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Directories excused by path, with the reason each is excused.
///
/// `evidence/` and `spec/receipts/` are **attested artifacts**: a ratification
/// receipt naming its actor *is* the provenance, and rewriting signed bytes to
/// sanitise them is tampering rather than fixing. They are excluded from the
/// scan so this probe never pressures anyone into falsifying them — which is a
/// mistake this very commit made once and had to revert.
const EXCUSED_PREFIXES: &[&str] = &[
    "LICENSE",
    "README.md",
    "docs/",     // states the project's sponsor and its own repository URL
    "evidence/",      // attested: do not rewrite
    "spec/receipts/", // attested: do not rewrite
    // The auxiliary corpus is attested the same way, and more subtly: RIGHTS.md
    // is block 2 of the pool-digest preimage, so editing its prose moves the
    // digest that pool.json, POOL-DIGEST, SELECTION.json and a signed Validator
    // verdict all bind. pool.json says so in writing. An earlier pass sanitised
    // it anyway, broke two green acceptance tests, and falsified a verdict that
    // was never touched — so this probe excuses it by path rather than pressuring
    // the next person into the same mistake. The PII in that corpus is real and
    // is a deliberate history-rewrite decision, not a lint fix.
    "tests/fixtures/",
    "tests/acceptance/_harness/debt.py", // mirrors the attested debt catalogue
    // Local agent/graph state, not product.
    ".kin/",
    ".brief/",
    "target/",
    ".git/",
    "crates/kinbase/tests/generic_by_construction.rs", // names the tokens to forbid them
];

const SCANNED_EXTENSIONS: &[&str] = &[
    "rs", "md", "json", "toml", "py", "sh", "html", "txt", "yaml", "yml", "b64",
];

/// Built at runtime so this file's own bytes do not trip the check it defines.
fn forbidden() -> Vec<(String, &'static str)> {
    let company = format!("{}{}", "wan", "der");
    // PII: the operator's complaint was "no PII", and the previous probe had no
    // token for it whatsoever — the highest-value disclosure was unguarded.
    let surname = format!("{}{}", "McEn", "tire");
    let handle = format!("{}{}", "jandrewmc", "entire");
    vec![
        (company, "a deployment's identity"),
        (surname, "PII: a named individual"),
        (handle, "PII: a personal account or address"),
        ("/users/".to_string(), "a developer-local path"),
        ("wanderrepos".to_string(), "a developer-local path"),
    ]
}

fn is_excused(relative: &str) -> bool {
    EXCUSED_PREFIXES.iter().any(|p| relative.starts_with(p))
}

fn scannable(root: &Path, dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if is_excused(&relative) {
            continue;
        }
        if path.is_dir() {
            scannable(root, &path, found);
        } else if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| SCANNED_EXTENSIONS.contains(&e))
        {
            found.push(path);
        }
    }
}

fn workspace_root() -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(crate_dir)
        .to_path_buf()
}

/// Offenders as `path:line — why`, over the whole workspace.
fn scan(root: &Path) -> (usize, Vec<String>) {
    let mut files = Vec::new();
    scannable(root, root, &mut files);
    let tokens = forbidden();
    let mut offenders = BTreeSet::new();
    for path in &files {
        let text = match fs::read_to_string(path) {
            Ok(text) => text.to_lowercase(),
            // Binary or unreadable: counted as scanned but cannot be judged.
            Err(_) => continue,
        };
        for (number, line) in text.lines().enumerate() {
            for (token, why) in &tokens {
                if line.contains(token.as_str()) {
                    offenders.insert(format!(
                        "{}:{} — {}",
                        path.strip_prefix(root).unwrap_or(path).display(),
                        number + 1,
                        why
                    ));
                }
            }
        }
    }
    (files.len(), offenders.into_iter().collect())
}

#[test]
fn no_file_names_a_deployment_or_a_person() {
    let root = workspace_root();
    let (scanned, offenders) = scan(&root);

    // Vacuity guard: a scan that found nothing to read proves nothing. The
    // number is deliberately well below the real count so ordinary growth or
    // pruning does not make this brittle, while a broken walk still trips it.
    assert!(
        scanned > 50,
        "only {scanned} file(s) scanned under {}; the walk is broken and this probe \
         would otherwise pass vacuously",
        root.display()
    );

    assert!(
        offenders.is_empty(),
        "{} disclosure(s) across {scanned} scanned file(s):\n  {}\n\n\
         Keep the measurement, drop the owner — \"87 repositories\" is a good comment, \
         \"87 of <company>'s repositories\" publishes that company's estate. If it is a \
         predicate rather than a comment, the tool is not generic at all. \
         LICENSE, README.md and docs/ may name the sponsor; evidence/ and spec/receipts/ \
         are attested and must not be rewritten to satisfy this test.",
        offenders.len(),
        offenders.join("\n  ")
    );
}

#[test]
fn the_probe_catches_its_own_positive_control() {
    // A detector that cannot catch its positive control yields an invalid
    // harness — the standard this repository's own acceptance suite applies.
    // The previous version of this test asserted that `String::contains` works
    // and never invoked the scan, so a broken directory walk or an over-broad
    // exclusion would have left both tests green.
    let root = std::env::temp_dir().join(format!(
        "kinbase-generic-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let nested = root.join("crates").join("deep");
    fs::create_dir_all(&nested).expect("temp tree");

    let company = format!("{}{}", "wan", "der");
    let planted = nested.join("planted.md");
    fs::write(&planted, format!("<!-- measured across seven {company} services -->\n"))
        .expect("write planted file");
    let clean = nested.join("clean.rs");
    fs::write(&clean, "// measured across seven services of one deployment\n")
        .expect("write clean file");
    // An excused path must stay excused even while carrying the token.
    let excused = root.join("docs");
    fs::create_dir_all(&excused).expect("docs dir");
    fs::write(excused.join("index.html"), format!("<p>A {company} project</p>\n"))
        .expect("write excused file");

    let (scanned, offenders) = scan(&root);
    // Three files planted; docs/ is excused by path, so two are scanned. That
    // asymmetry is the point: it proves the exclusion list is doing work.
    assert_eq!(scanned, 2, "expected to scan the two unexcused planted files");
    assert_eq!(
        offenders.len(),
        1,
        "the detector must flag the planted reference and nothing else, got: {offenders:?}"
    );
    assert!(
        offenders[0].starts_with("crates/deep/planted.md:1"),
        "wrong file flagged: {offenders:?}"
    );

    fs::remove_dir_all(&root).ok();
}
