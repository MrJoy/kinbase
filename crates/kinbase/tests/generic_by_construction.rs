//! Kinbase is a generic tool. No deployment's identity belongs in it.
//!
//! This exists because the violation arrived the way violations of this kind
//! always do — one honest sentence at a time. Nobody set out to put a company's
//! name in a generic tool. A comment explaining *why* a threshold is 87 is a
//! good comment, and naming the estate it was measured on felt like precision
//! rather than leakage. Thirty-two references accumulated that way, and one of
//! them had stopped being a comment: a production predicate branched on whether
//! a statement contained a particular company's name, so the tool behaved
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
//! The rule this encodes: keep the measurement, drop the owner.
//!
//! LICENSE and README are the two places a project legitimately names the
//! organisation behind it, so they are not scanned.

use std::fs;
use std::path::{Path, PathBuf};

/// Built at runtime so this file does not trip the very check it defines.
fn target_tokens() -> Vec<String> {
    // Split so the literal never appears in the source being scanned.
    let company = format!("{}{}", "wan", "der");
    let org = format!("{}{}", company, "com");
    vec![company, org]
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, found);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            // This file names the tokens in order to forbid them.
            if path.file_name().and_then(|n| n.to_str()) != Some("generic_by_construction.rs") {
                found.push(path);
            }
        }
    }
}

#[test]
fn no_source_file_names_a_deployment() {
    // CARGO_MANIFEST_DIR is the crate; the scan covers the whole workspace.
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = crate_dir.parent().and_then(Path::parent).unwrap_or(crate_dir);
    let mut sources = Vec::new();
    rust_sources(&root.join("crates"), &mut sources);
    rust_sources(&root.join("tests"), &mut sources);
    assert!(!sources.is_empty(), "the scan found no sources; the probe would pass vacuously");

    let tokens = target_tokens();
    let mut offenders = Vec::new();
    for path in &sources {
        let text = match fs::read_to_string(path) {
            Ok(text) => text.to_lowercase(),
            Err(_) => continue,
        };
        for (number, line) in text.lines().enumerate() {
            for token in &tokens {
                if line.contains(token.as_str()) {
                    offenders.push(format!(
                        "{}:{}",
                        path.strip_prefix(root).unwrap_or(path).display(),
                        number + 1
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a deployment's identity appears in {} place(s): {:?}\n\
         Keep the measurement, drop the owner — \"87 repositories\" is a good comment, \
         \"87 of <company>'s repositories\" publishes that company's estate. If it is a \
         predicate rather than a comment, the tool is not generic at all.",
        offenders.len(),
        offenders
    );
}

#[test]
fn the_probe_can_actually_fail() {
    // A guard nobody has watched fail is a claim, not a guard. This asserts the
    // detector fires on the exact shape it forbids, so the test above passing
    // means something.
    let tokens = target_tokens();
    let planted = format!("// measured across seven {} services", tokens[0]);
    assert!(
        tokens.iter().any(|t| planted.to_lowercase().contains(t.as_str())),
        "the detector failed to catch a planted reference"
    );
    let clean = "// measured across seven services of one deployment";
    assert!(
        !tokens.iter().any(|t| clean.to_lowercase().contains(t.as_str())),
        "the detector flagged a correctly genericised comment"
    );
}
