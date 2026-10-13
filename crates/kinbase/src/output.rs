//! Output discipline (interface contract §0, C23): under `--json` exactly
//! one single-line JSON document on stdout; every stderr line is one JSON
//! object; human output preserves the same IDs, state, and remediation.

use serde_json::Value;

/// Emit a success document. JSON is one canonical line; human output is a
/// compact key/value rendering of the top-level scalars plus the full
/// document as a single JSON line for inspection.
pub fn emit(value: &Value, json: bool) {
    // Known secrets never reach the terminal or a caller's pipe
    // (`crate::secret_mask`; `explain` and most commands print here).
    let mut masked;
    let value = match crate::secret_mask::active_table() {
        Some(table) => {
            masked = value.clone();
            crate::secret_mask::mask_value_with(&mut masked, &table);
            &masked
        }
        None => value,
    };
    if json {
        println!("{}", single_line(value));
        return;
    }
    if let Value::Object(map) = value {
        for (key, item) in map {
            match item {
                Value::String(text) => println!("{key}: {text}"),
                Value::Bool(flag) => println!("{key}: {flag}"),
                Value::Number(number) => println!("{key}: {number}"),
                Value::Null => println!("{key}: null"),
                Value::Array(items) => println!("{key}: [{} item(s)]", items.len()),
                Value::Object(_) => println!("{key}: {}", single_line(item)),
            }
        }
    } else {
        println!("{}", single_line(value));
    }
}

/// Canonical single-line JSON (falls back to serde_json when the value is
/// outside the canonical data model, e.g. contains floats in diagnostics).
pub fn single_line(value: &Value) -> String {
    crate::json::try_canonical_text(value)
        .unwrap_or_else(|_| serde_json::to_string(value).unwrap_or_else(|_| "{}".to_owned()))
}

/// A structured diagnostic on stderr: one JSON object per line, never raw
/// private bytes.
pub fn diagnostic(kind: &str, detail: Value) {
    let line = serde_json::json!({"diagnostic": kind, "detail": detail, "at": crate::time::now_rfc3339_millis()});
    eprintln!("{}", single_line(&line));
}

/// Rows a reader skipped: a total and the first few, described without
/// their bytes. The total is what a rising count is judged on; retaining
/// every skipped row's detail turned a corrupt ledger into a memory spike.
#[derive(Default)]
pub(crate) struct Skipped {
    total: usize,
    samples: Vec<Value>,
}

impl Skipped {
    const SAMPLES: usize = 8;

    /// A skipped row. `reason` is a closed category (see `unreadable_reason`),
    /// never a parser's message: those quote the keys and values they choke
    /// on, and a diagnostic never carries private bytes.
    pub(crate) fn push(&mut self, position: usize, bytes: usize, reason: &'static str) {
        self.push_sample(
            serde_json::json!({"position": position, "bytes": bytes, "error": reason}),
        );
    }

    /// A skipped file, named by its content-address shard path when it has
    /// one and otherwise only by a digest of its name.
    pub(crate) fn push_file(&mut self, file: &str, bytes: usize, reason: &'static str) {
        self.push_sample(
            serde_json::json!({"file": diagnostic_file_name(file), "bytes": bytes, "error": reason}),
        );
    }

    fn push_sample(&mut self, sample: Value) {
        self.total += 1;
        if self.samples.len() < Self::SAMPLES {
            self.samples.push(sample);
        }
    }

    pub(crate) fn total(&self) -> usize {
        self.total
    }

    /// The first skipped line positions, for a refusal that names them.
    pub(crate) fn positions(&self) -> Vec<u64> {
        self.samples
            .iter()
            .filter_map(|sample| sample.get("position").and_then(Value::as_u64))
            .collect()
    }

    /// The Recovered signal: one diagnostic per read naming the source, the
    /// total skipped and the first samples, so a rising count is visible
    /// before it becomes a lost ledger. Silence here is how the loss stayed
    /// hidden.
    pub(crate) fn report(&self, source: &str) {
        if self.total == 0 {
            return;
        }
        diagnostic(
            "unreadable-ledger-rows",
            serde_json::json!({"source": source, "skipped": self.total, "rows": self.samples}),
        );
    }
}

/// Why bytes could not be read as a record, as a closed category.
pub(crate) fn unreadable_reason(bytes: &[u8]) -> &'static str {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return "not UTF-8";
    };
    match serde_json::from_str::<Value>(text) {
        Err(_) => "not JSON",
        Ok(Value::Object(_)) => "outside the canonical data model",
        Ok(_) => "not a JSON object",
    }
}

/// A store-relative file name fit for a diagnostic: a content-addressed
/// event path (`ab/cd/<60 hex>.json`) is shown as is; any other name could be
/// anything, so only a digest of it is.
fn diagnostic_file_name(file: &str) -> String {
    let parts: Vec<&str> = file.split('/').collect();
    let hex = |part: &str, len: usize| {
        part.len() == len
            && part
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let addressed = parts.len() == 3
        && hex(parts[0], 2)
        && hex(parts[1], 2)
        && parts[2]
            .strip_suffix(".json")
            .is_some_and(|stem| hex(stem, 60));
    if addressed {
        file.to_owned()
    } else {
        format!(
            "unaddressed file sha256:{}",
            &crate::hash::sha256_text(file)[..16]
        )
    }
}

/// Render a typed error as the nested error document. Extra top-level keys
/// (counts) travel beside `error`.
pub fn error_document(error: &crate::error::ContractError) -> Value {
    let mut document = serde_json::json!({"error": {
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
        "retryable": error.retryable,
        "evidence_id": error.evidence_id
    }});
    if let Some(Value::Object(detail)) = &error.detail {
        for (key, value) in detail {
            document[key] = value.clone();
        }
        document["error"]["detail"] = Value::Object(detail.clone());
    }
    document
}

#[cfg(test)]
mod tests {
    use super::{diagnostic_file_name, unreadable_reason};

    #[test]
    fn a_skip_reason_never_quotes_the_bytes() {
        assert_eq!(unreadable_reason(b"\xff\xfe"), "not UTF-8");
        assert_eq!(unreadable_reason(b"{\"guest\": \"Wilhelmina"), "not JSON");
        assert_eq!(unreadable_reason(b"[1, 2]"), "not a JSON object");
        assert_eq!(
            unreadable_reason(b"{\"guest\": \"Wilhelmina\"}"),
            "outside the canonical data model"
        );
    }

    #[test]
    fn only_a_content_address_is_shown_as_a_file_name() {
        let addressed = format!("ab/cd/{}.json", "0".repeat(60));
        assert_eq!(diagnostic_file_name(&addressed), addressed);
        let named = diagnostic_file_name("ab/cd/Wilhelmina-notes.json");
        assert!(named.starts_with("unaddressed file sha256:"), "{named}");
        assert!(!named.contains("Wilhelmina"));
    }
}
