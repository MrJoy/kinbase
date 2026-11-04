//! Usage records for the Company service: who called it, what each request
//! did, how it ended, and how long it took, so a steward can see who uses
//! Kinbase, how, and how much.
//!
//! A row names its request from the closed route table, never from the
//! bytes the caller sent. The path's identifiers, the query string, the body
//! and any fact prose stay out: a usage count needs to know that a fact was
//! read, not which words were in the request for it. Every stored string is
//! therefore either a constant of this module, a code from the closed error
//! taxonomy, or the principal the Company itself registered for the token.

use crate::company::db::CompanyDb;
use crate::error::ContractError;
use serde_json::{Value, json};

pub const REPORT_SCHEMA: &str = "kinbase-usage-report/1";

/// One request's place in the closed taxonomy: an action (`fact.read`,
/// `recall.snapshot`, ...) and the route template it arrived on, with every
/// path identifier replaced by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    pub name: &'static str,
    pub target: &'static str,
}

impl Action {
    const fn new(name: &'static str, target: &'static str) -> Self {
        Self { name, target }
    }
}

/// A route the service does not serve. The path is the caller's text, so it
/// is never echoed into a row.
pub const UNROUTED: Action = Action::new("request.unrouted", "unrouted");

/// Classify one request by method and normalized route. `body` is the parsed
/// request body when the service got that far; it only separates a new fact
/// from a supersession or retraction, and nothing is read out of it.
pub fn classify(method: &str, route: &str, body: Option<&Value>) -> Action {
    let exact = match (method, route) {
        ("GET", "/status") => Some(Action::new("info.status", "/status")),
        ("GET", "/facts") => Some(Action::new("fact.list", "/facts")),
        ("POST", "/facts") => Some(if body.is_some_and(changes_an_existing_fact) {
            Action::new("fact.update", "/facts")
        } else {
            Action::new("fact.create", "/facts")
        }),
        ("GET", "/snapshot") => Some(Action::new("recall.snapshot", "/snapshot")),
        ("GET", "/events") => Some(Action::new("recall.events", "/events")),
        ("POST", "/authority-registry") => {
            Some(Action::new("registry.publish", "/authority-registry"))
        }
        ("GET", "/authority-registry") => Some(Action::new("registry.read", "/authority-registry")),
        ("POST", "/directory") => Some(Action::new("directory.write", "/directory")),
        ("POST", "/questions") => Some(Action::new("question.ask", "/questions")),
        ("GET", "/questions") => Some(Action::new("question.list", "/questions")),
        ("POST", "/answers") => Some(Action::new("answer.write", "/answers")),
        ("GET", "/answers") => Some(Action::new("answer.read", "/answers")),
        ("POST", "/unknowns") => Some(Action::new("unknown.write", "/unknowns")),
        ("GET", "/unknowns") => Some(Action::new("unknown.list", "/unknowns")),
        ("POST", "/certificates") => Some(Action::new("certificate.issue", "/certificates")),
        ("GET", "/certificates") => Some(Action::new("certificate.list", "/certificates")),
        ("POST", "/manifests") => Some(Action::new("manifest.publish", "/manifests")),
        ("POST", "/revocations") => Some(Action::new("revocation.publish", "/revocations")),
        ("GET", "/revocations") => Some(Action::new("revocation.read", "/revocations")),
        ("POST", "/rotations") => Some(Action::new("rotation.publish", "/rotations")),
        ("POST", "/tokens") => Some(Action::new("token.issue", "/tokens")),
        ("GET", "/steward-queue") => Some(Action::new("steward.queue", "/steward-queue")),
        _ => None,
    };
    if let Some(action) = exact {
        return action;
    }
    // The prefix routes, in the order the service matches them.
    let prefixed: [(&str, Action); 5] = [
        (
            "/questions/",
            Action::new("question.read", "/questions/{question_id}"),
        ),
        (
            "/directory/",
            Action::new("directory.read", "/directory/{authority_id}"),
        ),
        (
            "/certificates/",
            Action::new("certificate.read", "/certificates/{repository_uuid}"),
        ),
        (
            "/manifests/",
            Action::new("manifest.read", "/manifests/{repository_uuid}"),
        ),
        ("/facts/", Action::new("fact.read", "/facts/{fact_id}")),
    ];
    if method == "GET" {
        for (prefix, action) in prefixed {
            if route.starts_with(prefix) {
                return action;
            }
        }
    }
    UNROUTED
}

/// The lifecycle actions the service turns into tombstones on the events
/// they name (`current_view`). `never_true` is also a negative disposition;
/// `misextraction` and `support_withdrawn` are not, and were counted as new
/// facts.
const WITHDRAWALS: [&str; 3] = ["misextraction", "never_true", "support_withdrawn"];

/// A posted fact-event that supersedes another, carries a negative
/// disposition (retracted, withdrawn, ...) or is a lifecycle withdrawal
/// changes a fact that already exists. The event may arrive bare or wrapped
/// with its approval. A lifecycle action is named by its disposition or its
/// atom kind, as `model::action_of` reads it.
fn changes_an_existing_fact(body: &Value) -> bool {
    let event = body.get("event").unwrap_or(body);
    let supersedes = event
        .get("supersedes")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let negative = crate::json::get_str(event, "disposition")
        .is_some_and(crate::model::disposition_is_negative);
    let withdrawal = ["disposition", "atom_kind"].into_iter().any(|field| {
        crate::json::get_str(event, field).is_some_and(|value| WITHDRAWALS.contains(&value))
    });
    supersedes || negative || withdrawal
}

/// One authenticated request, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageEvent {
    pub recorded_at: String,
    /// The principal the Company registered for the presented token.
    pub principal_id: String,
    /// The first 16 hex of the client key, the same fingerprint the per-
    /// principal read ceiling keys on. A role token shared by several people
    /// is one principal; this is what tells their installations apart.
    pub client: String,
    /// The token's role: `facts`, `directory`, `admin`, `authority`, `issued`.
    pub token_role: String,
    pub action: &'static str,
    pub target: &'static str,
    pub status: u16,
    /// The closed error-taxonomy code of a refusal; absent on success.
    pub error_code: Option<String>,
    pub duration_ms: u64,
}

/// Append one usage row. Recording never changes the answer the caller gets:
/// a row that cannot be written is reported on stderr, with only the closed
/// fields, and the request's own outcome stands.
pub fn record(db: &CompanyDb, event: &UsageEvent) {
    if let Err(error) = db.append_usage(event) {
        crate::output::diagnostic(
            "usage-record-failed",
            json!({"action": event.action, "status": event.status, "code": error.code}),
        );
    }
}

/// Window granularity for the report's time breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Day,
    Hour,
}

impl Bucket {
    /// The prefix of an RFC 3339 millisecond instant that names the window:
    /// `2026-10-22` or `2026-10-22T14`.
    pub fn prefix_len(self) -> usize {
        match self {
            Bucket::Day => 10,
            Bucket::Hour => 13,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Bucket::Day => "day",
            Bucket::Hour => "hour",
        }
    }
}

/// The half-open window `[since, until)` a report covers; either end may be
/// open.
#[derive(Debug, Clone, Default)]
pub struct Window {
    pub since: Option<String>,
    pub until: Option<String>,
}

impl Window {
    /// Both ends must be RFC 3339 UTC millisecond instants, the form rows are
    /// stored in, so that comparing the text compares the instants.
    pub fn parse(since: Option<&str>, until: Option<&str>) -> Result<Self, ContractError> {
        let instant = |flag: &str, value: &str| {
            crate::time::parse_rfc3339_millis(value)
                .map(crate::time::format_rfc3339_millis)
                .map_err(|message| {
                    ContractError::refused(
                        "CONFIG_INVARIANT",
                        format!("--{flag} is not an RFC 3339 UTC millisecond instant ({message})"),
                        format!(
                            "Pass --{flag} as RFC 3339 UTC with millisecond precision, e.g. 2026-10-01T00:00:00.000Z."
                        ),
                    )
                })
        };
        let window = Self {
            since: since.map(|value| instant("since", value)).transpose()?,
            until: until.map(|value| instant("until", value)).transpose()?,
        };
        if let (Some(since), Some(until)) = (&window.since, &window.until)
            && since >= until
        {
            return Err(ContractError::refused(
                "CONFIG_INVARIANT",
                "--since must be earlier than --until",
                "Pass a window whose start precedes its end.",
            ));
        }
        Ok(window)
    }
}

/// Totals and breakdowns by principal, client installation, action and time
/// window, as one canonical document.
pub fn report(db: &CompanyDb, window: &Window, bucket: Bucket) -> Result<Value, ContractError> {
    // A store the service has not opened since usage rows were added has no
    // table yet. `serve` adds it; a report reads its absence as no rows
    // rather than writing to a store a live service may be using.
    let summary = if db.has_table("usage_events")? {
        db.usage_summary(window, bucket)?
    } else {
        Summary::empty()
    };
    Ok(json!({
        "schema": REPORT_SCHEMA,
        "window": {
            "since": window.since,
            "until": window.until,
            "bucket": bucket.name()
        },
        "totals": summary.totals,
        "by_principal": summary.by_principal,
        "by_client": summary.by_client,
        "by_action": summary.by_action,
        "by_window": summary.by_window
    }))
}

/// The aggregate rows behind a report; `CompanyDb::usage_summary` fills it.
pub struct Summary {
    pub totals: Value,
    pub by_principal: Vec<Value>,
    pub by_client: Vec<Value>,
    pub by_action: Vec<Value>,
    pub by_window: Vec<Value>,
}

impl Summary {
    /// What a store holding no usage rows reports.
    fn empty() -> Self {
        Self {
            totals: json!({
                "requests": 0,
                "succeeded": 0,
                "refused": 0,
                "failed": 0,
                "principals": 0,
                "clients": 0,
                "first_at": null,
                "last_at": null
            }),
            by_principal: Vec::new(),
            by_client: Vec::new(),
            by_action: Vec::new(),
            by_window: Vec::new(),
        }
    }
}

/// The report as aligned text for a terminal. The JSON form carries the same
/// numbers; this only lays them out.
pub fn render_human(report: &Value) -> String {
    let text = |value: &Value| match value {
        Value::String(text) => text.clone(),
        Value::Null => "-".to_owned(),
        other => other.to_string(),
    };
    let rows = |key: &str| report[key].as_array().cloned().unwrap_or_default();
    let mut out = String::new();
    let window = &report["window"];
    out.push_str(&format!(
        "company: {}\nwindow: {} .. {} (by {})\n",
        text(&report["company_id"]),
        text(&window["since"]),
        text(&window["until"]),
        text(&window["bucket"]),
    ));
    if report["recording"] == false {
        out.push_str("recording: off; set record_usage = true in the service config\n");
    }
    let totals = &report["totals"];
    out.push_str(&format!(
        "requests: {} (succeeded {}, refused {}, failed {}) from {} principal(s) on {} client(s)\n",
        text(&totals["requests"]),
        text(&totals["succeeded"]),
        text(&totals["refused"]),
        text(&totals["failed"]),
        text(&totals["principals"]),
        text(&totals["clients"]),
    ));
    out.push_str(&format!(
        "first: {}  last: {}\n",
        text(&totals["first_at"]),
        text(&totals["last_at"])
    ));
    out.push_str("\nby principal:\n");
    for row in rows("by_principal") {
        let actions = row["actions"]
            .as_object()
            .map(|actions| {
                actions
                    .iter()
                    .map(|(action, count)| format!("{action}={count}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "  {:<24} {:>8} req  {:>6} refused  {:>6} failed  {:>3} client(s)  last {}  {}\n",
            text(&row["principal_id"]),
            text(&row["requests"]),
            text(&row["refused"]),
            text(&row["failed"]),
            text(&row["clients"]),
            text(&row["last_at"]),
            actions,
        ));
    }
    // A row is a principal, client and token role: one principal can hold
    // two roles from one installation, and without the role those two rows
    // printed as identical lines.
    out.push_str("\nby client:\n");
    for row in rows("by_client") {
        out.push_str(&format!(
            "  {:<24} {:<16} {:<9} {:>8} req  last {}\n",
            text(&row["principal_id"]),
            text(&row["client"]),
            text(&row["token_role"]),
            text(&row["requests"]),
            text(&row["last_at"]),
        ));
    }
    out.push_str("\nby action:\n");
    for row in rows("by_action") {
        out.push_str(&format!(
            "  {:<24} {:>8} req  {:>6} refused  {:>6} failed  {:>3} principal(s)  mean {} ms\n",
            text(&row["action"]),
            text(&row["requests"]),
            text(&row["refused"]),
            text(&row["failed"]),
            text(&row["principals"]),
            text(&row["mean_duration_ms"]),
        ));
    }
    out.push_str(&format!("\nby {}:\n", text(&window["bucket"])));
    for row in rows("by_window") {
        out.push_str(&format!(
            "  {:<24} {:>8} req  {:>6} refused  {:>6} failed  {:>3} principal(s)\n",
            text(&row["window"]),
            text(&row["requests"]),
            text(&row["refused"]),
            text(&row["failed"]),
            text(&row["principals"]),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(at: &str, principal: &str, client: &str, action: Action, status: u16) -> UsageEvent {
        UsageEvent {
            recorded_at: at.to_owned(),
            principal_id: principal.to_owned(),
            client: client.to_owned(),
            token_role: "issued".to_owned(),
            action: action.name,
            target: action.target,
            status,
            error_code: (status >= 400).then(|| "AUTHORITY_SCOPE_DENIED".to_owned()),
            duration_ms: 4,
        }
    }

    fn store() -> (tempfile::TempDir, CompanyDb) {
        let temp = tempfile::tempdir().unwrap();
        let db = CompanyDb::open(&temp.path().join("company.sqlite")).unwrap();
        (temp, db)
    }

    #[test]
    fn a_path_identifier_never_becomes_the_target() {
        let marker = "Wilhelmina-0xCANARY";
        for (method, route, name) in [
            ("GET", "/facts/Wilhelmina-0xCANARY", "fact.read"),
            ("GET", "/questions/Wilhelmina-0xCANARY", "question.read"),
            ("GET", "/directory/Wilhelmina-0xCANARY", "directory.read"),
            (
                "GET",
                "/certificates/Wilhelmina-0xCANARY",
                "certificate.read",
            ),
            ("GET", "/manifests/Wilhelmina-0xCANARY", "manifest.read"),
            ("GET", "/Wilhelmina-0xCANARY", "request.unrouted"),
            ("DELETE", "/facts/Wilhelmina-0xCANARY", "request.unrouted"),
        ] {
            let action = classify(method, route, None);
            assert_eq!(action.name, name, "{method} {route}");
            assert!(
                !action.target.contains(marker),
                "{method} {route}: {action:?}"
            );
        }
    }

    #[test]
    fn every_served_route_has_its_own_action() {
        for (method, route, name, family) in [
            ("GET", "/status", "info.status", "info"),
            ("GET", "/facts", "fact.list", "fact"),
            ("POST", "/facts", "fact.create", "fact"),
            ("GET", "/snapshot", "recall.snapshot", "recall"),
            ("GET", "/events", "recall.events", "recall"),
            ("POST", "/questions", "question.ask", "question"),
            ("POST", "/answers", "answer.write", "answer"),
            ("POST", "/tokens", "token.issue", "token"),
            ("GET", "/steward-queue", "steward.queue", "steward"),
        ] {
            let action = classify(method, route, None);
            // An action is `family.verb`; the report groups nothing by
            // family, so only the naming is pinned here.
            let (action_family, _) = action.name.split_once('.').unwrap();
            assert_eq!((action.name, action_family), (name, family));
        }
    }

    #[test]
    fn a_supersession_or_retraction_is_an_update_not_a_create() {
        let new = json!({"schema": "kinbase-event/1", "supersedes": [], "disposition": "accepted"});
        let superseding = json!({"schema": "kinbase-event/1", "supersedes": ["fact-1"]});
        let retracting = json!({"event": {"disposition": "retracted", "supersedes": []}});
        assert_eq!(classify("POST", "/facts", Some(&new)).name, "fact.create");
        assert_eq!(
            classify("POST", "/facts", Some(&superseding)).name,
            "fact.update"
        );
        assert_eq!(
            classify("POST", "/facts", Some(&retracting)).name,
            "fact.update"
        );
        // Lifecycle withdrawals name their target in `parents`, not
        // `supersedes`, and by disposition or by atom kind.
        let withdrawing =
            json!({"disposition": "support_withdrawn", "parents": ["evt-1"], "supersedes": []});
        let misextracted =
            json!({"disposition": "notice", "atom_kind": "misextraction", "parents": ["evt-1"]});
        assert_eq!(
            classify("POST", "/facts", Some(&withdrawing)).name,
            "fact.update"
        );
        assert_eq!(
            classify("POST", "/facts", Some(&misextracted)).name,
            "fact.update"
        );
        // A body the service never parsed is still a fact write attempt.
        assert_eq!(classify("POST", "/facts", None).name, "fact.create");
    }

    fn count(db: &CompanyDb) -> i64 {
        db.connection
            .query_row("SELECT COUNT(*) FROM usage_events", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn a_usage_row_cannot_change_and_cannot_go_until_it_is_a_day_old() {
        let (_temp, db) = store();
        let status = classify("GET", "/status", None);
        let now = crate::time::now_rfc3339_millis();
        let old = crate::time::plus_seconds(&now, -2 * 24 * 3600).unwrap();
        db.append_usage(&event(&now, "p", "c", status, 200))
            .unwrap();
        db.append_usage(&event(&old, "p", "c", status, 200))
            .unwrap();
        assert!(
            db.connection
                .execute("UPDATE usage_events SET status=500", [])
                .is_err()
        );
        // The young row aborts the statement, so neither row goes.
        assert!(
            db.connection
                .execute("DELETE FROM usage_events", [])
                .is_err()
        );
        assert_eq!(count(&db), 2);
        let deleted = db
            .connection
            .execute(
                "DELETE FROM usage_events WHERE recorded_at = ?1",
                rusqlite::params![old],
            )
            .unwrap();
        assert_eq!((deleted, count(&db)), (1, 1));
    }

    #[test]
    fn rows_past_retention_are_pruned_once_the_oldest_is_due() {
        let (_temp, db) = store();
        let status = classify("GET", "/status", None);
        let now = crate::time::now_rfc3339_millis();
        let ago = |days: i64| crate::time::plus_seconds(&now, -days * 24 * 3600).unwrap();
        for at in [ago(40), ago(31), ago(2), now.clone()] {
            db.append_usage(&event(&at, "p", "c", status, 200)).unwrap();
        }
        // Past retention but not yet due: nothing is written.
        assert_eq!(db.prune_usage(&ago(30), &ago(45)).unwrap(), 0);
        assert_eq!(db.prune_usage(&ago(30), &ago(35)).unwrap(), 2);
        assert_eq!(count(&db), 2);
        // Whatever bound the caller passes, a row younger than a day stays.
        let ahead = crate::time::plus_seconds(&now, 60).unwrap();
        assert!(db.prune_usage(&ahead, &ahead).is_err());
        assert_eq!(count(&db), 2);
    }

    #[test]
    fn a_server_failure_is_counted_apart_from_a_refusal() {
        let (_temp, db) = store();
        let read = classify("GET", "/facts/f-1", None);
        for (status, duration_ms) in [(200, 1), (404, 2), (500, 2)] {
            let mut row = event("2026-10-01T09:00:00.000Z", "ana", "aaaa", read, status);
            row.duration_ms = duration_ms;
            db.append_usage(&row).unwrap();
        }
        let all = report(&db, &Window::default(), Bucket::Day).unwrap();
        let outcomes = |row: &Value| {
            ["requests", "succeeded", "refused", "failed"].map(|key| row[key].as_i64().unwrap())
        };
        for row in [
            &all["totals"],
            &all["by_principal"][0],
            &all["by_action"][0],
            &all["by_window"][0],
        ] {
            assert_eq!(outcomes(row), [3, 1, 1, 1], "{row}");
        }
        // 5 ms over three requests rounds to 2; integer division said 1.
        assert_eq!(all["by_action"][0]["mean_duration_ms"], 2);
        assert!(render_human(&all).contains("(succeeded 1, refused 1, failed 1)"));
    }

    #[test]
    fn a_store_without_the_usage_table_reports_what_an_empty_one_does() {
        let (_temp, db) = store();
        let empty = report(&db, &Window::default(), Bucket::Day).unwrap();
        db.connection
            .execute_batch("DROP TABLE usage_events")
            .unwrap();
        let missing = report(&db, &Window::default(), Bucket::Day).unwrap();
        assert_eq!(missing, empty);
        assert!(!db.has_table("usage_events").unwrap(), "the report wrote");
    }

    #[test]
    fn the_writer_refuses_a_principal_outside_the_text_rule() {
        let (_temp, db) = store();
        let status = classify("GET", "/status", None);
        let bad = event("2026-10-01T00:00:00.000Z", "p\u{202e}x", "c", status, 200);
        assert!(db.append_usage(&bad).is_err());
        assert_eq!(count(&db), 0, "a refused row was stored anyway");
    }

    #[test]
    fn the_report_breaks_usage_down_by_principal_client_action_and_window() {
        let (_temp, db) = store();
        let read = classify("GET", "/facts/f-1", None);
        let snapshot = classify("GET", "/snapshot", None);
        let create = classify("POST", "/facts", None);
        for row in [
            event("2026-10-01T09:00:00.000Z", "ana", "aaaa", read, 200),
            event("2026-10-01T09:30:00.000Z", "ana", "aaaa", snapshot, 200),
            event("2026-10-01T10:00:00.000Z", "ana", "bbbb", read, 404),
            event("2026-10-02T09:00:00.000Z", "bo", "cccc", create, 201),
            event("2026-10-03T09:00:00.000Z", "bo", "cccc", read, 200),
        ] {
            db.append_usage(&row).unwrap();
        }

        let all = report(&db, &Window::default(), Bucket::Day).unwrap();
        assert_eq!(all["totals"]["requests"], 5);
        assert_eq!(all["totals"]["succeeded"], 4);
        assert_eq!(all["totals"]["refused"], 1);
        assert_eq!(all["totals"]["principals"], 2);
        assert_eq!(all["totals"]["clients"], 3);
        assert_eq!(all["totals"]["first_at"], "2026-10-01T09:00:00.000Z");
        assert_eq!(all["totals"]["last_at"], "2026-10-03T09:00:00.000Z");

        let ana = &all["by_principal"][0];
        assert_eq!(ana["principal_id"], "ana");
        assert_eq!(ana["requests"], 3);
        assert_eq!(ana["refused"], 1);
        assert_eq!(ana["clients"], 2);
        assert_eq!(
            ana["actions"],
            json!({"fact.read": 2, "recall.snapshot": 1})
        );
        assert_eq!(
            all["by_principal"][1]["actions"],
            json!({"fact.create": 1, "fact.read": 1})
        );

        assert_eq!(all["by_client"].as_array().unwrap().len(), 3);
        assert_eq!(all["by_action"][0]["action"], "fact.read");
        assert_eq!(all["by_action"][0]["requests"], 3);
        assert_eq!(all["by_action"][0]["principals"], 2);
        assert_eq!(all["by_action"][0]["mean_duration_ms"], 4);
        let days: Vec<_> = all["by_window"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    row["window"].as_str().unwrap().to_owned(),
                    row["requests"].as_i64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            days,
            [
                ("2026-10-01".to_owned(), 3),
                ("2026-10-02".to_owned(), 1),
                ("2026-10-03".to_owned(), 1)
            ]
        );

        // The window is half-open: `since` is in, `until` is out.
        let window = Window::parse(
            Some("2026-10-01T10:00:00.000Z"),
            Some("2026-10-03T09:00:00.000Z"),
        )
        .unwrap();
        let narrowed = report(&db, &window, Bucket::Hour).unwrap();
        assert_eq!(narrowed["totals"]["requests"], 2);
        assert_eq!(narrowed["window"]["bucket"], "hour");
        assert_eq!(narrowed["by_window"][0]["window"], "2026-10-01T10");
        assert!(
            crate::json::try_canonical_text(&narrowed).is_ok(),
            "the report left the canonical data model"
        );
    }

    #[test]
    fn an_empty_store_reports_zeroes_not_an_error() {
        let (_temp, db) = store();
        let empty = report(&db, &Window::default(), Bucket::Day).unwrap();
        assert_eq!(empty["totals"]["requests"], 0);
        assert_eq!(empty["totals"]["first_at"], Value::Null);
        assert!(empty["by_principal"].as_array().unwrap().is_empty());
        assert!(render_human(&empty).contains("requests: 0"));
    }

    #[test]
    fn one_installation_holding_two_tokens_is_one_client() {
        let (_temp, db) = store();
        let status = classify("GET", "/status", None);
        for principal in ["steward", "facts-principal"] {
            let row = event("2026-10-01T09:00:00.000Z", principal, "aaaa", status, 200);
            db.append_usage(&row).unwrap();
        }
        let all = report(&db, &Window::default(), Bucket::Day).unwrap();
        assert_eq!(all["totals"]["principals"], 2);
        assert_eq!(all["totals"]["clients"], 1);
        assert_eq!(all["by_client"].as_array().unwrap().len(), 2);
        let text = render_human(&all);
        assert!(text.contains("on 1 client(s)"), "{text}");
        assert!(text.contains("aaaa             issued"), "{text}");
    }

    #[test]
    fn a_window_must_be_canonical_and_ordered() {
        assert!(Window::parse(Some("2026-10-01"), None).is_err());
        assert!(Window::parse(Some("2026-10-01T00:00:00Z"), None).is_err());
        let backwards = Window::parse(
            Some("2026-10-02T00:00:00.000Z"),
            Some("2026-10-01T00:00:00.000Z"),
        )
        .unwrap_err();
        assert_eq!(backwards.code, "CONFIG_INVARIANT");
        assert!(Window::parse(Some("2026-10-01T00:00:00.000Z"), None).is_ok());
    }
}
