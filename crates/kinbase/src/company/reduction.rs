//! The Company reduction and the log-derived rows built beside it.
//!
//! Shared by the request handlers and the view cache, so neither depends on
//! the other for how the Company log is reduced.

use super::db::CompanyDb;
use super::trust::TrustState;
use crate::error::ContractError;
use crate::model::FactEvent;
use crate::reducer::{AdmittedEvent, ReducerInput, Verification};
use serde_json::{Value, json};

/// Reduce the Company event log into the current view.
pub fn current_view(
    db: &CompanyDb,
    trust_state: &TrustState,
    as_of: &str,
) -> Result<crate::reducer::CurrentView, ContractError> {
    Ok(crate::reducer::reduce(&company_reducer_input(
        db,
        trust_state,
        as_of,
    )?))
}

/// The reducer's input for the Company log: the admitted fact events with
/// their recorded verification, lifecycle tombstones, unknowns and the trust
/// state. The view cache reads its validity window from these events.
pub(crate) fn company_reducer_input(
    db: &CompanyDb,
    trust_state: &TrustState,
    as_of: &str,
) -> Result<ReducerInput, ContractError> {
    let mut admitted = Vec::new();
    let mut tombstones = Vec::new();
    for (cursor, payload, verification) in db.events_of_kind("fact-event")? {
        let Ok(event) = FactEvent::from_value(&payload) else {
            continue;
        };
        let verification = match verification.as_str() {
            "verified" => Verification::Verified,
            "wrong-scope" => Verification::WrongScope,
            "revoked" => Verification::Revoked,
            "signature-invalid" => Verification::SignatureInvalid,
            _ => Verification::Unverified,
        };
        if let Some(action) = crate::model::action_of(&event) {
            if matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
                let targets = lifecycle_targets(db, &event);
                let (authorized, _) = lifecycle_authorized(trust_state, &event, action, &targets);
                for target in event.parents.iter().chain(event.supersedes.iter()) {
                    tombstones.push(crate::reducer::Tombstone {
                        kind: action.to_owned(),
                        target_event_id: target.clone(),
                        signer_authorized: verification == Verification::Verified && authorized,
                        reason_code: event.statement.clone(),
                        tombstone_id: event.event_id.clone(),
                    });
                }
                continue;
            }
        }
        let signer = event.signer.clone();
        admitted.push(AdmittedEvent {
            event,
            verification,
            store_cursor: cursor.to_string(),
            origin_trust: None,
            reachable: None,
            source_identity: Some(signer),
            environment_registered: None,
        });
    }
    let mut unknowns = Vec::new();
    for (_, payload, _) in db.events_of_kind("unknown-event")? {
        if let Ok(unknown) = crate::model::UnknownEvent::from_value(&payload) {
            unknowns.push(unknown);
        }
    }
    let input = ReducerInput {
        store_kind: "company".to_owned(),
        events: admitted,
        unknowns,
        tombstones,
        revocations: trust_state.observed_revocations(),
        as_of: as_of.to_owned(),
        authority_cursor: trust_state.cursor.to_string(),
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid: true,
        authority_owner_by_scope: trust_state.authority_owner_by_scope(),
        steward_authority_id: trust_state.steward_authority_id(),
    };
    Ok(input)
}

/// Resolve the events a lifecycle action names (parents and supersedes) to
/// `(event_id, logical_key, authority_scope)` from the admitted log.
pub(crate) fn lifecycle_targets(
    db: &CompanyDb,
    event: &FactEvent,
) -> Vec<(String, String, String)> {
    let named: Vec<&String> = event
        .parents
        .iter()
        .chain(event.supersedes.iter())
        .collect();
    if named.is_empty() {
        return Vec::new();
    }
    let mut targets = Vec::new();
    for (_, payload, _) in db.events_of_kind("fact-event").unwrap_or_default() {
        let event_id = crate::json::get_str(&payload, "event_id").unwrap_or_default();
        let fact_id = crate::json::get_str(&payload, "fact_id").unwrap_or_default();
        if named
            .iter()
            .any(|id| id.as_str() == event_id || id.as_str() == fact_id)
        {
            targets.push((
                event_id.to_owned(),
                crate::json::get_str(&payload, "logical_key")
                    .unwrap_or_default()
                    .to_owned(),
                crate::json::get_str(&payload, "authority_scope")
                    .unwrap_or_default()
                    .to_owned(),
            ));
        }
    }
    targets
}

/// Whether the signer of a lifecycle action holds the authority the action
/// requires. `misextraction` is an approver-owned claim about bytes versus
/// evidence, so any verified signer may issue it; `never_true` and
/// `support_withdrawn` are semantic withdrawals reserved for the Company
/// steward or the registered owner of the withdrawn fact's exact scope.
pub(crate) fn lifecycle_authorized(
    trust_state: &TrustState,
    event: &FactEvent,
    action: &str,
    targets: &[(String, String, String)],
) -> (bool, Option<String>) {
    let target_scope = targets.first().map(|(_, _, scope)| scope.clone());
    if action == "misextraction" {
        return (true, target_scope);
    }
    if trust_state.is_steward(&event.signer) {
        return (true, target_scope);
    }
    let Some(scope) = target_scope.clone() else {
        return (false, None);
    };
    let owns_scope = trust_state
        .entries_for_key(&event.signer)
        .iter()
        .any(|entry| crate::json::get_str(entry, "scope") == Some(scope.as_str()));
    (owns_scope, target_scope)
}

/// Lifecycle admissions derived from the admitted log, before any reader's
/// scope filter. Each one resolves its targets against the whole log, so the
/// view cache builds them once per change of the log, not once per read.
pub(crate) fn lifecycle_event_rows(db: &CompanyDb, trust_state: &TrustState) -> Vec<Value> {
    let mut rows = Vec::new();
    for (cursor, payload, verification) in db.events_of_kind("fact-event").unwrap_or_default() {
        let Ok(event) = FactEvent::from_value(&payload) else {
            continue;
        };
        let Some(action) = crate::model::action_of(&event) else {
            continue;
        };
        if !matches!(action, "misextraction" | "never_true" | "support_withdrawn") {
            continue;
        }
        let targets = lifecycle_targets(db, &event);
        let (authorized, target_scope) =
            lifecycle_authorized(trust_state, &event, action, &targets);
        let accepted = verification == "verified" && authorized;
        rows.push(json!({
            "action": action,
            "event_id": event.event_id,
            "cursor": cursor.to_string(),
            "authority_id": event.authority_id,
            "authority_scope": event.authority_scope,
            "logical_key": targets.first().map(|(_, key, _)| key.clone()).unwrap_or_else(|| event.logical_key.clone()),
            "target_event_ids": targets.iter().map(|(id, _, _)| id.clone()).collect::<Vec<_>>(),
            "target_scope": target_scope,
            "accepted": accepted,
            "refusal_code": if accepted { Value::Null } else { Value::String("AUTHORITY_WRONG_SCOPE".to_owned()) },
            "asserted_at": event.asserted_at,
            "reason_code": event.statement
        }));
    }
    rows
}
