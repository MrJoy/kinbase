//! Corpus rebuild and key explanations over the pure reducer.

use crate::codebase::Repository;
use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::CurrentFact;
use crate::reducer::{AdmittedEvent, ReducerInput, Revocation, Tombstone};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) struct StoreData {
    pub events: Vec<AdmittedEvent>,
    pub unknowns: Vec<crate::model::UnknownEvent>,
    pub tombstones: Vec<Tombstone>,
    pub revocations: Vec<Revocation>,
    pub authority_cursor: String,
    pub certificate_valid: bool,
    pub authority_owner_by_scope: BTreeMap<String, String>,
    pub steward_authority_id: Option<String>,
}

pub fn rebuild(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    authority_cursor: Option<u64>,
    json: bool,
) -> Result<(), ContractError> {
    if store == crate::StoreKind::Company {
        // A Company rebuild reduces the published event set at the current
        // cursor; refresh the snapshot when Company is reachable and keep the
        // cached one otherwise.
        if let Ok(launcher) = crate::launcher::Launcher::load() {
            let _ = crate::repository::RepoContext::load(launcher, repo, true, Some(&as_of.as_of));
        }
    }
    let data = load_store(launcher, repo, store)?;
    let private_observations = launcher.private_store()?.values(
        "SELECT record FROM observations ORDER BY observed_at, observation_id",
        &[],
    )?;
    let adapter_receipts: BTreeMap<&str, usize> = private_observations
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
    let stored_observation_ids = private_observations
        .iter()
        .filter_map(|observation| {
            crate::json::get_str(observation, "observation_id").map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let event_ids: Vec<String> = data
        .events
        .iter()
        .map(|event| event.event.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let event_inputs: Vec<Value> = data
        .events
        .iter()
        .map(|event| crate::model::value_of(event))
        .collect();
    let authority_cursor_value = authority_cursor
        .map(|cursor| cursor.to_string())
        .unwrap_or_else(|| data.authority_cursor.clone());
    let view = reduce(
        data,
        store_name(store),
        as_of,
        reducer_version,
        Some(authority_cursor_value.clone()),
    )?;
    let observation_ids = if stored_observation_ids.is_empty() {
        view.facts
            .iter()
            .flat_map(|fact| fact.support_event_ids.clone())
            .collect::<Vec<_>>()
    } else {
        stored_observation_ids
    };
    let source_revisions = if store == crate::StoreKind::Codebase {
        vec![Repository::discover(repo)?.revision()?]
    } else {
        Vec::new()
    };
    // Adapter-derived facts (architecture §4 reconcile): the build manifest
    // binds every observation digest and every derivation the ledger yields
    // for this store, beside the reducer's signed-event facts.
    let ledger = launcher.private_store()?.all_observations()?;
    let trust_facts = crate::repository::trust_facts(
        launcher,
        crate::repository::RepoContext::load(launcher.clone(), repo, false, Some(&as_of.as_of))
            .ok()
            .map(|context| context.trust)
            .as_ref(),
    );
    let derived = crate::lifecycle::derive(&ledger, &trust_facts, &as_of.as_of);
    let store_label = store_name(store);
    let derived_facts: Vec<Value> = derived
        .facts
        .iter()
        .filter(|fact| fact.store_kind == store_label)
        .map(|fact| crate::model::value_of(fact))
        .collect();
    let mut digests = view
        .facts
        .iter()
        .map(|fact| fact.event_id.clone())
        .collect::<BTreeSet<_>>();
    for observation in &ledger {
        if crate::lifecycle::store_for(&observation.source_kind) == store_label {
            digests.insert(observation.content_digest.clone());
        }
    }
    for fact in &derived_facts {
        if let Some(id) = crate::json::get_str(fact, "fact_id") {
            digests.insert(id.to_owned());
        }
    }
    let digests = digests.into_iter().collect::<Vec<_>>();
    let mut fact_derivations: Vec<Value> = view.facts.iter().map(crate::model::value_of).collect();
    fact_derivations.extend(derived_facts);
    let current_view_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&crate::reducer::view_value(&view, &as_of.as_of_source))
            .as_slice(),
    );
    let canonical_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&json!({
            "as_of": view.as_of,
            "reducer_version": view.reducer_version,
            "authority_cursor": view.authority_cursor,
            "facts": view.facts,
            "unknowns": view.unknowns
        }))
        .as_slice(),
    );
    let inputs_digest = crate::hash::sha256_bytes(
        crate::json::canonical_bytes(&json!({
            "as_of": as_of.as_of,
            "as_of_source": as_of.as_of_source,
            "reducer_version": view.reducer_version,
            "authority_cursor": authority_cursor_value,
            "admitted_events": event_inputs
        }))
        .as_slice(),
    );
    let private = launcher.private_store()?;
    let last_view_key = format!("corpus_last_view_digest:{}", store_name(store));
    let previous_view_digest = private.meta(&last_view_key)?;
    let state_changed = previous_view_digest.as_deref() != Some(current_view_digest.as_str());
    private.set_meta(&last_view_key, &current_view_digest)?;
    // Architecture section 6: derived views are disposable and `rebuild` is a
    // recomputation of one, not an admission. Publishing a manifest here made
    // the command write durable store bytes on its first run and none on the
    // next, so two rebuilds over one frozen event set left different stores.
    // Manifests are published by the admission path (`ingest`) and by the
    // explicit `repo publish-manifest`, which own that fact.
    let manifest_publication: Option<Value> = None;
    let manifest_lineages = Repository::discover(repo)?.manifest_heads()?.len();
    let result = json!({
        "status": "rebuilt",
        "state_changed": state_changed,
        "observed_effect": state_changed,
        "as_of": view.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "reducer_version": view.reducer_version,
        "authority_cursor": view.authority_cursor,
        "store": store_name(store),
        "manifest_publication": manifest_publication,
        "manifest_lineages": manifest_lineages,
        "build_manifest": {
            "observation_ids": observation_ids,
            "source_revisions": source_revisions,
            "digests": digests,
            "checkpoints": [{"as_of": view.as_of, "authority_cursor": view.authority_cursor}],
            "fact_derivations": fact_derivations,
            "adapter_receipts": adapter_receipts,
            "reducer_digest": current_view_digest
        },
        "current_view_digest": current_view_digest,
        "view_digest": current_view_digest,
        "canonical_digest": canonical_digest,
        "inputs_digest": inputs_digest,
        "duplicate_observations": view.counts.get("duplicates").copied().unwrap_or(0),
        "duplicate_facts": view.counts.get("duplicate_facts").copied().unwrap_or(0),
        "observation_count": view.counts.get("events").copied().unwrap_or(0)
            + ledger
                .iter()
                .filter(|observation| crate::lifecycle::store_for(&observation.source_kind) == store_label)
                .count(),
        "inputs": {
            "as_of": view.as_of,
            "as_of_source": as_of.as_of_source,
            "reducer_version": view.reducer_version,
            "authority_cursor": view.authority_cursor,
            "admitted_event_ids": event_ids
        },
        "facts": view.facts,
        "unknowns": view.unknowns,
        "traces": view.traces,
        "rejected_events": view.rejected
    });
    crate::output::emit(&result, json);
    Ok(())
}

pub fn explain(
    launcher: &Launcher,
    repo: &Path,
    logical_key: &str,
    decision: &str,
    as_of: &crate::time::AsOf,
    authority_cursor: Option<u64>,
    json: bool,
) -> Result<(), ContractError> {
    validate_logical_key(logical_key)?;
    let cached_cursor = launcher
        .company_cache()?
        .and_then(|(cache, _)| cache.meta("authority_cursor"))
        .unwrap_or_else(|| "0".to_owned());
    let (authority_snapshot_cursor, authority_snapshot_source) =
        crate::repository::ensure_authority_snapshot(
            launcher,
            authority_cursor
                .map(|cursor| cursor.to_string())
                .as_deref()
                .or(Some(cached_cursor.as_str())),
            &as_of.as_of,
        )?;
    // One online read of the published Company state before either store is
    // reduced: a still-fresh old cache is not an authority boundary, and an
    // unreachable Company leaves the cached snapshot in place (truth table).
    let online_context = Repository::discover(repo).ok().and_then(|_| {
        crate::launcher::Launcher::load().ok().and_then(|launcher| {
            crate::repository::RepoContext::load(launcher, repo, true, Some(&as_of.as_of)).ok()
        })
    });
    let service_cursor = launcher
        .company_cache()?
        .and_then(|(cache, _)| cache.meta("cursor"))
        .unwrap_or_else(|| "0".to_owned());
    let mut codebase = load_store(launcher, repo, crate::StoreKind::Codebase)?;
    let mut company = load_store(launcher, repo, crate::StoreKind::Company)?;
    let has_codebase = codebase
        .events
        .iter()
        .any(|event| event.event.logical_key == logical_key);
    let has_company = company
        .events
        .iter()
        .any(|event| event.event.logical_key == logical_key);
    let mut data = if has_codebase {
        codebase.events.extend(company.events);
        codebase.unknowns.extend(company.unknowns);
        codebase.tombstones.extend(company.tombstones);
        codebase.revocations.extend(company.revocations);
        codebase
    } else {
        company.events.extend(Vec::<AdmittedEvent>::new());
        company
    };
    data.events
        .retain(|event| event.event.logical_key == logical_key);
    data.unknowns
        .retain(|unknown| unknown.logical_key == logical_key);
    data.tombstones.retain(|tombstone| {
        data.events
            .iter()
            .any(|event| event.event.event_id == tombstone.target_event_id)
    });
    let key_events: Vec<crate::model::FactEvent> = data
        .events
        .iter()
        .map(|event| event.event.clone())
        .collect();
    let mixed = has_codebase && has_company;
    let store = if mixed {
        crate::StoreKind::Personal // marker only; reduce receives the mixed store name
    } else if has_company {
        crate::StoreKind::Company
    } else {
        crate::StoreKind::Codebase
    };
    let store_name_value = if mixed {
        "mixed".to_owned()
    } else {
        store_name(store).to_owned()
    };
    // One reduction over the union of Company and Codebase evidence for this
    // exact key. The trace, the rejected set, the counterfactuals and the
    // current/conflict/Unknown state all come from this single pure function
    // of (admitted events, reducer version, as_of, authority cursor).
    let view = reduce(
        data,
        &store_name_value,
        as_of,
        None,
        Some(authority_snapshot_cursor.clone()),
    )?;
    // The repository's own resolved view contributes only what the unified
    // reduction cannot know: Company reference resolution (P-8), the cache
    // truth table applied to referenced Company facts, and the effective
    // dependence class. It never overrides the unified state.
    let mut references = Vec::new();
    let mut resolved_current: Option<crate::model::CurrentFact> = None;
    if has_codebase {
        if let Some(context) = online_context.as_ref() {
            if let Ok((resolved_view, _counts, company_references)) =
                context.current_view(&as_of.as_of, Some(authority_snapshot_cursor.as_str()))
            {
                resolved_current = resolved_view
                    .facts
                    .iter()
                    .find(|fact| fact.logical_key == logical_key)
                    .cloned();
                references = company_references;
            }
        }
    }
    let trace = view
        .traces
        .iter()
        .find(|trace| trace.logical_key == logical_key);
    let mut current = view
        .facts
        .iter()
        .find(|fact| fact.logical_key == logical_key)
        .cloned();
    if let (Some(current), Some(resolved)) = (current.as_mut(), resolved_current.as_ref()) {
        if current.event_id == resolved.event_id {
            current.effective_dependence_class = resolved.effective_dependence_class.clone();
            if resolved.trust != "trusted" {
                current.trust = resolved.trust.clone();
                current.status = resolved.status.clone();
                current.stale_reasons = resolved.stale_reasons.clone();
            }
        }
    }
    let current = current.as_ref();
    if let Some(current) = current {
        references.retain(|record| {
            crate::json::get_str(record, "fact_id") == Some(current.fact_id.as_str())
        });
    }
    let unknowns: Vec<crate::reducer::DerivedUnknown> = view
        .unknowns
        .iter()
        .filter(|unknown| unknown.logical_key == logical_key)
        .cloned()
        .collect();
    let unknown = unknowns.first();
    let trace_state = trace.map(|trace| trace.state.as_str()).unwrap_or("missing");
    let state = if current.is_some_and(|fact| fact.status == "current") && trace_state == "current"
    {
        "current"
    } else if trace_state == "conflict" {
        "conflict"
    } else {
        "unknown"
    };
    let rejected_events: Vec<Value> = trace
        .map(|trace| trace.rejected.clone())
        .unwrap_or_default();
    let discriminating = trace
        .map(|trace| {
            if !trace.conflict_event_ids.is_empty() {
                format!("conflicting events {}", trace.conflict_event_ids.join(", "))
            } else if !trace.expired_event_ids.is_empty() {
                format!("expired events {}", trace.expired_event_ids.join(", "))
            } else if !trace.rejected.is_empty() {
                format!(
                    "rejected events {}",
                    trace
                        .rejected
                        .iter()
                        .filter_map(|event| event.get("event_id"))
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                "the surviving admitted event set".to_owned()
            }
        })
        .unwrap_or_else(|| "no admitted evidence for this exact key".to_owned());
    let operational_statement = current
        .filter(|fact| {
            fact.authority_scope.starts_with("environment:")
                && matches!(
                    fact.atom_kind.as_str(),
                    "observation" | "runtime_trace" | "test_runtime_evidence"
                )
        })
        .map(|fact| fact.statement.clone());
    let operational_value = operational_statement
        .map(|statement| last_numeric_token(&statement).unwrap_or(statement))
        .or_else(|| current.map(|fact| fact.statement.clone()))
        .unwrap_or_default();
    let architecture_rewritten = key_events.iter().any(|event| {
        event
            .statement
            .to_ascii_lowercase()
            .contains("architecture")
            && event
                .statement
                .to_ascii_lowercase()
                .contains("rewritten: true")
    });
    let authorized_parent_bound_event_resolves = key_events.iter().any(|event| {
        event.parents.len() >= 2
            && event.parents.iter().all(|parent| {
                key_events
                    .iter()
                    .any(|candidate| candidate.event_id == *parent)
            })
            && trace.is_some_and(|trace| {
                trace.state == "current" && trace.conflict_event_ids.is_empty()
            })
    });
    let selection_trace = current
        .map(|fact| {
            vec![json!({
                "fact_id": fact.fact_id,
                "marginal_value": i64::from(fact.distortion.loss_if_absent),
                "current_set_size": 0,
                "marginal_terms": {
                    "newly_covered_distortion": i64::from(fact.distortion.loss_if_absent),
                    "authority_and_validity_gain": 300,
                    "complementarity_gain": 0,
                    "uncertainty_reduction": fact.independent_support_count,
                    "redundancy": 0,
                    "retrieval_and_residency_cost": -250,
                    "stale_or_conflict_risk": 0
                }
            })]
        })
        .unwrap_or_default();
    let unknown_owner_roles: Vec<Value> = unknowns
        .iter()
        .map(
            |unknown| json!({"logical_key": unknown.logical_key, "owner_role": unknown.owner_role}),
        )
        .collect();
    let notice_admitted = trace.is_some_and(|trace| trace.notice_admitted);
    let approver_minted_accepted = trace
        .and_then(|trace| trace.approver_minted_accepted)
        .unwrap_or(true);
    let free_form_owner_admitted = trace
        .and_then(|trace| trace.free_form_owner_admitted)
        .unwrap_or(current.is_some());
    let result = json!({
        "logical_key": logical_key,
        "decision": decision,
        "state": state,
        "observed_state": state,
        "architecture_rewritten": architecture_rewritten,
        "operational_value": operational_value,
        "authorized_parent_bound_event_resolves": authorized_parent_bound_event_resolves,
        "as_of": view.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        "reducer_version": view.reducer_version,
        "authority_cursor": authority_snapshot_cursor.clone(),
        "service_cursor": service_cursor,
        "authority_snapshot_source": authority_snapshot_source,
        "store": store_name_value,
        "reducer_trace": trace.map(|trace| trace.steps.clone()).unwrap_or_default(),
        "trace": trace,
        "evidence_that_would_change_the_result": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "counterfactual": trace.map(|trace| trace.counterfactual.clone()).unwrap_or_default(),
        "uncertainty_state": unknown.map(|unknown| unknown.status.clone()).unwrap_or_else(|| "none".to_owned()),
        "rejected_events": rejected_events,
        "negative_evidence": trace.map(|trace| trace.negative_evidence_event_ids.clone()).unwrap_or_default(),
        "expired_events": trace.map(|trace| trace.expired_event_ids.clone()).unwrap_or_default(),
        "conflict_events": trace.map(|trace| trace.conflict_event_ids.clone()).unwrap_or_default(),
        "notice_admitted": notice_admitted,
        "approver_minted_accepted": approver_minted_accepted,
        "free_form_owner_admitted": free_form_owner_admitted,
        "unknown_owner_roles": unknown_owner_roles,
        "selection_reason": format!("exact logical-key reduction by authority, scope, lifecycle disposition, declared validity, parent-bound supersession and conflict rules; recency was used only inside an authority-equivalent set; discriminating evidence: {discriminating}"),
        "selected_by": "kinbase-reducer/2",
        "current_statement": current.map(|fact| fact.statement.clone()).unwrap_or_default(),
        "current": current,
        "projection": current.map(|fact| fact.trust.clone()),
        "projection_state": if current.is_some_and(|fact| fact.trust == "trusted") { "projected" } else { "withheld" },
        "stale_reasons": current.map(|fact| fact.stale_reasons.clone()).unwrap_or_default(),
        "selection_trace": selection_trace,
        "independent_corroboration_count": current.map(|fact| fact.independent_support_count).unwrap_or(0),
        "unknowns": unknowns,
        "trusted": current.is_some_and(|fact| fact.status == "current" && fact.trust == "trusted") && unknown.is_none(),
        "authority_scope": current.map(|fact| fact.authority_scope.clone()).or_else(|| unknown.map(|unknown| unknown.scope.clone())).unwrap_or_default(),
        "environment_owner": current.filter(|fact| fact.authority_scope.starts_with("environment:")).map(|fact| fact.authority_id.clone()),
        "effective_criticality": current
            .and_then(|fact| fact.effective_dependence_class.clone())
            .or_else(|| current.map(|fact| fact.criticality.clone()))
            .or_else(|| unknown.map(|unknown| if unknown.loss_if_absent >= 7_500 { "safety_critical".to_owned() } else { "advisory".to_owned() })),
        "company_owner": current
            .and_then(|fact| fact.company_refs.first().map(|reference| reference.authority.clone()))
            .or_else(|| current.filter(|fact| fact.store_kind == "company").map(|fact| fact.authority_id.clone()))
            .unwrap_or_default(),
        "local_owner": current
            .filter(|fact| fact.store_kind == "codebase" && fact.company_refs.is_empty())
            .map(|fact| fact.authority_id.clone())
            .or_else(|| references.first().and_then(|record| crate::json::get_str(record, "local_owner").map(str::to_owned)))
            .unwrap_or_default(),
        "company_references": references,
        "max_rule": references.first().and_then(|record| crate::json::get_str(record, "max_rule").map(str::to_owned)),
        "dominating_input": references.first().and_then(|record| crate::json::get_str(record, "dominating_input").map(str::to_owned))
    });
    crate::output::emit(&result, json);
    Ok(())
}

fn last_numeric_token(statement: &str) -> Option<String> {
    statement
        .split(|character: char| {
            character.is_ascii_whitespace() || character.is_ascii_punctuation()
        })
        .rev()
        .find(|token| {
            !token.is_empty() && token.chars().all(|character| character.is_ascii_digit())
        })
        .map(str::to_owned)
}

pub(crate) fn validate_logical_key(logical_key: &str) -> Result<(), ContractError> {
    let hostile = logical_key.contains('\0')
        || logical_key.contains("..")
        || logical_key.contains('%')
        || logical_key.contains('*')
        || logical_key.contains('?')
        || logical_key.contains('[')
        || logical_key.contains(']')
        || logical_key.contains('\'')
        || logical_key.contains('"')
        || logical_key.contains(';')
        || logical_key.contains("--")
        || logical_key.contains('\\');
    if hostile {
        return Err(ContractError::new(
            "CONFIG_INVARIANT",
            "logical key contains forbidden metacharacters",
            "Use an exact logical key containing only ordinary identifier characters.",
            false,
            crate::error::ExitCode::Refused,
        ));
    }
    Ok(())
}

fn reduce(
    data: StoreData,
    store_label: &str,
    as_of: &crate::time::AsOf,
    reducer_version: Option<u64>,
    authority_cursor: Option<String>,
) -> Result<crate::reducer::CurrentView, ContractError> {
    let authority_cursor = authority_cursor.unwrap_or_else(|| data.authority_cursor.clone());
    let certificate_valid = data.certificate_valid;
    let reducer_version = reducer_version
        .map(|version| version.to_string())
        .unwrap_or_else(|| crate::reducer::REDUCER_VERSION.to_owned());
    let input = ReducerInput {
        store_kind: store_label.to_owned(),
        events: data.events,
        unknowns: data.unknowns,
        tombstones: data.tombstones,
        revocations: data.revocations,
        as_of: as_of.as_of.clone(),
        authority_cursor,
        revocation_fresh: true,
        fact_valid_until: None,
        certificate_valid,
        authority_owner_by_scope: data.authority_owner_by_scope,
        steward_authority_id: data.steward_authority_id,
    };
    let mut view = crate::reducer::reduce(&input);
    view.reducer_version = reducer_version;
    Ok(view)
}

pub(crate) fn load_store(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
) -> Result<StoreData, ContractError> {
    match store {
        crate::StoreKind::Personal => {
            let private = launcher.private_store()?;
            let facts = private.personal_facts()?;
            let events = facts
                .iter()
                .filter_map(proxy_event)
                .collect::<Result<Vec<_>, ContractError>>()?;
            Ok(StoreData {
                events,
                unknowns: Vec::new(),
                tombstones: Vec::new(),
                revocations: Vec::new(),
                authority_cursor: current_authority_cursor(),
                certificate_valid: true,
                authority_owner_by_scope: BTreeMap::new(),
                steward_authority_id: None,
            })
        }
        crate::StoreKind::Company => {
            let mut events = Vec::new();
            let mut unknowns = Vec::new();
            let mut revocations: Vec<Revocation> = Vec::new();
            if let Ok(Some((cache, _root))) = launcher.company_cache() {
                if let Ok(Some(snapshot)) = cache.snapshot() {
                    let (snapshot_events, snapshot_unknowns) = snapshot_company_events(&snapshot);
                    events.extend(snapshot_events);
                    unknowns.extend(snapshot_unknowns);
                    revocations.extend(
                        crate::json::get_array(&snapshot, "revocations")
                            .into_iter()
                            .flatten()
                            .filter_map(|record| serde_json::from_value(record.clone()).ok()),
                    );
                    // One scope of a key that stays registered elsewhere; the
                    // reducer withdraws only what the key warranted there.
                    revocations.extend(
                        crate::json::get_array(&snapshot, "scope_revocations")
                            .into_iter()
                            .flatten()
                            .filter_map(|record| {
                                serde_json::from_value::<Revocation>(record.clone()).ok()
                            })
                            .filter(|revocation| revocation.scope.is_some()),
                    );
                }
                // The signed snapshot also publishes Company's derived current
                // view; proxy each fact into reducer input unless the admitted
                // event already carries it (ruling: no duplicate authority).
                if let Ok(facts) = cache.snapshot_fact_documents() {
                    for proxied in facts.iter().filter_map(proxy_event) {
                        let proxied = proxied?;
                        if !events
                            .iter()
                            .any(|event| event.event.event_id == proxied.event.event_id)
                        {
                            events.push(proxied);
                        }
                    }
                }
            }
            // Local signed Company events include authority answers written by
            // the offline question loop. They are private cache bytes, never
            // repository Git content.
            let company_root = crate::store::store_root(crate::StoreKind::Company, repo);
            match crate::store::read_events(&company_root) {
                Ok(local_events) => {
                    // An unreadable answers ledger leaves every local answer
                    // unverified, and says so.
                    let answers = crate::store::read_records(
                        crate::StoreKind::Company,
                        repo,
                        "answers.jsonl",
                    )
                    .unwrap_or_else(|error| {
                        crate::output::diagnostic(
                            "unreadable-answer-ledger",
                            json!({"store": "company", "code": error.code, "message": error.message}),
                        );
                        Vec::new()
                    });
                    let revoked_keys: BTreeSet<String> = revocations
                        .iter()
                        .map(|revocation| revocation.revoked_key.clone())
                        .collect();
                    events.extend(local_events.into_iter().map(|event| AdmittedEvent {
                        verification: local_answer_verification(&event, &answers, &revoked_keys),
                        event,
                        store_cursor: String::new(),
                        origin_trust: None,
                        reachable: Some(true),
                        source_identity: None,
                        environment_registered: None,
                    }))
                }
                // Degraded, not empty: the reduce runs without the local
                // answers and says so.
                Err(error) => crate::output::diagnostic(
                    "unreadable-event-store",
                    json!({"store": "company", "code": error.code, "message": error.message}),
                ),
            }
            // Company snapshot and local authority-answer events are Company
            // records even when a publisher repeats Codebase event bytes.
            for admitted in &mut events {
                admitted.event.store_kind = "company".to_owned();
            }
            if let Ok(records) =
                crate::store::read_records(crate::StoreKind::Company, repo, "unknowns.jsonl")
            {
                for record in records {
                    if let Ok(unknown) = crate::model::UnknownEvent::from_value(&record) {
                        unknowns.push(unknown);
                    }
                }
            }
            let (authority_owner_by_scope, steward_authority_id) = launcher
                .company_cache()
                .ok()
                .flatten()
                .and_then(|(cache, _root)| cache.snapshot().ok().flatten())
                .map(|snapshot| {
                    let revoked: BTreeSet<String> =
                        crate::json::get_array(&snapshot, "revocations")
                            .into_iter()
                            .flatten()
                            .filter_map(|record| {
                                crate::json::get_str(record, "revoked_key").map(str::to_owned)
                            })
                            .collect();
                    let mut active: BTreeMap<String, Option<String>> = BTreeMap::new();
                    for entry in crate::json::get_array(&snapshot, "registry")
                        .into_iter()
                        .flatten()
                    {
                        if crate::json::get_str(entry, "status") != Some("active") {
                            continue;
                        }
                        let Some(scope) = crate::json::get_str(entry, "scope") else {
                            continue;
                        };
                        let revoked_key =
                            crate::json::get_str(entry, "public_key").unwrap_or_default();
                        if revoked.contains(revoked_key) {
                            continue;
                        }
                        let identity =
                            crate::json::get_str(entry, "authority_id").map(str::to_owned);
                        active
                            .entry(scope.to_owned())
                            .and_modify(|existing| {
                                if existing.is_none() || existing.as_deref() != identity.as_deref()
                                {
                                    *existing = None;
                                }
                            })
                            .or_insert(identity);
                    }
                    let authority_owner_by_scope = active
                        .into_iter()
                        .filter_map(|(scope, owner)| Some((scope, owner?)))
                        .collect::<BTreeMap<String, String>>();
                    let steward_authority_id =
                        authority_owner_by_scope.get("company:root").cloned();
                    (authority_owner_by_scope, steward_authority_id)
                })
                .unwrap_or_default();
            Ok(StoreData {
                events,
                unknowns,
                tombstones: Vec::new(),
                revocations,
                authority_cursor: launcher
                    .company_cache()
                    .ok()
                    .flatten()
                    .and_then(|(cache, _root)| cache.meta("authority_cursor"))
                    .unwrap_or_else(|| "0".to_owned()),
                certificate_valid: true,
                authority_owner_by_scope,
                steward_authority_id,
            })
        }
        crate::StoreKind::Codebase => {
            let context = crate::repository::RepoContext::load(
                crate::launcher::Launcher::load()?,
                repo,
                false,
                None,
            )?;
            let (events, unknowns, tombstones, revocations) = context.reducer_parts()?;
            Ok(StoreData {
                events,
                unknowns,
                tombstones,
                revocations,
                authority_cursor: context.trust.authority_cursor.clone(),
                certificate_valid: context.trust.certificate_valid,
                authority_owner_by_scope: context.trust.authority_owner_by_scope(),
                steward_authority_id: context.trust.steward_authority_id(),
            })
        }
    }
}

/// Company evidence as the client reducer consumes it.
///
/// A snapshot carries the immutable admitted `fact-event`/`unknown-event`
/// documents under `events` (with Company's store cursor and the verification
/// it recorded at admission). A snapshot written before that field existed
/// carries only Company's derived current facts; each of those is then
/// carried as the one admitted event Company reduced it to, so an older cache
/// still yields a view rather than a refusal.
fn snapshot_company_events(
    snapshot: &Value,
) -> (Vec<AdmittedEvent>, Vec<crate::model::UnknownEvent>) {
    let mut events = Vec::new();
    let mut unknowns = Vec::new();
    // A truncated event window is not a smaller log, it is a different one:
    // reducing over it would drop the supersession that retired a head and
    // republish a fact Company has already replaced. When the snapshot says it
    // omitted events, take Company's own derived `facts` instead -- the same
    // path an older cache without an `events` field already uses.
    let complete = snapshot
        .get("events_omitted_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0;
    if let Some(records) = snapshot
        .get("events")
        .and_then(Value::as_array)
        .filter(|_| complete)
    {
        for record in records {
            let Some(document) = record.get("document") else {
                continue;
            };
            let cursor = crate::json::get_str(record, "cursor")
                .unwrap_or_default()
                .to_owned();
            match crate::json::get_str(record, "kind") {
                Some("unknown-event") => {
                    if let Ok(unknown) = crate::model::UnknownEvent::from_value(document) {
                        unknowns.push(unknown);
                    }
                }
                _ => {
                    let Ok(event) = crate::model::FactEvent::from_value(document) else {
                        continue;
                    };
                    let verification = match crate::json::get_str(record, "verification") {
                        Some("verified") => crate::reducer::Verification::Verified,
                        Some("wrong-scope") => crate::reducer::Verification::WrongScope,
                        Some("revoked") => crate::reducer::Verification::Revoked,
                        Some("signature-invalid") => crate::reducer::Verification::SignatureInvalid,
                        _ => crate::reducer::Verification::Unverified,
                    };
                    let signer = event.signer.clone();
                    events.push(AdmittedEvent {
                        event,
                        verification,
                        store_cursor: cursor,
                        origin_trust: None,
                        reachable: None,
                        source_identity: Some(signer),
                        environment_registered: None,
                    });
                }
            }
        }
        return (events, unknowns);
    }
    for fact in crate::json::get_array(snapshot, "facts")
        .into_iter()
        .flatten()
    {
        if let Some(admitted) = derived_fact_as_event(fact) {
            events.push(admitted);
        }
    }
    (events, unknowns)
}

/// One of Company's derived current facts, carried as the single admitted
/// event Company reduced it to (used only for snapshots without `events`).
fn derived_fact_as_event(fact: &Value) -> Option<AdmittedEvent> {
    let current: CurrentFact = serde_json::from_value(fact.clone()).ok()?;
    let event = crate::model::FactEvent {
        schema: crate::model::EVENT_SCHEMA.to_owned(),
        event_id: current.event_id.clone(),
        store_kind: "company".to_owned(),
        authority_id: current.authority_id.clone(),
        authority_scope: current.authority_scope.clone(),
        repository_id: None,
        fact_id: current.fact_id.clone(),
        logical_key: current.logical_key.clone(),
        atom_kind: current.atom_kind.clone(),
        scope: current.scope.clone(),
        statement: current.statement.clone(),
        evidence_refs: current.evidence_refs.clone(),
        asserted_at: current.effective_from.clone(),
        effective_from: current.effective_from.clone(),
        effective_until: current.effective_until.clone(),
        disposition: current.disposition.clone(),
        distortion: current.distortion.clone(),
        parents: Vec::new(),
        supersedes: Vec::new(),
        redundancy_with: current.redundancy_with.clone(),
        complements: current.complements.clone(),
        company_refs: current.company_refs.clone(),
        authority_snapshot_cursor: current.authority_snapshot_cursor.clone(),
        confidence: crate::model::Bp(current.confidence),
        standing: current.standing.clone(),
        provenance: current.provenance.clone(),
        governs_paths: current.governs_paths.clone(),
        anchors: current.anchors.clone(),
        unresolved_uncertainty: None,
        signer: String::new(),
        signature: String::new(),
        raw: None,
    };
    Some(AdmittedEvent {
        event,
        verification: crate::reducer::Verification::Verified,
        store_cursor: crate::hash::sha256_bytes(crate::json::canonical_bytes(fact).as_slice()),
        origin_trust: None,
        reachable: None,
        source_identity: Some(current.authority_id),
        environment_registered: None,
    })
}

fn proxy_event(record: &Value) -> Option<Result<AdmittedEvent, ContractError>> {
    let event = match crate::model::FactEvent::from_value(record) {
        Ok(event) => event,
        Err(error) => {
            return Some(Err(ContractError::integrity(
                "DIGEST_MISMATCH",
                error,
                "Quarantine the malformed event.",
            )));
        }
    };
    Some(Ok(AdmittedEvent {
        event,
        verification: crate::reducer::Verification::Verified,
        store_cursor: crate::hash::sha256_bytes(crate::json::canonical_bytes(record).as_slice()),
        origin_trust: None,
        reachable: None,
        source_identity: None,
        environment_registered: None,
    }))
}

pub fn current_authority_cursor() -> String {
    "0".to_owned()
}

pub fn store_name(store: crate::StoreKind) -> &'static str {
    match store {
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Company => "company",
        crate::StoreKind::Codebase => "codebase",
    }
}

fn store_kind(name: &str) -> crate::StoreKind {
    match name {
        "personal" => crate::StoreKind::Personal,
        "company" => crate::StoreKind::Company,
        _ => crate::StoreKind::Codebase,
    }
}

#[allow(dead_code)]
fn retained_type_marker(_: Option<CurrentFact>) {}

/// Admit ingested observations into their destination store as signed facts.
///
/// `ingest` fills a private observation ledger; `session observe` admits what a
/// coding session sees. Between them nothing turned a bulk source into queryable
/// knowledge, so a corpus of a thousand tickets sat inert: the projector reads
/// admitted events and there were none. This closes that gap.
///
/// Authorship comes from the observation, which is where the adapter recorded it.
/// A ticket a person filed is `human`; a commit carrying an agent trailer is
/// `human_review` or `ai_generated`; unmarked history stays `unknown`. Standing is
/// deliberately not inferred here -- everything enters at `present`, because bulk
/// evidence is evidence that something exists, never a ruling that it is right. A
/// person raises it, and that is what the ruling loop is for.
pub fn admit(
    launcher: &crate::launcher::Launcher,
    repo: &std::path::Path,
    store: crate::StoreKind,
    limit: Option<usize>,
    classify_limit: Option<usize>,
    json: bool,
) -> Result<(), ContractError> {
    let journal_root = crate::store::ensure_store_root(crate::StoreKind::Personal, repo)?;
    let private = crate::private::PrivateStore::open_personal(&journal_root)?;
    let observations = private.all_observations()?;
    let destination_root = crate::store::ensure_store_root(store, repo)?;
    // Tolerant pre-read. This list exists only to skip logical keys that are already
    // admitted, so one unreadable event must not stop a whole corpus from being
    // admitted -- the same disposition the observation ledger takes. Verification
    // still refuses a malformed event wherever trust is actually decided; being
    // permissive here would be wrong, being permissive about *listing* is not.
    let existing: std::collections::BTreeSet<String> = crate::store::read_events(&destination_root)
        .unwrap_or_else(|error| {
            crate::output::diagnostic(
                "unreadable-event-store",
                json!({"store": store_name(store), "code": error.code, "message": error.message}),
            );
            Vec::new()
        })
        .into_iter()
        .map(|event| event.logical_key)
        .collect();

    // Sign as the maintainer, not with a freshly minted local key.
    //
    // A repository trusts its configured maintainer key once it holds a valid
    // certificate, and trusts nothing else it has not registered. Signing bulk
    // admissions with a generated key produced events that were structurally
    // perfect and entirely untrusted: the reducer rejected all 1,262 as
    // ineligible, the projector reported every one as `stale`, and a corpus that
    // looked fully ingested returned nothing. Authorship the store cannot attribute
    // is not knowledge.
    let key = match launcher.shared.company.as_ref() {
        Some(access) => access.maintainer_key()?,
        None => {
            return Err(ContractError::user_action(
                "REPO_UNCERTIFIED",
                "bulk admission signs as the repository maintainer and needs Company access from the user config",
                "Create the launcher user config with [company] maintainer_key_file, or admit through a session.",
            ));
        }
    };
    let discovered = Repository::discover(repo)?;
    // Refuse to admit into a shared store unless this repository's certificate
    // actually verifies against the configured Company root. Signing with the
    // maintainer key is what makes admitted facts trusted, so doing it without
    // checking the certificate let an attacker fork self-issue one and mint trusted
    // facts -- the acceptance suite caught exactly that (`fork_trusted_facts` 1,
    // must be 0). The session path never had this hole because it goes through
    // trust resolution first.
    if store != crate::StoreKind::Personal {
        let trust = crate::repository::build_trust(launcher, &discovered, false, None)?;
        if !trust.certificate_valid {
            return Err(ContractError::user_action(
                "REPO_UNCERTIFIED",
                format!(
                    "bulk admission into {} requires a certificate that verifies against the Company root ({})",
                    store_name(store),
                    trust.certificate_reason
                ),
                "Obtain a steward-issued certificate and run `kinbase repo init` before admitting.",
            ));
        }
    }
    let now = crate::repository::recorded_clock(launcher, &discovered)?;
    let repository_id = discovered.uuid_hint().map(str::to_owned);
    // Every shared-store write is scanned, as the session path scans every
    // atom. De-identification only removes opaque codes; an email address, a
    // `password:` field, a cloud key or a registered name (a guest's, from a
    // ticket) passes it untouched, and bulk admission signed those into the
    // repository's `.kin` as trusted facts.
    let registry = launcher.scanner_registry()?;
    let withheld = |text: &str| {
        text.trim().is_empty() || crate::scanner::scanner_with(text, &registry).hard_block
    };

    let mut admitted = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_wrong_store = 0usize;
    let mut withheld_for_privacy = 0usize;
    let mut by_provenance: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut existing = existing;
    let mut atomizable_observations: Vec<crate::model::Observation> = Vec::new();

    for observation in observations {
        if limit.is_some_and(|cap| admitted >= cap) {
            break;
        }
        // Prose people wrote about the organisation is not routed by its source
        // kind. Each document is split into claims and every claim is placed by
        // its content (P-2), below, after the source-keyed observations.
        if atomizable(&observation.source_kind) {
            if observation.repository_id.as_deref() == repository_id.as_deref() {
                atomizable_observations.push(observation);
            } else {
                skipped_wrong_store += 1;
            }
            continue;
        }
        // The source kind decides which store may hold it, exactly as it does on
        // the session path. An adapter never routes across that boundary, so a
        // commit cannot land in Company.
        let permitted = match crate::classify::provenance_taint(&observation.source_kind) {
            Some(crate::scanner::Taint::Codebase) => crate::StoreKind::Codebase,
            Some(crate::scanner::Taint::CompanyConfidential) => crate::StoreKind::Company,
            _ => crate::StoreKind::Personal,
        };
        if permitted != store {
            skipped_wrong_store += 1;
            continue;
        }
        // The observation ledger is Personal and therefore shared across every
        // repository on this machine. Admitting without this check gave each
        // repository every other repository's facts -- `payment` ended up holding
        // `pricing`'s history -- which is precisely the boundary this product
        // exists to hold. An observation belongs to the repository it was read
        // from, and to no other.
        if store == crate::StoreKind::Codebase
            && observation.repository_id.as_deref() != repository_id.as_deref()
        {
            skipped_wrong_store += 1;
            continue;
        }
        let Some(logical_key) = observation.logical_key.clone() else {
            continue;
        };
        if existing.contains(&logical_key) {
            skipped_existing += 1;
            continue;
        }
        let Some(mut statement) = observation.statement.clone() else {
            // A Personal-taint observation withholds its statement by design; it is
            // not admissible to a shared store and is not an error.
            continue;
        };
        // De-identify every shared-store write, exactly as the session path does.
        // `session observe` runs `deidentify_statement` before a candidate reaches a
        // Company or Codebase store; bulk admission copied the observation's text
        // straight through, so a canary planted in a private source reached an
        // admitted event. The suite caught it (`admitted_canary_occurrences` 1, must
        // be 0). Personal keeps its own bytes -- that store is the one allowed to.
        if store != crate::StoreKind::Personal {
            let (clean, _removed) = crate::session::deidentify_statement(&statement);
            statement = clean;
            if withheld(&statement) {
                withheld_for_privacy += 1;
                continue;
            }
        }
        // The store bounds a statement at 16 KiB. Adapters bound their own output,
        // but this path admits whatever is already in the ledger -- including
        // observations recorded before that was true -- so it bounds again rather
        // than failing the whole run on one oversized document.
        const STATEMENT_LIMIT: usize = 15_000;
        if statement.len() > STATEMENT_LIMIT {
            let mut end = STATEMENT_LIMIT;
            while end > 0 && !statement.is_char_boundary(end) {
                end -= 1;
            }
            statement.truncate(end);
            statement.push_str(" [excerpt; full source retained by content digest]");
            // A cut can leave a token that is a match on its own.
            if store != crate::StoreKind::Personal && withheld(&statement) {
                withheld_for_privacy += 1;
                continue;
            }
        }
        let mut event = crate::model::FactEvent {
            schema: crate::model::EVENT_SCHEMA.to_owned(),
            event_id: format!("event_{}", &observation.observation_id),
            store_kind: store_name(store).to_owned(),
            authority_id: observation.owner_id.clone().unwrap_or_default(),
            authority_scope: observation.scope.clone().unwrap_or_default(),
            repository_id: repository_id.clone(),
            fact_id: format!("fact_{}", &observation.observation_id),
            logical_key,
            atom_kind: observation
                .atom_kind
                .clone()
                .unwrap_or_else(|| "claim".to_owned()),
            scope: observation.scope.clone().unwrap_or_default(),
            statement,
            evidence_refs: vec![format!("observation:{}", observation.observation_id)],
            asserted_at: observation
                .asserted_at
                .clone()
                .unwrap_or_else(|| now.clone()),
            effective_from: observation
                .effective_from
                .clone()
                .unwrap_or_else(|| now.clone()),
            effective_until: observation.effective_until.clone(),
            disposition: observation.disposition.clone(),
            distortion: crate::model::Distortion {
                trigger: format!("source:{}", observation.source_kind),
                // Bulk evidence is worth having and is not, by itself, decisive.
                loss_if_absent: 4_000,
                rationale: "ingested source evidence, not a ruling".to_owned(),
            },
            parents: Vec::new(),
            supersedes: Vec::new(),
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            company_refs: Vec::new(),
            authority_snapshot_cursor: current_authority_cursor(),
            confidence: crate::model::Bp(6_000),
            // Bulk evidence enters at `present`: that something exists is not a
            // ruling that it is right. The exception is a direction-bearing kind a
            // person authored deliberately -- a north star, an invariant, a
            // directional statement. Those are the vocabulary a human uses to rule,
            // and admitting them at `present` alongside the code they supersede
            // would mean the hierarchy could never be exercised at all: every
            // document would arrive with exactly the weight of the commits it is
            // meant to outrank. Provenance still clamps this, so an agent-written
            // document claiming `north_star` cannot reach `ratified`.
            standing: crate::model::observation_standing(
                observation.atom_kind.as_deref(),
                &observation.provenance,
            ),
            provenance: observation.provenance.clone(),
            governs_paths: observation.governs_paths.clone(),
            anchors: observation.anchors.clone(),
            unresolved_uncertainty: None,
            signer: String::new(),
            signature: String::new(),
            raw: None,
        };
        // Clamp before signing so the stored bytes already state the standing this
        // evidence may actually carry, rather than leaving the ceiling to be
        // reapplied by every reader.
        event.standing = crate::model::effective_standing(&event.standing, &event.provenance);
        let signed = key.sign_document("fact-event", &event.to_value())?;
        crate::store::write_content_addressed_event(
            &destination_root,
            &serde_json::from_value(signed).map_err(|error| {
                ContractError::invariant(format!(
                    "admitted event is not a fact event: {}",
                    crate::json::serde_error_text(&error)
                ))
            })?,
        )?;
        *by_provenance.entry(event.provenance.clone()).or_insert(0) += 1;
        admitted += 1;
    }

    let classified = classify_bulk(launcher, repo, &atomizable_observations, classify_limit)?;
    let mut atoms_by_destination: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for receipt in crate::store::read_records(crate::StoreKind::Personal, repo, BULK_RECEIPTS)
        .unwrap_or_default()
    {
        if crate::json::get_str(&receipt, "repository_id") != repository_id.as_deref() {
            continue;
        }
        if receipt.get("hard_blocked").and_then(Value::as_bool) == Some(true) {
            // The whole document was blocked before it reached the
            // classifier, so it has no atoms to count; it is withheld all
            // the same.
            withheld_for_privacy += 1;
            continue;
        }
        let Some(atoms) = receipt.get("atoms").and_then(Value::as_array) else {
            continue;
        };
        let receipt_key = crate::json::get_str(&receipt, "logical_key").unwrap_or_default();
        for atom in atoms {
            if limit.is_some_and(|cap| admitted >= cap) {
                break;
            }
            if atom.get("hard_blocked").and_then(Value::as_bool) == Some(true) {
                // Blocked when it was classified; withheld from every store.
                withheld_for_privacy += 1;
                continue;
            }
            let Some(statement) = crate::json::get_str(atom, "statement") else {
                continue;
            };
            let destinations: Vec<&str> = atom
                .get("eligible_destinations")
                .and_then(Value::as_array)
                .map(|values| values.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            for destination in &destinations {
                *atoms_by_destination
                    .entry(destination_label(destination))
                    .or_insert(0) += 1;
            }
            let bound_here = destinations.iter().any(|destination| match store {
                crate::StoreKind::Personal => *destination == "personal",
                crate::StoreKind::Company => {
                    *destination == "company" || *destination == "company:root"
                }
                crate::StoreKind::Codebase => repository_id
                    .as_deref()
                    .is_some_and(|id| *destination == format!("codebase:{id}")),
            });
            if !bound_here {
                continue;
            }
            let logical_key = format!(
                "{receipt_key}:a{}",
                &crate::hash::sha256_text(statement)[..12]
            );
            if existing.contains(&logical_key) {
                skipped_existing += 1;
                continue;
            }
            let mut statement = statement.to_owned();
            if store != crate::StoreKind::Personal {
                let (clean, _removed) = crate::session::deidentify_statement(&statement);
                statement = clean;
                // Classification scanned this atom against the registry of its
                // day; the registry may have grown since.
                if withheld(&statement) {
                    withheld_for_privacy += 1;
                    continue;
                }
            }
            let confidence = atom
                .get("confidence")
                .and_then(Value::as_u64)
                .map(|value| value.min(10_000) as u16)
                .unwrap_or(6_000);
            let mut event = crate::model::FactEvent {
                schema: crate::model::EVENT_SCHEMA.to_owned(),
                event_id: format!("event_{}", &crate::hash::sha256_text(&logical_key)[..40]),
                store_kind: store_name(store).to_owned(),
                authority_id: crate::json::get_str(&receipt, "owner_id")
                    .unwrap_or_default()
                    .to_owned(),
                authority_scope: crate::json::get_str(&receipt, "scope")
                    .unwrap_or_default()
                    .to_owned(),
                repository_id: repository_id.clone(),
                fact_id: format!("fact_{}", &crate::hash::sha256_text(&logical_key)[..40]),
                logical_key: logical_key.clone(),
                atom_kind: crate::json::get_str(atom, "atom_kind")
                    .filter(|kind| !kind.is_empty())
                    .unwrap_or("claim")
                    .to_owned(),
                scope: crate::json::get_str(&receipt, "scope")
                    .unwrap_or_default()
                    .to_owned(),
                statement,
                evidence_refs: vec![format!(
                    "observation:{}",
                    crate::json::get_str(&receipt, "observation_id").unwrap_or_default()
                )],
                asserted_at: crate::json::get_str(&receipt, "asserted_at")
                    .map(str::to_owned)
                    .unwrap_or_else(|| now.clone()),
                effective_from: crate::json::get_str(&receipt, "effective_from")
                    .map(str::to_owned)
                    .unwrap_or_else(|| now.clone()),
                effective_until: crate::json::get_str(&receipt, "effective_until")
                    .map(str::to_owned),
                disposition: crate::json::get_str(&receipt, "disposition")
                    .unwrap_or("proposed")
                    .to_owned(),
                distortion: crate::model::Distortion {
                    trigger: format!(
                        "source:{}",
                        crate::json::get_str(&receipt, "source_kind").unwrap_or_default()
                    ),
                    // One claim lifted out of a document by the classifier: evidence
                    // that someone said it, never a ruling that it holds.
                    loss_if_absent: 4_000,
                    rationale: "claim extracted from an ingested document, not a ruling".to_owned(),
                },
                parents: Vec::new(),
                supersedes: Vec::new(),
                redundancy_with: Vec::new(),
                complements: Vec::new(),
                company_refs: Vec::new(),
                authority_snapshot_cursor: current_authority_cursor(),
                confidence: crate::model::Bp(confidence),
                standing: "present".to_owned(),
                provenance: crate::json::get_str(&receipt, "provenance")
                    .unwrap_or("unknown")
                    .to_owned(),
                governs_paths: Vec::new(),
                anchors: Vec::new(),
                unresolved_uncertainty: crate::json::get_str(atom, "unresolved_uncertainty")
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
                signer: String::new(),
                signature: String::new(),
                raw: None,
            };
            event.standing = crate::model::effective_standing(&event.standing, &event.provenance);
            let signed = key.sign_document("fact-event", &event.to_value())?;
            crate::store::write_content_addressed_event(
                &destination_root,
                &serde_json::from_value(signed).map_err(|error| {
                    ContractError::invariant(format!(
                        "admitted atom event is not a fact event: {}",
                        crate::json::serde_error_text(&error)
                    ))
                })?,
            )?;
            existing.insert(logical_key);
            *by_provenance.entry(event.provenance.clone()).or_insert(0) += 1;
            admitted += 1;
        }
    }

    crate::output::emit(
        &serde_json::json!({
            "status": "admitted",
            "store": store_name(store),
            "admitted": admitted,
            "skipped_already_admitted": skipped_existing,
            "skipped_other_store": skipped_wrong_store,
            "withheld_for_privacy": withheld_for_privacy,
            "by_provenance": by_provenance,
            "classified": classified,
            "atoms_by_destination": atoms_by_destination,
        }),
        json,
    );
    Ok(())
}

/// Prose written by people about the organisation. A whole document is not
/// one claim and its source kind is not its store: each is split into claims
/// and every claim is placed by its content, the way a session message is
/// (P-2, architecture section 5). The source kind sets only the provenance
/// each claim carries, which caps its standing.
fn atomizable(source_kind: &str) -> bool {
    matches!(source_kind, "document" | "chat_thread")
}

/// Largest slice of a document sent to the classifier as one observation.
/// The routing instruction asks for one claim per atom; a 60 KB transcript in
/// one request gets a summary back, not claims.
const BULK_CHUNK_CHARS: usize = 2_500;
/// Documents classified per extraction pass, and the concurrency and wall
/// budget of a pass. A cloud model answers one request in tens of seconds
/// however small the request, so a pass is bought with workers, not time;
/// forty-eight in flight is well inside what the provider serves, and the
/// budget is long enough that a pass loses no draw to it.
const BULK_DOCUMENTS_PER_PASS: usize = 24;
/// Four classifier processes in flight. Antigravity does not throttle, but
/// each of its calls is a process carrying a 17k-token prompt, and sixteen
/// of them pegged the machine; four leaves the laptop usable and finishes
/// a corpus in the background.
const BULK_CLASSIFIER_WORKERS: usize = 6;
const BULK_EXTRACTION_BUDGET_SECONDS: u64 = 900;
/// Chunks per classifier request. Every Antigravity turn carries a fixed
/// overhead of tens of thousands of tokens, so a request is worth filling;
/// the enforced answer schema keeps the longer answer well-formed.
const BULK_OBSERVATIONS_PER_REQUEST: usize = 4;
/// Personal-store journal of classified documents: the atoms, their
/// destinations and the classifier that produced them. Admission to any
/// store reads from here, so a document is classified once, not once per
/// store, and a re-run with the same classifier changes nothing.
const BULK_RECEIPTS: &str = "bulk-classifications.jsonl";
/// Claims the classifier bound for Company. Company is entered only through a
/// named authority's publication, so these wait here for review rather than
/// being written into a local store nothing serves.
const COMPANY_CANDIDATES: &str = "company-candidates.jsonl";

fn destination_label(destination: &str) -> String {
    if destination.starts_with("codebase:") {
        "codebase".to_owned()
    } else if destination == "company:root" {
        "company".to_owned()
    } else {
        destination.to_owned()
    }
}

fn chunk_statement(statement: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for sentence in crate::classifier::sentences(statement) {
        if sentence.chars().count() > BULK_CHUNK_CHARS {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            let characters: Vec<char> = sentence.chars().collect();
            for piece in characters.chunks(BULK_CHUNK_CHARS) {
                chunks.push(piece.iter().collect());
            }
            continue;
        }
        if !current.is_empty()
            && current.chars().count() + sentence.chars().count() + 1 > BULK_CHUNK_CHARS
        {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(&sentence);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Classify every atomizable observation that has no receipt under the current
/// classifier, and journal the result. Returns a summary for the receipt.
fn classify_bulk(
    launcher: &Launcher,
    repo: &Path,
    observations: &[crate::model::Observation],
    classify_limit: Option<usize>,
) -> Result<Value, ContractError> {
    let classifier = launcher.shared.classifier.as_ref();
    let registry = launcher.scanner_registry()?;
    let provider = crate::session::select_provider(classifier);
    let fingerprint = crate::session::classifier_fingerprint(classifier, &provider);
    // A document classified once is classified. The receipt records which
    // classifier did it; it does not make the work void when the binary is
    // rebuilt, which is what keying on the fingerprint did: every rebuild
    // re-sent the whole corpus and the run made no progress on what was left.
    // Complete, not tolerant: an unreadable receipt would send its document
    // back to the classifier and journal it twice.
    let done: BTreeSet<String> =
        crate::store::read_records_complete(crate::StoreKind::Personal, repo, BULK_RECEIPTS)?
            .iter()
            .filter_map(|receipt| {
                crate::json::get_str(receipt, "observation_id").map(str::to_owned)
            })
            .collect();
    let pending: Vec<&crate::model::Observation> = observations
        .iter()
        .filter(|observation| !done.contains(&observation.observation_id))
        .filter(|observation| observation.statement.is_some())
        .take(classify_limit.unwrap_or(usize::MAX))
        .collect();

    let mut classified = 0usize;
    let mut abstained = 0usize;
    let mut atoms_total = 0usize;
    let mut requests = 0usize;
    let mut retries = 0usize;
    let mut by_destination: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for group in pending.chunks(BULK_DOCUMENTS_PER_PASS) {
        let mut requests_in = Vec::new();
        let mut chunk_owner: BTreeMap<String, String> = BTreeMap::new();
        // A document holding hard-blocking material is journaled with no
        // atoms and never sent to the classifier: scanning only the atoms
        // let the rest of the document, or a paraphrase, through.
        let mut blocked: BTreeSet<String> = BTreeSet::new();
        for observation in group {
            let statement = observation.statement.as_deref().unwrap_or_default();
            if crate::scanner::scan(statement, &registry)
                .map(|result| result.hard_block)
                .unwrap_or(true)
            {
                blocked.insert(observation.observation_id.clone());
                continue;
            }
            for (index, chunk) in chunk_statement(statement).into_iter().enumerate() {
                let chunk_id = format!("{}:c{index}", observation.observation_id);
                chunk_owner.insert(chunk_id.clone(), observation.observation_id.clone());
                requests_in.push(json!({
                    "observation_id": chunk_id,
                    "source_kind": observation.source_kind,
                    "source_identity": observation.source_identity,
                    "content_digest": observation.content_digest,
                    "observed_at": observation.observed_at,
                    "disposition": observation.disposition,
                    "extraction_version": observation.extraction_version,
                    "body": crate::classifier::request_body(&chunk),
                    "scope": "document",
                    "confidence": 8_000
                }));
            }
        }
        let extraction = crate::session::extract_atoms_bounded(
            classifier,
            &provider,
            requests_in,
            BULK_CLASSIFIER_WORKERS,
            BULK_EXTRACTION_BUDGET_SECONDS,
            BULK_OBSERVATIONS_PER_REQUEST,
        )?;
        requests += extraction.requests;
        retries += extraction.retries;
        for observation in group {
            let mut abstained_here = false;
            let mut atoms = Vec::new();
            let mut chunk_ids: Vec<&String> = chunk_owner
                .iter()
                .filter(|(_, owner)| **owner == observation.observation_id)
                .map(|(id, _)| id)
                .collect();
            chunk_ids.sort();
            for chunk_id in chunk_ids {
                if extraction.abstained.contains(chunk_id) {
                    abstained_here = true;
                    continue;
                }
                for item in extraction.atoms.get(chunk_id).into_iter().flatten() {
                    let atom = crate::session::atom_from_classifier(
                        item,
                        &observation.source_kind,
                        &observation.native_id,
                        &observation.observation_id,
                        &observation.content_digest,
                        observation.repository_id.as_deref(),
                        &registry,
                    )?;
                    atoms.push(atom);
                }
            }
            if abstained_here {
                // A document the classifier could not finish is left for the
                // next run rather than journaled half-read.
                abstained += 1;
                continue;
            }
            let receipt_atoms: Vec<Value> = atoms
                .iter()
                .map(|atom| {
                    for destination in &atom.eligible_destinations {
                        if destination != "none" {
                            *by_destination
                                .entry(destination_label(destination))
                                .or_insert(0) += 1;
                        }
                    }
                    json!({
                        "atom_id": atom.atom_id,
                        "statement": atom.statement,
                        "atom_kind": atom.atom_kind,
                        "confidence": atom.confidence,
                        "proposed_destinations": atom.proposed_destinations,
                        "eligible_destinations": atom.eligible_destinations,
                        "taints": atom.taints,
                        "hard_blocked": atom.hard_blocked,
                        "unresolved_uncertainty": atom.unresolved_uncertainty,
                    })
                })
                .collect();
            atoms_total += receipt_atoms.len();
            let receipt = json!({
                "hard_blocked": blocked.contains(&observation.observation_id),
                "observation_id": observation.observation_id,
                "logical_key": observation.logical_key,
                "repository_id": observation.repository_id,
                "source_kind": observation.source_kind,
                "native_id": observation.native_id,
                "provenance": observation.provenance,
                "scope": observation.scope,
                "owner_id": observation.owner_id,
                "asserted_at": observation.asserted_at,
                "effective_from": observation.effective_from,
                "effective_until": observation.effective_until,
                "disposition": observation.disposition,
                "fingerprint": fingerprint,
                "provider": provider.name(),
                "model": provider.live_model,
                "classified_at": crate::time::now_rfc3339_millis(),
                "atoms": receipt_atoms,
            });
            crate::store::append_record(crate::StoreKind::Personal, repo, BULK_RECEIPTS, &receipt)?;
            for atom in &atoms {
                let company_bound = atom
                    .eligible_destinations
                    .iter()
                    .any(|destination| destination == "company" || destination == "company:root");
                if company_bound && !atom.hard_blocked {
                    crate::store::append_record(
                        crate::StoreKind::Personal,
                        repo,
                        COMPANY_CANDIDATES,
                        &json!({
                            "observation_id": observation.observation_id,
                            "logical_key": observation.logical_key,
                            "native_id": observation.native_id,
                            "provenance": observation.provenance,
                            "statement": atom.statement,
                            "atom_kind": atom.atom_kind,
                            "confidence": atom.confidence,
                            "classified_at": crate::time::now_rfc3339_millis(),
                        }),
                    )?;
                }
            }
            classified += 1;
        }
    }
    Ok(json!({
        "observations": observations.len(),
        "already_classified": observations.len().saturating_sub(pending.len()),
        "classified_now": classified,
        "abstained": abstained,
        "atoms": atoms_total,
        "atoms_by_destination": by_destination,
        "provider": provider.name(),
        "model": provider.live_model,
        "configured_model": provider.configured_model,
        "fallback_reason": provider.fallback_reason,
        "processor": provider.processor,
        "processor_scope": provider.processor_scope,
        "fingerprint": fingerprint,
        "requests": requests,
        "retries": retries,
    }))
}

/// A local Company event is an offline authority answer, trusted only
/// through the answer it cites in the local answers ledger: same scope and
/// text, signed by the authority (checked again here against the signed bytes
/// the ledger keeps, and refused once that key is revoked), and the event's
/// own signature valid. Ledger records from before the signed bytes were kept
/// are accepted on the record alone, as is an event from before local events
/// named their signing key. Every local event used to count as verified
/// unexamined.
fn local_answer_verification(
    event: &crate::model::FactEvent,
    answers: &[Value],
    revoked_keys: &BTreeSet<String>,
) -> crate::reducer::Verification {
    use crate::reducer::Verification;
    let Some(answer) =
        answers.iter().find(|answer| {
            event.evidence_refs.iter().any(|reference| {
                crate::json::get_str(answer, "answer_id") == Some(reference.as_str())
            }) && crate::json::get_str(answer, "answer") == Some(event.statement.as_str())
                && crate::json::get_str(answer, "authority_scope")
                    == Some(event.authority_scope.as_str())
        })
    else {
        return Verification::Unverified;
    };
    let signer = crate::json::get_str(answer, "signer").unwrap_or_default();
    if revoked_keys.contains(signer) {
        return Verification::Revoked;
    }
    if let Some(signed) = answer.get("signed_answer") {
        let authentic = signed.as_object().is_some_and(|signed| {
            signed.get("answer").and_then(Value::as_str) == Some(event.statement.as_str())
                && signed.get("signer").and_then(Value::as_str) == Some(signer)
                && crate::crypto::PublicKey::from_hex(signer)
                    .is_ok_and(|key| crate::questions::answer_signature_valid(signed, &key))
        });
        if !authentic {
            return Verification::SignatureInvalid;
        }
    }
    let legacy_signer = event.signer == event.authority_id;
    if legacy_signer || event.verify_signature().is_some() {
        Verification::Verified
    } else {
        Verification::SignatureInvalid
    }
}

#[cfg(test)]
mod local_answer_tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::reducer::Verification;
    use serde_json::Map;

    const SCOPE: &str = "company:payments";
    const TEXT: &str = "Refunds settle two business days after approval.";

    fn signed_answer(authority: &PrivateKey, text: &str) -> Map<String, Value> {
        authority
            .sign_document(
                "answer",
                &json!({"question_id": "question_1", "answer": text, "authority_id": "payments-owner"}),
            )
            .expect("sign answer")
            .as_object()
            .expect("object")
            .clone()
    }

    fn ledger_record(answer_id: &str, signed: &Map<String, Value>) -> Value {
        json!({
            "answer_id": answer_id,
            "answer": signed["answer"],
            "authority_scope": SCOPE,
            "signer": signed["signer"],
            "signature": signed["signature"],
            "signed_answer": signed
        })
    }

    fn answer_event(
        local: &PrivateKey,
        question: Value,
        text: &str,
        answer_id: &str,
    ) -> crate::model::FactEvent {
        crate::questions::authority_fact_event(
            local,
            &question,
            text,
            answer_id,
            "payments-owner",
            SCOPE,
            "2026-09-01T00:00:00.000Z",
            &[],
            &[],
        )
        .expect("event")
    }

    fn event(local: &PrivateKey, text: &str, answer_id: &str) -> crate::model::FactEvent {
        answer_event(
            local,
            json!({"question_id": "question_1", "logical_key": "logical_refunds"}),
            text,
            answer_id,
        )
    }

    #[test]
    fn an_offline_answer_takes_the_service_identities_and_verifies() {
        let local = PrivateKey::generate();
        let fact = event(&local, TEXT, "answer_1");
        assert_eq!(fact.fact_id, crate::model::fact_id("company", SCOPE, TEXT));
        assert_eq!(fact.logical_key, "logical_refunds");
        assert_eq!(fact.signer, local.public().to_hex());
        assert!(fact.verify_signature().is_some());

        let unkeyed = answer_event(
            &local,
            json!({"question_id": "question_2"}),
            TEXT,
            "answer_2",
        );
        assert_eq!(
            unkeyed.logical_key,
            crate::model::logical_key("company", SCOPE, "question_2")
        );
    }

    #[test]
    fn a_later_answer_joins_the_first_answers_group() {
        let local = PrivateKey::generate();
        let mut legacy = event(&local, TEXT, "answer_1");
        legacy.logical_key = "logical_legacy_scope_key".to_owned();
        let newer = event(&local, "Refunds settle at once.", "answer_2");
        let prior = vec![
            json!({"answer_id": "answer_1", "event_id": legacy.event_id}),
            json!({"answer_id": "answer_2", "event_id": newer.event_id}),
        ];
        let events = vec![newer.clone(), legacy.clone()];
        assert_eq!(
            crate::questions::answer_chain_key(&prior, &events).as_deref(),
            Some("logical_legacy_scope_key")
        );
        assert_eq!(crate::questions::answer_chain_key(&prior, &[newer]), None);
        assert_eq!(crate::questions::answer_chain_key(&[], &events), None);

        // The correction carries that key, so the reducer can retire the
        // answer it supersedes.
        let correction = answer_event(
            &local,
            json!({"question_id": "question_1", "logical_key": "logical_legacy_scope_key"}),
            "Refunds settle in one business day.",
            "answer_3",
        );
        assert_eq!(correction.logical_key, legacy.logical_key);
    }

    #[test]
    fn a_local_answer_is_trusted_only_through_its_signed_answer() {
        let authority = PrivateKey::generate();
        let local = PrivateKey::generate();
        let signed = signed_answer(&authority, TEXT);
        let ledger = vec![ledger_record("answer_1", &signed)];
        let nothing_revoked = BTreeSet::new();
        let fact = event(&local, TEXT, "answer_1");
        let verify =
            |fact: &crate::model::FactEvent, ledger: &[Value], revoked: &BTreeSet<String>| {
                local_answer_verification(fact, ledger, revoked)
            };

        assert_eq!(
            verify(&fact, &ledger, &nothing_revoked),
            Verification::Verified
        );
        // No answer in the ledger backs the event.
        assert_eq!(
            verify(&event(&local, TEXT, "answer_9"), &ledger, &nothing_revoked),
            Verification::Unverified
        );
        assert_eq!(
            verify(
                &event(&local, "Refunds settle at once.", "answer_1"),
                &ledger,
                &nothing_revoked
            ),
            Verification::Unverified
        );
        // The event changed after it was signed.
        let mut altered = fact.clone();
        altered.raw = None;
        altered.distortion.rationale = "edited".to_owned();
        assert_eq!(
            verify(&altered, &ledger, &nothing_revoked),
            Verification::SignatureInvalid
        );
        // The ledger's signed answer no longer matches its signature.
        let mut edited = signed.clone();
        edited.insert("rationale".to_owned(), json!("edited"));
        assert_eq!(
            verify(
                &fact,
                &[ledger_record("answer_1", &edited)],
                &nothing_revoked
            ),
            Verification::SignatureInvalid
        );
        // The authority's key has since been revoked.
        let revoked = BTreeSet::from([authority.public().to_hex()]);
        assert_eq!(verify(&fact, &ledger, &revoked), Verification::Revoked);
        // A ledger record and event from before signed bytes were kept.
        let mut legacy_record = ledger_record("answer_1", &signed);
        legacy_record
            .as_object_mut()
            .expect("object")
            .remove("signed_answer");
        let mut legacy = fact.clone();
        legacy.raw = None;
        legacy.signer = "payments-owner".to_owned();
        assert_eq!(
            verify(&legacy, &[legacy_record], &nothing_revoked),
            Verification::Verified
        );
    }
}
