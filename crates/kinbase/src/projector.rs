//! P-7: deterministic, inspectable set-conditional projection.
//!
//! The selector is deliberately arithmetic-only: every reported term is a
//! signed integer in basis points. It never claims a causal quantity; it is
//! an additive approximation over admitted facts and explicit Unknowns.
//!
//! ```text
//! marginal(a | S, d) =
//!     newly_covered_distortion(d, a, S)
//!   + authority_and_validity_gain(a)
//!   + complementarity_gain(a, S)
//!   + uncertainty_reduction(a, d, S)
//!   - redundancy(a, S)
//!   - retrieval_and_residency_cost(a)
//!   - stale_or_conflict_risk(a)
//! ```
//!
//! `S` is the current set: the caller-declared working set already resident
//! at the dependent edit plus everything selected so far. Penalty terms are
//! reported as the positive magnitudes the formula subtracts.

use crate::error::ContractError;
use crate::launcher::Launcher;
use crate::model::{CurrentFact, FactEvent};
use crate::reducer::{CurrentView, ReducerInput};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const PROJECTION_LIMIT: usize = 32;
/// At most this share of a projection may be company direction.
///
/// Direction and evidence are complementary, not competing, and a single ranked
/// list cannot express that: a company fact outscores a repository fact on every
/// term in the formula -- higher declared distortion, higher authority gain,
/// higher confidence -- so without a reserve it takes all thirty-two slots. An
/// agent handed thirty-two rulings and no code cannot act; one handed
/// thirty-two commits and no ruling acts wrong. The cap is declared and
/// reported rather than tuned into the weights, because a caller is entitled to
/// know that facts were withheld by policy and not by score.
pub const PROJECTION_DIRECTION_SLOTS: usize = PROJECTION_LIMIT / 2;
pub const PROJECTION_BYTE_LIMIT: usize = 128 * 1024;
/// How many rejected evaluations of the stopping round the trace retains.
const STOP_ROUND_TRACE_LIMIT: usize = 16;
const TIERS: [(&str, i64, i64); 7] = [
    ("facts_and_unknowns", 0, 100),
    ("summary", 500, 100),
    ("exact_code_span", 1_200, 200),
    ("history_adr", 800, 150),
    ("test_runtime_evidence", 1_500, 200),
    ("authority_answer", 0, 300),
    ("broad_search", 250, 250),
];

#[derive(Debug, Clone)]
pub(crate) struct UnknownOut {
    pub(crate) unknown_id: String,
    pub(crate) logical_key: String,
    pub(crate) scope: String,
    pub(crate) decision_blocked: String,
    pub(crate) owner_role: String,
    pub(crate) owner_identity: String,
    pub(crate) question: String,
    pub(crate) evidence: Vec<String>,
    pub(crate) loss_if_absent: u16,
    pub(crate) status: String,
    pub(crate) kind: String,
}

/// One candidate scored against the current set. Gains are non-negative;
/// `redundancy`, `retrieval_and_residency_cost` and `stale_or_conflict_risk`
/// are the non-negative magnitudes the marginal subtracts.
#[derive(Debug, Clone)]
struct Evaluation {
    marginal_value: i64,
    newly_covered_distortion: i64,
    authority_and_validity_gain: i64,
    complementarity_gain: i64,
    uncertainty_reduction: i64,
    redundancy: i64,
    retrieval_and_residency_cost: i64,
    stale_or_conflict_risk: i64,
    redundancy_basis: String,
    complementarity_basis: String,
}

impl Evaluation {
    fn terms(&self) -> Value {
        json!({
            "newly_covered_distortion": self.newly_covered_distortion,
            "authority_and_validity_gain": self.authority_and_validity_gain,
            "complementarity_gain": self.complementarity_gain,
            "uncertainty_reduction": self.uncertainty_reduction,
            "redundancy": self.redundancy,
            "retrieval_and_residency_cost": self.retrieval_and_residency_cost,
            "stale_or_conflict_risk": self.stale_or_conflict_risk
        })
    }
}

/// Bytes of a JSON array holding facts of these canonical sizes: their sizes
/// plus k-1 commas and two brackets.
fn array_bytes(sizes: impl Iterator<Item = usize>) -> usize {
    let (count, total) = sizes.fold((0usize, 0usize), |(count, total), size| {
        (count + 1, total + size)
    });
    total + count.saturating_sub(1) + 2
}

/// The working-set residents a projection carries, in order, within its
/// 32-fact / 128-KiB ceiling. Returns the kept residents, how many were
/// omitted, and whether the byte ceiling (rather than the item ceiling)
/// omitted any.
fn bounded_residents(
    residents: Vec<CurrentFact>,
    bytes_of: impl Fn(&CurrentFact) -> usize,
) -> (Vec<CurrentFact>, usize, bool) {
    let mut kept: Vec<CurrentFact> = Vec::new();
    let mut omitted = 0usize;
    let mut byte_ceiling_hit = false;
    for fact in residents {
        if kept.len() >= PROJECTION_LIMIT {
            omitted += 1;
            continue;
        }
        let bytes = array_bytes(kept.iter().chain([&fact]).map(&bytes_of));
        if bytes > PROJECTION_BYTE_LIMIT {
            omitted += 1;
            byte_ceiling_hit = true;
            continue;
        }
        kept.push(fact);
    }
    (kept, omitted, byte_ceiling_hit)
}

/// Why the selection loop stopped. A ceiling that ended it is named: the
/// loop used to report `nonpositive_net_marginal_value` for a projection the
/// working set had already filled, without ever evaluating a candidate.
fn stopping_reason(
    question_raised: bool,
    sufficiency: bool,
    residents_filled: bool,
    item_ceiling_hit: bool,
    ended_at_byte_ceiling: bool,
) -> &'static str {
    if question_raised {
        "authority_question_raised"
    } else if sufficiency {
        "sufficiency_predicate_met"
    } else if residents_filled {
        "working_set_ceiling_reached"
    } else if item_ceiling_hit {
        "item_ceiling_reached"
    } else if ended_at_byte_ceiling {
        "byte_ceiling_reached"
    } else {
        "nonpositive_net_marginal_value"
    }
}

fn trace_step(
    fact: &CurrentFact,
    evaluation: &Evaluation,
    current_set_size: usize,
    action: &str,
    reason: &str,
) -> Value {
    json!({
        "fact_id": fact.fact_id,
        "logical_key": fact.logical_key,
        "action": action,
        "selected": action == "selected",
        "selection_reason": reason,
        "marginal_value": evaluation.marginal_value,
        "current_set_size": current_set_size,
        "redundancy_basis": evaluation.redundancy_basis,
        "complementarity_basis": evaluation.complementarity_basis,
        "marginal_terms": evaluation.terms()
    })
}

fn refuse_unrecordable_paths(
    working_set: &[String],
    evidence_repos: &[std::path::PathBuf],
) -> Result<(), ContractError> {
    let working = working_set
        .iter()
        .map(|entry| ("--working-set", entry.clone()));
    let repos = evidence_repos
        .iter()
        .map(|path| ("--evidence-repo", path.to_string_lossy().into_owned()));
    for (flag, value) in working.chain(repos) {
        if let Err(reason) = crate::json::validate_text(&value) {
            return Err(ContractError::invariant(format!(
                "a {flag} value cannot be recorded: {reason}"
            )));
        }
    }
    Ok(())
}

pub fn run(
    launcher: &Launcher,
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    evidence_repos: &[std::path::PathBuf],
    as_of: &crate::time::AsOf,
    json: bool,
) -> Result<(), ContractError> {
    let mut projection =
        project(launcher, repo, task, decision, working_set, evidence_repos, as_of)?;
    // The projection quotes facts and the task verbatim; known secrets are
    // masked before it is printed (`crate::secret_mask`).
    crate::secret_mask::mask_value(&mut projection.result);
    if json {
        println!("{}", crate::json::canonical_text(&projection.result));
    } else {
        let result = &projection.result;
        println!("decision: {}", result["decision"].as_str().unwrap_or_default());
        println!("selected_count: {}", projection.selected.len());
        println!("omitted_count: {}", result["omitted_count"]);
        println!("stopping_reason: {}", result["stopping_reason"].as_str().unwrap_or_default());
    }
    Ok(())
}

/// A projection: the canonical result `run` prints, and the selected facts.
pub struct Projection {
    pub result: Value,
    pub selected: Vec<CurrentFact>,
}

/// What a projection records besides its result. `kinbase project` raises a
/// question to the owner of a blocking Unknown and logs the query. A
/// projection made for a principal's own question (`kinbase recall`) records
/// neither: the question is Personal and must not reach a shared store or a
/// durable log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recording {
    Full,
    ReadOnly,
}

pub fn project(
    launcher: &Launcher,
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    evidence_repos: &[std::path::PathBuf],
    as_of: &crate::time::AsOf,
) -> Result<Projection, ContractError> {
    project_with(launcher, repo, task, decision, working_set, evidence_repos, as_of, Recording::Full)
}

#[allow(clippy::too_many_arguments)]
pub fn project_with(
    launcher: &Launcher,
    repo: &Path,
    task: &str,
    decision: &str,
    working_set: &[String],
    evidence_repos: &[std::path::PathBuf],
    as_of: &crate::time::AsOf,
    recording: Recording,
) -> Result<Projection, ContractError> {
    // Authority refresh is an optimization, not a command gate. When Company
    // is unavailable, the cached projection is still emitted and the explicit
    // degraded policy withholds the dependent decision.
    // A task is a query, not a durable record, but it is embedded in one: the
    // output and the query log are canonical documents, and the text rule
    // rejects control characters. A ticket pasted with its newlines used to
    // make the projection print nothing and exit 0. Fold control characters
    // to spaces here, once, for every consumer downstream.
    let task_text = fold_control_characters(task);
    let decision_text = fold_control_characters(decision);
    // Paths are not folded (a folded path names nothing); one the text rule
    // refuses is refused here, before a question or unknown is written, not
    // by the query log afterwards as an internal failure.
    refuse_unrecordable_paths(working_set, evidence_repos)?;
    let task = task_text.as_str();
    let decision = decision_text.as_str();
    // Ask as this repository: the service sends company-wide direction plus
    // the rulings that govern this repository, and a cached snapshot fetched
    // for another repository does not count as fresh.
    let repository_uuid = crate::codebase::Repository::discover(repo)
        .ok()
        .and_then(|repository| {
            crate::repository::build_trust(launcher, &repository, false, None)
                .ok()
                .and_then(|trust| trust.repository_uuid)
                .or_else(|| repository.uuid_hint().map(str::to_owned))
        })
        .unwrap_or_default();
    // Stated, never silent: a refresh the service refused (a ceiling, an
    // outage) leaves the cached snapshot in force, and the brief says so. A
    // ruling that exists but was withheld must not read as a ruling that
    // does not exist.
    let authority_refresh = match crate::repository::ensure_authority_snapshot_for(
        launcher,
        &repository_uuid,
        None,
        &as_of.as_of,
    ) {
        Ok((cursor, source)) => json!({"status": "ok", "source": source, "cursor": cursor}),
        Err(error) => json!({
            "status": "withheld",
            "code": error.code,
            "message": error.message,
            "remediation": error.remediation,
        }),
    };
    // The refresh may have stored a later signed instant than the one the
    // command resolved before it ran.
    let advanced = crate::repository::advance_as_of(launcher, as_of);
    let as_of = &advanced;
    let mut facts = Vec::new();
    let mut ingested_events = Vec::new();
    let mut conflict_event_ids = BTreeSet::new();
    let mut view_unknowns = Vec::new();
    let mut references = Vec::new();
    // Company direction, this repository's own evidence, and the evidence
    // held by any repository named as evidence for it. Tickets, pull
    // requests, threads and documents live in a corpus repository that
    // nobody codes in; a projection that only read the repository in front
    // of it never saw any of them.
    let mut sources: Vec<(std::path::PathBuf, crate::StoreKind)> = vec![
        (repo.to_path_buf(), crate::StoreKind::Company),
        (repo.to_path_buf(), crate::StoreKind::Codebase),
    ];
    for evidence in evidence_repos {
        sources.push((evidence.clone(), crate::StoreKind::Codebase));
    }
    let mut evidence_fact_count = 0usize;
    for (index, (source, store)) in sources.iter().enumerate() {
        let store_view = load_view(launcher, source, *store, as_of)?;
        conflict_event_ids.extend(
            store_view
                .view
                .traces
                .iter()
                .flat_map(|trace| trace.conflict_event_ids.iter().cloned()),
        );
        if index >= 2 {
            evidence_fact_count += store_view.view.facts.len();
        }
        facts.extend(store_view.view.facts);
        view_unknowns.extend(store_view.view.unknowns);
        ingested_events.extend(store_view.events);
        references.extend(store_view.references);
    }
    // A closure record is authoritative across stores: the original Unknown
    // remains in append-only history, but no later projection may treat it as
    // still blocking after the signed answer.
    let closed_unknown_ids: BTreeSet<String> =
        [crate::StoreKind::Company, crate::StoreKind::Codebase]
            .into_iter()
            .filter_map(|store| crate::store::read_records(store, repo, "unknowns.jsonl").ok())
            .flatten()
            .filter(|record| {
                matches!(
                    record.get("status").and_then(Value::as_str),
                    Some("closed") | Some("superseded")
                )
            })
            .filter_map(|record| {
                record
                    .get("fact_id")
                    .or_else(|| record.get("unknown_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
    view_unknowns.retain(|unknown| !closed_unknown_ids.contains(&unknown.unknown_id));
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));

    // A `question` atom is an open Unknown owned by the authority that asserted
    // it. It is never trusted guidance and never enters the selectable set.
    let (question_facts, facts): (Vec<CurrentFact>, Vec<CurrentFact>) = facts
        .into_iter()
        .partition(|fact| fact.atom_kind == "question");
    let question_unknowns: Vec<UnknownOut> = question_facts
        .iter()
        .filter(|fact| !closed_unknown_ids.contains(&question_unknown_id(fact)))
        .map(question_unknown)
        .collect();

    let working: BTreeSet<&str> = working_set.iter().map(String::as_str).collect();
    let candidates: Vec<&CurrentFact> = facts
        .iter()
        .filter(|fact| {
            fact.status == "current"
                && fact.trust == "trusted"
                && fact.stale_reasons.is_empty()
                && !matches!(
                    fact.disposition.as_str(),
                    "disputed" | "expired" | "conflict"
                )
        })
        .collect();
    let unknowns = unknown_outputs(&facts, &view_unknowns, &question_unknowns);
    let roles = Roles::derive(&facts);
    let mut candidate_documents: Vec<(String, Value)> = facts
        .iter()
        .map(|fact| (fact.fact_id.clone(), candidate_value(fact, &roles)))
        .collect();
    // Byte accounting for the ceilings: each candidate's canonical size once;
    // a JSON array of k values costs their sizes plus k-1 commas and two
    // brackets.
    let value_bytes: BTreeMap<String, usize> = candidate_documents
        .iter()
        .map(|(id, value)| (id.clone(), crate::json::canonical_text(value).len()))
        .collect();
    let mut represented_ids: BTreeSet<String> = candidate_documents
        .iter()
        .map(|(id, _)| id.clone())
        .chain(question_facts.iter().map(|fact| fact.fact_id.clone()))
        .collect();
    for event in ingested_events {
        if represented_ids.contains(&event.fact_id) {
            continue;
        }
        represented_ids.insert(event.fact_id.clone());
        candidate_documents.push((
            event.fact_id.clone(),
            event_candidate_value(&event, &conflict_event_ids, &as_of.as_of),
        ));
    }
    candidate_documents.sort_by(|left, right| left.0.cmp(&right.0));
    let candidate_values: Vec<Value> = candidate_documents
        .into_iter()
        .map(|(_, value)| value)
        .collect();
    let open_unknowns: Vec<_> = unknowns
        .iter()
        .filter(|unknown| {
            unknown.status == "open"
                || unknown.status == "asked"
                // A conflict whose scope has no registered authority carries
                // UNKNOWN_OWNER_UNRESOLVED rather than "open". Excluding it here is
                // how contested keys went silent: the absence of an owner became the
                // reason nobody was ever asked to become one. It is still an open
                // question -- it is the question of who should answer it.
                || (unknown.status == "UNKNOWN_OWNER_UNRESOLVED" && unknown.kind == "conflict")
        })
        .cloned()
        .collect();
    // Low-distortion Unknowns are represented, but only a high-distortion
    // Unknown blocks dependent trusted guidance.
    // An Unknown blocks this projection when it names the task or the
    // decision as the decision it blocks, when its own precise question is
    // the decision at stake, or when it is architecture-owned.
    let blocks = |unknown: &UnknownOut| {
        unknown.loss_if_absent >= 7_000
            && (unknown.decision_blocked == decision
                || unknown.decision_blocked == task
                || unknown.question == decision
                || unknown.scope.starts_with("architecture:")
                || unknown.owner_role == "chief-architect")
    };
    let has_blocking_unknown = open_unknowns.iter().any(|unknown| blocks(unknown));

    // The current set S starts as the caller-declared working set: facts
    // already resident at the dependent edit. They condition every marginal
    // but are never re-selected; re-adding a resident fact has zero value.
    // A working-set entry is either a fact id or a file path. Requiring fact ids
    // only was unusable from the seat that matters: an agent about to edit
    // `src/pay/reconcile.ts` knows the path and not which facts describe it, and
    // had to be told "unresolved" for every entry. A path entry resolves to every
    // fact anchored in that file or under that directory.
    let resolves = |fact: &CurrentFact, entry: &str| -> bool {
        fact.fact_id == entry
            || fact.anchors.iter().any(|anchor| {
                anchor.path == entry
                    // A directory entry covers the files beneath it; a file entry
                    // covers anchors into that file. Both need the separator so
                    // `src/pay` never reaches `src/payments-legacy`.
                    || anchor.path.starts_with(&format!("{}/", entry.trim_end_matches('/')))
            })
    };
    let resolved: Vec<CurrentFact> = candidates
        .iter()
        .filter(|fact| working.iter().any(|entry| resolves(fact, entry)))
        .map(|fact| (*fact).clone())
        .collect();
    let working_set_unresolved: Vec<&str> = working_set
        .iter()
        .map(String::as_str)
        .filter(|entry| !resolved.iter().any(|fact| resolves(fact, entry)))
        .collect();
    // Residents occupy the projection like selected facts do, so a working
    // set that resolves past the ceiling is cut to it and the rest counted.
    let (residents, resident_omitted_count, resident_byte_ceiling_hit) =
        bounded_residents(resolved, |fact| {
            value_bytes.get(fact.fact_id.as_str()).copied().unwrap_or(0)
        });
    let resident_ids: BTreeSet<String> =
        residents.iter().map(|fact| fact.fact_id.clone()).collect();
    let mut context: Vec<CurrentFact> = residents.clone();
    let mut selected: Vec<CurrentFact> = Vec::new();
    let mut selection_trace = Vec::new();
    for fact in &residents {
        let evaluation = resident_evaluation();
        selection_trace.push(trace_step(
            fact,
            &evaluation,
            context.len(),
            "resident",
            "working_set_resident",
        ));
    }
    let context_bytes = |set: &[CurrentFact], extra: Option<&CurrentFact>| -> usize {
        array_bytes(
            set.iter()
                .chain(extra)
                .map(|fact| value_bytes.get(fact.fact_id.as_str()).copied().unwrap_or(0)),
        )
    };
    let mut sufficiency = false;
    let mut ended_at_byte_ceiling = false;
    let mut stop_round: Vec<(&CurrentFact, Evaluation)> = Vec::new();
    let mut direction_slots_used = 0usize;
    let mut direction_slots_withheld = 0usize;
    let cache = EvalCache::new(&candidates, task, decision);
    let mut folds: BTreeMap<&str, SetFold> = candidates
        .iter()
        .map(|fact| (fact.fact_id.as_str(), SetFold::of(fact, &context, &cache)))
        .collect();
    while context.len() < PROJECTION_LIMIT {
        let mut round: Vec<(&CurrentFact, Evaluation)> = Vec::new();
        // Whether a candidate of positive value did not fit in this round.
        // Only the round that ends selection counts: a candidate refused for
        // bytes earlier can have become redundant since.
        let mut round_byte_blocked = false;
        for fact in &candidates {
            if context
                .iter()
                .any(|existing| existing.fact_id == fact.fact_id)
            {
                continue;
            }
            if is_direction(fact) && direction_slots_used >= PROJECTION_DIRECTION_SLOTS {
                direction_slots_withheld += 1;
                continue;
            }
            let evaluation = match folds.get(fact.fact_id.as_str()) {
                Some(fold) => evaluate_folded(fact, fold, &cache),
                None => evaluate_cached(fact, &context, &cache),
            };
            if context_bytes(&context, Some(fact)) > PROJECTION_BYTE_LIMIT {
                if evaluation.marginal_value > 0 {
                    round_byte_blocked = true;
                }
                continue;
            }
            round.push((fact, evaluation));
        }
        // Deterministic order: marginal value, then role priority, then id.
        round.sort_by(|(left, left_value), (right, right_value)| {
            right_value
                .marginal_value
                .cmp(&left_value.marginal_value)
                .then_with(|| {
                    candidate_priority(roles.name(right)).cmp(&candidate_priority(roles.name(left)))
                })
                .then_with(|| left.fact_id.cmp(&right.fact_id))
        });
        let Some((fact, evaluation)) = round.first().cloned() else {
            // Nothing left fits; if something of value did not, the byte
            // ceiling is what stopped the loop.
            ended_at_byte_ceiling = round_byte_blocked;
            break;
        };
        if evaluation.marginal_value <= 0 {
            // What fits adds nothing; a candidate that would have is the
            // byte ceiling's doing.
            ended_at_byte_ceiling = round_byte_blocked;
            // The loop stops on net marginal value: record why every
            // remaining candidate was left out, best first.
            stop_round = round;
            break;
        }
        selection_trace.push(trace_step(
            fact,
            &evaluation,
            context.len(),
            "selected",
            "positive_conditional_marginal_value",
        ));
        if is_direction(fact) {
            direction_slots_used += 1;
        }
        selected.push(fact.clone());
        context.push(fact.clone());
        for candidate in &candidates {
            if let Some(fold) = folds.get_mut(candidate.fact_id.as_str()) {
                fold.absorb(candidate, fact, &cache);
            }
        }
        if is_authority_answer(fact) && !has_blocking_unknown {
            sufficiency = true;
            break;
        }
    }
    let rejected_count = stop_round.len();
    for (fact, evaluation) in stop_round.iter().take(STOP_ROUND_TRACE_LIMIT) {
        selection_trace.push(trace_step(
            fact,
            evaluation,
            context.len(),
            "rejected",
            "nonpositive_conditional_marginal_value",
        ));
    }

    let question_id = if !has_blocking_unknown || recording == Recording::ReadOnly {
        None
    } else {
        let evidence: Vec<String> = context
            .iter()
            .map(|fact| fact.fact_id.clone())
            .chain(
                open_unknowns
                    .iter()
                    .flat_map(|unknown| unknown.evidence.clone()),
            )
            .collect();
        let remaining: Vec<String> = candidates
            .iter()
            .filter_map(|fact| {
                if context
                    .iter()
                    .any(|selected| selected.fact_id == fact.fact_id)
                {
                    None
                } else {
                    Some(fact.statement.clone())
                }
            })
            .collect();
        let mut raised = None;
        // A contested key always asks, whatever its computed loss.
        //
        // The loss threshold is right for uncertainty that might not matter: do not
        // interrupt a person over a gap the projection can live without. A conflict
        // is the opposite case. Two incompatible statements are both being carried,
        // and every session that reads this key will pick one by accident until
        // somebody rules. "Which of these five implementations?" is the question the
        // loop exists to ask, and it is worth a minute of an architect's time even
        // when the individual fact looks cheap.
        //
        // This holds especially when no authority is registered for the scope: that
        // unknown carries UNKNOWN_OWNER_UNRESOLVED, and suppressing it would make
        // the absence of an owner the reason nobody is ever asked to become one.
        //
        // One question is raised per projection, so the order decides which one a
        // person sees. The Unknowns that stopped this projection come first: asking
        // about an unrelated expired fact while the decision at hand stays blocked
        // answers nothing the caller asked.
        let (blocking, elsewhere): (Vec<&UnknownOut>, Vec<&UnknownOut>) = open_unknowns
            .iter()
            .filter(|unknown| unknown.loss_if_absent >= 7_000 || unknown.kind == "conflict")
            .partition(|unknown| blocks(unknown));
        for unknown in blocking.into_iter().chain(elsewhere) {
            if let Some(id) =
                crate::questions::ensure_question(repo, unknown, decision, &evidence, &remaining)?
            {
                raised = Some(id);
                break;
            }
        }
        raised
    };

    // The working set alone filled the projection: no candidate was ever
    // selected because the residents left no room.
    let byte_ceiling_hit = resident_byte_ceiling_hit || ended_at_byte_ceiling;
    let residents_filled = residents.len() >= PROJECTION_LIMIT
        || (resident_byte_ceiling_hit && selected.is_empty() && ended_at_byte_ceiling);
    let item_ceiling_hit = context.len() >= PROJECTION_LIMIT
        && (resident_omitted_count > 0
            || candidates.iter().any(|fact| {
                !context
                    .iter()
                    .any(|existing| existing.fact_id == fact.fact_id)
                    && evaluate_cached(fact, &context, &cache).marginal_value > 0
            }));
    let stopping_reason = stopping_reason(
        question_id.is_some(),
        sufficiency,
        residents_filled,
        item_ceiling_hit,
        ended_at_byte_ceiling,
    );
    let omitted_count = if byte_ceiling_hit || item_ceiling_hit || resident_omitted_count > 0 {
        candidates.len().saturating_sub(context.len())
    } else {
        0
    };
    let tier_escalation: Vec<Value> = TIERS
        .iter()
        .map(|(tier, value, cost)| {
            json!({"tier": tier, "estimated_value": value, "estimated_cost": cost, "action": "visited"})
        })
        .collect();
    let invariant_selected = context
        .iter()
        .any(|fact| roles.name(fact) == "high_distortion_compatibility_invariant");
    let projection_bytes = context_bytes(&selected, None);
    let resident_bytes = context_bytes(&residents, None);
    let company_reference = company_reference(&context, &facts);
    let context_ids: BTreeSet<&str> = context.iter().map(|fact| fact.fact_id.as_str()).collect();
    let selected_reference = references
        .iter()
        .filter(|record| {
            crate::json::get_str(record, "fact_id")
                .is_some_and(|fact_id| context_ids.contains(fact_id))
        })
        .find(|record| crate::json::get_str(record, "resolution") == Some("resolved"))
        .cloned();
    let effective_reference = selected_reference
        .clone()
        .or_else(|| references.first().cloned());
    let company_owner = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "company_owner").map(str::to_owned));
    let local_owner = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "local_owner").map(str::to_owned));
    let effective_criticality = effective_reference.as_ref().and_then(|record| {
        crate::json::get_str(record, "effective_dependence_class").map(str::to_owned)
    });
    let dominating_input = effective_reference
        .as_ref()
        .and_then(|record| crate::json::get_str(record, "dominating_input").map(str::to_owned));
    let cache_state_constructed = launcher.company_cache()?.is_some();
    // Trusted guidance is released only once no high-distortion Unknown
    // blocks the decision, and it cites the admitted answer it rests on
    // (question, answer and fact identities) rather than restating prose.
    let recommendation_fact = if !has_blocking_unknown {
        selected
            .iter()
            .find(|fact| is_authority_answer(fact))
            .or_else(|| context.iter().find(|fact| is_authority_answer(fact)))
    } else {
        None
    };
    let recommendation = recommendation_fact.map(|fact| fact.statement.clone());
    let recommendation_basis = recommendation_fact.map(|fact| {
        json!({
            "fact_id": fact.fact_id,
            "event_id": fact.event_id,
            "authority_id": fact.authority_id,
            "authority_scope": fact.authority_scope,
            "cites": fact.evidence_refs,
            "authority_snapshot_cursor": fact.authority_snapshot_cursor
        })
    });
    let safety_is_degraded = facts.iter().any(|fact| {
        crate::model::criticality_is_safety(
            fact.effective_dependence_class
                .as_deref()
                .unwrap_or(&fact.criticality),
        ) && fact.trust != "trusted"
            && fact
                .stale_reasons
                .iter()
                .any(|reason| reason == "CACHE_EXPIRED" || reason == "REVOCATION_STALE")
    });
    let advisory_is_degraded = facts.iter().any(|fact| {
        !crate::model::criticality_is_safety(
            fact.effective_dependence_class
                .as_deref()
                .unwrap_or(&fact.criticality),
        ) && fact.trust == "excluded"
    });
    // Architecture §6: an expired or revocation-stale safety dependency
    // withholds the projection; an open high-distortion Unknown does too.
    let projection_withheld = has_blocking_unknown || safety_is_degraded;
    let degraded_policy = if safety_is_degraded
        || open_unknowns
            .iter()
            .any(|unknown| unknown.loss_if_absent >= 7_500)
    {
        "block_dependent_decision"
    } else if !has_blocking_unknown && !advisory_is_degraded {
        "block_dependent_decision"
    } else {
        "reversible_sandbox_only_experiment"
    };
    let selected_value = |fact: &CurrentFact| {
        json!({
            "fact_id": fact.fact_id,
            "logical_key": fact.logical_key,
            "role": roles.name(fact),
            "store_kind": fact.store_kind,
            // The point of selecting a fact is to act on it, and how much weight
            // it carries is the first thing the caller needs. Without these the
            // consumer sees a flat list and cannot tell a ratified architecture
            // ruling from the majority pattern in a directory being retired --
            // which is the entire distinction this system exists to draw.
            "atom_kind": fact.atom_kind,
            "standing": fact.standing,
            "provenance": fact.provenance,
            "governs_paths": fact.governs_paths,
            "anchors": fact.anchors,
            "resident": resident_ids.contains(&fact.fact_id),
            "selection_reason": if resident_ids.contains(&fact.fact_id) { "working_set_resident" } else { "positive_conditional_marginal_value" }
        })
    };
    let mut brief = direction_brief(&facts, &context, task, decision, &as_of.as_of, &repository_uuid);
    brief["authority_refresh"] = authority_refresh;
    let result = json!({
        "decision": decision,
        "task": task,
        "as_of": as_of.as_of,
        "as_of_source": as_of.as_of_source,
        "ambient_clock_read": false,
        // What a long-tenured engineer would say before the plan: who owns the
        // code the ticket names in the target state, which of the ticket's words
        // the ratified vocabulary defines differently, where the direction lives,
        // and the direction that governs, each row with its owner and age. An
        // agent does not have to know the vocabulary or search for any of it.
        "brief": brief,
        "candidates": candidate_values.into_iter().chain(unknowns.iter().map(unknown_value)).collect::<Vec<_>>(),
        "working_set": working_set,
        "evidence_repos": evidence_repos,
        "evidence_repo_fact_count": evidence_fact_count,
        "resident_working_set": residents.iter().map(selected_value).collect::<Vec<_>>(),
        "working_set_unresolved": working_set_unresolved,
        "selected": selected.iter().map(selected_value).collect::<Vec<_>>(),
        "current_set": context.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selection_trace": selection_trace,
        "rejected_count": rejected_count,
        "tier_escalation": tier_escalation,
        "projection_bytes": projection_bytes,
        "resident_bytes": resident_bytes,
        "invariant_selected": invariant_selected,
        "stopping_reason": stopping_reason,
        "unknowns": unknowns.iter().map(unknown_value).collect::<Vec<_>>(),
        "voi_approximation": "additive deterministic basis-point approximation over conditional distortion, authority, complementarity, uncertainty, redundancy, retrieval, and staleness",
        "trusted_recommendation": recommendation,
        "trusted_recommendation_basis": recommendation_basis,
        "degraded_policy": degraded_policy,
        "cache_state_constructed": cache_state_constructed,
        "company_reference_resolved": selected_reference.is_some(),
        "reference_resolved": selected_reference.is_some(),
        "company_statement": selected_reference
            .as_ref()
            .and_then(|record| crate::json::get_str(record, "company_statement"))
            .or(company_reference.as_deref())
            .unwrap_or_default(),
        "effective_criticality": effective_criticality,
        "company_owner": company_owner,
        "local_owner": local_owner,
        "max_rule": effective_reference
            .as_ref()
            .and_then(|record| crate::json::get_str(record, "max_rule")),
        "dominating_input": dominating_input,
        "projection_state": if projection_withheld { "withheld" } else { "projected" },
        "question_id": question_id,
        // Facts withheld by policy rather than by score: a caller comparing two
        // projections needs to see the reserve, not infer it.
        "direction_slots_used": direction_slots_used,
        "direction_slots_cap": PROJECTION_DIRECTION_SLOTS,
        "direction_withheld_evaluations": direction_slots_withheld,
        "omitted_count": omitted_count,
        "resident_omitted_count": resident_omitted_count
    });

    let query_record = json!({
        "requested": TIERS.iter().map(|(tier, _, _)| *tier).collect::<Vec<_>>(),
        "returned": candidates.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selected": selected.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "selected_ids": selected.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "working_set": working_set,
        "evidence_repos": evidence_repos,
        "evidence_repo_fact_count": evidence_fact_count,
        "resident_at_dependent_edit": working_set,
        "resident_ids": residents.iter().map(|fact| fact.fact_id.clone()).collect::<Vec<_>>(),
        "declared_use": decision,
        "task": task,
        "stopping_reason": stopping_reason,
        "direction_slots_used": direction_slots_used,
        "direction_slots_cap": PROJECTION_DIRECTION_SLOTS,
        // Counted per round, so it is a measure of pressure on the reserve
        // rather than a count of distinct facts.
        "direction_withheld_evaluations": direction_slots_withheld,
        "outcome": stopping_reason,
        "question_id": question_id,
        "task_outcome": "pending",
        "cost": TIERS.iter().map(|(_, _, cost)| *cost).sum::<i64>(),
        "marginal_gain": selection_trace
            .iter()
            .filter(|row| row.get("selected") == Some(&Value::Bool(true)))
            .filter_map(|row| row.get("marginal_value"))
            .filter_map(Value::as_i64)
            .sum::<i64>(),
        "selection_trace": selection_trace.clone(),
        "as_of": as_of.as_of
    });
    // A projection has no host session, and the decision is already the
    // record's `declared_use`; passing it as the session id put sentences in
    // an identifier column.
    if recording == Recording::Full {
        launcher.private_store()?.log_query(None, &query_record)?;
    }
    Ok(Projection { result, selected })
}

fn question_unknown_id(fact: &CurrentFact) -> String {
    format!("unknown_{}", &fact.fact_id[5.min(fact.fact_id.len())..])
}

/// A `question` atom asserted by an authority is an open Unknown that
/// authority owns; the question text is the fact statement.
fn question_unknown(fact: &CurrentFact) -> UnknownOut {
    UnknownOut {
        unknown_id: question_unknown_id(fact),
        logical_key: fact.logical_key.clone(),
        scope: fact.authority_scope.clone(),
        decision_blocked: fact.distortion.trigger.clone(),
        owner_role: owner_role_for(&fact.authority_scope, &fact.store_kind).to_owned(),
        owner_identity: fact.authority_id.clone(),
        question: fact.statement.clone(),
        evidence: fact.evidence_refs.clone(),
        loss_if_absent: fact.distortion.loss_if_absent,
        status: "open".to_owned(),
        kind: "question".to_owned(),
    }
}

fn owner_role_for(scope: &str, store_kind: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "chief-architect"
    } else if store_kind == "company" || scope.starts_with("company:") {
        "company-steward"
    } else if scope.starts_with("environment:") {
        "deploy-owner"
    } else {
        "repository-maintainer"
    }
}

struct StoreView {
    view: CurrentView,
    events: Vec<FactEvent>,
    references: Vec<Value>,
}

/// The Company store's current view from the verified cache alone (no
/// network): what a host start may project as trusted Company context.
pub(crate) fn company_view(
    launcher: &Launcher,
    repo: &Path,
    as_of: &crate::time::AsOf,
) -> Result<CurrentView, ContractError> {
    load_view(launcher, repo, crate::StoreKind::Company, as_of).map(|store| store.view)
}

fn load_view(
    launcher: &Launcher,
    repo: &Path,
    store: crate::StoreKind,
    as_of: &crate::time::AsOf,
) -> Result<StoreView, ContractError> {
    let mut data = crate::corpus::load_store(launcher, repo, store)?;
    let mut references = Vec::new();
    if store == crate::StoreKind::Codebase {
        if let Ok(repository) = crate::codebase::Repository::discover(repo) {
            let repository_uuid = repository.uuid_hint().map(str::to_owned);
            data.events.retain(|admitted| {
                admitted
                    .event
                    .repository_id
                    .as_deref()
                    .map(|bound| repository_uuid.as_deref().is_some_and(|uuid| bound == uuid))
                    .unwrap_or(true)
            });
            let ingested_events: Vec<FactEvent> = data
                .events
                .iter()
                .map(|admitted| admitted.event.clone())
                .collect();
            let context = crate::repository::RepoContext::load(
                crate::launcher::Launcher::load()?,
                repo,
                true,
                Some(&as_of.as_of),
            )?;
            let (view, _counts, store_references) = context.current_view(&as_of.as_of, None)?;
            references = store_references;
            return Ok(StoreView {
                view,
                events: ingested_events,
                references,
            });
        }
    }

    let store_name_value = match store {
        crate::StoreKind::Company => "company",
        crate::StoreKind::Personal => "personal",
        crate::StoreKind::Codebase => "codebase",
    };
    let ingested_events: Vec<FactEvent> = data
        .events
        .iter()
        .map(|admitted| admitted.event.clone())
        .collect();
    let cache_freshness = launcher
        .company_cache()?
        .map(|(cache, _root)| cache.freshness(&as_of.as_of));
    let input = ReducerInput {
        store_kind: store_name_value.to_owned(),
        events: data.events,
        unknowns: data.unknowns,
        tombstones: data.tombstones,
        revocations: data.revocations,
        as_of: as_of.as_of.clone(),
        authority_cursor: data.authority_cursor,
        revocation_fresh: cache_freshness
            .as_ref()
            .map(|freshness| freshness.revocation_fresh)
            .unwrap_or(true),
        fact_valid_until: cache_freshness.and_then(|freshness| freshness.fact_valid_until),
        certificate_valid: data.certificate_valid,
        authority_owner_by_scope: data.authority_owner_by_scope,
        steward_authority_id: data.steward_authority_id,
    };
    Ok(StoreView {
        view: crate::reducer::reduce(&input),
        events: ingested_events,
        references,
    })
}

fn event_candidate_value(
    event: &FactEvent,
    conflict_event_ids: &BTreeSet<String>,
    as_of: &str,
) -> Value {
    let expired = event
        .effective_until
        .as_deref()
        .is_some_and(|until| until <= as_of);
    let invariant = event.distortion.loss_if_absent >= 7_000
        && matches!(event.atom_kind.as_str(), "constraint" | "decision");
    let (role, reason) = if conflict_event_ids.contains(&event.event_id) {
        (
            "conflict",
            "event participates in a logical-key conflict".to_owned(),
        )
    } else if invariant {
        (
            "high_distortion_compatibility_invariant",
            "high-loss durable invariant constrains compatible implementations".to_owned(),
        )
    } else if expired || event.disposition == "expired" {
        ("stale", format!("fact is expired as of {as_of}"))
    } else {
        (
            "stale",
            "event was superseded or otherwise not represented by the current view".to_owned(),
        )
    };
    json!({
        "logical_key": event.logical_key,
        "fact_id": event.fact_id,
        "atom_kind": event.atom_kind,
        "standing": crate::model::effective_standing(&event.standing, &event.provenance),
        "claimed_standing": event.standing,
        "provenance": event.provenance,
        "governs_paths": event.governs_paths,
        "anchors": event.anchors,
        "statement": event.statement,
        "scope": event.scope,
        "authority_scope": event.authority_scope,
        "distortion": event.distortion,
        "validity": {
            "status": if expired { "expired" } else { "admitted" },
            "effective_from": event.effective_from,
            "effective_until": event.effective_until
        },
        "role": role,
        "roles": if role == "stale" {
            vec!["stale_fact".to_owned()]
        } else if invariant && role != "conflict" {
            vec![role.to_owned(), "current".to_owned()]
        } else {
            vec![role.to_owned()]
        },
        "derived_role": role,
        "reason": reason,
        "authority_id": event.authority_id,
        "owner_role": if event.store_kind == "company" { "company-steward".to_owned() } else { "repository-maintainer".to_owned() },
        "owner_identity": event.authority_id
    })
}

/// Every fact's derived role, computed once: the paraphrase test needs the
/// set of statements that recur under distinct logical keys, not a scan of
/// every other fact per call.
struct Roles {
    by_id: BTreeMap<String, (&'static str, String)>,
}

impl Roles {
    fn derive(facts: &[CurrentFact]) -> Self {
        let mut keys_by_statement: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
        for fact in facts {
            keys_by_statement
                .entry(normalized_statement(&fact.statement))
                .or_default()
                .insert(fact.logical_key.as_str());
        }
        let duplicated: BTreeSet<String> = keys_by_statement
            .into_iter()
            .filter(|(_, keys)| keys.len() > 1)
            .map(|(statement, _)| statement)
            .collect();
        let by_id = facts
            .iter()
            .map(|fact| {
                let restated = duplicated.contains(&normalized_statement(&fact.statement));
                (fact.fact_id.clone(), candidate_role(fact, restated))
            })
            .collect();
        Self { by_id }
    }

    fn of(&self, fact: &CurrentFact) -> (&'static str, String) {
        self.by_id
            .get(&fact.fact_id)
            .cloned()
            .unwrap_or_else(|| candidate_role(fact, false))
    }

    fn name(&self, fact: &CurrentFact) -> &'static str {
        self.of(fact).0
    }
}

fn candidate_role(fact: &CurrentFact, restated_elsewhere: bool) -> (&'static str, String) {
    if !fact.stale_reasons.is_empty() {
        return ("stale_fact", fact.stale_reasons.join(","));
    }
    if fact.disposition == "conflict" {
        return ("conflict", "fact disposition is conflict".to_owned());
    }
    if fact.disposition == "expired" || fact.disposition == "disputed" {
        return (
            "stale_fact",
            format!("fact disposition is {}", fact.disposition),
        );
    }
    if fact.distortion.loss_if_absent >= 7_000
        && matches!(fact.atom_kind.as_str(), "constraint" | "decision")
    {
        return (
            "high_distortion_compatibility_invariant",
            "high-loss durable invariant constrains compatible implementations".to_owned(),
        );
    }
    match fact.atom_kind.as_str() {
        "test" | "runtime_trace" | "test_runtime_evidence" => {
            return (
                "test",
                "runtime or test evidence validates the decision".to_owned(),
            );
        }
        "rationale" => {
            return (
                "rationale",
                "rationale explains the compatibility invariant".to_owned(),
            );
        }
        _ => {}
    }
    let paraphrase = !fact.redundancy_with.is_empty() || restated_elsewhere;
    if paraphrase {
        return (
            "high_scoring_paraphrase",
            "edge or semantic duplicate restates an already scoreable fact".to_owned(),
        );
    }
    ("current", "selectable current trusted fact".to_owned())
}

fn candidate_priority(role: &str) -> i64 {
    match role {
        "high_distortion_compatibility_invariant" => 4,
        "test" | "rationale" => 3,
        "high_scoring_paraphrase" => 2,
        "high_distortion_unknown" => 1,
        _ => 0,
    }
}

fn normalized_statement(statement: &str) -> String {
    statement
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn candidate_value(fact: &CurrentFact, roles: &Roles) -> Value {
    let (derived_role, reason) = roles.of(fact);
    let primary_role = if derived_role == "high_distortion_compatibility_invariant"
        || derived_role == "high_scoring_paraphrase"
        || derived_role == "test"
        || derived_role == "rationale"
    {
        "current"
    } else {
        derived_role
    };
    let mut roles = vec![derived_role];
    if primary_role != derived_role {
        roles.push(primary_role);
    }
    json!({
        "logical_key": fact.logical_key,
        "fact_id": fact.fact_id,
        "atom_kind": fact.atom_kind,
        "standing": fact.standing,
        "claimed_standing": fact.standing,
        "provenance": fact.provenance,
        "governs_paths": fact.governs_paths,
        "anchors": fact.anchors,
        "statement": fact.statement,
        "scope": fact.scope,
        "authority_scope": fact.authority_scope,
        "distortion": fact.distortion,
        "validity": {
            "status": fact.status,
            "effective_from": fact.effective_from,
            "effective_until": fact.effective_until
        },
        "role": primary_role,
        "roles": roles,
        "derived_role": derived_role,
        "reason": reason,
        "trust": fact.trust,
        "stale_reasons": fact.stale_reasons,
        "store_kind": fact.store_kind,
        "authority_id": fact.authority_id
    })
}

fn unknown_value(unknown: &UnknownOut) -> Value {
    let role = if unknown.loss_if_absent >= 7_000 {
        "high_distortion_unknown"
    } else {
        "unknown"
    };
    json!({
        "role": role,
        "roles": [role],
        "derived_role": role,
        "owner_role": unknown.owner_role,
        "owner_identity": unknown.owner_identity,
        "logical_key": unknown.logical_key,
        "unknown_id": unknown.unknown_id,
        "status": unknown.status,
        "kind": unknown.kind,
        "loss_if_absent": unknown.loss_if_absent,
        "decision_blocked": unknown.decision_blocked,
        "reason": if unknown.kind == "explicit" { format!("{}: {}", unknown.status, unknown.question) } else { format!("{}: {}", unknown.status, unknown.kind) }
    })
}

fn unknown_outputs(
    facts: &[CurrentFact],
    view_unknowns: &[crate::reducer::DerivedUnknown],
    question_unknowns: &[UnknownOut],
) -> Vec<UnknownOut> {
    // Keyed by Unknown id: one logical key may carry several owned Unknowns
    // (the Company fact's own expiry and the repository reference to it).
    let mut by_key: BTreeMap<String, UnknownOut> = BTreeMap::new();
    for unknown in question_unknowns {
        by_key.insert(unknown.unknown_id.clone(), unknown.clone());
    }
    for unknown in view_unknowns {
        if unknown.status != "open" && unknown.status != "asked" {
            continue;
        }
        by_key.insert(
            unknown.unknown_id.clone(),
            UnknownOut {
                unknown_id: unknown.unknown_id.clone(),
                logical_key: unknown.logical_key.clone(),
                scope: unknown.scope.clone(),
                decision_blocked: unknown.decision_blocked.clone(),
                owner_role: unknown.owner_role.clone(),
                owner_identity: unknown.owner_identity.clone(),
                question: unknown.question.clone(),
                evidence: unknown.discriminating_evidence.clone(),
                loss_if_absent: unknown.loss_if_absent,
                status: unknown.status.clone(),
                kind: unknown.kind.clone(),
            },
        );
    }
    let represented_keys: BTreeSet<String> = by_key
        .values()
        .map(|unknown| unknown.logical_key.clone())
        .collect();
    for fact in facts {
        let ineligible = fact.status != "current"
            || fact.trust != "trusted"
            || !fact.stale_reasons.is_empty()
            || matches!(
                fact.disposition.as_str(),
                "disputed" | "expired" | "conflict"
            );
        if ineligible && !represented_keys.contains(&fact.logical_key) {
            let owner_role = if fact.store_kind == "company" {
                "company-steward"
            } else {
                "repository-maintainer"
            };
            let unknown_id = format!("unknown_{}", &fact.fact_id[5.min(fact.fact_id.len())..]);
            if by_key.contains_key(&unknown_id) {
                continue;
            }
            by_key.insert(
                unknown_id.clone(),
                UnknownOut {
                    unknown_id,
                    logical_key: fact.logical_key.clone(),
                    scope: fact.scope.clone(),
                    decision_blocked: fact.distortion.trigger.clone(),
                    owner_role: owner_role.to_owned(),
                    owner_identity: fact.authority_id.clone(),
                    question: format!(
                        "Fact {} is not selectable; refresh or supersede its evidence.",
                        fact.fact_id
                    ),
                    evidence: fact.evidence_refs.clone(),
                    loss_if_absent: fact.distortion.loss_if_absent,
                    status: "open".to_owned(),
                    kind: if fact.stale_reasons.is_empty() {
                        fact.disposition.clone()
                    } else {
                        "stale".to_owned()
                    },
                },
            );
        }
    }
    let mut values: Vec<_> = by_key.into_values().collect();
    values.sort_by(|left, right| {
        right
            .loss_if_absent
            .cmp(&left.loss_if_absent)
            .then_with(|| left.unknown_id.cmp(&right.unknown_id))
    });
    values
}

/// A resident working-set fact re-added to its own set: every gain is already
/// realised, nothing is retrieved, and nothing new is displaced.
fn resident_evaluation() -> Evaluation {
    Evaluation {
        marginal_value: 0,
        newly_covered_distortion: 0,
        authority_and_validity_gain: 0,
        complementarity_gain: 0,
        uncertainty_reduction: 0,
        redundancy: 0,
        retrieval_and_residency_cost: 0,
        stale_or_conflict_risk: 0,
        redundancy_basis: "resident_in_working_set".to_owned(),
        complementarity_basis: "none".to_owned(),
    }
}

/// Score one candidate against the current set `S` (residents plus the
/// facts selected so far) for the declared task and decision.
/// The per-fact work of an evaluation, done once per projection. Selection
/// re-evaluates every candidate on every round, and with a corpus of
/// evidence repositories that is thousands of candidates times dozens of
/// rounds: tokenising each statement and normalising it against every
/// resident fact on every visit took a projection from six seconds to four
/// minutes without changing a single score.
struct EvalCache {
    decision_terms: BTreeSet<String>,
    task_terms: BTreeSet<String>,
    normalized: BTreeMap<String, String>,
    statement_terms: BTreeMap<String, BTreeSet<String>>,
    trigger_terms: BTreeMap<String, BTreeSet<String>>,
    distinctive: BTreeMap<String, BTreeSet<String>>,
    support: BTreeMap<String, BTreeSet<String>>,
    /// Relevance in basis points (2,000 to 10,000) per fact, from `relevance_scores`.
    relevance: BTreeMap<String, i64>,
}

/// BM25 parameters: term-frequency saturation and length normalisation.
const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;
/// Question words weigh this much more when they come from the decision.
const DECISION_WEIGHT: f64 = 1.5;

/// How well each candidate's statement matches the task and decision, scored
/// BM25-style over light-stemmed terms and mapped onto the relevance range
/// (2,000 for no shared term, 10,000 for the best match among the candidates).
/// A shared word counts by how rare it is among the candidates (inverse
/// document frequency), not as one of at most four equal words: a repository's
/// name, shared by every fact about it, no longer weighs what a word naming
/// the one mechanism asked about does.
fn relevance_scores(facts: &[&CurrentFact], task: &str, decision: &str) -> BTreeMap<String, i64> {
    let sets: Vec<(&str, BTreeSet<String>)> = facts
        .iter()
        .map(|fact| (fact.fact_id.as_str(), stemmed_terms(&fact.statement)))
        .collect();
    let mut query: BTreeMap<String, f64> = BTreeMap::new();
    for term in stemmed_terms(task) {
        query.insert(term, 1.0);
    }
    for term in stemmed_terms(decision) {
        query.insert(term, DECISION_WEIGHT);
    }
    let count = sets.len().max(1) as f64;
    let mut frequency: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, set) in &sets {
        for term in set {
            if query.contains_key(term) {
                *frequency.entry(term.as_str()).or_default() += 1;
            }
        }
    }
    let average = (sets.iter().map(|(_, set)| set.len()).sum::<usize>() as f64 / count).max(1.0);
    let scores: Vec<(&str, f64)> = sets
        .iter()
        .map(|(id, set)| {
            let norm = 1.0 + BM25_K1 * (1.0 - BM25_B + BM25_B * set.len() as f64 / average);
            let score = query
                .iter()
                .filter(|(term, _)| set.contains(*term))
                .map(|(term, weight)| {
                    let df = frequency.get(term.as_str()).copied().unwrap_or(0) as f64;
                    let idf = (1.0 + (count - df + 0.5) / (df + 0.5)).ln();
                    weight * idf * (BM25_K1 + 1.0) / norm
                })
                .sum::<f64>();
            (*id, score)
        })
        .collect();
    let best = scores.iter().map(|(_, score)| *score).fold(0.0_f64, f64::max);
    scores
        .into_iter()
        .map(|(id, score)| {
            let bp = if best > 0.0 && score > 0.0 {
                2_000 + (8_000.0 * score / best).round() as i64
            } else {
                2_000
            };
            (id.to_owned(), bp)
        })
        .collect()
}

/// `terms`, each reduced to a light stem (plural and verb endings), so a
/// question about "snapshots" or "validated" meets a fact about a "snapshot"
/// that "validates". Used for relevance only.
fn stemmed_terms(value: &str) -> BTreeSet<String> {
    terms(value).into_iter().map(|term| stem(&term)).collect()
}

fn stem(word: &str) -> String {
    let w = word;
    let n = w.len();
    let cut = |k: usize| w[..n - k].to_owned();
    let stripped = if n > 4 && (w.ends_with("ies") || w.ends_with("ied")) {
        format!("{}y", &w[..n - 3])
    } else if n > 5 && w.ends_with("ing") {
        cut(3)
    } else if n > 4 && w.ends_with("ed") && !w.ends_with("eed") {
        cut(2)
    } else if n > 4 && (w.ends_with("sses") || w.ends_with("xes") || w.ends_with("ches") || w.ends_with("shes")) {
        cut(2)
    } else if n > 3 && w.ends_with('s') && !w.ends_with("ss") && !w.ends_with("us") && !w.ends_with("is") {
        cut(1)
    } else {
        w.to_owned()
    };
    // A silent final e goes too, so "validate", "validates", "validated" and
    // "validating" all reduce to "validat".
    if stripped.len() > 3 && stripped.ends_with('e') && !stripped.ends_with("ee") {
        stripped[..stripped.len() - 1].to_owned()
    } else {
        stripped
    }
}

impl EvalCache {
    fn new(facts: &[&CurrentFact], task: &str, decision: &str) -> Self {
        let mut normalized = BTreeMap::new();
        let mut statement_terms = BTreeMap::new();
        let mut trigger_terms = BTreeMap::new();
        let mut distinctive = BTreeMap::new();
        let mut support = BTreeMap::new();
        for fact in facts {
            normalized.insert(fact.fact_id.clone(), normalized_statement(&fact.statement));
            statement_terms.insert(fact.fact_id.clone(), terms(&fact.statement));
            trigger_terms.insert(fact.fact_id.clone(), terms(&fact.distortion.trigger));
            distinctive.insert(fact.fact_id.clone(), distinctive_terms(&fact.statement));
            support.insert(fact.fact_id.clone(), support_ids(fact));
        }
        Self {
            decision_terms: terms(decision),
            task_terms: terms(task),
            normalized,
            statement_terms,
            trigger_terms,
            distinctive,
            support,
            relevance: relevance_scores(facts, task, decision),
        }
    }

    fn distinctive(&self, fact: &CurrentFact) -> std::borrow::Cow<'_, BTreeSet<String>> {
        match self.distinctive.get(&fact.fact_id) {
            Some(value) => std::borrow::Cow::Borrowed(value),
            None => std::borrow::Cow::Owned(distinctive_terms(&fact.statement)),
        }
    }

    fn support(&self, fact: &CurrentFact) -> std::borrow::Cow<'_, BTreeSet<String>> {
        match self.support.get(&fact.fact_id) {
            Some(value) => std::borrow::Cow::Borrowed(value),
            None => std::borrow::Cow::Owned(support_ids(fact)),
        }
    }

    fn normalized(&self, fact: &CurrentFact) -> std::borrow::Cow<'_, str> {
        match self.normalized.get(&fact.fact_id) {
            Some(value) => std::borrow::Cow::Borrowed(value.as_str()),
            None => std::borrow::Cow::Owned(normalized_statement(&fact.statement)),
        }
    }

    fn statement_terms(&self, fact: &CurrentFact) -> std::borrow::Cow<'_, BTreeSet<String>> {
        match self.statement_terms.get(&fact.fact_id) {
            Some(value) => std::borrow::Cow::Borrowed(value),
            None => std::borrow::Cow::Owned(terms(&fact.statement)),
        }
    }

    fn trigger_terms(&self, fact: &CurrentFact) -> std::borrow::Cow<'_, BTreeSet<String>> {
        match self.trigger_terms.get(&fact.fact_id) {
            Some(value) => std::borrow::Cow::Borrowed(value),
            None => std::borrow::Cow::Owned(terms(&fact.distortion.trigger)),
        }
    }
}

fn evaluate(
    fact: &CurrentFact,
    current_set: &[CurrentFact],
    task: &str,
    decision: &str,
) -> Evaluation {
    let cache = EvalCache::new(&[fact], task, decision);
    evaluate_cached(fact, current_set, &cache)
}

fn evaluate_cached(
    fact: &CurrentFact,
    current_set: &[CurrentFact],
    cache: &EvalCache,
) -> Evaluation {
    evaluate_folded(fact, &SetFold::of(fact, current_set, cache), cache)
}

fn evaluate_folded(fact: &CurrentFact, set: &SetFold, cache: &EvalCache) -> Evaluation {
    let decision_terms = &cache.decision_terms;
    let task_terms = &cache.task_terms;
    let statement_terms = cache.statement_terms(fact);
    let decision_overlap = statement_terms.intersection(decision_terms).count().min(4) as i64;
    let task_overlap = statement_terms.intersection(task_terms).count().min(4) as i64;
    // Range matters more than the shape: at 3000 + small increments every
    // candidate landed within a third of every other, so `loss_if_absent`
    // decided the order and the most emphatic fact won every question whatever
    // was asked. A fact that shares nothing with the question keeps a floor --
    // context without lexical overlap is still context -- but it must not
    // outrank one that answers it.
    let relevance = cache.relevance.get(&fact.fact_id).copied().unwrap_or_else(|| {
        (2_000 + decision_overlap.saturating_mul(1_500) + task_overlap.saturating_mul(1_000))
            .min(10_000)
    });
    // Distortion already covered by an equivalent member of S is not newly
    // covered: a paraphrase of a resident fact covers nothing new.
    let covered_by_set = set.covered;
    // The trigger names the decision a fact exists to settle. Full weight goes
    // to a fact whose *trigger* the question is about -- not one whose own
    // statement merely mentions its own trigger, which every honestly written
    // fact does by construction and which therefore granted the bypass to
    // everything. Asking about reconcilers must not hand full weight to an
    // invariant about pricing simply because the invariant is well-formed.
    let trigger_terms = cache.trigger_terms(fact);
    let question_is_about_this = trigger_terms.intersection(decision_terms).count()
        + trigger_terms.intersection(task_terms).count()
        > 0;
    let own_trigger = !trigger_terms.is_empty()
        && trigger_terms
            .iter()
            .all(|term| statement_terms.contains(term));
    let newly_covered = if covered_by_set {
        0
    } else if own_trigger && question_is_about_this {
        i64::from(fact.distortion.loss_if_absent)
    } else {
        i64::from(fact.distortion.loss_if_absent)
            .saturating_mul(relevance)
            .saturating_div(10_000)
    };
    let authority_gain = {
        let base =
            if fact.authority_scope.starts_with("architecture") || fact.store_kind == "company" {
                800
            } else {
                300
            };
        base + (i64::from(fact.confidence) / 20).min(500)
    };
    let (complementarity, complementarity_basis) =
        set.complement.clone().unwrap_or((0, "none".to_owned()));
    let uncertainty = (i64::try_from(fact.independent_support_count)
        .unwrap_or(i64::MAX)
        .saturating_mul(250))
    .min(1_000)
        + if fact.company_refs.is_empty() { 0 } else { 250 };
    let (redundancy, redundancy_basis) = set.edge.clone().unwrap_or_else(|| set.lexical.clone());
    let cost = 250;
    let stale = 0;
    Evaluation {
        marginal_value: newly_covered + authority_gain + complementarity + uncertainty
            - redundancy
            - cost
            - stale,
        newly_covered_distortion: newly_covered,
        authority_and_validity_gain: authority_gain,
        complementarity_gain: complementarity,
        uncertainty_reduction: uncertainty,
        redundancy,
        retrieval_and_residency_cost: cost,
        stale_or_conflict_risk: stale,
        redundancy_basis,
        complementarity_basis,
    }
}

/// Company-owned direction, as opposed to evidence from this repository.
fn is_direction(fact: &CurrentFact) -> bool {
    fact.store_kind == "company"
}

fn covers_own_trigger(fact: &CurrentFact) -> bool {
    let trigger = terms(&fact.distortion.trigger);
    if trigger.is_empty() {
        return false;
    }
    let statement = terms(&fact.statement);
    trigger.iter().all(|term| statement.contains(term))
}

/// Evidence class of an atom: test/runtime/observation evidence versus the
/// rationale, constraint or decision it can evidence. Complementarity needs
/// one of each.
fn evidence_class(atom_kind: &str) -> Option<&'static str> {
    match atom_kind {
        "observation" | "test" | "runtime_trace" | "test_runtime_evidence" => Some("evidence"),
        "rationale" | "constraint" | "decision" => Some("explanation"),
        _ => None,
    }
}

/// The subject a hierarchical logical key names: its last path segment.
fn key_subject(logical_key: &str) -> Option<&str> {
    let (_, subject) = logical_key.rsplit_once('/')?;
    if subject.is_empty() {
        None
    } else {
        Some(subject)
    }
}

/// Two-letter grammar. Almost every two-character English word is grammar, and
/// almost every two-character identifier is not: `Db`, `Tx`, `Id`, `Ok`. A
/// length floor cannot tell them apart, so it dropped both -- which meant a
/// fact about `Db` could not match a question about `Db`, and the census
/// measurement of the most-copied class in the estate was unreachable by name.
/// Drop grammar by name instead.
const TINY_STOPWORDS: [&str; 30] = [
    "of", "to", "in", "is", "it", "as", "at", "by", "on", "or", "an", "be", "we", "do", "if", "no",
    "so", "up", "my", "me", "he", "us", "am", "re", "vs", "et", "al", "eg", "ie", "the",
];

/// Three-letter grammar. The list above is applied where a four-character floor
/// already excludes these; `terms` admits three-character words because real
/// vocabulary lives there (`api`, `sql`, `dao`, `fee`), so it needs both.
const SHORT_STOPWORDS: [&str; 36] = [
    // "the" above all: it is three letters, so the four-character floor the
    // other list assumes never excluded it, and every candidate scored a free
    // relevance point for sharing it with the question. Two facts about nothing
    // in common looked equally on-topic and `loss_if_absent` broke the tie.
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can", "had", "was", "one",
    "our", "out", "get", "has", "how", "its", "new", "now", "see", "two", "way", "who", "did",
    "she", "her", "him", "his", "why", "yes", "off", "too", "yet", "let",
];

const STOPWORDS: [&str; 44] = [
    "this", "that", "with", "from", "than", "then", "they", "them", "have", "been", "were", "will",
    "must", "into", "when", "which", "what", "where", "while", "also", "only", "over", "under",
    "about", "because", "cannot", "remain", "should", "would", "could", "their", "there", "these",
    "those", "here", "such", "each", "other", "some", "more", "most", "very", "after", "before",
];

fn distinctive_terms(statement: &str) -> BTreeSet<String> {
    terms(statement)
        .into_iter()
        .filter(|term| term.len() >= 4 && !STOPWORDS.contains(&term.as_str()))
        .collect()
}

/// Complementarity: a test/runtime/observation and the rationale, constraint
/// or decision it evidences are jointly useful when they address one subject.
/// The subject link is an explicit `complements` edge, a shared logical-key
/// subject, or shared distinctive vocabulary; the trace names which.
fn support_ids(fact: &CurrentFact) -> BTreeSet<String> {
    fact.support_event_ids
        .iter()
        .chain(fact.evidence_refs.iter())
        .cloned()
        .collect()
}

/// Complementarity with one member of the set; the set's value is the first
/// member, in set order, that complements the fact.
fn complement_with(
    fact: &CurrentFact,
    existing: &CurrentFact,
    cache: &EvalCache,
) -> Option<(i64, String)> {
    const GAIN: i64 = 2_500;
    if fact.complements.contains(&existing.fact_id) || existing.complements.contains(&fact.fact_id) {
        return Some((GAIN, format!("explicit_edge:{}", existing.fact_id)));
    }
    let (Some(left), Some(right)) = (
        evidence_class(&fact.atom_kind),
        evidence_class(&existing.atom_kind),
    ) else {
        return None;
    };
    if left == right {
        return None;
    }
    if let (Some(subject), Some(other)) = (
        key_subject(&fact.logical_key),
        key_subject(&existing.logical_key),
    ) {
        if subject == other && fact.logical_key != existing.logical_key {
            return Some((GAIN, format!("shared_subject_key:{subject}")));
        }
    }
    let fact_terms = cache.distinctive(fact);
    let existing_terms = cache.distinctive(existing);
    if fact_terms.intersection(&existing_terms).nth(1).is_none() {
        return None;
    }
    let shared: Vec<&str> = fact_terms
        .intersection(&existing_terms)
        .map(String::as_str)
        .collect();
    Some((GAIN, format!("shared_subject_terms:{}", shared.join(","))))
}

/// A high-loss constraint or decision: redundancy reduces its value but is
/// capped so it stays recoverable.
fn protected_invariant(fact: &CurrentFact) -> bool {
    fact.distortion.loss_if_absent >= 7_000
        && matches!(fact.atom_kind.as_str(), "constraint" | "decision")
}

/// Redundancy through an explicit edge or shared provenance with one member;
/// the first member, in set order, that has one decides.
fn redundancy_edge_with(
    fact: &CurrentFact,
    existing: &CurrentFact,
    cache: &EvalCache,
) -> Option<(i64, String)> {
    let protected = protected_invariant(fact);
    let explicit = fact.redundancy_with.contains(&existing.fact_id)
        || existing.redundancy_with.contains(&fact.fact_id);
    if explicit {
        return Some(if protected {
            (2_000, format!("protected_invariant_explicit_edge:{}", existing.fact_id))
        } else {
            (8_000, format!("explicit_edge:{}", existing.fact_id))
        });
    }
    let fact_support = cache.support(fact);
    let existing_support = cache.support(existing);
    if fact_support.iter().any(|id| existing_support.contains(id)) {
        return Some(if protected {
            (1_000, format!("protected_invariant_shared_provenance:{}", existing.fact_id))
        } else {
            (3_000, format!("shared_provenance:{}", existing.fact_id))
        });
    }
    None
}

/// Lexical redundancy with one member, when the statements are near
/// duplicates; the set's value is the largest, earliest member on ties.
fn lexical_redundancy_with(
    fact: &CurrentFact,
    existing: &CurrentFact,
    cache: &EvalCache,
) -> Option<(i64, String)> {
    let fact_terms = cache.statement_terms(fact);
    let existing_terms = cache.statement_terms(existing);
    let intersection = fact_terms.intersection(&existing_terms).count() as i64;
    let total = fact_terms.len() as i64 + existing_terms.len() as i64;
    if total == 0 {
        return None;
    }
    let similarity = intersection
        .saturating_mul(2)
        .saturating_mul(10_000)
        .saturating_div(total);
    if similarity < 6_000 {
        return None;
    }
    // A near-duplicate may reduce value, but a distinct high-loss
    // invariant must remain recoverable. Complementary test/rationale
    // evidence is likewise capped so its gain is reported
    // separately instead of being erased by lexical redundancy.
    let complementary = evidence_class(&fact.atom_kind).is_some()
        && evidence_class(&existing.atom_kind).is_some()
        && evidence_class(&fact.atom_kind) != evidence_class(&existing.atom_kind);
    let ceiling = if protected_invariant(fact) || complementary {
        2_000
    } else {
        10_000
    };
    let penalty = similarity.min(ceiling);
    (penalty > 0).then(|| (penalty, format!("lexical_similarity:{similarity}:{}", existing.fact_id)))
}

/// Everything an evaluation depends on from the current set, folded member by
/// member in set order: coverage by an equivalent member, complementarity,
/// and redundancy (explicit edges and shared provenance first, then lexical
/// similarity). Selection only ever appends to the set, so a
/// candidate's fold carries from one round to the next and absorbs just the
/// newly selected fact; folding the whole set gives exactly what scanning it
/// gave.
#[derive(Clone)]
struct SetFold {
    covered: bool,
    complement: Option<(i64, String)>,
    edge: Option<(i64, String)>,
    lexical: (i64, String),
}

impl SetFold {
    fn new() -> Self {
        Self { covered: false, complement: None, edge: None, lexical: (0, "none".to_owned()) }
    }

    fn of(fact: &CurrentFact, set: &[CurrentFact], cache: &EvalCache) -> Self {
        let mut fold = Self::new();
        for existing in set {
            fold.absorb(fact, existing, cache);
        }
        fold
    }

    fn absorb(&mut self, fact: &CurrentFact, existing: &CurrentFact, cache: &EvalCache) {
        if !self.covered {
            self.covered = existing.logical_key == fact.logical_key
                || cache.normalized(existing) == cache.normalized(fact);
        }
        if self.complement.is_none() {
            self.complement = complement_with(fact, existing, cache);
        }
        if self.edge.is_none() {
            self.edge = redundancy_edge_with(fact, existing, cache);
        }
        if let Some(lexical) = lexical_redundancy_with(fact, existing, cache) {
            if lexical.0 > self.lexical.0 {
                self.lexical = lexical;
            }
        }
    }
}

fn is_authority_answer(fact: &CurrentFact) -> bool {
    fact.store_kind == "company"
        && fact.atom_kind == "decision"
        && fact
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("answer_"))
}

fn company_reference(selected: &[CurrentFact], all_facts: &[CurrentFact]) -> Option<String> {
    let company_facts: BTreeMap<&str, &CurrentFact> = all_facts
        .iter()
        .filter(|fact| fact.store_kind == "company")
        .map(|fact| (fact.fact_id.as_str(), fact))
        .collect();
    for fact in selected {
        for reference in &fact.company_refs {
            if let Some(company_fact) = company_facts.get(reference.fact_id.as_str()) {
                return Some(company_fact.statement.clone());
            }
        }
    }
    None
}

/// Topical words only.
///
/// Relevance is measured as term overlap, and until this filter existed the
/// overlap was mostly grammar: "what pattern should the reconciler follow"
/// shares "the" and "should" with almost any statement, so nearly every
/// candidate reached the same relevance and `loss_if_absent` became the only
/// thing ordering a projection. The most emphatic facts then won every
/// question regardless of what was asked -- sixteen invariants and not one
/// mention of the subject.
fn terms(value: &str) -> BTreeSet<String> {
    value
        .to_lowercase()
        .split(|character: char| !character.is_alphanumeric())
        .filter(|part| {
            part.len() >= 2
                && !TINY_STOPWORDS.contains(part)
                && !STOPWORDS.contains(part)
                && !SHORT_STOPWORDS.contains(part)
        })
        .map(str::to_owned)
        .collect()
}

/// Direction older than this without re-affirmation is served as stale, not
/// as fact: a copy of an outside decision is a reference to a point in time.
const DIRECTION_STALE_AFTER_DAYS: i64 = 180;

fn days_between(earlier: &str, later: &str) -> Option<i64> {
    let a = crate::time::parse_rfc3339_millis(earlier).ok()?;
    let b = crate::time::parse_rfc3339_millis(later).ok()?;
    Some((b - a).num_days())
}

/// Path-like tokens in free text: anything containing a `/` that looks like a
/// repository path rather than a URL.
fn path_tokens(text: &str) -> Vec<String> {
    text.split(|c: char| {
        c.is_whitespace() || matches!(c, '`' | '"' | '\'' | '(' | ')' | ',' | ';' | ':')
    })
    .filter(|t| t.contains('/') && !t.contains("://") && !t.starts_with('/'))
    .map(|t| t.trim_end_matches('.').to_owned())
    .filter(|t| t.len() > 3)
    .collect()
}

fn direction_row(fact: &CurrentFact, as_of: &str) -> Value {
    let age_days = days_between(&fact.effective_from, as_of);
    json!({
        "logical_key": fact.logical_key,
        "statement": fact.statement,
        "standing": fact.standing,
        "provenance": fact.provenance,
        "owner": fact.authority_id,
        "as_of": fact.effective_from,
        "age_days": age_days,
        "stale": age_days.is_some_and(|d| d > DIRECTION_STALE_AFTER_DAYS),
        "not_yet_built": not_yet_built(fact),
    })
}

/// A row that describes something planned rather than running: a greenfield
/// service, a spec with no repository, a catalog entry marked NEW, a planning
/// item. A plan that builds on it is building on air; the brief says so and
/// asks the user for an override or an alternative before work proceeds.
fn not_yet_built(fact: &CurrentFact) -> bool {
    let statement = fact.statement.as_str();
    let key = fact.logical_key.as_str();
    // An ownership ruling names an owner; it is not the thing being built,
    // however its statement describes the repository it governs.
    if key.starts_with("ownership/") {
        return false;
    }
    key.contains("/in-discussion-brief-planning/")
        || statement.contains("Greenfield")
        || statement.contains("greenfield")
        || statement.contains("No repository")
        || statement.contains("No repo ")
        || statement.contains("**Status:** NEW")
        || statement.contains("Status: NEW")
        || statement.contains("not near-term")
        || statement.contains("does not exist yet")
}

/// The rows every brief carries whole: the architectural guidance and the
/// numbered invariants.
const STANDING_PREFIXES: [&str; 2] = [
    "architecture/architectural-guidance/",
    "architecture/architecture-notes/3-invariants/",
];

/// Guidance first in key order, then invariants in numeric order (I-2 before
/// I-10), so the block reads the way the source document does.
fn standing_order(key: &str) -> (u8, u32, String) {
    if let Some(rest) = key.strip_prefix("architecture/architecture-notes/3-invariants/") {
        let number = rest
            .trim_start_matches("i-")
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|digits| digits.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        return (1, number, rest.to_owned());
    }
    (0, 0, key.to_owned())
}

/// Control characters folded to single spaces; runs collapsed.
fn fold_control_characters(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_control() || ch == ' ' {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(ch);
    }
    out
}

/// The names a repository-level ruling (`ownership/repo/<name>`) calls its
/// repository by: the key's leaf, and the leaf of each `org/repo` identity it
/// governs. Uuids are governed too but are never what a sentence says.
fn ruling_repository_names(fact: &CurrentFact) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(leaf) = fact.logical_key.strip_prefix("ownership/repo/") {
        names.push(leaf.trim_matches('/').to_owned());
    }
    for governed in &fact.governs_paths {
        let governed = governed.trim().trim_matches('/');
        if let Some((_, leaf)) = governed.rsplit_once('/') {
            names.push(leaf.to_owned());
        }
    }
    names.retain(|name| !name.is_empty());
    names
}

/// The repository a per-path ruling governs, as the ticket names it: the first
/// segment of the governing prefix the ticket path matched (`legacy/src/x`
/// names `legacy`). The ticket path's own leaf is a file name, never a
/// repository, so it cannot stand in.
fn prefix_repository_names(fact: &CurrentFact, path: &str) -> Vec<String> {
    fact.governs_paths
        .iter()
        .map(|prefix| prefix.trim_end_matches('/'))
        .filter(|prefix| path.starts_with(prefix))
        .filter_map(|prefix| prefix.split('/').find(|segment| !segment.is_empty()))
        .map(str::to_owned)
        .collect()
}

/// Whether `statement` says work moves "out of <name>", ignoring case, with
/// `name` ending at a word boundary so `out of core` does not match
/// `out of corenet`.
fn names_out_of(statement: &str, name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() {
        return false;
    }
    let statement = statement.to_lowercase();
    let needle = format!("out of {}", name.to_lowercase());
    statement.match_indices(&needle).any(|(at, _)| {
        statement[at + needle.len()..]
            .chars()
            .next()
            .is_none_or(|next| !(next.is_alphanumeric() || next == '_' || next == '-'))
    })
}

/// The brief a projection carries above its selected facts.
fn direction_brief(
    facts: &[CurrentFact],
    selected: &[CurrentFact],
    task: &str,
    decision: &str,
    as_of: &str,
    repository_uuid: &str,
) -> Value {
    let company: Vec<&CurrentFact> = facts
        .iter()
        .filter(|f| f.store_kind == "company" && f.status == "current" && f.trust == "trusted")
        .collect();
    let question = format!("{task}\n{decision}");
    let question_terms = terms(&question);

    // Target-state owner: an `ownership/` fact whose governed path prefixes the
    // paths the ticket names. No fact is a reportable answer, not a guess.
    let paths = path_tokens(&question);
    let mut owners = Vec::new();
    // Parallel to `owners`: the repository names each owner's governing
    // prefix carries, kept out of the brief's JSON so its shape is unchanged.
    let mut owner_names: Vec<Vec<String>> = Vec::new();
    for fact in company
        .iter()
        .filter(|f| f.logical_key.starts_with("ownership/") && !f.logical_key.starts_with("ownership/repo/"))
    {
        for path in &paths {
            if fact
                .governs_paths
                .iter()
                .any(|prefix| path.starts_with(prefix.trim_end_matches('/')))
            {
                owners.push(json!({"path": path, "row": direction_row(fact, as_of)}));
                owner_names.push(prefix_repository_names(fact, path));
            }
        }
    }
    // Repository-level owner: an `ownership/repo/` fact that governs the
    // repository the projection is for, by uuid. A ticket in payment gets
    // the Payment Service as owner whether or not it names a path.
    let governs_repository = |fact: &CurrentFact| -> bool {
        fact.logical_key.starts_with("ownership/repo/")
            && !repository_uuid.is_empty()
            && fact.governs_paths.iter().any(|g| g == repository_uuid)
    };
    let repository_owner_fact: Option<&CurrentFact> =
        company.iter().copied().find(|f| governs_repository(f));
    let repository_owner: Option<Value> = repository_owner_fact.map(|f| direction_row(f, as_of));
    // Direction by ownership: an ownership fact cites the rows that justify
    // it (evidence_refs of the form `row:<logical key>`). Those rows govern
    // any ticket that touches the prefix, whatever words the ticket uses, so
    // they are delivered without a lexical match. This is how "the monorepo is
    // retiring" reaches a ticket that says "platform" and "user-agent".
    let mut cited: Vec<Value> = Vec::new();
    let mut cited_keys: BTreeSet<String> = BTreeSet::new();
    for fact in company
        .iter()
        .filter(|f| f.logical_key.starts_with("ownership/"))
    {
        let governs_named = governs_repository(fact)
            || paths.iter().any(|path| {
                fact.governs_paths
                    .iter()
                    .any(|prefix| path.starts_with(prefix.trim_end_matches('/')))
            });
        if !governs_named {
            continue;
        }
        for reference in &fact.evidence_refs {
            if let Some(key) = reference.strip_prefix("row:") {
                if cited_keys.insert(key.to_owned()) {
                    if let Some(row) = company.iter().find(|f| f.logical_key == key) {
                        cited.push(direction_row(row, as_of));
                    }
                }
            }
        }
    }
    // A ticket that names code whose target-state owner is another component
    // is a conflict between the ticket and direction. That is the owner's call,
    // not the agent's: the brief carries a question to raise before planning.
    let mut questions: Vec<Value> = Vec::new();
    // The words a ruling uses when the code in front of the agent is not
    // where the work belongs: the module is transitional, the monorepo is
    // retiring, landing here is for emergencies, work refactors out.
    //
    // One clause used to hard-code a particular company's name here — a proper
    // noun in a live predicate, so the tool classified one deployment's rulings
    // and nobody else's. Deleting it alone would have narrowed the behaviour for
    // that deployment and widened it for none, because every surviving clause is
    // a fixed English phrase. The generic form derives the phrase from the
    // governing repository's OWN name, so "move it out of <repo>" is recognised
    // for every deployment rather than for one.
    let retiring = |statement: &str, repositories: &[String]| -> bool {
        statement.contains("transitional")
            || statement.contains("retir")
            || statement.contains("out of the monorepo")
            || statement.contains("emergenc")
            || statement.contains("refactor out")
            || repositories
                .iter()
                .any(|name| names_out_of(statement, name))
    };
    if let (Some(row), Some(fact)) = (&repository_owner, repository_owner_fact) {
        let statement = row["statement"].as_str().unwrap_or_default();
        // The repository's names come from the ruling itself: its logical key
        // and the `org/repo` identities it governs. A row built by
        // `direction_row` carries neither, which is why reading `subject` or
        // `path` off the row left this clause unable to fire.
        if retiring(statement, &ruling_repository_names(fact)) {
            questions.push(json!({
                "kind": "ownership_conflict",
                "path": "",
                "owner_row": row["logical_key"],
                "owner": row["owner"],
                "question": format!(
                    "This repository is retiring or its target-state owner is elsewhere ({}). Should this work land here, land with the owner, or wait? Ask the owner before planning.",
                    statement.split(". ").next().unwrap_or(statement)
                ),
            }));
        }
    }
    for (owner, names) in owners.iter().zip(&owner_names) {
        let statement = owner["row"]["statement"].as_str().unwrap_or_default();
        if retiring(statement, names) {
            questions.push(json!({
                "kind": "ownership_conflict",
                "path": owner["path"],
                "owner_row": owner["row"]["logical_key"],
                "owner": owner["row"]["owner"],
                "question": format!(
                    "The ticket names {}, whose target-state owner is elsewhere ({}). Should this work land there, land here as a transitional change, or wait? Ask the owner before planning.",
                    owner["path"].as_str().unwrap_or_default(),
                    statement.split(". ").next().unwrap_or(statement)
                ),
            }));
        }
    }
    let mut ownership = if !owners.is_empty() {
        json!({"status": "resolved", "paths": paths, "owners": owners})
    } else if repository_owner.is_some() {
        json!({"status": "resolved_repository", "paths": paths})
    } else if paths.is_empty() {
        json!({"status": "no_paths_named", "paths": []})
    } else {
        json!({"status": "no_ownership_fact", "paths": paths})
    };
    ownership["repository"] = repository_owner.clone().unwrap_or(Value::Null);

    // Vocabulary: a ratified-vocabulary row whose term the ticket uses.
    let mut collisions = Vec::new();
    for fact in &company {
        let Some(term) = fact
            .logical_key
            .split("ratified-vocabulary/")
            .nth(1)
            .and_then(|tail| tail.split('/').next())
        else {
            continue;
        };
        let term = term.replace('-', " ");
        if question_terms.contains(&term) || question.to_lowercase().contains(&format!(" {term} "))
        {
            collisions.push(json!({"term": term, "row": direction_row(fact, as_of)}));
        }
    }

    // Where direction lives: the architecture notes by section, with counts.
    let mut sections: BTreeMap<String, usize> = BTreeMap::new();
    for fact in &company {
        if let Some(rest) = fact
            .logical_key
            .strip_prefix("architecture/architecture-notes/")
        {
            let section = rest.split('/').next().unwrap_or(rest).to_owned();
            *sections.entry(section).or_insert(0) += 1;
        }
    }
    let index: Vec<Value> = sections
        .into_iter()
        .map(|(section, rows)| json!({"section": section, "rows": rows, "key_prefix": format!("architecture/architecture-notes/{section}/")}))
        .collect();

    // Standing rules: the architectural guidance and the invariants are a
    // bounded set that governs every ticket. They reach the brief whole, not
    // by the luck of a ticket's words matching theirs; the term-overlap
    // selection then only has to find the ticket-specific rows.
    let mut standing_facts: Vec<&CurrentFact> = company
        .iter()
        .copied()
        .filter(|f| STANDING_PREFIXES.iter().any(|p| f.logical_key.starts_with(p)))
        .collect();
    standing_facts.sort_by_key(|f| standing_order(&f.logical_key));
    let standing_keys: BTreeSet<&str> = standing_facts.iter().map(|f| f.logical_key.as_str()).collect();
    let standing: Vec<Value> = standing_facts.iter().map(|f| direction_row(f, as_of)).collect();

    // Governing direction: the company facts the selection chose, as rows
    // with owner and age, so the caller never has to look them up. Rows the
    // standing block already carries are not repeated here.
    let governing: Vec<Value> = selected
        .iter()
        .filter(|f| f.store_kind == "company" && !standing_keys.contains(f.logical_key.as_str()))
        .map(|f| direction_row(f, as_of))
        .collect();

    // Not yet built: every delivered row that describes a planned thing
    // raises a question. Proceeding on it needs the user's override or an
    // alternative; a weak model reads "greenfield" as "available".
    for row in cited.iter().chain(governing.iter()) {
        if row["not_yet_built"].as_bool() == Some(true) {
            let statement = row["statement"].as_str().unwrap_or_default();
            questions.push(json!({
                "kind": "not_yet_built",
                "row": row["logical_key"],
                "question": format!(
                    "Row {} describes something not yet built ({}). Do not build on it as if it existed: ask the user for an override (build against the planned contract anyway) or an alternative (the running component to use until it exists).",
                    row["logical_key"].as_str().unwrap_or_default(),
                    statement.split(". ").next().unwrap_or(statement).chars().take(160).collect::<String>()
                ),
            }));
        }
    }

    json!({
        "target_state_owner": ownership,
        "questions": questions,
        "direction_by_ownership": cited,
        "vocabulary_collisions": collisions,
        "direction_index": index,
        "governing_direction": governing,
        "standing_direction": standing,
        "stale_after_days": DIRECTION_STALE_AFTER_DAYS,
    })
}

#[cfg(test)]
mod brief_tests {
    use super::*;

    #[test]
    fn a_repository_level_ruling_resolves_by_identity_and_delivers_its_rows() {
        let spec = company_fact(
            "architecture/delta-current-state-to-target/payment-spec-07",
            "Delta — Payment — spec 07. example/payment, largest and most mature.",
            &[],
            &[],
        );
        let owner = company_fact(
            "ownership/repo/payment",
            "Target-state owner of example/payment: Payment Service (spec 07). Status: live, refactoring.",
            &["uuid-payment", "example/payment"],
            &["row:architecture/delta-current-state-to-target/payment-spec-07"],
        );
        let retiring = company_fact(
            "ownership/repo/monorepo",
            "Target-state owner of example/monorepo: the retiring monorepo. Landing in monorepo/ is for emergencies only.",
            &["uuid-monorepo", "example/monorepo"],
            &[],
        );
        let facts = vec![spec, owner, retiring];
        let brief = direction_brief(
            &facts,
            &facts,
            "Add a disbursement rule for management fees",
            "",
            "2026-09-13T00:00:00.000Z",
            "uuid-payment",
        );
        assert_eq!(brief["target_state_owner"]["status"], "resolved_repository");
        assert_eq!(brief["target_state_owner"]["repository"]["logical_key"], "ownership/repo/payment");
        assert_eq!(brief["direction_by_ownership"][0]["logical_key"], "architecture/delta-current-state-to-target/payment-spec-07");
        assert!(brief["questions"].as_array().unwrap().is_empty());
        let monorepo = direction_brief(&facts, &facts, "Fix a null check", "", "2026-09-13T00:00:00.000Z", "uuid-monorepo");
        assert_eq!(monorepo["target_state_owner"]["status"], "resolved_repository");
        assert_eq!(monorepo["questions"][0]["kind"], "ownership_conflict");
        let nobody = direction_brief(&facts, &facts, "Fix a null check", "", "2026-09-13T00:00:00.000Z", "uuid-other");
        assert_eq!(nobody["target_state_owner"]["status"], "no_paths_named");
        assert!(nobody["target_state_owner"]["repository"].is_null());
    }

    /// A ruling that says only "out of <repo>" — none of the fixed English
    /// phrases — must still raise the conflict, at both call sites. The first
    /// generic form read the repository's name off the brief row (which carries
    /// none) and off the ticket path's leaf (a file name), so this clause could
    /// never fire.
    #[test]
    fn a_ruling_that_moves_work_out_of_its_named_repository_is_a_conflict() {
        let repository = company_fact(
            "ownership/repo/legacy-core",
            "Target-state owner of example/legacy-core: the Platform Service. New work moves out of legacy-core.",
            &["uuid-legacy", "example/legacy-core"],
            &[],
        );
        let billing = company_fact(
            "ownership/legacy-core-billing",
            "Billing moves out of legacy-core into the Payment Service.",
            &["legacy-core/src/billing"],
            &[],
        );
        let facts = vec![repository, billing];

        let by_repository = direction_brief(
            &facts,
            &facts,
            "Fix a null check",
            "",
            "2026-09-13T00:00:00.000Z",
            "uuid-legacy",
        );
        let questions = by_repository["questions"].as_array().unwrap();
        assert_eq!(questions.len(), 1, "{questions:?}");
        assert_eq!(questions[0]["kind"], "ownership_conflict");
        assert_eq!(questions[0]["owner_row"], "ownership/repo/legacy-core");

        let by_path = direction_brief(
            &facts,
            &facts,
            "Fix rounding in legacy-core/src/billing/invoice.ts",
            "",
            "2026-09-13T00:00:00.000Z",
            "",
        );
        let questions = by_path["questions"].as_array().unwrap();
        assert_eq!(questions.len(), 1, "{questions:?}");
        assert_eq!(questions[0]["path"], "legacy-core/src/billing/invoice.ts");
        assert_eq!(questions[0]["owner_row"], "ownership/legacy-core-billing");

        // A longer name sharing the prefix is a different repository.
        assert!(!super::names_out_of(
            "Work moves out of legacy-core2.",
            "legacy-core"
        ));
        assert!(super::names_out_of(
            "Work moves Out Of Legacy-Core/ soon.",
            "legacy-core"
        ));
    }

    #[test]
    fn a_multi_line_task_is_folded_to_one_line() {
        assert_eq!(super::fold_control_characters("PAY-1\n\nline two\ttabbed  wide"), "PAY-1 line two tabbed wide");
        assert_eq!(super::fold_control_characters("\n leading"), "leading");
    }

    #[test]
    fn standing_rules_reach_every_brief_and_are_not_repeated_as_governing_rows() {
        let invariant = company_fact(
            "architecture/architecture-notes/3-invariants/i-14",
            "I-14 Request/response over Baton by default.",
            &[],
            &[],
        );
        let guidance = company_fact(
            "architecture/architectural-guidance/data/caches-narrow-authorities-decide",
            "Caches narrow; authorities decide.",
            &[],
            &[],
        );
        let roadmap = company_fact(
            "architecture/platform-1-september-to-end-of-year/being-built/software-factory",
            "Software Factory, TOOL, 87%.",
            &[],
            &[],
        );
        let facts = vec![invariant.clone(), guidance.clone(), roadmap.clone()];
        let brief = direction_brief(&facts, &facts, "Anything at all", "", "2026-09-13T00:00:00.000Z", "");
        let standing: Vec<&str> = brief["standing_direction"].as_array().unwrap().iter().map(|r| r["logical_key"].as_str().unwrap()).collect();
        assert_eq!(standing, vec![guidance.logical_key.as_str(), invariant.logical_key.as_str()]);
        let governing: Vec<&str> = brief["governing_direction"].as_array().unwrap().iter().map(|r| r["logical_key"].as_str().unwrap()).collect();
        assert_eq!(governing, vec![roadmap.logical_key.as_str()]);
        assert!(super::standing_order("architecture/architecture-notes/3-invariants/i-2") < super::standing_order("architecture/architecture-notes/3-invariants/i-10"));
    }

    #[test]
    fn a_planned_service_row_is_flagged_and_asks_for_an_override_or_alternative() {
        let user = company_fact(
            "architecture/platform-1-september-to-end-of-year/in-design-architecture/08",
            "Platform — In design / architecture — 08 — **User** — Greenfield. Accounts by realm, capacities.",
            &[],
            &[],
        );
        let messaging = company_fact(
            "architecture/delta-current-state-to-target/messaging-spec-13",
            "Delta — Messaging — spec 13. **No repository.** Most of what is in the monolith is good.",
            &[],
            &[],
        );
        let live = company_fact(
            "architecture/delta-current-state-to-target/payment-spec-07",
            "Delta — Payment — spec 07. example/payment, largest and most mature.",
            &[],
            &[],
        );
        let facts = vec![user.clone(), messaging.clone(), live.clone()];
        let brief = direction_brief(&facts, &facts, "Operator permissions", "", "2026-09-13T00:00:00.000Z", "");
        let flagged: Vec<(&str, bool)> = brief["governing_direction"].as_array().unwrap().iter()
            .map(|r| (r["logical_key"].as_str().unwrap(), r["not_yet_built"].as_bool().unwrap())).collect();
        assert!(flagged.contains(&(user.logical_key.as_str(), true)));
        assert!(flagged.contains(&(messaging.logical_key.as_str(), true)));
        assert!(flagged.contains(&(live.logical_key.as_str(), false)));
        let asks: Vec<&str> = brief["questions"].as_array().unwrap().iter()
            .filter(|q| q["kind"] == "not_yet_built").map(|q| q["row"].as_str().unwrap()).collect();
        assert_eq!(asks.len(), 2);
        assert!(asks.contains(&user.logical_key.as_str()));
    }

    fn company_fact(key: &str, statement: &str, governs: &[&str], refs: &[&str]) -> CurrentFact {
        CurrentFact {
            standing: "ratified".to_owned(),
            provenance: "human".to_owned(),
            governs_paths: governs.iter().map(|g| g.to_string()).collect(),
            anchors: Vec::new(),
            fact_id: format!("fact_{}", key.replace('/', "_")),
            event_id: format!("evt_{}", key.replace('/', "_")),
            logical_key: key.to_owned(),
            atom_kind: "decision".to_owned(),
            scope: "company:architecture".to_owned(),
            statement: statement.to_owned(),
            status: "current".to_owned(),
            disposition: "accepted".to_owned(),
            authority_id: "jmc".to_owned(),
            authority_scope: "company:architecture".to_owned(),
            store_kind: "company".to_owned(),
            effective_from: "2026-08-31T00:00:00.000Z".to_owned(),
            effective_until: None,
            distortion: crate::model::Distortion {
                trigger: key.to_owned(),
                loss_if_absent: 7_000,
                rationale: "test".to_owned(),
            },
            company_refs: Vec::new(),
            evidence_refs: refs.iter().map(|r| r.to_string()).collect(),
            support_event_ids: Vec::new(),
            independent_support_count: 0,
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            confidence: 9_500,
            criticality: String::new(),
            trust: "trusted".to_owned(),
            stale_reasons: Vec::new(),
            authority_snapshot_cursor: String::new(),
            effective_dependence_class: None,
        }
    }

    #[test]
    fn ownership_delivers_cited_rows_and_asks_on_conflict() {
        let retirement = company_fact(
            "architecture/delta-current-state-to-target/thesis/three-greenfield-services",
            "Three greenfield services; nothing worth preserving underneath",
            &[],
            &[],
        );
        let owner = company_fact(
            "ownership/src/pms/bookings",
            "Target-state owner of src/pms/bookings/: Booking Service. The monorepo module is transitional.",
            &["src/pms/bookings/"],
            &["row:architecture/delta-current-state-to-target/thesis/three-greenfield-services"],
        );
        let vocab = company_fact(
            "architecture/architecture-notes/2-ratified-vocabulary/channel",
            "Channel is a supply-side program",
            &[],
            &[],
        );
        let facts = vec![retirement, owner, vocab];
        let brief = direction_brief(
            &facts,
            &[],
            "Add a platform label to the counter in src/pms/bookings/module/src/actions/confirm-booking-metrics.ts",
            "Which channel does the platform belong to?",
            "2026-09-13T00:00:00.000Z",
            "",
        );
        assert_eq!(brief["target_state_owner"]["status"], "resolved");
        let kinds: Vec<&str> = brief["questions"].as_array().unwrap().iter().map(|q| q["kind"].as_str().unwrap()).collect();
        assert!(kinds.contains(&"ownership_conflict"));
        // The retirement row names three greenfield services: building on
        // them needs an override or an alternative, so it asks too.
        assert!(kinds.contains(&"not_yet_built"));
        assert_eq!(kinds.iter().filter(|k| **k == "ownership_conflict").count(), 1);
        let cited: Vec<&str> = brief["direction_by_ownership"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["logical_key"].as_str().unwrap())
            .collect();
        assert_eq!(
            cited,
            vec!["architecture/delta-current-state-to-target/thesis/three-greenfield-services"]
        );
        let terms: Vec<&str> = brief["vocabulary_collisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["term"].as_str().unwrap())
            .collect();
        assert_eq!(terms, vec!["channel"]);
        assert_eq!(brief["direction_by_ownership"][0]["age_days"], 13);
    }

    #[test]
    fn no_ownership_fact_is_reported_not_guessed() {
        let brief = direction_brief(
            &[],
            &[],
            "touch services/api/src/app.ts",
            "why",
            "2026-09-13T00:00:00.000Z",
            "",
        );
        assert_eq!(brief["target_state_owner"]["status"], "no_ownership_fact");
        assert!(brief["questions"].as_array().unwrap().is_empty());
    }

    fn residents(count: usize) -> Vec<CurrentFact> {
        (0..count)
            .map(|n| company_fact(&format!("resident/{n:02}"), "A resident fact.", &[], &[]))
            .collect()
    }

    #[test]
    fn a_working_set_past_the_item_ceiling_is_cut_and_counted() {
        let (kept, omitted, byte_hit) = bounded_residents(residents(40), |_| 100);
        assert_eq!(kept.len(), PROJECTION_LIMIT);
        assert_eq!(omitted, 8);
        assert!(!byte_hit);
        assert_eq!(kept[0].logical_key, "resident/00");

        let (kept, omitted, _) = bounded_residents(residents(5), |_| 100);
        assert_eq!((kept.len(), omitted), (5, 0));
    }

    #[test]
    fn a_working_set_past_the_byte_ceiling_is_cut_and_counted() {
        // Three 50 KiB facts: two fit in 128 KiB, the third does not.
        let (kept, omitted, byte_hit) = bounded_residents(residents(3), |_| 50 * 1024);
        assert_eq!((kept.len(), omitted, byte_hit), (2, 1, true));
        assert!(array_bytes(kept.iter().map(|_| 50 * 1024)) <= PROJECTION_BYTE_LIMIT);
    }

    #[test]
    fn a_ceiling_that_ended_selection_is_the_stopping_reason() {
        assert_eq!(
            stopping_reason(false, false, true, true, false),
            "working_set_ceiling_reached"
        );
        assert_eq!(
            stopping_reason(false, false, false, true, false),
            "item_ceiling_reached"
        );
        assert_eq!(
            stopping_reason(false, false, false, false, true),
            "byte_ceiling_reached"
        );
        assert_eq!(
            stopping_reason(false, false, false, false, false),
            "nonpositive_net_marginal_value"
        );
        // An authority question or a met sufficiency predicate still ends the
        // loop first.
        assert_eq!(
            stopping_reason(true, true, true, true, true),
            "authority_question_raised"
        );
        assert_eq!(
            stopping_reason(false, true, true, true, true),
            "sufficiency_predicate_met"
        );
        assert_eq!(array_bytes(std::iter::empty()), 2);
        assert_eq!(array_bytes([3, 4].into_iter()), 3 + 4 + 1 + 2);
    }

    #[test]
    fn a_path_the_query_log_cannot_record_is_refused_first() {
        assert!(refuse_unrecordable_paths(&["src/pay".to_owned()], &[]).is_ok());
        let error =
            refuse_unrecordable_paths(&["src/pay\nsrc/api".to_owned()], &[]).expect_err("newline");
        assert_eq!((error.code.as_str(), error.exit()), ("CONFIG_INVARIANT", 4));
        let error = refuse_unrecordable_paths(&[], &[std::path::PathBuf::from("/repos/a\u{85}b")])
            .expect_err("C1 control");
        assert!(
            error.message.contains("--evidence-repo"),
            "{}",
            error.message
        );
    }
}

/// SetFold against the scan it replaced: the set-scanning complementarity and
/// redundancy functions as they were before folding, kept here as the
/// reference, compared on generated fact sets, folded at once and one member
/// at a time.
#[cfg(test)]
mod set_fold_differential_tests {
    use super::*;
    use rand::{Rng, SeedableRng, seq::SliceRandom};

    fn reference_complementarity(fact: &CurrentFact, set: &[CurrentFact], cache: &EvalCache) -> (i64, String) {
        const GAIN: i64 = 2_500;
        let fact_terms = cache.distinctive(fact);
        for existing in set {
            if fact.complements.contains(&existing.fact_id) || existing.complements.contains(&fact.fact_id) {
                return (GAIN, format!("explicit_edge:{}", existing.fact_id));
            }
            let (Some(left), Some(right)) = (evidence_class(&fact.atom_kind), evidence_class(&existing.atom_kind)) else {
                continue;
            };
            if left == right {
                continue;
            }
            if let (Some(subject), Some(other)) = (key_subject(&fact.logical_key), key_subject(&existing.logical_key)) {
                if subject == other && fact.logical_key != existing.logical_key {
                    return (GAIN, format!("shared_subject_key:{subject}"));
                }
            }
            let existing_terms = cache.distinctive(existing);
            let shared: Vec<&str> = fact_terms.intersection(&existing_terms).map(String::as_str).collect();
            if shared.len() >= 2 {
                return (GAIN, format!("shared_subject_terms:{}", shared.join(",")));
            }
        }
        (0, "none".to_owned())
    }

    fn reference_redundancy(fact: &CurrentFact, set: &[CurrentFact], cache: &EvalCache) -> (i64, String) {
        let protected = fact.distortion.loss_if_absent >= 7_000 && matches!(fact.atom_kind.as_str(), "constraint" | "decision");
        let fact_support = cache.support(fact);
        for existing in set {
            if fact.redundancy_with.contains(&existing.fact_id) || existing.redundancy_with.contains(&fact.fact_id) {
                return if protected {
                    (2_000, format!("protected_invariant_explicit_edge:{}", existing.fact_id))
                } else {
                    (8_000, format!("explicit_edge:{}", existing.fact_id))
                };
            }
            let existing_support = cache.support(existing);
            if fact_support.iter().any(|id| existing_support.contains(id)) {
                return if protected {
                    (1_000, format!("protected_invariant_shared_provenance:{}", existing.fact_id))
                } else {
                    (3_000, format!("shared_provenance:{}", existing.fact_id))
                };
            }
        }
        let fact_terms = cache.statement_terms(fact);
        let mut best = (0i64, "none".to_owned());
        for existing in set {
            let existing_terms = cache.statement_terms(existing);
            let intersection = fact_terms.intersection(&existing_terms).count() as i64;
            let total = fact_terms.len() as i64 + existing_terms.len() as i64;
            if total == 0 {
                continue;
            }
            let similarity = intersection.saturating_mul(2).saturating_mul(10_000).saturating_div(total);
            if similarity >= 6_000 {
                let complementary = evidence_class(&fact.atom_kind).is_some()
                    && evidence_class(&existing.atom_kind).is_some()
                    && evidence_class(&fact.atom_kind) != evidence_class(&existing.atom_kind);
                let ceiling = if protected || complementary { 2_000 } else { 10_000 };
                let penalty = similarity.min(ceiling);
                if penalty > best.0 {
                    best = (penalty, format!("lexical_similarity:{similarity}:{}", existing.fact_id));
                }
            }
        }
        best
    }

    const WORDS: [&str; 14] = [
        "retry", "backoff", "ledger", "invoice", "scheduler", "webhook", "timeout", "payment",
        "reconcile", "booking", "the", "should", "queue", "cache",
    ];
    const KINDS: [&str; 7] = ["constraint", "decision", "rationale", "test", "observation", "claim", "runtime_trace"];

    fn generated(rng: &mut rand::rngs::StdRng, index: usize, count: usize) -> CurrentFact {
        let words: Vec<&str> = (0..rng.gen_range(1..7)).map(|_| *WORDS.choose(rng).unwrap()).collect();
        let pick_ids = |rng: &mut rand::rngs::StdRng| -> Vec<String> {
            (0..rng.gen_range(0..2)).map(|_| format!("f{}", rng.gen_range(0..count))).collect()
        };
        let complements = pick_ids(rng);
        let redundancy_with = pick_ids(rng);
        CurrentFact {
            standing: "present".to_owned(),
            provenance: "unknown".to_owned(),
            governs_paths: Vec::new(),
            anchors: Vec::new(),
            fact_id: format!("f{index}"),
            event_id: format!("e{index}"),
            logical_key: format!("area{}/{}", rng.gen_range(0..3), ["retry", "ledger", "queue", "cache"][rng.gen_range(0..4)]),
            atom_kind: KINDS.choose(rng).unwrap().to_string(),
            scope: "test".to_owned(),
            statement: words.join(" "),
            status: "current".to_owned(),
            disposition: "approved".to_owned(),
            authority_id: "a".to_owned(),
            authority_scope: "codebase:x".to_owned(),
            store_kind: "codebase".to_owned(),
            effective_from: "2026-09-01T00:00:00.000Z".to_owned(),
            effective_until: None,
            distortion: crate::model::Distortion {
                trigger: WORDS.choose(rng).unwrap().to_string(),
                loss_if_absent: rng.gen_range(3_000..9_500),
                rationale: "generated".to_owned(),
            },
            company_refs: Vec::new(),
            evidence_refs: (0..rng.gen_range(0..2)).map(|_| format!("ev{}", rng.gen_range(0..4))).collect(),
            support_event_ids: (0..rng.gen_range(0..2)).map(|_| format!("ev{}", rng.gen_range(0..4))).collect(),
            independent_support_count: 0,
            redundancy_with,
            complements,
            confidence: 8_000,
            criticality: String::new(),
            trust: "trusted".to_owned(),
            stale_reasons: Vec::new(),
            authority_snapshot_cursor: String::new(),
            effective_dependence_class: None,
        }
    }

    #[test]
    fn folding_the_set_matches_scanning_it() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5e7f01d);
        let mut compared = 0;
        for _ in 0..400 {
            let count = rng.gen_range(2..14);
            let facts: Vec<CurrentFact> = (0..count).map(|i| generated(&mut rng, i, count)).collect();
            let refs: Vec<&CurrentFact> = facts.iter().collect();
            let cache = EvalCache::new(&refs, "reconcile the ledger", "which retry backoff");
            for fact in &facts {
                let set: Vec<CurrentFact> = facts.iter().filter(|other| other.fact_id != fact.fact_id)
                    .filter(|_| rng.gen_bool(0.6)).cloned().collect();
                // At once, and one member at a time as selection appends them.
                let whole = SetFold::of(fact, &set, &cache);
                let mut incremental = SetFold::new();
                for member in &set {
                    incremental.absorb(fact, member, &cache);
                }
                for fold in [&whole, &incremental] {
                    assert_eq!(fold.complement.clone().unwrap_or((0, "none".to_owned())),
                               reference_complementarity(fact, &set, &cache));
                    assert_eq!(fold.edge.clone().unwrap_or_else(|| fold.lexical.clone()),
                               reference_redundancy(fact, &set, &cache));
                    assert_eq!(fold.covered, set.iter().any(|existing| existing.logical_key == fact.logical_key
                        || cache.normalized(existing) == cache.normalized(fact)));
                }
                compared += 1;
            }
        }
        assert!(compared > 2_000);
    }
}

#[cfg(test)]
mod stem_tests {
    use super::stem;

    #[test]
    fn inflections_of_one_verb_share_a_stem() {
        for group in [
            ["validate", "validates", "validated", "validating"],
            ["cache", "caches", "cached", "caching"],
            ["retry", "retries", "retried", "retrying"],
        ] {
            let stems: std::collections::BTreeSet<String> = group.iter().map(|w| stem(w)).collect();
            assert_eq!(stems.len(), 1, "{group:?} -> {stems:?}");
        }
        assert_eq!(stem("free"), "free");
        assert_eq!(stem("status"), "status");
    }
}
