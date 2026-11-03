//! The current-view reducer (architecture §6 "Reduction algorithm", P-4,
//! P-5). A pure function of `(admitted event set, reducer version, as_of,
//! authority snapshot cursor)` that emits a trace per logical key. Recency is
//! used only inside an authority/lifecycle-equivalent set and only through
//! the explicit source-type decay policy below.

use crate::model::{CurrentFact, Distortion, FactEvent, UnknownEvent};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const REDUCER_VERSION: &str = "kinbase-reducer/2";
/// Transient evidence (draft/proposed/incident/experiment/workaround)
/// without a declared lifetime expires this long after it became effective.
pub const DEFAULT_TRANSIENT_LIFETIME_SECONDS: i64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verification {
    Verified,
    Unverified,
    Foreign,
    SignatureInvalid,
    Revoked,
    WrongScope,
}

/// A fact event plus the admission metadata the store attached to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittedEvent {
    pub event: FactEvent,
    pub verification: Verification,
    /// Opaque store cursor that orders equal-time events (never a timestamp).
    pub store_cursor: String,
    #[serde(default)]
    pub origin_trust: Option<String>,
    /// Branch reachability from the default lineage, when known.
    #[serde(default)]
    pub reachable: Option<bool>,
    /// Source identity used for independence (adapter identity or signer).
    #[serde(default)]
    pub source_identity: Option<String>,
    /// Registered environment for runtime observations, and whether it was
    /// registered at the authority cursor.
    #[serde(default)]
    pub environment_registered: Option<bool>,
}

/// Explicit withdrawals: `misextraction` (approver), `never_true`
/// (subject-matter authority), `support_withdrawn` (revocation cascade).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tombstone {
    pub kind: String,
    pub target_event_id: String,
    pub signer_authorized: bool,
    pub reason_code: String,
    pub tombstone_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revocation {
    pub revoked_key: String,
    pub cursor: String,
    pub effective_at: String,
    /// The one exact authority scope this revocation withdraws, when the key
    /// stays registered under others (a registry republication dropped one of
    /// its entries). `None` revokes the key everywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The reader holds this revocation from its own record and has observed
    /// it whatever its cursor says. The Company service is that reader: a
    /// registry-derived revocation is numbered in the steward's authority
    /// cursors, which the service's row cursor does not order against, and it
    /// was being skipped as not yet observed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub observed: bool,
}

impl Revocation {
    /// A revocation of `key` everywhere.
    pub fn of_key(revoked_key: String, cursor: String, effective_at: String) -> Self {
        Revocation {
            revoked_key,
            cursor,
            effective_at,
            scope: None,
            observed: false,
        }
    }

    /// Does this revocation withdraw what `signer` warranted in `authority_scope`?
    pub fn covers(&self, signer: &str, authority_scope: &str) -> bool {
        self.revoked_key == signer
            && self
                .scope
                .as_deref()
                .is_none_or(|scope| scope == authority_scope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReducerInput {
    pub store_kind: String,
    pub events: Vec<AdmittedEvent>,
    pub unknowns: Vec<UnknownEvent>,
    pub tombstones: Vec<Tombstone>,
    pub revocations: Vec<Revocation>,
    pub as_of: String,
    pub authority_cursor: String,
    /// Freshness of Company data behind the view (P-8 truth table).
    #[serde(default)]
    pub revocation_fresh: bool,
    #[serde(default)]
    pub fact_valid_until: Option<String>,
    #[serde(default)]
    pub certificate_valid: bool,
    /// Exact scope to stable registry authority identity. A missing key is an
    /// unresolved registry owner, never a reducer-side default.
    #[serde(default)]
    pub authority_owner_by_scope: BTreeMap<String, String>,
    /// Stable identity of the Company steward authority; used only for the
    /// spec-mandated registry Unknown and unregistered environment fallback.
    #[serde(default)]
    pub steward_authority_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    pub step: u8,
    pub name: String,
    pub event_ids: Vec<String>,
    pub outcome: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyTrace {
    pub logical_key: String,
    pub steps: Vec<TraceStep>,
    pub admitted_event_ids: Vec<String>,
    pub rejected: Vec<Value>,
    pub current_fact_id: Option<String>,
    pub state: String,
    pub conflict_event_ids: Vec<String>,
    pub negative_evidence_event_ids: Vec<String>,
    pub expired_event_ids: Vec<String>,
    pub unknown_id: Option<String>,
    pub counterfactual: Vec<String>,
    pub decay_policy_applied: Option<String>,
    #[serde(default)]
    pub notice_admitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_minted_accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_form_owner_admitted: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedUnknown {
    pub unknown_id: String,
    pub logical_key: String,
    pub scope: String,
    pub decision_blocked: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub question: String,
    pub closure_evidence: Vec<String>,
    pub loss_if_absent: u16,
    pub discriminating_evidence: Vec<String>,
    pub status: String,
    pub kind: String,
    /// The authority scopes of the evidence the Unknown was derived from,
    /// which decide who may read it: `scope` is that evidence's subject
    /// scope and need not be an authority scope. Not part of the wire form.
    #[serde(default, skip_serializing)]
    pub authority_scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentView {
    pub schema: String,
    pub store_kind: String,
    pub reducer_version: String,
    pub as_of: String,
    pub authority_cursor: String,
    pub facts: Vec<CurrentFact>,
    pub unknowns: Vec<DerivedUnknown>,
    pub open_unknown_ids: Vec<String>,
    pub traces: Vec<KeyTrace>,
    pub rejected: Vec<Value>,
    pub counts: BTreeMap<String, usize>,
    pub decay_policy: Vec<Value>,
}

/// Authority rank inside one store. Higher wins a cross-rank conflict; a
/// same-rank disagreement is a conflict, never a vote.
/// Which paths a ruling governs, and how hard it demotes what lives under them.
///
/// The problem: `monorepo/` has more commits than any other repository in the deployment it was measured on, and
/// is being retired. Every one of those commits is real evidence that code exists
/// and what it does. None of it is evidence that anyone still wants it. Outranking
/// that crowd one comparison at a time is not enough -- a `directional` fact scoped
/// to a path has to reach down and mark the evidence underneath it stale, or the
/// crowd keeps winning by being a crowd.
#[derive(Debug, Default, Clone)]
pub struct Governance {
    /// (path prefix, standing of the fact that governs it, id of that fact)
    rules: Vec<(String, String, String)>,
    /// Each distinct path once, with its rules' indices in order. Every version of
    /// a ruling repeats its paths: 10,971 rules named 94 paths on staging, and
    /// matching each rule made a snapshot cost 26 s.
    by_path: Vec<(String, Vec<usize>)>,
}

impl Governance {
    /// Collect governing facts. Only kinds that express direction govern: a
    /// `north_star` says where we are going, `directional` says what to move
    /// toward, `invariant` says what may not move. An `observation` about a path
    /// governs nothing, however authoritative its source.
    pub fn build<'a>(events: impl Iterator<Item = &'a FactEvent>) -> Self {
        let mut rules = Vec::new();
        for event in events {
            if event.governs_paths.is_empty() {
                continue;
            }
            if !matches!(
                event.atom_kind.as_str(),
                "north_star" | "directional" | "invariant"
            ) {
                continue;
            }
            let standing = crate::model::effective_standing(&event.standing, &event.provenance);
            for path in &event.governs_paths {
                rules.push((path.clone(), standing.clone(), event.fact_id.clone()));
            }
        }
        let mut by_path: Vec<(String, Vec<usize>)> = Vec::new();
        let mut slot: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (index, (path, _, _)) in rules.iter().enumerate() {
            let at = *slot.entry(path.as_str()).or_insert_with(|| {
                by_path.push((path.clone(), Vec::new()));
                by_path.len() - 1
            });
            by_path[at].1.push(index);
        }
        Self { rules, by_path }
    }

    /// True when this event's evidence sits under a governed path.
    ///
    /// A governed path is matched against every place an event records where it
    /// came from, because different adapters record location differently: a code
    /// anchor carries a real file path, a repository-scoped fact carries only its
    /// repository UUID, and a document fact carries the source in `scope` or an
    /// evidence reference. Matching only the last of those was the reason
    /// governance never fired on real ingested corpora -- the repository adapter
    /// writes `scope: "repository"` and opaque `observation:` references, so no
    /// ruling about `example/property` could ever reach the facts it governs.
    fn governing_rule(&self, event: &FactEvent) -> Option<&(String, String, String)> {
        // The first rule, in build order, whose path matches and which is not the
        // event's own fact: the earliest such index across the matching paths.
        let mut first: Option<usize> = None;
        for (path, indices) in &self.by_path {
            // Groups are in order of their first rule, so none after this can win.
            if first.is_some_and(|seen| indices[0] > seen) {
                break;
            }
            if !Self::governs(path, event) {
                continue;
            }
            // A ruling never demotes itself, and never demotes a sibling ruling
            // from the same fact.
            if let Some(&index) = indices.iter().find(|&&i| self.rules[i].2 != event.fact_id) {
                first = Some(first.map_or(index, |seen| seen.min(index)));
            }
        }
        first.map(|index| &self.rules[index])
    }

    fn governs(path: &str, event: &FactEvent) -> bool {
        event.scope.contains(path)
                    // Repository-wide governance: the ruling names the repository
                    // by the identity the event actually carries. Exact, never a
                    // prefix -- one repository UUID is not a parent of another.
                    || event.repository_id.as_deref() == Some(path)
                    // A path rule is a prefix of a path, not a substring of one:
                    // `src/pay` governs `src/payment/x.ts` and must not be reached
                    // by a file that merely mentions it.
                    || event
                        .anchors
                        .iter()
                        .any(|anchor| anchor.path.starts_with(path))
                    || event
                        .evidence_refs
                        .iter()
                        .any(|reference| reference.contains(path))
    }

    /// The standing this event actually carries once governance is applied.
    ///
    /// Demotion is one-directional: a ruling can only weaken evidence beneath it,
    /// never promote it. Evidence that already outranks the ruling is untouched,
    /// because a `ratified` decision inside a deprecated directory is still a
    /// decision -- what is stale is the ambient code around it, not every fact
    /// that happens to live there.
    pub fn standing_for(&self, event: &FactEvent) -> String {
        let own = crate::model::effective_standing(&event.standing, &event.provenance);
        let Some((_, governing, _)) = self.governing_rule(event) else {
            return own;
        };
        // Only *ambient* evidence is demoted. `prevalent` is "the majority
        // pattern", which is precisely the noise a ruling exists to overrule:
        // the retired repository has the most commits. Everything stronger was
        // assigned deliberately -- `enforced` is mechanically true right now and
        // a target-state document does not stop CI from failing your build
        // today; `exemplary` is a human naming the implementation to copy. A
        // ruling that contradicts one of those is a conflict to surface, not a
        // standing to quietly lower.
        let ambient = matches!(own.as_str(), "prevalent" | "present");
        if ambient && crate::model::outranks(governing, &own) {
            // Governed and weaker: this is ambient evidence under a path someone
            // has ruled on. It survives as `present` -- still retrievable, no
            // longer a signal about direction.
            "present".to_owned()
        } else {
            own
        }
    }
}

pub fn authority_rank(event: &FactEvent, origin_trust: Option<&str>) -> u8 {
    authority_rank_governed(event, origin_trust, None)
}

pub fn authority_rank_governed(
    event: &FactEvent,
    origin_trust: Option<&str>,
    governance: Option<&Governance>,
) -> u8 {
    // A declared standing dominates where the fact happens to live. This is what
    // lets "we are retiring monorepo/" outweigh monorepo/ having more commits than any
    // other repository: volume produces `present` evidence, a ruling produces
    // `ratified`, and the ruling wins without anyone counting.
    //
    // Provenance is applied first, so a pattern an agent wrote forty times cannot
    // claim `prevalent` and feed itself back as direction.
    // Trust first, standing second. Standing is a claim the event makes about
    // itself, so consulting it before the origin-trust check let an untrusted event
    // declare `standing: "authoritative"` and skip the check entirely -- an attacker
    // fork with a self-issued certificate minted a trusted fact that way. An event
    // whose origin is not trusted ranks zero no matter what it claims about its own
    // importance.
    if event.store_kind == "codebase"
        && origin_trust.is_some_and(|trust| trust != "merged-default")
        && !(origin_trust == Some("approved-pr")
            && event
                .evidence_refs
                .iter()
                .any(|reference| reference.starts_with("authorization:")))
    {
        return 0;
    }
    let standing = match governance {
        Some(governance) => governance.standing_for(event),
        None => crate::model::effective_standing(&event.standing, &event.provenance),
    };
    match standing.as_str() {
        "authoritative" => return 12,
        "ratified" => return 11,
        "enforced" => return 10,
        "exemplary" => return 9,
        "prevalent" => return 8,
        // `unruled` is evidence that conflicts with no ruling to settle it. It must
        // never win a comparison; it exists to be reported and asked about.
        "unruled" => return 0,
        // `present` falls through to the store-shaped rank below, which is what
        // every fact carried before standings existed.
        _ => {}
    }
    let scope = event.authority_scope.as_str();
    match event.store_kind.as_str() {
        "company" => {
            if scope.starts_with("architecture:") {
                6
            } else if scope.starts_with("environment:") {
                3
            } else {
                5
            }
        }
        "codebase" => {
            if scope.starts_with("environment:") {
                3
            } else if origin_trust.is_some_and(|trust| trust != "merged-default")
                && !(origin_trust == Some("approved-pr")
                    && event
                        .evidence_refs
                        .iter()
                        .any(|reference| reference.starts_with("authorization:")))
            {
                0
            } else if event.disposition == "approved"
                || event.evidence_refs.iter().any(|r| r.starts_with("cand_"))
            {
                4
            } else if event.atom_kind == "constraint" || event.atom_kind == "decision" {
                4
            } else {
                2
            }
        }
        _ => 1,
    }
}

/// Source-type decay policy: inside an authority-equivalent set, only these
/// kinds let the newest cursor retire an older statement.
pub fn decay_policy() -> Vec<Value> {
    vec![
        json!({"atom_kind": "observation", "rule": "newest-cursor-within-same-source", "rationale": "an observation from the same registered source describes the same subject at a later time"}),
        json!({"atom_kind": "claim", "rule": "conflict-unless-superseded", "rationale": "a newer claim never retires an older one without a parent-bound supersession"}),
        json!({"atom_kind": "decision", "rule": "conflict-unless-superseded", "rationale": "decisions retire only through explicit supersession by the same scoped authority"}),
        json!({"atom_kind": "constraint", "rule": "conflict-unless-superseded", "rationale": "constraints retire only through explicit supersession, retraction, or revocation"}),
        json!({"atom_kind": "rationale", "rule": "accumulate", "rationale": "rationales complement one another and never conflict"}),
    ]
}

pub(crate) fn expiry_of(event: &FactEvent) -> Option<String> {
    if let Some(until) = &event.effective_until {
        return Some(until.clone());
    }
    if crate::model::disposition_is_transient(&event.disposition) {
        return crate::time::plus_seconds(
            &event.effective_from,
            DEFAULT_TRANSIENT_LIFETIME_SECONDS,
        )
        .ok();
    }
    None
}

/// The question a person is actually asked when heads disagree.
///
/// It used to name the candidates by event id and nothing else: "Candidates:
/// event_obs_6c8b9e4b…, event_obs_a7a6f779…, event_obs_ba93bf33…". Nobody can
/// answer that. A ruling loop whose entire purpose is to let a human give a
/// definitive answer has to show the human what they are choosing between, so
/// the question carries the competing statements themselves, each labelled and
/// paired with the id an answer must name.
fn conflict_question(logical_key: &str, conflict_ids: &[String], heads: &[Head]) -> String {
    const MAX_CANDIDATES: usize = 6;
    const MAX_STATEMENT: usize = 240;
    let mut question = format!(
        "Which of the {} incompatible statements for logical key {logical_key} is current?",
        conflict_ids.len()
    );
    for (index, id) in conflict_ids.iter().take(MAX_CANDIDATES).enumerate() {
        let statement = heads
            .iter()
            .find(|head| head.representative.event.event_id == *id)
            .map(|head| head.representative.event.statement.as_str())
            .unwrap_or("");
        let label = (b'a' + index as u8) as char;
        let shown: String = statement.chars().take(MAX_STATEMENT).collect();
        let ellipsis = if statement.chars().count() > MAX_STATEMENT {
            "…"
        } else {
            ""
        };
        question.push_str(&format!(" ({label}) {shown}{ellipsis} [{id}]"));
    }
    if conflict_ids.len() > MAX_CANDIDATES {
        question.push_str(&format!(
            " and {} more, listed in full under discriminating_evidence.",
            conflict_ids.len() - MAX_CANDIDATES
        ));
    }
    question
}

fn statement_identity(event: &FactEvent) -> String {
    crate::scanner::squeeze(&event.statement)
}

pub fn reduce(input: &ReducerInput) -> CurrentView {
    let mut rejected_global = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let bump = |counts: &mut BTreeMap<String, usize>, name: &str| {
        *counts.entry(name.to_owned()).or_insert(0) += 1;
    };

    // Rulings are collected before anything is ranked, so a directional fact can
    // demote the ambient evidence under the paths it governs rather than merely
    // outrank it one comparison at a time.
    let governance = Governance::build(input.events.iter().map(|admitted| &admitted.event));
    let governance = Some(&governance);

    // Deterministic iteration: store cursor, then event ID.
    let mut ordered: Vec<&AdmittedEvent> = input.events.iter().collect();
    ordered.sort_by(|left, right| {
        cursor_order(&left.store_cursor, &right.store_cursor)
            .then_with(|| left.event.event_id.cmp(&right.event.event_id))
    });

    let observed_revocations: Vec<&Revocation> = input
        .revocations
        .iter()
        .filter(|revocation| {
            revocation.observed
                || cursor_order(&revocation.cursor, &input.authority_cursor)
                    != std::cmp::Ordering::Greater
        })
        .collect();
    // The newest observed revocation withdrawing this event's support, if any:
    // one of its key everywhere, or of the exact scope it was signed in.
    let revocation_of = |event: &FactEvent| -> Option<&Revocation> {
        observed_revocations
            .iter()
            .copied()
            .filter(|revocation| revocation.covers(&event.signer, &event.authority_scope))
            .max_by(|left, right| cursor_order(&left.cursor, &right.cursor))
    };

    // Group by logical key.
    let mut groups: BTreeMap<String, Vec<&AdmittedEvent>> = BTreeMap::new();
    for admitted in &ordered {
        groups
            .entry(admitted.event.logical_key.clone())
            .or_default()
            .push(admitted);
    }
    let tombstones_by_target: BTreeMap<&str, Vec<&Tombstone>> = {
        let mut map: BTreeMap<&str, Vec<&Tombstone>> = BTreeMap::new();
        for tombstone in &input.tombstones {
            map.entry(tombstone.target_event_id.as_str())
                .or_default()
                .push(tombstone);
        }
        map
    };
    let all_event_ids: BTreeSet<&str> = input
        .events
        .iter()
        .map(|admitted| admitted.event.event_id.as_str())
        .collect();

    let mut facts = Vec::new();
    let mut unknowns = Vec::new();
    let mut registry_unknown_emitted: BTreeSet<String> = BTreeSet::new();
    let mut traces = Vec::new();
    let company_stale = input.store_kind != "personal" && !input.certificate_valid;
    let fact_expired = input
        .fact_valid_until
        .as_ref()
        .is_some_and(|until| until.as_str() <= input.as_of.as_str());

    for (logical_key, group) in groups {
        let mut trace = KeyTrace {
            logical_key: logical_key.clone(),
            steps: Vec::new(),
            admitted_event_ids: Vec::new(),
            rejected: Vec::new(),
            current_fact_id: None,
            state: "missing".to_owned(),
            conflict_event_ids: Vec::new(),
            negative_evidence_event_ids: Vec::new(),
            expired_event_ids: Vec::new(),
            unknown_id: None,
            counterfactual: Vec::new(),
            decay_policy_applied: None,
            notice_admitted: false,
            approver_minted_accepted: None,
            free_form_owner_admitted: None,
        };

        // Step 1: reject ineligible authority/scope/signature/repository events.
        let mut eligible: Vec<&AdmittedEvent> = Vec::new();
        let mut untrusted_branch: Vec<String> = Vec::new();
        let mut unregistered_environment = false;
        for admitted in group.iter().copied() {
            let event = &admitted.event;
            if admitted.environment_registered == Some(false) {
                unregistered_environment = true;
                let reason = "ENVIRONMENT_UNREGISTERED: runtime observation names an environment absent from the authority registry";
                trace
                    .rejected
                    .push(json!({"event_id": event.event_id, "step": 1, "reason": reason}));
                rejected_global.push(json!({"logical_key": logical_key, "event_id": event.event_id, "step": 1, "reason": reason}));
                bump(&mut counts, "rejected");
                bump(&mut counts, "environment_unregistered");
                continue;
            }
            let reason = match admitted.verification {
                Verification::Verified => None,
                Verification::Unverified => Some(
                    "UNVERIFIED: no resolvable out-of-worktree certificate or registry entry authorizes the signer",
                ),
                Verification::Foreign => {
                    Some("FOREIGN_REPO_EVENTS: event binds another repository UUID")
                }
                Verification::SignatureInvalid => {
                    Some("SIGNATURE_INVALID: domain-separated signature failed")
                }
                Verification::Revoked => Some("REVOKED: signer key was revoked before this event"),
                Verification::WrongScope => {
                    Some("AUTHORITY_WRONG_SCOPE: signer does not own the exact authority scope")
                }
            };
            let reason = reason.or_else(|| {
                if observed_revocations.iter().any(|revocation| {
                    revocation.covers(&event.signer, &event.authority_scope)
                        && revocation.effective_at.as_str() <= event.asserted_at.as_str()
                }) {
                    Some("REVOKED: signer key was revoked at an earlier cursor than this event")
                } else if event.store_kind != input.store_kind && input.store_kind != "mixed" {
                    Some("WRONG_STORE: event belongs to another store kind")
                } else {
                    None
                }
            });
            if let Some(reason) = reason {
                // An approver-minted never_true reaches the reducer as a
                // WrongScope event when the repository adapter cannot turn it
                // into a tombstone; expose the required typed outcome on the
                // affected key rather than only in the generic rejection list.
                if reason.starts_with("AUTHORITY_WRONG_SCOPE")
                    && crate::model::action_of(event) == Some("never_true")
                {
                    trace.approver_minted_accepted = Some(false);
                }
                trace
                    .rejected
                    .push(json!({"event_id": event.event_id, "step": 1, "reason": reason}));
                rejected_global.push(json!({"logical_key": logical_key, "event_id": event.event_id, "step": 1, "reason": reason}));
                bump(&mut counts, "rejected");
                continue;
            }
            let trust = admitted.origin_trust.as_deref();
            if authority_rank_governed(event, trust, governance) == 0
                || admitted.reachable == Some(false)
            {
                untrusted_branch.push(event.event_id.clone());
                trace.rejected.push(json!({"event_id": event.event_id, "step": 1, "reason": "UNTRUSTED_BRANCH: origin trust below merged-default or unreachable from the default lineage; ineligible for trusted durable direction"}));
                bump(&mut counts, "untrusted_branch");
                continue;
            }
            eligible.push(admitted);
            trace.admitted_event_ids.push(event.event_id.clone());
        }
        trace.steps.push(TraceStep {
            step: 1,
            name: "reject-ineligible".to_owned(),
            event_ids: trace.admitted_event_ids.clone(),
            outcome: format!("{} eligible, {} rejected", eligible.len(), trace.rejected.len()),
            reason: "authority, scope, signature, repository identity, revocation cursor, and origin trust".to_owned(),
        });
        if !untrusted_branch.is_empty() {
            trace.counterfactual.push(format!(
                "merging {} unreviewed-branch event(s) into the default lineage would make them eligible",
                untrusted_branch.len()
            ));
        }

        // Step 2: explicit retraction/revocation and parent-bound supersession.
        let mut retired: BTreeMap<String, String> = BTreeMap::new();
        let mut withheld: BTreeMap<String, DerivedUnknownSeed> = BTreeMap::new();
        let mut support_retired_ids: BTreeSet<String> = BTreeSet::new();
        for admitted in &eligible {
            let event = &admitted.event;
            // A conflict resolution is parent-bound to the incompatible heads.
            // It retires exactly the heads its signer owns (same exact scope,
            // no lower authority); a parent it does not own is acknowledged
            // lineage, never erased by role prestige. A parentless message
            // never resolves a conflict, and an unauthorized one leaves the
            // heads in place and survives only as ordinary lower evidence.
            if event.parents.len() >= 2 {
                let new_rank =
                    authority_rank_governed(event, admitted.origin_trust.as_deref(), governance);
                let own_identity = statement_identity(event);
                let mut unauthorized_disagreement: Vec<String> = Vec::new();
                for target in &event.parents {
                    let Some(old) = eligible
                        .iter()
                        .find(|candidate| candidate.event.event_id == *target)
                    else {
                        continue;
                    };
                    let old_rank = authority_rank_governed(
                        &old.event,
                        old.origin_trust.as_deref(),
                        governance,
                    );
                    let owns =
                        old_rank <= new_rank && old.event.authority_scope == event.authority_scope;
                    if owns {
                        if event.supersedes.is_empty() {
                            retired.insert(
                                target.clone(),
                                format!("conflict resolved by parent-bound {}", event.event_id),
                            );
                        }
                    } else if statement_identity(&old.event) != own_identity {
                        unauthorized_disagreement.push(target.clone());
                    }
                }
                if !unauthorized_disagreement.is_empty() {
                    // The message contradicts a head it has no authority to
                    // retire. It must not become a higher-ranked third head
                    // and win the conflict it failed to resolve.
                    let reason = format!(
                        "AUTHORITY_WRONG_SCOPE: {} names {} as parent(s) but {}/{} does not own that scope; the heads survive and the attempted resolution is set aside",
                        event.event_id,
                        unauthorized_disagreement.join(", "),
                        event.authority_id,
                        event.authority_scope
                    );
                    trace.rejected.push(
                        json!({"event_id": event.event_id, "step": 2, "reason": reason.clone()}),
                    );
                    rejected_global.push(json!({"logical_key": logical_key, "event_id": event.event_id, "step": 2, "reason": reason.clone()}));
                    bump(&mut counts, "rejected");
                    trace.counterfactual.push(format!(
                        "a parent-bound resolution signed by the authority owning the scope of {} would retire those heads",
                        unauthorized_disagreement.join(", ")
                    ));
                    retired.insert(
                        event.event_id.clone(),
                        "unauthorized conflict resolution".to_owned(),
                    );
                }
            }
            if crate::model::disposition_is_negative(&event.disposition)
                && matches!(event.disposition.as_str(), "retracted" | "withdrawn")
            {
                for target in event.supersedes.iter().chain(event.parents.iter()) {
                    retired.insert(target.clone(), format!("retracted by {}", event.event_id));
                }
                retired.insert(event.event_id.clone(), "self-retraction".to_owned());
                continue;
            }
            // A rejected or reverted proposal is negative evidence. Its
            // `supersedes` list describes the change it proposed, not an
            // authorization to retire the accepted rule it proposed replacing.
            if !matches!(event.disposition.as_str(), "rejected" | "reverted") {
                for target in &event.supersedes {
                    // Parent-bound: the superseded event must be in the admitted set
                    // and the superseding authority must not be lower.
                    if let Some(old) = eligible
                        .iter()
                        .find(|candidate| candidate.event.event_id == *target)
                    {
                        let old_rank = authority_rank_governed(
                            &old.event,
                            old.origin_trust.as_deref(),
                            governance,
                        );
                        let new_rank = authority_rank_governed(
                            event,
                            admitted.origin_trust.as_deref(),
                            governance,
                        );
                        if new_rank >= old_rank
                            && old.event.authority_scope == event.authority_scope
                        {
                            retired.insert(
                                target.clone(),
                                format!("superseded by {}", event.event_id),
                            );
                        } else {
                            trace.counterfactual.push(format!(
                            "{} claims to supersede {} but its authority ({}/{}) does not own that scope; it survives as a conflict",
                            event.event_id, target, event.authority_id, event.authority_scope
                        ));
                        }
                    } else if all_event_ids.contains(target.as_str()) {
                        retired.insert(target.clone(), format!("superseded by {}", event.event_id));
                    }
                }
            }
        }
        for admitted in &eligible {
            let event = &admitted.event;
            if let Some(tombstones) = tombstones_by_target.get(event.event_id.as_str()) {
                for tombstone in tombstones {
                    if !tombstone.signer_authorized {
                        if tombstone.kind == "never_true" {
                            trace.approver_minted_accepted = Some(false);
                            let reason = "AUTHORITY_WRONG_SCOPE: approver-minted never_true is not signed by the subject-matter authority for the scope";
                            trace.rejected.push(
                                json!({"event_id": tombstone.tombstone_id, "reason": reason}),
                            );
                            rejected_global.push(json!({"logical_key": logical_key, "event_id": tombstone.tombstone_id, "reason": reason}));
                            bump(&mut counts, "rejected");
                        }
                        continue;
                    }
                    match tombstone.kind.as_str() {
                        "never_true" => {
                            retired.insert(
                                event.event_id.clone(),
                                format!("withdrawn as never_true by {}", tombstone.tombstone_id),
                            );
                        }
                        "misextraction" => {
                            trace.notice_admitted = true;
                            withheld.insert(
                                event.event_id.clone(),
                                DerivedUnknownSeed {
                                    kind: "misextraction".to_owned(),
                                    question: format!(
                                        "The approver reported that the approved bytes of {} did not faithfully represent the evidence shown (reason {}). Does the statement hold?",
                                        event.event_id, tombstone.reason_code
                                    ),
                                    evidence: vec![tombstone.tombstone_id.clone()],
                                },
                            );
                        }
                        "support_withdrawn" => {
                            support_retired_ids.insert(event.event_id.clone());
                            trace.counterfactual.push(format!(
                                "support for {} was withdrawn by {}",
                                event.event_id, tombstone.tombstone_id
                            ));
                        }
                        _ => {}
                    }
                }
            }
        }
        let after_step2: Vec<&AdmittedEvent> = eligible
            .iter()
            .copied()
            .filter(|admitted| !retired.contains_key(&admitted.event.event_id))
            .collect();
        for admitted in &eligible {
            if let Some(reason) = retired.get(&admitted.event.event_id) {
                trace.rejected.push(json!({
                    "event_id": admitted.event.event_id,
                    "step": 2,
                    "reason": format!("RETIRED: {reason}")
                }));
            }
        }
        trace.steps.push(TraceStep {
            step: 2,
            name: "retraction-revocation-supersession".to_owned(),
            event_ids: retired.keys().cloned().collect(),
            outcome: format!(
                "{} retired, {} withheld by notice",
                retired.len(),
                withheld.len()
            ),
            reason: retired.values().cloned().collect::<Vec<_>>().join("; "),
        });

        // Step 3: classify source disposition and branch reachability.
        let mut negative: Vec<&AdmittedEvent> = Vec::new();
        let mut positive: Vec<&AdmittedEvent> = Vec::new();
        for admitted in after_step2 {
            if crate::model::disposition_is_negative(&admitted.event.disposition) {
                negative.push(admitted);
                trace
                    .negative_evidence_event_ids
                    .push(admitted.event.event_id.clone());
                trace.rejected.push(json!({
                    "event_id": admitted.event.event_id,
                    "step": 3,
                    "reason": format!(
                        "NEGATIVE_EVIDENCE: disposition {} is negative evidence, not a current rule; its recency does not promote it",
                        admitted.event.disposition
                    )
                }));
            } else {
                positive.push(admitted);
            }
        }
        trace.steps.push(TraceStep {
            step: 3,
            name: "disposition-and-reachability".to_owned(),
            event_ids: trace.negative_evidence_event_ids.clone(),
            outcome: format!(
                "{} positive, {} negative evidence",
                positive.len(),
                negative.len()
            ),
            reason: "rejected/reverted proposals are negative evidence, not current rules"
                .to_owned(),
        });

        // Step 4: expire temporary/incident/experiment evidence by lifetime.
        let mut live: Vec<&AdmittedEvent> = Vec::new();
        for admitted in positive {
            let event = &admitted.event;
            if event.effective_from.as_str() > input.as_of.as_str() {
                trace.expired_event_ids.push(event.event_id.clone());
                trace.counterfactual.push(format!(
                    "{} becomes effective at {}",
                    event.event_id, event.effective_from
                ));
                trace.rejected.push(json!({
                    "event_id": event.event_id,
                    "step": 4,
                    "reason": format!("NOT_YET_EFFECTIVE: effective_from {} has not been reached", event.effective_from)
                }));
                continue;
            }
            if let Some(until) = expiry_of(event) {
                if until.as_str() <= input.as_of.as_str() {
                    trace.expired_event_ids.push(event.event_id.clone());
                    trace.counterfactual.push(format!(
                        "{} ({}) expired at {}; a renewed or refreshed observation, or a durable rule, from {} ({}) would restore it",
                        event.event_id, event.disposition, until, event.authority_id, event.authority_scope
                    ));
                    trace.rejected.push(json!({
                        "event_id": event.event_id,
                        "step": 4,
                        // The published reason cites the event's own declared
                        // validity only. Stamping the reader's as_of into it
                        // made one immutable fact serialise differently on
                        // every read (architecture section 6: the projection is
                        // a function of its inputs, not of when it was read).
                        "reason": format!(
                            "EXPIRED: declared validity ended at {until}; temporary evidence past its validity is not a current rule"
                        )
                    }));
                    continue;
                }
            }
            live.push(admitted);
        }
        trace.steps.push(TraceStep {
            step: 4,
            name: "expire-transient".to_owned(),
            event_ids: trace.expired_event_ids.clone(),
            outcome: format!("{} live, {} expired", live.len(), trace.expired_event_ids.len()),
            reason: "declared effective_until, or the default transient lifetime for draft/proposed/incident/experiment/workaround".to_owned(),
        });

        // Step 5: collapse exact semantic duplicates, retaining provenance.
        let mut clusters: BTreeMap<String, Vec<&AdmittedEvent>> = BTreeMap::new();
        for admitted in &live {
            if support_retired_ids.contains(&admitted.event.event_id) {
                continue;
            }
            clusters
                .entry(statement_identity(&admitted.event))
                .or_default()
                .push(admitted);
        }
        trace.steps.push(TraceStep {
            step: 5,
            name: "collapse-duplicates".to_owned(),
            event_ids: live
                .iter()
                .map(|admitted| admitted.event.event_id.clone())
                .collect(),
            outcome: format!(
                "{} distinct statement(s) from {} event(s)",
                clusters.len(),
                live.len()
            ),
            reason: "exact semantic duplicates collapse; provenance multiplicity is retained"
                .to_owned(),
        });

        // Step 6: independence versus common-source repetition.
        let mut heads: Vec<Head> = Vec::new();
        let mut revoked_support_heads: Vec<(String, Vec<String>, String)> = Vec::new();
        for (identity, members) in clusters {
            // Revocation cascade (architecture §3): once a client has observed
            // a cursor at or beyond a revocation, a statement whose only
            // admissible support was the revoked key withdraws from trusted
            // projection; one with other support stays current and records
            // the withdrawn support.
            let revoked_members: Vec<&AdmittedEvent> = members
                .iter()
                .copied()
                .filter(|member| revocation_of(&member.event).is_some())
                .collect();
            let members: Vec<&AdmittedEvent> = if revoked_members.len() == members.len() {
                let revoked_at = revoked_members
                    .first()
                    .and_then(|member| revocation_of(&member.event))
                    .map(|revocation| revocation.cursor.clone())
                    .unwrap_or_default();
                for member in &revoked_members {
                    trace.rejected.push(json!({
                        "event_id": member.event.event_id,
                        "step": 6,
                        "reason": format!(
                            "SUPPORT_REVOKED: the signing key was revoked at authority cursor {revoked_at} and no independently admissible support remains; withdrawn from trusted projection under the destination owner"
                        )
                    }));
                }
                revoked_support_heads.push((
                    identity,
                    revoked_members
                        .iter()
                        .map(|member| member.event.event_id.clone())
                        .collect(),
                    revoked_at,
                ));
                continue;
            } else {
                for member in &revoked_members {
                    support_retired_ids.insert(member.event.event_id.clone());
                    trace.counterfactual.push(format!(
                        "support {} was withdrawn because its signing key was revoked; the statement stays current on its remaining independent support",
                        member.event.event_id
                    ));
                }
                members
                    .into_iter()
                    .filter(|member| revocation_of(&member.event).is_none())
                    .collect()
            };
            let mut sources: BTreeSet<String> = BTreeSet::new();
            for member in &members {
                sources.insert(member.source_identity.clone().unwrap_or_else(|| {
                    format!("{}|{}", member.event.authority_id, member.event.signer)
                }));
            }
            let Some(representative) = members.iter().copied().min_by(|left, right| {
                cursor_order(&left.store_cursor, &right.store_cursor)
                    .then_with(|| left.event.event_id.cmp(&right.event.event_id))
            }) else {
                continue;
            };
            let Some(newest) = members.iter().copied().max_by(|left, right| {
                cursor_order(&left.store_cursor, &right.store_cursor)
                    .then_with(|| left.event.event_id.cmp(&right.event.event_id))
            }) else {
                continue;
            };
            let rank = members
                .iter()
                .map(|member| {
                    authority_rank_governed(
                        &member.event,
                        member.origin_trust.as_deref(),
                        governance,
                    )
                })
                .max()
                .unwrap_or(0);
            heads.push(Head {
                identity,
                representative,
                newest,
                support: members
                    .iter()
                    .map(|member| member.event.event_id.clone())
                    .collect(),
                independent: sources.len(),
                rank,
                withheld: members
                    .iter()
                    .any(|member| withheld.contains_key(&member.event.event_id)),
            });
        }
        trace.steps.push(TraceStep {
            step: 6,
            name: "independence".to_owned(),
            event_ids: heads
                .iter()
                .map(|head| head.representative.event.event_id.clone())
                .collect(),
            outcome: heads
                .iter()
                .map(|head| {
                    format!(
                        "{}: {} support, {} independent",
                        head.representative.event.event_id,
                        head.support.len(),
                        head.independent
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
            reason: "repetition from one source is not corroboration; no vote-count winner"
                .to_owned(),
        });

        // Step 7: surface incompatible surviving heads as conflict, applying
        // the explicit decay policy only inside an authority-equivalent set.
        heads.sort_by(|left, right| {
            right.rank.cmp(&left.rank).then_with(|| {
                left.representative
                    .event
                    .fact_id
                    .cmp(&right.representative.event.fact_id)
            })
        });
        let mut conflict_ids = Vec::new();
        let mut current_head: Option<&Head> = None;
        let mut contradicted_lower: Vec<&Head> = Vec::new();
        if let Some(top_rank) = heads.first().map(|head| head.rank) {
            let mut top: Vec<&Head> = heads.iter().filter(|head| head.rank == top_rank).collect();
            let lower: Vec<&Head> = heads.iter().filter(|head| head.rank < top_rank).collect();
            if top.len() > 1 {
                // Decay policy: observations from the same source decay to the newest cursor.
                let all_observations = top
                    .iter()
                    .all(|head| head.representative.event.atom_kind == "observation");
                let same_source = top
                    .iter()
                    .map(|head| {
                        head.representative
                            .source_identity
                            .clone()
                            .unwrap_or_default()
                    })
                    .collect::<BTreeSet<_>>()
                    .len()
                    == 1;
                let all_rationale = top
                    .iter()
                    .all(|head| head.representative.event.atom_kind == "rationale");
                if all_observations && same_source {
                    top.sort_by(|left, right| {
                        cursor_order(&right.newest.store_cursor, &left.newest.store_cursor)
                            .then_with(|| {
                                left.representative
                                    .event
                                    .fact_id
                                    .cmp(&right.representative.event.fact_id)
                            })
                    });
                    trace.decay_policy_applied =
                        Some("newest-cursor-within-same-source".to_owned());
                    current_head = top.first().copied();
                    for head in top.iter().skip(1) {
                        trace.counterfactual.push(format!(
                            "{} decayed under the observation policy; it would return if the source re-observed it",
                            head.representative.event.event_id
                        ));
                    }
                } else if all_rationale {
                    current_head = top.first().copied();
                } else {
                    conflict_ids = top
                        .iter()
                        .map(|head| head.representative.event.event_id.clone())
                        .collect();
                }
            } else if top.len() == 1
                && top[0].representative.event.store_kind == "company"
                && top[0]
                    .representative
                    .event
                    .authority_scope
                    .starts_with("architecture:")
                && lower.iter().any(|head| {
                    head.representative.event.store_kind == "codebase"
                        && crate::model::disposition_is_durable(
                            &head.representative.event.disposition,
                        )
                })
            {
                // P-5: accepted code contradicting a current Company
                // architecture fact is a two-head conflict; authority rank
                // cannot silently win and the local code cannot silently
                // override. A merely proposed change is not drift: it is set
                // aside below as a proposal that was never accepted or merged.
                conflict_ids = top
                    .iter()
                    .chain(lower.iter().filter(|head| {
                        head.representative.event.store_kind == "codebase"
                            && crate::model::disposition_is_durable(
                                &head.representative.event.disposition,
                            )
                    }))
                    .map(|head| head.representative.event.event_id.clone())
                    .collect();
            } else {
                current_head = top.first().copied();
            }
            contradicted_lower = lower
                .into_iter()
                .filter(|head| {
                    !conflict_ids.contains(&head.representative.event.event_id)
                        && current_head.is_none_or(|current| current.identity != head.identity)
                })
                .collect();
        }
        // Lower heads that never became current: a proposal is set aside as
        // negative-weight evidence (never accepted or merged); a live runtime
        // observation defeats a code default for the operational question
        // without acquiring architecture authority; any other durable lower
        // head is a contradiction the owning authority must resolve.
        let mut contradictions: Vec<&Head> = Vec::new();
        for head in &contradicted_lower {
            let event = &head.representative.event;
            if crate::model::disposition_is_transient(&event.disposition) {
                let copies = head.support.len();
                trace.rejected.push(json!({
                    "event_id": event.event_id,
                    "step": 7,
                    "reason": format!(
                        "PROPOSED_NOT_ACCEPTED: disposition {} was never accepted or merged, so it does not displace the current rule; {} repetition(s) from {} independent source(s) add no independent corroboration",
                        event.disposition, copies, head.independent
                    )
                }));
                trace.counterfactual.push(format!(
                    "an accepted or merged disposition for {} signed by the authority owning {} would make it a candidate current statement; repetition alone never would",
                    event.event_id, event.authority_scope
                ));
                continue;
            }
            let runtime_wins = current_head.is_some_and(|current| {
                current
                    .representative
                    .event
                    .authority_scope
                    .starts_with("environment:")
                    && current.representative.event.atom_kind == "observation"
                    && !event.authority_scope.starts_with("environment:")
            });
            if runtime_wins {
                let current = current_head.map(|current| current.representative.event.clone());
                let freshness = current
                    .as_ref()
                    .and_then(expiry_of)
                    .unwrap_or_else(|| "its freshness deadline".to_owned());
                trace.rejected.push(json!({
                    "event_id": event.event_id,
                    "step": 7,
                    "reason": format!(
                        "DEFEATED_BY_RUNTIME: the live runtime observation from the registered environment owner {} defeats this code-default diagnosis for the operational question; no architecture decision is rewritten",
                        current.as_ref().map(|event| event.authority_id.as_str()).unwrap_or("unknown")
                    )
                }));
                trace.counterfactual.push(format!(
                    "at the observation freshness deadline {} the runtime value lapses into an owned Unknown for {}; a fresh runtime observation with a different value would change the diagnosis",
                    freshness,
                    current.as_ref().map(|event| event.authority_id.as_str()).unwrap_or("the environment owner")
                ));
                continue;
            }
            trace.rejected.push(json!({
                "event_id": event.event_id,
                "step": 7,
                "reason": "CONTRADICTED: lower-authority evidence contradicts the current rule; it is recorded for the owning authority, not promoted"
            }));
            contradictions.push(*head);
        }
        let contradicted_lower = contradictions;
        for event_id in &conflict_ids {
            trace.rejected.push(json!({
                "event_id": event_id,
                "step": 7,
                "reason": "CONFLICT: incompatible surviving head; neither head is current until an authorized parent-bound event resolves the conflict"
            }));
        }
        trace.conflict_event_ids = conflict_ids.clone();
        trace.steps.push(TraceStep {
            step: 7,
            name: "conflict".to_owned(),
            event_ids: conflict_ids.clone(),
            outcome: if conflict_ids.is_empty() {
                format!(
                    "no same-authority conflict; {} lower-authority contradiction(s)",
                    contradicted_lower.len()
                )
            } else {
                format!(
                    "{} incompatible heads at equal authority",
                    conflict_ids.len()
                )
            },
            reason: "timestamps and file order never choose among incompatible heads".to_owned(),
        });

        // Step 8/9: derive one current fact or an owned Unknown.
        let decision_blocked = format!("use of logical key {logical_key}");
        if unregistered_environment {
            let scope = group
                .iter()
                .map(|admitted| admitted.event.authority_scope.as_str())
                .find(|scope| scope.starts_with("environment:"))
                .unwrap_or("environment:unknown")
                .to_owned();
            let steward_identity = input
                .steward_authority_id
                .as_deref()
                .unwrap_or("company-steward");
            let mut unknown = derive_unknown(
                &logical_key,
                &input.store_kind,
                "environment-registry",
                &scope,
                &decision_blocked,
                "company-steward",
                Some(steward_identity),
                &format!(
                    "Environment {scope} is not in the authority registry. Register its owner before this runtime observation can be trusted."
                ),
                9_000,
                trace
                    .rejected
                    .iter()
                    .filter_map(|value| value.get("event_id"))
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                input.as_of.as_str(),
            );
            if input.steward_authority_id.is_none() {
                unknown.status = "UNKNOWN_OWNER_UNRESOLVED".to_owned();
            }
            trace.state = "unknown".to_owned();
            trace.free_form_owner_admitted = Some(false);
            trace.unknown_id = Some(unknown.unknown_id.clone());
            trace.counterfactual.push(format!(
                "a steward-signed registry republication that registers {scope} with exactly one deploy owner and public key would make this runtime observation admissible; a free-form owner string never would"
            ));
            unknowns.push(unknown);
            bump(&mut counts, "unknown");
        } else if !conflict_ids.is_empty() {
            let scope = heads
                .first()
                .map(|head| head.representative.event.scope.clone())
                .unwrap_or_else(|| "unknown".to_owned());
            let owner_role = owner_role_for_scope(input, &scope);
            let owner_identity =
                authority_owner_for_scope(input, &scope, repository_scope(&group).as_deref());
            let mut unknown = derive_unknown(
                &logical_key,
                &input.store_kind,
                "conflict",
                &scope,
                &decision_blocked,
                owner_role,
                owner_identity.as_deref(),
                &conflict_question(&logical_key, &conflict_ids, &heads),
                heads
                    .iter()
                    .map(|head| head.representative.event.distortion.loss_if_absent)
                    .max()
                    .unwrap_or(9_000),
                conflict_ids.clone(),
                input.as_of.as_str(),
            );
            unknown.authority_scopes = heads
                .iter()
                .map(|head| head.representative.event.authority_scope.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            trace.state = "conflict".to_owned();
            trace.unknown_id = Some(unknown.unknown_id.clone());
            trace.counterfactual.push("a parent-bound supersession or retraction from the owning authority resolves the conflict".to_owned());
            trace.counterfactual.push(format!(
                "a signed answer from {} ({}) naming the discriminating evidence closes the Unknown and selects the current statement",
                unknown.owner_identity, unknown.owner_role
            ));
            if owner_identity.is_some() {
                unknowns.push(unknown);
            } else {
                mark_owner_unresolved_and_emit_registry_unknown(
                    input,
                    unknown,
                    &scope,
                    &logical_key,
                    &mut registry_unknown_emitted,
                    &mut unknowns,
                    input.as_of.as_str(),
                );
            }
            bump(&mut counts, "conflict");
        } else if let Some(head) = current_head {
            let event = &head.representative.event;
            let mut stale_reasons = Vec::new();
            let mut trust = "trusted".to_owned();
            let criticality = if event.distortion.loss_if_absent >= 7_500 {
                "safety_critical".to_owned()
            } else {
                "advisory".to_owned()
            };
            if company_stale && input.store_kind == "company" {
                stale_reasons.push("certificate-or-root-invalid".to_owned());
                trust = "withheld".to_owned();
            }
            if input.store_kind == "company" && !input.revocation_fresh {
                stale_reasons.push("REVOCATION_STALE".to_owned());
                trust = if crate::model::criticality_is_safety(&criticality) {
                    "withheld".to_owned()
                } else {
                    "excluded".to_owned()
                };
            }
            if input.store_kind == "company" && fact_expired {
                stale_reasons.push("CACHE_EXPIRED".to_owned());
                if crate::model::criticality_is_safety(&criticality) {
                    trust = "withheld".to_owned();
                } else if trust == "trusted" {
                    trust = "excluded".to_owned();
                }
            }
            if head.withheld {
                stale_reasons.push("misextraction-notice".to_owned());
                trust = "withheld".to_owned();
            }
            let status = if trust == "trusted" {
                "current"
            } else {
                "withheld"
            };
            let fact = CurrentFact {
                // Governance is applied here, not at read time: the view records the
                // standing that actually decided the outcome, including any demotion
                // a ruling over these paths imposed.
                standing: governance
                    .map(|g| g.standing_for(event))
                    .unwrap_or_else(|| {
                        crate::model::effective_standing(&event.standing, &event.provenance)
                    }),
                provenance: event.provenance.clone(),
                governs_paths: event.governs_paths.clone(),
                anchors: event.anchors.clone(),
                fact_id: event.fact_id.clone(),
                event_id: event.event_id.clone(),
                logical_key: logical_key.clone(),
                atom_kind: event.atom_kind.clone(),
                scope: event.scope.clone(),
                statement: event.statement.clone(),
                status: status.to_owned(),
                disposition: event.disposition.clone(),
                authority_id: event.authority_id.clone(),
                authority_scope: event.authority_scope.clone(),
                store_kind: event.store_kind.clone(),
                effective_from: event.effective_from.clone(),
                effective_until: expiry_of(event),
                distortion: event.distortion.clone(),
                company_refs: event.company_refs.clone(),
                evidence_refs: event.evidence_refs.clone(),
                support_event_ids: head.support.clone(),
                independent_support_count: head.independent,
                redundancy_with: event.redundancy_with.clone(),
                complements: event.complements.clone(),
                confidence: event.confidence.0,
                criticality,
                trust: trust.clone(),
                stale_reasons: stale_reasons.clone(),
                authority_snapshot_cursor: input.authority_cursor.clone(),
                effective_dependence_class: None,
            };
            trace.current_fact_id = Some(fact.fact_id.clone());
            trace.state = status.to_owned();
            trace.counterfactual.push(format!(
                "a parent-bound supersession or retraction of {} signed by {} ({}) would retire the current rule",
                event.event_id, event.authority_id, event.authority_scope
            ));
            for (retired_id, reason) in &retired {
                if reason.starts_with("superseded by") || reason.starts_with("conflict resolved by")
                {
                    trace.counterfactual.push(format!(
                        "{retired_id} was retired ({reason}); it would return only if that supersession were itself retracted"
                    ));
                }
            }
            if trust != "trusted" {
                let scope = event.authority_scope.clone();
                let unknown_role = if stale_reasons.iter().any(|r| r == "REVOCATION_STALE") {
                    "company-steward"
                } else {
                    owner_role_for_scope(input, &scope)
                };
                let owner_identity =
                    authority_owner_for_scope(input, &scope, repository_scope(&group).as_deref());
                let unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    if head.withheld {
                        "misextraction"
                    } else {
                        "stale"
                    },
                    &scope,
                    &decision_blocked,
                    unknown_role,
                    owner_identity.as_deref(),
                    &format!(
                        "Fact {} is withheld ({}). Refresh the authority snapshot or supply corrected evidence before it is trusted.",
                        event.fact_id,
                        stale_reasons.join(",")
                    ),
                    event.distortion.loss_if_absent,
                    head.support.clone(),
                    input.as_of.as_str(),
                );
                trace.unknown_id = Some(unknown.unknown_id.clone());
                if owner_identity.is_some() {
                    unknowns.push(unknown);
                } else {
                    mark_owner_unresolved_and_emit_registry_unknown(
                        input,
                        unknown,
                        &scope,
                        &logical_key,
                        &mut registry_unknown_emitted,
                        &mut unknowns,
                        input.as_of.as_str(),
                    );
                }
                bump(&mut counts, "withheld");
            } else {
                bump(&mut counts, "current");
            }
            facts.push(fact);
            for lower in &contradicted_lower {
                let scope = event.authority_scope.clone();
                let unknown_role = if scope.starts_with("architecture:") {
                    "chief-architect"
                } else {
                    owner_role_for_scope(input, &scope)
                };
                let owner_identity =
                    authority_owner_for_scope(input, &scope, repository_scope(&group).as_deref());
                let unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    "contradiction",
                    &scope,
                    &format!(
                        "drift between {} and the current rule {}",
                        lower.representative.event.event_id, event.fact_id
                    ),
                    unknown_role,
                    owner_identity.as_deref(),
                    &format!(
                        "Lower-authority evidence {} ({}) contradicts current {} {}. Is the current rule still the intended direction, or should it be superseded?",
                        lower.representative.event.event_id,
                        lower.representative.event.atom_kind,
                        event.atom_kind,
                        event.fact_id
                    ),
                    event
                        .distortion
                        .loss_if_absent
                        .max(lower.representative.event.distortion.loss_if_absent),
                    vec![
                        lower.representative.event.event_id.clone(),
                        event.event_id.clone(),
                    ],
                    input.as_of.as_str(),
                );
                trace.counterfactual.push(format!(
                    "a signed supersession by {} would make {} the current rule; without it the higher authority stays current",
                    event.authority_id, lower.representative.event.event_id
                ));
                trace
                    .conflict_event_ids
                    .push(lower.representative.event.event_id.clone());
                if owner_identity.is_some() {
                    unknowns.push(unknown);
                } else {
                    mark_owner_unresolved_and_emit_registry_unknown(
                        input,
                        unknown,
                        &scope,
                        &logical_key,
                        &mut registry_unknown_emitted,
                        &mut unknowns,
                        input.as_of.as_str(),
                    );
                }
                bump(&mut counts, "contradiction");
            }
            if !negative.is_empty() {
                trace.counterfactual.push(format!(
                    "{} rejected/reverted proposal(s) remain negative evidence and do not change the current rule",
                    negative.len()
                ));
                for rejected in &negative {
                    trace.counterfactual.push(format!(
                        "an accepted disposition for {} signed by the authority owning {} would make it a candidate to supersede the current rule; its recency alone never would",
                        rejected.event.event_id, rejected.event.authority_scope
                    ));
                }
            }
        } else {
            // Nothing survives: an expired or fully negative key produces an
            // Unknown only when evidence existed at all.
            if !trace.expired_event_ids.is_empty()
                || !negative.is_empty()
                || !trace.rejected.is_empty()
                || !support_retired_ids.is_empty()
                || !revoked_support_heads.is_empty()
            {
                let representative_scope = eligible
                    .first()
                    .map(|admitted| admitted.event.scope.clone())
                    .or_else(|| {
                        negative
                            .first()
                            .map(|admitted| admitted.event.scope.clone())
                    })
                    .unwrap_or_else(|| "unknown".to_owned());
                let revoked_at_step_1 = trace.rejected.iter().any(|entry| {
                    entry
                        .get("reason")
                        .and_then(Value::as_str)
                        .is_some_and(|reason| reason.starts_with("REVOKED"))
                });
                let kind = if !revoked_support_heads.is_empty() || revoked_at_step_1 {
                    "revoked"
                } else if !support_retired_ids.is_empty() {
                    "withdrawn"
                } else if !trace.expired_event_ids.is_empty() {
                    "expired"
                } else if !trace.rejected.is_empty() && negative.is_empty() {
                    "unverified"
                } else {
                    "withdrawn"
                };
                let (owner_role, owner_identity) = if kind == "revoked" {
                    // The apology Unknown belongs to the destination owner
                    // (Company steward or repository maintainer), never to
                    // the revoked principal.
                    destination_owner(input, &group)
                } else {
                    (
                        owner_role_for_scope(input, &representative_scope),
                        authority_owner_for_scope(
                            input,
                            &representative_scope,
                            repository_scope(&group).as_deref(),
                        ),
                    )
                };
                let question = match kind {
                    "revoked" => format!(
                        "The only support for logical key {logical_key} was signed by a key revoked at authority cursor {}; an independently admissible support or a signed withdrawal from the destination owner closes this apology Unknown.",
                        revoked_support_heads
                            .first()
                            .map(|(_, _, cursor)| cursor.as_str())
                            .unwrap_or(input.authority_cursor.as_str())
                    ),
                    "expired" => format!(
                        "The only evidence for logical key {logical_key} expired. Is the workaround, incident value, or observation still in force?"
                    ),
                    "unverified" => format!(
                        "Evidence for logical key {logical_key} exists but none of it is verified by a resolvable certificate or registry entry."
                    ),
                    _ => format!(
                        "Every proposal for logical key {logical_key} was rejected or reverted. What is the intended rule?"
                    ),
                };
                let mut unknown = derive_unknown(
                    &logical_key,
                    &input.store_kind,
                    kind,
                    &representative_scope,
                    &decision_blocked,
                    owner_role,
                    owner_identity.as_deref(),
                    &question,
                    9_000,
                    trace
                        .expired_event_ids
                        .iter()
                        .chain(trace.negative_evidence_event_ids.iter())
                        .cloned()
                        .chain(
                            revoked_support_heads
                                .iter()
                                .flat_map(|(_, support, _)| support.iter().cloned()),
                        )
                        .collect(),
                    input.as_of.as_str(),
                );
                unknown.authority_scopes = eligible
                    .iter()
                    .map(|admitted| admitted.event.authority_scope.clone())
                    .chain(
                        negative
                            .iter()
                            .map(|admitted| admitted.event.authority_scope.clone()),
                    )
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                if kind == "revoked" {
                    trace.counterfactual.push(
                        "an independently admissible support signed by an active registered key, or a steward republication that re-registers the key at a newer authority cursor, would restore the statement".to_owned(),
                    );
                }
                trace.state = kind.to_owned();
                trace.unknown_id = Some(unknown.unknown_id.clone());
                if owner_identity.is_some() {
                    unknowns.push(unknown);
                } else {
                    mark_owner_unresolved_and_emit_registry_unknown(
                        input,
                        unknown,
                        &representative_scope,
                        &logical_key,
                        &mut registry_unknown_emitted,
                        &mut unknowns,
                        input.as_of.as_str(),
                    );
                }
                bump(&mut counts, kind);
            }
        }
        trace.steps.push(TraceStep {
            step: 8,
            name: "derive-current-or-unknown".to_owned(),
            event_ids: trace.current_fact_id.iter().cloned().collect(),
            outcome: trace.state.clone(),
            reason: "one current fact only when authority and lifecycle make it unambiguous; otherwise an owned Unknown with the discriminating evidence".to_owned(),
        });
        traces.push(trace);
    }

    // Explicit Unknown events: open ones are surfaced; closed ones are history.
    // A later closed record with the same stable ID retires the earlier open
    // record without rewriting append-only history.
    let closed_unknown_ids: BTreeSet<&str> = input
        .unknowns
        .iter()
        .filter(|unknown| unknown.status == "closed" || unknown.status == "superseded")
        .map(|unknown| unknown.fact_id.as_str())
        .collect();
    unknowns.retain(|unknown| !closed_unknown_ids.contains(unknown.unknown_id.as_str()));

    // `shrug` is a ruling that no ruling is wanted. It is the difference between a
    // tool that asks a question once and one that becomes 472 hoops: without it,
    // every ambiguity nobody cares about resurfaces on every session, forever.
    //
    // Distinct from `unruled`, which means nobody has decided yet and must keep
    // asking. A shrug is somebody deciding, and it is honoured wherever the question
    // came from -- filtering here rather than at each of the six derivation sites,
    // because the rule is about the key, not about how the doubt arose.
    let shrugged: BTreeSet<&str> = facts
        .iter()
        .filter(|fact| fact.atom_kind == "shrug" && fact.status == "current")
        .map(|fact| fact.logical_key.as_str())
        .collect();
    if !shrugged.is_empty() {
        unknowns.retain(|unknown| !shrugged.contains(unknown.logical_key.as_str()));
    }
    let mut open_unknown_ids = Vec::new();
    for unknown in &input.unknowns {
        if unknown.status == "open" || unknown.status == "asked" {
            open_unknown_ids.push(unknown.fact_id.clone());
            unknowns.push(DerivedUnknown {
                unknown_id: unknown.fact_id.clone(),
                logical_key: unknown.logical_key.clone(),
                scope: unknown.scope.clone(),
                decision_blocked: unknown.decision_blocked.clone(),
                owner_role: unknown.owner_role.clone(),
                owner_identity: unknown.owner_identity.clone(),
                question: unknown.question.clone(),
                closure_evidence: unknown.closure_evidence.clone(),
                loss_if_absent: unknown.distortion.loss_if_absent,
                discriminating_evidence: unknown.evidence_refs.clone(),
                status: unknown.status.clone(),
                kind: "explicit".to_owned(),
                authority_scopes: vec![unknown.authority_scope.clone()],
            });
        }
    }
    for unknown in &unknowns {
        if !open_unknown_ids.contains(&unknown.unknown_id) {
            open_unknown_ids.push(unknown.unknown_id.clone());
        }
    }
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    unknowns.sort_by(|left, right| left.unknown_id.cmp(&right.unknown_id));
    traces.sort_by(|left, right| left.logical_key.cmp(&right.logical_key));
    open_unknown_ids.sort();
    open_unknown_ids.dedup();
    counts.insert("facts".to_owned(), facts.len());
    counts.insert("unknowns".to_owned(), unknowns.len());
    counts.insert("events".to_owned(), input.events.len());
    CurrentView {
        schema: crate::model::CURRENT_VIEW_SCHEMA.to_owned(),
        store_kind: input.store_kind.clone(),
        reducer_version: REDUCER_VERSION.to_owned(),
        as_of: input.as_of.clone(),
        authority_cursor: input.authority_cursor.clone(),
        facts,
        unknowns,
        open_unknown_ids,
        traces,
        rejected: rejected_global,
        counts,
        decay_policy: decay_policy(),
    }
}

struct Head<'a> {
    identity: String,
    representative: &'a AdmittedEvent,
    newest: &'a AdmittedEvent,
    support: Vec<String>,
    independent: usize,
    rank: u8,
    withheld: bool,
}

struct DerivedUnknownSeed {
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    question: String,
    #[allow(dead_code)]
    evidence: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn derive_unknown(
    logical_key: &str,
    store_kind: &str,
    kind: &str,
    scope: &str,
    decision_blocked: &str,
    owner_role: &str,
    owner_identity: Option<&str>,
    question: &str,
    loss: u16,
    evidence: Vec<String>,
    as_of: &str,
) -> DerivedUnknown {
    let _ = as_of;
    let owner_identity = owner_identity.unwrap_or(owner_role);
    let unknown_id = format!(
        "unknown_{}",
        &crate::hash::sha256_text(&format!(
            "{store_kind}\0{logical_key}\0{kind}\0{}",
            evidence.join(",")
        ))[..40]
    );
    DerivedUnknown {
        unknown_id,
        logical_key: logical_key.to_owned(),
        scope: scope.to_owned(),
        decision_blocked: decision_blocked.to_owned(),
        owner_role: owner_role.to_owned(),
        owner_identity: owner_identity.to_owned(),
        question: question.to_owned(),
        closure_evidence: vec![format!(
            "a signed {} event from {} naming the discriminating evidence",
            if kind == "conflict" {
                "supersession or retraction"
            } else {
                "fact or answer"
            },
            owner_identity
        )],
        loss_if_absent: loss,
        discriminating_evidence: evidence,
        status: "open".to_owned(),
        kind: kind.to_owned(),
        authority_scopes: vec![scope.to_owned()],
    }
}

fn authority_owner_for_scope(
    input: &ReducerInput,
    scope: &str,
    fallback_scope: Option<&str>,
) -> Option<String> {
    if let Some(identity) = input.authority_owner_by_scope.get(scope) {
        return Some(identity.clone());
    }
    if let Some(fallback) = fallback_scope {
        if let Some(identity) = input.authority_owner_by_scope.get(fallback) {
            return Some(identity.clone());
        }
    }
    // Architecture scopes are hierarchical: a leaf diagnosis scope is owned by
    // its unique registered architecture ancestor. Ambiguous ancestors remain
    // unresolved so the reducer still raises an owned-registry Unknown.
    if !scope.starts_with("architecture:") {
        return None;
    }
    let mut resolved: Option<String> = None;
    let mut prefix = "architecture:".to_owned();
    for part in scope.split('/').skip(1) {
        prefix.push_str(part);
        if let Some(identity) = input.authority_owner_by_scope.get(&prefix) {
            if resolved.is_none() {
                resolved = Some(identity.clone());
            } else if resolved.as_deref() != Some(identity) {
                return None;
            }
        }
        prefix.push('/');
    }
    resolved
}

/// The destination store's owner: the Company steward for Company facts,
/// the registered repository maintainer for Codebase facts.
fn destination_owner(
    input: &ReducerInput,
    group: &[&AdmittedEvent],
) -> (&'static str, Option<String>) {
    let company = group
        .first()
        .is_some_and(|admitted| admitted.event.store_kind == "company")
        || input.store_kind == "company";
    if company {
        ("company-steward", input.steward_authority_id.clone())
    } else {
        let maintainer = repository_scope(group)
            .and_then(|scope| input.authority_owner_by_scope.get(&scope).cloned());
        ("repository-maintainer", maintainer)
    }
}

fn owner_role_for_scope(input: &ReducerInput, scope: &str) -> &'static str {
    if scope.starts_with("architecture:") {
        "chief-architect"
    } else if scope.starts_with("environment:") {
        "deploy-owner"
    } else if scope.starts_with("company:") {
        "company-steward"
    } else if scope.starts_with("codebase:") {
        "repository-maintainer"
    } else if scope.starts_with("approver:") {
        "approving-principal"
    } else if input.store_kind == "company" {
        "company-steward"
    } else {
        "repository-maintainer"
    }
}

fn repository_scope(group: &[&AdmittedEvent]) -> Option<String> {
    group
        .iter()
        .find_map(|admitted| admitted.event.repository_id.clone())
        .map(|uuid| format!("codebase:{uuid}"))
}

fn registry_unknown(
    input: &ReducerInput,
    scope: &str,
    logical_key: &str,
    as_of: &str,
) -> DerivedUnknown {
    let steward = input
        .steward_authority_id
        .as_deref()
        .unwrap_or("company-steward");
    let mut unknown = derive_unknown(
        logical_key,
        "company",
        "registry",
        scope,
        &format!("use of authority scope {scope}"),
        "company-steward",
        Some(steward),
        &format!(
            "The authority registry cannot resolve exactly one owner for scope {scope}; register a stable authority identity for it."
        ),
        10_000,
        Vec::new(),
        as_of,
    );
    if input.steward_authority_id.is_none() {
        unknown.status = "UNKNOWN_OWNER_UNRESOLVED".to_owned();
    }
    unknown
}

fn mark_owner_unresolved_and_emit_registry_unknown(
    input: &ReducerInput,
    mut unknown: DerivedUnknown,
    scope: &str,
    logical_key: &str,
    emitted: &mut BTreeSet<String>,
    unknowns: &mut Vec<DerivedUnknown>,
    as_of: &str,
) {
    unknown.status = "UNKNOWN_OWNER_UNRESOLVED".to_owned();
    unknowns.push(unknown);
    if emitted.insert(scope.to_owned()) {
        unknowns.push(registry_unknown(input, scope, logical_key, as_of));
    }
}

/// Opaque decimal cursor ordering: numeric when both parse, else lexical.
pub fn cursor_order(left: &str, right: &str) -> std::cmp::Ordering {
    match (left.parse::<u128>(), right.parse::<u128>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.len().cmp(&right.len()).then_with(|| left.cmp(right)),
    }
}

/// Build the derived view value written to `current.json`.
pub fn view_value(view: &CurrentView, as_of_source: &str) -> Value {
    let mut value = crate::model::value_of(view);
    value["as_of_source"] = Value::String(as_of_source.to_owned());
    value["ambient_clock_read"] = Value::Bool(false);
    value
}

impl DerivedUnknown {
    pub fn to_distortion(&self) -> Distortion {
        Distortion {
            trigger: self.decision_blocked.clone(),
            loss_if_absent: self.loss_if_absent,
            rationale: "derived by the reducer from the discriminating evidence".to_owned(),
        }
    }
}

#[cfg(test)]
mod packet10_tests {
    use super::*;
    use crate::model::{Bp, Distortion};

    fn event(
        event_id: &str,
        statement: &str,
        store_kind: &str,
        authority_scope: &str,
        disposition: &str,
        effective_until: Option<&str>,
        parents: Vec<String>,
    ) -> FactEvent {
        FactEvent {
            schema: crate::model::EVENT_SCHEMA.to_owned(),
            event_id: event_id.to_owned(),
            store_kind: store_kind.to_owned(),
            authority_id: if store_kind == "company" {
                "chief-architect".to_owned()
            } else {
                "repository-maintainer".to_owned()
            },
            authority_scope: authority_scope.to_owned(),
            repository_id: None,
            fact_id: format!("fact_{event_id}"),
            logical_key: "packet10/key".to_owned(),
            atom_kind: if disposition == "rejected" {
                "decision".to_owned()
            } else {
                "observation".to_owned()
            },
            scope: authority_scope.to_owned(),
            statement: statement.to_owned(),
            evidence_refs: Vec::new(),
            asserted_at: "2026-01-01T00:00:00.000Z".to_owned(),
            effective_from: "2026-01-01T00:00:00.000Z".to_owned(),
            effective_until: effective_until.map(str::to_owned),
            disposition: disposition.to_owned(),
            distortion: Distortion {
                trigger: "dependent decision".to_owned(),
                loss_if_absent: 7_000,
                rationale: "test".to_owned(),
            },
            parents,
            supersedes: Vec::new(),
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            company_refs: Vec::new(),
            authority_snapshot_cursor: "0".to_owned(),
            confidence: Bp(8_000),
            standing: crate::model::default_standing_pub(),
            provenance: crate::model::default_provenance_pub(),
            governs_paths: Vec::new(),
            anchors: Vec::new(),
            unresolved_uncertainty: None,
            signer: if store_kind == "company" {
                "chief-architect".to_owned()
            } else {
                "repository-maintainer".to_owned()
            },
            signature: String::new(),
            raw: None,
        }
    }

    fn admitted(
        event: FactEvent,
        source: &str,
        environment_registered: Option<bool>,
    ) -> AdmittedEvent {
        AdmittedEvent {
            event,
            verification: Verification::Verified,
            store_cursor: source.to_owned(),
            origin_trust: Some("merged-default".to_owned()),
            reachable: Some(true),
            source_identity: Some(source.to_owned()),
            environment_registered,
        }
    }

    fn input(events: Vec<AdmittedEvent>, tombstones: Vec<Tombstone>) -> ReducerInput {
        ReducerInput {
            store_kind: "mixed".to_owned(),
            events,
            unknowns: Vec::new(),
            tombstones,
            revocations: Vec::new(),
            as_of: "2026-02-01T00:00:00.000Z".to_owned(),
            authority_cursor: "0".to_owned(),
            revocation_fresh: true,
            fact_valid_until: None,
            certificate_valid: true,
            authority_owner_by_scope: BTreeMap::new(),
            steward_authority_id: None,
        }
    }

    #[test]
    fn every_origin_below_merged_default_is_ineligible_unless_authorized() {
        for class in ["approved-pr", "unreviewed-branch", "uncommitted-worktree"] {
            let mut observation = admitted(
                event(
                    &format!("origin-{class}"),
                    "branch observation",
                    "codebase",
                    "repository",
                    "current",
                    None,
                    Vec::new(),
                ),
                "source",
                None,
            );
            observation.origin_trust = Some(class.to_owned());
            let view = reduce(&input(vec![observation], Vec::new()));
            assert!(view.facts.is_empty(), "{class} produced a durable fact");
            assert!(
                view.unknowns
                    .iter()
                    .any(|unknown| unknown.logical_key == "packet10/key"),
                "{class} did not open an owned Unknown"
            );
            assert!(
                view.traces[0].rejected.iter().any(|record| record["reason"]
                    .as_str()
                    .unwrap()
                    .contains("UNTRUSTED_BRANCH")),
                "{class} was not typed as untrusted"
            );
        }

        let mut cited = event(
            "origin-authorized",
            "authorized branch observation",
            "codebase",
            "repository",
            "current",
            None,
            Vec::new(),
        );
        cited.evidence_refs = vec!["authorization:company-steward".to_owned()];
        let mut observation = admitted(cited, "source", None);
        observation.origin_trust = Some("approved-pr".to_owned());
        let view = reduce(&input(vec![observation], Vec::new()));
        assert_eq!(view.traces[0].state, "current");
        assert_eq!(view.facts[0].event_id, "origin-authorized");
    }

    #[test]
    fn support_retirement_withdraws_only_after_the_last_support() {
        let left = admitted(
            event(
                "support-1",
                "same fact",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "source-1",
            None,
        );
        let right = admitted(
            event(
                "support-2",
                "same fact",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "source-2",
            None,
        );
        let first = input(
            vec![left.clone(), right.clone()],
            vec![Tombstone {
                kind: "support_withdrawn".to_owned(),
                target_event_id: "support-1".to_owned(),
                signer_authorized: true,
                reason_code: "source-deleted".to_owned(),
                tombstone_id: "withdraw-1".to_owned(),
            }],
        );
        let view = reduce(&first);
        let fact = view
            .facts
            .iter()
            .find(|fact| fact.logical_key == "packet10/key")
            .unwrap();
        assert_eq!(fact.support_event_ids, vec!["support-2".to_owned()]);
        let last = input(
            vec![left, right],
            vec![
                Tombstone {
                    kind: "support_withdrawn".to_owned(),
                    target_event_id: "support-1".to_owned(),
                    signer_authorized: true,
                    reason_code: "source-deleted".to_owned(),
                    tombstone_id: "withdraw-1".to_owned(),
                },
                Tombstone {
                    kind: "support_withdrawn".to_owned(),
                    target_event_id: "support-2".to_owned(),
                    signer_authorized: true,
                    reason_code: "source-deleted".to_owned(),
                    tombstone_id: "withdraw-2".to_owned(),
                },
            ],
        );
        let view = reduce(&last);
        assert_eq!(view.traces[0].state, "withdrawn");
        assert!(
            view.unknowns
                .iter()
                .any(|unknown| unknown.logical_key == "packet10/key")
        );
    }

    #[test]
    fn lifecycle_notices_are_admitted_or_typed_refused() {
        let target = admitted(
            event(
                "extracted-1",
                "extracted statement",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "source-1",
            None,
        );
        let misextraction = input(
            vec![target],
            vec![Tombstone {
                kind: "misextraction".to_owned(),
                target_event_id: "extracted-1".to_owned(),
                signer_authorized: true,
                reason_code: "evidence-byte-mismatch".to_owned(),
                tombstone_id: "notice-1".to_owned(),
            }],
        );
        let view = reduce(&misextraction);
        assert!(view.traces[0].notice_admitted);
        assert_eq!(view.traces[0].state, "withheld");
        let unknown = view
            .unknowns
            .iter()
            .find(|unknown| unknown.logical_key == "packet10/key")
            .unwrap();
        assert_eq!(unknown.owner_role, "repository-maintainer");

        let target = admitted(
            event(
                "extracted-2",
                "true statement",
                "company",
                "architecture:company",
                "current",
                None,
                Vec::new(),
            ),
            "source-1",
            None,
        );
        let never_true = input(
            vec![target],
            vec![Tombstone {
                kind: "never_true".to_owned(),
                target_event_id: "extracted-2".to_owned(),
                signer_authorized: false,
                reason_code: "approver-minted".to_owned(),
                tombstone_id: "notice-2".to_owned(),
            }],
        );
        let view = reduce(&never_true);
        assert_eq!(view.traces[0].approver_minted_accepted, Some(false));
        assert!(view.rejected.iter().any(|record| {
            record["reason"]
                .as_str()
                .unwrap()
                .starts_with("AUTHORITY_WRONG_SCOPE")
        }));

        let target = admitted(
            event(
                "extracted-3",
                "true statement",
                "company",
                "architecture:company",
                "current",
                None,
                Vec::new(),
            ),
            "source-1",
            None,
        );
        let mut notice = admitted(
            event(
                "notice-3",
                "approver claims never_true",
                "company",
                "approver:review",
                "never_true",
                None,
                vec!["extracted-3".to_owned()],
            ),
            "source-2",
            None,
        );
        notice.verification = Verification::WrongScope;
        let view = reduce(&input(vec![target, notice], Vec::new()));
        assert_eq!(view.traces[0].approver_minted_accepted, Some(false));
        assert!(view.rejected.iter().any(|record| {
            record["reason"]
                .as_str()
                .unwrap()
                .starts_with("AUTHORITY_WRONG_SCOPE")
        }));
    }

    #[test]
    fn conflict_requires_an_authorized_event_parented_to_both_heads() {
        let left = admitted(
            event(
                "head-a",
                "left",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "source-1",
            None,
        );
        let right = admitted(
            event(
                "head-b",
                "right",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "source-2",
            None,
        );
        let unresolved = input(vec![left.clone(), right.clone()], Vec::new());
        assert_eq!(reduce(&unresolved).traces[0].state, "conflict");

        let parentless = event(
            "parentless",
            "later but parentless",
            "codebase",
            "repository",
            "current",
            None,
            Vec::new(),
        );
        let parentless = input(
            vec![
                left.clone(),
                right.clone(),
                admitted(parentless, "source-3", None),
            ],
            Vec::new(),
        );
        assert_eq!(reduce(&parentless).traces[0].state, "conflict");

        let mut lower_authority = event(
            "lower-authority",
            "lower authority resolution",
            "codebase",
            "repository:other",
            "current",
            None,
            vec!["head-a".to_owned(), "head-b".to_owned()],
        );
        lower_authority.atom_kind = "decision".to_owned();
        let lower_authority = input(
            vec![
                left.clone(),
                right.clone(),
                admitted(lower_authority, "source-4", None),
            ],
            Vec::new(),
        );
        assert_eq!(reduce(&lower_authority).traces[0].state, "conflict");

        let resolution = event(
            "resolve",
            "resolved",
            "codebase",
            "repository",
            "current",
            None,
            vec!["head-a".to_owned(), "head-b".to_owned()],
        );
        let resolved = input(
            vec![left, right, admitted(resolution, "source-3", None)],
            Vec::new(),
        );
        let view = reduce(&resolved);
        assert_eq!(view.traces[0].state, "current");
        assert_eq!(view.facts[0].event_id, "resolve");
    }

    #[test]
    fn unregistered_environment_creates_a_company_steward_unknown() {
        let runtime = admitted(
            event(
                "runtime-1",
                "live value",
                "codebase",
                "environment:missing",
                "deployed",
                Some("2026-03-01T00:00:00.000Z"),
                Vec::new(),
            ),
            "runtime",
            Some(false),
        );
        let view = reduce(&input(vec![runtime], Vec::new()));
        assert_eq!(view.traces[0].state, "unknown");
        assert_eq!(view.traces[0].free_form_owner_admitted, Some(false));
        let unknown = view
            .unknowns
            .iter()
            .find(|unknown| unknown.logical_key == "packet10/key")
            .unwrap();
        assert_eq!(unknown.owner_role, "company-steward");
    }

    #[test]
    fn company_architecture_and_code_drift_remain_two_conflicting_heads() {
        let architecture = admitted(
            event(
                "adr-1",
                "architecture says left",
                "company",
                "architecture:company",
                "current",
                None,
                Vec::new(),
            ),
            "company",
            None,
        );
        let drift = admitted(
            event(
                "code-1",
                "code implements right",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "code",
            None,
        );
        let view = reduce(&input(vec![architecture, drift], Vec::new()));
        assert_eq!(view.traces[0].state, "conflict");
        assert_eq!(
            view.traces[0].conflict_event_ids,
            vec!["adr-1".to_owned(), "code-1".to_owned()]
        );
    }

    #[test]
    fn temporal_disposition_independence_and_expiry_are_discerned() {
        let adr = admitted(
            event(
                "adr-current",
                "ADR remains current",
                "company",
                "architecture:company",
                "current",
                None,
                Vec::new(),
            ),
            "company",
            None,
        );
        let mut rejected = admitted(
            event(
                "pr-rejected",
                "newer rejected proposal",
                "codebase",
                "repository",
                "rejected",
                None,
                Vec::new(),
            ),
            "pr",
            None,
        );
        rejected.event.supersedes = vec!["adr-current".to_owned()];
        let view = reduce(&input(vec![adr, rejected], Vec::new()));
        assert_eq!(view.traces[0].state, "current");
        assert_eq!(
            view.traces[0].negative_evidence_event_ids,
            vec!["pr-rejected".to_owned()]
        );

        let repetitions: Vec<_> = (0..5)
            .map(|index| {
                admitted(
                    event(
                        &format!("repeat-{index}"),
                        "same conversational claim",
                        "codebase",
                        "repository",
                        "current",
                        None,
                        Vec::new(),
                    ),
                    "one-source",
                    None,
                )
            })
            .collect();
        let view = reduce(&input(repetitions, Vec::new()));
        assert_eq!(view.facts[0].independent_support_count, 1);

        let workaround = admitted(
            event(
                "workaround",
                "temporary workaround",
                "codebase",
                "environment:prod",
                "workaround",
                Some("2026-01-15T00:00:00.000Z"),
                Vec::new(),
            ),
            "runtime",
            None,
        );
        let view = reduce(&input(vec![workaround], Vec::new()));
        assert_eq!(view.traces[0].state, "expired");

        let live = admitted(
            event(
                "live-config",
                "live configuration",
                "codebase",
                "environment:prod",
                "deployed",
                Some("2026-03-01T00:00:00.000Z"),
                Vec::new(),
            ),
            "runtime",
            None,
        );
        let code_default = admitted(
            event(
                "code-default",
                "old code default",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            ),
            "code",
            None,
        );
        let view = reduce(&input(vec![live, code_default], Vec::new()));
        assert_eq!(view.facts[0].event_id, "live-config");
        assert_eq!(
            view.facts[0].effective_until.as_deref(),
            Some("2026-03-01T00:00:00.000Z")
        );
    }

    /// A ruling about a repository must reach the facts that repository actually
    /// emits. The repository adapter records location as a UUID and opaque
    /// observation references, never as a path, so matching evidence strings
    /// alone left every ingested fact ungoverned.
    #[test]
    fn a_repository_ruling_demotes_facts_carrying_only_that_repository_id() {
        let mut ruling = event(
            "retire-legacy",
            "we are retiring this service; new code goes to the replacement",
            "company",
            "company:architecture",
            "current",
            None,
            Vec::new(),
        );
        ruling.atom_kind = "directional".to_owned();
        ruling.standing = "ratified".to_owned();
        ruling.provenance = "human".to_owned();
        ruling.governs_paths = vec!["5e3211e9-3637-47f8-ba3c-38cf31dcf417".to_owned()];

        let mut ambient = event(
            "ambient-commit",
            "the prevailing pattern in the legacy service",
            "codebase",
            "repository",
            "current",
            None,
            Vec::new(),
        );
        ambient.repository_id = Some("5e3211e9-3637-47f8-ba3c-38cf31dcf417".to_owned());
        ambient.standing = "prevalent".to_owned();
        ambient.provenance = "human".to_owned();
        ambient.evidence_refs = vec!["observation:obs_037c5555".to_owned()];

        let mut elsewhere = ambient.clone();
        elsewhere.event_id = "other-repo".to_owned();
        elsewhere.fact_id = "fact_other-repo".to_owned();
        elsewhere.repository_id = Some("11111111-2222-3333-4444-555555555555".to_owned());

        let governance = Governance::build([&ruling, &ambient, &elsewhere].into_iter());
        assert_eq!(governance.standing_for(&ambient), "present");
        assert_eq!(governance.standing_for(&elsewhere), "prevalent");
        // A ruling never demotes itself.
        assert_eq!(governance.standing_for(&ruling), "ratified");
    }

    /// Path governance is a prefix of a path, not a substring of arbitrary text:
    /// a rule about `src/pay` governs files under it and nothing that merely
    /// mentions the string.
    #[test]
    fn an_anchor_path_is_governed_by_prefix_not_by_substring() {
        let mut ruling = event(
            "payment-is-the-exemplar",
            "copy Payment's reconcilers",
            "company",
            "company:architecture",
            "current",
            None,
            Vec::new(),
        );
        ruling.atom_kind = "north_star".to_owned();
        ruling.standing = "ratified".to_owned();
        ruling.provenance = "human".to_owned();
        ruling.governs_paths = vec!["src/pay".to_owned()];

        let mut under = event(
            "under-path",
            "a helper inside the governed tree",
            "codebase",
            "repository",
            "current",
            None,
            Vec::new(),
        );
        under.standing = "prevalent".to_owned();
        under.provenance = "human".to_owned();
        under.anchors = vec![crate::model::CodeAnchor {
            path: "src/payment/reconcile.ts".to_owned(),
            line_start: 10,
            line_end: 20,
            revision: None,
            span_sha256: None,
        }];

        let mut mentions = under.clone();
        mentions.event_id = "mentions-path".to_owned();
        mentions.fact_id = "fact_mentions-path".to_owned();
        mentions.anchors = vec![crate::model::CodeAnchor {
            path: "docs/notes-about-src/pay.md".to_owned(),
            line_start: 1,
            line_end: 2,
            revision: None,
            span_sha256: None,
        }];

        let governance = Governance::build([&ruling, &under, &mentions].into_iter());
        assert_eq!(governance.standing_for(&under), "present");
        assert_eq!(governance.standing_for(&mentions), "prevalent");
    }

    /// A ruling overrules the majority pattern, not a mechanically-verified
    /// fact. CI enforcing something today is true today, whatever the target
    /// state says, and an agent that stops seeing it will write code that does
    /// not build.
    #[test]
    fn governance_demotes_the_prevalent_pattern_but_not_enforced_truth() {
        let mut ruling = event(
            "target-state",
            "the target architecture for this service",
            "company",
            "company:architecture",
            "current",
            None,
            Vec::new(),
        );
        ruling.atom_kind = "north_star".to_owned();
        ruling.standing = "ratified".to_owned();
        ruling.provenance = "human".to_owned();
        ruling.governs_paths = vec!["example/property".to_owned()];

        let make = |id: &str, standing: &str| {
            let mut fact = event(
                id,
                "a fact inside the governed repository",
                "codebase",
                "repository",
                "current",
                None,
                Vec::new(),
            );
            fact.fact_id = format!("fact_{id}");
            fact.standing = standing.to_owned();
            fact.provenance = "human".to_owned();
            fact.evidence_refs = vec!["source:example/property/src/x.ts".to_owned()];
            fact
        };
        let prevalent = make("majority", "prevalent");
        let enforced = make("ci", "enforced");
        let exemplary = make("copy-this", "exemplary");

        let governance =
            Governance::build([&ruling, &prevalent, &enforced, &exemplary].into_iter());
        assert_eq!(governance.standing_for(&prevalent), "present");
        assert_eq!(governance.standing_for(&enforced), "enforced");
        assert_eq!(governance.standing_for(&exemplary), "exemplary");
    }
}

#[cfg(test)]
mod revocation_scope_tests {
    use super::Revocation;

    #[test]
    fn a_scope_revocation_covers_only_its_scope() {
        let key = Revocation::of_key("k".to_owned(), "1".to_owned(), String::new());
        assert!(key.covers("k", "architecture:storage"));
        assert!(key.covers("k", "architecture:scheduling"));
        assert!(!key.covers("other", "architecture:storage"));
        let mut scoped = key.clone();
        scoped.scope = Some("architecture:storage".to_owned());
        assert!(scoped.covers("k", "architecture:storage"));
        assert!(!scoped.covers("k", "architecture:scheduling"));
    }

    #[test]
    fn a_key_revocation_keeps_its_published_bytes() {
        // Snapshots publish key revocations; the new fields stay off the wire
        // unless set, so an existing snapshot's bytes do not change.
        let key = Revocation::of_key("k".to_owned(), "1".to_owned(), "t".to_owned());
        assert_eq!(
            serde_json::to_value(&key).unwrap(),
            serde_json::json!({"revoked_key": "k", "cursor": "1", "effective_at": "t"})
        );
    }
}
