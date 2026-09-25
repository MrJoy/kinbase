//! Canonical durable messages (architecture §3) with the ratified field
//! names verbatim. Every signed message is a JSON object whose `signer` is
//! the 64-hex Ed25519 public key and whose `signature` is computed over the
//! JCS bytes of the object without `signature`.

use crate::crypto::{PrivateKey, PublicKey};
use crate::error::ContractError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const EVENT_SCHEMA: &str = "kinbase-event/1";
pub const UNKNOWN_SCHEMA: &str = "kinbase-unknown/1";
pub const MANIFEST_SCHEMA: &str = "kinbase-manifest/1";
pub const CERTIFICATE_SCHEMA: &str = "kinbase-repo-certificate/1";
pub const REGISTRY_SCHEMA: &str = "kinbase-authority-registry/1";
pub const ANSWER_SCHEMA: &str = "kinbase-answer/1";
pub const QUESTION_SCHEMA: &str = "kinbase-question/1";
pub const TOMBSTONE_SCHEMA: &str = "kinbase-tombstone/1";
pub const REVOCATION_SCHEMA: &str = "kinbase-revocation/1";
pub const ROTATION_SCHEMA: &str = "kinbase-rotation/1";
pub const RECEIPT_SCHEMA: &str = "kinbase-receipt/1";
pub const CURRENT_VIEW_SCHEMA: &str = "kinbase-current-view/1";
pub const MAX_CONFIDENCE: u16 = 10_000;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;
pub const DIGEST_ALG_VERSION: &str = "kinbase-digest/1";

/// Basis-point score field that also accepts the qualitative vocabulary
/// (`high`/`medium`/`low`) planted by fixtures; serialized as an integer.
/// Semantic use only — signature verification always uses the original
/// immutable bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bp(pub u16);

impl Serialize for Bp {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.0)
    }
}

impl<'de> Deserialize<'de> for Bp {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::Number(number) => {
                let raw = number
                    .as_i64()
                    .ok_or_else(|| serde::de::Error::custom("basis points must be an integer"))?;
                if !(0..=10_000).contains(&raw) {
                    return Err(serde::de::Error::custom(
                        "basis points must be within 0..=10000",
                    ));
                }
                Ok(Bp(raw as u16))
            }
            Value::String(text) => match text.to_lowercase().as_str() {
                "high" | "critical" | "safety" | "safety_critical" | "irreversible" => {
                    Ok(Bp(9_000))
                }
                "medium" | "moderate" => Ok(Bp(6_000)),
                "low" | "advisory" | "reversible" => Ok(Bp(3_000)),
                "none" | "" => Ok(Bp(0)),
                other => other
                    .parse::<u16>()
                    .ok()
                    .filter(|value| *value <= 10_000)
                    .map(Bp)
                    .ok_or_else(|| serde::de::Error::custom("unrecognized qualitative score")),
            },
            _ => Err(serde::de::Error::custom(
                "score must be an integer or qualitative label",
            )),
        }
    }
}

impl From<u16> for Bp {
    fn from(value: u16) -> Self {
        Bp(value)
    }
}

/// Closed atom kinds (P-2).
pub const ATOM_KINDS: [&str; 14] = [
    "claim",
    "question",
    "decision",
    "constraint",
    "rationale",
    "observation",
    "reference",
    "relaxation",
    // A brownfield repository contains every pattern anyone ever tried. These
    // kinds are how a human says which of them is the one to follow.
    "north_star",  // a document that defines direction; contradicting code is stale
    "invariant",   // must not change; violating it is an error, not a style opinion
    "directional", // we are moving toward this; new code must, existing is grandfathered
    "shrug",       // explicitly nobody's call to make -- never ask about this again
    "interface",   // a named shape at a code location: struct, signature, return type
    "exemplar",    // of the several implementations that exist, emulate this one
];

/// Truth-value hierarchy, strongest first.
///
/// The problem this solves: in a brownfield repository, frequency is not authority.
/// `monorepo/` has more commits than any other repository and is being retired. Five
/// implementations of one thing may exist and none of them be right. Nothing in the
/// evidence itself says which signal wins, so a rank has to be carried explicitly.
///
/// A fact's standing is not how sure the extractor was -- that is `confidence`. It
/// is how much weight the claim carries when evidence disagrees.
/// Whose word it is, which decides how high a fact may rank.
///
/// the founder's point, and it is the ordering a company actually runs on: a directive
/// he gives directly outranks his own architecture documents, which outrank
/// everything else. And software is compromise, so none of this is absolute -- a
/// higher standing demotes weaker evidence to `present`, it never deletes it. The
/// code that contradicts a north star stays retrievable and stops being direction.
pub const AUTHORITY_TIERS: [&str; 3] = [
    "founder_directive", // said directly, in a session or a signed answer
    "founder_document",  // an architecture document filed as current
    "other",             // everything else, ranked on its own merits
];

/// The ceiling an authority tier permits.
pub fn tier_ceiling(tier: &str) -> &'static str {
    match tier {
        "founder_directive" => "authoritative",
        "founder_document" => "ratified",
        _ => "prevalent",
    }
}

pub const STANDINGS: [&str; 7] = [
    "authoritative", // a named authority answered this exact question, in scope
    "ratified",      // an approved organization decision, within its declared scope
    "enforced",      // mechanically true right now: CI, types, lint
    "exemplary",     // a designated canonical implementation
    "prevalent",     // the majority pattern in merged human-authored code
    "present",       // it exists somewhere; presence is not endorsement
    "unruled",       // evidence conflicts and no authority has spoken -- say so, ask
];

/// How a piece of evidence came to exist.
///
/// This gates what standing evidence may reach, and it is the guard against a
/// feedback loop that would otherwise eat the whole idea: an agent writes forty
/// files in one pattern, prevalence reports that pattern as the house style, the
/// next agent reads that as direction and writes more of it. The signal stops
/// measuring what the company decided and starts measuring what an agent guessed.
pub const PROVENANCE: [&str; 6] = [
    "human",        // a person authored it deliberately
    "human_review", // an agent wrote it, a person reviewed and merged it
    // A person said it; a machine wrote it down. The words are human and the
    // failure mode is mis-hearing a name or a piece of jargon, not inventing a
    // conclusion. That is categorically different from a summary, and collapsing
    // the two would throw away the richest record of what people actually decided.
    "transcript",
    "ai_generated", // an agent authored the words, including meeting summaries
    "bot",          // automation: dependabot, codegen, formatters
    "unknown",      // unlabelled history; most of any existing repository
];

/// Rank of a standing; lower is stronger. Unknown standings sort last.
pub fn standing_rank(standing: &str) -> usize {
    STANDINGS
        .iter()
        .position(|value| *value == standing)
        .unwrap_or(STANDINGS.len())
}

/// True when `a` wins against `b` on a disagreement.
pub fn outranks(a: &str, b: &str) -> bool {
    standing_rank(a) < standing_rank(b)
}

/// The strongest standing this provenance may reach.
///
/// Agent-written code is real evidence that a file exists and what it does. It is
/// not evidence that anyone chose it, so it can never enter the ranks that mean
/// "this is the direction". A person reviewing an agent's output approved that
/// output; they did not thereby set a convention, so `human_review` stops one rank
/// below `prevalent`.
pub fn provenance_ceiling(provenance: &str) -> &'static str {
    match provenance {
        "human" => "authoritative",
        "human_review" => "prevalent",
        // A transcript can carry a named authority saying the thing that settles a
        // question, which makes it far better evidence than a summary of the same
        // meeting. It still stops below `ratified`, because speech in a meeting is
        // not a considered ruling -- people think out loud, and half of what is said
        // is discarded by the end of the hour. Its real value is as a high-quality
        // *trigger*: "you said this on the 8th, is that a ruling?" is a question
        // worth one minute of an architect's time, and the loop exists to ask it.
        "transcript" => "prevalent",
        "ai_generated" | "bot" => "present",
        // Unlabelled history is the bulk of any real repository and cannot be
        // recovered retroactively. It counts as weak evidence, never as direction.
        _ => "present",
    }
}

/// Clamp a claimed standing to what its provenance permits.
pub fn effective_standing(standing: &str, provenance: &str) -> String {
    let ceiling = provenance_ceiling(provenance);
    if standing_rank(standing) < standing_rank(ceiling) {
        ceiling.to_owned()
    } else {
        standing.to_owned()
    }
}

pub fn default_standing_pub() -> String {
    default_standing()
}

pub fn default_provenance_pub() -> String {
    default_provenance()
}

/// A location in the code that evidence can point at.
///
/// The unit of association is not a file but a span, because "the retry policy" is
/// twelve lines inside a 900-line module and the twelve lines are what a PR, a
/// ticket and a Slack thread are all actually talking about. `revision` pins which
/// version of the file the span was taken from, so an anchor stays checkable after
/// the lines move.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CodeAnchor {
    pub path: String,
    pub line_start: u32,
    pub line_end: u32,
    /// Commit the span was read at; an anchor without one is a guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Digest of the exact bytes of the span at `revision`, so drift is detectable
    /// rather than silently assumed away when the file changes underneath.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_sha256: Option<String>,
}

/// Where a reference to a code span came from.
///
/// Independence is what makes a reference worth counting. Five mentions of the same
/// span inside one pull request are one opinion; a ticket, a PR and a design
/// document that independently point at it are three.
pub const REFERENCE_ORIGINS: [&str; 7] = [
    "pull_request",
    "issue_tracker", // Linear, Jira
    "chat_thread",   // Slack
    "document",      // ADR, design doc, gdoc
    "commit",
    "conversation", // an agent session transcript
    "authority",    // a named human answering directly
];

/// One recorded link between a subject and a span of code.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Association {
    /// The concept, component, or keyword being linked.
    pub subject: String,
    pub anchor: CodeAnchor,
    /// One of `REFERENCE_ORIGINS`.
    pub origin: String,
    /// Identifier of the referring artifact: PR number, ticket key, thread ts.
    pub origin_id: String,
    /// One of `PROVENANCE`, for the referring artifact -- not for the code.
    pub provenance: String,
    pub observed_at: String,
}

/// How much one reference contributes to an association's strength.
///
/// Weighted by provenance for the same reason standing is: if an agent opens forty
/// pull requests that all mention a span, that is one prompt echoed forty times,
/// not forty independent judgments that the span matters. A human writing a ticket
/// about it is worth more than an agent's commit message mentioning it in passing.
pub fn reference_weight(origin: &str, provenance: &str) -> u32 {
    let origin_weight = match origin {
        "authority" => 8,
        "document" => 5,
        "issue_tracker" => 4,
        "pull_request" => 3,
        "chat_thread" => 2,
        "commit" => 2,
        _ => 1,
    };
    let provenance_factor = match provenance {
        "human" => 4,
        "human_review" => 2,
        "unknown" => 1,
        // An agent referring to a span is evidence the span exists, and almost no
        // evidence that it matters.
        "ai_generated" | "bot" => 0,
        _ => 1,
    };
    origin_weight * provenance_factor
}

/// Strength of an association across everything that references it.
///
/// Two properties this must have. Independent origins count for more than repeats:
/// three different kinds of artifact pointing at one span is a much stronger signal
/// than three of the same kind, so distinct origins multiply. And repeats within a
/// single origin saturate, because a thread with sixty messages about one function
/// is one conversation, not sixty.
pub fn association_strength(references: &[Association]) -> u32 {
    use std::collections::{BTreeMap, BTreeSet};
    let mut per_origin: BTreeMap<&str, u32> = BTreeMap::new();
    let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for reference in references {
        // One artifact contributes once, however many times it mentions the span.
        if !seen.insert((reference.origin.as_str(), reference.origin_id.as_str())) {
            continue;
        }
        let weight = reference_weight(&reference.origin, &reference.provenance);
        let entry = per_origin.entry(reference.origin.as_str()).or_insert(0);
        // Saturating within an origin: the second and later artifacts of the same
        // kind add progressively less.
        *entry += if *entry == 0 { weight } else { weight / 2 };
    }
    let distinct = per_origin.values().filter(|value| **value > 0).count() as u32;
    let total: u32 = per_origin.values().sum();
    // Breadth multiplies; a span that a ticket, a PR and a document all point at
    // beats a span mentioned in three tickets.
    total * distinct.max(1)
}

fn default_standing() -> String {
    "present".to_owned()
}

fn default_provenance() -> String {
    "unknown".to_owned()
}

/// Lifecycle actions expressed as dispositions of FactEvent messages
/// (interface contract C13).
pub const ACTION_DISPOSITIONS: [&str; 8] = [
    "misextraction",
    "never_true",
    "support_withdrawn",
    "orphan_abandoned",
    "manifest_observation_expired",
    "relaxation",
    "exception_request",
    "unreachable_clone_residual",
];

pub fn disposition_is_negative(disposition: &str) -> bool {
    matches!(
        disposition,
        "rejected"
            | "reverted"
            | "retracted"
            | "withdrawn"
            | "expired"
            | "never_true"
            | "superseded"
    )
}

pub fn disposition_is_transient(disposition: &str) -> bool {
    matches!(
        disposition,
        "draft" | "proposed" | "open" | "incident" | "experiment" | "workaround"
    )
}

pub fn disposition_is_durable(disposition: &str) -> bool {
    matches!(
        disposition,
        "approved" | "accepted" | "merged" | "deployed" | "current"
    )
}

/// The action name of a lifecycle message, from either `disposition` or a
/// fixture-planted `atom_kind`.
pub fn action_of(event: &FactEvent) -> Option<&str> {
    if ACTION_DISPOSITIONS.contains(&event.disposition.as_str()) {
        return Some(event.disposition.as_str());
    }
    if ACTION_DISPOSITIONS.contains(&event.atom_kind.as_str()) {
        return Some(event.atom_kind.as_str());
    }
    if event.disposition == "notice" && event.atom_kind == "misextraction" {
        return Some("misextraction");
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Observation {
    /// Authorship of the underlying evidence, carried from the adapter that read
    /// it. Adapters were already computing this -- git trailers, ticket creators,
    /// Kindex `prov_who` -- and ingest dropped it on the floor, so every fact
    /// derived from a bulk source arrived as `unknown` however well the source
    /// identified its author. Without it the provenance ceiling has nothing to
    /// clamp and agent-written evidence can climb to `prevalent`.
    #[serde(default = "default_provenance")]
    pub provenance: String,
    pub observation_id: String,
    pub source_kind: String,
    pub source_identity: String,
    pub native_id: String,
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    pub disposition: String,
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub body_ref: String,
    pub extraction_version: String,
    /// Origin trust class for repository observations (architecture §4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_trust: Option<String>,
    /// Registered environment/deploy owner for runtime evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// Source-adapter lifecycle: `observed`, `superseded`, `renamed`,
    /// `retracted`, `absent`, `rewritten`.
    #[serde(default = "default_lifecycle")]
    pub lifecycle: String,
    /// Native unit the record came from (file, session, commit, snapshot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Derived statement for shared-store observations; never stored for
    /// Personal transcripts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub atom_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parents: Option<Vec<String>>,
    /// Adapter-specific structured attributes (counts, ids, states); never
    /// raw bodies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
    /// The raw private body is withheld past the retention bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_withheld: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renamed_from: Option<String>,
    /// Receipt-time claim carried by the native record (R-14).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_observed_at: Option<String>,
    /// The record is a signed `.kin/events` FactEvent the reducer owns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reducer_owned: Option<bool>,
    /// Spans of code this observation is about. Carried from the adapter, which
    /// is the only place that knows: a commit knows the paths it touched, a pull
    /// request knows its diff hunks. Ingest used to drop them, so every fact in
    /// the store was unlocatable in the code it described.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<CodeAnchor>,
    /// Paths this observation rules over, for the direction-bearing kinds.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governs_paths: Vec<String>,
    /// Ledger admission cursor (opaque, monotonic); never part of the record.
    #[serde(default, skip)]
    pub cursor: Option<u64>,
}

fn default_lifecycle() -> String {
    "observed".to_owned()
}

/// An extracted, routed atom before any approval. Lives only in private
/// storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Atom {
    pub atom_id: String,
    pub observation_id: String,
    pub source_kind: String,
    pub source_digest: String,
    pub statement: String,
    pub atom_kind: String,
    pub scope: String,
    pub confidence: u16,
    pub provenance: String,
    pub taints: Vec<String>,
    pub hard_blocked: bool,
    pub proposed_destinations: Vec<String>,
    pub eligible_destinations: Vec<String>,
    pub demoted_destinations: Vec<String>,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub extractor: String,
    pub scanner_version: String,
    pub scan_findings: Vec<crate::scanner::Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disposition: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub supersedes_hint: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Distortion {
    pub trigger: String,
    pub loss_if_absent: u16,
    pub rationale: String,
}

impl Serialize for Distortion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("trigger", &self.trigger)?;
        map.serialize_entry("loss_if_absent", &self.loss_if_absent)?;
        map.serialize_entry("rationale", &self.rationale)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Distortion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Value::Object(map) = value else {
            return Err(serde::de::Error::custom("distortion must be an object"));
        };
        let trigger = map
            .get("trigger")
            .and_then(Value::as_str)
            .unwrap_or("dependent decision")
            .to_owned();
        let rationale = map
            .get("rationale")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                map.get("reversibility")
                    .and_then(Value::as_str)
                    .map(|value| format!("reversibility: {value}"))
                    .unwrap_or_else(|| "unstated".to_owned())
            });
        let loss = map
            .get("loss_if_absent")
            .or_else(|| map.get("severity"))
            .cloned()
            .unwrap_or(Value::from(3_000));
        let loss: Bp = serde_json::from_value(loss).map_err(serde::de::Error::custom)?;
        Ok(Distortion {
            trigger,
            loss_if_absent: loss.0,
            rationale,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompanyReference {
    pub company_id: String,
    pub fact_id: String,
    #[serde(alias = "semantic_content_digest")]
    pub semantic_digest: String,
    pub digest_alg_version: String,
    pub authority: String,
    pub valid_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub company_criticality: String,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fact_version: Option<String>,
}

pub const RELATIONS: [&str; 5] = [
    "applies",
    "specializes",
    "implements",
    "contradicts",
    "exception_request",
];
pub const CRITICALITIES: [&str; 3] = ["advisory", "safety", "safety_critical"];

pub fn criticality_is_safety(value: &str) -> bool {
    matches!(value, "safety" | "safety_critical")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FactEvent {
    pub schema: String,
    pub event_id: String,
    pub store_kind: String,
    pub authority_id: String,
    pub authority_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub asserted_at: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub disposition: String,
    pub distortion: Distortion,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<CompanyReference>,
    pub authority_snapshot_cursor: String,
    #[serde(default = "default_confidence")]
    pub confidence: Bp,
    /// How much weight this claim carries when evidence disagrees. Distinct from
    /// `confidence`, which is how sure the extractor was that the claim was made.
    #[serde(default = "default_standing")]
    pub standing: String,
    /// How the underlying evidence came to exist. Caps `standing`.
    #[serde(default = "default_provenance")]
    pub provenance: String,
    /// Paths this fact governs. A `directional` or `north_star` fact scoped to a
    /// path demotes the weaker evidence found under it, which is how "we are
    /// retiring monorepo/" outweighs monorepo/ having the most commits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governs_paths: Vec<String>,
    /// Spans of code this fact is about. An `interface` or `exemplar` fact is
    /// meaningless without one: "use this struct" has to say which lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<CodeAnchor>,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub signer: String,
    pub signature: String,
    /// The immutable original document, retained for signature verification
    /// and content addressing; never re-serialized.
    #[serde(skip)]
    pub raw: Option<Value>,
}

fn default_confidence() -> Bp {
    Bp(6_000)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnknownEvent {
    pub schema: String,
    pub event_id: String,
    pub store_kind: String,
    pub authority_id: String,
    pub authority_scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    pub fact_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub evidence_refs: Vec<String>,
    pub asserted_at: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub disposition: String,
    pub distortion: Distortion,
    pub parents: Vec<String>,
    pub supersedes: Vec<String>,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub company_refs: Vec<CompanyReference>,
    pub authority_snapshot_cursor: String,
    #[serde(default = "default_confidence")]
    pub confidence: Bp,
    /// How much weight this claim carries when evidence disagrees. Distinct from
    /// `confidence`, which is how sure the extractor was that the claim was made.
    #[serde(default = "default_standing")]
    pub standing: String,
    /// How the underlying evidence came to exist. Caps `standing`.
    #[serde(default = "default_provenance")]
    pub provenance: String,
    /// Paths this fact governs. A `directional` or `north_star` fact scoped to a
    /// path demotes the weaker evidence found under it, which is how "we are
    /// retiring monorepo/" outweighs monorepo/ having the most commits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governs_paths: Vec<String>,
    /// Spans of code this fact is about. An `interface` or `exemplar` fact is
    /// meaningless without one: "use this struct" has to say which lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<CodeAnchor>,
    #[serde(default)]
    pub unresolved_uncertainty: Option<String>,
    pub decision_blocked: String,
    pub owner_role: String,
    pub owner_identity: String,
    pub question: String,
    /// The evidence that closes the Unknown. Planted documents carry either
    /// one free-text description or a list; both are read, the list form is
    /// written. Signature verification always uses the immutable raw bytes.
    #[serde(deserialize_with = "string_or_list")]
    pub closure_evidence: Vec<String>,
    pub status: String,
    pub response_due_at: String,
    pub expiry_policy: String,
    pub signer: String,
    pub signature: String,
    #[serde(skip)]
    pub raw: Option<Value>,
}

fn string_or_list<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<String>, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Null => Ok(Vec::new()),
        Value::String(text) => Ok(if text.is_empty() {
            Vec::new()
        } else {
            vec![text]
        }),
        Value::Array(items) => items
            .into_iter()
            .map(|item| match item {
                Value::String(text) => Ok(text),
                other => Err(serde::de::Error::custom(format!(
                    "closure_evidence entries must be strings, got {other}"
                ))),
            })
            .collect(),
        other => Err(serde::de::Error::custom(format!(
            "closure_evidence must be a string or a list of strings, got {other}"
        ))),
    }
}

/// Closed Unknown statuses and degraded policies (P-6).
pub const UNKNOWN_STATUSES: [&str; 6] = [
    "open",
    "asked",
    "closed",
    "abandoned",
    "superseded",
    "reopened",
];
pub const EXPIRY_POLICIES: [&str; 3] = [
    "block_dependent_decision",
    "reversible_sandbox_only_experiment",
    "named_human_granted_exception",
];

/// Normalize a planted policy spelling to the closed vocabulary.
pub fn normalize_policy(value: &str) -> &'static str {
    match value {
        "sandbox" | "sandbox-only-experiment" | "reversible_sandbox_only_experiment" => {
            "reversible_sandbox_only_experiment"
        }
        "exception" | "named-human-exception" | "named_human_granted_exception" => {
            "named_human_granted_exception"
        }
        _ => "block_dependent_decision",
    }
}

/// A derived current fact in a disposable current view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CurrentFact {
    /// The standing this fact carried when the view was reduced, after provenance
    /// clamped it. The reducer decides *using* this value, so dropping it from the
    /// result would leave every caller unable to check the decision it just made.
    #[serde(default = "default_standing")]
    pub standing: String,
    #[serde(default = "default_provenance")]
    pub provenance: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub governs_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anchors: Vec<CodeAnchor>,
    pub fact_id: String,
    pub event_id: String,
    pub logical_key: String,
    pub atom_kind: String,
    pub scope: String,
    pub statement: String,
    pub status: String,
    pub disposition: String,
    pub authority_id: String,
    pub authority_scope: String,
    pub store_kind: String,
    pub effective_from: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_until: Option<String>,
    pub distortion: Distortion,
    pub company_refs: Vec<CompanyReference>,
    pub evidence_refs: Vec<String>,
    pub support_event_ids: Vec<String>,
    pub independent_support_count: usize,
    pub redundancy_with: Vec<String>,
    pub complements: Vec<String>,
    pub confidence: u16,
    pub criticality: String,
    pub trust: String,
    pub stale_reasons: Vec<String>,
    pub authority_snapshot_cursor: String,
    #[serde(default)]
    pub effective_dependence_class: Option<String>,
}

pub fn value_of<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

impl FactEvent {
    pub fn to_value(&self) -> Value {
        value_of(self)
    }

    /// Strict single parse from immutable bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds the {MAX_EVENT_BYTES}-byte ceiling"));
        }
        let map = crate::json::parse_strict_object(bytes)?;
        if map.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA) {
            return Err("unsupported event schema".to_owned());
        }
        let raw = Value::Object(map.clone());
        let mut event: FactEvent = serde_json::from_value(Value::Object(map))
            .map_err(|error| crate::json::serde_error_text(&error))?;
        event.raw = Some(raw);
        event.validate()?;
        Ok(event)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let bytes = crate::json::try_canonical_bytes(value)?;
        Self::parse(&bytes)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.confidence.0 > MAX_CONFIDENCE || self.distortion.loss_if_absent > MAX_CONFIDENCE {
            return Err("confidence and loss are basis points in 0..=10000".to_owned());
        }
        if !matches!(
            self.store_kind.as_str(),
            "company" | "codebase" | "personal"
        ) {
            return Err("store_kind must be company, codebase, or personal".to_owned());
        }
        crate::time::parse_rfc3339_millis(&self.asserted_at)?;
        crate::time::parse_rfc3339_millis(&self.effective_from)?;
        if let Some(until) = &self.effective_until {
            crate::time::parse_rfc3339_millis(until)?;
        }
        if self.authority_scope.is_empty() || self.logical_key.is_empty() || self.fact_id.is_empty()
        {
            return Err("authority_scope, logical_key, and fact_id are required".to_owned());
        }
        for forbidden in ['*', '%', '?', '\0'] {
            if self.authority_scope.contains(forbidden) || self.logical_key.contains(forbidden) {
                return Err("authority_scope and logical_key are exact strings; wildcard characters are rejected".to_owned());
            }
        }
        if self.statement.len() > 16 * 1024 {
            return Err("statement exceeds the 16 KiB bound".to_owned());
        }
        for reference in &self.company_refs {
            if !RELATIONS.contains(&reference.relation.as_str()) {
                return Err(format!(
                    "unsupported company reference relation {}",
                    reference.relation
                ));
            }
            if !CRITICALITIES.contains(&reference.company_criticality.as_str()) {
                return Err("company_criticality must be advisory or safety_critical".to_owned());
            }
        }
        Ok(())
    }

    /// The immutable document: the original bytes when parsed from a
    /// buffer, otherwise the serialized struct.
    pub fn document(&self) -> Value {
        self.raw.clone().unwrap_or_else(|| self.to_value())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        crate::json::canonical_bytes(&self.document())
    }

    pub fn digest(&self) -> String {
        crate::hash::sha256_bytes(&self.canonical_bytes())
    }

    /// Sign in place: sets `signer` and `signature` and freezes the document.
    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), ContractError> {
        self.raw = None;
        let signed = key.sign_document("fact-event", &self.to_value())?;
        self.signer = signed["signer"].as_str().unwrap_or_default().to_owned();
        self.signature = signed["signature"].as_str().unwrap_or_default().to_owned();
        self.raw = Some(signed);
        Ok(())
    }

    pub fn verify_signature(&self) -> Option<PublicKey> {
        PublicKey::verify_document("fact-event", &self.document())
    }

    /// Semantic content digest (P-8), algorithm `kinbase-digest/1`:
    /// `sha256(JCS({"statement": statement}))`.
    pub fn semantic_digest(&self) -> String {
        semantic_digest(&self.statement)
    }
}

pub fn semantic_digest(statement: &str) -> String {
    crate::json::digest(&serde_json::json!({"statement": statement}))
}

impl UnknownEvent {
    pub fn to_value(&self) -> Value {
        value_of(self)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_EVENT_BYTES {
            return Err(format!("event exceeds the {MAX_EVENT_BYTES}-byte ceiling"));
        }
        let map = crate::json::parse_strict_object(bytes)?;
        if map.get("schema").and_then(Value::as_str) != Some(UNKNOWN_SCHEMA) {
            return Err("unsupported unknown-event schema".to_owned());
        }
        let raw = Value::Object(map.clone());
        let mut event: UnknownEvent = serde_json::from_value(Value::Object(map))
            .map_err(|error| crate::json::serde_error_text(&error))?;
        event.raw = Some(raw);
        if !UNKNOWN_STATUSES.contains(&event.status.as_str()) {
            return Err("unknown status is outside the closed set".to_owned());
        }
        Ok(event)
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        let bytes = crate::json::try_canonical_bytes(value)?;
        Self::parse(&bytes)
    }

    pub fn document(&self) -> Value {
        self.raw.clone().unwrap_or_else(|| self.to_value())
    }

    pub fn sign(&mut self, key: &PrivateKey) -> Result<(), ContractError> {
        self.raw = None;
        let signed = key.sign_document("unknown-event", &self.to_value())?;
        self.signer = signed["signer"].as_str().unwrap_or_default().to_owned();
        self.signature = signed["signature"].as_str().unwrap_or_default().to_owned();
        self.raw = Some(signed);
        Ok(())
    }

    pub fn verify_signature(&self) -> Option<PublicKey> {
        PublicKey::verify_document("unknown-event", &self.document())
    }

    pub fn digest(&self) -> String {
        crate::json::digest(&self.document())
    }

    /// Build an Unknown with the ratified defaults; caller sets identity
    /// fields and signs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_kind: &str,
        repository_id: Option<&str>,
        authority_id: &str,
        authority_scope: &str,
        logical_key: &str,
        scope: &str,
        decision_blocked: &str,
        owner_role: &str,
        owner_identity: &str,
        question: &str,
        loss_if_absent: u16,
        created_at: &str,
        response_due_at: &str,
        expiry_policy: &str,
        cursor: &str,
    ) -> Self {
        let seed = format!(
            "{store_kind}\0{}\0{logical_key}\0{decision_blocked}\0{question}",
            repository_id.unwrap_or_default()
        );
        let unknown_id = format!("unknown_{}", &crate::hash::sha256_text(&seed)[..40]);
        Self {
            schema: UNKNOWN_SCHEMA.to_owned(),
            event_id: format!("{unknown_id}:{}", &crate::hash::sha256_text(&format!("{seed}\0{created_at}"))[..16]),
            store_kind: store_kind.to_owned(),
            authority_id: authority_id.to_owned(),
            authority_scope: authority_scope.to_owned(),
            repository_id: repository_id.map(str::to_owned),
            fact_id: unknown_id,
            logical_key: logical_key.to_owned(),
            atom_kind: "question".to_owned(),
            scope: scope.to_owned(),
            statement: question.to_owned(),
            evidence_refs: Vec::new(),
            asserted_at: created_at.to_owned(),
            effective_from: created_at.to_owned(),
            effective_until: None,
            disposition: "current".to_owned(),
            distortion: Distortion {
                trigger: decision_blocked.to_owned(),
                loss_if_absent,
                rationale: "a stale or disputed fact is worse than a missing fact; the dependent decision is withheld until named evidence closes this Unknown".to_owned(),
            },
            parents: Vec::new(),
            supersedes: Vec::new(),
            redundancy_with: Vec::new(),
            complements: Vec::new(),
            company_refs: Vec::new(),
            authority_snapshot_cursor: cursor.to_owned(),
            confidence: Bp(0),
            standing: default_standing_pub(),
            provenance: default_provenance_pub(),
            governs_paths: Vec::new(),
            anchors: Vec::new(),
            unresolved_uncertainty: Some(question.to_owned()),
            decision_blocked: decision_blocked.to_owned(),
            owner_role: owner_role.to_owned(),
            owner_identity: owner_identity.to_owned(),
            question: question.to_owned(),
            closure_evidence: Vec::new(),
            status: "open".to_owned(),
            response_due_at: response_due_at.to_owned(),
            expiry_policy: normalize_policy(expiry_policy).to_owned(),
            signer: String::new(),
            signature: String::new(),
            raw: None,
        }
    }
}

/// Stable identifiers: fact IDs derive from `(store, scope, statement)`,
/// logical keys from `(store, authority_scope, subject)`.
pub fn fact_id(store_kind: &str, scope: &str, statement: &str) -> String {
    format!(
        "fact_{}",
        &crate::hash::sha256_text(&format!(
            "{store_kind}\0{scope}\0{}",
            crate::scanner::squeeze(statement)
        ))[..40]
    )
}

pub fn logical_key(store_kind: &str, authority_scope: &str, subject: &str) -> String {
    format!(
        "logical_{}",
        &crate::hash::sha256_text(&format!("{store_kind}\0{authority_scope}\0{subject}"))[..40]
    )
}

pub fn event_id(
    fact_id: &str,
    statement_digest: &str,
    asserted_at: &str,
    signer_hint: &str,
) -> String {
    format!(
        "event_{}",
        &crate::hash::sha256_text(&format!(
            "{fact_id}\0{statement_digest}\0{asserted_at}\0{signer_hint}"
        ))[..40]
    )
}

/// Loss-if-absent defaults by atom kind (basis points).
pub fn default_loss(atom_kind: &str) -> u16 {
    match atom_kind {
        "constraint" => 9_000,
        "decision" => 7_500,
        "relaxation" => 7_000,
        "rationale" => 5_000,
        "question" => 5_000,
        "reference" => 6_000,
        "claim" => 4_500,
        _ => 3_000,
    }
}

#[cfg(test)]
mod association_tests {
    use super::*;

    fn reference(origin: &str, id: &str, provenance: &str) -> Association {
        Association {
            subject: "retry policy".to_owned(),
            anchor: CodeAnchor {
                path: "src/retry.rs".to_owned(),
                line_start: 40,
                line_end: 52,
                revision: None,
                span_sha256: None,
            },
            origin: origin.to_owned(),
            origin_id: id.to_owned(),
            provenance: provenance.to_owned(),
            observed_at: "2026-09-10T00:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn breadth_beats_repetition() {
        let broad = [
            reference("issue_tracker", "WAN-1", "human"),
            reference("pull_request", "42", "human"),
            reference("document", "adr-7", "human"),
        ];
        let deep = [
            reference("issue_tracker", "WAN-1", "human"),
            reference("issue_tracker", "WAN-2", "human"),
            reference("issue_tracker", "WAN-3", "human"),
        ];
        assert!(association_strength(&broad) > association_strength(&deep));
    }

    #[test]
    fn agent_references_do_not_manufacture_strength() {
        let mut agent = Vec::new();
        for index in 0..40 {
            agent.push(reference(
                "pull_request",
                &index.to_string(),
                "ai_generated",
            ));
        }
        let one_human = [reference("chat_thread", "T1", "human")];
        assert_eq!(association_strength(&agent), 0);
        assert!(association_strength(&one_human) > 0);
    }

    #[test]
    fn one_artifact_counts_once_however_often_it_mentions_the_span() {
        let repeated = [
            reference("chat_thread", "T1", "human"),
            reference("chat_thread", "T1", "human"),
            reference("chat_thread", "T1", "human"),
        ];
        let single = [reference("chat_thread", "T1", "human")];
        assert_eq!(
            association_strength(&repeated),
            association_strength(&single)
        );
    }
}
