# Candidate Amendment 002 — Emission ledger, leak stories, withhold, and redaction by reference

Status: **candidate, revision 3; not authority; no Coder dispatch permitted from these bytes**

## Reader summary

This candidate adds one mechanism and rewrites two runbook steps so that the
question a shared-data leak raises first, "what else got through?", is answered by a
query rather than an investigation. It adopts the shape of Example Corp's Event service and
its story builders: a lossy observation path for notes, an acknowledged record path
for the few facts whose loss would itself be a failure, a single-writer story builder
that assembles related records into an addressable story with a disposition, and
erasure by reference so that redaction appends a new version and never deletes a
story.

One invariant generates the design. A projection that was served but not recorded
under-approximates the served set, and that hole is exactly the failure this
candidate exists to close. A projection that was recorded but not served
over-approximates it, and that error is safe: someone is notified who did not need
to be. Every rule below is chosen so that the only errors the system can make are
in the safe direction. Any later change that admits served-but-not-recorded, such as
batching or asynchronous acknowledgment of emissions, is outside this design; any
change that admits recorded-but-not-served is a tuning.

Concretely, in one still-unproven Kinbase generation it:

1. requires every projection served to a coding session to leave an acknowledged
   **emission record** before it is returned: references to the atoms served by
   identity and version, the store and cursors they came from, the service-issued
   session and sequence, the authenticated principal and host, and the receipt time;
   never bytes, never content digests (`O-01`, `O-02`);
2. makes the emission a fact with states `intended` on write, `delivered` on the
   host adapter's attributed acknowledgment, and `withdrawn` when the projection was
   refused before any byte reached the transport; the served set is `intended` and
   `delivered` together, an over-approximation by construction, and `withdrawn` is
   reported separately (`O-01`);
3. separates **withhold**, which is reversible and immediate, from **redact**, which
   is irreversible and happens only on an owner's confirmed disposition or a
   principal's erasure request; both are append-only events, and redaction is a new
   atom version whose content is a canonical tombstone, so identity, digest history,
   and byte-identical rebuild over the event set are preserved (`O-01`);
4. defines the **leak story**: a single-writer story builder that, on a trigger,
   assembles the atom's lineage from source observation through candidate, approval
   receipt, store commit, every emission, every session that received it, and the
   transitive **derived set** enumerated to an unbounded, deterministically ordered
   fixed point, into an ordered path of references with `missing[]` and
   `unattested[]`, an attributed disposition, an owner determined by the trigger's
   store, and impact reported as confirmed and unconfirmed counts; enumeration is
   never truncated, and it is the withhold action, not the enumeration, that is
   bounded, by refusal and escalation rather than silent degradation (`O-01`);
5. defines a **responder capability**: a signed, time-boxed, single-story lineage
   query, references only, whose every use is itself recorded, with a pre-issued
   sealed dual-control break-glass path and a named issuance bound, so that the
   responder is locked out neither by the taint that raised the story nor by the
   absence or implication of the Company owner (`O-01`, `O-02`);
6. replaces the runbook's manual "enumerate distribution" and "publish revocation"
   steps with the ledger query, the withhold, and the redaction, keeping every step
   the ledger cannot cover, in particular Git clones (`O-03`);
7. adds five glossary terms (`O-04`); and
8. adds V-3 instruments for enumeration under the responder capability, two-hop
   derived-set withholding, the recorded-not-delivered case, the write-versus-
   revocation race, key conflict, forced emission failure, service restart,
   over-ceiling withhold refusal, purge, and `missing[]` versus `unattested[]`
   (`O-05`).

It does **not** weaken P-3. It adds no read path into Personal. It does not make the
observation notes reliable, because a lost note costs a diagnosis, not a boundary.
It does not promise general detection of private meaning; it promises that once
something is known to be tainted, everywhere the system sent it by recorded
emission is enumerable and everything downstream by recorded emission is withheld
or escalated. What a person carried between sessions is outside the ledger and is
named as such. It deletes nothing from the graph.

This is an append-only amendment candidate. Its base is the specification tree as it
stands after Amendment 001 is materialized; if the Validator materializes it against
the unamended manifest instead, every anchor below still occurs exactly once in the
named base files as of the working tree on 2026-09-08, and the Validator records
which base was used. It supersedes only the clauses named below. Every Product
behavior, threat, failure disposition, proof gate, role boundary, and source statement
not named here remains byte-for-byte binding. Decoding, matching, ordering, and
mismatch rules are exactly those stated in Amendment 001; they are not restated.

| Operation | Base path | Exact containing heading |
|---|---|---|
| O-01 | spec/architecture.md | ## 6. Durable stores and corpus maintenance |
| O-02 | spec/product.md | ### P-3 — physically separate products and disclosure boundary |
| O-03 | spec/leak-runbook.md | # Shared-data leak runbook |
| O-04 | spec/glossary.md | # Glossary |
| O-05 | spec/verification.md | ### V-3 — privacy and authority boundary (`P-3`, Critical, zero tolerance) |

## 0. Stakes

Personal bytes reaching a shared store is the founder's named Type 1 failure (SRC-4):
Git distribution makes erasure functionally impossible. The runbook already accepts
that. What it does not yet give the responder is speed. Step 3 today says "enumerate
distribution" and lists places to look. For anything the system itself served to a
session, looking is the wrong verb; the system should already know. Every hour spent
reconstructing who received a fact is an hour in which those sessions keep acting on
it, and an investigation with holes exactly where the system acted is the
investigation you were trying to run.

The founder's ruling on this question (2026-09-08) was: bookend the taint check at
proposal and at commit, collect every open and self-answered question for
transparency, and build the containment on the pattern of the Event service and its
story builders. This candidate is that pattern applied to Kinbase's one irreversible
failure.

## 1. Problem statement

Kinbase records what it admitted (immutable events), what it asked (Unknowns), and
what it decided to project (decision traces with the authority-snapshot cursor, per
architecture section 6). It does not yet record, as a first-class acknowledged fact,
**what it handed to whom**: which admitted atoms were served into which session, on
which host, for which principal, at which cursor. Without that record:

- "which sessions received atom X after it was tainted" is a forensic exercise over
  host logs the shared process is forbidden from reading in full;
- retraction can withhold a fact from future projections but cannot tell the sessions
  that already hold it in context;
- the leak runbook's enumeration step has no system of record for the one channel
  the system controls, so it is performed by hand and never completely;
- derived atoms (atoms extracted from a session that had a tainted atom in context)
  cannot be found from the tainted source, so taint stops at the store boundary
  instead of following the fact into the work.

Detection layers (deterministic scanners, canaries, an advisory model reviewer) can
raise the alarm. None of them can answer the responder's first question. Only a
ledger can.

## 2. Proposed approach

### 2.1 The two paths, translated

The Event service distinguishes an **observation path** (high volume, permissive,
best effort, many writers, ephemeral) from a **record path** (low volume, governed,
acknowledged, single writer, durable). Kinbase already has the record path: the
append-only event table behind `kinbased`, with the authority cursor. This
candidate places a small closed set of new event kinds on it and states what stays
off it.

On the record path, acknowledged: emission records and attributed delivery
acknowledgments, session issuance and per-session sequence high-water marks,
withhold, release, redact, and purge events, responder-capability issuance and use,
and leak stories. Each is small, each is a set of references, and the loss of any
one would be a boundary failure rather than a lost diagnosis.

On the observation path, best effort and never load bearing: candidate previews,
scanner passes over shared surfaces, advisory model-reviewer opinions, and any other
note whose absence costs a diagnosis. Observation notes carry a producer sequence and
a declared cadence so that a gap is detectable; a story assembled from them records
what it could not find and names what it could not have known.

### 2.2 The emission record

Every projection delivered to a coding session writes one emission record before the
projection is returned. The write and the read of the current revocation cursor are
one serializable transaction on the record path. If the write is not acknowledged,
the projection is not returned; the session receives the typed `EMISSION_UNRECORDED`
refusal and degrades exactly as it does for a stale revocation snapshot. No
projection byte is handed to the transport until the service has re-read the
revocation cursor after the acknowledgment; if it has advanced past a withhold or
redaction of any served atom, the projection is discarded inside the service, the
session receives `REVOCATION_RACE`, and the emission is marked `withdrawn` by a new
event. A `withdrawn` emission therefore records a projection that never left the
process; it is not in the served set and does not seed the derived closure, and it
is reported as its own count. The residual window is the transit between the
service return and the adapter's acknowledgment: a withhold committed there is
handled by the `retraction_notice` path, which is the named apology for that race.

The record holds references only:

- `emission_id`: `(session_id, projection_seq)`. `session_id` is issued by the
  service at SessionStart, bound to the authenticated client instance, and committed
  on the record path, so it is unique across host restarts, host kinds, and service
  restarts. `projection_seq` is assigned by the service, strictly monotonic per
  session, with the per-session high-water mark committed on the record path before
  the sequence is used; a service restart resumes from the committed mark and never
  reissues a sequence. The pair is the idempotency key: a retry with an identical
  reference-payload digest returns the original receipt; a repeat key with a
  different reference-payload digest is refused with `EMISSION_KEY_CONFLICT` and is
  itself a leak-story trigger, because a mismatched replay is evidence. The
  reference-payload digest is over the record's own references and cursors, never
  over fact content;
- `atom_refs`: the admitted atom identities served, each as `(atom_id, version)`
  with the store (`company` or `codebase:<repo-id>`). The record carries no content
  digest; the atom's own version history is the sole authority for what bytes an
  identity had at a time, and a reference that does not resolve there is a
  `missing[]` entry with reason `inconsistent` and an open story, never resolved
  silently in favor of either side;
- `authority_cursor` and `revocation_cursor` observed at the transaction;
- `principal_id`, `host_instance_id`, and `host_kind`, stamped by the service from
  the authenticated client identity, never taken from the payload;
- `received_at` service receipt time, kept beside the client's claimed time;
- `state`: `intended` on write. The host adapter posts a delivery acknowledgment
  after the projection is in the session's context; the service records
  `delivered` as an attributed adapter assertion, `delivery_claimed_by` with the
  adapter's authenticated identity and the adapter's own sequence, never as a
  service-owned truth. `delivered` means dispatched and acknowledged by the adapter,
  not received by a person or a model. An emission that never receives an
  acknowledgment stays `intended`.

The **served set** of an atom is every emission referencing it in state `intended`
or `delivered`. It is an over-approximation by construction and is reported as two
counts, confirmed and unconfirmed, with `withdrawn` reported beside them.

Emission records contain no fact bodies, no transcript bytes, and nothing from
Personal, and the emission table is included in every shared-surface byte scan named
in P-3. Availability: the record path in the proof is the existing single-node,
fsync-on-commit SQLite behind `kinbased`; its unavailability is a total outage of
shared projection, which is accepted and ratified rather than degraded around. Per
principal and per session write ceilings bound the record path; `EMISSION_UNRECORDED`
is retried by idempotency key with bounded backoff, and a sustained refusal rate is a
monitored signal with a named owner and is itself a leak-story trigger, because a
sustained refusal is indistinguishable from an attack.

### 2.3 Reading the ledger

Two read operations, with distinct authorization:

1. **Whole-record read** requires a facts token whose authority scopes could read
   every atom the record references, under the existing volume ceilings. This is the
   ordinary case and it fails closed for any record naming an atom the caller cannot
   scope.
2. **Lineage query** by atom identity returns session, host, and principal
   identifiers, emission states, and derived atom identities, never bodies and never
   co-served atoms outside the caller's scope. It is authorized by a **responder
   capability**: issued by the Company owner to the owner of the trigger's store,
   signed, time-boxed, scoped to one story, references only. Every use is a record-
   path event naming the principal, the story, and the justification. The responder
   is audited by the same ledger they are reading.

The second operation exists because the first is unsatisfiable in exactly the case
that matters: after taint, no ordinary token has scope for the tainted atom, so no
ordinary token could read any emission that references it.

Issuance is bounded and never depends on one person. The Company owner issues
within one hour of the story opening. A pre-issued, sealed, time-boxed capability
under dual control (the Company security steward and one named delegate) is the
break-glass path when the owner is unreachable, and the only path when the owner is
the principal named in the story; opening it is loudly recorded. Capability-use
events are written through a bounded-deferral path with its own durability, separate
from the projection write ceilings, so that record-path write pressure, which is
itself a story trigger, cannot prevent the investigation of the story it raised.

### 2.4 Withhold, release, redact, purge

Four append-only event kinds, distinguished by reversibility and authority:

- **withhold** (reversible, immediate): on a story trigger the reducer excludes the
  atom and its derived set from trusted projection and reopens each dependent
  decision as an apology Unknown, exactly as a revocation does today. Every session
  in the served set is told at its next projection, through the apology channel,
  that a fact it holds in context was withheld and must not be relied on; the notice
  is injected beside the projection, not in place of it, and the host adapter
  records its delivery as an emission record of kind `retraction_notice` with the
  same two states.
- **release** (reversal): the story's owner releases withheld atoms by a signed event
  over a predicate evaluated against the story's enumerated derived set, for
  example "generation at least two, excluding a listed set", so that undoing a false
  positive costs one signature rather than one per atom. The evaluated membership is
  recorded with the release.
- **redact** (irreversible, adjudicated): only on the owner's `confirmed` disposition
  or on a principal's erasure request, which is its own adjudication. Redaction
  appends a new atom version whose content is the canonical tombstone, fully
  determined by the redact event identity; the reducer resolves identity to the
  latest version, earlier versions become unreachable through the reducer, and the
  digest chain remains verifiable against every version whose bytes still exist.
  Byte-identical rebuild is defined over the event set including redact events and
  reproduces the tombstoned state.
- **purge** (physical destruction): the owner-signed removal of an earlier version's
  bytes from the event store, leaving a purge marker that records the version, its
  claimed digest, the purge event, and the signer. Purge redefines the frozen event
  set: rebuild receipts taken before a purge are no longer reproducible, and a
  verifier encountering a purged version marks its digest `unverifiable`, never
  `verified`, because a marker's claim about bytes that no longer exist cannot be
  checked. This is a ratified weakening of the rebuild gate, scoped to purged
  versions and recorded per purge. Purge has its own proof gate and is the only
  operation that changes stored bytes; rebuild reproduces the purged state.

A defective scanner rule therefore has the authority to withhold, which is reversible
and recorded, and never the authority to destroy. A refuted story releases; a
confirmed story redacts; an erasure request redacts and purges. Nothing is deleted
from the graph; a hole in a corpus that agents reason over is a wrong answer waiting.

### 2.5 The leak story and the derived set

A **leak story** is written by one component, the story builder, which is the sole
author of stories and therefore single-writer by construction; concurrency on the
observation path is upstream of it and irrelevant to it. A story is an ordered path
of references over records, never copies; one record may appear in many stories, and
stories may reference other stories.

Triggers, each a record-path event: retroactive taint on an admitted atom or its
source; a scanner or canary hit on any shared surface named in P-3; an approval
whose source acquired taint by the commit-time recheck; a principal's erasure
request; an `EMISSION_KEY_CONFLICT`; and a sustained `EMISSION_UNRECORDED` rate.

The **derived set** of atom A is the transitive closure, to a fixed point, of the
relation "B is derived from A if B's extraction provenance names a session S and an
emission record referencing A for S exists in state `intended` or `delivered`, with
receipt time at or before B's extraction time". The predicate is decidable from the
ledger alone. Within recorded emissions it over-approximates, because context-window
eviction is invisible to it, which is the safe direction. It cannot see an atom
extracted by a session that received A by a person carrying it between sessions;
that class is named in `unattested[]` on every story so that an empty `missing[]` is
never read as closure complete, and the promise is "everything downstream by
recorded emission", not everything downstream.

Enumeration is never truncated. It runs to the fixed point in a total order of
`(generation, extraction_time, atom_id)`, so the same story rebuilds byte-identically
over the same event set, and the responder always receives the complete answer,
because the complete answer is the product. What is bounded is the action. The
withhold ceiling is a ratified count, proposed 512; a story whose derived set is
within it withholds automatically; a story whose derived set exceeds it does not
truncate and does not withhold automatically. It withholds the source atom and the
first generation, escalates to the owner with the full enumeration and its counts,
and records the deferred withhold as an open question with the owner named. The
owner then withholds or releases by predicate over the complete set, on complete
information, in one recorded act.

The staleness bound applies to membership: an atom whose extraction time cannot be
ordered against the emission's receipt time inside the ratified window is placed in
`missing[]` with reason `unordered`, never silently in or out. A `missing[]` entry
with reason `inconsistent` names a disagreement between the ledger and an atom's
version history; its adjudicating owner is the owner of the referenced atom's store,
or the Company security steward if the store is indeterminate, the containment
default while adjudication is pending is to treat the reference as served and
withhold the identity, and the resolution is a recorded disposition on the story.

On a trigger the builder assembles, in order: the source observation, the candidate
and its classification, the approval receipt, the store commit event, every emission
referencing the atom with its state, every session, host, and principal in the
served set, and the derived set. `missing[]` names each record that a sequence or
schedule says should exist and cannot be found, with reason `evicted`,
`unreachable`, `forbidden`, `inconsistent`, or `unordered`. `unattested[]` names each
observation class for which no expectation was declared, and always names
cross-session human transfer, so that an empty `missing[]` is never vacuous.

Every story carries an attributed `disposition` of `open`, `confirmed`, `refuted`,
or `tolerated`; a refuted story feeds back to the rule or scanner that raised it, and
a rule refuted repeatedly is reported as defective rather than quietly tuned.
`impact` is reported as counts: confirmed sessions, unconfirmed sessions, hosts,
principals, and derived atoms, never as prose. The **owner** is the owner of the
trigger's store: the Company security steward for `company`, the codebase maintainer
for `codebase:<repo-id>`, the principal for their own material. Where the derived set
reaches a store with a different owner, the story spawns a child story owned by that
store's owner and records it by reference; a story never carries a disposition on
another owner's atoms. Stories reach their owner through the existing Unknown
channel and count against the approval-fatigue budget, so a leak story is a batched,
owned question and never a stream of prompts.

### 2.6 Exact operations

#### O-01 — architecture section 6: emission ledger, leak stories, withhold and redaction

In `spec/architecture.md` section 6 insert after this exact anchor block:

> stability metrics. Byte-identical rebuild applies only to reduction/current-view and
> selection over a frozen admitted event set.

this exact new block:

>
> ### Emission ledger, leak stories, withhold, and redaction by reference
>
> The governing invariant: a projection served but not recorded under-approximates
> the served set and is the failure this section exists to close; a projection
> recorded but not served over-approximates it and is a safe error. Every rule here
> permits only the second. Batching or asynchronous acknowledgment of emissions that
> could admit the first is outside this design.
>
> The append-only event table is the acknowledged record path. The following event
> kinds are added to it; each is a set of references and none carries fact bodies or
> fact-content digests.
>
> An **emission record** is written before any projection is returned to a session,
> in one serializable transaction with the read of the current revocation cursor.
> Its key is `(session_id, projection_seq)`: the service issues `session_id` at
> SessionStart bound to the authenticated client instance and commits it on the
> record path, and assigns `projection_seq` strictly monotonic per session from a
> committed high-water mark, so neither is reissued across host or service restarts.
> A retry with an identical reference-payload digest returns the original receipt; a
> repeat key with a different reference-payload digest is refused with
> `EMISSION_KEY_CONFLICT` and opens a leak story. The reference-payload digest is over
> the record's own references and cursors, never fact content. The record holds the
> served atoms as `(atom_id, version)` with their store, the authority and revocation
> cursors observed, the principal, host instance, and host kind stamped by the
> service from the authenticated identity, and the service receipt time beside the
> client's claimed time. The atom's version history is the sole authority for what
> bytes an identity had at a time; a reference that does not resolve there is a
> `missing[]` entry with reason `inconsistent`, adjudicated by the referenced atom's
> store owner or, if indeterminate, the Company security steward, treated as served
> and withheld while pending. If the write is not acknowledged the projection is not
> returned and the session receives `EMISSION_UNRECORDED`. No projection byte is
> handed to the transport until the service has re-read the revocation cursor after
> the acknowledgment; if it advanced past a withhold or redaction of any served atom
> the projection is discarded inside the service, the session receives
> `REVOCATION_RACE`, and the emission is marked `withdrawn`, which records a
> projection that never left the process, is not in the served set, does not seed
> the derived closure, and is reported as its own count. The residual window is the
> transit to the adapter's acknowledgment; a withhold committed there is handled by
> the `retraction_notice` path, which is the named apology for that race. The
> emission is `intended` on write and `delivered` when the host adapter acknowledges
> that the projection is in the session's context; `delivered` is recorded as an
> attributed adapter assertion, `delivery_claimed_by` with the adapter's
> authenticated identity and sequence, and means dispatched and acknowledged by the
> adapter, not received by a person or a model. The served set of an atom is every
> emission referencing it in state `intended` or `delivered`, reported as confirmed
> and unconfirmed counts with `withdrawn` beside them. The record path is the
> existing fsync-on-commit SQLite; its unavailability is a total outage of shared
> projection and is accepted. Per-principal and per-session write ceilings apply; a
> sustained `EMISSION_UNRECORDED` rate is a monitored, owned signal and a leak-story
> trigger. The emission table is inside every shared-surface byte scan.
>
> Reads are two operations. A whole-record read requires a facts token whose
> authority scopes could read every referenced atom. A lineage query by atom identity
> returns session, host, and principal identifiers, emission states, and derived atom
> identities, never bodies and never out-of-scope co-served atoms, and is authorized
> by a **responder capability**: issued by the Company owner within one hour of the
> story opening to the owner of the trigger's store, signed, time-boxed, scoped to
> one story, references only. A pre-issued, sealed, time-boxed capability under dual
> control of the Company security steward and one named delegate is the break-glass
> path when the owner is unreachable and the only path when the owner is the
> principal named in the story; opening it is loudly recorded. Every use is recorded
> as an event naming principal, story, and justification, written through a
> bounded-deferral path with its own durability, separate from the projection write
> ceilings, so that record-path write pressure cannot prevent the investigation of
> the story it raised.
>
> Four further event kinds are distinguished by reversibility and authority. A
> **withhold** is immediate and reversible: the reducer excludes the atom and its
> derived set from trusted projection and reopens dependents as apology Unknowns;
> every session in the served set is told at its next projection through the apology
> channel, beside the projection, and the host adapter records that delivery as an
> emission of kind `retraction_notice` with the same attributed states. A **release**
> reverses a withhold by an owner-signed event over a predicate evaluated against the
> story's enumerated derived set, with the evaluated membership recorded. A
> **redact** occurs only on the owner's `confirmed` disposition or a principal's
> erasure request and appends a new atom version whose content is the canonical
> tombstone determined by the redact event identity; identity is stable, earlier
> versions are unreachable through the reducer, and the digest chain stays
> verifiable against every version whose bytes still exist. A **purge** is the
> owner-signed physical removal of an earlier version's bytes, leaving a marker with
> the version, its claimed digest, the purge event, and the signer; purge redefines
> the frozen event set, earlier rebuild receipts are no longer reproducible, a
> verifier marks a purged version's digest `unverifiable` and never `verified`, and
> this is a ratified weakening of the rebuild gate scoped to purged versions and
> recorded per purge. Byte-identical rebuild is defined over the event set including
> redact and purge events and reproduces the tombstoned or purged state. A scanner
> rule can withhold; only an owner or a data subject can destroy.
>
> A **leak story** is written only by the story builder, the sole author of stories,
> as an ordered path of references, never copies; one record may appear in many
> stories, and stories may reference stories. Triggers are record-path events:
> retroactive taint, a scanner or canary hit on a shared surface, an approval whose
> source acquired taint by the commit-time recheck, an erasure request, an
> `EMISSION_KEY_CONFLICT`, or a sustained `EMISSION_UNRECORDED` rate. The derived
> set is the transitive closure to a fixed point of "B is derived from A if B's
> extraction provenance names a session for which an emission referencing A exists
> in state `intended` or `delivered`, with receipt time at or before B's extraction
> time". Enumeration is never truncated: it runs to the fixed point in the total
> order `(generation, extraction_time, atom_id)`, so a story rebuilds byte-identically
> and the responder receives the complete answer. The action is what is bounded: a
> story whose derived set is within the ratified withhold ceiling of 512 atoms
> withholds automatically; a story that exceeds it withholds the source atom and the
> first generation, escalates to the owner with the full enumeration and counts, and
> records the deferred withhold as an open question with the owner named, and the
> owner then withholds or releases by predicate in one recorded act. A member whose
> times cannot be ordered inside the staleness window is `missing[]` with reason
> `unordered`. The builder assembles the source observation, candidate and
> classification, approval receipt, store commit, every emission with its state, the
> served set, and the derived set. `missing[]` names each record that a sequence or
> schedule says should exist and cannot be found, with reason `evicted`,
> `unreachable`, `forbidden`, `inconsistent`, or `unordered`; `unattested[]` names
> each observation class with no declared expectation and always names cross-session
> human transfer, which no emission records. A story carries an attributed
> `disposition` of `open`, `confirmed`, `refuted`, or `tolerated`, with refutation
> fed back to the rule that raised it and repeated refutation reported as a
> defective rule; `impact` as counts of confirmed sessions, unconfirmed sessions,
> withdrawn emissions, hosts, principals, and derived atoms; and an `owner` equal to
> the owner of the trigger's store, with a child story spawned by reference for any
> derived atom in a store with a different owner. Stories reach their owner through
> the Unknown channel inside the approval-fatigue budget. Nothing is deleted from
> the graph. Erasure requests use withhold, redact, and purge; the runbook's
> statement that erasure cannot be proven for Git clones is unchanged.
>
> Candidate previews, shared-surface scans, and advisory model-reviewer opinions are
> observation notes: best effort, many writers, ephemeral, never load bearing. Each
> carries a producer sequence and a declared cadence so that a gap is detectable. A
> story assembled from them records what it could not find and names what it could
> not have known.

#### O-02 — product P-3: emission and containment obligations

In `spec/product.md` section P-3 insert after this exact anchor block:

> an immediate proof failure under the exact ratified finite
> [`threat-model.md`](threat-model.md). The proof must always state that qualifier and
> may not market the result as universal privacy.

this exact new block:

>
> Every projection served to a session leaves an acknowledged emission record of
> references before it is returned, and a projection without one is refused; a
> projection served but not recorded is a proof failure, while a projection recorded
> but not served is a tolerated over-approximation. For any admitted atom the system
> answers, from its own records and under a signed, story-scoped responder
> capability whose use is itself recorded and whose issuance has a break-glass path
> that does not depend on one person, which sessions, hosts, and principals received
> it after a given cursor, in which delivery state, and which atoms were derived from
> those sessions by recorded emission to a complete, deterministically ordered
> transitive closure, as a single query completing in under sixty seconds on the
> proof corpus. What a person carried between sessions is outside the ledger and is
> named as such on every story. A withhold removes the atom and its derived set from
> trusted projection, reopens dependents as apology Unknowns, and reaches every
> recorded session by its next projection; above the ratified withhold ceiling the
> system withholds the source and first generation and escalates the rest with the
> complete enumeration rather than truncating. A redaction appends a tombstone
> version without changing identity or deleting any story and occurs only on an
> owner's confirmed disposition or a principal's erasure request. Taint is checked at
> proposal and again at commit; a candidate whose source acquired taint between the
> two is refused with a story, not admitted. Open questions and questions the system
> answered for itself are both collected, and the self-answered ones are reported to
> the owner for transparency.

#### O-03 — leak runbook: ledger-driven enumeration and containment

In `spec/leak-runbook.md` replace this exact old block:

> 3. Enumerate distribution: Company replicas/caches; Git server forks, pull requests,
>    mirrors, CI artifacts, package/source archives, and known clone owners. Treat
>    unknown clones as retained copies.

with this exact new block:

> 3. Enumerate distribution. For what the system served, obtain the responder
>    capability for the story and run the lineage query: every session, host, and
>    principal that received the fact after the taint cursor, confirmed and
>    unconfirmed, and the derived set to its bound. Treat `missing[]` and
>    `unattested[]` entries and any truncated frontier as retained copies. For what
>    Git distributed, enumerate Company replicas/caches; Git server forks, pull
>    requests, mirrors, CI artifacts, package/source archives, and known clone
>    owners. Treat unknown clones as retained copies.

and replace this exact old block:

> 5. Publish signed revocation/apology events so every reachable client withholds the
>    leaked fact and its dependents. Rotate affected keys/tokens and invalidate caches.

with this exact new block:

> 5. Publish the signed withhold. It removes the leaked fact and its derived set from
>    trusted projection, reopens dependents as apology Unknowns, and notifies every
>    recorded session at its next projection; confirm each notice as dispatched and
>    acknowledged by its adapter through the `retraction_notice` emission, which is
>    not proof that a person or model read it. If the story exceeded the withhold
>    ceiling, decide the deferred withhold on the complete enumeration now. Rotate
>    affected keys/tokens and invalidate caches. Set the story's disposition; on
>    `confirmed`, or on the data subject's request, publish the redaction and, where
>    required, the purge.

#### O-04 — glossary terms

In `spec/glossary.md` insert after this exact anchor block:

> - **Distortion cost**: expected loss when a fact is absent as a named dependent
>   decision fires.

this exact new block:

> - **Emission record**: acknowledged record-path entry, keyed by service-issued
>   session and sequence, of which admitted atoms were served into which session for
>   which principal and host at which cursors, in state `intended`, `delivered`
>   (an attributed adapter assertion), or `withdrawn` (refused before any byte left
>   the process); references only, never bytes or fact-content digests.
> - **Leak story**: ordered path of references assembled by the single-writer story
>   builder from a taint, scanner, approval-recheck, erasure, key-conflict, or
>   refusal-rate trigger, carrying an attributed disposition, counted impact, an
>   owner set by the trigger's store, a staleness bound, `missing[]`, and
>   `unattested[]`; its derived set is enumerated completely in a total order, and
>   only the withhold action is bounded.
> - **Observation note**: best-effort, many-writer, ephemeral record such as a
>   candidate preview, a scan pass, or an advisory reviewer opinion, carrying a
>   producer sequence and declared cadence; never load bearing and never a system of
>   record.
> - **Responder capability**: Company-owner-issued, signed, time-boxed, single-story
>   authorization for the lineage query over emission records, references only, with
>   every use recorded through a separately durable path and a sealed dual-control
>   break-glass issuance when the owner is unreachable or implicated.
> - **Withhold / release / redact / purge**: withhold is the reversible exclusion of
>   an atom and its derived set from trusted projection with notice to the served
>   set; release reverses it by an owner-signed predicate over the enumerated set;
>   redact appends a tombstone version on an owner's confirmed disposition or an
>   erasure request without changing identity; purge is the owner-signed physical
>   removal of an earlier version's bytes behind a marker whose digest a verifier
>   reports as unverifiable; nothing is deleted from the graph.

#### O-05 — V-3 instruments: enumeration, derived set, delivery states, races

In `spec/verification.md` section V-3 insert after this exact anchor block:

> - Any canary or deterministic lineage on a shared surface immediately yields
>   `NOT_PROVEN`; no later rerun erases the recorded failure.

this exact new block:

> - Admit a clean atom, serve it into at least twenty sessions across both host kinds
>   and two principals, extract at least five first-generation derived atoms from
>   those sessions, serve two of those into further sessions, and extract at least
>   two second-generation atoms from them; then register a canary that taints the
>   source after the fact. Under the responder capability the lineage query must
>   enumerate every serving session, host, and principal with its delivery state and
>   every derived atom of both generations in the order `(generation,
>   extraction_time, atom_id)`, twice over the same event set with byte-identical
>   results, with empty `missing[]` and an `unattested[]` naming cross-session human
>   transfer and only classes with no declared expectation, in under sixty seconds;
>   without the capability the same query must refuse with the bounded typed body;
>   with the Company owner unavailable, the sealed dual-control capability must
>   permit it and record its opening; the story must reach the owner inside the
>   fatigue budget with confirmed, unconfirmed, and withdrawn counts; the withhold
>   must remove the atom and both generations from the next projection of every
>   session and deliver a `retraction_notice` to each with a matching attributed
>   emission; and the redacted version, after `confirmed`, must resolve by identity
>   from every referencing story with a verifiable digest chain. In a separate run
>   evict one scheduled observation note before assembly; the story must list
>   exactly it in `missing[]` with `evicted`. Construct a derived set larger than
>   the withhold ceiling; the story must enumerate it completely, withhold only the
>   source and first generation automatically, escalate the remainder with counts,
>   and accept one owner-signed predicate release over the enumerated set. Suppress
>   one host adapter's delivery acknowledgment; the emission must remain `intended`
>   and the story must count it as unconfirmed, never omit it. Force the emission
>   write to fail; the session must receive `EMISSION_UNRECORDED` and no facts, and
>   the served set must not name it. Commit a withhold of a served atom between the
>   emission acknowledgment and the return; the session must receive
>   `REVOCATION_RACE` and no facts, the emission must be `withdrawn`, and the
>   served set must not include it. Restart the service mid-session; the next
>   projection must continue the committed sequence with no spurious
>   `EMISSION_KEY_CONFLICT` and no spurious story. Replay an emission key with a
>   different reference-payload digest; the service must refuse with
>   `EMISSION_KEY_CONFLICT` and open a story. Purge a redacted version; rebuild must
>   reproduce the purged state, the verifier must report that version's digest as
>   `unverifiable`, and every referencing story must still resolve. Propose a
>   candidate, then register taint on its source before commit; the commit recheck
>   must refuse it and open a story. Any served session not enumerated, any derived
>   atom of either generation not withheld or escalated, any truncated enumeration,
>   any redaction before `confirmed` or an erasure request, or any deletion of a
>   story is `NOT_PROVEN`.

## 3. Failure modes

- **Emission write is on the projection path.** By design, and only for
  projections: one small acknowledged row per projection, not per token. The refusal
  is typed and degrades like a stale revocation snapshot. Sustained refusal is an
  owned signal and a story trigger. If the cost is unacceptable in practice, the
  answer is a faster record path, not an unrecorded projection.
- **Recorded but not delivered.** Now a named state rather than an ambiguity: the
  served set counts it as unconfirmed and notifies it anyway, which is the safe
  direction.
- **Write-versus-revocation race.** Closed by the serializable transaction and the
  post-acknowledgment cursor re-read; the losing projection is refused, never served.
- **Ledger as disclosure oracle.** The record carries identities and versions, not
  content digests, so it cannot confirm a guessed secret. Whole-record reads are
  scope-gated; lineage queries need a story-scoped, audited capability. A leaked
  record would reveal that an atom was served, not the atom.
- **Story builder as single point of failure.** Single-writer so that stories order;
  if it is down, triggers queue on the record path and stories assemble late, never
  lost. Its lag is a monitored signal with an owner.
- **Derived-set over-approximation.** Transitive closure withholds clean atoms. That
  is the correct direction for an irreversible failure; release is one owner-signed
  predicate over the complete enumeration, so a false positive costs one signature.
- **Unaffordably reversible withhold.** Removed: above the ceiling the system does
  not withhold thousands of atoms and then ask for sixty-three signatures; it
  withholds the source and first generation, escalates with the whole enumeration,
  and the owner decides once.
- **Purge versus rebuild.** Named rather than hidden: a purge redefines the frozen
  event set, prior rebuild receipts stop reproducing, and a purged digest is
  reported unverifiable. The weakening is scoped and recorded per purge.
- **Investigation deadlocked by the trigger.** Removed: capability-use events have a
  separately durable, bounded-deferral path, so record-path write pressure that
  opens a story cannot block the query that resolves it.
- **Owner unavailable or implicated.** Removed: sealed dual-control issuance with a
  one-hour bound and loud recording.
- **Defective rule with destructive authority.** Removed: a rule can withhold, which
  is reversible and recorded; only an owner's confirmed disposition or a data
  subject can redact, and only an owner can purge.
- **Refutation as a hidden defect.** A rule refuted repeatedly is reported as
  defective rather than quietly tuned; the O-ring rule applies.

## 4. Constraints

- No new read capability into Personal. Emission records for Personal projections do
  not exist because Personal is never projected into coding sessions.
- No fact bytes and no fact-content digests on the record path beyond what P-3
  already permits in receipts. The idempotency digest is over an emission's own
  references and cursors, not over fact content.
- No deletion of stories, emissions, withholds, redactions, or purge markers;
  corrections are new events.
- The founder's approval-fatigue bound applies to story routing.
- Atom identity is independent of content digest; content is resolved through the
  version history. Any existing consumer that treats an atom digest as its identity
  must be enumerated by the Validator's semantic-delta receipt and migrated or named
  as a residual before ratification.

## 5. Assumptions

- The host adapters can deliver a withhold notice beside the next projection through
  the existing apology-Unknown channel and can post a delivery acknowledgment,
  without a new protocol surface beyond those two messages.
- Extraction provenance already names the session and an extraction time, which
  architecture section 5 requires; the derived set is a query over that, not a new
  capture.

## 6. Limitations

- The ledger covers what Kinbase served. It does not cover what a person copied out
  of a session, what Git distributed, or what a model retained in context after a
  notice; the runbook's erasure caveat stands.
- Detection recall is not improved by this candidate. It improves response, not
  discovery.
- The served set and the derived set over-approximate, deliberately, and the
  amendment names that tolerance rather than claiming precision.

## 7. Alternatives considered

- **Reconstruct from host transcripts.** Rejected: the shared process may not read
  Personal transcripts, and Codex and Claude logs are neither complete nor ours.
- **Copy facts into the story.** Rejected: copies lose the graph, make erasure a
  search for every copy, and fail quietly on the one they miss. References make
  erasure constant in the number of stories.
- **Best-effort emission on the observation path.** Rejected: a note that does not
  arrive is an accepted loss for a diagnosis and an unacceptable loss for a boundary.
- **Redact in place.** Rejected: it breaks append-only and byte-identical rebuild and
  gives a scanner rule destructive authority. Append a tombstone version instead.
- **Delete on retraction.** Rejected: a hole in a corpus agents reason over is a wrong
  answer waiting.
- **One-hop derived set.** Rejected: taint escapes at the second hop with every record
  needed to catch it already in the ledger.

## 8. Review disposition

Revision 1 was reviewed by Simulacrum and by Advocate (Helland, red team, subject
matter expert, adversarial). Dispositions:

- Read rule unsatisfiable after taint (Simulacrum, red team, adversarial): accepted;
  the responder capability and the two-operation read model in 2.3.
- Redaction irreversible before adjudication, and in-place rehash contradicting the
  append-only anchor (Simulacrum, red team, SME): accepted; withhold, release,
  redact, and purge separated in 2.4, with redaction as an appended tombstone
  version.
- Content digest in the emission record as an offline oracle (Simulacrum, Helland):
  accepted; references are `(atom_id, version)` and the version history is the sole
  authority.
- Derived-set transitivity unspecified (Simulacrum, red team, SME, adversarial):
  accepted; transitive closure to a bounded fixed point, a decidable predicate over
  receipt and extraction times, set-level release, and a two-generation instrument.
- `missing[]` vacuous without an expectation source (Simulacrum): accepted;
  sequenced and scheduled observation notes, `unattested[]`, and the instrument
  split into two runs.
- Recorded-but-not-delivered ambiguity and the write-versus-revocation race
  (Helland, red team, adversarial): accepted; two delivery states, the serializable
  transaction, the post-acknowledgment cursor re-read, and `REVOCATION_RACE`.
- Client-influenced idempotency key (red team, adversarial): accepted; service-issued
  session and sequence, and `EMISSION_KEY_CONFLICT` as a story trigger.
- Availability and refusal-rate denial of service (SME, adversarial, red team):
  accepted; durability level named, total-outage disposition ratified explicitly,
  write ceilings, and refusal rate as an owned signal.
- Story ownership across stores (Helland): accepted; owner by trigger's store and
  child stories by reference.
- The governing invariant stated rather than the ordering asserted (Simulacrum):
  accepted; it opens the reader summary and O-01.

Revision 2 was reviewed again by Simulacrum and by Advocate (Helland, adversarial).
Dispositions:

- Closure bound reintroduces under-approximation in the high-fan-out case and is
  nondeterministic (Simulacrum): accepted; enumeration is unbounded, ordered by
  `(generation, extraction_time, atom_id)`, and only the withhold action is bounded,
  by refusal and escalation; release is by predicate.
- `withdrawn` undefined against the served set, and discard not proven atomic with
  the transport (Simulacrum, adversarial): accepted; no byte reaches the transport
  before the re-read, `withdrawn` is outside the served set and the closure, and the
  transit window is named with `retraction_notice` as its apology.
- Purge contradicts digest-chain verifiability and rebuild (Simulacrum,
  adversarial): accepted; purge is a ratified, scoped weakening, purged digests are
  reported unverifiable, and a purge instrument is added.
- Idempotency payload digest contradicts the no-digest constraint (Simulacrum):
  accepted; the constraint now distinguishes reference-payload digests from
  fact-content digests.
- `unattested[]` overloaded with truncation (Simulacrum): accepted; truncation no
  longer exists, and `unattested[]` always names cross-session human transfer.
- `delivered` is an adapter claim, not a service truth (Helland, adversarial):
  accepted; recorded as `delivery_claimed_by`, defined as dispatched and
  acknowledged, and the runbook wording follows.
- Serializable transaction with an out-of-process adapter (Helland): accepted; the
  transaction bounds the window to the transit, and the residual is named.
- `inconsistent` has no adjudicator (Helland): accepted; owner, containment default,
  and disposition path named.
- Derived set under-approximates for human transfer between sessions
  (adversarial): accepted; the promise is scoped to recorded emission and the class
  is always named in `unattested[]`.
- Session and sequence across service restart (adversarial): accepted; both are
  committed record-path facts, with a restart instrument.
- Responder capability depends on one available, uncompromised person
  (adversarial, Simulacrum): accepted; one-hour issuance bound, sealed dual-control
  break-glass, and a separately durable use-event path.

## 9. Open questions and resolution gates

1. The sixty-second query bound, the one-hour issuance bound, the twenty-session and
   two-generation instrument sizes, and the 512-atom withhold ceiling are proposed
   numbers for founder ratification.
2. Whether the Codebase store's Git-carried `.kin/` events should carry withhold and
   redact events so that clones learn of them on pull; proposed yes, as a follow-up
   amendment, since it changes the `.kin/` event schema.
3. Whether existing consumers of atom digests treat the digest as identity; the
   Validator's semantic-delta receipt must enumerate them (section 4).
4. A Validator semantic-delta receipt for O-01 through O-05, a second Advocate pass
   over this revision, and founder ratification of its exact digest are required
   before any Coder lane may read these bytes.
