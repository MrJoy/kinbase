# Architecture Specification — Kinbase proving ground

Status: **candidate for review and exact-byte ratification**

Authority: [`product.md`](product.md). The finite acceptance adversary is separately
bound by [`threat-model.md`](threat-model.md). Declared tradition: one authority per
fact; Helland-style entity ownership and immutable messages; Evans-style bounded
contexts; Hickey-style values over mutable place.

## 1. One protocol, three bounded products

The implementation is a Python 3.12 package with a CLI and local HTTP service. It
uses one canonical event/projection protocol but never one universal graph.

```text
private principal boundary     company authority boundary       Git boundary

Kindex Personal          --[no shared capability]--  Kinbase / Kindex Company
SQLite event+graph store                            service + SQLite event store
raw private provenance                              org facts / authority registry

Kinbase / Kindex Company --[references, no shared rows]-- Kindex Codebase
service + SQLite event store                           repo/.kin/events
org facts / authority registry                         repo facts / references
```

Each labeled separation is a capability and filesystem boundary, not an audience predicate. A handle
is constructed for exactly one store kind. The type and runtime interfaces do not
offer “select audience” or “open all stores.” Coding projection accepts a Company
read capability and one Codebase read capability; its process receives no Personal
path or handle. Shared promotion receives a minimized candidate payload, not the
Personal store or transcript.

This is enforced in the shipped proof process, not only its tests. The launcher runs
shared projector/writer helpers under an OS policy that denies the Personal root and
all unrelated user paths while allowing only the declared Company socket/cache and
one repository root (macOS sandbox profile; Linux Landlock/bubblewrap backend). It
passes already-open minimum descriptors, closes the rest, and runs a denial probe at
startup. If no supported kernel enforcement is available or the probe succeeds in
reading Personal, shared projection/publication is disabled with a typed failure.

The existing Kindex package is integrated behind `PersonalKindexAdapter` and
`CodebaseKindexAdapter`; Kinbase does not fork its generic graph/search code.
Adapters use public Store/export/import surfaces or subprocess JSON contracts. Any
missing public seam is isolated in the adapter and recorded rather than answered by
writing Kindex SQLite tables directly.

The preregistration pins Kindex 0.36.0. Verified public seams are `kin export`
(JSON/JSONL and audience scope), `kin ingest` (sessions, codex-sessions, files,
commits, github, code, projects), `kin setup-hooks --dry-run`,
`kin setup-codex-hooks --dry-run`, and Store node/edge/candidate/
verify/invalidate/supersede methods. The existing `kin index` repository path exports
code nodes rather than arbitrary conceptual/decision facts; the new signed `.kin/`
event adapter is the explicit compatibility gap this proof exercises. A startup
compatibility test checks each named seam and blocks the affected adapter on
conformance failure.

Kinbase owns protocol `kinbase-event/1` under `.kin/events/` and
`.kin/manifests/`; it does not claim existing Kindex owns or already writes that
format. A pre-existing `.kin/index.json` is a legacy source observation owned by the
`kindex` adapter: it is preserved, never treated as a reducer cache, and never becomes
signed direction automatically. Kinbase's derived compatibility view has the
distinct ignored path `.kin/local/kinbase-index.json`. `repo init` is additive and
refuses a conflicting path.
Kindex 0.36.0 is the known-good proof baseline, but the executable gate is the frozen
public-seam conformance suite, not version-string equality. A different version may
run only after passing that suite byte-for-byte. Failure is a loud degraded product
state and blocks P-1/P-2/P-9 proof dispatch—Personal is not silently removed while the
system presents itself as complete. Native Kinbase events remain inspectable. A
future migration tool is post-proof packaging work, not an excuse to overwrite an
existing `.kin/`.

## 2. Entity ownership and identities

The following entities have exactly one owner and stable identity:

| Entity | Owner | Identity / concurrency rule |
|---|---|---|
| Personal observation/fact | principal | private random ID; never leaves Personal |
| Company observation/fact | Company steward in scope | company ID + stable fact ID; optimistic expected-parent |
| Codebase observation/fact | repository authority in scope | signed repository ID + stable fact ID; branch events union |
| source observation | source adapter | source kind + native ID + content digest + revision |
| runtime/environment observation | registered environment/deploy owner in exact scope | environment ID + observation digest + effective-until |
| authority answer | named scoped authority | question ID + answer event + signer |
| Unknown | store owning the dependent decision | stable question ID; close only with named evidence |
| session candidate | principal/run | random unlinkable ID; expires; never used as shared identity |
| approval | approving authority | one destination + exact payload digest + nonce |
| derived current view | reducer version | disposable content-addressed projection |
| query/decision trace | evaluation run | immutable trace, privacy-minimized by store boundary |

Company and Codebase exchange references, never shared mutable rows. Network/write
retries use a destination-owned record keyed by destination, approval nonce, approved
event digest, approver client-key binding, and exact authority scope. A retry must
carry the same scoped client-key signature as the original approval and consumes the
ordinary read-volume ceiling; another client receives one indistinguishable typed
refusal rather than a receipt/digest oracle. Company commits nonce consumption, event
append, and receipt in one SQLite transaction with a unique `(destination, nonce)`
constraint. A matching authorized committed retry returns the stored historical
receipt without re-admitting or re-projecting the event; a mismatch refuses.

New admission order is normative: parse once; verify canonical bytes, domain,
signature, approval, exact scope, repository identity, and current revocation cursor;
then compute the content path and enter the idempotent destination transaction. A
pre-revocation committed retry may return its historical receipt to its original
client, but current projection is still recalculated under current revocation state.
No path-exists fast path can admit a new/revoked event. Codebase uses a recoverable
destination journal plus the computed content-addressed event path: atomic rename
makes the exact already-admitted event idempotent, and
restart completes or rolls back manifest/receipt state from the journal. Every crash
point is replayed; no check-then-act lookup may create a second event or hide a first.
A repository-scoped admission lock is an exclusive OS file lock stored in Git's common
directory and keyed by certified repository UUID, so every linked worktree contends on
the same lock. It serializes journal generation, event rename, manifest construction,
index/cache update, and receipt finalization; competing local
writers retry from the committed generation, while ordinary Git later unions distinct
content-addressed events. Journal states and transitions are a closed enum and every
transition fsyncs before the next side effect.
A matching committed event returns its original receipt during the seven-day nonce
retention window even after token expiry; an uncommitted expired/replayed nonce
refuses. Consumed nonce records survive backup/restore, outlive the 15-minute token
plus five-minute proof clock-skew bound, and prune only after seven days. Startup
refuses unless configured nonce retention is strictly greater than candidate/token
lifetime plus the skew allowance; documenting current values is not enforcement. A nonce
absent after that horizon is always `APPROVAL_EXPIRED`, never eligible as fresh.
Cross-destination fan-out is a saga: each destination returns its own
committed/refused/pending/abandoned receipt. No global rollback is claimed. A
terminally divergent fan-out emits a new apology Unknown in every committed
destination. It names the approving principal as responsible party and the in-scope
destination steward/maintainer as closing authority, and withholds the orphaned claim
from trusted use until an explicit reconcile/abandon event. Missing closing authority
creates the normal registry Unknown; deadline invokes the destination's declared P-6
degraded policy and the destination service emits a signed `orphan_abandoned` event
naming the unresponsive closing authority. That event terminally closes the saga while
keeping the fact withdrawn; it is not a semantic rejection on the authority's behalf.
An apology write failure stays in the destination journal, blocks
the orphan, and retries without recursively creating another apology.
The principal sees one in-session reconcile/abandon item and the closing authority
receives the same Unknown through its registry channel with `response_due_at`. That
item uses the ordinary prompt-budget reservation. Permanent inability to write the
apology leaves a local quarantine marker and exit-5 `doctor` failure; local orphan
blocking requires no Company round trip.

Repository identity is an out-of-worktree Company-steward certificate whose sole
identity is a random repository UUID. A normalized upstream URL is only a discovery
hint and is never admission authority. A clone may move or its remote may change; a
fork is a new identity unless a steward certificate explicitly declares lineage.
After first verified resolution the client pins `(discovery hint, repository UUID,
certificate digest)` in its out-of-worktree Company cache. A later hint returning a
different UUID or certificate blocks with a steward-owned identity Unknown; it never
silently repins. Only a signed Company lineage/move event may update the binding.
The cache record is itself Company-signed with authority cursor and expiry. A deleted
or rolled-back cache is cold, never trusted offline, and must refetch a cursor at
least as new as the last locally sealed cursor; inability to do so withholds all
affected facts. Every online refresh sends a fresh client nonce; the Company response
signs that nonce and a cursor no older than Company's current revocation cursor, so a
replayed old signed response cannot rebuild a deleted high-water mark. The cache root
is mode 0700. A same-UID process can delete local cache/high-water bytes and force
online/degraded operation; the design does not claim local rollback detection against
that process without an online challenge. It cannot turn a replay into trusted state.
Worktree `.kin/` bytes cannot introduce trust roots, authorities, Company endpoints,
or certificates. Without a resolvable Company/out-of-worktree certificate, all
`.kin/` events are counted as `UNVERIFIED`, trusted projection is empty, and writes
are refused. Event bodies are visible only through an explicit diagnostic inspect
command and never enter SessionStart, a host projection, model request, or tool-result
envelope. Foreign parent events in an uncertified fork are counted and reported, not
silently presented as an empty healthy view.
Every uncertified SessionStart creates or reuses one certificate Unknown owned by the
in-scope repository maintainer with Company steward fallback, `response_due_at`, and
the declared P-6 degraded policy; repeated starts do not duplicate it.

## 3. Canonical data model

All durable messages use RFC 8785 JSON Canonicalization Scheme bytes after NFC
normalization, with duplicate keys and non-finite numbers rejected and integers
bounded to the interoperable ±(2^53−1) range. Scores use signed integer basis points,
a frozen fact-ID-ordered expression tree, signed 256-bit integer intermediates,
rational division reduced after each operation with round-half-to-even, and fact-ID
tie breaking. The first ordered subexpression outside the signed 256-bit range emits
the typed integrity failure; serialized results must also fit the JSON bound. No
binary floats enter a signed event. Times are RFC 3339 UTC strings with exactly millisecond precision and
a `Z` suffix; monotonic cursors are opaque decimal strings whose ordering is defined
by the owning store, never JSON numbers. Absolute local paths and executable
command/policy fields are
forbidden. Schema versions are closed, canonicalization test vectors are frozen,
and content is length-bounded hostile data. Every human-readable text field rejects
C0/C1 controls, Unicode noncharacters, and bidi formatting controls U+061C,
U+200E–U+200F, U+202A–U+202E, and U+2066–U+2069 before signature verification. The
approval renderer presents a bijective escaped view: printable ASCII remains literal
and every other code point, quote, backslash, CR/LF, or non-printable byte is escaped;
round-tripping that view must reproduce the exact signed UTF-8 buffer and digest.

Signatures are domain separated. Every signer signs
`SHA-256("kinbase-sig/1" || 0x00 || message_type || 0x00 || jcs_bytes)` where
`message_type` is one closed enum: `fact-event`, `unknown-event`, `manifest`,
`approval-token`, `repo-certificate`, `authority-registry-entry`, `rotation`,
`revocation`, `tombstone`, `question`, `answer`, or `receipt`. Verification and
semantic use share one strict parse of the same immutable byte buffer; no second
parser supplies application semantics. Scope and logical-key authorization uses
canonical exact equality, never SQL `LIKE`, glob, regex, or prefix matching. All SQL
values are bound parameters. Cross-type reuse, parser differentials, wildcard/NUL/
FTS metacharacters, and normalization changes are frozen attack vectors.

`Observation` records native evidence without asserting truth:

```text
observation_id, source_kind, source_identity, native_id, content_digest,
repository_id?, revision?, branch?, disposition, observed_at,
asserted_at?, effective_from?, effective_until?, body_ref, extraction_version
```

Raw body storage follows its source boundary. Personal transcript bodies stay in
Personal private storage. Shared observations contain only admitted source bytes or
approved minimized evidence. `body_ref` is store-local and never portable across
boundaries.

`FactEvent` is an immutable message:

```text
schema, event_id, store_kind, authority_id, authority_scope, repository_id?,
fact_id, logical_key, atom_kind, scope, statement, evidence_refs,
asserted_at, effective_from, effective_until?, disposition,
distortion {trigger, loss_if_absent, rationale},
parents[], supersedes[], redundancy_with[], complements[],
company_refs[], authority_snapshot_cursor, confidence, unresolved_uncertainty,
signer, signature
```

`UnknownEvent` adds `decision_blocked`, `owner_role`, `owner_identity`, `question`,
`closure_evidence`, `status`, `response_due_at`, and `expiry_policy`. A blocking
Unknown always names a person. If the registry cannot resolve one, it creates a
second registry Unknown owned by the Company steward. Unknown closure names the
answer/evidence event; absence and deadline expiry are not closure. Deadline expiry
executes the declared P-6 degraded policy.

`CompanyReference` copies the Company-published Company ID, fact ID, semantic-content
digest, `digest_alg_version`, authority, observed valid interval,
`company_criticality`, and relation. Company owns those fields. A separate
`local_dependence_class` is a Codebase fact owned by the in-scope repository
maintainer and states the consequence of losing this reference in this repository.
Projection uses the stricter of Company criticality and local dependence; raising
the local class records its maintainer, and a missing local owner is a
repository-maintainer Unknown. Codebase never recomputes the published digest or
edits Company criticality.

Every decision trace records derived `effective_dependence_class`, both input facts
and owners, the deterministic max rule, and which input dominated; the reducer owns
only that reproducible derived value, not either input. A maintainer who raises local
dependence may open a Company-steward Unknown requesting Company reclassification.
A later over-withhold apology names the dominating input's owner and leaves the
original trace intact.

A maintainer who needs a repository-local relaxation cannot lower Company criticality
or ask for a global downgrade as a shortcut. It files the existing P-8
`exception_request` bound to repository UUID, Company fact/version, requested class,
reason, and expiry. Only the Company steward may sign a scoped `relaxation` event.
Projection then compares local dependence with the Company class as explicitly
relaxed for that repository; absence/expiry restores the unrelaxed class. The trace
records the exception owner, scope, version, and dominating input.

Unknown digest-algorithm version means client upgrade/degraded mode. For a known
algorithm mismatch, the client asks Company for the published digest bound to the
reference's exact fact version and algorithm, plus Company's separately current
head. A differing historical digest means a changed/corrupt reference and a steward-
owned Unknown; a matching historical digest means a client canonicalization defect
and a client-owned Unknown; unavailable or no-longer-retained historical version
yields a Company publication-retention Unknown without accusing the client. Company
text is dereferenced only through an authorized live Company
capability and is never copied into `.kin/`.

`SessionCandidate` contains the one atom, source taints, destination, omitted fields,
minimized payload, classifier trace, expiry, and a random candidate ID. It lives only
in a mode-0700 private run directory. `ApprovalToken` binds candidate, destination,
payload digest, approver, nonce, issue/expiry, and signature. Candidate source taint
never clears; the token authorizes only the rendered bytes.

An approver who later discovers model misextraction may issue a domain-separated
`misextraction` notice naming the original event and a closed reason code. The
approver owns only the claim that the approved bytes did not faithfully represent the
evidence shown; that notice immediately withholds the fact and reopens it as a
destination-steward/maintainer-owned Unknown. Only that subject-matter authority may
sign the semantic `never_true` withdrawal. If approver and authority are the same
principal, both message types are still explicit. Original approval, notice,
withdrawal, and apology remain linked and immutable.

### Trust and key lifecycle

The PoC uses Ed25519 keys and one externally configured Company root. User config
contains only the root public key, Company endpoint, per-instance bearer-token file,
and repository-discovery hints; it is outside every worktree and mode 0600. Company
stewards issue repository certificates and publish scoped authority/maintainer public
keys through the signed AuthorityRegistry. A fresh clone resolves by URL hint to a
UUID certificate, then treats the UUID as identity. No trust-on-first-use exists.

The registry only moves forward. Company admits a registry document only at an
authority cursor greater than the one it has published; posting the current document
again returns its receipt with no effect, and any older or equal-cursor document
refuses with `APPROVAL_REPLAY`, because a steward signature on a superseded registry
stays valid and would otherwise roll every later entry back into revocations. A
republication that drops an entry revokes exactly what the entry granted: a key no
entry lists any more is revoked, and a key still listed under other scopes is revoked
for the dropped scope only, with the recalculation below applied to what it warranted
there.

Rotation is a Company event signed by an already authorized steward and names old
key, new key, effective cursor, and scope. Revocation is a signed Company event with
its own cursor and effective time. Pre-revocation facts remain historical but any
client that has observed a cursor at or beyond the revocation cursor recalculates
current trust as follows: a decision trace warranted by that key reopens under the
decision principal; a fact whose sole admissible support was that key withdraws from
trusted projection under the destination steward/maintainer; a multiply supported
fact remains current but records a signed `support_withdrawn` event. The immutable
historical transaction is never erased or rewritten. A client that has not synced
cannot know the revocation, so no global-instantaneous claim is made; its bounded
revocation freshness clock controls whether it may project offline. Post-revocation
events refuse. Compromise response is: revoke, advance the authority cursor,
invalidate caches, enumerate affected decision traces, emit destination-owned
apology Unknowns, and rotate. Key loss requires a distinct steward recovery key; it
never licenses local replacement. The PoC proves this lifecycle with test keys but
does not claim enterprise key custody or hardware protection.

Revocation propagation is a bounded local job keyed by the newly observed cursor.
Until every locally addressable fact/trace is re-evaluated, projection state is
`REVOCATION_CASCADE_INCOMPLETE` and all not-yet-rechecked facts are withheld, not
assumed unaffected. At the proof ceiling of 10,000 events it must finish within 120
seconds; exceeding that records the remaining count, retains fail-closed state, and
returns a typed limit/integrity failure. No client claims recomputation in another
clone it cannot address. The Company steward owns an immutable
`unreachable_clone_residual` record naming revoked key, cursor, potentially warranted
fact/logical-key set, maximum offline revocation-freshness window, and the explicit
fact that unknown clones may keep projecting until they sync or expire. Every client
with a stale revocation clock withholds affected facts, so the residual is unbounded
in clone count but bounded by the declared freshness interval for conforming clients.

## 4. Source adapter contract

Every adapter implements:

```text
probe(source) -> SourceReceipt
scan(source, checkpoint?) -> ObservationBatch + next_checkpoint
reconcile(previous_checkpoint, current_batch) -> lifecycle events
```

It must preserve stable native IDs, detect update/deletion/disposition changes, bind
the source revision, and be idempotent. Repository observations also carry an origin
trust class derived from Git evidence: `merged-default`, `approved-pr`,
`unreviewed-branch`, or `uncommitted-worktree`. Anything below `merged-default` is
ineligible for trusted durable direction unless a separately authorized event cites
it; merely checking out an attacker branch cannot promote its ADR. Runtime evidence
names the environment/deployment owner and a freshness-bounded `effective_until`.
Adapters do not classify destinations or assert facts. The initial implementation
includes:

- `codex_jsonl`: parses Codex rollout JSONL and recorded cwd/repo metadata;
- `claude_jsonl`: parses Claude Code project-session JSONL;
- `repo_code`: language-agnostic files plus Python/TypeScript declarations;
- `repo_tests`: tests and command-result envelopes;
- `git_history`: commits, diffs, refs, merge-base/reachability, reverts;
- `docs_adr`: Markdown/RST/text and ADR status metadata;
- `github_export`: `gh` JSON output or recorded export for issues, PRs, reviews,
  merged/closed state; live access is optional but native JSON parsing is not;
- `runtime_evidence`: canonical command/config/trace envelopes;
- `kindex`: exported SQLite graph facts and `.kin/` events/indexes;
- `authority_answer`: signed responses to registered questions.

Corpus builds are manifests over exact adapter receipts. A source-class count alone
does not pass P-1: the evidence report lists native observations and derived facts.

## 5. Extraction, taint, and routing

`Extractor` receives one or more observations in one boundary and returns atomic
claim candidates using a structured JSON model contract. The reference implementation
supports a live model command and a deterministic replay provider for tests. The live
proof uses the model command; recorded model output is only reproducibility evidence.
The launcher opens the absolute classifier executable once, verifies owner, mode,
regular-file identity, containing-directory chain, and pinned SHA-256 through that
descriptor, then executes that same descriptor with `fexecve`/`execveat`; it never
re-resolves the pathname between check and execution. A platform without verified
descriptor-backed execution disables the external-classifier path. There is no shell/
PATH resolution; the child receives a scrubbed environment and an explicit close-on-
exec descriptor allowlist. Its exact authorized processor/data scope is in the
manifest; digest/config/descriptor mutation refuses before any Personal bytes are
sent.

`RoutingPolicy` is deterministic and runs after extraction:

1. attach non-clearable provenance taint (`personal-session`,
   `company-confidential`, `codebase`, `public`, `secret`, configured canary classes);
2. validate one-claim atomization and declared scope;
3. derive eligible destinations from source boundary, repository binding, authority,
   and sensitivity;
4. reject/demote destinations the model was not eligible to propose;
5. run secret/identifier/correlation scanners over the exact minimized payload;
6. require a destination-specific authority approval for shared output.

A `secret`, credential, configured-canary, or forbidden-identifier taint is
hard-blocking for every shared destination and cannot be approved. An observation
containing one yields no shared candidate at all, preventing a model paraphrase from
escaping a string scanner. `personal-session` and `company-confidential` are
approval-gating provenance classes: they remain on the private candidate record but
may produce a shared atom only after destination eligibility, minimization, scanning,
and exact-byte approval. Taint is never described as cleared; its policy consequence
differs by class.

A Personal session may yield a private Personal fact automatically and separate
Company/Codebase proposals when it contains no hard-blocking taint, but shared
renderers receive only the selected atom and public evidence summary. `deidentify`
strips identity and incidental narrative, then shows every output byte and omission
to the approver. It never claims anonymity.
There is no batch/accept-all endpoint in Core or CLI. Approval UI presents one item,
one destination, and one digest; rate and queue ceilings make blind approval visible.
The decision vocabulary is closed to `approve`, `reject`, `defer`, and `escalate`.
The endpoint accepts no free-text edit, annotation, explanation, or replacement
payload. `escalate` creates an owned Unknown from the already frozen question
template; it does not accept answer prose. Operational resets accept a closed reason
code that never enters a candidate, fact, question, projection, or experiment context.
The approver sees inline canonical bytes B and signs the domain-separated approval
message containing `digest(B)`, destination, nonce, principal, session, and expiry.
The destination writer receives the same immutable B inline, verifies token and
signature, recomputes `digest(B)`, and commits that buffer through the destination's
atomic/recoverable admission state machine. It never resolves or re-reads a candidate
pathname. Private directory permissions are defense in depth, not the TOCTOU control.

Approval-fatigue counters are scoped to composite `(principal_id, host_instance_id)`
and live in one serialized Core SQLite store; no cross-machine budget claim is made.
The host instance owns a signed `prompt_budget_shard` observation, and `doctor` shows
its identity/counts plus an explicit unknown-global-total warning. Core executes one
`BEGIN IMMEDIATE` transaction that checks reissue eligibility, inserts the unique
`(principal, destination, content_digest, lock_window)` reissue lock, reserves one of
four total cross-destination sliding-hour slots, increments the consecutive count,
and issues a single-use display token. Destinations may have stricter sublimits but do
not each receive four slots. A host cannot render a prompt without that token. Crash/
abandon releases no counter directly—the reservation expires on the same sliding
clock—preventing race/decrement abuse. Suppressed proposals do not reserve and remain
private session suggestions until expiry; nothing shared is queued or dropped
silently.

The sliding four-per-hour ceiling cannot be reset and naturally clears as reservations
age out. A principal reset may clear only the three-consecutive counter after a new
primary-task event and is limited to once per hour. A rejected/deferred/expired content
digest cannot be reissued for 24 hours unless its source revision or rendered bytes
change; byte-change reissue is eligible only for an authority-trusted source revision,
and it never bypasses priority, the atomic lock, or total slot reservation. Concurrent Codex/Claude sessions
on the host contend on the same transaction. Reserved, rendered, decided, expired,
suppressed, and delivery-loss counts are product-quality metrics.

Approved Company contributions enter a steward review queue unless the approver is
already the in-scope steward. Approved Codebase contributions require an in-scope
maintainer. A coding agent cannot self-promote its proposal by signing as itself.

## 6. Durable stores and corpus maintenance

### Personal

`PersonalKindexAdapter` owns a Kindex SQLite data directory outside all repositories,
mode 0700. It may retain raw private provenance under configured retention. Its IDs
are never referenced from Company or Codebase. There is no coding-query method on
this adapter. The launcher opens the Personal root as a directory file descriptor
only in the Personal worker, then derives a separate immutable shared-process config
containing Company endpoint, scoped token descriptors, Company root key, cache root,
and certified repository identity. The shared writer/projector never receives the
Personal pathname, directory descriptor, environment variable, argv value, or
serialized parent config. Product components enforce capability non-possession;
shared helpers and acceptance coding agents run in the OS sandbox that denies the Personal root. An
arbitrary same-UID process outside that sandbox can read user-readable files and is
explicitly outside the Kindex application-boundary claim; V-3 still injects such an
exfiltration attempt to prove that shared promotion blocks what reaches it.

Sandbox startup proves both pathname denial and descriptor non-possession. The shared
process enumerates its live descriptors using the platform-native facility, rejects
any descriptor whose `fstat` device/inode falls under the Personal root, and accepts
only a frozen `CLOEXEC`-by-default allowlist. The launcher independently attests the
same allowlist. Passing an already-open Personal directory/file descriptor is a hard
startup failure even when path access remains denied.

### Company / Kinbase

`kinbased` is a real loopback-capable HTTP service with an append-only SQLite event
table, authority registry, source observations, current-view cache, Unknown queue,
and monotonic change cursor. The proof runs service and client as separate processes.
Every endpoint, including reads, requires a per-instance bearer token loaded from a
mode-0600 file, exact loopback Host validation, absent Origin header, and JSON content
type for bodies. Tokens are capability-scoped (`facts:read`, `questions:write`,
`directory:read`, or administrative issuance), compared in constant time, bound to a
client-instance public key, rotated by the Company owner, and throttled by a serialized
failed-authentication counter. The private client key is supplied by an already-open
keychain/file descriptor and never copied beside the token. The ordinary facts token
cannot read the separate directory/contact table or post an answer. Every read,
write, question, and answer also requires a scoped domain-separated request signature
over method, path, body digest, monotonic nonce, and short expiry; answers must match
the AuthorityRegistry signer. A facts token contains a closed set of exact canonical
`authority_scope` byte strings; a fact is readable iff its authority scope is a member
by byte equality. Missing or empty sets grant nothing. Wildcards/prefixes do not exist,
and the administrative issuance capability cannot read fact bodies. Read scopes also
bind per-principal volume ceilings, so a copied token alone cannot enumerate Company
prose. Authentication/authorization failures return the same bounded body and typed
refusal. Host/Origin checks are anti-CSRF hardening only; the security claim against a
local same-UID process rests on scoped token plus client-key request signature, not
those headers.

A client cache binds company ID, cursor, authority snapshot, separate short
revocation-valid-until, fact-valid-until, and the root/signature chain. Both clocks
are rechecked at every projection, not only SessionStart. Every decision trace and
new fact records the authority-snapshot cursor used. A later revocation reopens
affected downstream facts as apology Unknowns. Expired safety facts fail closed
offline; advisory facts are labeled stale and excluded from trusted claims.

Cache disagreement is total and ordered:

| revocation snapshot | fact validity | dependence class | projection |
|---|---|---|---|
| fresh | fresh | any | trusted |
| fresh | expired | safety | withheld, fact-owner Unknown |
| fresh | expired | advisory | excluded with stale label and owner Unknown |
| stale | any | safety | withheld, `REVOCATION_STALE` plus Company-steward Unknown |
| stale | fresh | advisory | excluded/degraded; never called trusted |
| stale | expired | advisory | excluded with both stale reasons |

Certificate/root validity failure dominates every row and yields no trusted facts.

### Codebase

The canonical shared form is one signed event per content-addressed path:
`.kin/events/<hex-0:2>/<hex-2:4>/<remaining-60-hex>.json`. A tracked `.kin/config` contains
only repository metadata and safe client hints. Signed, parent-linked,
content-addressed `.kin/manifests/<hex-0:2>/<hex-2:4>/<remaining-60-hex>.json` events publish complete event counts
and Merkle roots for repository revisions; concurrent branch manifests therefore
union rather than fight over one pointer. An in-scope repository maintainer executes
`kinbase repo publish-manifest`, signing `(repository_uuid, branch,
observed_default_branch_revision, manifest_head_set, event_count, merkle_root,
observed_at, fresh_until)` and sending it to Company. Company stores and republishes
that dated observation; it does not become Git authority. Server-side monotonicity
rejects lower event counts for the same reachable branch lineage unless a separately
signed maintainer rollback/rewrite event explains it. When `fresh_until` lapses without
a replacement, Company emits its own `manifest_observation_expired` event, retires the
observation to historical-only status, and opens a Company-steward publication Unknown;
it does not wait for a clone or maintainer to notice its stale claim.

Comparison evaluates equality, strict superset, strict subset, and incomparable sets
against Git reachability from `observed_default_branch_revision`. Equal is complete.
A local strict superset within freshness is normal Company lag and records a signed
delta. A strict subset missing a published reachable head is `INCOMPLETE` with a
repository-maintainer Unknown and dependent facts withheld. For incomparable sets,
local-only heads unreachable from the published default lineage are divergent-branch
observations, not missing-data accusations; any published reachable head absent
locally still produces `INCOMPLETE`. An expired Company observation is a Company-
steward publication-pipeline Unknown and cannot by itself accuse the clone. Company
unreachable applies the cache truth table. Foreign events are counted separately and
never trusted.

The current view is regenerated under ignored `.kin/local/current.json`; no derived
index participates in Git merge. `.kin/local/kinbase-index.json` is a reducer-owned
cache and `fsck` requires byte-equivalence to a rebuild before use. The tracked legacy
`.kin/index.json`, when present, remains adapter-owned input and is never compared to
that view. Runtime state, candidates, raw source, caches, and private data live under
ignored `.kin/local/` or outside the worktree.

`fsck` validates full SHA-256 path equals exact canonical event bytes, schema,
signature, authority, repository UUID, manifest/Merkle completeness, checkout
completeness, size, and any compatibility index. Deletion, shallow/sparse omission,
modified event, manifest divergence, foreign fork events, or conflicting heads is
loud and typed. Ordinary Git add/add merges preserve distinct event paths. The
reducer works from unioned events at the checked-out revision and exposes conflicts
instead of resolving them by time. Incremental fsck caches only a verified
manifest/checkpoint and revalidates a parent-linked delta. Normal append, branch
switch, restart, and linked-worktree movement with a verifiable path between cached
and target manifests remain incremental. Full fsck is required only for missing/
corrupt cache, reducer/trust-root change, non-bridgable history, or an integrity
disagreement; it is never the default response to an ordinary different checkout.

Event and manifest paths are constructed only from a computed lowercase ASCII
SHA-256 digest with fixed sharded length. The two digest-byte directory levels keep
bounded fan-out under the 10,000-event admission ceiling. User-supplied paths, uppercase aliases,
separators, dot segments, NUL, and Unicode are rejected before filesystem access.
Repository initialization installs and `fsck` verifies effective Git attributes
`.kin/events/** -text -diff -merge` and `.kin/manifests/** -text -diff -merge`.
Acceptance covers `core.ignorecase=true`, `core.autocrlf=true`, macOS normalization,
and a deliberately supplied case alias.

### Reduction algorithm

The reducer is a pure function of `(admitted event set, reducer version, as_of,
authority snapshot cursor)` and emits a trace. `as_of` is an explicit RFC 3339 UTC
millisecond timestamp, never an ambient wall-clock read. For each logical key:

1. reject ineligible authority/scope/signature/repository events;
2. interpret explicit retraction/revocation and parent-bound supersession;
3. classify source disposition and branch reachability;
4. expire temporary/incident/experiment evidence by its declared lifetime;
5. collapse exact semantic duplicates while retaining provenance multiplicity;
6. distinguish independent corroboration from common-source repetition;
7. surface incompatible surviving heads as conflict;
8. derive one current fact only when authority and lifecycle make it unambiguous;
9. otherwise produce an owned Unknown with the exact discriminating evidence.

Recency is used only inside an authority/lifecycle-equivalent set and through an
explicit source-type decay policy. A recent rejected/reverted proposal is negative
evidence, not a current rule. Live runtime configuration may defeat a code-default
diagnosis for an operational question without acquiring authority to rewrite a
Company architecture decision. That operational fact names the environment/deploy
owner and expires at the observation freshness deadline into an owned Unknown.

Ordering never relies on millisecond timestamps alone. Within one store, its opaque
monotonic cursor orders equal-time events; remaining equal-cursor sets use event ID
only for deterministic iteration, never conflict resolution. Every Codebase admission
records the Company authority-snapshot cursor it observed. Event times more than five
minutes ahead/behind the receiving proof clock are quarantined as `CLOCK_SKEW` until
an owner supplies corrected evidence; leap-second text or backward clock steps never
rewrite store cursor order.

Derived views are disposable. `rebuild` from immutable events with the same explicit
inputs must be byte-identical.
Private observations and candidates have separate retention clocks. Company and
Codebase facts are retired by new events, never destructive overwrite.

Extraction is intentionally not byte-deterministic because a pinned live model may
still vary. Each run retains model/version/settings, extraction version, input
digests, and proposed event bytes; repeated live extraction is judged by fact-level
stability metrics. Byte-identical rebuild applies only to reduction/current-view and
selection over a frozen admitted event set.

## 7. Authority-seeking loop

`AuthorityRegistry` is a Company-owned mapping from `(company, scope, question_kind)`
to named principal, public key, and channel adapter. Supported PoC channels are:

- interactive terminal round trip to a real human;
- signed inbox/outbox files for asynchronous/reproducible runs.

The registry stores a stable authority ID, scope, public key, and opaque channel
reference. Display name and contact endpoint are directory Personal data kept in a
separate access-controlled table with explicit retention; they are omitted from
Codebase events and proof packets. Private signing keys and bearer tokens are never
registry values—only references to caller-supplied file descriptors or keychain
handles. Test runs use fictional principals and generated keys. A live founder
channel is opt-in.

An admitted answer is a Company business record under the Company's declared
retention policy, attributed by stable authority ID rather than copied contact data.
Erasing or deactivating directory/contact fields does not silently rewrite that
record. If governing policy requires answer-content removal, a signed tombstone
withdraws it and every dependent decision reopens as an Unknown; the system never
pretends the evidence still exists.

The mapping resolves to exactly one authority identity for an exact scope; role
prestige and recency are not an implicit lattice. The founder owns product and
experiment intent but has architecture-answer authority only when separately
registered for that scope. Two active registry entries for an overlapping exact
scope are a registry conflict owned by the Company steward, and neither answer can
close the Unknown. A principal may replace its own earlier answer only with an
explicit parent-bound supersession. A contradictory answer without that parent
survives as a conflict; newest timestamp never wins.

`environment:<id>` is a first-class exact registry scope with one deploy owner and
public key. The runtime adapter refuses trusted admission for an unregistered
environment and creates a Company-steward registry Unknown instead; it never admits
an observation carrying only a free-form owner string.

The HTTP API exposes `POST /questions`, `GET /questions/{id}`, and
`POST /answers`. The question writer supplies the decision, evidence examined,
remaining alternatives, distortion if wrong, and one precise question. An answer is
accepted only from the resolved in-scope authority and becomes a Company observation
and fact/Unknown-closure event. The original Unknown remains in history.

The decision loop is:

```text
retrieve next evidence tier
  -> recompute marginal decision value and remaining Unknowns
  -> if sufficient, project
  -> if another tier has positive net value, retrieve it
  -> if a high-distortion Unknown is authority-resolvable, ask and wait/degrade
  -> otherwise report bounded uncertainty; never fill it from model prior
```

## 8. Set-conditional projector

The projector receives only admitted facts and explicit source fetch capabilities.
For a decision `d`, fact set `S`, and candidate `a`, it computes an inspectable
approximation:

```text
marginal(a | S, d) =
    newly_covered_distortion(d, a, S)
  + authority_and_validity_gain(a)
  + complementarity_gain(a, S)
  + uncertainty_reduction(a, d, S)
  - redundancy(a, S)
  - retrieval_and_residency_cost(a)
  - stale_or_conflict_risk(a)
```

Distortion is tied to a named dependent decision/trigger and severity; it is not a
generic node weight. Redundancy uses explicit edges, shared provenance, and semantic
similarity. Complementarity permits a test plus rationale to be jointly useful. A
deterministic greedy selector recalculates marginal value after each addition,
honors hard byte/item/cost ceilings, and stops on sufficiency or nonpositive net
gain. The trace records the terms, not just a score.

Evidence tiers are facts/Unknowns, summary, exact code span, history/ADR, test/runtime
evidence, authority answer, broad search. Query logs record retrievals, returned and
selected IDs, working set, edit-time residency, declared use, outcome, and cost. The
logged demand can later specify a compiler; this implementation does not summarize
the repository in advance.

## 9. Host lifecycle and permission contract

The internal executable `kinbase hooks dispatch <host> <event>` accepts Codex and Claude native hook
envelopes and emits the host's required response. Host setup commands perform a dry
run, print the exact files/commands and permissions, and require the host/user's own
approval path; no `--yes`, silent config write, or permission bypass is provided.

- At `SessionStart`, resolve Git root and certified repository ID; connect to the
  configured Company endpoint; verify/cache Company state; `fsck`/load `.kin/`;
  start a private session run; emit bounded non-instruction context plus Unknowns.
- At prompt/observation events, enqueue the current message/tool evidence to the
  private run and perform classification outside the critical host response path.
- Before a dependent edit/tool event, project and record the exact resident fact IDs.
- At `PreCompact` and `SessionEnd`/`Stop`, checkpoint observations, display pending
  destination-specific proposals/questions, persist Personal facts, and materialize
  only independently approved Company/Codebase events.

Repository discovery resolves Git's common directory: linked worktrees share the
certified repository UUID while their checkout revision remains distinct. A submodule
or nested repository is an independent repository and needs its own certificate;
superproject facts do not automatically scope into it. `doctor` reports each boundary,
and an uncertified nested root projects no event bodies.

Codex and Claude adapters normalize to the same `HostEvent` and call the same Core.
Their emitted payload is a length-prefixed canonical JSON tool-result envelope whose
fact bodies are base64 encoded and decoded only into a quoted evidence field by the
host adapter. It has no command/tool/policy/system fields; delimiter text inside
evidence cannot escape its length. In-band framing is mitigation, not a security
boundary, so acceptance also measures that signed insider prompt-injection facts do
not alter the allowed action/tool trace. The wrapper labels every decoded body
`UNTRUSTED_EVIDENCE_NOT_INSTRUCTIONS`; Kinbase facts cannot carry host permission,
tool-call, policy, system, destination, or approval capabilities, and every actual
tool/edit still traverses the host's native permission policy. No fact is executable
by Kinbase itself. A changed action trace in the frozen malicious-fact probe is a
product failure rather than proof that the framing boundary worked. Actual host integration is tested in
temporary homes by invoking installed hook commands and config, not by passing
`host="codex"` to a unit function. The evidence packet pins exact host versions and
native envelope samples; `doctor` rejects unsupported ranges.

SessionStart has a two-second p95 proof budget. It uses a previously verified cache
and launches asynchronous Company refresh with a 250-millisecond connection budget;
a blackholed endpoint cannot hold the
host open. Fail-closed means affected facts are withheld with a loud degraded/Unknown
status, never that an ordinary editor session is prevented from starting.
Warm, cold, cache-invalid, and full-fsck-required starts all return the hook response
within that two-second p95: warm may project verified cache; the other three return
zero affected trusted facts plus a typed degraded state and start background
verification. At the 10,000-event/128-MiB ceiling, full `fsck` must finish within 120
seconds or P-9 fails. No fact becomes trusted merely because asynchronous work is
still running.

## 10. Brownfield proof harness

`kinbase experiment` consumes a preregistered manifest. Each benchmark task binds:
repository URL/path, commit, issue text, allowed tools, budget, source corpus,
load-bearing facts, dependent-edit detectors, hidden test command, architecture
rubric, judging-only accepted patch/decision evidence, pre-change authoritative fact
set, least-privilege evaluation principal, exact authority scopes and denial labels,
screening and measurement seed schedules, and frozen authority replies. Administrative
or broad service-reader identities cannot run a measurement task. The
schema-blind Oracle Curator receives the date-bounded repository-history census and
judging-only accepted outcomes but no Kinbase design/schema or candidate output. It
freezes the eligible census, seeded draw, neutral pre-change `oracle-spec`, authority
replies, source citations, and load-bearing labels before Coder outputs are visible.
Tester freezes hidden acceptance artifacts independently.

Eligibility requires two independently owned, nonredundant pre-change sources whose
individual removal flips the counterfactual judge, and excludes any task whose complete
fact-only oracle/solution is specified by one artifact. The public sampler also binds
an authorization-restricted stratum: 20–40% Company-fact denial by count and bytes
under the task principal, with initially denied load-bearing guidance resolvable only
through the frozen scoped-authority path. Denied prose never enters evidence packets.

After V-1 through V-9 pass and the adapter/reducer digest freezes, but before that
curation, a separate schema-blind Corpus Builder receives only the full
candidate-parent revision list, frozen native source adapters/reducer, and evidence
available at each revision. It deterministically constructs and seals the Company/
Codebase snapshot for every candidate parent before seeing issues, accepted patches,
hidden tests, eligibility/load-bearing labels, seeds, arms, or scores. The static-prior
document freezes in the same pre-task step. The Oracle Curator later selects only from
that already sealed snapshot map; no task-aware corpus edit or regeneration exists.
If the reducer changes while the Builder remains task-blind, every snapshot in the
complete census map is discarded and rebuilt. Once any Builder has learned task/
oracle material, a reducer change kills that run and requires a fresh blind Builder.

The harness creates fresh worktrees and agent homes for every arm, constructs only
the arm-specific context, launches the same coding model command, records full tool
and token telemetry, freezes the candidate tree, and hands it to the Validator. It
never lets the coding agent self-score. Opaque candidate IDs hide arms until two
score artifacts are committed by digest. All arms receive the same frozen authority
tool schema, latency envelope, and per-call accounting; the arm manifest selects
whether the response view contains frozen answers or the typed empty result.
Use/non-use is a reported stratum. Context controls are token matched within five
percent, including `oracle-spec`.
The manifest also freezes the exact threat-model and attack-catalog digests,
Detector Reviewer-selected auxiliary corpus, and the encrypted canary-registry
ciphertext/schema/count digests; no raw registry value enters the harness manifest.

The `authority-only` arm has baseline inputs plus required use of the frozen
one-or-two-question authority service and no maintained corpus/projector. It controls
for senior consultation itself. The full system shares the two-call ceiling; V-10
never exposes a live human to a task or result. Arms are randomized and interleaved
inside task/seed blocks, and response-level provider fingerprints are bound to each
pairing. Every measurement-task launch/score first enters the append-only run census;
only synthetic and excluded-pilot tasks may be used for harness development.

The `null-system` arm traverses the same full-system host adapter, native hooks,
observation protocol, tool schema, permission policy, timing envelope, and telemetry,
but its content-addressed corpus/index is empty, its selector yields no facts, and its
authority service returns the typed empty response. It isolates the causal value of
knowledge from the mere presence of Kinbase-shaped machinery. `static-prior` injects
one task-independent repository-agnostic conventions document and has no store,
retrieval, maintenance, temporal reducer, or authority loop. `codebase-only` and
`company-only` run full machinery while structurally withholding the opposite shared
store and, for `codebase-only`, Company references and authority replies. They expose
whether both coding stores contribute rather than merely exist. Personal is never a
coding-query arm; P-1 through P-3 and P-9 test its private behavior and approved
promotion path without breaching that boundary. All eleven arms in a task/seed block
bind the same explicit `as_of` and Company authority cursor.

One content-addressed execution manifest binds every field that can change an arm:
coding-model artifact or immutable provider snapshot, decoding settings, system
prompt, tool schema/permissions, policy bundle, host adapter, retriever, index and
corpus snapshot, task/repository inputs, worktree revision, `as_of`, authority cursor/
service/replies, budgets, and seed. It separately binds each automated grader's model
fingerprint, decoding settings, system/rubric prompt, parser, calibration set, and
blinded-packet schema. A field that differs without an explicit arm assignment, or a
runtime value that differs from the manifest, invalidates the run. After freeze, the
broker admits no operator prose or live human answer; closed launch/decision codes are
control data and are never delivered into an arm context.

Composite quality is preregistered as:

- 0.50 held-out functional behavior;
- 0.20 architecture/invariant conformance;
- 0.10 internal API reuse and absence of duplication;
- 0.10 false-completion/verification behavior;
- 0.10 efficiency and constraint residency.

No arm-specific weighting is allowed. Raw per-task metrics and excluded screening
runs remain in the report. Threshold computation is deterministic and produces
`PROVEN`, `NOT_PROVEN`, `INCONCLUSIVE_NO_HEADROOM`, or
`INCONCLUSIVE_CEILING`; it has no `demo-success` state. Infrastructure/harness
failures are reported separately from product falsifiers and never converted to a
passing product result.

## 11. Repository compatibility

`repo init` edits an existing `.gitattributes` additively and refuses contradictory
rules; it never replaces the file. Existing `.kin/config` or Kinbase event paths
with an incompatible schema block and preserve bytes. A legacy Kindex
`.kin/index.json` remains adapter-owned source input as defined above. Collaborators
without Kinbase see ordinary inert JSON event files and need no filter/driver; Git
never invokes executable merge logic for the event/manifests paths. The proof reports
repository-size growth and enforces the 10,000-event/128-MiB ceiling.

Before init, the pinned Kindex seam-conformance suite enumerates every path that the
installed Kindex may read or write under `.kin/`. Kinbase compares that inventory
with its reserved paths; any actual collision produces a typed refusal and changes no
byte. Acceptance initializes against a fully populated real pinned-Kindex repository,
proves every legacy byte is preserved, and injects one deliberate path collision that
must refuse.

A deliberate sparse checkout excluding `.kin/` is a safe `MANIFEST_INCOMPLETE`
degraded state (exit 3), not a privacy/integrity accusation: trusted Codebase facts
are withheld and `doctor` gives the exact sparse-checkout remediation. Missing events
from a checkout that claims `.kin/` complete remain exit 5. Submodules and linked
worktrees follow the identity rules in §9.

## 12. Containment and deliberate omissions

All PoC services bind loopback by default and run against dedicated temporary roots.
Real Personal and Company stores are opt-in and never used in acceptance. Secrets
are file descriptors or environment names, never logged values. Files are created
with restrictive modes; symlinks and paths escaping declared roots are rejected.

The architecture omits production hosting, multi-region replication, enterprise
identity/SSO and hardware key custody, web UI, billing, and the learned compiler. It
does implement the finite key issuance/rotation/revocation and cache-apology behavior
needed to test authority. It does not omit any P-1 through P-10 behavior. A local
service, finite corpus, and bounded benchmark are scale limitations; adapters,
authority round trips, host hooks, routing, temporal maintenance, and outcome
measurement are real executions.
