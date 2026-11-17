# Testing and Operational Proof Strategy

Status: **candidate for review and exact-byte ratification**

Authority: [`product.md`](product.md), [`architecture.md`](architecture.md), and the
finite [`threat-model.md`](threat-model.md) for V-3.

## Verdict semantics

The evidence carries two component results and one composed product verdict:

- `gate_result` over V-1 through V-9 is `PASS`, `PRODUCT_FAILURE`, or
  `INVALID_HARNESS`;
- `measurement_result` over V-10 is `PROVEN`, `NOT_PROVEN`,
  `INCONCLUSIVE_NO_HEADROOM`, `INCONCLUSIVE_CEILING`, or `NOT_RUN`;
- `terminal_product_verdict` is `PROVEN`, `NOT_PROVEN`,
  `INCONCLUSIVE_NO_HEADROOM`, `INCONCLUSIVE_CEILING`, or `INVALID_RUN`.

Composition is total and ordered. A separately verified product/privacy failure
yields terminal `NOT_PROVEN` regardless of measurement state. Otherwise an integrity
failure that makes gate observations untrustworthy yields `INVALID_RUN`. With gates
`PASS`, the measurement result maps directly; `NOT_RUN` is terminal `NOT_PROVEN`
because the proof was not performed, with a diagnostic that must not imply a product
mechanism falsifier. If both
headroom and ceiling conditions hold, ceiling is reported as the instrument failure
and the headroom flag remains visible, but neither can mask a product gate failure.

| `gate_result` \ `measurement_result` | `PROVEN` | `NOT_PROVEN` | `INCONCLUSIVE_NO_HEADROOM` | `INCONCLUSIVE_CEILING` | `NOT_RUN` |
|---|---|---|---|---|---|
| `PASS` | `PROVEN` | `NOT_PROVEN` | `INCONCLUSIVE_NO_HEADROOM` | `INCONCLUSIVE_CEILING` | `NOT_PROVEN` |
| `PRODUCT_FAILURE` | `NOT_PROVEN` | `NOT_PROVEN` | `NOT_PROVEN` | `NOT_PROVEN` | `NOT_PROVEN` |
| `INVALID_HARNESS` | `INVALID_RUN` | `INVALID_RUN` | `INVALID_RUN` | `INVALID_RUN` | `INVALID_RUN` |

If a separately content-addressed product-failure observation exists alongside an
invalid detector, the product failure is retained and terminal `NOT_PROVEN` dominates;
the table's `INVALID_HARNESS` row assumes no independently valid product failure.
Document/ledger statuses (`candidate`, `ratified`, `proven`) are not run verdicts.

Implementation complete, service starts, unit green, architecture present, or
Factory milestone reached are never product verdicts. The role arrangement uses
tmux and an interactive Claude Tester, so Factory method evidence is labeled
`METHOD_POC`, never `CLEAN_QUALIFIED`.

Verdict consequences are fixed in advance. `PROVEN` authorizes only founder review
of a new production design and private soak decision; it never authorizes deployment
or shared-remote use. `NOT_PROVEN` stops Kinbase's current product/value claim and
preserves the gate vector for founder-authorized redesign. It does not reopen the
separate Type-1 rule that Personal, Company, and Codebase remain physically distinct.
Only a documented pre-unblinding harness defect permits one founder-authorized
superseding run over the same pool and preregistered reserve seeds; the failed run
remains. `INCONCLUSIVE_NO_HEADROOM` retires this pool and requires a new founder-
approved preregistration before any new pool. `INCONCLUSIVE_CEILING` requires a new
task/oracle preregistration. None permits quiet task swapping, threshold tuning, or
selective reruns. Company stewards and Agy have no experiment authority.

Authority precedence is `source-request > Product > Architecture > Threat Model >
Verification > generated manifest`; a downstream artifact may implement but not
contradict its upstream. The experiment manifest is bound to every exact authority
artifact digest and may contain only values permitted or deterministically derived
by them. Any digest/value disagreement blocks dispatch; no role adjudicates by
preference inside the run. A semantic change requires new phase ratification.

Ratified artifacts are immutable for one run. The founder may propose amended intent
and a distinct Validator may co-ratify exact superseding Product, Architecture,
Threat Model, or Verification bytes; reviewers remain advisory. An amendment always starts a new
Factory run/generation and invalidates any unstarted manifest derived from the old
digests. A run already in flight either completes under its retained old bytes or is
explicitly aborted and retained; it never absorbs the amendment. A new measurement
run requires a new preregistration and eligible-pool draw except the single
pre-unblinding harness-defect replay already bound to its original pool/reserve seeds.
Unimplementable or unaffordable obligations cannot be silently edited mid-run.

## Role separation

- **Validator (Codex):** owns these exact phase artifacts, run setup, immutable
  candidate combination, execution of Tester-authored suites, mutation testing,
  benchmark scoring, adversarial review, and verdict. It authors no product code or
  acceptance tests.
- **Resident Orchestrator (Agy):** receives the verbatim goal and every bounded
  activity delta from ignition through verdict; maintains ultimate goal and
  outstanding work; evaluates direction, implications, side effects, adherence,
  requirement pressure, decomposition, and model routing. It can block/no-op only.
- **Coder (GLM-5.3 via Ollama-launched Codex):** reads ratified product,
  architecture, verification strategy, and its build lane; authors implementation
  and implementation docs only; cannot read Tester work or judge success.
- **Tester (Claude):** reads ratified product, architecture, verification strategy,
  and a clean test lane; authors acceptance/benchmark tests and fixtures only;
  cannot read implementation or Coder work or issue a verdict.
- **Oracle Curator (fresh isolated agent):** sees the frozen repository-history
  population and judging-only post-change ground truth, but no Kinbase schema,
  retrieval design, candidates, arms, or scores; authors the eligible-task census,
  neutral pre-change fact-only oracle, frozen authority replies, and load-bearing
  labels. It does not write tests or judge Kinbase.
- **Corpus Builder (fresh isolated agent):** sees only the full candidate-parent
  revision list, frozen adapters/reducer, and evidence available at each revision;
  seals every historical Company/Codebase snapshot and the generic static prior before
  seeing issues, accepted patches, hidden tests, eligibility labels, seeds, arms, or
  scores.
- **Detector Reviewer (fresh isolated agent):** sees ratified specs and the
  Tester-authored detector package but no Coder work; selects/freezes the licensed
  auxiliary corpus and must clear coverage and mutation sensitivity before combine.
- **Run Integrity Auditor (fresh isolated agent):** sees the manifest, launch ledger,
  environment attestations, and integrity telemetry but no candidate contents,
  scores, arm mapping, or aggregates; seals the manifest-derived validity decision
  before unblinding.
- **Rubric Gold Annotators (two implementation-blind human domain experts):** label
  only the excluded calibration set before measurement freeze; they see no arm labels,
  measurement candidates, or Kinbase implementation and never interact with a V-10
  run after freeze.
- **Reconstructor and two automated scorers:** receive only their blinded packets,
  run under separately frozen model/prompt/parser identities, seal outputs
  independently, and have no product, test-authoring, or verdict authority.

Coder and Tester use disjoint worktrees and prompts. The Validator audits filesystem
access/logs for cross-lane reads. Because this is not kernel-enforced isolation, that
audit limits the method claim even when clean.

## Instrument validity

Every V-1 through V-9 gate freezes its threshold, positive control, negative control,
and detector mutation in the preregistered acceptance catalog before implementation
is combined. A detector that cannot catch its positive control yields
`INVALID_HARNESS`, never PASS. Mutations target detectors as well as product code—for
example, disable archive scanning, SQLite blob scanning, normalization decoding, or
manifest comparison and require the planted defect to escape the detector's own
self-test while causing the gate to reject the instrument.

After the implementation-blind Tester freezes tests, a second implementation-blind
Detector Reviewer receives only ratified specs, tests/fixtures, detector design, and
the eligible licensed-public auxiliary-corpus pool.
It must disposition coverage, positive/negative controls, mutation sensitivity, and
privacy of the oracle before the Coder snapshot is combined. The Validator may
execute/review but does not author missing tests. Unresolved detector findings block.

The two human Rubric Gold Annotators independently label the excluded-pilot
calibration set, reach quadratic-weighted kappa at least 0.80, and seal adjudicated
gold before any automated grader or measurement candidate exists. Each automated
grader comes from a different model family and provider, reaches weighted kappa at
least 0.80 against that human gold, and achieves at least 0.90 accuracy on rubric pass-
boundary classification. Each grader's immutable model/provider fingerprint,
decoding settings, system/rubric prompt, parser, calibration-set digest, and blinded-
packet schema freeze in the manifest. Main-run inter-grader reliability is computed
while arm labels remain encrypted; below 0.80 is `INVALID_HARNESS` regardless of which
arm benefited.
A qualitative component straddling a pass boundary uses the lower sealed score; no
post-unblinding consensus session can rescue it.
They also seal arm guesses after scoring but before identity decryption. Guess
accuracy greater than 1/11 + 0.15 with exact-binomial p<0.05 is a preregistered
blinding failure and yields `INVALID_HARNESS`; high kappa cannot override it.
They separately guess the binary fact-bearing/non-fact-bearing family. Balanced accuracy above
0.65 with exact-binomial p<0.05 is also a blinding failure. Both tests, confidence,
and confusion matrices freeze before arm decryption; a good semantic score is not
itself labeled proof of which arm produced it.

## Acceptance map

### V-1 — real heterogeneous corpus (`P-1`, Critical)

- Run all ten adapters against native-format sources in isolated fixtures; at least
  seven participate in the recorded end-to-end build.
- Both transcript adapters parse exports produced by their actual host layouts.
- Build manifest binds observation IDs, source revisions, digests, checkpoints, and
  fact derivations.
- Re-run unchanged ingestion: no duplicate observations/facts and byte-identical
  current views.
- Change, delete, reject/revert, and re-run representative sources: history remains,
  current disposition changes explicitly.
- Mutation: make one adapter return a source count without observations; V-1 fails.

The adapter lifecycle matrix is frozen rather than inferred from one demonstration:

| adapter | required lifecycle cells |
|---|---|
| `codex_jsonl` | create, append, edited/duplicate event, end, raw expiry, missing source, restart |
| `claude_jsonl` | create, append, edited/duplicate event, stop, raw expiry, missing source, restart |
| `repo_code` | create, modify, delete, rename, branch divergence, rebase/force-push, shallow/sparse view |
| `repo_tests` | create, pass-to-fail, fail-to-pass, superseded result, delete, out-of-order result |
| `git_history` | branch, merge, reject, revert, delete ref, rebase/force-push, shallow fetch, clock skew |
| `docs_adr` | proposed, accepted, rejected, superseded, retracted/deleted, conflicting heads |
| `github_export` | open, edit, approve/request-change, merge/close/reopen, missing/withdrawn object |
| `runtime_evidence` | create, changed value, owner change, expiry, late arrival, bounded clock skew |
| `kindex` | duplicate import, supersede, retract, revoke, expire, conflict, deterministic rebuild |
| `authority_answer` | answer, explicit parent supersession, unparented conflict, revoke, late arrival |

Every declared cell has an expected observation/current-fact/Unknown state and at
least one negative mutation. A semantically inapplicable cell needs a ratified reason;
it cannot disappear from the report. Core transition tests also retire one support
from a multiply supported derived fact and then its final support: the first
recomputes provenance while retaining the fact, the second withdraws the fact and
reopens every dependent decision. Out-of-order delivery and positive/negative clock
skew run across Personal, Company, and Codebase cursors.
An approved model misreading also exercises the approver-signed `misextraction`
notice: it asserts only evidence/byte mismatch, withholds the fact, and reopens a
subject-matter-authority Unknown. A distinct steward/maintainer `never_true` event
performs semantic withdrawal; mutation that lets the approver mint it must fail.

### V-2 — classification and fan-out (`P-2`, Critical)

- Tester freezes at least 120 held-out natural messages with gold atom boundaries
  and destination sets; at least 40 are mixed and at least 100 contain varied
  private/safety canaries or transformations.
- The live semantic classifier executes at least five preregistered runs with pinned
  model/version/settings. Apply utility thresholds to the lower confidence bound and
  freeze replay from run 1, never the best run. Deterministic replay verifies
  downstream behavior without relabeling outputs.
- Before V-10, run a separate excluded 60-message calibration corpus through the same
  five-run configuration. Its 95% lower bound must reach macro-F1 0.90 and each shared
  precision 0.95; failure is a P-2 product failure and stops expensive measurement,
  not an excuse to change the held-out corpus. Macro-F1 uses a message-stratified
  bootstrap and shared precision a Wilson interval over pooled frozen predictions.
- Compute exact-match atomization, per-label precision/recall/F1, macro-F1, shared
  precision, private-to-shared detection, and calibration/abstention.
- Two independent annotators label the routing/atomization gold set before model
  execution. Cohen's kappa must be at least 0.80 per destination; disagreements are
  adjudicated and the adjudication digest freezes before classifier runs. Below that,
  V-2 is `INVALID_HARNESS`, not a classifier failure.
- One mixed message must yield independent Personal and Codebase candidates; another
  yields Personal, Company, and Codebase candidates with distinct minimized bytes.
- Force Company failure after Codebase commit: receipts expose partial success and
  an apology Unknown names the approver as responsible and destination maintainer as
  closing authority, withholds the orphaned Codebase fact, and reaches an explicit
  reconcile/abandon state; retry returns the original receipt without duplication.
- Let the closing deadline expire without a response: the destination service emits
  one signed `orphan_abandoned`, names the unresponsive authority, keeps the fact
  withdrawn, and leaves no pending orphan forever.
- Invoke the actual host/CLI path and assert the approver sees the one-item apology,
  can dispatch reconcile or abandon, and the closing authority receives the same
  signed Unknown with deadline; a permanently unwritable apology yields local
  quarantine and exit-5 doctor state without Company dependency.
- Kill each destination between nonce reservation, event append/rename, manifest,
  receipt, and apology transitions, then retry concurrently. Company returns the
  one transaction's receipt; Codebase recovery completes the one content-addressed
  event/journal without duplicate or recursive apologies.
- Mutations: whole-message single label; shared-by-default under low confidence;
  common fan-out transaction; remove nonce uniqueness/recovery. Each must fail.

### V-3 — privacy and authority boundary (`P-3`, Critical, zero tolerance)

The gate executes [`threat-model.md`](threat-model.md) exactly. Its public claim is
limited to “zero observed unauthorized durable disclosure outside the authorized
processor boundary under Acceptance Threat Model `kinbase-atm/1`, digest
`<sha256>`, across execution census `<digest>`.” An unqualified “zero leakage” claim
is a reporting failure.

- Run seeded raw messages through classification, approval, rejection, defer,
  expiry, fan-out, host projection, logs, receipts, caches, service, `.kin/`, restart,
  and cleanup.
- Recursively scan every persistent/shared byte and SQLite text/blob value for exact,
  encoded, normalized, partial, and deterministic-correlation canaries.
- Give an adversarial reconstructor all shared surfaces plus the Detector Reviewer-
  selected, preregistered auxiliary corpus; record exact/deterministic recovery
  separately from semantic guesses.
- Attempt approval replay, destination retarget, payload substitution, preview race,
  symlink/path traversal, malicious clone trust root, unauthorized signer, signed
  prompt injection, oversized event, and stale revocation cache.
- Verify the shared writer process/call graph has no Personal-store capability.
- Assert deterministic scanners normalize NFC/NFD plus hex, base64, percent, and JSON
  escape forms and fail closed on scanner error. Report semantic paraphrase leakage
  separately; do not call the seeded test a universal privacy bound.
- Bind the exact Codex, Claude, and classifier processor/account/retention
  authorizations and capture outbound request digests. Plant a forbidden historical-
  Personal canary at each egress; a send to an unnamed processor, a separate
  unapproved classifier provider, or a scope-ineligible request must fail.
- Seed one observation with a hard-blocking canary whose model output contains only
  a paraphrase and no matching string. The entire observation must remain private by
  taint policy; the scanner is defense in depth, not the claimed semantic boundary.
- Prove the approver-visible inline bytes are the exact buffer rehashed inside the
  destination immediately before commit; mutation to pathname re-read must fail.
- Revoke a signer at a later Company cursor and assert decisions/facts admitted under
  an older authority snapshot are found and reopened as owned Unknowns.
- Run the coding agent under its acceptance sandbox with an injected attempt to read
  the Personal root, then repeat as an arbitrary same-UID process to prove the stated
  threat-model distinction and outer promotion gate.
- Plant known canaries in every scanned surface and encoding during a positive-
  control run, including packed Git objects and SQLite blobs, and require each exact
  detector/location receipt before trusting a clean run. Then remove those planted
  controls and run the actual no-leakage assertion.
- Qualify stochastic detection with at least 300 independently randomized planted
  positive variants, stratified with at least ten per declared surface/encoding
  family, and at least 500 randomized true-negative decoys. Every deterministic
  catalog control must be detected. The Wilson 95% lower bound on randomized
  sensitivity must be at least 0.98 and the Wilson 95% upper bound on false-positive
  rate at most 0.01. Publish successes, misses, denominators, confidence bounds, and
  the resulting false-negative bound; do not expose registry values to satisfy it.
- Publish the complete vector/surface/control count and a confidence interval for
  sampled or stochastic detectors. The result is zero observations in the frozen
  execution census, never an inferred universal zero rate.
- Keep all raw V-2/V-3 canaries, salts, keys, raw instantiated fixtures, and the
  encrypted canary registry in the Tester-custodied mode-0700 vault defined by the
  threat model. Bind only ciphertext/schema/count digests into the manifest.
- Tester and reconstructor seal independent findings. The Validator adjudicates only
  by the frozen mechanical recovery rule; an underdetermined dispute is
  `INVALID_HARNESS`, never PASS.
- Mutations: add transcript digest to receipt; mount Personal in coding query; trust
  `.kin/trust.json`; clear taint after de-identification; re-read candidate path after
  approval; accept an event from a worktree-only key; reuse a signature across
  message types; verify one parse and apply another; wildcard an authority scope;
  interpolate SQL; expose the Personal path in shared argv/config; remove scoped-token
  enforcement; remove nonce uniqueness; race concurrent approvals. Each must fail.
- A same-UID attacker steals only the base facts bearer token and attempts directory
  reads, bulk fact reads without the client-key signature, answer admission, scope
  escalation, and post-rotation replay; all refuse or trip the frozen volume/anomaly
  ceiling without exposing out-of-scope prose.
- Exercise facts tokens with missing, empty, exact, adjacent, wildcard-like, and
  prefix-like authority-scope sets. Only exact canonical membership reads a fact;
  administrative issuance has no body-read capability. Mutating empty to read-all
  must fail.
- Rewrite the launcher config to a relative/PATH classifier and then to an attacker
  binary under the expected name. Absolute-path, owner/directory-mode, executable-
  digest, scrubbed-environment, and processor-scope checks must refuse before any
  Personal byte reaches the child.
- Swap the classifier pathname after descriptor hashing and before execution; only the
  already verified descriptor may execute. Pass an open Personal directory descriptor
  while pathname denial still succeeds; descriptor enumeration/attestation must fail
  startup before shared work.
- Render CR/ANSI/bidi/noncharacter payloads through approval preview and require parse-
  time rejection or the frozen bijective escaped form. Mutation to raw terminal output
  must fail. Run the malicious signed-evidence action-trace probe at the complete
  32-fact/128-KiB projection ceiling, not one convenient fact.
- Dump argv, environment, file-descriptor metadata, serialized config, errors, and
  child inputs for every shared process; the Personal-root canary must be absent.
- Delete both Company cache and local cursor high-water state, then replay an old
  valid signed snapshot during refresh. A fresh client nonce and Company's signed
  current-cursor response prevent trust; offline operation stays degraded. Cache root
  mode must be 0700.
- Configure nonce retention equal to or shorter than candidate lifetime plus clock
  skew. Service startup must refuse with a typed invariant error.
- Any canary or deterministic lineage on a shared surface immediately yields
  `NOT_PROVEN`; no later rerun erases the recorded failure.

### V-4 — corpus maintenance and distributed conflicts (`P-4`, Critical)

- Repeated incremental cycle: create, duplicate, edit, supersede, retract, revoke,
  expire, branch, merge, conflict, resolve, rebuild, restart.
- Verify immutable observations/events remain addressable; derived current view is
  deterministic; private ephemeral data expires under the private clock; shared
  history is not destroyed by cache cleanup.
- Merge two clones adding disjoint events and incompatible heads. Both events survive;
  incompatible facts remain conflict/Unknown until an authorized parent-bound event.
- Delete/modify an event, delete its local manifest, use a shallow clone, use a sparse
  checkout, rebase, force-push, and squash. Compare against the dated maintainer-
  published manifest observation: local strict superset within freshness is normal
  lag, missing expected heads is repository-owned `INCOMPLETE`, and expired expected
  state is a Company publication Unknown rather than an integrity accusation.
- Exercise `core.ignorecase=true`, `core.autocrlf=true`, macOS normalization, an
  uppercase digest alias, and missing/ineffective Git attributes. Only computed
  lowercase ASCII digest paths admit; canonical bytes remain identical.
- Rebuild with fixed `(events, reducer version, as_of, authority cursor)` twice and
  vary each input once. Omitting/reading ambient `as_of` must fail determinism.
- Exercise a corpus at 10× the admission ceiling. Intake refuses new writes while
  bounded incremental `fsck`/diagnosis remains available; SessionStart latency and
  full-rebuild time are recorded rather than allowed to hang.
- Revoke a key supporting a dense derivation graph at the 10,000-event ceiling.
  Until local transitive recomputation completes, every not-yet-rechecked fact is
  `REVOCATION_CASCADE_INCOMPLETE` and withheld; completion must be within 120 seconds
  or the typed fail-closed limit state persists with remaining count.
- Replay a pre-revocation event after observing the revocation cursor: a path-exists
  fast path may return a historical receipt only to the original scoped client and
  must not re-admit/project it. Mutation that checks content path before authority/
  revocation admission fails.
- Admit concurrently from two linked worktrees and prove one exclusive lock in Git's
  common directory serializes one manifest lineage. A worktree-local lock mutation
  must fail.
- Initialize against a fully populated real pinned-Kindex `.kin/` inventory and prove
  byte preservation; inject a collision between an enumerated Kindex path and a
  Kinbase reserved path and require typed no-write refusal.
- Mutation: choose the greatest timestamp/latest file on conflict, omit `as_of`, or
  treat a stale Company head observation as Git authority; V-4 fails.

### V-5 — temporal discernment (`P-5`, Critical)

Table-driven and narrative cases include:

| Case | Expected decision |
|---|---|
| newer rejected PR vs current accepted ADR | ADR remains current; rejection is evidence |
| ten copied recent comments vs one independent authoritative decision | copied chorus adds little; no vote-count winner |
| old rule explicitly superseded by same scoped authority | new rule current; dependents re-evaluated |
| incident workaround past its validity | excluded; Unknown if decision still depends on it |
| deployed config 568 vs code default 90 | operational diagnosis uses live 568; architecture authority unchanged |
| repo code contradicts current Company architecture | conflict plus Chief Architect Unknown, not silent local override |
| unmerged branch plants a new ADR | branch evidence stays untrusted; merged ADR remains current |
| registered runtime observation passes freshness window | operational fact withdraws into its exact environment-owner Unknown |
| runtime observation names an unregistered environment | observation is untrusted; Company-steward registry Unknown |

Every case freezes `as_of` and authority cursor and asserts the reducer trace and
counterfactual. Mutations newest-wins,
highest-authority-always-wins, and repetition-as-independence must each fail.

### V-6 — real authority round trip (`P-6`, Critical)

- Start `kinbased` and register a named Chief Architect with a test signing key and
  a live channel endpoint/process separate from the caller.
- Present an architectural ambiguity whose decision has high distortion and whose
  corpus tiers are exhausted.
- Assert a targeted question is delivered to that authority, dependent trusted
  guidance is withheld, and another role's signature is rejected.
- Return a signed answer from the authority process; ingest it; close the exact
  Unknown; rebuild; assert the projected decision changes and cites the answer.
- Repeat with authority unavailable and cache expired: verify the declared degraded
  policy rather than guessed guidance.
- Mutation: locally synthesize an answer from model prior; V-6 fails.

The recorded demonstration should use the human-interactive channel when the founder
is available. The independent acceptance test uses the signed process channel so it
is repeatable.

V-6 is the live-human capability proof. Benchmark runs use a frozen pre-change
answer service exposed with identical cost and access to every arm; answers and
semantic matching are frozen before candidate execution. Results are stratified by
whether an arm asked. No live authority sees a V-10 task, candidate, hidden test, or
arm result. A response contains fact and rationale only—never code or a solution—and
the service refuses more than two calls per task. The `authority-only` arm must make
the preregistered one or two calls without receiving any maintained corpus, so direct
senior consultation has its own causal control.
These replies are experimental instruments citing pre-change authority records,
never newly admitted Company facts and never written to Company or Codebase. A
pre-unblinding factual error is an oracle/harness defect; a post-unblinding complaint
cannot retroactively relabel a product result.

### V-7 — set-conditional projection and VOI stop (`P-7`, Critical)

- Construct a candidate set with high-scoring paraphrases, one distinct
  high-distortion compatibility invariant, one complementary test/rationale pair,
  one stale fact, and one high-distortion Unknown.
- Assert selection changes when working-set IDs change; duplicates show diminishing
  returns; the invariant is selected; complementarity is visible; stale fact is not
  trusted; and the retrieval trace either reaches sufficiency or asks authority.
- Escalate evidence tiers and assert the loop stops on net marginal value, not a
  filled token window.
- Mutation: independent scalar rank/top-k; V-7 fails because duplicates crowd out the
  invariant.

This fixture proves selector mechanics only. Causal evidence for set selection comes
from `topk-maintained` versus `full-system` in V-10, with natural-corpus redundancy
cluster sizes and source dependence reported rather than manufactured.

### V-8 — Company references from `.kin/` (`P-8`, Critical)

- From a fresh clone, resolve a valid Company architecture reference and project its
  live statement without copying it into Git.
- Exercise specialization, contradiction, exception request, and steward-approved
  exception, including a repository-UUID-scoped criticality relaxation. A maintainer
  may request but cannot sign the relaxation; expiry restores the Company class.
- Supersede/revoke the Company fact and invalidate client cache; the repo reference
  becomes an owned Unknown until updated.
- Exercise Company advisory + repository safety-critical and the reverse. The
  stricter class controls freshness; only the named maintainer may raise local
  dependence, and missing local owner becomes a repository Unknown.
- Present an unknown `digest_alg_version`; assert a client-upgrade error rather than
  a false accusation that the steward changed content. For a known mismatch, query
  Company's digest for the reference's exact historical fact version plus current
  head: differing historical digest creates a steward-owned reference Unknown;
  matching historical digest creates a client-canonicalization Unknown; missing
  retained version creates a Company publication-retention Unknown; unavailable
  Company withholds without accusation.
- Fresh clone with no certificate or Company access yields zero trusted facts and one
  actionable certificate Unknown. An attacker fork with parent events and a
  self-issued certificate does the same while reporting foreign event count.
- Change URL/protocol/ownership hint without changing the certified UUID; identity
  remains stable. Resolve one hint to a different UUID after pinning and require a
  steward-owned identity Unknown. Two certificates for one UUID fail `fsck`.
- Have a maintainer run the real signed `repo publish-manifest` path. Verify Company
  monotonic-count admission, normal strict-superset lag, missing-head failure, stale
  publication Unknown, unreachable-Company cache behavior, and signed rewrite/
  rollback exception. On `fresh_until`, Company itself emits one observation-expired
  event, retires the old observation to historical-only, and opens its steward-owned
  publication Unknown without waiting for maintainer/clone activity.
- Exhaust the revocation-fresh/stale × fact-fresh/stale × safety/advisory truth table;
  stale revocation dominates safety projection.
- Scan Git objects, not only the worktree, for copied Company/private canaries.
- In uncertified Codebase-only mode, SessionStart and every host payload contain
  counts/status only and zero unverified event bodies.
- Mutation: let Codebase authorize `exception_to`; V-8 fails.

### V-9 — real host lifecycle (`P-9`, Critical)

- Use isolated temporary `HOME`, config, and repository roots. Run the actual setup
  and hook executables for Codex and Claude.
- Verify setup dry-run exposes permission needs and changes nothing; explicit
  approval installs only expected files. Missing/unapproved capabilities yield one
  actionable warning and `doctor` evidence.
- Invoke native SessionStart, prompt/observation, pre-edit, PreCompact, and Stop/end
  payloads. Assert repo discovery, Company+Codebase prime, absence of Personal,
  ongoing capture, pending questions, approved `.kin/` write, and private cleanup.
- For matched conversations, canonical facts/projections/receipts match across hosts.
- Inspect actual host config and executable invocation records; a mocked host branch
  is not accepted evidence.
- Pin and report exact Codex/Claude versions and native envelope fixtures. Blackhole
  the Company endpoint; SessionStart remains under the two-second p95 budget while
  affected facts are withheld and loudly degraded.
- Measure warm, cold, invalid-cache, and full-fsck-required SessionStart separately;
  run at least 200 invocations per host/state on the recorded proof machine, report
  CPU/RAM/filesystem, and require every state's p95 under two seconds. Company connect
  budget is 250 ms, cold/degraded projection is empty, and background full fsck at
  the 10,000-event ceiling finishes within 120 seconds. Across the 20-session private
  soak, at least 90% of starts must take the warm verified path and deliver nonempty
  trusted context when eligible facts exist; after the first cold start, at most 5%
  of ordinary append/branch-switch/restart/linked-worktree starts may require a full
  fsck. Latency cannot pass by always degrading or repeatedly forcing a two-minute
  knowledge blackout.
- Launch inside a normal clone, linked worktree, submodule, and nested repository:
  common-dir worktrees share UUID, while nested/submodule roots require independent
  certificates and never inherit superproject fact bodies.
- Run the four-total-per-hour/three-consecutive approval flood across destinations and
  concurrent Codex/Claude sessions sharing one host instance. Destinations do not each
  receive four slots; hourly state cannot reset, consecutive reset requires a new task
  event and has one-per-hour cooldown, and the signed host budget-shard plus unknown-
  global-total warning is visible in `doctor`.
- Force Codex and Claude sessions on one host instance to interleave exactly between
  slot check and render. Moving the
  reservation increment after render must produce more than four prompts and make the
  mutation fail; crash after reservation remains counted until expiry and delivery-
  loss rate is explicit.
- Race two byte-changed reissues with rejection and reservation. Reissue eligibility,
  unique digest lock, total slot reservation, and consecutive count must commit in one
  `BEGIN IMMEDIATE`; moving any check outside the transaction must produce a failing
  duplicate/starvation mutation. Untrusted branch/worktree churn cannot trigger
  byte-change reissue.
- Conduct the 20-item blinded operator exercise; record accuracy and decision time.
- Run the frozen 100-observation/20-durable-fact maintenance workload through five
  simulated sliding-hour windows. At least 18 durable facts receive a decision slot,
  at least 17 correct facts admit, no window exceeds four total prompts, and low-
  authority churn cannot outrank high-distortion eligible facts.
- Mutation: disable mid-session capture while keeping SessionStart green; V-9 fails.

### V-10 — brownfield causal outcome (`P-10`, terminal product proof)

#### Task freeze

- Run at least twelve explicitly excluded pilot tasks across at least three
  repositories with at least three seeds each to estimate task-by-arm covariance,
  within-task variance, model nondeterminism, context use, and cost. The task—not a
  task-seed—is the paired analysis unit; seeds are averaged within task. Freeze at
  least eight eligible tasks, three measurement seeds, and a larger N selected by
  the co-primary power rule below. If the population or founder-approved budget
  cannot supply that N, no measurement arm dispatches; never lower the floor.
- Before a pilot outcome exists, bind the founder-ratified aggregate budget and forbid
  increases for this run. Keep pilot arm effects sealed; expose only fully loaded cost
  and conservative covariance/variance to the frozen power program. Insufficient
  population, power, or prepaid/escrowed budget terminates `NOT_PROVEN` with
  `UNFUNDED_OR_UNDERPOWERED`, no partial endpoint claims.
- Require the excluded-pilot `oracle-spec` lower 95% bound to reach 0.90 before
  measurement freeze. A miss is `INCONCLUSIVE_CEILING`; retain the pilots and require
  a new ratified comparator/run rather than tightening eligibility or swapping tasks.
- Only after V-1 through V-9 pass and the adapter/reducer digest freezes, but before
  the Oracle Curator receives issues, accepted changes, hidden tests, or
  eligibility/load-bearing labels, the isolated Corpus Builder runs the frozen
  adapters/reducer for every candidate parent revision in the complete date-bounded
  census and seals a content-addressed Company/Codebase snapshot map. It also freezes
  the one repository-agnostic static-prior document (at most 2 KiB). Neither may be
  selected, pruned, authored, or regenerated after task knowledge exists. The Curator
  and public seeded sampler may only reference those sealed snapshots. A pre-task
  reducer repair discards and rebuilds every census-parent snapshot; a repair after
  Builder task exposure invalidates the run and requires a fresh blind Builder, never
  a drawn-task-only reseal.

The causal claim is an intersection-union claim: it passes only when every
preregistered co-primary endpoint passes, so no failed endpoint is averaged away.
Co-primary endpoints are absolute full-system quality 0.90, paired lift over baseline
0.15, paired lift over `null-system` 0.15, paired superiority over `static-prior` and
each top-k control 0.10, paired superiority over `codebase-only` on Company-unique
tasks and `company-only` on Codebase-unique tasks 0.10, authorization-restricted-
stratum quality/lift/equivalence at the same 0.90/0.15/±0.05 bounds, and overall
equivalence to oracle-spec within ±0.05. The pilot covariance and one-sided 90% upper variance bounds feed a
fixed Monte Carlo power program whose Gaussian-copula/resampling dependence model and
correlation-matrix digest freeze before pilot labels open. It chooses the smallest N
with at least 80% joint pass probability and rejects any N where an endpoint has less
than 80% marginal power. Alternatives freeze before the pilot: full quality 0.95,
baseline and null-system lift 0.20, static/top-k/store-ablation deltas 0.15, and oracle
gap 0. Pilot effect means never determine N.
The same simulation powers edit-time residency and false-completion gates from their
observed denominators. Alpha is 0.05; equivalence uses two one-sided tests and the
reported 95% interval must lie inside the band.

This normal-approximation table is a preregistered sanity check; the conservative
pilot simulation may only increase N:

| upper paired SD | N for a 0.10 nonzero paired effect, 80% power | N for 95%-CI equivalence ±0.05 at true gap 0 |
|---:|---:|---:|
| 0.05 | 2 (structural floor still 8) | 8 |
| 0.10 | 8 | 32 |
| 0.15 | 18 | 71 |
| 0.20 | 32 | 126 |

The packet publishes the formula, code digest, pilot covariance, upper bounds, power
per endpoint, expected joint pass probability, N, and cost. An underpowered or
unfunded design is terminal `NOT_PROVEN` before measurement, with a resource/
instrument diagnostic rather than a mechanism-failure claim, and never a smaller
proof.

The power program computes effective N separately for each source stratum; a one-third
stratum has roughly N/3 observations and cannot borrow the aggregate denominator. It
chooses total N large enough for every stratum endpoint and the joint endpoint vector.
Before author-lane ratification, the Validator publishes this unavoidable call-count
envelope for eleven arms, three seeds, twelve all-arm pilot tasks, two graders, and the
full 10% block reserve (gate/calibration calls are additional):

| powered task N | reserved coding-agent calls | reserved scorer calls |
|---:|---:|---:|
| 8 | 693 | 1,386 |
| 32 | 1,562 | 3,124 |
| 71 | 2,981 | 5,962 |
| 126 | 4,972 | 9,944 |

For arbitrary N, reserved coding calls are
`396 + 33*N + 11*ceil(0.10*3*N)` and scorer calls are twice that. Before pilot labels
open, the frozen model/pricing/throughput manifest multiplies this envelope by measured
per-call token/cost/time bounds and the founder ratifies a ceiling covering the chosen
N or the run ends `UNFUNDED_OR_UNDERPOWERED`. No one may discover the scale only after
pilot results or quietly power stratum endpoints with total N.
- Give an Oracle Curator a date-bounded census of every merged change in at least two
  repositories, judging-only accepted outcomes, and the ratified selection program,
  but no Kinbase schema/design, candidate, arm, or score. The program uses only
  repository history: reproducible parent, issue/request, post-change functional
  oracle, at least three pre-change evidence classes, and at least two independently
  owned nonredundant pre-change sources absent from the issue/direct edit surface,
  either of whose removal flips a frozen counterfactual judge. No single pre-change
  artifact may specify the complete fact-only oracle or solution; publish
  `SINGLE_ARTIFACT_SPEC` and every other examined/eligible/excluded reason.
  No baseline result controls inclusion.
- Seal the full eligible census, then draw without replacement using the public
  manifest seed under a frozen source-lineage stratification: at least one third of
  selected tasks require a Company fact unavailable in Codebase, at least one third
  require a Codebase fact unavailable in Company, and at least one task requires
  complementary facts from both. At least one third also form an authorization-
  restricted stratum with a pre-frozen least-privilege principal, 20–40% Company-fact
  denial by count and bytes, and a load-bearing fact initially denied but resolvable
  only through its frozen scoped-authority reply. Report when the set is effectively a census rather
  than generalize from it. Fewer tasks than the power-derived floor, or a census unable
  to supply the frozen strata, is an incomplete/invalid instrument rather than a
  license to hand-pick replacements.
- Each task binds the pre-change commit, issue/request, judging-only accepted change,
  dispersed evidence, load-bearing facts, pre-change authoritative fact set, frozen
  authority replies, least-privilege principal and exact authority scopes/denial
  labels, hidden tests, architecture rubric, dependent-edit detector, budgets,
  pilot/measurement/reserve seeds, and exclusions. Administrative/broad service-reader
  identities are ineligible.
- Tester owns hidden acceptance artifacts without reading Coder implementation.
- The schema-blind Oracle Curator authors `oracle-spec`, load-bearing fact labels,
  frozen fact-only authority replies, and source citations before candidate
  generation. Every oracle sentence is entailed by a pre-change source. Accepted
  patches/hidden tests may identify judging ground truth but their solution text and
  post-change-only identifiers are rejected by a leakage scanner and never enter the
  artifact. A failed leakage positive control is `INVALID_HARNESS`.
- A manifest digest freezes tasks, all eleven arms, coding-model artifact or immutable
  provider snapshot, decoding settings, system prompt, tool schema/permissions,
  policy bundle, host adapter, retriever, index/corpus snapshot, worktree revision,
  explicit `as_of`, Company authority cursor/service/replies, task principal and exact
  scopes/denial density, budget, seeds, blinding,
  aggregation and scoring, plus each automated grader's model/provider fingerprint,
  decoding settings, system/rubric prompt, parser, calibration-set digest, and packet
  schema and both gold annotator identities/receipts plus the adjudicated gold digest.
  It also binds exact authority-artifact digests, threat/attack catalogs,
  auxiliary corpus, and sealed canary-registry ciphertext metadata before measurement
  results. Each arm difference is enumerated. Any unbound difference or runtime drift
  is `INVALID_RUN`.
- Every launch or score against a ratified measurement task appends a signed census
  record first and consumes that scheduled seed. “Smoke” and “debug” are not
  exemptions; harness development can use only synthetic or excluded-pilot tasks.

#### Execution

- Run all eleven arms for the same measurement task/seed schedule in fresh worktrees
  and homes, with identical explicit `as_of` and Company authority cursor in each
  task/seed block and the same task-bound least-privilege principal/scopes. Every arm
  has the same frozen authority-answer tool schema and query
  cost; the
  `authority-only` arm is required to make its preregistered one or two calls without
  receiving any maintained corpus or projector output. `null-system` traverses the
  full host/hook/tool/policy/timing path but receives an empty corpus/projection and
  typed empty authority response. `static-prior` has only its frozen generic document;
  `codebase-only` and `company-only` structurally withhold the opposite shared store.
- Match allowed tools and wall/tool/token budgets. Token-match controls within 5%.
- Randomize and interleave arms within each task/seed block under one immutable
  local/open-weight artifact digest or provider-guaranteed immutable snapshot. Record
  it on every response. A change invalidates the block and may consume only the 10%
  preregistered reserve (rounded up) only when the mismatch is attested before the
  launch gate. Drift found after admission is `INVALID_RUN` and cannot replace that
  outcome. Reserve exhaustion is `INVALID_RUN`. A provider without an immutable
  fingerprint can run excluded pilots only, never measurement.
- Capture full context provenance and query traces; preserve failures and timeouts.
  The broker records `human_bytes_after_freeze`; any value other than zero is
  `INVALID_RUN`. Closed operator codes and preregistered launch inputs cannot carry
  prose into an arm.
- The coding model receives no hidden test, accepted patch, or result from another
  arm. The Validator freezes each tree before testing.
- Content-address each candidate, replace task/arm identity with an opaque random ID,
  and obtain two independently committed rubric score artifacts before unblinding.

The host blinding broker randomizes execution order, strips arm/context metadata from
candidate snapshots, and encrypts the opaque-ID-to-arm mapping to a founder-held
unblinding key. Scorers receive only opaque candidates, the common rubric, and
mechanical test observations. No per-arm dashboard or streaming arm aggregate exists.
The unblinding event is the first successful decryption of that mapping, admitted to
the append-only run ledger only after all candidate, test, and dual-score digests are
sealed. Before decryption, the outcome-blind Run Integrity Auditor sees only the
manifest, launch ledger, environment attestations, and integrity telemetry and seals
whether every invalidity predicate fired. It cannot see candidate bytes, scores, arm
mapping, or aggregates. An invalidity claim first raised after outcome access cannot
remove a run from the intention-to-treat denominator or authorize replacement. A
harness-defect record must enter that ledger before the unblinding event and be
countersigned by the founder to authorize the one superseding run. Reserve seeds and
unchanged pool are already in the original manifest. Sequence and subjects are
therefore independently verifiable rather than Validator self-report.

#### Scoring and falsification

- The Validator runs held-out functional and architecture checks and computes the
  single preregistered composite from `architecture.md`.
- Require the two scorers to have passed the excluded-pilot calibration before
  dispatch and quadratic-weighted Cohen's kappa at least 0.80 on ordinal 0–4
  non-mechanical components while the measurement blind remains sealed. Otherwise
  the harness is invalid in either outcome direction; a boundary-straddling
  qualitative component uses the lower sealed score.
- Mean seeds within each task, then compute paired task differences and the
  preregistered 95% paired bootstrap interval. Improvement gates use the lower bound;
  report each task/seed, positive-lift fraction, pilot runs, tokens/tools/cost,
  false-done rate, natural redundancy clusters, constraint residency, resident
  precision, mean set size, and ceiling-stop frequency.
- Apply every threshold in P-10 mechanically. No subjective override converts a miss
  to success.
- If `distractor` matches `full-system`, context volume explains the result. If
  `null-system` is not at least 0.15 worse than `full-system` on the lower 95% paired
  bound, integration scaffolding explains the result and the product is `NOT_PROVEN`.
  If `static-prior` is not at least 0.10 worse, a generic constant explains the result.
  If `topk-raw` matches it, corpus+selector added no measured value. If
  `topk-maintained` matches it, set-conditional/temporal selection added no measured
  value. If `authority-only` matches it within 0.05, direct authority consultation
  explains the measured gain; fewer full-system authority calls may establish an
  efficiency result but not a corpus-selection effect. Each is a named mechanism
  finding, not a renamed success.
- On the frozen Company-unique stratum, require the lower paired 95% bound for
  `full-system - codebase-only` to clear 0.10. On the Codebase-unique stratum, require
  the corresponding `full-system - company-only` bound to clear 0.10. Failure is
  `NOT_PROVEN`; mere store existence cannot substitute for measured contribution.
- On the authorization-restricted stratum, require `full-system` quality at least
  0.90, TOST equivalence to its authorized oracle within ±0.05, and lower paired 95%
  bounds at least 0.15 over both baseline and null-system. Report denied fact/byte
  density and authority resolution without denied prose. A broad-reader/open-only
  result cannot satisfy this gate.
- Apply intention-to-treat accounting. A launch becomes admitted when its prompt or
  model request crosses the sealed launch gate. Thereafter timeouts, refusals,
  model/agent/tool errors, fail-closed revocation, degraded/empty projection, and no
  patch remain in the scheduled task/seed/arm denominator. A missing candidate scores
  zero composite; declaring done without a passing candidate counts false completion.
  Only a preregistered infrastructure failure proven before admission may consume a
  reserve. No admitted result is dropped, retried, or replaced.
- Apply the exact result entry rules from P-10: baseline mean above 0.85 is the only
  `INCONCLUSIVE_NO_HEADROOM` condition; oracle below 0.90 or full-system exceeding it
  by more than 0.05 on the lower 95% bound is `INCONCLUSIVE_CEILING`; mechanical
  oracle/test-to-candidate contamination is `INVALID_RUN`, while an actual protected-
  data disclosure is a product failure and `NOT_PROVEN`; every other missed or
  crossing threshold is `NOT_PROVEN`.
- A `NOT_PROVEN` report includes the full gate vector and deltas and distinguishes a
  product falsifier from infrastructure/harness failure. One rerun is allowed only
  for a documented pre-unblinding harness defect; disappointing results do not
  authorize tuning.

The published conclusion must use the exact licensed-claim template in P-10 with
run-specific digests and metrics. Broader “Kindex works,” universal privacy, or
general greenfield-equivalence claims are evidence failures even after numeric gates
pass.

Company-steward exceptions can change Company facts only; they cannot waive a proof
gate, change a score, or override a verdict. Agy may block before evidence sealing or
unblinding on a rule-adherence defect, forcing `INVALID_HARNESS`/repair, but cannot
alter frozen evidence or a deterministic result. Once the sealed inputs exist, the
computation is unblockable and reproducible; any later objection is a new retained
finding. Unresolved validity disagreement is `INVALID_RUN`, never a discretionary
pass.

## Nonfunctional proof gates

- Python package installs in a clean environment and commands have bounded help.
- All service/data roots are explicit; default bind is loopback; filesystem modes are
  asserted; symlinks and escapes fail closed.
- Schema validation, canonicalization, migrations, and rebuilds are deterministic.
- Logs are structured and contain IDs/digests/statuses, never raw private messages.
- Every external/model/process call has a timeout and typed failure; failed writes do
  not become admitted facts.
- `fsck`, `doctor`, corpus status, question status, and experiment status are
  executable and useful after restart. `explain <logical-key>` shows each reducer
  admission/rejection step and the evidence needed to flip the result.
- Kinbase HTTP rejects unauthenticated reads, non-loopback Host, Origin-bearing
  requests, and non-JSON writes; all receive typed remediation-safe errors.
- Static analysis, formatting, type checks, dependency audit, and full test suite run
  without undeclared network access.
- [`leak-runbook.md`](leak-runbook.md) is exercised as a tabletop against one seeded
  event. No non-private remote may receive `.kin/` events before the specified
  private-repository soak and commit-time tripwire evidence.

## Evidence packet

The packet is Validator-owned mode-0700 run state outside Git during execution and
is transferred only to the founder/security custodian. A sanitized aggregate report
may be committed; raw Personal data never is. Permanent failure rows contain canary
ID, keyed-HMAC match, detector/encoding class, destination/location digest, offset,
and times—not the canary or leaked bytes. The HMAC key and raw incident subject live
in a separately access-controlled incident vault under its own retention/legal
decision. “No rerun erases a failure” preserves the sanitized event, not leaked
Personal bytes past their retention clock.

Acceptance and committed fixtures are synthetic or licensed public material and may
not derive from real private conversations. Committed V-2/V-3 fixtures contain only
generators, placeholder IDs, structural gold labels, and policies. Raw randomized
instantiations and their registry live only in the Tester vault described by the
threat model and are destroyed on its clock. An opt-in private soak follows the same
sanitized evidence rule and honors the applicable raw-data erasure policy.

Benchmark repositories must be founder-owned or open source under a license that
permits local evaluation and transmission to the pinned model provider. Customer,
employer-confidential, or collaborator-private repositories are ineligible without a
separate explicit owner authorization bound into the manifest. Repository license,
owner/basis, provider disclosure basis, and data-retention class are frozen per task.
Git author names/emails are scrubbed from projected context unless load-bearing; the
private source checkout still receives restrictive run-root handling.

Per-arm worktrees, agent homes, model transcripts, raw Git history, and raw tool logs
are private run evidence and expire after sanitized scoring/evidence extraction and
no later than 24 hours after terminal verdict unless a separately authorized incident
hold applies. Candidate code needed for audit is retained only when its repository
license/authorization permits it; otherwise retain content digests and metrics.
Withdrawing the consent basis destroys the affected raw copies and appends a
`RETIRED_DATA_WITHDRAWN` notice: the old result remains historically reported but is
no longer reproducible/current and cannot support a product claim. A manifest freeze
does not override data rights.

An incident hold requires founder and named security-custodian signatures, reason,
asset IDs, encrypted vault, access list, and `expires_at`. It is reviewed every 24
hours and expires after seven days unless a separately cited legal obligation names
the new deadline; it never makes raw bytes Git-reachable.

Byte-identical rebuild applies to admitted fact events and current-view derivation,
not deleted raw transcript bodies. Personal facts retain minimized private evidence
summaries or explicit evidence tombstones; expiring raw observation content cannot
force the system to immortalize it.

The final packet contains:

- exact ratified specs and digests;
- source/corpus manifests and adapter receipts;
- classifier corpus, gold labels, raw predictions, and metrics;
- privacy scan/reconstructor and adversarial results;
- exact threat-model, attack-catalog, and auxiliary-corpus digests plus sanitized
  control/mutation coverage and reconstruction adjudication receipts;
- leak-runbook tabletop, private-soak, and staged-commit tripwire results;
- maintenance/temporal traces;
- authority question and signed answer receipts;
- host setup/hook invocation receipts;
- immutable benchmark manifest, candidate commits, test outputs, rubric scores,
  context/residency traces, costs, and aggregate analysis;
- Coder/Tester/Orchestrator/Validator identities and method limitations;
- all failed attempts and the terminal `PROVEN`, `NOT_PROVEN`,
  `INCONCLUSIVE_NO_HEADROOM`, `INCONCLUSIVE_CEILING`, or `INVALID_RUN` verdict, plus
  the full gate diagnostic vector even when terminal proof fails.

## Operational limits

The PoC runs locally and may use finite test keys and loopback service processes.
That limits deployment claims, not functionality claims. Per-run ceilings are:

- source body: 1 MiB; observation batch: 10,000 items / 256 MiB;
- shared event: 64 KiB; `.kin/` intake: 10,000 events / 128 MiB;
- projection call: 32 facts / 128 KiB; every ceiling stop reports omitted count and
  is a confound if it exceeds 10% of dependent edits;
- candidate and approval lifetime: 15 minutes;
- private raw-session default retention in proof roots: 24 hours;
- Company cache freshness: configured by the stricter Company criticality/local
  dependence class, never silently extended;
- all child processes: explicit wall and idle timeout;
- candidate generation/questions/shared admission: per-principal hourly limits, with
  typed refusal rather than silent dropping;
- benchmark: pilot-generated fully loaded estimate and human-ratified aggregate
  maximum calls, tokens, and USD before measurement dispatch. The harness atomically
  reserves and enforces the aggregate ceiling.

Scale beyond these bounds, production availability, and human-response SLOs remain
future work. Behavior inside them is acceptance-critical.
