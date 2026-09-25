# Kinbase black-box acceptance suite (Tester lane)

Authored under the Factory **Tester** dispatch against ratification manifest
`12dd4c18aaca12c29cc816ca4a5161b5e011814f021879897b88b0e6e85168dd` at repository
baseline `e29f3fe03595d594c0546f9b0012b58f7c45bac1`.

Rebound on 2026-09-17 to manifest
`10c36a4790e09b082ac96df5368bfeeef40360658480312e441d523d8e4e31a4`, which adds
`spec/amendment-003-ruling-contract.md` and the revised `architecture.md` and
`cli.md`.

This suite is an **observation instrument**, not a verdict. `spec/verification.md`
"Role separation" reserves the verdict to the Validator; the suite reports a gate
vector and the evidence a verdict is composed from.

## Remediation 002 — what changed

A fresh implementation-blind Detector Reviewer blocked the previous instrument on
17 findings. The central ones were that unexecuted work reported `PASS`, that the
frozen catalog had no executable controls or mutations, and that the instrument
told the product the answer through forty environment selectors. All 17 are
closed; the mechanisms are below and each is executable without the product.

| finding | closure |
|---|---|
| 1 cleanliness not attestable | `tests/tools/attest-clean.sh` — content-addressed attestation over `spec/**` and `tests/**` only |
| 2 self-test crosses the review boundary | `tests/reviewer-selftest.sh` — reads ratified `spec/**` + `tests/**`, installs nothing, writes only outside the repo |
| 3 unexecuted work is `PASS` | every gate starts `NOT_RUN`; deselect/skip/uncollected/empty-parameter all stay non-green |
| 4 product failure hides an invalid detector | two independent channels; dominance only with an independently content-addressed product observation |
| 5 catalog lacks the four frozen elements | 92 obligations, 401 thresholds, all four derived per threshold |
| 6 mutations declarative, not executable | kill ledger over frozen raw controls + 35 pre-execution planters + `tests/mutation-run.sh` + `tests/detector-mutation-run.sh` |
| 7 expected answers reach the product | all 40 selectors removed; policy enforced statically by `test_control_policy.py` |
| 8–16 per-gate vacuity | real state construction, typed evidence, total quantifiers; every bare return, permissive default and tautology removed |
| 17 no auxiliary corpus | `tests/fixtures/auxiliary/` — CC0 sources, dictionaries, correlations, decoys, digests, rights basis |

## Remediation 007 — Validator conformance rulings

The instrument follows dispatch 007's binding rulings. The earlier partial
commit established isolated launcher config, external certificate installation,
live Company admission, registry anchors, one signing convention, closed event
vocabularies, and content-derived event IDs. This continuation completes the
session, native lifecycle, and hook repairs:

* Session observe/list/decision flows use the ID returned by `session start`.
* All 64 native lifecycle transitions execute in order, with ingest/status between
  transitions. The harness derives its matrix from per-adapter receipt counts,
  Observation disposition/state, evidence-linked facts, and related Unknowns.
  The product is never asked for harness cell names or mutation outcomes.
* Kindex fixtures use the 0.36.0 `nodes(id, node_type, title, content, payload,
  created_at)` / `edges` schema. Duplicate import re-ingests one export; it does
  not invent duplicate primary-key rows.
* Hook installation uses the host user config and no bypass flag. The oracle
  checks the displayed files/content, installation digest, and unchanged project
  settings. Host wrappers lead every invocation's PATH, including explicit envs.
* Discovery hints change through Git remotes; manifests use `.kin/manifests/`.
  Timeout/blackhole endpoints come from user config. Env endpoints remain refusal
  probes with a zero-connection obligation. Cache-clearing preserves the installed
  certificate, and `repo init` must copy the external certificate into the cache.
* R-11 pins the resolved product executable with args `["classifier", "--json"]`.
  V-2 defaults to `[classifier] model = "ollama:qwen2.5:7b"`. Set the harness-only
  `KINBASE_CLASSIFIER_MODEL=ollama:glm-5.3:cloud` (or another available Ollama
  model) to write that model into every world's user-config `[classifier]` table.
  The variable never reaches the product environment; the config chooses the
  provider per R-11. The Validator provisions the selected live model. Without
  an override, other worlds omit model for structural rule/replay operation.
  Doctor's spawn pin and live provider are checked after
  extraction. No empty classifier stub licenses an extraction gate.
* Dispatch 008 orders transcript create/update/delete/restart/expiry explicitly,
  republishes registries for revocation, preserves branch observations on the
  reducer revision, and uses receipt-time claims for CLOCK_SKEW (R-14).
  Historical validity timestamps are not clock-skew probes. Hooks dispatch JSON
  carries one base64 envelope (R-12); all macro-F1 scoring is instrument-owned
  (R-13). Product-independent selftests allocate no network listener merely to
  construct filesystem roots.

`test_dispatch007_selftest.py` exercises the native transitions and regression
oracles without a product, including ten dispatch-008 regression guards.
Frozen controls retain their dispatch-007 digest; dispatch 008 updates catalog
wording for R-13/R-14 without changing numeric thresholds or human-signature debt.
Dispatch 009 starts at the committed 008 patch (`057cff4`). Synthetic timestamps
use calendar arithmetic; both latency gates read the numeric p95 property.
Blackhole probes bind an available port before redirecting the client. Privacy
claim validation counts problems in the correct direction, and claim/diagnostic
failures quote the product output. Five new regression guards (ten nodes) cover
these faults; the temporal guard also verifies every intermediate reducer HEAD.
The 009 handover remains in the worktree and an exact scratch patch; Git metadata
is read-only and the Validator owns application and commit.

Dispatch 010 starts at `2e7163b`. Positive controls restore their native locations
and pre-control Git object database, count removed cells rather than shared
files, and retain the detector registry for the clean sweep. Empty V-2
predictions and private-store Git overwrite refusals report typed product
observations. V-4 reports complete refusal output when no path admits, leaving
normalisation unmeasured. V-9 explicitly opens its input pipes and feeds both
hosts before waiting. Crash probes observe new journal markers under
`.kin/local/journal/` or the configured private store, with typed `journal_state`
from `status --json` as a fallback. Each probe uses a fresh world and must witness
a reaped SIGKILL exit and exactly one recovered event. No stale marker, ordinary
nonzero exit, or completed transaction can license crash coverage. Live journal
timing and model quality remain Validator measurements.

Dispatch 012 starts at `c9391e6` and implements the reopened-suite R-18 ruling.
The incremental snapshot consumes `GitRepo.run`'s string result. All nine V-5
histories now contain at least two signed events: earlier expired observations
and an earlier unregistered observation are explicitly superseded in rows 4, 8,
and 9. The late test envelope reuses its earlier receipt even after a long
delivery delay. Runtime freshness and intentionally expired V-4/V-7/Kindex
fixtures use the proof clock; V-5 retains historical validity against its frozen
`2026-03-05` as-of query. Identity testing supplies the duplicate-certificate
clause from a clean/duplicate/restored `fsck` sequence before the UUID-repin probe.
Every anchored world writes its registered maintainer's seed outside Git, mode
0600, and supplies the absolute path through `[identity] maintainer_key_file`;
config rewrites retain that identity. Manifest expiry reports a publication
refusal before attempting the Company clock advance.

Ten new product-independent selftest nodes exercise these repairs, and the
existing temporal witness guard checks every row's minimum history and the new
supersession links. All 117 obligations and 482 thresholds are retained. The
catalogue, frozen controls, and kill-ledger digests below were recomputed and
remain unchanged; no product clause or control was relaxed.

Dispatch 013 starts at `8d9e873`. Kindex and authority-answer revocation witnesses
use a boolean unchanged-tree flag and carry the external-registry explanation
separately. The native lifecycle selftest checks typed transition evidence for
all 64 cells. V-4 distinctness applies to the ten mutation-stage post-state
digests; all thirteen stages retain their before/after evidence. Duplicate,
rebuild, and restart must preserve state, with rebuild/restart also retaining
their view-determinism checks. Seventeen synthetic cycle regressions cover a
valid preserving cycle, every idle mutation or unintended preserving-stage
change, failed rebuild/restart determinism, and a mutation revisiting an earlier
state. All 117 obligations, 482 thresholds, numeric bounds, and frozen control
bytes are retained. Catalogue wording and its mirror and recorded digests are
updated; the human-signature debt remains open.

## Reviewer entrypoint

```sh
tests/reviewer-selftest.sh
```

Product-independent, offline, and creates nothing inside the repository. It runs
pyflakes over `tests/**` first (an undefined name in a gate module must fail with
no product present), then the instrument-validity work only: catalog totality,
the kill ledger, the control policy, the green-path guard, the backreference
integrity checks, and the trust-installer and planted-event witness selftests.
It needs an interpreter carrying `tests/requirements.txt`; `tests/.venv` is used
automatically when present.

## Exact Validator invocation

```sh
tests/run-acceptance.sh
```

Everything the suite needs lives beneath `tests/`: `tests/requirements.txt`,
`tests/pytest.ini`, `tests/conftest.py`, and `tests/run-acceptance.sh`. No shared
packaging file at the repository root is read or edited.

Useful subsets:

```sh
tests/run-acceptance.sh -m selftest              # instrument validity, no product needed
tests/run-acceptance.sh -m "v3 and not slow"     # one gate, fast subset
tests/run-acceptance.sh -m "not slow and not soak"
KINBASE_ACCEPT_GATE_VECTOR=/tmp/gates.json tests/run-acceptance.sh
```

### Environment

| variable | meaning |
|---|---|
| `KINBASE_BIN` | **required** argv prefix for the ratified CLI; its first word is the absolute path of the build under test. Nothing is taken from `PATH`. The census records the path, SHA-256 and `--version`. |
| `KINBASE_SPEC_ROOT` | repository containing `spec/`. Default: discovered upward from the suite. |
| `KINBASE_TESTER_VAULT` | mode-0700 canary vault root. Default: `$TMPDIR/kinbase-acceptance-vault-<uid>`. |
| `KINBASE_HOST_CODEX` / `KINBASE_HOST_CLAUDE` | absolute paths to the pinned host executables (V-9). |
| `KINBASE_ACCEPT_GATE_VECTOR` | path to write the JSON gate vector and per-node records. |
| `KINBASE_ACCEPT_MUTATION` | one frozen mutation id; the named nodes must then **fail**. |
| `KINBASE_ACCEPT_DETECTOR_MUTATION` | one detector mutation id (Tester-owned detectors). |

## What makes this black box

The suite reaches the product only through the surfaces frozen in `spec/cli.md`
and `spec/architecture.md` section 6: the `kinbase` command, its `--json`
payloads, its typed error contract, and the loopback HTTP service. It never
imports product modules; `test_backreference_integrity.py` asserts that
mechanically. Nothing under `tests/` was written by reading implementation
source, and the Tester ran none of the product-facing tests.

## Backreferencing is mechanical, not editorial

Every assertion cites an exact ratified requirement:

* `acceptance/_harness/requirements.py` recomputes SHA-256 over the ratification
  manifest and every artifact it names at import. A digest disagreement stops the
  run as `INVALID_HARNESS` rather than reporting product results against
  unratified bytes.
* `@spec_ref(...)` attaches one or more `SpecRef` records to each test. Each
  carries the gate, the artifact, a section anchor and a **verbatim quote**. The
  quote must occur in that artifact or the module fails at import. Only markdown
  structure — hard-wrapping, hyphenated line breaks and blockquote markers — is
  normalised; no word, threshold or identifier is altered.
* `test_backreference_integrity.py` asserts that every collected test carries at
  least one *authority* reference. `spec/behavior-ledger.md`, the glossary and
  the review disposition may be cited only as `TRACE`, which never satisfies the
  rule alone.

### Counts, reconciled

| quantity | value |
|---|---:|
| collected by pytest | 359 |
| catalogued obligations | 117 |
| catalogued thresholds | 482 |
| kill-ledger rows over frozen controls | 482 |
| executable pre-execution planters | 35 |
| detector mutations with a demonstrated escape | 6 |
| product-independent self-tests | 240 |
| unbackreferenced tests | 0 |

Catalog digest `a8655ac61a8c33db`; kill-ledger digest `6df354962e4f0178`;
frozen-controls digest `0c264e8c12f2e969`;
instrument-debt digest `ac2ee9f12dff2a8b`.

Collected node ids exceed authored functions because `@pytest.mark.parametrize`
expands one function into several, most visibly the nine frozen V-5 temporal rows
and the per-host V-9 functions. Verify with
`tests/run-acceptance.sh --collect-only -q`.

Finding 21 is closed with the supplied Jeremy McEntire grant as evidence.
The grant's original digest is superseded; `acceptance._harness.auxsel --verify`
now verifies a precisely framed, reproducible pool identity. Auxiliary
qualification remains `INVALID_HARNESS` until Validator obtains the founder's
current-digest re-attestation and the implementation-blind Detector Reviewer
produces the signed, frozen selection in `SELECTION-PROTOCOL.md` steps 4-6.
No product result follows from a passing debt ledger.

### Recording the blinded operator exercise

Use `corpora.bind_operator_exercise(corpora.load_gold("operator_exercise.json"),
Path("/private/tmp/operator-presentation.jsonl"))` from a harness process with
`tests/` on its Python path. Give the operator only the emitted JSONL, never the
gold fixture or the returned harness mapping. Each record includes its opaque
`id`, statement, atom kind, proposed destination, and the fixture's verbatim
`decision_semantics` and routing context. Approve means the displayed routing
action is correct, including retaining nothing for `none`; reject means the
statement warrants a different routing action. IDs derive
from the canonical frozen exercise digest, so a later scoring process uses the
same IDs; changing the exercise invalidates earlier recordings.

Record JSONL objects in presentation order with `item_id` equal to the emitted
`id`, `decision` (`approve` or `reject`) and `decided_at` (UTC
`YYYY-MM-DDTHH:MM:SS.ffffffZ`). Set `KINBASE_OPERATOR_RESPONSES` to that file.
An optional `also_belongs_in` list (`personal`, `company`, `codebase`) annotates
other independently warranted destinations. It does not change the decision on
the shown write and is not itself scored or executed. This binary exercise does
not measure fan-out completeness. See `fixtures/gold/OPERATOR-AUDIT.md`.

## Instrument validity comes first

`spec/verification.md` "Instrument validity": *"A detector that cannot catch its
positive control yields `INVALID_HARNESS`, never PASS."*

`test_harness_selftest.py` runs without the product and proves the instruments
before any gate observation is believed:

* Ed25519 against RFC 8032 vectors and, when available, against `cryptography`;
* ChaCha20 against the RFC 8439 vector; JCS bounds and domain separation;
* the canary detector catches every frozen transformation family;
* 500 decoys keep the Wilson 95% upper false-positive bound at or below 0.01;
* 300 stratified randomized positives keep the Wilson 95% lower sensitivity bound
  at or above 0.98;
* every detector mutation genuinely blinds the capability it names;
* every declared decoder in the normalisation ladder actually fires, and each
  decoded view keeps the canary whole rather than collapsing to a fragment;
* the reserved-call formula `396 + 33*N + 11*ceil(0.10*3*N)` reproduces the
  ratified envelope table exactly for N ∈ {8, 32, 71, 126};
* `ceil((z₀.₉₇₅ + z₀.₈₀)² · (sd/δ)²)` reproduces **both** columns of the
  normal-approximation table exactly at every published row, with no tolerance.

`INVALID_HARNESS` and `PRODUCT_FAILURE` are separated at the failure site.
`conftest.py` classifies, in order: any failure outside the call phase (a
fixture or collection defect); any failure in a `selftest`-marked test, which by
construction never touches the product; an explicit `HarnessInvalid`; any
unexpected exception type, which means the instrument misbehaved rather than
observed a violation. Only a deliberate `ProductFailure` or product assertion is
`PRODUCT_FAILURE`. The `INSTRUMENT` gate is always an instrument observation.
Inside a gate `PRODUCT_FAILURE` dominates `INVALID_HARNESS`, matching
`spec/verification.md`, which retains an independently valid product failure
alongside an invalid detector.

A defect in the measuring device is therefore never reported as a product
defect, and a fixture error can no longer leave a gate reading `PASS`.

## The obligation catalog and the kill ledger

`acceptance/_harness/catalog.py` declares each obligation once, as a conjunction
of typed clauses. All four ratified elements are *derived* from that single
declaration, so none can drift from the others:

* **threshold** — the clause bound;
* **positive control** — synthesised conforming evidence, which must be accepted;
* **product mutation** — evidence violating one clause, which must be rejected in
  the obligation's declared fail-closed channel;
* **detector mutation** — the same evidence with that clause deleted from the
  checker, which must therefore be *missed*.

`tests/test_catalog_and_kill_ledger.py` executes all four for every threshold,
with no product present, and refuses to pass if any positive control is rejected,
any mutation survives, any detector mutation fails to blind, or any negative
control trips. The result is content addressed.

## Controls that may reach the product

`acceptance/_harness/controls.py` is a closed allowlist. Only ordinary
configuration and *witnessed* fault schedules may cross into the product process.
Names shaped like `*_SCENARIO`, `*_CASE`, `*_FIXTURE`, `*_STATE`, `*_OVERRIDE`
and anything acceptance-prefixed are forbidden outright, because their presence
alone lets an implementation recognise the probe. `test_control_policy.py`
enforces this by AST inspection over the whole suite.

## Mutation protocol

`acceptance/_harness/mutations.py` is the frozen catalog: 41 entries, each with
the ratified sentence that requires it, the exact change, its application method,
and the pytest node ids that **must fail** under it.

`spec/verification.md` "Role separation" assigns mutation testing to the
Validator, and the Tester is implementation-blind. So:

* mutations expressible through ratified levers — fixture bytes, config values,
  filesystem state, or the Tester's own detectors — are driven directly by tests;
* mutations that can only be a source change are *declared* with exact semantics
  and must-fail nodes for the Validator to apply.

A mutation run inverts polarity: `KINBASE_ACCEPT_MUTATION=<id>` means the named
nodes must fail. If they still pass, the gate cannot detect the defect it claims
to detect — `INVALID_HARNESS`, never a pass.

## Fixtures are synthetic by construction

`spec/verification.md` "Evidence packet": *"Committed V-2/V-3 fixtures contain
only generators, placeholder IDs, structural gold labels, and policies."*

`tests/fixtures/` holds exactly that. Every message template was deliberately
constructed for this instrument; none derives from a real private conversation.
`fixtures/hosts/envelopes.json` holds the V-9 native envelopes: Claude's were
recorded from the pinned build in a scratch repository with a synthetic prompt
(session id, paths and prompt replaced by placeholders); Codex's carry exactly
the required fields of the pinned executable's own input schemas, kept beside
them. `hosts.envelope_for` fills the placeholders and refuses any field the host
does not send, and the V-9 native-events node refuses a host whose version
differs from the frozen one.
Raw canary values are generated at run time into a mode-0700 vault that
`acceptance/_harness/vault.py` refuses to place inside any repository, worktree,
agent home or evidence packet, and destroys on its 24-hour clock.

## V-10 scope boundary

This lane deliberately **does not** author or expose the V-10 task corpus.
`spec/product.md` P-10 requires it to be built only after V-1 through V-9 pass
and the reducer freezes, by a separate schema-blind Corpus Builder, before task
exposure. A Tester-authored corpus would be the contamination P-10 forbids.

`test_v10_protocol.py` authors the *harness and denial checks that enforce that
ordering*: the phase ledger, Builder and Curator blindness predicates, the
reducer-repair recovery rule, `freeze` and census denial probes, the arm-difference
binding table, and independent implementations of the power program, call
envelope, blinding predicates, intention-to-treat accounting and result-entry
rules. `test_tester_lane_contains_no_v10_task_corpus` asserts the boundary.

## What the Tester did not do

Per the dispatch: the Tester authored no product code, read no implementation or
Coder output, inspected no sibling lane, contacted no Coder, and issued no
verdict. The suite was validated by syntax and import checks only — import-time
`spec_ref` resolution, AST parse, and the fixture generators — and was **not
executed against an implementation**. No expected value was adapted to observed
behaviour.

## Layout

```
tests/
  run-acceptance.sh          exact Validator invocation
  pytest.ini                 markers, timeouts, strict config
  requirements.txt           lane-local dependencies
  conftest.py                isolated roots, vault, gate-vector reporting
  acceptance/
    _harness/                instruments: requirements, cli, service, detectors,
                             scanners, canaries, vault, stats, gates, ordering,
                             mutations, evidence, hosts, synth, gitfix, crypto
    test_*.py                the gates
  fixtures/
    gold/                    structural gold labels and generators
    policies/                the auxiliary-corpus request for the Detector Reviewer
    hosts/                   native V-9 envelopes and the Codex input schemas
```
