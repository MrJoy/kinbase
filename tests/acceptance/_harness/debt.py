"""The instrument's own outstanding-validity ledger.

Detector Reviewer dispatch 003 found 22 blocking defects. The entries record
closure evidence for each. Finding 21's supplied human grant closes the missing
grant debt; current-digest re-attestation and independent selection remain
explicit prerequisites checked by auxiliary qualification, not fabricated acts.

This is deliberately not a suppression list. Nothing here is skipped, xfailed or
tolerated.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

OPEN = "OPEN"
CLOSED = "CLOSED"


@dataclass(frozen=True)
class DebtEntry:
    """One instrument-validity defect and its disposition."""

    finding: int
    title: str
    status: str
    gates: tuple[str, ...]
    why_blocking: str
    required_work: str
    #: What the instrument reports because of this entry.
    current_effect: str = "gate instrument channel reports INVALID_HARNESS"

    def as_json(self) -> dict:
        return {
            "finding": self.finding,
            "title": self.title,
            "status": self.status,
            "gates": list(self.gates),
            "why_blocking": self.why_blocking,
            "required_work": self.required_work,
            "current_effect": self.current_effect,
        }


_ALL = tuple(f"V-{i}" for i in range(1, 10))


def _closed(finding, title, gates, why, work, effect) -> DebtEntry:
    return DebtEntry(finding, title, CLOSED, gates, why, work, effect)


LEDGER: tuple[DebtEntry, ...] = (
    _closed(
        1, "Full clean-worktree attestation unavailable", ("INSTRUMENT",),
        "Git cannot stat tracked paths under .kin/** and evidence/**, so untracked "
        "or modified material there cannot be excluded.",
        "tools/attest-clean.sh enumerates untracked paths, records the exact "
        "commit and tree, and names each inaccessible path explicitly rather "
        "than silently scoping it away.",
        "the attestation states its own scope and unreadable paths",
    ),
    _closed(
        2, "V-10 reported product PASS with no product", ("V-10",),
        "Two static selftest assertions resolved both channels to PASS.",
        "Nodes carry an origin; a selftest-marked node is instrument-only and "
        "can never resolve the product channel.",
        "V-10 reports instrument=PASS product=NOT_RUN",
    ),
    _closed(
        3, "Parameterised nodes collapsed into one census record", ("V-9",),
        "f[codex] skipped and f[claude] passing folded to one key; the later "
        "record overwrote the earlier.",
        "The census folds every collected parameter instance, keeping the worst "
        "outcome, and never discards an instance.",
        "a skipped parameter keeps its function NOT_RUN",
    ),
    _closed(
        4, "Controls and mutations are circular synthetic artifacts", _ALL,
        "conforming(), violating(), the blinded checker and the judge all derived "
        "from one clause object, so the ledger could only restate the clause to "
        "itself and could not establish sensitivity to product behaviour.",
        "tests/tools/freeze-controls.py derives the positive, negative and benign "
        "controls once and commits them with a digest; rawcontrols.py reads those "
        "frozen bytes at run time and never regenerates them, and every row names "
        "the executable pre-execution planters bound to its own nodes.",
        "a loosened clause no longer rejects its own frozen negative, so the "
        "ledger reports a survivor",
    ),
    _closed(
        5, "Obligations lack executable checker coupling", _ALL,
        "66 of 92 obligations were named by a test that never called their "
        "checker, so a weak test satisfied the census without consuming its row.",
        "test_no_green_paths.py rejects any catalog row whose declared node does "
        "not literally call its checker for that exact OID, and consumption.py "
        "records a content-addressed evaluation per row at run time.",
        "an executed row with no evaluation record makes its gate INVALID_HARNESS",
    ),
    _closed(
        6, "Static green-path audit missed the patterns it forbids", _ALL,
        "The linter checked three literal defaults and accepted a module if one "
        "total-quantifier name appeared anywhere; 24 collection defaults, 17 "
        "optional loops and 41 guarded assertion blocks survived it.",
        "greenpath.py analyses every test function individually for bare return, "
        "untyped assert, permissive default, collection fallback, tautology, "
        "swallowed failure, unproved loop domain, optional guard and missing "
        "catalog consumption.",
        "all fifteen gate modules report zero findings",
    ),
    _closed(
        7, "Planters rewrite the result after execution", _ALL,
        "The interposer ran the real product first and then edited stdout and "
        "exit status, mutating observation rather than causal behaviour.",
        "planters.py applies all 35 catalogued mutations to raw state at a "
        "declared seam before the product starts --- event body and bytes, "
        "certificate, external root, published registry, native source, user and "
        "service config, corpus record, host envelope, fault schedule --- and "
        "records an independent read-back witness.",
        "a mutation changes what the product reads, not what it printed",
    ),
    _closed(
        8, "Mutation runner counts infrastructure failure as a kill", _ALL,
        "Any nonzero pytest status marked the whole mutation KILLED, and the "
        "interposer's own configuration was dropped by the driver's env scrub.",
        "mutation-run.sh parses per-node call-phase reports, requires every named "
        "node to fail in the planter's declared channel, and rejects a run whose "
        "planter never reached its seam.",
        "a partial or infrastructure failure is not a kill",
    ),
    _closed(
        9, "Detector mutations never demonstrate gate invalidation", ("V-3",),
        "One unit selftest confirmed local blindness; nothing activated a "
        "mutation, executed its gate and required INVALID_HARNESS.",
        "detectorprobe.py plants one positive control per detector mutation on "
        "the exact surface it disables; conftest.py rejects V-3 while any "
        "detector mutation is active; detector-mutation-run.sh requires both "
        "halves per isolated run.",
        "all six mutations demonstrate escape and gate rejection",
    ),
    _closed(
        10, "Assertion classification conflates instrument and product", _ALL,
        "Every non-selftest AssertionError became PRODUCT_FAILURE, including "
        "assertions about Tester fixture counts and absent prerequisites.",
        "prereq.py types every instrument-owned prerequisite and raises "
        "HarnessInvalid; gate modules may not contain a bare assert, so a bare "
        "AssertionError can only originate in instrument code.",
        "a missing fixture, right, binary, service or gold record never accuses "
        "the product",
    ),
    _closed(
        11, "V-1 lifecycle matrix is neither exact nor natively executed", ("V-1",),
        "The ratified table sums to 64 cells; the catalog required 61. "
        "Transitions wrote generic JSON outside the adapter's native source and "
        "all cells shared one receipt mutation.",
        "lifecycle.py declares all 64 ratified cells with their native format, "
        "three frozen expected states and a per-cell negative mutation, and "
        "executes each transition in the adapter's own source format with "
        "before/after raw source digests.",
        "V-1 reports the exact ratified table, natively executed",
    ),
    _closed(
        12, "V-2 lacks calibration, gold-derived metrics and real sagas", ("V-2",),
        "The calibration manifest was absent yet a refusal passed; metrics were "
        "product-reported; mixed-message lookups used pre-opaque IDs; crash seams "
        "were sleep-duration labels with a hardcoded recovery flag.",
        "The excluded 60-message calibration corpus and its manifest are "
        "committed and digest bound; metrics.py computes macro-F1, per-label "
        "metrics, pooled shared precision, atomisation and abstention in the "
        "harness from raw predictions joined to gold on the opaque token; each "
        "crash seam is killed at a witnessed artefact and recovery is read back "
        "from the store.",
        "V-2 measures the product rather than quoting it",
    ),
    _closed(
        13, "V-3 coverage is not total over surfaces and encodings", ("V-3",),
        "Family coverage checked anchor names; qualification labelled in-memory "
        "payloads with surface names without planting through them; the lifecycle "
        "stage list was reported rather than executed.",
        "matrix.py writes native bytes onto each of the twelve declared surfaces "
        "across the full surface x encoding cross product and returns an exact "
        "receipt per cell; all nineteen threat-model families execute a real "
        "probe with control, decoy and detector blinding; the fourteen lifecycle "
        "stages are driven through the ratified CLI.",
        "V-3 coverage is executed rather than named",
    ),
    _closed(
        14, "Signed worlds lack the ratified external trust prerequisites",
        ("V-4", "V-5", "V-7", "V-8", "V-9"),
        "SignedWorld wrote a worktree hint and local signers with no external "
        "Company root, repository certificate or signed AuthorityRegistry, so a "
        "conforming product should have refused the intended positive fixtures.",
        "trust.py establishes a live Company, the external root outside the work "
        "tree, a steward-signed repository certificate and a published "
        "AuthorityRegistry before any fixture is planted, and every gate fixture "
        "uses it.",
        "positive controls are worlds a conforming product may admit",
    ),
    _closed(
        15, "V-4 substitutes labels for transitions, scale, replay and locking",
        ("V-4",),
        "Rebuild and restart marked themselves changed; conflict planted no "
        "authorized resolution; three of four manifest relations existed; there "
        "was no 10x corpus, no 10,000-event revocation graph, no replay and no "
        "lock witness.",
        "Each of the thirteen incremental stages digests the store before and "
        "after; the conflict resolves through a real parent-bound event; all four "
        "manifest relations are constructed; scale.py builds the 100,000-event "
        "ceiling corpus and the 10,000-event dense graph with cross-checked "
        "signatures; replay and a two-worktree lock witness are executed.",
        "V-4 constructs the state it reports",
    ),
    _closed(
        16, "V-6 has no registered live authority round trip", ("V-6",),
        "The fixture never registered the helper key, scope or channel; the test "
        "invoked the helper directly, so the product never delivered a question "
        "through a registered channel.",
        "authority.py runs an independent signed answering process whose key, "
        "scope and channel are published through the live registry; delivery is "
        "evidenced by the process's own append-only log and the digest of the "
        "exact request bytes it received.",
        "the product must resolve and use a registered channel",
    ),
    _closed(
        17, "V-8's live service holds no fact history, cache or revocation",
        ("V-8",),
        "Company started but no referenced fact version was inserted, the "
        "certificate was not installed, and cache rows hardcoded "
        "state_constructed.",
        "Every V-8 fixture installs the certificate and admits the referenced "
        "fact plus a superseding version through Company's own admission "
        "surface; each cache-table row is constructed by really expiring or "
        "revoking state and reading the result back.",
        "V-8 ranges over a Company that holds the referenced fact",
    ),
    DebtEntry(
        18, "V-9 performs no approved install or native host invocation", OPEN,
        ("V-9",),
        "The invocation witness passed on a single `--version` probe of the "
        "host: the harness itself sends every native envelope through `hooks "
        "dispatch`, so no host ever ran a session or delivered a hook. The "
        "earlier closure (real executables behind a recorder, filesystem-digest "
        "install comparison, the 250 ms budget, 10,000-event corpora, a real "
        "submodule) stands; host-driven delivery was never shown.",
        "Run each real host non-interactively with Kinbase hooks installed in "
        "the isolated HOME and credentials the operator supplies, derive "
        "`not_mocked` from dispatcher invocations the host made during that "
        "session, and pin the KINBASE_HOST_* versions in a frozen fixture.",
        "V-9 native-event evidence is INVALID_HARNESS until a host delivers "
        "its own hooks",
    ),
    _closed(
        19, "V-9 permits zero operator work and trusts reported adequacy", ("V-9",),
        "The blinded file was never driven; absence of a result passed; adequacy "
        "sent the same file five times and trusted product-reported slots.",
        "The blinded operator responses are a typed prerequisite and every one of "
        "the twenty decisions is scored and timed by the harness against gold the "
        "operator never saw; adequacy sends distinct per-window arrivals and "
        "counts slots and admitted facts from the receipts.",
        "absence of operator work is INVALID_HARNESS, never a pass",
    ),
    _closed(
        20, "Control inspection incomplete; case identity leaks", _ALL,
        "The policy read only literal env= keys, missing argv, cwd, stdin, "
        "extra_env and committed history; the V-4 scenario, V-8 digest case and "
        "V-9 start state crossed those channels.",
        "The policy inspects argv, cwd, stdin, extra_env, base_env overrides and "
        "committed paths, and the three named leaks use opaque harness-mapped "
        "identifiers.",
        "semantic identity no longer reaches the product on any inspected channel",
    ),
    _closed(
        21, "Auxiliary corpus human rights grant", ("V-3",),
        "A Tester assertion of authorship cannot independently prove authority to grant CC0.",
        "Supplied tests/fixtures/auxiliary/GRANT.md, signed Jeremy McEntire of Wander "
        "at 2026-09-09T20:42:31Z, clauses 1-4, supplies the named rightsholder, "
        "asserted VP of Engineering authority, CC0 legal-code digest and both permissions. "
        "pool.json records the grant digest as closure evidence; auxsel verifies the "
        "reproducible pool. Tester did not author or modify the grant.",
        "human-grant absence closed; qualification still requires Validator's founder "
        "re-attestation over the current digest and Detector Reviewer's signed selection",
    ),
    _closed(
        22, "Reviewer environment did not enforce pytest timeouts", ("INSTRUMENT",),
        "pytest_timeout was unavailable and the strict run still exited zero.",
        "The suite refuses to start when a declared plugin is missing unless an "
        "explicitly recorded untimed run is requested.",
        "a missing timeout plugin stops the run",
    ),
)


def open_entries() -> tuple[DebtEntry, ...]:
    return tuple(e for e in LEDGER if e.status == OPEN)


def closed_entries() -> tuple[DebtEntry, ...]:
    return tuple(e for e in LEDGER if e.status == CLOSED)


def gates_with_open_debt() -> frozenset[str]:
    out: set[str] = set()
    for entry in open_entries():
        out.update(entry.gates)
    return frozenset(out)


def as_json() -> dict:
    return {
        "schema": "kinbase-acceptance-instrument-debt/1",
        "review": "detector-reviewer dispatch 003",
        "total_findings": len(LEDGER),
        "closed": len(closed_entries()),
        "open": len(open_entries()),
        "gates_with_open_debt": sorted(gates_with_open_debt()),
        "entries": [e.as_json() for e in LEDGER],
    }


def digest() -> str:
    return hashlib.sha256(
        json.dumps(as_json(), sort_keys=True).encode("utf-8")
    ).hexdigest()
