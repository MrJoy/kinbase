# Command and configuration contract

Status: **candidate for review and exact-byte ratification**

Authority: product and architecture specifications. Commands emit canonical JSON
under `--json`; human output includes the same IDs, state, and remediation.

## Configuration

Launcher-only user config is
`${XDG_CONFIG_HOME:-~/.config}/kinbase/config.toml` (0600). Only the launcher reads
the whole file. It opens the Personal root for the Personal worker, then constructs a
separate shared-process configuration that contains no Personal path, descriptor,
environment variable, or serialized parent config. Every process reports its granted
capability names under `doctor --json`.

Minimal user config:

```toml
schema_version = "1"

[personal]
data_root = "/private/example/kindex" # required; launcher and Personal worker only

[company]
url = "http://127.0.0.1:8421"
facts_token_file = "/private/example/kinbase/facts.token"
root_public_key_file = "/private/example/kinbase/company-root.pub"
cache_root = "/private/example/kinbase/cache"

[classifier]
executable = "/opt/example/bin/local-classifier"
executable_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
args = ["--json"] # local, or current authorized host processor
timeout_seconds = 20

[hosts]
codex_version = ">=0.0.0"
claude_version = ">=0.0.0"
```

Directory and administrative token files are optional, separate capabilities and
are never forwarded to the ordinary coding process. Missing config selects
Codebase-only mode: without an out-of-tree certificate, `status`/`fsck` show counts
and `UNVERIFIED`, but event bodies never enter a host/model projection. A repository
without `.kin/` starts with no Codebase facts and offers `kinbase repo init`;
ordinary coding remains available.

Service config is an explicit `kinbased.toml` (0600) naming Company ID, SQLite
path, bind address (loopback only in the PoC), bearer-token file, root key file,
retention, freshness, and rate ceilings. Malformed or unsafe config fails startup.

```toml
schema_version = "1"
company_id = "company-demo"
sqlite_path = "/private/example/kinbase/company.sqlite3"
bind = "127.0.0.1:8421"
root_key_file = "/private/example/kinbase/company-root.key"
facts_token_file = "/private/example/kinbase/facts.token"
directory_token_file = "/private/example/kinbase/directory.token"
auth_failures_per_minute = 10
default_fact_freshness_seconds = 3600
candidate_lifetime_seconds = 900
clock_skew_seconds = 300
nonce_retention_seconds = 604800 # must be greater than lifetime + skew
```

Company cache directories are mode 0700. Facts tokens enumerate exact
`authority_scope` strings; a missing/empty list grants nothing and no wildcard syntax
exists. Startup refuses a nonce-retention ordering violation before binding the port.

Tracked `.kin/config` contains only schema version, repository UUID hint, safe name,
domains, and local policy hints. It cannot name roots, keys, authorities, or Company
endpoints. `.kin/manifests/` and `.kin/events/` are signed shared state;
`.kin/local/` is ignored private/cache state.

```toml
schema_version = "kinbase-repo/1"
repository_uuid_hint = "018f0000-0000-7000-8000-000000000001"
safe_name = "example-service"
domains = ["scheduling", "api"]
```

`repository_uuid_hint` is not trust; the out-of-tree signed certificate is. Unknown
keys and missing required keys fail closed. Examples are illustrative paths, not
defaults.

Executable configuration requires an absolute regular-file path, owner equal to the
effective UID, a pinned SHA-256 rechecked immediately before every spawn, no PATH or
shell resolution, a scrubbed environment, and a containing directory not writable by
group/other. `doctor --json` reports path/digest/processor scope, never input bytes.

## Initialization and service

```text
kinbase company init --config kinbased.toml
kinbase company serve --config kinbased.toml
kinbase repo issue --repo PATH --company URL
kinbase repo init --repo PATH --certificate FILE
kinbase repo publish-manifest --repo PATH
kinbase status [--repo PATH]
kinbase doctor [--host codex|claude] [--repo PATH]
```

Initialization previews every created path and certificate subject before requiring
the appropriate steward/maintainer signature. There is no trust-on-first-use flag.
`repo publish-manifest` sends the maintainer-signed dated default-branch observation
to Company and refuses a count regression without a signed rewrite/rollback event.

## First working session

The Company steward performs steps 1–3 once; a repository maintainer performs 4–5;
the developer performs 6–9:

1. Preview and initialize the loopback Company service:
   `kinbase company init --config kinbased.toml`, then
   `kinbase company serve --config kinbased.toml`.
2. Verify `kinbase status --json` reports the Company ID, cursor, token scopes, and
   no raw key values.
3. Register authorities, including an exact `architecture:<scope>` Chief Architect
   and any `environment:<id>` deploy owner, through the signed authority commands.
4. In the repository, run `kinbase repo issue --repo . --company
   http://127.0.0.1:8421`; inspect and sign the displayed repository UUID certificate.
5. Run `kinbase repo init --repo . --certificate <outside-worktree-file>` and
   commit only `.kin/config`, `.kin/events/`, `.kin/manifests/`, and the required
   `.gitattributes`. Then publish the signed branch observation with
   `kinbase repo publish-manifest --repo .`.
6. Create the launcher-only user config and run `kinbase doctor --host codex
   --repo .` (then Claude). The doctor must show that shared processes lack Personal.
   It also attests the classifier's descriptor-backed executable digest, the closed
   child-fd allowlist, and absence of any descriptor under the Personal root; a
   pathname-only check does not pass.
7. Run `kinbase hooks plan codex`; review the exact host file/command/permission
   diff. Run `kinbase hooks install codex` only after the host presents its native
   approval. Repeat for Claude. Refusal leaves config untouched and doctor explains
   the missing hook.
8. Start a real host session in the repository. SessionStart prints verified Company
   and Codebase fact IDs/Unknowns; prompt, pre-edit, PreCompact, and Stop events are
   captured without querying Personal history.
9. Inspect one proposal with `kinbase proposals show`, approve only its displayed
   destination/digest, run `kinbase fsck --repo .`, and commit the new signed
   `.kin` event/manifest together with the codebase knowledge it records.

At every step, a missing dependency returns the typed safe state below. No command
silently invents a root, owner, or approval.

## Corpus and inspection

```text
kinbase ingest SOURCE_KIND SOURCE [--repo PATH] [--checkpoint ID]
kinbase corpus rebuild --store personal|company|codebase --repo PATH
kinbase fsck --repo PATH [--full]
kinbase explain LOGICAL_KEY --repo PATH --decision TEXT
kinbase project --repo PATH --task TEXT --decision TEXT --working-set ID...
```

`ingest` returns adapter receipt and observation/fact counts, never success by count
alone. `explain` shows reducer steps, rejected events, current/conflict/Unknown state,
and evidence that would change it. Ceiling breaches return omitted/refused counts.

## Session, candidates, and approval

```text
kinbase session start --host codex|claude --repo PATH
kinbase session observe SESSION --event FILE
kinbase session checkpoint SESSION
kinbase session end SESSION
kinbase proposals list --session SESSION
kinbase proposals show CANDIDATE --destination DESTINATION
kinbase proposals decide CANDIDATE --destination DESTINATION \
  --approve-digest SHA256|--reject|--defer|--escalate
kinbase proposals reissue CANDIDATE
kinbase proposals reset --after-primary-event EVENT_ID \
  --reason-code new-primary-task|operator-recovery|host-restart
```

`show` parses one immutable canonical buffer and renders both a legible field view and
the exact escaped UTF-8 bytes whose digest is signed. The renderer never fetches a
second copy. C0/C1 controls, bidi formatting controls, and Unicode noncharacters are
rejected before signature verification; printable ASCII is literal and every other
code point plus quote/backslash is rendered in a frozen bijective escape form whose
round trip must equal the signed buffer. Example:

```text
Candidate: cand_7f...       Destination: codebase:018f...
Statement: Scheduler diagnosis must use deployed lookahead, not the source default.
Scope: scheduler/diagnosis    Kind: constraint    Expires: 2026-09-05T04:15:00.000Z
Omitted: personal anecdote; participant name; transcript path
Authority required: repository-maintainer:maint_2a...
Canonical UTF-8 (exact): {"atom_kind":"constraint","scope":"scheduler/diagnosis","statement":"Scheduler diagnosis must use deployed lookahead, not the source default."}
SHA-256: 8f2c...91a0
Approve only these bytes:
  kinbase proposals decide cand_7f... --destination codebase:018f... --approve-digest 8f2c...91a0
```

`approve-digest` is accepted only when it matches the inline immutable bytes bound to
candidate, destination, session, nonce, principal, and expiry. The destination
writer receives those bytes inline and never reads a candidate pathname. Expiry
during review refuses. `reissue` re-runs current eligibility/scanning and creates a
new candidate ID, nonce, digest, and expiry only if the source still exists and its
revision/rendered bytes changed or 24 hours passed; it never reuses approval or
bypasses prompt reservation.
`defer` expires the candidate without publishing and may create a Personal reminder;
it is not a durable shared approval queue. Core atomically reserves a display slot
before rendering; every destination draws from the same four-slot
`(principal_id,host_instance_id)` sliding-hour shard even if the host later crashes or
the candidate expires. The hourly
ceiling cannot reset and clears only with time. `reset` only clears the three-
consecutive counter after a real new primary-task event, is limited to once per hour,
and records its closed reason code. `escalate` creates an owned Unknown from the
candidate's frozen question template. Decision/reset commands accept no free-text
edits, annotations, answers, or replacement bytes, and their control codes never
enter a fact or experiment context. Suppressed suggestions remain private until expiry
and their count is shown. No accept-all command exists.

## Questions and authorities

```text
kinbase questions list [--owner SELF]
kinbase questions ask QUESTION_ID
kinbase questions answer QUESTION_ID --answer-file FILE --key-file FILE
kinbase questions status QUESTION_ID
```

`ask` delivers through the registry channel and records a receipt. Only the resolved
named in-scope authority may answer. Missing owner becomes a Company-steward Unknown;
timeout executes the recorded degraded policy.

## Hosts and experiments

```text
kinbase hooks plan codex|claude
kinbase hooks install codex|claude
kinbase hooks dispatch codex|claude EVENT
kinbase experiment census MANIFEST
kinbase experiment pilot MANIFEST
kinbase experiment calibrate MANIFEST
kinbase experiment freeze MANIFEST --budget FILE
kinbase experiment run FROZEN_MANIFEST
kinbase experiment score RUN
kinbase experiment verdict RUN
```

`hooks plan` is read-only. `install` invokes the host's normal user approval path and
cannot bypass it. `hooks dispatch` is the host-invoked internal entry point; ordinary
users do not type it. `census` emits the full examined/eligible/excluded population and
seeded draw. `calibrate` freezes scorer reliability, threat detector controls, model
fingerprints, and oracle-leakage controls on excluded/synthetic inputs. `freeze`
refuses without census, power/MDE/cost results, valid calibration, and exact human
budget ratification. `run` writes its signed run-census row before any candidate call
and enforces the frozen aggregate ceiling. `verdict` has only the states in the
verification strategy.

## Error contract

Errors are JSON objects with `code`, `message`, `remediation`, `retryable`, and
`evidence_id`; human output preserves all five. This closed proof-version taxonomy
may grow only through a new schema version.

| exit | meaning | scripting rule |
|---:|---|---|
| 0 | requested operation completed | continue |
| 1 | unused, reserved to prevent ambiguous generic failures | treat as implementation defect |
| 2 | named human/user action is required, with no unsafe state change | stop and present remediation; do not retry blindly |
| 3 | degraded but safe; affected facts withheld | coding may continue, trusted claim may not |
| 4 | policy, capability, or authority refusal | do not retry until authority/input changes |
| 5 | integrity/privacy product failure | halt affected writes and execute leak/integrity runbook |
| 6 | declared dependency unavailable | retry only when `retryable=true` and within bound |
| 70 | internal or acceptance-instrument failure | preserve evidence; no product pass |

`hooks dispatch` answers a host, not a script, and hosts read exit 2 as an instruction
to block: Claude Code refuses the tool call, or refuses to stop and runs the Stop hook
again, so a user-action refusal inside a hook would stall or loop the session. When a
host invokes it, `hooks dispatch` therefore reports every exit-2 refusal as exit 3,
with the same `code`, `message` and `remediation` on stderr; no other exit changes, and
the same refusal from an ordinary command still exits 2.

| code | trigger | exit | retryable | example remediation |
|---|---|---:|:---:|---|
| `COMPANY_UNREACHABLE` | Company endpoint cannot answer within timeout | 6 or 3 on safe cached read | yes | Restore endpoint or continue with named facts withheld. |
| `CACHE_EXPIRED` | fact/cache freshness elapsed | 3 | yes | Refresh Company state; do not use the stale fact. |
| `REVOCATION_STALE` | revocation snapshot expired | 3 | yes | Refresh authority cursor; safety facts remain withheld. |
| `REPO_UNCERTIFIED` | no valid out-of-tree repository certificate | 2 | no | Ask a steward to issue and maintainer to install the displayed UUID certificate. |
| `FOREIGN_REPO_EVENTS` | events bind another repository UUID | 4 | no | Inspect counts; obtain signed lineage or remove them from this repository history. |
| `SIGNATURE_INVALID` | domain-separated signature fails | 5 | no | Quarantine bytes and contact the named owner; never resign locally. |
| `DIGEST_MISMATCH` | canonical bytes/path/reference digest disagree | 5 | no | Run full fsck and compare Company's published digest before assigning blame. |
| `DIGEST_ALGORITHM_UNSUPPORTED` | Company digest version is unknown | 3 | no | Upgrade the adapter; do not recompute with a guessed algorithm. |
| `MANIFEST_INCOMPLETE` | expected heads/events are missing | 5, or 3 for declared sparse checkout | no | Fetch full history/`.kin`, or ask the maintainer to reconcile the signed head set. |
| `MANIFEST_HEAD_REGRESSION` | published reachable lineage lowers event count without rewrite event | 4 | no | Supply a maintainer-signed rollback/rewrite event or correct the publication. |
| `LIMIT_EXCEEDED` | size/rate/cost ceiling would be crossed | 4 | conditional | Reduce one bounded input or obtain a new ratified run budget; never truncate silently. |
| `APPROVAL_EXPIRED` | candidate/token expired before commit | 2 | no | Reissue the candidate and review its new exact bytes/digest. |
| `APPROVAL_REPLAY` | consumed nonce is reused with nonmatching bytes/destination, or a registry document does not advance the published authority cursor | 4 | no | Use the original receipt or create/review a new candidate; publish a newly signed registry at a newer cursor. |
| `AUTHORITY_WRONG_SCOPE` | signer does not own exact scope | 4 | no | Resolve the registered authority; role prestige cannot widen scope. |
| `AUTHORITY_SCOPE_DENIED` | token lacks exact canonical authority scope | 4 | no | Issue a least-privilege exact-scope token; empty and wildcard-like sets grant nothing. |
| `UNKNOWN_OWNER_UNRESOLVED` | no exact person/closing authority can be resolved | 3 | yes | Company steward repairs the registry entry before guidance is trusted. |
| `PERSONAL_TAINT_BLOCKED` | hard-blocking secret/canary/private identifier reaches shared admission | 5 | no | Keep source private; create a new safe source rather than clearing taint. |
| `HOOK_APPROVAL_REQUIRED` | host has not approved planned hook/config changes | 2 | no | Review `hooks plan` and use the host's native approval flow. |
| `UNSUPPORTED_HOST_VERSION` | native Codex/Claude envelope is outside tested range | 3 | no | Upgrade Kinbase adapter or use a supported host; do not guess the envelope. |
| `UNSUPPORTED_KINDEX_VERSION` | Personal/legacy adapter seam conformance fails | 3 | no | Install pinned Kindex 0.36.0 or add and ratify a compatibility adapter. |
| `PROCESSOR_UNAUTHORIZED` | model/network request exceeds named processor scope | 5 | no | Use a local/current authorized processor or keep the input private. |
| `MODEL_FINGERPRINT_CHANGED` | paired experimental block observes a different model fingerprint | 70 | no | Before launch admission, consume only a preregistered reserve; after admission, preserve and invalidate the run without replacement. |
| `ORACLE_LEAKAGE` | patch/test/post-change-only content enters an agent context | 70 | no | Invalidate the run and repair the pre-dispatch oracle instrument. |
| `SCORER_UNCALIBRATED` | blinded ordinal scorer kappa is below 0.80 | 70 | no | Stop before measurement; qualify independent scorers on excluded pilots. |
| `RUN_CENSUS_MISSING` | benchmark action lacks its pre-launch signed census row | 70 | no | Invalidate launch; never relabel it smoke/debug. |
| `CONFIG_INVARIANT` | retention, clock, mode, or capability ordering is unsafe | 4 | no | Correct the named values; startup changes no state. |
| `RUN_INTEGRITY_FAILED` | outcome-blind auditor observes a frozen manifest/runtime mismatch | 70 | no | Preserve the run; an admitted outcome cannot be dropped or replaced. |

Common first-run failures are fixed, not guessed:

| situation | result |
|---|---|
| no user config | Codebase-only, zero trusted facts unless an out-of-tree certificate resolves |
| unreadable token or key file | exit 4 with exact path role, never file contents |
| token/key mode broader than 0600 | exit 4; chmod remediation |
| Company unreachable during repo init | exit 6; no certificate/root is cached from worktree bytes |
| command outside a Git worktree | exit 2 (exit 3 from host `hooks dispatch`); ordinary non-repo Personal session may continue |
| requested store uninitialized | exit 2 with exact `company init` or `repo init` command |
| unwritable data root | exit 4 before partial schema creation |
| malformed certificate/config | exit 5 and quarantine; no trust-on-first-use fallback |

The CLI installs one top-level exception boundary that emits the typed internal error
and exits 70 for every caught application exception. Exit 1 can occur only before
that boundary exists (for example interpreter/loader failure) and therefore still
means the executable itself failed outside its contract.
