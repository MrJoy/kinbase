# Changelog

Notable changes to Kinbase. Dates are UTC.

## Unreleased

## 0.1.2 - 2026-10-30

### Fixed

- `hooks install codex` writes nested hook groups (`{"hooks": [...]}`), the
  shape Codex runs, into `~/.codex/hooks.json` when the user keeps one. Earlier
  builds wrote flat entries Codex never ran; a reinstall replaces them (and
  takes them out of `config.toml` when the hooks move to `hooks.json`), and
  `doctor` no longer counts them.
- A Nix-store build no longer hooks its own store path, which the next update
  removes: it hooks the first executable `kinbase` on PATH outside the store,
  or refuses and says so.

## 0.1.1 - 2026-10-26

### Added

- `[company] gateway_api_key_file` for callers that cannot sign in through a
  browser (an agent sandbox): Company requests send `Authorization: ApiKey <key>`
  beside `X-Kinbase-Token`, and the https gateway URL is admitted as with OIDC.
  It cannot be combined with OIDC, and a routable `http://` URL is refused.

### Changed

- A `v*` release attaches its binaries to a draft and then publishes it, since
  published releases are immutable; a re-run finishes the draft.

## 0.1.0 - 2026-10-24

### Added

- Unchanged snapshot receipts. A full `/snapshot` now carries a signed `content_digest`;
  a client offers it back as `known`, and when its content is still Company's answer
  for that client's scopes and repository the service replies with a ~600-byte
  root-signed `kinbase-snapshot-unchanged/1` receipt (fresh nonce, cursors and
  validity clocks) instead of the snapshot. The cache keeps the content it verified,
  takes freshness from the receipt in one transaction, and falls back to one full
  refresh if another refresh replaced the content meanwhile. On a 22k-event store an
  unchanged refresh costs ~23 ms and 627 B instead of 443 ms and 12.1 MB, and one read
  against the hourly budget instead of the whole snapshot. `kinbase doctor` reports
  `cache_freshness_record`: which signed document the cache's clocks came from,
  re-verified.
- `kinbase auth login` signs in through a browser with any OIDC provider: it
  prints the sign-in URL, listens for the callback on loopback, and stores the
  session in a mode-0600 `oidc.json` beside `config.toml`. The three optional
  `[company]` keys are `oidc_issuer`, `oidc_client_id`, and
  `oidc_client_secret_file`; the issuer and client ID must be set together, and
  a partial configuration is refused. With OIDC configured, Company requests
  use an `https://` gateway, carry the ID token in `Authorization` and the facts
  token in `X-Kinbase-Token`, and automatically refresh the ID token before it
  expires; a plaintext routable URL is refused. Without OIDC, existing behavior
  is unchanged.

- `[company] snapshot_timeout_seconds` in the user config: how long a snapshot
  read waits for the Company service (integer 1..=600, default 20, the previous
  fixed bound). A snapshot costs what the whole Company log costs, and in
  one deployment at ~12k facts it outgrew 20 s, so every refresh reported
  `COMPANY_UNREACHABLE`; a deployment can now raise the ceiling without a new
  build. Only snapshot reads use it: checkpoint and Unknown posts from host hooks
  keep the 20 s default.

- Known-secret masking. A `[secret_mask]` table in the user config names env files
  (`files`), optional name selectors (`keys`) and a shortest value (`min_length`,
  default 8). Every selected value becomes `$NAME` before Kinbase digests, stores or
  signs it (hook envelopes, session transcripts, ingest scans, the query log, signed
  Fact and Unknown events) and before hook, projection, explain and other command
  output is printed. Off unless configured; a repository's config cannot set or
  weaken it. See README, "Masking known secrets".

- `kinbase dream`: the Personal store's maintenance, off the hook path. It
  compacts `observations`, `session-events`, `atoms`, `candidates` and
  `session-checkpoints` by identity (the first copy stands; an unreadable line is
  kept as it is), puts old checkpoints in the current form (receipts settled by an
  earlier checkpoint of the session are counted, not listed again; checkpoints
  that decided nothing are dropped), swaps each compacted ledger in under its lock
  and brings the ledger index fully up to date. Each replaced ledger is kept as
  `<ledger>.pre-dream-<unix seconds>` for a week. SessionEnd starts a detached
  dream at most once a day; `--force` runs one now. On a copy of a 1.6 GB store
  the first dream took 4.5 s: checkpoints 803 MB to 8.5 MB, observations 276 MB to
  175 MB, every identity and receipt kept.

### Changed

- The Company service reduces its log once per change instead of on every
  `/snapshot`, `/facts` page and `/facts/<id>`, keeping two reductions (the one at
  its own clock is never evicted) and rebuilding one at a time. A snapshot window
  loads only the events it sends. Responses are byte-identical; on a 22k-event store
  a cached `/snapshot` takes 0.44 s instead of 2.81 s and a `/facts` page 0.14 s
  instead of 1.31 s.
- At most two snapshots are assembled at once; a request beyond that gets a 503
  `LIMIT_EXCEEDED` naming the ceiling, and the client keeps its cached snapshot.
  Eight concurrent warm snapshots on that store went from +2 GB to +134 MB.

- A checkpoint that decided nothing (no admission, hold, failure, Personal fact
  or swept state) is no longer recorded; its counters are already in the ledgers.
  A checkpoint's id is now the digest of what it decided, so one that decided what
  an earlier one did (the same candidates held again) is recorded once. The hook
  response is unchanged apart from `checkpoint_recorded`.

### Fixed

- Stop, SessionEnd and PreCompact no longer slow down as the Personal store grows.
  A checkpoint appends without hashing the whole checkpoint ledger first, looks up
  its candidates' receipts in one read of the decision ledger, and counts candidates
  already admitted (`admissions_settled`) instead of admitting and listing them
  again. On an 832 MB checkpoint ledger a SessionEnd went from 2.65 s to 0.04 s,
  and a Stop in a session with 2,776 admitted candidates from 27.8 s to 0.45 s.
- A record seen again is no longer appended again. `observations`, `session-events`,
  `atoms` and `candidates` are deduplicated by identity (`observation_id`,
  `session_id` + `event_id`, `atom_id`, `candidate_id`), not by the bytes of the
  whole line, which differed whenever only a timestamp, nonce or confidence did; the
  first copy stands. A re-ingest after the Personal SQLite was recreated had
  re-appended 61,690 observations this way. The identity check and the session
  lookups at Stop, PreCompact and SessionEnd use `.ledger-index.sqlite3` beside the
  ledgers, a projection that follows the ledger, reads only what was appended since
  it last looked, and is rebuilt from the ledger when missing, stale or of another
  version. On a copy of a 1.6 GB Personal store, a Stop or SessionEnd with nothing
  to do went from 0.16 s to 0.02 s, a Stop in a 3,548-candidate session from 0.41 s
  to 0.29 s, and the per-prompt observe worker from 0.71 s to 0.15 s. A hook reads
  at most 64 MiB of ledger to bring the index up to date; further behind (the
  first run over an existing store), it does without the index and the dream pass
  indexes the ledger.
- Ingest no longer reads the whole Personal store on every run. It derives only
  the cohorts of the observations it reports (those sharing a logical key, or
  `source_kind:native_id`), which `derive` already derived from their own rows
  alone; counts an adapter's receipts in SQL; and looks for rows under a source's
  older identities before reading anything to adopt them. A re-ingest at 130,000
  observations went from 0.90 s and 532 MB to 0.03 s and 12 MB, with the same
  receipt. The two indexes this reads are built by the first ingest or dream, not
  by a hook. A quarantined record is identified by what failed, not when: the same
  bad record re-ingested is quarantined once.
- Masking known secrets no longer asks every value whether it occurs in every
  string: a prefilter on the values' leading bytes passes over text that holds
  none. A Stop masking a 3,548-candidate response went from 0.29 s to 0.22 s.
