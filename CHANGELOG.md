# Changelog

Notable changes to Kinbase. Dates are UTC.

## Unreleased

### Added

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
