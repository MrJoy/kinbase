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
  to 0.29 s, and the per-prompt observe worker from 0.71 s to 0.15 s. The first run
  builds the index once (1.6 s on that store).
