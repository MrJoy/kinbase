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
