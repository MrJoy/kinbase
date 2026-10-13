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
