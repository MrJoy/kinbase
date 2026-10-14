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

- Directories Kinbase creates now take the mode of the directory they are created
  in, and a file keeps group or other access only for a class that can traverse its
  directory. A new Personal store's event shard directories were created 0755 and
  its events 0644 under a 0700 root; they are now 0700 and 0600. An existing store
  keeps the modes it has, and new shards inherit them: its `events/` directories are
  likely 0755 already. Tighten them once by hand, for example
  `find <store> -type d -exec chmod 700 {} + && find <store> -type f -exec chmod 600 {} +`.
