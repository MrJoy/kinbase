# Candidate Amendment 006 — Kinbase's tracked config is `.kin/kinbase.toml`

Status: **candidate; not authority until the founder and a distinct Validator
ratify its exact digest.**

## Why

The ratified artifacts name kinbase's tracked repository config `.kin/config`.
Kindex already owns that path, in YAML, and most repositories at one deployment
carry one.
Kinbase read Kindex's YAML as a malformed kinbase config and refused with
`DIGEST_MISMATCH`, so it could not be initialised in those repositories. Commit
`e970ae5` ("Give kinbase its own config filename so it can share .kin/ with
kindex", 2026-09-10) moved kinbase to `.kin/kinbase.toml`. The spec was not
updated. This amendment records the rename.

## Supersessions

In each passage below, kinbase's tracked config is `.kin/kinbase.toml` where the
ratified text says `.kin/config`:

1. `cli.md`, "Tracked `.kin/config` contains only schema version, repository
   UUID hint, safe name, domains, and local policy hints."
2. `cli.md`, first-run step 5: "commit only `.kin/config`, `.kin/events/`,
   `.kin/manifests/`, and the required `.gitattributes`."
3. `architecture.md`: "A tracked `.kin/config` contains only repository metadata
   and safe client hints."
4. `architecture.md`: "Existing `.kin/config` or Kinbase event paths with an
   incompatible schema block and preserve bytes."
5. `threat-model.md`, adversary item 11: "malicious `.kin/config` fields" covers
   `.kin/kinbase.toml`, and a `.kin/config` that names kinbase's schema (below).

The content rules are unchanged: the file still holds only schema version,
repository UUID hint, safe name, domains and local policy hints, and still
cannot name roots, keys, authorities or Company endpoints.

## Requirements

1. `repo init` writes `.kin/kinbase.toml`. It never writes, edits or removes
   `.kin/config`.
2. A `.kin/config` is Kindex's unless its bytes name kinbase's schema
   (`kinbase-repo/`). Kinbase ignores Kindex's file and never reports it as a
   kinbase error.
3. A repository initialised before the rename may still hold kinbase's TOML at
   `.kin/config`. Kinbase reads it when `.kin/kinbase.toml` is absent.
4. A `.kin/config` that names kinbase's schema but does not parse is kinbase's
   malformed config. It refuses with the integrity error and exit 5 that
   `cli.md` requires for malformed config, even when `.kin/kinbase.toml` is
   present. It is never silently skipped.
5. When both files are valid, `.kin/kinbase.toml` governs.

## Verification

- `tests/acceptance/test_nonfunctional.py::test_hostile_bytes_never_escape_the_exception_boundary`
  writes a hostile kinbase config to `.kin/config`; requirement 4 makes it
  refuse with exit 5.
- Requirements 1 and 2 (`repo init` in a repository whose `.kin/config` is
  Kindex YAML succeeds and leaves that file byte-identical) have no automated
  test yet; one should be added before ratification.
