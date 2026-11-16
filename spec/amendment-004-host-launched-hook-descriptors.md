# Candidate Amendment 004 — Descriptors a host leaks into a hook

Status: **candidate; not authority until the founder and a distinct Validator
ratify its exact digest.**

## Why

Two ratified passages assume kinbase's own launcher starts every shared process:

- `architecture.md`, "Sandbox startup proves both pathname denial and descriptor
  non-possession": the shared process "accepts only a frozen `CLOEXEC`-by-default
  allowlist";
- `amendment-001-rust-vast.md`, §2.1, under the process/capability table: "The
  host transfers only already-open, allowlisted descriptors or an authenticated
  narrow endpoint; startup rejects every additional inherited descriptor."

A native host hook breaks that assumption. Codex or Claude Code, not kinbase,
starts `kinbase hooks dispatch`, and kinbase cannot choose what the host passes
down. When a host leaks one open descriptor into its hooks, startup refuses with
`CONFIG_INVARIANT`, exit 4, on every event: SessionStart, UserPromptSubmit,
PreToolUse, PreCompact, Stop and SessionEnd. The host reports each one as a
failed hook, and no hook does its work. One reporter's log recorded 1,910
`hooks dispatch codex` calls, all exiting 4, while the 34 ordinary `kinbase`
commands in the same log exited 0.

The property these passages protect is **non-possession**: a shared process
never holds a descriptor it was not meant to have. Refusing startup is one way to
keep it. Closing the descriptor before any shared work is another, and it is the
only one a host-launched hook can apply.

## What this amendment supersedes

For a process started as `kinbase hooks dispatch <host> <event>` only, it
supersedes "startup rejects every additional inherited descriptor"
(`amendment-001-rust-vast.md`) and "accepts only a frozen `CLOEXEC`-by-default
allowlist" (`architecture.md`). On every other point, and for every other
command, the earlier artifacts govern unchanged.

## Requirements

1. **Personal first, unchanged.** Startup attestation enumerates every live
   descriptor and refuses, before any other step, a descriptor that is the
   Personal root or resolves under it (device/inode or resolved path), exactly as
   `architecture.md` requires: `CONFIG_INVARIANT`, exit 4, no shared work. A hook
   closes nothing in that case.
2. **Close the rest.** With no Personal descriptor present, a host-launched hook
   closes every remaining descriptor outside the allowlist (stdio plus the
   explicit `KINBASE_*_FD` values) before any shared work, and continues. It never
   reads from, writes to or duplicates a descriptor it closes.
3. **One enumeration.** The Personal check and the closing use the same
   enumeration, so a hook pays the descriptor scan once per event (`REVIEW.md`,
   "Hook cost is paid every turn").
4. **Say what was closed.** The hook writes one line to stderr,
   `{"kinbase":"closed_inherited_descriptors","descriptors":[<fd>, ...]}`:
   descriptor numbers only, never paths, file names or contents. The attestation
   record lists them as `closed_host_descriptors`.
5. **Everything else stays strict.** Every other command, including `doctor`,
   `status` and the shared projector, still refuses any additional inherited
   descriptor with `CONFIG_INVARIANT`, exit 4.

## Threat-model effect

None that widens the claim. A closed descriptor is not held, so non-possession
holds for a hook exactly as it does after a refusal. A descriptor whose path
cannot be resolved (a pipe, a socket, an unlinked file) was refused before and is
closed now; in neither case is it read. An adversary who controls the host
already controls every byte the hook is given, so accepting the host's leak adds
no capability. Threat-model item 19 (inherited open-Personal descriptors) and V-3
`inherited-fd` are unaffected: a Personal descriptor still fails startup.

## Verification

- `tests/hook_host_protocol.rs`,
  `a_descriptor_the_host_leaked_does_not_fail_the_hook`: a PreToolUse dispatch
  with a stray descriptor 9 exits 0 and names `[9]` on stderr. It exits 4 on the
  code before this amendment.
- `tests/hook_host_protocol.rs`,
  `a_leaked_personal_descriptor_still_fails_the_hook`: a dispatch holding the
  Personal root as descriptor 9 exits 4 naming the Personal root.
- `tests/acceptance/test_v3_privacy.py`,
  `test_inherited_personal_descriptor_fails_startup` (V-3 `inherited-fd`), keeps
  its expectation unchanged.
