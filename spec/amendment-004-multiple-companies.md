# Candidate Amendment 004 — Several Companies for one person

Status: **candidate, revision 1; not authority until ratified**

## Reader summary

A person who works for several organizations needs each one to be its own Company:
its own root key, facts, authorities and certificates. The launcher config admits one
`[company]`, so today that person either merges organizations into one Company,
which carries one organization's rulings into another's coding sessions, or swaps
`XDG_CONFIG_HOME` per invocation, which the installed host hooks cannot follow.

This candidate adds a named form, `[companies.<name>]`, and one rule: **the launcher
selects at most one Company per invocation, from the repository the invocation acts
on, and selection only narrows.** Everything after selection is today's
single-Company product, so the ratified "one externally configured Company root"
(architecture.md, "Trust and key lifecycle") holds per repository and per invocation. Whenever
the evidence on this machine does not point at exactly one configured Company, the
answer is a refusal, never a pick.

The implementation accompanying this candidate stays inside the ratified text: the
user config holds Company endpoints and "repository-discovery hints"
(architecture.md), worktree `.kin/` names nothing, no endpoint comes from the
environment (ruling C28), and the error taxonomy is unchanged (refusals are
`CONFIG_INVARIANT` with a `detail.reason`). This candidate makes that reading
explicit and adds the named form to cli.md.

## 1. Configuration (amends cli.md "Configuration")

The single form is unchanged. The named form is mutually exclusive with it:

```toml
[companies.globex]
url = "http://127.0.0.1:8421"
facts_token_file = "/private/example/globex/facts.token"
root_public_key_file = "/private/example/globex/company-root.pub"
cache_root = "/private/example/globex/cache"
discovery_hints = ["github.com/globex/*"]

[companies.acme]
url = "http://127.0.0.1:8422"
facts_token_file = "/private/example/acme/facts.token"
root_public_key_file = "/private/example/acme/company-root.pub"
cache_root = "/private/example/acme/cache"
discovery_hints = ["github.com/acme-corp/*", "gitlab.acme.example/platform/**"]
```

- `M-01` Names are 1-32 characters of `a-z`, `0-9`, `-`. Each table accepts every
  `[company]` key with the same meaning, plus `discovery_hints`.
- `M-02` `discovery_hints` are normalized exactly as an origin is for pins
  (lowercase; scheme and `git@` removed; `:` to `/`; `.git` removed). `*` matches
  within one path segment, `**` across segments.
- `M-03` Two Companies sharing a `url`, a `root_public_key_file`, or overlapping
  `cache_root`s is refused when the config is read.
- `M-04` Client and maintainer keys default to `<config dir>/companies/<name>/`.
  A defaulted per-Company key that is absent while the single-form key exists is
  refused rather than minted, so converting `[company]` to `[companies.x]` keeps its
  identity or stops with the line to add.
- `M-05` `[identity] maintainer_key_file` presents one key to several Companies only
  with `[identity] share_maintainer_key = true`; otherwise it is refused while two or
  more Companies are configured.
- `M-06` `KINBASE_CLIENT_KEY_FD` carries one key and is refused under the named form.

## 2. Selection

- `S-01` The target is the repository the invocation acts on (`--repo`, the host
  envelope `cwd`, else the process cwd); `repo issue --company <name>` names a
  Company; `repo init` counts the certificate being installed as evidence.
- `S-02` Evidence, from configured Companies only: a Company **holds** the repository
  when its cache keeps a certificate for the `repository_uuid_hint` that verifies
  against its own root; its `discovery_hints` match the normalized origin; its cache
  pins that origin.
- `S-03` One Company in the union of the evidence is selected; none is Codebase-only
  mode; two or more is `CONFIG_INVARIANT` `company-ambiguous`. No kind of evidence
  overrides another. The UUID is worktree bytes and a certificate binds no origin, so
  a worktree that copied another organization's `.kin/kinbase.toml` must not outvote
  its own origin.
- `S-04` Evidence that cannot be read (root key, cache, certificate) refuses
  (`company-unverifiable`); it never turns into a fall-through to another Company.
- `S-05` Selection grants no trust. The selected Company's build_trust still checks
  signature, pins, revocation and freshness, and fails closed as today.
- `S-06` `repo issue --company <name>` refuses `certified-elsewhere` when another
  configured Company holds or pins the repository, and `company-ambiguous` when
  another Company's `discovery_hints` match its origin: S-03 would refuse to install
  the certificate it issued.

## 3. Hosts and sessions

- `H-01` Hooks need no reinstall: dispatch selects by the envelope `cwd`.
- `H-02` A refused or empty selection never blocks the host. SessionStart projects no
  Company or trusted Codebase facts, adds a constant notice to the context, and on
  Claude a constant `systemMessage` the person sees.
- `H-03` Hook output carries no Company name, URL, cache path or company_id of a
  Company other than the selected one; names appear only in `status` and `doctor`.
- `H-04` A Company candidate minted under the named form has destination
  `company:<company_id>` and records its `repository_uuid`. A checkpoint admits it
  only from that repository with that Company selected; otherwise it is held.
  A `company:root` candidate is held under the named form. The single form's records
  are unchanged.
- `H-05` `project --evidence-repo` refuses an evidence repository that resolves to a
  different Company (`company-mismatch`): a projection holds one Company view
  (amendment-001).

## 4. Stores

- `P-01` Revocation watermarks are keyed by company_id under the named form. A
  watermark recorded under the single form names no Company and carries over to
  none: a cached snapshot that lacks a revocation may only be stale, so nothing on
  this machine proves which Company recorded it. Each Company starts a fresh
  watermark, which reopens more history rather than less.
- `P-02` With no Company selected, local Company records go to a per-repository
  directory, never one shared fallback.

## 5. New identity

There is no cross-Company lineage event in code. A repository that was copied,
forked or moved to another organization gets a new identity: delete
`.kin/kinbase.toml`, then `repo issue --company <name>` and `repo init`. The old
certificate stays held for the old UUID, which nothing points at.

## 6. Limitations and follow-ups

- `certified-elsewhere` is a client-side check over this machine's caches; a Company
  server still certifies a UUID it did not mint. Server-side mint-only issuance is a
  follow-up.
- Deleting a Company's `cache_root` is the purge; Personal-store keys that name its
  company_id or repository UUIDs remain. A `company forget <name>` command is a
  follow-up.
- `corpus_last_view_digest` already changes with the repository; unchanged.
- Backups and other tools that read the Personal store are outside the threat model,
  as for Personal conversations today.
- Pre-existing under the single form: a copied UUID pins a new origin silently. The
  named form refuses when another Company claims that origin; the single form does
  not change here.
- Moving a repository between Companies with its signed history needs a lineage
  event; a follow-up.
- Dedicated error codes instead of `CONFIG_INVARIANT` reasons would amend the
  taxonomy.
- Removing a Company makes its cache stop being evidence; a remaining Company's
  overlapping hint may then select its repositories, and build_trust fails closed
  because no remaining root verifies their certificates.
