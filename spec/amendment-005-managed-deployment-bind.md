# Candidate Amendment 005 — A managed deployment may bind beyond loopback

Status: **candidate; not authority until the founder and a distinct Validator
ratify its exact digest.**

## Why this file exists

PR #24 (`9fb7fa4`, "Let a managed deployment bind somewhere other than
loopback") wrote its spec changes directly into three ratified artifacts:
`architecture.md`, `verification.md` and `cli.md`. Their bytes then no longer
matched `ratification-manifest.json`, and the acceptance suite refused every run
with `INVALID_HARNESS`. Those three files are restored to their ratified bytes,
and the same text is carried here, word for word, as a candidate overlay. The
product behaviour (`allow_non_loopback`, default off) is unchanged.

## Supersessions

Each item names the ratified passage and the text that replaces or follows it.

### `architecture.md`, Company / Kinbase

1. In "Every endpoint, including reads, requires a per-instance bearer token
   loaded from a mode-0600 file, exact loopback Host validation, absent Origin
   header, and JSON content type for bodies", replace "exact loopback Host
   validation" with "loopback Host validation unless opted out".

2. After the paragraph ending "the security claim against a local same-UID
   process rests on scoped token plus client-key request signature, not those
   headers.", add:

   > A deployment may set `allow_non_loopback`, which lifts the bind, Host and
   > client endpoint rules together so the service can be reached through a
   > cluster Service name. Doing so moves the peer set from the operator's own
   > processes to everything the network permits, and the transport is
   > cleartext: the endpoint parser accepts `http://` only, so TLS is
   > unreachable rather than merely absent, and the bearer token crosses the
   > network on every request. The signature does not narrow this. A request
   > supplies its own client key, and while a token and key pair is recorded the
   > first-use binding that would pin them is not yet enforced, so an observer
   > of one request can mint a fresh key and sign for the same token. On a
   > routable bind the token is therefore the whole credential.
   >
   > Isolation for such a deployment comes from the network, not from the
   > service: ingress denied by default, and no workload admitted to the port
   > that is not meant to read the store. That is an accepted risk of the
   > managed shape rather than a property of the proof, and it is recorded here
   > so it is not inherited silently. A transport option for operators wanting
   > defence in depth, and enforcement of the first-use client-key binding,
   > remain open.

### `architecture.md`, host SessionStart budget

3. Replace "launches asynchronous Company refresh with a 250-millisecond
   connection budget; a blackholed endpoint cannot hold the host open" with
   "launches asynchronous Company refresh with a 250-millisecond connection
   budget and, where the endpoint names a host rather than a literal, a separate
   250-millisecond resolution budget ahead of it, so a refresh that must resolve
   is bounded at 500 milliseconds; a blackholed endpoint cannot hold the host
   open".

### `verification.md`

4. Replace "Company connect budget is 250 ms, cold/degraded projection is empty"
   with "Company connect budget is 250 ms, with a separate 250 ms resolution
   budget where the endpoint names a host, cold/degraded projection is empty".

5. Replace "Kinbase HTTP rejects unauthenticated reads, non-loopback Host,
   Origin-bearing requests, and non-JSON writes; all receive typed
   remediation-safe errors." with "Kinbase HTTP rejects unauthenticated reads,
   Origin-bearing requests, and non-JSON writes; all receive typed
   remediation-safe errors. A non-loopback Host is rejected unless
   `allow_non_loopback` is set, which a managed deployment sets because it is
   reached through a cluster Service name rather than a literal."

### `cli.md`

6. In the service config sentence, replace "bind address (loopback only in the
   PoC)" with "bind address (loopback unless `allow_non_loopback` is set)".

## What does not change

Every other ratified passage. With `allow_non_loopback` unset, which is the
default, the service, Host checks and client endpoint behave exactly as the
ratified text says.
