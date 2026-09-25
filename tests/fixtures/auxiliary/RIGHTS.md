# Auxiliary-corpus rights basis

## Status: grant recorded; current-digest re-attestation and selection pending

The supplied `GRANT.md` names Jeremy McEntire of Wander, asserts authority based
on his role as VP of Engineering at Wander, and is signed and dated
2026-09-09T20:42:31Z. Clauses 1-4 identify the five candidate documents, dedicate
them under CC0 1.0, and expressly permit local evaluation and transmission to
the model provider named in the experiment manifest. `pool.json.rights_basis`
transcribes these claims and records the grant's content digest. The local
`CC0-1.0.txt` digest matches the legal-code digest in clause 3.

Finding 21's missing human grant is closed with that supplied grant as evidence.
This is an attestation, not independent proof of authorship, signature authenticity,
employment authority, or legal sufficiency. The Tester still claims that the
candidate source bytes originated in this lane without reproduced third-party
text; repository history can corroborate that claim but cannot prove legal title.

The signature in clause 5 cites the superseded, never-reproducible pool digest.
The Tester preserves `GRANT.md` exactly. The Validator must obtain the founder's
re-attestation over the reproducible current `POOL-DIGEST` before selection.
`selectable: true` records the supplied grant's permissions and pool eligibility;
it does not attest completion of that precondition or of independent selection.
The qualification test refuses missing current-digest attestation or selection.

## Reproducible corpus identity

`python3 -m acceptance._harness.auxsel --verify` (from `tests/`) verifies the
explicit manifest projection, exact rights/protocol/template bytes, candidate
content, and seed-generated components. The framing, serialization and assembly
order are defined in `auxsel.py` and summarized by `digest_binds`. Grant status,
grant bytes, selection evidence and historical digest markers are excluded to
avoid circular signatures. No old digest preimage has been fabricated.

The implementation-blind Detector Reviewer owns steps 4-6 of
`SELECTION-PROTOCOL.md`; `selection_record` stays null until that pass. The
Validator owns obtaining and retaining the current-digest re-attestation.
