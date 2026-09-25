"""Reproducible auxiliary pool identity; no grant or Reviewer act is generated.

Preimage v1: the ASCII domain below, followed by four length-prefixed blocks.
Each length is an unsigned 8-byte big-endian byte count. Block 1 is the explicit
manifest projection, JSON encoded with sorted object keys, preserved array
order, ensure_ascii=True, separators=(',', ':'), allow_nan=False, UTF-8, and no
newline. Blocks 2-4 are the exact file bytes in DOCUMENTS order. SHA-256 hashes
this concatenation. Candidate/component bytes are bound via verified SHA-256s.
Only the fields named below enter the projection; mutable grant/selection state
and historical markers do not. No filesystem traversal order affects identity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from . import auxgen

ROOT = Path(__file__).resolve().parents[3]
AUXILIARY = ROOT / "tests/fixtures/auxiliary"
DOMAIN = b"kinbase-auxiliary-pool-digest/1\x00"
DOCUMENTS = ("RIGHTS.md", "GRANT-TEMPLATE.md", "SELECTION-PROTOCOL.md")
FIELDS = (
    "schema", "authority", "digest_field", "grant_template",
    "mutable_after_execution_begins", "reconstructor_denied",
    "reconstructor_receives", "reviewer_must_record", "selected_by",
    "selection_protocol", "selection_timing",
)
CANDIDATE_FIELDS = ("bytes", "path", "sha256", "topic", "version")
COMPONENT_FIELDS = ("entries", "kind", "path", "seed", "sha256")
GENERATION_FIELDS = ("schema", "reproduce_with", "seeds", "algorithms", "counts", "serialisation")
COMPONENTS = ("correlations", "decoys", "dictionaries")


def project(pool: dict) -> dict:
    result = {key: pool[key] for key in FIELDS}
    result["candidates"] = [
        {key: row[key] for key in CANDIDATE_FIELDS} for row in pool["candidates"]
    ]
    result["generated_components"] = [
        {key: row[key] for key in COMPONENT_FIELDS}
        for row in pool["generated_components"]
    ]
    result["generation"] = {key: pool["generation"][key] for key in GENERATION_FIELDS}
    for key in ("seeds", "algorithms", "counts"):
        result["generation"][key] = {
            name: pool["generation"][key][name] for name in COMPONENTS
        }
    return result


def preimage(pool: dict, directory: Path = AUXILIARY) -> bytes:
    core = json.dumps(project(pool), sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    blocks = [core] + [(directory / name).read_bytes() for name in DOCUMENTS]
    return DOMAIN + b"".join(len(block).to_bytes(8, "big") + block for block in blocks)


def compute(pool: dict, directory: Path = AUXILIARY) -> str:
    return hashlib.sha256(preimage(pool, directory)).hexdigest()


def verify(directory: Path = AUXILIARY, root: Path = ROOT) -> str:
    """Verify stored identities, actual content, counts, and generation recipe."""
    pool = json.loads((directory / "pool.json").read_bytes())
    digest = compute(pool, directory)
    if digest != pool["pool_digest_sha256"] or digest != (directory / "POOL-DIGEST").read_text().strip():
        raise ValueError(f"pool digest mismatch: computed {digest}")
    if pool["generation"] != auxgen.recipe():
        raise ValueError("generation recipe mismatch")
    regenerated = auxgen.regenerate()
    if not pool["candidates"] or len(pool["generated_components"]) != len(regenerated):
        raise ValueError("empty candidates or incomplete generated components")
    seen = set()
    for row in pool["candidates"] + pool["generated_components"]:
        path = (root / row["path"]).resolve()
        if not path.is_relative_to(directory.resolve()) or path in seen:
            raise ValueError(f"outside-pool or duplicate path: {row['path']}")
        seen.add(path)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError(f"content digest mismatch: {row['path']}")
        if row in pool["candidates"]:
            if len(raw) != row["bytes"]:
                raise ValueError(f"candidate byte count mismatch: {row['path']}")
        else:
            name = path.stem
            if name not in regenerated or raw != auxgen.serialise(regenerated[name]).encode("utf-8"):
                raise ValueError(f"component regeneration mismatch: {row['path']}")
            if row["entries"] != pool["generation"]["counts"][name] or row["seed"] != pool["generation"]["seeds"][name]:
                raise ValueError(f"component seed/count mismatch: {row['path']}")
    return digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool-dir", type=Path, default=AUXILIARY)
    parser.add_argument("--root", type=Path, default=ROOT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--default-selection", action="store_true")
    args = parser.parse_args()
    try:
        pool = json.loads((args.pool_dir / "pool.json").read_bytes())
        if args.verify:
            print(verify(args.pool_dir, args.root))
        elif args.default_selection:
            print(json.dumps(sorted(pool["candidates"], key=lambda row: row["path"]), indent=1, sort_keys=True))
        else:
            print(compute(pool, args.pool_dir))
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
        print(f"auxsel: {exc}", file=sys.stderr)
        return 1
    return 0


def require_review(directory: Path, pool: dict, digest: str) -> dict:
    """Check evidence structure and content binding; not signature authenticity.

    Validator must authenticate the human attestations and establish the
    implementation-blind selection's commit/timing in its experiment manifest.
    """
    from .requirements import HarnessInvalid

    missing = []
    grant = (directory / "GRANT.md").read_text(encoding="utf-8")
    attestation = directory / "RE-ATTESTATION.md"
    current = grant if digest in grant else (
        attestation.read_text(encoding="utf-8") if attestation.is_file() else ""
    )
    if digest not in current or "Signed: Jeremy McEntire" not in current:
        missing.append(f"Validator must obtain founder-signed RE-ATTESTATION.md reaffirming GRANT.md over {digest}")
    selection = directory / "SELECTION.json"
    if not selection.is_file():
        missing.append("implementation-blind Detector Reviewer must execute SELECTION-PROTOCOL.md steps 4-6: signed SELECTION.json and Validator manifest binding its exact SHA-256, commit and pre-implementation timing")
    if missing:
        raise HarnessInvalid("auxiliary corpus: " + "; ".join(missing))
    try:
        record = json.loads(selection.read_bytes())["selection_record"]
        for key in ("selection_procedure", "source_rights", "contents", "versions", "reviewer_signature"):
            if not record[key]:
                raise ValueError(f"empty selection {key}")
        if record["selected_by"] != "detector-reviewer" or record["pool_digest_sha256"] != digest:
            raise ValueError("selection owner or pool digest mismatch")
        chosen = record["candidates"]
        if not chosen or len({row["path"] for row in chosen}) != len(chosen):
            raise ValueError("empty or duplicate selection")
        if any(row not in pool["candidates"] for row in chosen):
            raise ValueError("selected candidate is not an exact frozen pool row")
        if record["versions"] != {row["path"]: row["version"] for row in chosen}:
            raise ValueError("selection versions mismatch")
        if record["generated_components"] != pool["generated_components"]:
            raise ValueError("selection generated components mismatch")
        signature = record["reviewer_signature"]
        if not all(signature[key] for key in ("name", "signature", "date")):
            raise ValueError("incomplete Reviewer signature")
        return record
    except (ValueError, KeyError, TypeError) as exc:
        raise HarnessInvalid(f"auxiliary selection invalid: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
