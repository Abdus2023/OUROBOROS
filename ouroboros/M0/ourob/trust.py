"""External journal trust anchor (M1.5).

A hash chain proves the journal is internally consistent; it does not prove
the journal is the *same* journal that existed earlier, because an attacker
who can rewrite the file can recompute every digest. A ``JournalTrustAnchor``
is a small record — sequence number + digest of the record at that sequence,
optionally bound to a repository generation — that is held **outside** the
mutable journal (operator storage, CI secret, signed artifact, etc.).

``verify_anchor`` checks that the journal prefix ending at ``anchor.sequence``
still hashes to the anchored digest. It fails closed on:

* whole-history rewrite (digest at the sequence differs);
* truncation before the checkpoint (journal shorter than the anchor);
* generation mismatch (anchor bound to a different repository generation).

The journal never writes, rotates or selects its own anchor.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:  # pragma: no cover
    from .journal import JournalRecord

ANCHOR_SCHEMA = "ourob.trust-anchor.v1"


class TrustAnchorError(RuntimeError):
    pass


@dataclass(frozen=True)
class JournalTrustAnchor:
    sequence: int
    journal_digest: str
    generation: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise TrustAnchorError("anchor sequence must be a positive integer")
        if not isinstance(self.journal_digest, str) or len(self.journal_digest) != 64:
            raise TrustAnchorError("anchor journal_digest must be a 64-hex SHA-256 digest")
        if self.generation is not None and (not isinstance(self.generation, str) or len(self.generation) != 64):
            raise TrustAnchorError("anchor generation must be a 64-hex generation id or None")

    def canonical_bytes(self) -> bytes:
        payload = {
            "schema": ANCHOR_SCHEMA,
            "sequence": self.sequence,
            "journal_digest": self.journal_digest,
            "generation": self.generation,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def binding_digest(self) -> str:
        """Content address of the anchor itself (for cross-referencing/logging)."""
        return sha256(self.canonical_bytes()).hexdigest()

    def to_record(self) -> dict[str, Any]:
        return {
            "schema": ANCHOR_SCHEMA,
            "sequence": self.sequence,
            "journal_digest": self.journal_digest,
            "generation": self.generation,
        }

    @classmethod
    def from_record(cls, record: Any) -> "JournalTrustAnchor":
        if not isinstance(record, dict):
            raise TrustAnchorError("anchor record must be an object")
        if record.get("schema") != ANCHOR_SCHEMA:
            raise TrustAnchorError(f"unsupported anchor schema: {record.get('schema')!r}")
        if set(record) != {"schema", "sequence", "journal_digest", "generation"}:
            raise TrustAnchorError("anchor record has unexpected fields")
        return cls(record["sequence"], record["journal_digest"], record.get("generation"))

    @classmethod
    def capture(cls, records: Sequence["JournalRecord"], generation: str | None = None) -> "JournalTrustAnchor":
        """Build an anchor for the *current* journal head. This helper exists so
        an external authority can capture anchors; the journal itself never calls it."""
        if not records:
            raise TrustAnchorError("cannot anchor an empty journal")
        head = records[-1]
        return cls(head.sequence, head.digest, generation)


def verify_anchor(
    anchor: JournalTrustAnchor,
    records: Sequence["JournalRecord"],
    generation: str | None = None,
) -> None:
    """Prove that ``records`` extends the prefix the anchor describes."""
    if anchor.generation is not None and generation is not None and anchor.generation != generation:
        raise TrustAnchorError("anchor is bound to a different repository generation")
    if len(records) < anchor.sequence:
        raise TrustAnchorError(
            f"journal truncated before trust anchor: anchor sequence {anchor.sequence}, journal length {len(records)}"
        )
    candidate = records[anchor.sequence - 1]
    if candidate.sequence != anchor.sequence:
        raise TrustAnchorError("journal sequence numbering does not match anchor")
    if candidate.digest != anchor.journal_digest:
        raise TrustAnchorError("journal prefix digest does not match trust anchor (history rewritten)")
