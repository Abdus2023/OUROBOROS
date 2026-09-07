"""M1.13 trust-state-bound signed checkpoints.

Version 1 checkpoints bind a journal anchor and generation. Version 2 adds the
canonical digest of the externally-rooted, journal-reconstructed TrustStore.
Authoritative current bootstrap requires this stronger binding.
"""
from __future__ import annotations

import re
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .signed_trust import ALGORITHM_ED25519, SignedCheckpoint, SignedTrustError, TrustStore, canonical_signed_bytes
from .trust import JournalTrustAnchor

TRUST_BOUND_CHECKPOINT_SCHEMA = "ourob.signed-checkpoint.v2"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def trust_state_digest(store: TrustStore) -> str:
    """Return the canonical SHA-256 digest of a validated trust state."""
    return sha256(canonical_signed_bytes(store.to_record())).hexdigest()


class TrustStateBoundCheckpoint(SignedCheckpoint):
    """Signed checkpoint whose payload commits to reconstructed trust state."""

    def __init__(
        self,
        key_id: str,
        trust_epoch: int,
        sequence: int,
        journal_digest: str,
        generation: str,
        signature: bytes,
        trust_state_digest: str,
        algorithm: str = ALGORITHM_ED25519,
    ) -> None:
        super().__init__(key_id, trust_epoch, sequence, journal_digest, generation, signature, algorithm)
        if not isinstance(generation, str) or not generation:
            raise SignedTrustError("trust-bound checkpoint requires a generation")
        if not isinstance(trust_state_digest, str) or not _HEX64.fullmatch(trust_state_digest):
            raise SignedTrustError("trust_state_digest must be a lowercase SHA-256 hex digest")
        object.__setattr__(self, "trust_state_digest", trust_state_digest)

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": TRUST_BOUND_CHECKPOINT_SCHEMA,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "trust_epoch": self.trust_epoch,
            "sequence": self.sequence,
            "journal_digest": self.journal_digest,
            "generation": self.generation,
            "trust_state_digest": self.trust_state_digest,
        }

    def to_record(self) -> dict[str, Any]:
        record = self.signed_payload()
        record["signature"] = bytes(self.signature).hex()
        return record

    @classmethod
    def from_record(cls, record: Any) -> "TrustStateBoundCheckpoint":
        if not isinstance(record, dict) or record.get("schema") != TRUST_BOUND_CHECKPOINT_SCHEMA:
            raise SignedTrustError("unsupported trust-state-bound checkpoint schema")
        expected = {"schema", "algorithm", "key_id", "trust_epoch", "sequence", "journal_digest", "generation", "trust_state_digest", "signature"}
        if set(record) != expected:
            raise SignedTrustError("trust-state-bound checkpoint has unexpected fields")
        try:
            signature = bytes.fromhex(record["signature"])
        except (TypeError, ValueError) as exc:
            raise SignedTrustError("checkpoint signature must be hex") from exc
        return cls(record["key_id"], record["trust_epoch"], record["sequence"], record["journal_digest"], record["generation"], signature, record["trust_state_digest"], record["algorithm"])


def sign_trust_state_checkpoint(
    private_key: Ed25519PrivateKey,
    key_id: str,
    store: TrustStore,
    anchor: JournalTrustAnchor,
) -> TrustStateBoundCheckpoint:
    """Sign a v2 checkpoint over the canonical current trust state and anchor."""
    if anchor.generation is None:
        raise SignedTrustError("trust-state-bound checkpoint requires a generation-bound anchor")
    state_digest = trust_state_digest(store)
    draft = TrustStateBoundCheckpoint(
        key_id,
        store.epoch,
        anchor.sequence,
        anchor.journal_digest,
        anchor.generation,
        b"\0",
        state_digest,
    )
    signature = private_key.sign(draft.signed_bytes())
    return TrustStateBoundCheckpoint(
        key_id,
        store.epoch,
        anchor.sequence,
        anchor.journal_digest,
        anchor.generation,
        signature,
        state_digest,
    )
