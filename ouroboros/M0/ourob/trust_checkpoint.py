"""M1.13/M1.14 trust-state-bound signed checkpoints."""
from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .journal import Journal, JournalIntegrityError
from .signed_trust import ALGORITHM_ED25519, SignedCheckpoint, SignedTrustError, TrustStore, canonical_signed_bytes
from .trust import JournalTrustAnchor
from .trust_recovery import TrustRecoveryError, recover_trust_store

TRUST_BOUND_CHECKPOINT_SCHEMA = "ourob.signed-checkpoint.v2"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def trust_state_digest(store: TrustStore) -> str:
    """Return the canonical SHA-256 digest of a validated trust state."""
    return sha256(canonical_signed_bytes(store.to_record())).hexdigest()


@dataclass(frozen=True)
class TrustStateBoundCheckpoint(SignedCheckpoint):
    """Signed checkpoint whose payload commits to reconstructed trust state."""

    trust_state_digest: str = ""

    def __post_init__(self) -> None:
        SignedCheckpoint.__post_init__(self)
        if not isinstance(self.generation, str) or not self.generation:
            raise SignedTrustError("trust-bound checkpoint requires a generation")
        if not _HEX64.fullmatch(self.trust_state_digest) if isinstance(self.trust_state_digest, str) else True:
            raise SignedTrustError("trust_state_digest must be a lowercase SHA-256 hex digest")

    def signed_payload(self) -> dict[str, Any]:
        return {"schema": TRUST_BOUND_CHECKPOINT_SCHEMA, "algorithm": self.algorithm, "key_id": self.key_id, "trust_epoch": self.trust_epoch, "sequence": self.sequence, "journal_digest": self.journal_digest, "generation": self.generation, "trust_state_digest": self.trust_state_digest}

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
        return cls(record["key_id"], record["trust_epoch"], record["sequence"], record["journal_digest"], record["generation"], signature, record["algorithm"], record["trust_state_digest"])


def sign_trust_state_checkpoint(private_key: Ed25519PrivateKey, key_id: str, store: TrustStore, anchor: JournalTrustAnchor) -> TrustStateBoundCheckpoint:
    """Sign a v2 checkpoint after proving the signer is the store's active key."""
    if anchor.generation is None:
        raise SignedTrustError("trust-state-bound checkpoint requires a generation-bound anchor")
    if key_id != store.active.key_id:
        raise SignedTrustError("checkpoint signer must be the current active trust key")
    if private_key.public_key().public_bytes_raw() != store.active.public_key:
        raise SignedTrustError("checkpoint signing key does not match the current active trust key")
    state_digest = trust_state_digest(store)
    draft = TrustStateBoundCheckpoint(key_id, store.epoch, anchor.sequence, anchor.journal_digest, anchor.generation, b"\0", ALGORITHM_ED25519, state_digest)
    signature = private_key.sign(draft.signed_bytes())
    return TrustStateBoundCheckpoint(key_id, store.epoch, anchor.sequence, anchor.journal_digest, anchor.generation, signature, ALGORITHM_ED25519, state_digest)


def issue_current_checkpoint(journal: Journal, initial_store: TrustStore, private_key: Ed25519PrivateKey, key_id: str, *, generation: str) -> TrustStateBoundCheckpoint:
    """Issue only from the externally rooted, fully reconstructed current state.

    Issuance is deliberately not a journal event: appending an issuance event
    after signing would advance the journal head and invalidate the checkpoint.
    """
    if not isinstance(generation, str) or not generation:
        raise SignedTrustError("checkpoint issuance requires a non-empty generation")
    try:
        records = journal.records()
        if not records:
            raise TrustRecoveryError("cannot issue a current checkpoint for an empty journal")
        recovered = recover_trust_store((record.event for record in records), initial_store)
        anchor = JournalTrustAnchor(records[-1].sequence, records[-1].digest, generation)
        return sign_trust_state_checkpoint(private_key, key_id, recovered, anchor)
    except SignedTrustError:
        raise
    except (JournalIntegrityError, ValueError, TypeError, TrustRecoveryError) as exc:
        raise SignedTrustError(f"cannot issue checkpoint from invalid trust history: {exc}") from exc
