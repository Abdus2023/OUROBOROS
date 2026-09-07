"""M1.7 — authenticated trust-key lifecycle statements.

The M1.6 trust store can represent rotation/revocation state, but state
changes must not themselves be treated as proof of authority.  This module
adds signed lifecycle statements: the currently authoritative ACTIVE key
must authorize a transition before it can be applied.

Private signing keys remain outside OUROBOROS.  The repository consumes only
public trust material and signed statements.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .signed_trust import ALGORITHM_ED25519, SignedTrustError, TrustStore, public_bytes

LIFECYCLE_SCHEMA = "ourob.trust-transition.v1"


class TransitionOperation(StrEnum):
    ROTATE = "ROTATE"
    REVOKE = "REVOKE"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class TrustTransition:
    """A signed authorization for exactly one trust-store transition."""

    operation: TransitionOperation
    signer_key_id: str
    from_epoch: int
    to_epoch: int
    target_key_id: str
    target_public_key: bytes | None
    signature: bytes
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported lifecycle algorithm: {self.algorithm!r}")
        if not isinstance(self.signer_key_id, str) or not self.signer_key_id:
            raise SignedTrustError("lifecycle signer_key_id must be non-empty")
        if not isinstance(self.target_key_id, str) or not self.target_key_id:
            raise SignedTrustError("lifecycle target_key_id must be non-empty")
        if not isinstance(self.from_epoch, int) or isinstance(self.from_epoch, bool) or self.from_epoch < 0:
            raise SignedTrustError("lifecycle from_epoch must be non-negative")
        if not isinstance(self.to_epoch, int) or isinstance(self.to_epoch, bool) or self.to_epoch < 0:
            raise SignedTrustError("lifecycle to_epoch must be non-negative")
        if not self.signature:
            raise SignedTrustError("lifecycle signature must be non-empty")
        if self.target_public_key is not None and len(self.target_public_key) != 32:
            raise SignedTrustError("Ed25519 lifecycle target key must be 32 bytes")
        if self.operation is TransitionOperation.ROTATE and self.target_public_key is None:
            raise SignedTrustError("ROTATE requires target public key material")
        if self.operation is TransitionOperation.REVOKE and self.target_public_key is not None:
            raise SignedTrustError("REVOKE must not carry replacement key material")

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": LIFECYCLE_SCHEMA,
            "algorithm": self.algorithm,
            "operation": self.operation.value,
            "signer_key_id": self.signer_key_id,
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "target_key_id": self.target_key_id,
            "target_public_key": self.target_public_key.hex() if self.target_public_key is not None else None,
        }

    def signed_bytes(self) -> bytes:
        return _canonical(self.signed_payload())

    @property
    def binding_digest(self) -> str:
        return sha256(self.signed_bytes()).hexdigest()

    def to_record(self) -> dict[str, Any]:
        record = self.signed_payload()
        record["signature"] = bytes(self.signature).hex()
        return record

    @classmethod
    def from_record(cls, record: Any) -> "TrustTransition":
        if not isinstance(record, dict) or record.get("schema") != LIFECYCLE_SCHEMA:
            raise SignedTrustError("unsupported trust transition record")
        expected = {
            "schema", "algorithm", "operation", "signer_key_id", "from_epoch", "to_epoch",
            "target_key_id", "target_public_key", "signature",
        }
        if set(record) != expected:
            raise SignedTrustError("trust transition record has unexpected fields")
        try:
            operation = TransitionOperation(record["operation"])
            signature = bytes.fromhex(record["signature"])
            target = None if record["target_public_key"] is None else bytes.fromhex(record["target_public_key"])
        except (TypeError, ValueError) as exc:
            raise SignedTrustError("malformed trust transition record") from exc
        return cls(
            operation, record["signer_key_id"], record["from_epoch"], record["to_epoch"],
            record["target_key_id"], target, signature, record["algorithm"],
        )


def sign_rotation(
    private_key: Ed25519PrivateKey,
    store: TrustStore,
    new_key_id: str,
    new_public_key: bytes,
) -> TrustTransition:
    """Create an externally signed authorization for the next trust epoch."""
    active = store.active
    raw = bytes(new_public_key)
    draft = TrustTransition(
        TransitionOperation.ROTATE, active.key_id, store.epoch, store.epoch + 1,
        new_key_id, raw, b"\0",
    )
    return TrustTransition(
        draft.operation, draft.signer_key_id, draft.from_epoch, draft.to_epoch,
        draft.target_key_id, draft.target_public_key, private_key.sign(draft.signed_bytes()),
    )


def sign_revocation(
    private_key: Ed25519PrivateKey,
    store: TrustStore,
    target_key_id: str,
) -> TrustTransition:
    """Create an externally signed authorization to revoke a non-active key."""
    active = store.active
    if target_key_id == active.key_id:
        raise SignedTrustError("cannot revoke the current ACTIVE key without a replacement rotation")
    if target_key_id not in store.keys:
        raise SignedTrustError(f"unknown key id: {target_key_id}")
    draft = TrustTransition(
        TransitionOperation.REVOKE, active.key_id, store.epoch, store.epoch,
        target_key_id, None, b"\0",
    )
    return TrustTransition(
        draft.operation, draft.signer_key_id, draft.from_epoch, draft.to_epoch,
        draft.target_key_id, draft.target_public_key, private_key.sign(draft.signed_bytes()),
    )


def verify_transition(statement: TrustTransition, store: TrustStore) -> None:
    """Verify lifecycle authorization without mutating the trust store."""
    if statement.signer_key_id != store.active.key_id:
        raise SignedTrustError("lifecycle signer is not the current ACTIVE key")
    if statement.from_epoch != store.epoch:
        raise SignedTrustError("lifecycle statement starts at the wrong trust epoch")
    if statement.operation is TransitionOperation.ROTATE:
        if statement.to_epoch != store.epoch + 1:
            raise SignedTrustError("rotation must advance exactly one trust epoch")
        if statement.target_key_id in store.keys:
            raise SignedTrustError("rotation target key id is not fresh")
        if statement.target_public_key == store.active.public_key:
            raise SignedTrustError("rotation target must use new key material")
    elif statement.operation is TransitionOperation.REVOKE:
        if statement.to_epoch != store.epoch:
            raise SignedTrustError("revocation must not change the trust epoch")
        target = store.keys.get(statement.target_key_id)
        if target is None:
            raise SignedTrustError("revocation target key is unknown")
        if target.key_id == store.active.key_id:
            raise SignedTrustError("cannot revoke the current ACTIVE key")
        if target.state.value == "REVOKED":
            raise SignedTrustError("revocation target is already REVOKED")
    else:  # pragma: no cover
        raise SignedTrustError("unsupported lifecycle operation")
    try:
        store.active.verifier().verify(statement.signature, statement.signed_bytes())
    except InvalidSignature as exc:
        raise SignedTrustError("trust transition signature is invalid") from exc


def apply_transition(statement: TrustTransition, store: TrustStore) -> None:
    """Verify and then apply one authenticated lifecycle transition."""
    verify_transition(statement, store)
    if statement.operation is TransitionOperation.ROTATE:
        assert statement.target_public_key is not None
        store.rotate(statement.target_key_id, statement.target_public_key)
    else:
        store.revoke(statement.target_key_id)
