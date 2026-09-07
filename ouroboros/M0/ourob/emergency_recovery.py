"""M1.20 — externally authenticated emergency replacement authority.

Emergency recovery is a separate trust root. It is never inferred from the
repository or from the compromised active key. A recovery statement commits
to the exact active key and trust epoch it is allowed to replace.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .signed_trust import ALGORITHM_ED25519, KeyState, SignedTrustError, TrustStore, public_bytes

RECOVERY_SCHEMA = "ourob.emergency-recovery.v1"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class EmergencyRecoveryAuthority:
    """Externally provisioned public root for emergency trust replacement."""

    key_id: str
    public_key: bytes
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise SignedTrustError("recovery authority key_id must be non-empty")
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported recovery algorithm: {self.algorithm!r}")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise SignedTrustError("recovery authority Ed25519 public key must be 32 bytes")
        Ed25519PublicKey.from_public_bytes(self.public_key)

    @classmethod
    def from_public_key(cls, key_id: str, key: Ed25519PublicKey | bytes) -> "EmergencyRecoveryAuthority":
        return cls(key_id, bytes(key) if isinstance(key, bytes) else public_bytes(key))

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_key)


@dataclass(frozen=True)
class EmergencyRecoveryStatement:
    """One externally signed replacement of the current active trust key."""

    recovery_key_id: str
    expected_active_key_id: str
    from_epoch: int
    to_epoch: int
    replacement_key_id: str
    replacement_public_key: bytes
    reason: str
    signature: bytes
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        for name in ("recovery_key_id", "expected_active_key_id", "replacement_key_id", "reason"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise SignedTrustError(f"recovery {name} must be non-empty")
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported recovery algorithm: {self.algorithm!r}")
        for name in ("from_epoch", "to_epoch"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SignedTrustError(f"recovery {name} must be a non-negative integer")
        if self.to_epoch != self.from_epoch + 1:
            raise SignedTrustError("emergency recovery must advance exactly one trust epoch")
        if not isinstance(self.replacement_public_key, bytes) or len(self.replacement_public_key) != 32:
            raise SignedTrustError("recovery replacement Ed25519 key must be 32 bytes")
        Ed25519PublicKey.from_public_bytes(self.replacement_public_key)
        if not isinstance(self.signature, (bytes, bytearray)) or not self.signature:
            raise SignedTrustError("recovery signature must be non-empty")

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": RECOVERY_SCHEMA,
            "algorithm": self.algorithm,
            "recovery_key_id": self.recovery_key_id,
            "expected_active_key_id": self.expected_active_key_id,
            "from_epoch": self.from_epoch,
            "to_epoch": self.to_epoch,
            "replacement_key_id": self.replacement_key_id,
            "replacement_public_key": self.replacement_public_key.hex(),
            "reason": self.reason,
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
    def from_record(cls, record: Any) -> "EmergencyRecoveryStatement":
        if not isinstance(record, dict) or record.get("schema") != RECOVERY_SCHEMA:
            raise SignedTrustError("unsupported emergency recovery statement")
        expected = {
            "schema", "algorithm", "recovery_key_id", "expected_active_key_id",
            "from_epoch", "to_epoch", "replacement_key_id",
            "replacement_public_key", "reason", "signature",
        }
        if set(record) != expected:
            raise SignedTrustError("emergency recovery statement has unexpected fields")
        try:
            replacement = bytes.fromhex(record["replacement_public_key"])
            signature = bytes.fromhex(record["signature"])
        except (TypeError, ValueError) as exc:
            raise SignedTrustError("malformed emergency recovery statement") from exc
        return cls(
            record["recovery_key_id"], record["expected_active_key_id"],
            record["from_epoch"], record["to_epoch"], record["replacement_key_id"],
            replacement, record["reason"], signature, record["algorithm"],
        )


def sign_emergency_recovery(
    private_key: Ed25519PrivateKey,
    authority: EmergencyRecoveryAuthority,
    store: TrustStore,
    replacement_key_id: str,
    replacement_public_key: bytes,
    *,
    reason: str,
) -> EmergencyRecoveryStatement:
    """Sign an emergency replacement against the externally known current state."""
    store._validate_invariants()
    if authority.verifier().public_bytes_raw() != private_key.public_key().public_bytes_raw():
        raise SignedTrustError("recovery signing key does not match external recovery authority")
    active = store.active
    draft = EmergencyRecoveryStatement(
        authority.key_id, active.key_id, store.epoch, store.epoch + 1,
        replacement_key_id, bytes(replacement_public_key), reason, b"\0",
    )
    return EmergencyRecoveryStatement(
        draft.recovery_key_id, draft.expected_active_key_id, draft.from_epoch,
        draft.to_epoch, draft.replacement_key_id, draft.replacement_public_key,
        draft.reason, private_key.sign(draft.signed_bytes()), draft.algorithm,
    )


def verify_emergency_recovery(
    statement: EmergencyRecoveryStatement,
    store: TrustStore,
    authority: EmergencyRecoveryAuthority,
) -> None:
    """Authenticate and authorize one emergency replacement without mutation."""
    store._validate_invariants()
    if statement.recovery_key_id != authority.key_id:
        raise SignedTrustError("emergency recovery signer is not the provisioned recovery authority")
    if statement.from_epoch != store.epoch:
        raise SignedTrustError("emergency recovery statement starts at the wrong trust epoch")
    if statement.expected_active_key_id != store.active.key_id:
        raise SignedTrustError("emergency recovery targets a different ACTIVE key")
    if statement.replacement_key_id in store.keys:
        raise SignedTrustError("emergency recovery replacement key id is not fresh")
    if statement.replacement_public_key == store.active.public_key:
        raise SignedTrustError("emergency recovery requires new key material")
    try:
        authority.verifier().verify(bytes(statement.signature), statement.signed_bytes())
    except InvalidSignature as exc:
        raise SignedTrustError("emergency recovery signature is invalid") from exc


def apply_emergency_recovery(
    statement: EmergencyRecoveryStatement,
    store: TrustStore,
    authority: EmergencyRecoveryAuthority,
) -> None:
    """Verify then atomically replace the compromised ACTIVE key."""
    verify_emergency_recovery(statement, store, authority)
    active = store.active
    store.keys[active.key_id] = type(active)(active.key_id, active.algorithm, active.public_key, KeyState.REVOKED, active.epoch)
    store.keys[statement.replacement_key_id] = type(active)(
        statement.replacement_key_id, ALGORITHM_ED25519, statement.replacement_public_key,
        KeyState.ACTIVE, statement.to_epoch,
    )
    store.epoch = statement.to_epoch
    store._validate_invariants()
