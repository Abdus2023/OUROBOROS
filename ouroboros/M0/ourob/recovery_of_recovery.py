"""M1.22 — independent quorum authority for recovery-of-recovery.

This module provides a separately provisioned N-of-M authority that can replace a
compromised emergency recovery root.  The quorum itself is an external root for
this milestone: its private keys and provisioning state are never repository
controlled.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .emergency_recovery import EmergencyRecoveryAuthority
from .signed_trust import ALGORITHM_ED25519, SignedTrustError, public_bytes

RECOVERY_OF_RECOVERY_SCHEMA = "ourob.recovery-of-recovery.v1"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class RecoveryOfRecoveryAuthority:
    """Externally provisioned independent N-of-M signing authority."""
    keys: dict[str, bytes]
    threshold: int
    epoch: int = 0
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported recovery-of-recovery algorithm: {self.algorithm!r}")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise SignedTrustError("recovery-of-recovery epoch must be non-negative")
        if not isinstance(self.keys, dict) or not self.keys:
            raise SignedTrustError("recovery-of-recovery authority requires at least one key")
        if not isinstance(self.threshold, int) or isinstance(self.threshold, bool):
            raise SignedTrustError("recovery-of-recovery threshold must be an integer")
        if self.threshold < 1 or self.threshold > len(self.keys):
            raise SignedTrustError("recovery-of-recovery threshold must be between 1 and key count")
        for key_id, key in self.keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise SignedTrustError("recovery-of-recovery key id must be non-empty")
            if not isinstance(key, bytes) or len(key) != 32:
                raise SignedTrustError("recovery-of-recovery Ed25519 public key must be 32 bytes")
            Ed25519PublicKey.from_public_bytes(key)

    @classmethod
    def from_public_keys(cls, keys: dict[str, Ed25519PublicKey | bytes], threshold: int, *, epoch: int = 0) -> "RecoveryOfRecoveryAuthority":
        material = {key_id: (value if isinstance(value, bytes) else public_bytes(value)) for key_id, value in keys.items()}
        return cls(material, threshold, epoch)


@dataclass(frozen=True)
class RecoveryOfRecoverySignature:
    signer_key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.signer_key_id, str) or not self.signer_key_id:
            raise SignedTrustError("recovery-of-recovery signer id must be non-empty")
        if not isinstance(self.signature, (bytes, bytearray)) or not self.signature:
            raise SignedTrustError("recovery-of-recovery signature must be non-empty")

    def to_record(self) -> dict[str, str]:
        return {"signer_key_id": self.signer_key_id, "signature": bytes(self.signature).hex()}


@dataclass(frozen=True)
class RecoveryOfRecoveryStatement:
    """Quorum-authorized replacement of the current emergency recovery root."""
    authority_epoch: int
    expected_recovery_key_id: str
    expected_recovery_epoch: int
    replacement_key_id: str
    replacement_public_key: bytes
    reason: str
    signatures: tuple[RecoveryOfRecoverySignature, ...]
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported recovery-of-recovery algorithm: {self.algorithm!r}")
        for name in ("authority_epoch", "expected_recovery_epoch"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SignedTrustError(f"{name} must be non-negative")
        for name in ("expected_recovery_key_id", "replacement_key_id", "reason"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise SignedTrustError(f"{name} must be non-empty")
        if self.expected_recovery_key_id == self.replacement_key_id:
            raise SignedTrustError("replacement recovery key id must be fresh")
        if not isinstance(self.replacement_public_key, bytes) or len(self.replacement_public_key) != 32:
            raise SignedTrustError("replacement recovery key must be 32 bytes")
        Ed25519PublicKey.from_public_bytes(self.replacement_public_key)
        if not self.signatures:
            raise SignedTrustError("recovery-of-recovery statement requires signatures")
        ids = [item.signer_key_id for item in self.signatures]
        if len(ids) != len(set(ids)):
            raise SignedTrustError("recovery-of-recovery statement contains duplicate signers")

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": RECOVERY_OF_RECOVERY_SCHEMA,
            "algorithm": self.algorithm,
            "authority_epoch": self.authority_epoch,
            "expected_recovery_key_id": self.expected_recovery_key_id,
            "expected_recovery_epoch": self.expected_recovery_epoch,
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
        record["signatures"] = [item.to_record() for item in self.signatures]
        return record

    @classmethod
    def from_record(cls, record: Any) -> "RecoveryOfRecoveryStatement":
        if not isinstance(record, dict) or record.get("schema") != RECOVERY_OF_RECOVERY_SCHEMA:
            raise SignedTrustError("unsupported recovery-of-recovery statement")
        expected = {"schema", "algorithm", "authority_epoch", "expected_recovery_key_id", "expected_recovery_epoch", "replacement_key_id", "replacement_public_key", "reason", "signatures"}
        if set(record) != expected or not isinstance(record["signatures"], list):
            raise SignedTrustError("recovery-of-recovery statement has unexpected fields")
        try:
            replacement = bytes.fromhex(record["replacement_public_key"])
            signatures = tuple(RecoveryOfRecoverySignature(item["signer_key_id"], bytes.fromhex(item["signature"])) for item in record["signatures"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SignedTrustError("malformed recovery-of-recovery statement") from exc
        return cls(record["authority_epoch"], record["expected_recovery_key_id"], record["expected_recovery_epoch"], record["replacement_key_id"], replacement, record["reason"], signatures, record["algorithm"])


def sign_recovery_of_recovery(
    private_keys: Iterable[tuple[str, Ed25519PrivateKey]],
    authority: RecoveryOfRecoveryAuthority,
    current_recovery: EmergencyRecoveryAuthority,
    replacement_key_id: str,
    replacement_public_key: bytes,
    *,
    reason: str,
) -> RecoveryOfRecoveryStatement:
    """Create a quorum statement using distinct externally held private keys."""
    signers = list(private_keys)
    if len({key_id for key_id, _ in signers}) != len(signers):
        raise SignedTrustError("duplicate recovery-of-recovery signer")
    draft = RecoveryOfRecoveryStatement(authority.epoch, current_recovery.key_id, current_recovery.epoch, replacement_key_id, bytes(replacement_public_key), reason, tuple(RecoveryOfRecoverySignature(key_id, b"\0") for key_id, _ in signers))
    signatures: list[RecoveryOfRecoverySignature] = []
    for key_id, private_key in signers:
        expected = authority.keys.get(key_id)
        if expected is None or private_key.public_key().public_bytes_raw() != expected:
            raise SignedTrustError("recovery-of-recovery signer is not externally authorized")
        signatures.append(RecoveryOfRecoverySignature(key_id, private_key.sign(draft.signed_bytes())))
    return RecoveryOfRecoveryStatement(draft.authority_epoch, draft.expected_recovery_key_id, draft.expected_recovery_epoch, draft.replacement_key_id, draft.replacement_public_key, draft.reason, tuple(signatures), draft.algorithm)


def verify_recovery_of_recovery(
    statement: RecoveryOfRecoveryStatement,
    authority: RecoveryOfRecoveryAuthority,
    current_recovery: EmergencyRecoveryAuthority,
) -> None:
    if statement.authority_epoch != authority.epoch:
        raise SignedTrustError("recovery-of-recovery statement uses the wrong authority epoch")
    if statement.expected_recovery_key_id != current_recovery.key_id:
        raise SignedTrustError("recovery-of-recovery targets a different recovery root")
    if statement.expected_recovery_epoch != current_recovery.epoch:
        raise SignedTrustError("recovery-of-recovery targets a different recovery-root epoch")
    if statement.replacement_key_id in {current_recovery.key_id}:
        raise SignedTrustError("recovery-of-recovery replacement key id is not fresh")
    if statement.replacement_public_key == current_recovery.public_key:
        raise SignedTrustError("recovery-of-recovery requires new key material")
    if len(statement.signatures) < authority.threshold:
        raise SignedTrustError("recovery-of-recovery threshold is not satisfied")
    valid = 0
    seen: set[str] = set()
    for item in statement.signatures:
        if item.signer_key_id in seen:
            raise SignedTrustError("recovery-of-recovery signer replay detected")
        seen.add(item.signer_key_id)
        public = authority.keys.get(item.signer_key_id)
        if public is None:
            raise SignedTrustError("recovery-of-recovery statement contains unauthorized signer")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(bytes(item.signature), statement.signed_bytes())
        except InvalidSignature as exc:
            raise SignedTrustError("recovery-of-recovery signature is invalid") from exc
        valid += 1
    if valid < authority.threshold:
        raise SignedTrustError("recovery-of-recovery threshold is not satisfied")


def apply_recovery_of_recovery(
    statement: RecoveryOfRecoveryStatement,
    authority: RecoveryOfRecoveryAuthority,
    current_recovery: EmergencyRecoveryAuthority,
) -> EmergencyRecoveryAuthority:
    """Verify a quorum statement and atomically replace the recovery root."""
    verify_recovery_of_recovery(statement, authority, current_recovery)
    return EmergencyRecoveryAuthority(statement.replacement_key_id, statement.replacement_public_key, current_recovery.epoch + 1, statement.algorithm)
