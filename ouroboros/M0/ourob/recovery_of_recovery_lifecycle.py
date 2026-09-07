"""M1.23 — authenticated lifecycle for the independent recovery quorum.

The recovery-of-recovery quorum is an external root at genesis, but its
membership and threshold must themselves have a durable, authenticated
lifecycle. Every lifecycle statement is authorized by the quorum that is
current at that journal position and advances the quorum epoch exactly once.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import Event, EventName
from .recovery_of_recovery import RecoveryOfRecoveryAuthority
from .signed_trust import ALGORITHM_ED25519, SignedTrustError, public_bytes

RECOVERY_OF_RECOVERY_LIFECYCLE_SCHEMA = "ourob.recovery-of-recovery-lifecycle.v1"

class RecoveryOfRecoveryOperation(StrEnum):
    ROTATE_SIGNER = "ROTATE_SIGNER"
    REVOKE_SIGNER = "REVOKE_SIGNER"
    CHANGE_THRESHOLD = "CHANGE_THRESHOLD"

def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

@dataclass(frozen=True)
class RecoveryOfRecoveryLifecycleSignature:
    signer_key_id: str
    signature: bytes
    def __post_init__(self) -> None:
        if not isinstance(self.signer_key_id, str) or not self.signer_key_id:
            raise SignedTrustError("recovery quorum lifecycle signer id must be non-empty")
        if not isinstance(self.signature, (bytes, bytearray)) or not self.signature:
            raise SignedTrustError("recovery quorum lifecycle signature must be non-empty")
    def to_record(self) -> dict[str, str]:
        return {"signer_key_id": self.signer_key_id, "signature": bytes(self.signature).hex()}

@dataclass(frozen=True)
class RecoveryOfRecoveryLifecycleStatement:
    operation: RecoveryOfRecoveryOperation
    authority_epoch: int
    target_key_id: str | None
    replacement_key_id: str | None
    replacement_public_key: bytes | None
    new_threshold: int | None
    reason: str
    signatures: tuple[RecoveryOfRecoveryLifecycleSignature, ...]
    algorithm: str = ALGORITHM_ED25519
    def __post_init__(self) -> None:
        if self.algorithm != ALGORITHM_ED25519:
            raise SignedTrustError(f"unsupported recovery quorum lifecycle algorithm: {self.algorithm!r}")
        if not isinstance(self.authority_epoch, int) or isinstance(self.authority_epoch, bool) or self.authority_epoch < 0:
            raise SignedTrustError("recovery quorum lifecycle epoch must be non-negative")
        if not isinstance(self.reason, str) or not self.reason:
            raise SignedTrustError("recovery quorum lifecycle reason must be non-empty")
        if not isinstance(self.signatures, tuple) or not self.signatures:
            raise SignedTrustError("recovery quorum lifecycle statement requires signatures")
        if self.operation == RecoveryOfRecoveryOperation.ROTATE_SIGNER:
            if not self.target_key_id or not self.replacement_key_id or self.replacement_public_key is None:
                raise SignedTrustError("signer rotation requires target and replacement key material")
            if self.target_key_id == self.replacement_key_id:
                raise SignedTrustError("replacement signer id must be fresh")
            if len(self.replacement_public_key) != 32:
                raise SignedTrustError("replacement signer key must be 32 bytes")
            Ed25519PublicKey.from_public_bytes(self.replacement_public_key)
            if self.new_threshold is not None:
                raise SignedTrustError("signer rotation must not carry threshold")
        elif self.operation == RecoveryOfRecoveryOperation.REVOKE_SIGNER:
            if not self.target_key_id:
                raise SignedTrustError("signer revocation requires a target")
            if self.replacement_key_id is not None or self.replacement_public_key is not None or self.new_threshold is not None:
                raise SignedTrustError("signer revocation carries unexpected replacement fields")
        elif self.operation == RecoveryOfRecoveryOperation.CHANGE_THRESHOLD:
            if self.new_threshold is None or isinstance(self.new_threshold, bool) or self.new_threshold < 1:
                raise SignedTrustError("threshold change requires a positive threshold")
            if self.target_key_id is not None or self.replacement_key_id is not None or self.replacement_public_key is not None:
                raise SignedTrustError("threshold change carries unexpected key fields")
        else:
            raise SignedTrustError("unknown recovery quorum lifecycle operation")
        signer_ids = [item.signer_key_id for item in self.signatures]
        if len(signer_ids) != len(set(signer_ids)):
            raise SignedTrustError("recovery quorum lifecycle statement contains duplicate signers")
    def signed_payload(self) -> dict[str, Any]:
        return {"schema": RECOVERY_OF_RECOVERY_LIFECYCLE_SCHEMA, "algorithm": self.algorithm, "operation": self.operation.value, "authority_epoch": self.authority_epoch, "target_key_id": self.target_key_id, "replacement_key_id": self.replacement_key_id, "replacement_public_key": None if self.replacement_public_key is None else self.replacement_public_key.hex(), "new_threshold": self.new_threshold, "reason": self.reason}
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
    def from_record(cls, record: Any) -> "RecoveryOfRecoveryLifecycleStatement":
        expected = {"schema", "algorithm", "operation", "authority_epoch", "target_key_id", "replacement_key_id", "replacement_public_key", "new_threshold", "reason", "signatures"}
        if not isinstance(record, dict) or record.get("schema") != RECOVERY_OF_RECOVERY_LIFECYCLE_SCHEMA or set(record) != expected or not isinstance(record["signatures"], list):
            raise SignedTrustError("unsupported recovery quorum lifecycle statement")
        try:
            operation = RecoveryOfRecoveryOperation(record["operation"])
            replacement = None if record["replacement_public_key"] is None else bytes.fromhex(record["replacement_public_key"])
            signatures = tuple(RecoveryOfRecoveryLifecycleSignature(item["signer_key_id"], bytes.fromhex(item["signature"])) for item in record["signatures"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SignedTrustError("malformed recovery quorum lifecycle statement") from exc
        return cls(operation, record["authority_epoch"], record["target_key_id"], record["replacement_key_id"], replacement, record["new_threshold"], record["reason"], signatures, record["algorithm"])

def _validate_private_signers(private_keys: Iterable[tuple[str, Ed25519PrivateKey]], authority: RecoveryOfRecoveryAuthority) -> list[tuple[str, Ed25519PrivateKey]]:
    signers = list(private_keys)
    if len({key_id for key_id, _ in signers}) != len(signers):
        raise SignedTrustError("duplicate recovery quorum lifecycle signer")
    for key_id, private_key in signers:
        expected = authority.keys.get(key_id)
        if expected is None or public_bytes(private_key.public_key()) != expected:
            raise SignedTrustError("recovery quorum lifecycle signer is not externally authorized")
    if len(signers) < authority.threshold:
        raise SignedTrustError("recovery quorum lifecycle threshold is not satisfied")
    return signers

def _next_membership(statement: RecoveryOfRecoveryLifecycleStatement, authority: RecoveryOfRecoveryAuthority) -> dict[str, bytes]:
    keys = dict(authority.keys)
    if statement.operation == RecoveryOfRecoveryOperation.ROTATE_SIGNER:
        assert statement.target_key_id is not None and statement.replacement_key_id is not None and statement.replacement_public_key is not None
        if statement.target_key_id not in keys:
            raise SignedTrustError("recovery quorum rotation target is unknown")
        if statement.replacement_key_id in keys:
            raise SignedTrustError("recovery quorum rotation replacement id is not fresh")
        if statement.replacement_public_key in keys.values():
            raise SignedTrustError("recovery quorum rotation requires new key material")
        del keys[statement.target_key_id]
        keys[statement.replacement_key_id] = statement.replacement_public_key
    elif statement.operation == RecoveryOfRecoveryOperation.REVOKE_SIGNER:
        assert statement.target_key_id is not None
        if statement.target_key_id not in keys:
            raise SignedTrustError("recovery quorum revocation target is unknown")
        if len(keys) == 1:
            raise SignedTrustError("recovery quorum cannot revoke its final signer")
        del keys[statement.target_key_id]
    return keys

def sign_lifecycle_statement(private_keys: Iterable[tuple[str, Ed25519PrivateKey]], authority: RecoveryOfRecoveryAuthority, operation: RecoveryOfRecoveryOperation, *, target_key_id: str | None = None, replacement_key_id: str | None = None, replacement_public_key: bytes | None = None, new_threshold: int | None = None, reason: str) -> RecoveryOfRecoveryLifecycleStatement:
    """Create a quorum-signed lifecycle statement using external private keys."""
    signers = _validate_private_signers(private_keys, authority)
    draft = RecoveryOfRecoveryLifecycleStatement(operation, authority.epoch, target_key_id, replacement_key_id, None if replacement_public_key is None else bytes(replacement_public_key), new_threshold, reason, tuple(RecoveryOfRecoveryLifecycleSignature(key_id, b"\0") for key_id, _ in signers))
    _next_membership(draft, authority)
    threshold = authority.threshold if new_threshold is None else new_threshold
    next_keys = _next_membership(draft, authority)
    if threshold < 1 or threshold > len(next_keys):
        raise SignedTrustError("recovery quorum threshold is incompatible with membership")
    signatures = tuple(RecoveryOfRecoveryLifecycleSignature(key_id, private_key.sign(draft.signed_bytes())) for key_id, private_key in signers)
    return RecoveryOfRecoveryLifecycleStatement(draft.operation, draft.authority_epoch, draft.target_key_id, draft.replacement_key_id, draft.replacement_public_key, draft.new_threshold, draft.reason, signatures, draft.algorithm)

def verify_lifecycle_statement(statement: RecoveryOfRecoveryLifecycleStatement, authority: RecoveryOfRecoveryAuthority) -> None:
    if statement.authority_epoch != authority.epoch:
        raise SignedTrustError("recovery quorum lifecycle statement uses the wrong authority epoch")
    keys = _next_membership(statement, authority)
    threshold = authority.threshold if statement.new_threshold is None else statement.new_threshold
    if threshold < 1 or threshold > len(keys):
        raise SignedTrustError("recovery quorum threshold is incompatible with membership")
    seen: set[str] = set()
    valid = 0
    for item in statement.signatures:
        if item.signer_key_id in seen:
            raise SignedTrustError("recovery quorum lifecycle signer replay detected")
        seen.add(item.signer_key_id)
        public = authority.keys.get(item.signer_key_id)
        if public is None:
            raise SignedTrustError("recovery quorum lifecycle contains unauthorized signer")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(bytes(item.signature), statement.signed_bytes())
        except InvalidSignature as exc:
            raise SignedTrustError("recovery quorum lifecycle signature is invalid") from exc
        valid += 1
    if valid < authority.threshold:
        raise SignedTrustError("recovery quorum lifecycle threshold is not satisfied")

def apply_lifecycle_statement(statement: RecoveryOfRecoveryLifecycleStatement, authority: RecoveryOfRecoveryAuthority) -> RecoveryOfRecoveryAuthority:
    verify_lifecycle_statement(statement, authority)
    keys = _next_membership(statement, authority)
    threshold = authority.threshold if statement.new_threshold is None else statement.new_threshold
    return RecoveryOfRecoveryAuthority(keys, threshold, authority.epoch + 1, authority.algorithm)

def recovery_of_recovery_lifecycle_event(statement: RecoveryOfRecoveryLifecycleStatement) -> Event:
    """Create the unscoped durable event carrying one authenticated transition."""
    return Event(EventName.RECOVERY_OF_RECOVERY_LIFECYCLE_AUTHORIZED.value, data={"lifecycle": statement.to_record()})

def recover_recovery_of_recovery_authority(events: Iterable[Any], initial_authority: RecoveryOfRecoveryAuthority) -> RecoveryOfRecoveryAuthority:
    """Replay quorum lifecycle statements strictly in journal order."""
    authority = RecoveryOfRecoveryAuthority(dict(initial_authority.keys), initial_authority.threshold, initial_authority.epoch, initial_authority.algorithm)
    seen: set[str] = set()
    historical_key_ids = set(authority.keys)
    for event in events:
        if getattr(event, "name", None) != EventName.RECOVERY_OF_RECOVERY_LIFECYCLE_AUTHORIZED.value:
            continue
        if any(getattr(event, field, None) is not None for field in ("run_id", "action_id", "generation")):
            raise SignedTrustError("recovery quorum lifecycle event must not be run-scoped")
        statement = RecoveryOfRecoveryLifecycleStatement.from_record(getattr(event, "data", {}).get("lifecycle"))
        if statement.binding_digest in seen:
            raise SignedTrustError("recovery quorum lifecycle replay detected")
        if statement.operation == RecoveryOfRecoveryOperation.ROTATE_SIGNER and statement.replacement_key_id in historical_key_ids:
            raise SignedTrustError("recovery quorum lifecycle signer id was previously used")
        authority = apply_lifecycle_statement(statement, authority)
        historical_key_ids.update(authority.keys)
        seen.add(statement.binding_digest)
    return authority
