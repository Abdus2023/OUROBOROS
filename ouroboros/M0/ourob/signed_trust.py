"""Signed checkpoints and trust-key lifecycle (M1.6+).

The trust store is externally provisioned authority material. Serialized trust
state is accepted only when it satisfies the complete lifecycle invariants;
repository-controlled state can never manufacture a new root of trust.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .trust import JournalTrustAnchor, verify_anchor

if TYPE_CHECKING:  # pragma: no cover
    from .journal import JournalRecord

SIGNED_CHECKPOINT_SCHEMA = "ourob.signed-checkpoint.v1"
TRUST_STORE_SCHEMA = "ourob.trust-store.v1"
ALGORITHM_ED25519 = "ed25519"
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({ALGORITHM_ED25519})


class SignedTrustError(RuntimeError):
    pass


class KeyState(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class SignedCheckpoint:
    key_id: str
    trust_epoch: int
    sequence: int
    journal_digest: str
    generation: str | None
    signature: bytes
    algorithm: str = ALGORITHM_ED25519

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise SignedTrustError("checkpoint key_id must be a non-empty string")
        if not isinstance(self.trust_epoch, int) or isinstance(self.trust_epoch, bool) or self.trust_epoch < 0:
            raise SignedTrustError("checkpoint trust_epoch must be a non-negative integer")
        if not isinstance(self.signature, (bytes, bytearray)) or not self.signature:
            raise SignedTrustError("checkpoint signature must be non-empty bytes")
        JournalTrustAnchor(self.sequence, self.journal_digest, self.generation)

    @property
    def anchor(self) -> JournalTrustAnchor:
        return JournalTrustAnchor(self.sequence, self.journal_digest, self.generation)

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": SIGNED_CHECKPOINT_SCHEMA,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "trust_epoch": self.trust_epoch,
            "sequence": self.sequence,
            "journal_digest": self.journal_digest,
            "generation": self.generation,
        }

    def signed_bytes(self) -> bytes:
        return canonical_signed_bytes(self.signed_payload())

    @property
    def binding_digest(self) -> str:
        return sha256(self.signed_bytes()).hexdigest()

    def to_record(self) -> dict[str, Any]:
        record = self.signed_payload()
        record["signature"] = bytes(self.signature).hex()
        return record

    @classmethod
    def from_record(cls, record: Any) -> "SignedCheckpoint":
        if not isinstance(record, dict):
            raise SignedTrustError("checkpoint record must be an object")
        if record.get("schema") != SIGNED_CHECKPOINT_SCHEMA:
            raise SignedTrustError(f"unsupported checkpoint schema: {record.get('schema')!r}")
        expected = {"schema", "algorithm", "key_id", "trust_epoch", "sequence", "journal_digest", "generation", "signature"}
        if set(record) != expected:
            raise SignedTrustError("checkpoint record has unexpected fields")
        try:
            signature = bytes.fromhex(record["signature"])
        except (TypeError, ValueError) as exc:
            raise SignedTrustError("checkpoint signature must be hex") from exc
        return cls(record["key_id"], record["trust_epoch"], record["sequence"], record["journal_digest"], record.get("generation"), signature, record["algorithm"])


def canonical_signed_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_checkpoint(private_key: Ed25519PrivateKey, key_id: str, trust_epoch: int, anchor: JournalTrustAnchor) -> SignedCheckpoint:
    """Produce a checkpoint with an externally held private key."""
    draft = SignedCheckpoint(key_id, trust_epoch, anchor.sequence, anchor.journal_digest, anchor.generation, b"\0")
    signature = private_key.sign(draft.signed_bytes())
    return SignedCheckpoint(key_id, trust_epoch, anchor.sequence, anchor.journal_digest, anchor.generation, signature)


@dataclass(frozen=True)
class TrustKey:
    key_id: str
    algorithm: str
    public_key: bytes
    state: KeyState
    epoch: int

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not self.key_id:
            raise SignedTrustError("trust key id must be non-empty")
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise SignedTrustError(f"unsupported algorithm: {self.algorithm!r}")
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise SignedTrustError("trust key epoch must be non-negative")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise SignedTrustError("Ed25519 public key must be 32 bytes")
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key)
        except ValueError as exc:
            raise SignedTrustError(f"invalid public key material for {self.key_id}") from exc

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_key)

    def to_record(self) -> dict[str, Any]:
        return {"key_id": self.key_id, "algorithm": self.algorithm, "public_key": self.public_key.hex(), "state": self.state.value, "epoch": self.epoch}


def public_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass
class TrustStore:
    """Externally provisioned trust roots.

    ``genesis`` is the provisioning boundary. Lifecycle mutation is performed
    only by ``trust_lifecycle.apply_transition`` after a signed authorization.
    The mutation helpers below are intentionally private to this module.
    """

    keys: dict[str, TrustKey] = field(default_factory=dict)
    epoch: int = 0

    @classmethod
    def genesis(cls, key_id: str, public_key: Ed25519PublicKey | bytes) -> "TrustStore":
        raw = public_key if isinstance(public_key, (bytes, bytearray)) else public_bytes(public_key)
        store = cls()
        store.keys[key_id] = TrustKey(key_id, ALGORITHM_ED25519, bytes(raw), KeyState.ACTIVE, 0)
        store._validate_invariants()
        return store

    def _validate_invariants(self) -> None:
        if not isinstance(self.epoch, int) or isinstance(self.epoch, bool) or self.epoch < 0:
            raise SignedTrustError("trust store epoch must be a non-negative integer")
        if not isinstance(self.keys, dict) or not self.keys:
            raise SignedTrustError("trust store must contain at least one key")
        if any(key_id != key.key_id for key_id, key in self.keys.items()):
            raise SignedTrustError("trust store mapping key does not match TrustKey.key_id")
        actives = [key for key in self.keys.values() if key.state is KeyState.ACTIVE]
        if len(actives) != 1:
            raise SignedTrustError(f"trust store must have exactly one ACTIVE key, found {len(actives)}")
        active = actives[0]
        if active.epoch != self.epoch:
            raise SignedTrustError("ACTIVE key epoch must equal trust store epoch")
        epochs = [key.epoch for key in self.keys.values()]
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in epochs):
            raise SignedTrustError("trust key epochs must be non-negative integers")
        if any(value > self.epoch for value in epochs):
            raise SignedTrustError("trust key epoch is outside the store epoch")
        if len(set(epochs)) != len(epochs):
            raise SignedTrustError("trust store must contain at most one key per epoch")

    @property
    def active(self) -> TrustKey:
        self._validate_invariants()
        return next(key for key in self.keys.values() if key.state is KeyState.ACTIVE)

    def _apply_rotation(self, new_key_id: str, public_key: Ed25519PublicKey | bytes) -> None:
        self._validate_invariants()
        if new_key_id in self.keys:
            raise SignedTrustError("rotation requires a fresh key id")
        current = self.active
        raw = public_key if isinstance(public_key, (bytes, bytearray)) else public_bytes(public_key)
        if bytes(raw) == current.public_key:
            raise SignedTrustError("rotation requires new key material")
        next_epoch = self.epoch + 1
        self.keys[current.key_id] = TrustKey(current.key_id, current.algorithm, current.public_key, KeyState.RETIRED, current.epoch)
        self.keys[new_key_id] = TrustKey(new_key_id, ALGORITHM_ED25519, bytes(raw), KeyState.ACTIVE, next_epoch)
        self.epoch = next_epoch
        self._validate_invariants()

    def _apply_revocation(self, key_id: str) -> None:
        self._validate_invariants()
        key = self.keys.get(key_id)
        if key is None:
            raise SignedTrustError(f"unknown key id: {key_id}")
        if key_id == self.active.key_id:
            raise SignedTrustError("cannot revoke the current ACTIVE key")
        self.keys[key_id] = TrustKey(key.key_id, key.algorithm, key.public_key, KeyState.REVOKED, key.epoch)
        self._validate_invariants()

    def verify(self, checkpoint: SignedCheckpoint, *, historical: bool = False) -> TrustKey:
        self._validate_invariants()
        if checkpoint.algorithm not in SUPPORTED_ALGORITHMS:
            raise SignedTrustError(f"unsupported checkpoint algorithm: {checkpoint.algorithm!r}")
        key = self.keys.get(checkpoint.key_id)
        if key is None:
            raise SignedTrustError(f"unknown key id: {checkpoint.key_id}")
        if key.algorithm != checkpoint.algorithm:
            raise SignedTrustError("checkpoint algorithm does not match key algorithm")
        if key.state is KeyState.REVOKED:
            raise SignedTrustError(f"key {key.key_id} is REVOKED")
        if checkpoint.trust_epoch > self.epoch:
            raise SignedTrustError("checkpoint claims a trust epoch newer than the trust store")
        if checkpoint.trust_epoch != key.epoch:
            raise SignedTrustError("checkpoint trust epoch does not match the signing key's epoch")
        if key.state is KeyState.RETIRED:
            if not historical:
                raise SignedTrustError(f"key {key.key_id} is RETIRED and cannot authenticate current checkpoints")
        elif checkpoint.trust_epoch != self.epoch:
            raise SignedTrustError("checkpoint trust epoch is older than the current trust epoch")
        try:
            key.verifier().verify(bytes(checkpoint.signature), checkpoint.signed_bytes())
        except InvalidSignature as exc:
            raise SignedTrustError("checkpoint signature is invalid") from exc
        return key

    def to_record(self) -> dict[str, Any]:
        self._validate_invariants()
        return {"schema": TRUST_STORE_SCHEMA, "epoch": self.epoch, "keys": [self.keys[k].to_record() for k in sorted(self.keys)]}

    @classmethod
    def from_record(cls, record: Any) -> "TrustStore":
        if not isinstance(record, dict) or record.get("schema") != TRUST_STORE_SCHEMA:
            raise SignedTrustError("unsupported trust store record")
        if set(record) != {"schema", "epoch", "keys"}:
            raise SignedTrustError("trust store record has unexpected fields")
        epoch = record["epoch"]
        keys = record["keys"]
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0 or not isinstance(keys, list):
            raise SignedTrustError("malformed trust store record")
        store = cls(epoch=epoch)
        for entry in keys:
            if not isinstance(entry, dict) or set(entry) != {"key_id", "algorithm", "public_key", "state", "epoch"}:
                raise SignedTrustError("malformed trust key entry")
            try:
                state = KeyState(entry["state"])
                raw = bytes.fromhex(entry["public_key"])
            except (ValueError, TypeError) as exc:
                raise SignedTrustError("malformed trust key entry") from exc
            key_id = entry["key_id"]
            if not isinstance(key_id, str) or not key_id:
                raise SignedTrustError("trust key id must be non-empty")
            if key_id in store.keys:
                raise SignedTrustError("duplicate key id in trust store")
            if entry["algorithm"] not in SUPPORTED_ALGORITHMS:
                raise SignedTrustError(f"unsupported algorithm in trust store: {entry['algorithm']!r}")
            store.keys[key_id] = TrustKey(key_id, entry["algorithm"], raw, state, entry["epoch"])
        store._validate_invariants()
        return store


def verify_signed_anchor(checkpoint: SignedCheckpoint, store: TrustStore, records: Sequence["JournalRecord"], generation: str | None = None, *, historical: bool = False) -> TrustKey:
    """Authenticate the checkpoint first, then apply it as a journal anchor."""
    key = store.verify(checkpoint, historical=historical)
    verify_anchor(checkpoint.anchor, records, generation)
    return key
