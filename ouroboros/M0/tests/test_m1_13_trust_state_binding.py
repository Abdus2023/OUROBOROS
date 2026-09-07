"""M1.13 — checkpoint continuity and trust-state binding conformance."""

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust import JournalTrustAnchor
from ourob.trust_checkpoint import TrustStateBoundCheckpoint, sign_trust_state_checkpoint, trust_state_digest
from ourob.trust_lifecycle import apply_transition, sign_rotation


def _anchor() -> JournalTrustAnchor:
    return JournalTrustAnchor(1, "d" * 64, "generation-a")


def test_trust_state_digest_is_canonical_and_changes_with_state():
    key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", key.public_key())
    first = trust_state_digest(root)
    clone = TrustStore.from_record(root.to_record())
    assert trust_state_digest(clone) == first

    next_key = Ed25519PrivateKey.generate()
    rotation = sign_rotation(key, root, "k1", next_key.public_key().public_bytes_raw())
    changed = TrustStore.from_record(root.to_record())
    apply_transition(rotation, changed)
    assert trust_state_digest(changed) != first


def test_v2_checkpoint_binds_exact_trust_state():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, _anchor())
    assert checkpoint.trust_state_digest == trust_state_digest(store)
    assert store.verify(checkpoint).key_id == "k0"


def test_v2_checkpoint_rejects_tampered_state_digest():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, _anchor())
    tampered = dataclasses.replace(checkpoint, trust_state_digest="0" * 64)
    with pytest.raises(SignedTrustError, match="signature is invalid"):
        store.verify(tampered)


def test_v2_checkpoint_requires_generation():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    with pytest.raises(SignedTrustError, match="generation"):
        TrustStateBoundCheckpoint("k0", 0, 1, "d" * 64, "", b"x", "ed25519", trust_state_digest(store))


def test_v2_checkpoint_round_trip_preserves_binding():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, _anchor())
    restored = TrustStateBoundCheckpoint.from_record(checkpoint.to_record())
    assert restored.to_record() == checkpoint.to_record()
    assert restored.binding_digest == checkpoint.binding_digest


def test_malformed_binding_digest_is_rejected():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, _anchor())
    record = checkpoint.to_record()
    record["trust_state_digest"] = "not-a-digest"
    with pytest.raises(SignedTrustError, match="trust_state_digest"):
        TrustStateBoundCheckpoint.from_record(record)
