"""M1.7 — authenticated trust lifecycle conformance."""

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_lifecycle import (
    TrustTransition,
    apply_transition,
    sign_rotation,
    sign_revocation,
    verify_transition,
)


def test_rotation_requires_signature_from_current_active_key():
    old = Ed25519PrivateKey.generate()
    rogue = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", old.public_key())
    statement = sign_rotation(old, store, "k1", new.public_key().public_bytes_raw())
    apply_transition(statement, store)
    assert store.epoch == 1
    assert store.active.key_id == "k1"
    forged = dataclasses.replace(
        statement,
        signature=rogue.sign(statement.signed_bytes()),
    )
    with pytest.raises(SignedTrustError):
        verify_transition(forged, store)


def test_rotation_is_exactly_next_epoch_and_fresh_key():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", old.public_key())
    statement = sign_rotation(old, store, "k1", new.public_key().public_bytes_raw())
    bad_epoch = dataclasses.replace(statement, to_epoch=2)
    with pytest.raises(SignedTrustError, match="exactly one"):
        verify_transition(bad_epoch, store)
    bad_id = dataclasses.replace(statement, target_key_id="k0")
    with pytest.raises(SignedTrustError, match="fresh"):
        verify_transition(bad_id, store)


def test_rotation_cannot_be_replayed_after_epoch_changes():
    old = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", old.public_key())
    statement = sign_rotation(old, store, "k1", k1.public_key().public_bytes_raw())
    apply_transition(statement, store)
    with pytest.raises(SignedTrustError, match="ACTIVE"):
        verify_transition(statement, store)
    second = sign_rotation(k1, store, "k2", k2.public_key().public_bytes_raw())
    apply_transition(second, store)
    assert store.epoch == 2 and store.active.key_id == "k2"


def test_revocation_is_authenticated_and_does_not_change_epoch():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    rotation = sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw())
    apply_transition(rotation, store)
    statement = sign_revocation(k1, store, "k0")
    apply_transition(statement, store)
    assert store.epoch == 1
    assert store.keys["k0"].state.value == "REVOKED"


def test_active_key_cannot_be_revoked_without_rotation():
    k0 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    with pytest.raises(SignedTrustError, match="replacement"):
        sign_revocation(k0, store, "k0")


def test_revocation_replay_and_unknown_target_fail():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    apply_transition(sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw()), store)
    statement = sign_revocation(k1, store, "k0")
    apply_transition(statement, store)
    with pytest.raises(SignedTrustError, match="already"):
        verify_transition(statement, store)
    with pytest.raises(SignedTrustError, match="unknown"):
        sign_revocation(k1, store, "missing")


def test_every_lifecycle_field_is_signed():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    statement = sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw())
    for field, value in {
        "signer_key_id": "rogue",
        "from_epoch": 1,
        "to_epoch": 9,
        "target_key_id": "k9",
        "target_public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
        "algorithm": "rsa",
    }.items():
        with pytest.raises(SignedTrustError):
            verify_transition(dataclasses.replace(statement, **{field: value}), store)


def test_roundtrip_record_is_canonical_and_contains_no_private_material():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    statement = sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw())
    restored = TrustTransition.from_record(statement.to_record())
    assert restored == statement
    assert "private" not in str(restored.to_record()).lower()
