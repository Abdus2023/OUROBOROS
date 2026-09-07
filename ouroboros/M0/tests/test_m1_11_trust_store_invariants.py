"""M1.11 — adversarial trust-store state conformance."""

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.signed_trust import KeyState, SignedTrustError, TrustStore
from ourob.trust_lifecycle import apply_transition, sign_rotation


def _record() -> dict:
    key = Ed25519PrivateKey.generate()
    return TrustStore.genesis("k0", key.public_key()).to_record()


def test_zero_active_keys_rejected():
    record = _record()
    record["keys"][0]["state"] = "RETIRED"
    with pytest.raises(SignedTrustError, match="exactly one ACTIVE"):
        TrustStore.from_record(record)


def test_multiple_active_keys_rejected():
    record = _record()
    second = copy.deepcopy(record["keys"][0])
    second["key_id"] = "k1"
    second["public_key"] = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    record["keys"].append(second)
    with pytest.raises(SignedTrustError, match="exactly one ACTIVE"):
        TrustStore.from_record(record)


def test_active_epoch_mismatch_rejected():
    record = _record()
    record["epoch"] = 1
    with pytest.raises(SignedTrustError, match="ACTIVE key epoch"):
        TrustStore.from_record(record)


def test_future_key_epoch_rejected():
    record = _record()
    record["keys"][0]["epoch"] = 1
    with pytest.raises(SignedTrustError, match="outside"):
        TrustStore.from_record(record)


def test_duplicate_epoch_rejected():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    record = store.to_record()
    extra = copy.deepcopy(record["keys"][0])
    extra["key_id"] = "k1"
    extra["public_key"] = k1.public_key().public_bytes_raw().hex()
    extra["state"] = "RETIRED"
    record["keys"].append(extra)
    with pytest.raises(SignedTrustError, match="one key per epoch"):
        TrustStore.from_record(record)


def test_private_material_or_extra_fields_rejected():
    record = _record()
    record["keys"][0]["private_key"] = "deadbeef"
    with pytest.raises(SignedTrustError, match="malformed|unexpected"):
        TrustStore.from_record(record)


def test_negative_and_boolean_epochs_rejected():
    for value in (-1, True, False):
        record = _record()
        record["epoch"] = value
        with pytest.raises(SignedTrustError):
            TrustStore.from_record(record)


def test_malformed_public_key_rejected():
    record = _record()
    record["keys"][0]["public_key"] = "00" * 32
    with pytest.raises(SignedTrustError, match="invalid public key"):
        TrustStore.from_record(record)


def test_rollback_epoch_and_key_state_rejected():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    apply_transition(sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw()), store)
    record = store.to_record()
    record["epoch"] = 0
    record["keys"][1]["epoch"] = 0
    with pytest.raises(SignedTrustError):
        TrustStore.from_record(record)


def test_canonical_roundtrip_preserves_valid_state():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    apply_transition(sign_rotation(k0, store, "k1", k1.public_key().public_bytes_raw()), store)
    restored = TrustStore.from_record(store.to_record())
    assert restored == store
    assert restored.active.state is KeyState.ACTIVE
