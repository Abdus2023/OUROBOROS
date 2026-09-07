"""Additional fail-closed trust-store invariants for M1.7+."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.signed_trust import KeyState, SignedTrustError, TrustStore
from ourob.trust_lifecycle import sign_revocation


def test_deserialization_rejects_active_key_from_wrong_epoch():
    key = Ed25519PrivateKey.generate()
    record = TrustStore.genesis("k0", key.public_key()).to_record()
    record["epoch"] = 1
    record["keys"][0]["epoch"] = 0
    with pytest.raises(SignedTrustError, match="ACTIVE key epoch"):
        TrustStore.from_record(record)


def test_deserialization_rejects_future_key_epoch():
    key = Ed25519PrivateKey.generate()
    record = TrustStore.genesis("k0", key.public_key()).to_record()
    record["keys"][0]["epoch"] = 1
    with pytest.raises(SignedTrustError, match="ACTIVE key epoch|outside the store epoch"):
        TrustStore.from_record(record)


def test_authenticated_revocation_of_active_key_is_forbidden():
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    with pytest.raises(SignedTrustError, match="current ACTIVE"):
        sign_revocation(key, store, "k0")


def test_key_material_length_is_validated_at_provisioning():
    with pytest.raises(SignedTrustError, match="32 bytes"):
        TrustStore.genesis("bad", b"short")
