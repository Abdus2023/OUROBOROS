"""M1.6+ — signed checkpoints and authenticated trust lifecycle."""
import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import (KeyState, SignedCheckpoint, SignedTrustError, TrustStore, sign_checkpoint,
                                verify_signed_anchor)
from ourob.trust import JournalTrustAnchor, TrustAnchorError
from ourob.trust_lifecycle import apply_transition, sign_revocation, sign_rotation

GEN = "a" * 64


@pytest.fixture
def authority():
    k0 = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", k0.public_key())
    return {"k0": k0}, store


def journal_with(journal_path, n=3):
    journal = Journal(journal_path)
    for i in range(n):
        journal.append(Event(f"E{i}", "run", None, GEN, {"i": i}))
    return journal


def rotate(keys, store, key_id="k1"):
    private = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys[store.active.key_id], store, key_id, private.public_key())
    apply_transition(statement, store)
    keys[key_id] = private
    return private


def test_roundtrip_and_signed_read(journal_path, authority):
    keys, store = authority
    journal = journal_with(journal_path)
    cp = sign_checkpoint(keys["k0"], "k0", store.epoch, JournalTrustAnchor.capture(journal.records(), GEN))
    restored = SignedCheckpoint.from_record(cp.to_record())
    assert restored == cp
    assert store.verify(restored).key_id == "k0"
    assert len(journal.read_signed_trusted(restored, store, GEN)) == 3


@pytest.mark.parametrize("field,value", [("sequence", 2), ("journal_digest", "f" * 64), ("generation", "b" * 64), ("trust_epoch", 1), ("key_id", "k1"), ("algorithm", "ed448")])
def test_any_signed_field_tamper_fails(journal_path, authority, field, value):
    keys, store = authority
    journal = journal_with(journal_path)
    cp = sign_checkpoint(keys["k0"], "k0", 0, JournalTrustAnchor.capture(journal.records(), GEN))
    tampered = dataclasses.replace(cp, **{field: value})
    with pytest.raises(SignedTrustError):
        store.verify(tampered)


def test_signature_from_unprovisioned_key_rejected(journal_path, authority):
    _, store = authority
    rogue = Ed25519PrivateKey.generate()
    journal = journal_with(journal_path)
    anchor = JournalTrustAnchor.capture(journal.records())
    with pytest.raises(SignedTrustError, match="unknown key id"):
        store.verify(sign_checkpoint(rogue, "rogue", 0, anchor))
    with pytest.raises(SignedTrustError, match="signature is invalid"):
        store.verify(sign_checkpoint(rogue, "k0", 0, anchor))


def test_revoked_key_never_authenticates(journal_path, authority):
    keys, store = authority
    journal = journal_with(journal_path)
    cp = sign_checkpoint(keys["k0"], "k0", 0, JournalTrustAnchor.capture(journal.records()))
    store.verify(cp)
    rotate(keys, store)
    apply_transition(sign_revocation(keys["k1"], store, "k0"), store)
    with pytest.raises(SignedTrustError, match="REVOKED"):
        store.verify(cp)
    with pytest.raises(SignedTrustError, match="REVOKED"):
        store.verify(cp, historical=True)


def test_rotation_advances_exactly_one_epoch_and_retires_old_key(authority):
    keys, store = authority
    k1 = rotate(keys, store)
    assert store.epoch == 1
    assert store.keys["k0"].state is KeyState.RETIRED and store.keys["k0"].epoch == 0
    assert store.active.key_id == "k1" and store.active.epoch == 1
    with pytest.raises(SignedTrustError, match="target key id is not fresh"):
        apply_transition(sign_rotation(k1, store, "k1", Ed25519PrivateKey.generate().public_key()), store)
    with pytest.raises(SignedTrustError, match="new key material"):
        apply_transition(sign_rotation(k1, store, "k2", k1.public_key()), store)


def test_retired_key_is_historical_only(journal_path, authority):
    keys, store = authority
    journal = journal_with(journal_path)
    anchor = JournalTrustAnchor.capture(journal.records())
    old_cp = sign_checkpoint(keys["k0"], "k0", 0, anchor)
    rotate(keys, store)
    with pytest.raises(SignedTrustError, match="RETIRED"):
        store.verify(old_cp)
    assert store.verify(old_cp, historical=True).key_id == "k0"
    forged = sign_checkpoint(keys["k0"], "k0", 1, anchor)
    with pytest.raises(SignedTrustError, match="epoch does not match the signing key"):
        store.verify(forged, historical=True)


def test_epoch_rollback_rejected(journal_path, authority):
    keys, store = authority
    k1 = rotate(keys, store)
    journal = journal_with(journal_path)
    anchor = JournalTrustAnchor.capture(journal.records())
    with pytest.raises(SignedTrustError, match="epoch"):
        store.verify(sign_checkpoint(k1, "k1", 0, anchor))
    with pytest.raises(SignedTrustError, match="newer than the trust store"):
        store.verify(sign_checkpoint(k1, "k1", 2, anchor))


def test_repository_cannot_choose_the_trust_epoch(journal_path, authority):
    keys, store = authority
    journal = journal_with(journal_path)
    anchor = JournalTrustAnchor.capture(journal.records())
    cp_epoch0 = sign_checkpoint(keys["k0"], "k0", 0, anchor)
    store.verify(cp_epoch0)
    rotate(keys, store)
    with pytest.raises(SignedTrustError):
        journal.read_signed_trusted(cp_epoch0, store)


def test_signed_read_checks_signature_before_anchor(journal_path, authority):
    keys, store = authority
    journal = journal_with(journal_path)
    anchor = JournalTrustAnchor.capture(journal.records())
    cp = sign_checkpoint(Ed25519PrivateKey.generate(), "k0", 0, anchor)
    with pytest.raises(SignedTrustError):
        verify_signed_anchor(cp, store, journal.records())
    good = sign_checkpoint(keys["k0"], "k0", 0, anchor)
    journal.append(Event("X", "run", None, GEN, {}))
    assert len(journal.read_signed_trusted(good, store)) == 4
    journal_path.write_text("")
    with pytest.raises(TrustAnchorError):
        journal.read_signed_trusted(good, store)


def test_trust_store_record_roundtrip_and_validation(authority):
    keys, store = authority
    rotate(keys, store)
    restored = TrustStore.from_record(store.to_record())
    assert restored.epoch == 1 and restored.active.key_id == "k1"
    assert restored.keys["k0"].state is KeyState.RETIRED
    bad = store.to_record()
    bad["keys"][0]["algorithm"] = "rsa"
    with pytest.raises(SignedTrustError, match="unsupported algorithm"):
        TrustStore.from_record(bad)
    two_active = store.to_record()
    two_active["keys"][0]["state"] = "ACTIVE"
    with pytest.raises(SignedTrustError, match="exactly one ACTIVE"):
        TrustStore.from_record(two_active)


def test_no_private_key_material_in_store(authority):
    _, store = authority
    record = store.to_record()
    assert all(len(bytes.fromhex(k["public_key"])) == 32 for k in record["keys"])
    assert "private" not in str(record).lower()
