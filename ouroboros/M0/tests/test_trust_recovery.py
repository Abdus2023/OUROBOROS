"""Conformance tests for M1.7 durable authenticated trust-state recovery."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.model import Event, EventName
from ourob.trust_lifecycle import sign_rotation, sign_revocation
from ourob.trust_recovery import TrustRecoveryError, recover_trust_store, trust_transition_event
from ourob.signed_trust import KeyState, TrustStore


def authority():
    k0 = Ed25519PrivateKey.generate()
    return {"k0": k0}, TrustStore.genesis("k0", k0.public_key())


def test_recover_rotation_from_durable_signed_event():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    recovered = recover_trust_store([trust_transition_event(statement)], store)
    assert recovered.epoch == 1
    assert recovered.active.key_id == "k1"
    assert recovered.keys["k0"].state is KeyState.RETIRED


def test_recovery_uses_external_initial_store_as_root():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    rogue = TrustStore.genesis("rogue", Ed25519PrivateKey.generate().public_key())
    with pytest.raises(TrustRecoveryError, match="invalid authenticated trust transition"):
        recover_trust_store([trust_transition_event(statement)], rogue)


def test_replayed_transition_is_rejected():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    event = trust_transition_event(statement)
    with pytest.raises(TrustRecoveryError, match="replay"):
        recover_trust_store([event, event], store)


def test_revocation_is_recovered_after_authenticated_rotation():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    rotation = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    store.rotate("k1", k1.public_key())
    revocation = sign_revocation(k1, store, "k0")
    recovered = recover_trust_store([trust_transition_event(rotation), trust_transition_event(revocation)], TrustStore.from_record(
        TrustStore.genesis("k0", keys["k0"].public_key()).to_record()
    ))
    assert recovered.epoch == 1
    assert recovered.keys["k0"].state is KeyState.REVOKED


def test_unknown_events_do_not_change_trust_state():
    _, store = authority()
    recovered = recover_trust_store([Event("RUN_CREATED", "r", generation="a" * 64, data={"task": "x"})], store)
    assert recovered.to_record() == store.to_record()


def test_trust_event_must_not_be_run_scoped():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    event = Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, "run", data={"transition": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="run-scoped"):
        recover_trust_store([event], store)
