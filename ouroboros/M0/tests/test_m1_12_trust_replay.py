"""M1.12 — trust-state replay-integrity conformance."""

import dataclasses

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.model import Event, EventName
from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_lifecycle import apply_transition, sign_revocation, sign_rotation
from ourob.trust_recovery import TrustRecoveryError, recover_trust_store


def test_replay_is_deterministic_and_ordered():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", k0.public_key())
    first = sign_rotation(k0, root, "k1", k1.public_key().public_bytes_raw())
    state1 = TrustStore.from_record(root.to_record())
    apply_transition(first, state1)
    second = sign_rotation(k1, state1, "k2", k2.public_key().public_bytes_raw())
    events = [
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": first.to_record()}),
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": second.to_record()}),
    ]
    a = recover_trust_store(events, root)
    b = recover_trust_store(events, root)
    assert a.to_record() == b.to_record()
    assert a.epoch == 2
    assert a.active.key_id == "k2"


def test_reordered_transitions_are_rejected():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    k2 = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", k0.public_key())
    first = sign_rotation(k0, root, "k1", k1.public_key().public_bytes_raw())
    state1 = TrustStore.from_record(root.to_record())
    apply_transition(first, state1)
    second = sign_rotation(k1, state1, "k2", k2.public_key().public_bytes_raw())
    events = [
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": second.to_record()}),
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": first.to_record()}),
    ]
    with pytest.raises(TrustRecoveryError):
        recover_trust_store(events, root)


def test_duplicate_binding_is_rejected_even_when_event_records_differ():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", k0.public_key())
    statement = sign_rotation(k0, root, "k1", k1.public_key().public_bytes_raw())
    event1 = Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": statement.to_record()})
    event2 = dataclasses.replace(event1, generation="different-generation")
    with pytest.raises(TrustRecoveryError, match="run-scoped"):
        recover_trust_store([event1, event2], root)


def test_revocation_is_permanent_across_replay():
    k0 = Ed25519PrivateKey.generate()
    k1 = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", k0.public_key())
    rotation = sign_rotation(k0, root, "k1", k1.public_key().public_bytes_raw())
    state = TrustStore.from_record(root.to_record())
    apply_transition(rotation, state)
    revoke = sign_revocation(k1, state, "k0")
    events = [
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": rotation.to_record()}),
        Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": revoke.to_record()}),
    ]
    restored = recover_trust_store(events, root)
    assert restored.keys["k0"].state.value == "REVOKED"
    assert restored.epoch == 1


def test_recovery_never_accepts_repository_derived_root():
    k0 = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", k0.public_key())
    record = root.to_record()
    record["epoch"] = 1
    with pytest.raises(SignedTrustError):
        TrustStore.from_record(record)
