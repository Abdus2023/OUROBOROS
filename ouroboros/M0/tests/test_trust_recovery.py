"""Conformance tests for M1.7/M1.8 authenticated trust-state recovery."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal, JournalIntegrityError
from ourob.model import Event, EventName
from ourob.signed_trust import KeyState, TrustStore
from ourob.trust_lifecycle import sign_rotation, sign_revocation
from ourob.trust_recovery import (
    TrustRecoveryError,
    append_authorized_transition,
    recover_trust_store,
    recover_trust_store_from_journal,
    trust_transition_event,
)


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
    event = trust_transition_event(sign_rotation(keys["k0"], store, "k1", k1.public_key()))
    with pytest.raises(TrustRecoveryError, match="replay"):
        recover_trust_store([event, event], store)


def test_revocation_is_recovered_after_authenticated_rotation():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    rotation = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    store.rotate("k1", k1.public_key())
    revocation = sign_revocation(k1, store, "k0")
    recovered = recover_trust_store(
        [trust_transition_event(rotation), trust_transition_event(revocation)],
        TrustStore.genesis("k0", keys["k0"].public_key()),
    )
    assert recovered.epoch == 1
    assert recovered.keys["k0"].state is KeyState.REVOKED


def test_unknown_events_do_not_change_trust_state():
    _, store = authority()
    recovered = recover_trust_store(
        [Event("RUN_CREATED", "r", generation="a" * 64, data={"task": "x"})], store
    )
    assert recovered.to_record() == store.to_record()


def test_trust_event_must_not_be_run_scoped():
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    event = Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, "run", data={"transition": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="run-scoped"):
        recover_trust_store([event], store)


def test_atomic_append_reconstructs_state_before_authorizing(tmp_path: Path):
    keys, store = authority()
    journal = Journal(tmp_path / "journal.jsonl")
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    record = append_authorized_transition(journal, statement, store)
    assert record.sequence == 1
    recovered = recover_trust_store_from_journal(journal.path, store)
    assert recovered.active.key_id == "k1"


def test_atomic_append_refuses_stale_statement_without_writing(tmp_path: Path):
    keys, store = authority()
    journal = Journal(tmp_path / "journal.jsonl")
    k1 = Ed25519PrivateKey.generate()
    first = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    append_authorized_transition(journal, first, store)
    k2 = Ed25519PrivateKey.generate()
    stale = sign_rotation(keys["k0"], store, "k2", k2.public_key())
    with pytest.raises(TrustRecoveryError):
        append_authorized_transition(journal, stale, store)
    assert len(journal.records()) == 1


def test_atomic_append_rejects_corrupt_journal_before_validation(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    journal.append(Event("RUN_CREATED", "r", generation="a" * 64, data={"task": "x"}))
    journal.path.write_text(journal.path.read_text(encoding="utf-8") + "not-json\n", encoding="utf-8")
    keys, store = authority()
    k1 = Ed25519PrivateKey.generate()
    statement = sign_rotation(keys["k0"], store, "k1", k1.public_key())
    with pytest.raises(JournalIntegrityError):
        append_authorized_transition(journal, statement, store)
