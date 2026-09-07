"""M1.21 — authenticated emergency recovery-root lifecycle conformance."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.emergency_recovery import EmergencyRecoveryAuthority, RecoveryRootTransition, sign_emergency_recovery, sign_recovery_root_rotation
from ourob.journal import Journal
from ourob.model import Event, EventName
from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_recovery import TrustRecoveryError, append_authorized_emergency_recovery, append_authorized_recovery_root_rotation, recover_recovery_authority, recover_trust_store


def _fixture(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    root_private = Ed25519PrivateKey.generate()
    root = EmergencyRecoveryAuthority.from_public_key("recovery-root-0", root_private.public_key())
    journal.append(Event("OBSERVATION"))
    return journal, root, root_private


def test_recovery_root_rotation_advances_external_authority(tmp_path: Path):
    journal, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    append_authorized_recovery_root_rotation(journal, statement, root)
    current = recover_recovery_authority((r.event for r in journal.records()), root)
    assert current.key_id == "recovery-root-1"
    assert current.epoch == 1
    assert current.public_key == replacement.public_key().public_bytes_raw()


def test_new_recovery_root_authorizes_subsequent_emergency_replacement(tmp_path: Path):
    journal, root, root_private = _fixture(tmp_path)
    replacement_root_private = Ed25519PrivateKey.generate()
    root_rotation = sign_recovery_root_rotation(root_private, root, "recovery-root-1", replacement_root_private.public_key().public_bytes_raw())
    append_authorized_recovery_root_rotation(journal, root_rotation, root)
    current_root = recover_recovery_authority((r.event for r in journal.records()), root)
    trust_private = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("trust-0", trust_private.public_key())
    replacement_trust_private = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(replacement_root_private, current_root, store, "trust-1", replacement_trust_private.public_key().public_bytes_raw(), reason="compromise")
    append_authorized_emergency_recovery(journal, statement, store, root)
    current_store = recover_trust_store((r.event for r in journal.records()), store, root)
    assert current_store.active.key_id == "trust-1"
    assert current_store.epoch == 1


def test_old_recovery_root_cannot_authorize_after_rotation(tmp_path: Path):
    journal, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    rotation = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    append_authorized_recovery_root_rotation(journal, rotation, root)
    stale = sign_recovery_root_rotation(private, root, "recovery-root-2", Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(TrustRecoveryError):
        append_authorized_recovery_root_rotation(journal, stale, root)


def test_forged_root_rotation_is_rejected(tmp_path: Path):
    journal, root, _ = _fixture(tmp_path)
    forged_private = Ed25519PrivateKey.generate()
    forged = sign_recovery_root_rotation(forged_private, EmergencyRecoveryAuthority.from_public_key("forged", forged_private.public_key()), "recovery-root-1", Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(TrustRecoveryError):
        append_authorized_recovery_root_rotation(journal, forged, root)


def test_root_rotation_requires_fresh_key_id_and_material(tmp_path: Path):
    _, root, private = _fixture(tmp_path)
    with pytest.raises(SignedTrustError):
        sign_recovery_root_rotation(private, root, root.key_id, Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(SignedTrustError):
        sign_recovery_root_rotation(private, root, "recovery-root-1", root.public_key)


def test_root_rotation_replay_and_historical_id_reuse_are_rejected(tmp_path: Path):
    journal, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    append_authorized_recovery_root_rotation(journal, statement, root)
    with pytest.raises(TrustRecoveryError):
        append_authorized_recovery_root_rotation(journal, statement, root)
    second_private = replacement
    current = recover_recovery_authority((r.event for r in journal.records()), root)
    reuse = sign_recovery_root_rotation(second_private, current, root.key_id, Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    with pytest.raises(TrustRecoveryError, match="already been used"):
        recover_recovery_authority([*[(r.event) for r in journal.records()], Event(EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value, data={"transition": reuse.to_record()})], root)


def test_root_rotation_is_not_run_scoped(tmp_path: Path):
    _, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    event = Event(EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value, run_id="run-1", data={"transition": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="must not be run-scoped"):
        recover_recovery_authority([event], root)


def test_repository_cannot_create_recovery_root_from_tampered_event(tmp_path: Path):
    _, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    record = statement.to_record()
    record["replacement_key_id"] = "attacker-root"
    event = Event(EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value, data={"transition": record})
    with pytest.raises(TrustRecoveryError):
        recover_recovery_authority([event], root)


def test_recovery_root_transition_has_no_private_material(tmp_path: Path):
    _, root, private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_root_rotation(private, root, "recovery-root-1", replacement.public_key().public_bytes_raw())
    record = statement.to_record()
    assert "private_key" not in record
    assert "seed" not in record
