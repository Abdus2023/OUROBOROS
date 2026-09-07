"""M1.22 — quorum recovery-of-recovery conformance."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.emergency_recovery import EmergencyRecoveryAuthority, sign_emergency_recovery
from ourob.journal import Journal
from ourob.model import Event, EventName
from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority, sign_recovery_of_recovery, verify_recovery_of_recovery
from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_recovery import (
    TrustRecoveryError,
    append_authorized_emergency_recovery,
    append_authorized_recovery_of_recovery,
    recover_recovery_authority,
    recover_trust_store,
)


def _fixture(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    recovery_private = Ed25519PrivateKey.generate()
    recovery = EmergencyRecoveryAuthority.from_public_key("recovery-root-0", recovery_private.public_key())
    quorum_private = [Ed25519PrivateKey.generate() for _ in range(3)]
    quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"break-{i}": key.public_key() for i, key in enumerate(quorum_private)}, 2
    )
    journal.append(Event("OBSERVATION"))
    return journal, recovery, recovery_private, quorum, quorum_private


def _statement(recovery, quorum, quorum_private):
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_of_recovery(
        [("break-0", quorum_private[0]), ("break-1", quorum_private[1])],
        quorum,
        recovery,
        "recovery-root-1",
        replacement.public_key().public_bytes_raw(),
        reason="current recovery root compromised",
    )
    return statement, replacement


def test_valid_threshold_replaces_compromised_recovery_root(tmp_path: Path):
    journal, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, replacement = _statement(recovery, quorum, quorum_private)
    append_authorized_recovery_of_recovery(journal, statement, recovery, quorum)
    current = recover_recovery_authority((r.event for r in journal.records()), recovery, quorum)
    assert current.key_id == "recovery-root-1"
    assert current.epoch == 1
    assert current.public_key == replacement.public_key().public_bytes_raw()


def test_insufficient_threshold_is_rejected(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_recovery_of_recovery(
        [("break-0", quorum_private[0])], quorum, recovery, "recovery-root-1",
        replacement.public_key().public_bytes_raw(), reason="break glass"
    )
    with pytest.raises(SignedTrustError, match="threshold"):
        verify_recovery_of_recovery(statement, quorum, recovery)


def test_duplicate_signer_is_rejected(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    with pytest.raises(SignedTrustError, match="duplicate"):
        sign_recovery_of_recovery(
            [("break-0", quorum_private[0]), ("break-0", quorum_private[0])], quorum, recovery,
            "recovery-root-1", Ed25519PrivateKey.generate().public_key().public_bytes_raw(), reason="break glass"
        )


def test_unauthorized_signer_is_rejected(tmp_path: Path):
    _, recovery, _, quorum, _ = _fixture(tmp_path)
    rogue = Ed25519PrivateKey.generate()
    with pytest.raises(SignedTrustError, match="not externally authorized"):
        sign_recovery_of_recovery(
            [("rogue", rogue)], quorum, recovery, "recovery-root-1",
            Ed25519PrivateKey.generate().public_key().public_bytes_raw(), reason="break glass"
        )


def test_wrong_expected_recovery_root_is_rejected(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    replacement_root = EmergencyRecoveryAuthority.from_public_key("other-root", Ed25519PrivateKey.generate().public_key())
    with pytest.raises(SignedTrustError, match="different recovery root"):
        verify_recovery_of_recovery(statement, quorum, replacement_root)


def test_wrong_expected_recovery_epoch_is_rejected(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    wrong_epoch = EmergencyRecoveryAuthority(recovery.key_id, recovery.public_key, epoch=7)
    with pytest.raises(SignedTrustError, match="epoch"):
        verify_recovery_of_recovery(statement, quorum, wrong_epoch)


def test_replay_is_rejected(tmp_path: Path):
    journal, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    append_authorized_recovery_of_recovery(journal, statement, recovery, quorum)
    with pytest.raises(TrustRecoveryError, match="different recovery root|replay|already been used"):
        append_authorized_recovery_of_recovery(journal, statement, recovery, quorum)


def test_break_glass_event_is_not_run_scoped(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    event = Event(EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value, run_id="run-1", data={"recovery": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="must not be run-scoped"):
        recover_recovery_authority([event], recovery, quorum)


def test_missing_external_quorum_fails_closed(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    event = Event(EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value, data={"recovery": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="externally provisioned quorum"):
        recover_recovery_authority([event], recovery, None)


def test_old_recovery_root_cannot_authorize_after_break_glass(tmp_path: Path):
    journal, recovery, old_private, quorum, quorum_private = _fixture(tmp_path)
    statement, replacement = _statement(recovery, quorum, quorum_private)
    append_authorized_recovery_of_recovery(journal, statement, recovery, quorum)
    current = recover_recovery_authority((r.event for r in journal.records()), recovery, quorum)
    assert old_private.public_key().public_bytes_raw() != current.public_key
    with pytest.raises(SignedTrustError):
        from ourob.emergency_recovery import sign_recovery_root_rotation
        sign_recovery_root_rotation(old_private, current, "recovery-root-2", Ed25519PrivateKey.generate().public_key().public_bytes_raw())


def test_no_private_material_is_serialized(tmp_path: Path):
    _, recovery, _, quorum, quorum_private = _fixture(tmp_path)
    statement, _ = _statement(recovery, quorum, quorum_private)
    record = statement.to_record()
    assert "private_key" not in record
    assert "seed" not in record
    assert all("private_key" not in item and "seed" not in item for item in record["signatures"])


def test_recovery_and_trust_replay_are_strictly_interleaved(tmp_path: Path):
    """A later recovery-root replacement must not authorize an earlier event."""
    journal, recovery, recovery_private, quorum, quorum_private = _fixture(tmp_path)
    trust_private_1 = Ed25519PrivateKey.generate()
    initial_store = TrustStore.genesis("trust-0", Ed25519PrivateKey.generate().public_key())

    first = sign_emergency_recovery(
        recovery_private, recovery, initial_store, "trust-1",
        trust_private_1.public_key().public_bytes_raw(), reason="first recovery",
    )
    append_authorized_emergency_recovery(journal, first, initial_store, recovery, quorum)

    break_glass, recovery_private_1 = _statement(recovery, quorum, quorum_private)
    append_authorized_recovery_of_recovery(journal, break_glass, recovery, quorum)
    current_store = recover_trust_store((r.event for r in journal.records()), initial_store, recovery, quorum)

    trust_private_2 = Ed25519PrivateKey.generate()
    second = sign_emergency_recovery(
        recovery_private_1,
        EmergencyRecoveryAuthority.from_public_key("recovery-root-1", recovery_private_1.public_key()),
        current_store,
        "trust-2",
        trust_private_2.public_key().public_bytes_raw(),
        reason="post break-glass recovery",
    )
    append_authorized_emergency_recovery(journal, second, initial_store, recovery, quorum)

    recovered = recover_trust_store((r.event for r in journal.records()), initial_store, recovery, quorum)
    assert recovered.active.key_id == "trust-2"
    assert recovered.epoch == 2
