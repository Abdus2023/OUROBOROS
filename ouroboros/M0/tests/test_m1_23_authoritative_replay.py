"""M1.23 — authoritative replay must consume quorum lifecycle in order."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.authoritative_recovery import AuthoritativeRecoveryError, recover_authoritative_state
from ourob.emergency_recovery import EmergencyRecoveryAuthority
from ourob.journal import Journal
from ourob.model import Event
from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority, sign_recovery_of_recovery
from ourob.recovery_of_recovery_lifecycle import RecoveryOfRecoveryOperation, sign_lifecycle_statement
from ourob.signed_trust import TrustStore
from ourob.trust_recovery import recovery_of_recovery_event
from ourob.authoritative_recovery import recovery_quorum_lifecycle_event


def _fixture(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    recovery_private = Ed25519PrivateKey.generate()
    recovery = EmergencyRecoveryAuthority.from_public_key("recovery-root-0", recovery_private.public_key())
    quorum_private = [Ed25519PrivateKey.generate() for _ in range(3)]
    quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"q{i}": key.public_key() for i, key in enumerate(quorum_private)}, 2
    )
    initial_store = TrustStore.genesis("trust-0", Ed25519PrivateKey.generate().public_key())
    journal.append(Event("OBSERVATION"))
    return journal, recovery, recovery_private, quorum, quorum_private, initial_store


def test_new_quorum_member_authorizes_later_break_glass(tmp_path: Path):
    journal, recovery, _, quorum, quorum_private, initial_store = _fixture(tmp_path)
    replacement_quorum_key = Ed25519PrivateKey.generate()
    lifecycle = sign_lifecycle_statement(
        [("q0", quorum_private[0]), ("q1", quorum_private[1])],
        quorum,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q1",
        replacement_key_id="q3",
        replacement_public_key=replacement_quorum_key.public_key().public_bytes_raw(),
        reason="replace quorum signer",
    )
    journal.append(recovery_quorum_lifecycle_event(lifecycle))
    current_quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {"q0": quorum_private[0].public_key(), "q2": quorum_private[2].public_key(), "q3": replacement_quorum_key.public_key()},
        2,
        epoch=1,
    )
    replacement_recovery_key = Ed25519PrivateKey.generate()
    break_glass = sign_recovery_of_recovery(
        [("q0", quorum_private[0]), ("q3", replacement_quorum_key)],
        current_quorum,
        recovery,
        "recovery-root-1",
        replacement_recovery_key.public_key().public_bytes_raw(),
        reason="replace compromised recovery root",
    )
    journal.append(recovery_of_recovery_event(break_glass))

    _, current_recovery, recovered_quorum = recover_authoritative_state(
        (record.event for record in journal.records()), initial_store, recovery, quorum
    )
    assert current_recovery is not None
    assert current_recovery.key_id == "recovery-root-1"
    assert recovered_quorum is not None
    assert recovered_quorum.epoch == 1
    assert set(recovered_quorum.keys) == {"q0", "q2", "q3"}


def test_removed_quorum_member_cannot_authorize_later_break_glass(tmp_path: Path):
    journal, recovery, _, quorum, quorum_private, initial_store = _fixture(tmp_path)
    replacement_quorum_key = Ed25519PrivateKey.generate()
    lifecycle = sign_lifecycle_statement(
        [("q0", quorum_private[0]), ("q1", quorum_private[1])], quorum,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q1", replacement_key_id="q3",
        replacement_public_key=replacement_quorum_key.public_key().public_bytes_raw(),
        reason="replace quorum signer",
    )
    journal.append(recovery_quorum_lifecycle_event(lifecycle))
    stale_quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {"q0": quorum_private[0].public_key(), "q2": quorum_private[2].public_key(), "q3": replacement_quorum_key.public_key()}, 2, epoch=1
    )
    replacement_recovery_key = Ed25519PrivateKey.generate()
    forged = sign_recovery_of_recovery(
        [("q0", quorum_private[0]), ("q2", quorum_private[2])],
        stale_quorum, recovery, "recovery-root-1",
        replacement_recovery_key.public_key().public_bytes_raw(), reason="valid current quorum"
    )
    # Alter one valid signature so that the statement is presented as if the
    # removed q1 had authorized it; the authoritative verifier must reject it.
    signatures = list(forged.signatures)
    signatures[1] = type(signatures[1])("q1", signatures[1].signature)
    from ourob.recovery_of_recovery import RecoveryOfRecoveryStatement
    forged_with_removed = RecoveryOfRecoveryStatement(
        forged.authority_epoch, forged.expected_recovery_key_id, forged.expected_recovery_epoch,
        forged.replacement_key_id, forged.replacement_public_key, forged.reason, tuple(signatures), forged.algorithm
    )
    journal.append(recovery_of_recovery_event(forged_with_removed))
    with pytest.raises(AuthoritativeRecoveryError, match="unauthorized signer|signature"):
        recover_authoritative_state((record.event for record in journal.records()), initial_store, recovery, quorum)
