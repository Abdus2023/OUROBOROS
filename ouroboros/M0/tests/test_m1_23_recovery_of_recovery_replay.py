from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.model import Event
from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority
from ourob.recovery_of_recovery_lifecycle import (
    RecoveryOfRecoveryOperation,
    apply_lifecycle_statement,
    recover_recovery_of_recovery_authority,
    recovery_of_recovery_lifecycle_event,
    sign_lifecycle_statement,
)
from ourob.signed_trust import SignedTrustError, public_bytes


def test_ordered_replay_advances_quorum_epoch():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys({f"q{i}": k.public_key() for i, k in enumerate(keys)}, 2)
    replacement = Ed25519PrivateKey.generate()
    rotation = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])], authority,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2", replacement_key_id="q3",
        replacement_public_key=public_bytes(replacement.public_key()), reason="rotate",
    )
    event = recovery_of_recovery_lifecycle_event(rotation)
    recovered = recover_recovery_of_recovery_authority([event], authority)
    assert recovered.epoch == 1
    assert set(recovered.keys) == {"q0", "q1", "q3"}


def test_replay_of_same_lifecycle_binding_is_rejected():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys({f"q{i}": k.public_key() for i, k in enumerate(keys)}, 2)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])], authority,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2", replacement_key_id="q3",
        replacement_public_key=public_bytes(replacement.public_key()), reason="rotate",
    )
    event = recovery_of_recovery_lifecycle_event(statement)
    with pytest.raises(SignedTrustError, match="replay"):
        recover_recovery_of_recovery_authority([event, event], authority)


def test_lifecycle_event_cannot_create_its_own_external_root():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys({f"q{i}": k.public_key() for i, k in enumerate(keys)}, 2)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])], authority,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2", replacement_key_id="q3",
        replacement_public_key=public_bytes(replacement.public_key()), reason="rotate",
    )
    scoped = Event(
        recovery_of_recovery_lifecycle_event(statement).name,
        run_id="run-1",
        data={"lifecycle": statement.to_record()},
    )
    with pytest.raises(SignedTrustError, match="run-scoped"):
        recover_recovery_of_recovery_authority([scoped], authority)


def test_epoch_cannot_be_skipped():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys({f"q{i}": k.public_key() for i, k in enumerate(keys)}, 2)
    statement = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])], authority,
        RecoveryOfRecoveryOperation.CHANGE_THRESHOLD,
        new_threshold=3, reason="raise threshold",
    )
    recovered = apply_lifecycle_statement(statement, authority)
    assert recovered.epoch == authority.epoch + 1
    with pytest.raises(SignedTrustError, match="wrong authority epoch"):
        apply_lifecycle_statement(statement, recovered)
