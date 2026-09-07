from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority
from ourob.recovery_of_recovery_lifecycle import (
    RecoveryOfRecoveryOperation,
    RecoveryOfRecoveryLifecycleStatement,
    apply_lifecycle_statement,
    sign_lifecycle_statement,
    verify_lifecycle_statement,
)
from ourob.signed_trust import SignedTrustError, public_bytes


def _authority() -> tuple[RecoveryOfRecoveryAuthority, list[Ed25519PrivateKey]]:
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"q{i}": key.public_key() for i, key in enumerate(keys)}, 2
    )
    return authority, keys


def _signed(authority, keys, operation, **kwargs):
    return sign_lifecycle_statement(
        [(f"q{i}", keys[i]) for i in (0, 1)],
        authority,
        operation,
        reason="conformance",
        **kwargs,
    )


def test_signer_rotation_advances_epoch_and_preserves_threshold():
    authority, keys = _authority()
    replacement = Ed25519PrivateKey.generate()
    statement = _signed(
        authority,
        keys,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2",
        replacement_key_id="q3",
        replacement_public_key=public_bytes(replacement.public_key()),
    )
    next_authority = apply_lifecycle_statement(statement, authority)
    assert next_authority.epoch == 1
    assert next_authority.threshold == 2
    assert set(next_authority.keys) == {"q0", "q1", "q3"}


def test_revocation_cannot_leave_quorum_unsatisfiable():
    authority, keys = _authority()
    statement = _signed(
        authority, keys, RecoveryOfRecoveryOperation.REVOKE_SIGNER, target_key_id="q2"
    )
    next_authority = apply_lifecycle_statement(statement, authority)
    assert set(next_authority.keys) == {"q0", "q1"}
    assert next_authority.threshold == 2

    with pytest.raises(SignedTrustError, match="incompatible|threshold"):
        _signed(
            next_authority,
            [keys[0], keys[1]],
            RecoveryOfRecoveryOperation.REVOKE_SIGNER,
            target_key_id="q1",
        )


def test_threshold_change_is_authenticated_and_epoch_bound():
    authority, keys = _authority()
    statement = _signed(
        authority,
        keys,
        RecoveryOfRecoveryOperation.CHANGE_THRESHOLD,
        new_threshold=3,
    )
    next_authority = apply_lifecycle_statement(statement, authority)
    assert next_authority.threshold == 3
    assert next_authority.epoch == 1

    stale = RecoveryOfRecoveryLifecycleStatement(
        statement.operation,
        0,
        statement.target_key_id,
        statement.replacement_key_id,
        statement.replacement_public_key,
        statement.new_threshold,
        statement.reason,
        statement.signatures,
        statement.algorithm,
    )
    with pytest.raises(SignedTrustError, match="wrong authority epoch"):
        verify_lifecycle_statement(stale, next_authority)


def test_old_signer_cannot_authorize_after_rotation():
    authority, keys = _authority()
    replacement = Ed25519PrivateKey.generate()
    rotation = _signed(
        authority,
        keys,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2",
        replacement_key_id="q3",
        replacement_public_key=public_bytes(replacement.public_key()),
    )
    next_authority = apply_lifecycle_statement(rotation, authority)
    with pytest.raises(SignedTrustError, match="not externally authorized"):
        sign_lifecycle_statement(
            [("q0", keys[0]), ("q2", keys[2])],
            next_authority,
            RecoveryOfRecoveryOperation.CHANGE_THRESHOLD,
            new_threshold=2,
            reason="stale signer",
        )


def test_lifecycle_statement_binds_all_mutation_fields():
    authority, keys = _authority()
    statement = _signed(
        authority,
        keys,
        RecoveryOfRecoveryOperation.CHANGE_THRESHOLD,
        new_threshold=3,
    )
    tampered = RecoveryOfRecoveryLifecycleStatement(
        statement.operation,
        statement.authority_epoch,
        statement.target_key_id,
        statement.replacement_key_id,
        statement.replacement_public_key,
        2,
        statement.reason,
        statement.signatures,
        statement.algorithm,
    )
    with pytest.raises(SignedTrustError, match="signature is invalid|threshold"):
        verify_lifecycle_statement(tampered, authority)


def test_replacement_key_id_and_material_must_be_fresh():
    authority, keys = _authority()
    with pytest.raises(SignedTrustError, match="fresh"):
        _signed(
            authority,
            keys,
            RecoveryOfRecoveryOperation.ROTATE_SIGNER,
            target_key_id="q2",
            replacement_key_id="q1",
            replacement_public_key=authority.keys["q1"],
        )
