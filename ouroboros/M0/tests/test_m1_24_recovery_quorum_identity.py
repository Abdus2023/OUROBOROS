from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority
from ourob.recovery_of_recovery_lifecycle import (
    RecoveryOfRecoveryOperation,
    recover_recovery_of_recovery_authority,
    recovery_of_recovery_lifecycle_event,
    sign_lifecycle_statement,
)
from ourob.signed_trust import SignedTrustError, public_bytes


def test_historical_quorum_signer_id_cannot_be_reused():
    keys = [Ed25519PrivateKey.generate() for _ in range(4)]
    authority = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"q{i}": keys[i].public_key() for i in range(3)}, 2
    )

    first = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])],
        authority,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q2",
        replacement_key_id="q3",
        replacement_public_key=public_bytes(keys[3].public_key()),
        reason="replace q2",
    )
    authority_after_first = authority
    from ourob.recovery_of_recovery_lifecycle import apply_lifecycle_statement
    authority_after_first = apply_lifecycle_statement(first, authority_after_first)

    q4 = Ed25519PrivateKey.generate()
    second = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])],
        authority_after_first,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q3",
        replacement_key_id="q4",
        replacement_public_key=public_bytes(q4.public_key()),
        reason="replace q3",
    )
    authority_after_second = apply_lifecycle_statement(second, authority_after_first)

    reuse = sign_lifecycle_statement(
        [("q0", keys[0]), ("q1", keys[1])],
        authority_after_second,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q4",
        replacement_key_id="q2",
        replacement_public_key=public_bytes(keys[2].public_key()),
        reason="attempt historical id reuse",
    )

    with pytest.raises(SignedTrustError, match="previously used"):
        recover_recovery_of_recovery_authority(
            [
                recovery_of_recovery_lifecycle_event(first),
                recovery_of_recovery_lifecycle_event(second),
                recovery_of_recovery_lifecycle_event(reuse),
            ],
            authority,
        )
