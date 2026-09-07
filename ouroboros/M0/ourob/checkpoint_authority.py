"""M1.18+ — explicit checkpoint authority state classification.

All current-authority decisions use the single authoritative replay path so
recovery-quorum lifecycle history cannot be bypassed by a legacy trust replay.
"""
from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from .authoritative_recovery import AuthoritativeRecoveryError, recover_authoritative_state
from .checkpoint_store import CheckpointPublicationError, load_checkpoint
from .journal import Journal, JournalIntegrityError
from .signed_trust import KeyState
from .trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository


class CheckpointAuthorityState(StrEnum):
    ABSENT = "ABSENT"
    INVALID = "INVALID"
    STALE = "STALE"
    CURRENT = "CURRENT"
    REVOKED = "REVOKED"


class CheckpointAuthorityError(RuntimeError):
    """Raised when checkpoint authority cannot be classified safely."""


def classify_checkpoint(
    journal: Journal,
    authority: ExternalTrustAuthority,
    checkpoint_path: Path,
    *,
    generation: str,
) -> CheckpointAuthorityState:
    """Classify one checkpoint without treating repository data as authority."""
    path = Path(checkpoint_path)
    if not path.exists():
        return CheckpointAuthorityState.ABSENT
    try:
        checkpoint = load_checkpoint(path)
    except CheckpointPublicationError:
        return CheckpointAuthorityState.INVALID

    candidate_authority = ExternalTrustAuthority(
        authority.initial_store,
        checkpoint,
        authority.recovery,
        authority.recovery_quorum,
    )
    try:
        authenticate_current_repository(journal, candidate_authority, generation=generation)
        return CheckpointAuthorityState.CURRENT
    except TrustBoundaryError:
        pass

    # REVOKED is a stronger diagnosis than STALE: the signed checkpoint names
    # a key which the *authoritatively reconstructed* trust history revoked.
    try:
        records = journal.records()
        recovered, _, _ = recover_authoritative_state(
            (record.event for record in records),
            authority.initial_store,
            authority.recovery,
            authority.recovery_quorum,
        )
        key = recovered.keys.get(checkpoint.key_id)
        if key is not None and key.state is KeyState.REVOKED:
            return CheckpointAuthorityState.REVOKED
    except (JournalIntegrityError, AuthoritativeRecoveryError, ValueError, TypeError):
        return CheckpointAuthorityState.INVALID
    return CheckpointAuthorityState.STALE


def require_current_checkpoint(
    journal: Journal,
    authority: ExternalTrustAuthority,
    checkpoint_path: Path,
    *,
    generation: str,
) -> None:
    """Fail closed unless the supplied checkpoint is the current authority."""
    state = classify_checkpoint(journal, authority, checkpoint_path, generation=generation)
    if state is not CheckpointAuthorityState.CURRENT:
        raise CheckpointAuthorityError(
            f"checkpoint authority state is {state.value}; CURRENT required"
        )
