"""M1.18/M1.20 — explicit checkpoint authority state classification."""
from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from .checkpoint_store import CheckpointPublicationError, load_checkpoint
from .journal import Journal, JournalIntegrityError
from .signed_trust import KeyState
from .trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository
from .trust_recovery import TrustRecoveryError, recover_trust_store


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
    """Classify one checkpoint without granting authority."""
    path = Path(checkpoint_path)
    if not path.exists():
        return CheckpointAuthorityState.ABSENT
    try:
        checkpoint = load_checkpoint(path)
    except CheckpointPublicationError:
        return CheckpointAuthorityState.INVALID

    try:
        authenticate_current_repository(
            journal,
            ExternalTrustAuthority(authority.initial_store, checkpoint, authority.recovery),
            generation=generation,
        )
        return CheckpointAuthorityState.CURRENT
    except TrustBoundaryError:
        pass

    # REVOKED is a stronger diagnosis than STALE: the signed checkpoint names
    # a key which the authenticated trust history has permanently revoked.
    try:
        records = journal.records()
        recovered = recover_trust_store(
            (record.event for record in records), authority.initial_store, authority.recovery
        )
        key = recovered.keys.get(checkpoint.key_id)
        if key is not None and key.state is KeyState.REVOKED:
            return CheckpointAuthorityState.REVOKED
    except (JournalIntegrityError, TrustRecoveryError, ValueError, TypeError):
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
