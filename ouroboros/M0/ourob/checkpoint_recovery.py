"""M1.17+ recovery of current checkpoints after interrupted publication.

Every candidate independently authenticates through the authoritative replay
path. Redundant files are availability copies, never roots of authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .checkpoint_store import CheckpointPublicationError, load_checkpoint
from .emergency_recovery import EmergencyRecoveryAuthority
from .journal import Journal
from .recovery_of_recovery import RecoveryOfRecoveryAuthority
from .signed_trust import TrustStore
from .trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository


class CheckpointRecoveryError(RuntimeError):
    """Raised when published checkpoint recovery cannot establish one authority."""


class CheckpointCandidateStatus(StrEnum):
    ABSENT = "ABSENT"
    INVALID = "INVALID"
    STALE = "STALE"
    CURRENT = "CURRENT"


@dataclass(frozen=True)
class CheckpointCandidate:
    path: Path
    status: CheckpointCandidateStatus
    checkpoint: object | None = None
    reason: str | None = None


def inspect_checkpoint(
    path: Path,
    journal: Journal,
    initial_store: TrustStore,
    *,
    generation: str,
    recovery: EmergencyRecoveryAuthority | None = None,
    recovery_quorum: RecoveryOfRecoveryAuthority | None = None,
) -> CheckpointCandidate:
    """Classify a checkpoint through the authoritative recovery path."""
    path = Path(path)
    if not path.exists():
        return CheckpointCandidate(path, CheckpointCandidateStatus.ABSENT, reason="checkpoint does not exist")
    try:
        checkpoint = load_checkpoint(path)
    except CheckpointPublicationError as exc:
        return CheckpointCandidate(path, CheckpointCandidateStatus.INVALID, reason=str(exc))
    try:
        authenticate_current_repository(
            journal,
            ExternalTrustAuthority(initial_store, checkpoint, recovery, recovery_quorum),
            generation=generation,
        )
    except TrustBoundaryError as exc:
        return CheckpointCandidate(path, CheckpointCandidateStatus.STALE, checkpoint, str(exc))
    return CheckpointCandidate(path, CheckpointCandidateStatus.CURRENT, checkpoint)


def recover_current_checkpoint(
    paths: tuple[Path, ...],
    journal: Journal,
    initial_store: TrustStore,
    *,
    generation: str,
    recovery: EmergencyRecoveryAuthority | None = None,
    recovery_quorum: RecoveryOfRecoveryAuthority | None = None,
) -> tuple[object, Path]:
    """Recover exactly one current checkpoint from redundant publication slots.

    Invalid and stale candidates are ignored for availability, but at least one
    candidate must authenticate. If two distinct candidates both authenticate,
    recovery fails closed because the publication state is ambiguous.
    """
    if not paths:
        raise CheckpointRecoveryError("no checkpoint candidates were supplied")
    candidates = tuple(
        inspect_checkpoint(
            path,
            journal,
            initial_store,
            generation=generation,
            recovery=recovery,
            recovery_quorum=recovery_quorum,
        )
        for path in paths
    )
    current = tuple(candidate for candidate in candidates if candidate.status is CheckpointCandidateStatus.CURRENT)
    if not current:
        summary = "; ".join(f"{candidate.path}: {candidate.status}" for candidate in candidates)
        raise CheckpointRecoveryError(f"no current checkpoint authenticated: {summary}")
    first = current[0]
    assert first.checkpoint is not None
    for candidate in current[1:]:
        assert candidate.checkpoint is not None
        if candidate.checkpoint != first.checkpoint:
            raise CheckpointRecoveryError("multiple distinct checkpoints authenticate as current")
    return first.checkpoint, first.path
