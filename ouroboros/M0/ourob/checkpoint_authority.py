"""M1.18 — explicit checkpoint authority state classification.

Structural validity is not authority.  A checkpoint is authoritative only
when it authenticates the current journal, generation, and reconstructed trust
state against the externally provisioned genesis root.
"""
from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from .checkpoint_recovery import CheckpointRecoveryError, inspect_checkpoint
from .checkpoint_store import load_checkpoint
from .journal import Journal
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
    """Classify one externally published checkpoint without granting authority."""
    path = Path(checkpoint_path)
    if not path.exists():
        return CheckpointAuthorityState.ABSENT
    try:
        checkpoint = load_checkpoint(path)
    except Exception:
        return CheckpointAuthorityState.INVALID
    try:
        authenticate_current_repository(
            journal,
            ExternalTrustAuthority(authority.initial_store, checkpoint),
            generation=generation,
        )
    except TrustBoundaryError:
        return _classify_noncurrent(journal, authority, checkpoint, generation)
    return CheckpointAuthorityState.CURRENT


def _classify_noncurrent(journal, authority, checkpoint, generation: str) -> CheckpointAuthorityState:
    """Distinguish ordinary staleness from an explicitly revoked signer."""
    try:
        records = journal.records()
        # A revoked signer can never be authoritative, even historically for
        # current use.  inspect_checkpoint is deliberately non-authoritative.
        report = inspect_checkpoint(checkpoint, records, generation, authority.initial_store)
        if report.state == "REVOKED":
            return CheckpointAuthorityState.REVOKED
    except Exception:
        pass
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
        raise CheckpointAuthorityError(f"checkpoint authority state is {state.value}; CURRENT required")
