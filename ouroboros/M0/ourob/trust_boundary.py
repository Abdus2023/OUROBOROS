"""External trust boundary for authoritative cold bootstrap (M1.13)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .generation import repository_generation
from .journal import Journal, JournalIntegrityError, JournalRecord
from .signed_trust import SignedTrustError, TrustStore
from .trust import TrustAnchorError, verify_anchor
from .trust_checkpoint import TRUST_BOUND_CHECKPOINT_SCHEMA, TrustStateBoundCheckpoint, trust_state_digest
from .trust_recovery import TrustRecoveryError, recover_trust_store


class TrustBoundaryError(RuntimeError):
    """Raised when external trust cannot authenticate the current repository."""


@dataclass(frozen=True)
class ExternalTrustAuthority:
    """Externally provisioned authority material used only for verification."""

    initial_store: TrustStore
    checkpoint: TrustStateBoundCheckpoint


def load_external_authority(checkpoint_path: Path, trust_store_path: Path) -> ExternalTrustAuthority:
    """Load public authority material from externally supplied paths."""
    try:
        checkpoint_raw = json.loads(Path(checkpoint_path).read_text(encoding="utf-8"))
        store_raw = json.loads(Path(trust_store_path).read_text(encoding="utf-8"))
        checkpoint = TrustStateBoundCheckpoint.from_record(checkpoint_raw)
        store = TrustStore.from_record(store_raw)
    except (OSError, json.JSONDecodeError, ValueError, TypeError, SignedTrustError) as exc:
        raise TrustBoundaryError(f"external trust material is invalid: {exc}") from exc
    return ExternalTrustAuthority(store, checkpoint)


def authenticate_current_repository(
    journal: Journal,
    authority: ExternalTrustAuthority,
    *,
    generation: str | None = None,
) -> tuple[TrustStore, tuple[JournalRecord, ...]]:
    """Authenticate current trust state, journal head, and repository generation."""
    try:
        records = journal.records()
        recovered_store = recover_trust_store((record.event for record in records), authority.initial_store)
        current_generation = generation if generation is not None else repository_generation(journal.path.parent.parent).id
        checkpoint = authority.checkpoint
        if checkpoint.signed_payload().get("schema") != TRUST_BOUND_CHECKPOINT_SCHEMA:
            raise TrustBoundaryError("authoritative current bootstrap requires a trust-state-bound checkpoint")
        if checkpoint.generation is None:
            raise TrustBoundaryError("current bootstrap requires a generation-bound signed checkpoint")
        if checkpoint.generation != current_generation:
            raise TrustBoundaryError("signed checkpoint generation does not match current repository generation")
        if checkpoint.sequence != len(records):
            raise TrustBoundaryError("signed checkpoint does not bind the current journal head")
        expected_digest = records[-1].digest if records else "GENESIS"
        if checkpoint.journal_digest != expected_digest:
            raise TrustBoundaryError("signed checkpoint does not bind the current journal head digest")
        if checkpoint.trust_state_digest != trust_state_digest(recovered_store):
            raise TrustBoundaryError("signed checkpoint does not bind the reconstructed trust state")
        recovered_store.verify(checkpoint, historical=False)
        verify_anchor(checkpoint.anchor, records, current_generation)
        return recovered_store, tuple(records)
    except (JournalIntegrityError, SignedTrustError, TrustAnchorError, TrustRecoveryError) as exc:
        raise TrustBoundaryError(f"current trust authentication failed: {exc}") from exc


def authenticate_current_paths(
    journal_path: Path,
    checkpoint_path: Path,
    trust_store_path: Path,
    *,
    repo_root: Path,
) -> TrustStore:
    """Authenticate current authority from externally supplied public files."""
    authority = load_external_authority(checkpoint_path, trust_store_path)
    generation = repository_generation(repo_root).id
    store, _ = authenticate_current_repository(Journal(journal_path), authority, generation=generation)
    return store
