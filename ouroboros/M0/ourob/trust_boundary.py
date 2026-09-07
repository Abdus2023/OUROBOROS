"""External trust boundary for authoritative cold bootstrap (M1.9).

The repository may contain signed trust-transition events and a journal, but it
never supplies the initial trust root.  An operator provisions a public
``TrustStore`` externally and a signed checkpoint produced by an external key
authority.  M1.9 binds those facts to the *current* repository state:

    external initial root
        -> authenticated trust-transition replay
        -> signed current-head checkpoint
        -> journal integrity + anchor verification
        -> generation equality
        -> authoritative bootstrap

A checkpoint over an older prefix is valid for historical audit, but it is
never sufficient for current bootstrap authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .generation import repository_generation
from .journal import Journal, JournalIntegrityError, JournalRecord
from .signed_trust import SignedCheckpoint, SignedTrustError, TrustStore
from .trust import TrustAnchorError
from .trust_recovery import TrustRecoveryError, recover_trust_store


class TrustBoundaryError(RuntimeError):
    """Raised when external trust cannot authenticate the current repository."""


@dataclass(frozen=True)
class ExternalTrustAuthority:
    """Externally provisioned authority material used only for verification."""

    initial_store: TrustStore
    checkpoint: SignedCheckpoint


def load_external_authority(checkpoint_path: Path, trust_store_path: Path) -> ExternalTrustAuthority:
    """Load public authority material from paths outside the repository contract."""
    try:
        checkpoint_raw = __import__("json").loads(Path(checkpoint_path).read_text(encoding="utf-8"))
        store_raw = __import__("json").loads(Path(trust_store_path).read_text(encoding="utf-8"))
        checkpoint = SignedCheckpoint.from_record(checkpoint_raw)
        store = TrustStore.from_record(store_raw)
    except (OSError, ValueError, TypeError, SignedTrustError) as exc:
        raise TrustBoundaryError(f"external trust material is invalid: {exc}") from exc
    return ExternalTrustAuthority(store, checkpoint)


def authenticate_current_repository(
    journal: Journal,
    authority: ExternalTrustAuthority,
    *,
    generation: str | None = None,
) -> tuple[TrustStore, tuple[JournalRecord, ...]]:
    """Authenticate the complete current journal and current repository generation.

    The initial trust store is the external root.  Durable trust transitions
    are replayed from the validated journal while the signed checkpoint is
    checked against the resulting trust state.  The checkpoint must bind the
    journal's actual current head and the current repository generation.
    """
    try:
        records = journal.records()
        recovered_store = recover_trust_store((record.event for record in records), authority.initial_store)
        current_generation = generation if generation is not None else repository_generation(journal.path.parent.parent).id
        if authority.checkpoint.generation is None:
            raise TrustBoundaryError("current bootstrap requires a generation-bound signed checkpoint")
        if authority.checkpoint.generation != current_generation:
            raise TrustBoundaryError("signed checkpoint generation does not match current repository generation")
        if authority.checkpoint.sequence != len(records):
            raise TrustBoundaryError("signed checkpoint does not bind the current journal head")
        if records:
            if authority.checkpoint.journal_digest != records[-1].digest:
                raise TrustBoundaryError("signed checkpoint does not bind the current journal head digest")
        elif authority.checkpoint.journal_digest != "GENESIS":
            raise TrustBoundaryError("empty journal requires a GENESIS checkpoint")
        recovered_store.verify(authority.checkpoint, historical=False)
        from .trust import verify_anchor
        verify_anchor(authority.checkpoint.anchor, records, current_generation)
        return recovered_store, tuple(records)
    except (JournalIntegrityError, SignedTrustError, TrustAnchorError, TrustRecoveryError) as exc:
        raise TrustBoundaryError(f"current trust authentication failed: {exc}") from exc


def authenticate_current_paths(
    journal_path: Path,
    checkpoint_path: Path,
    trust_store_path: Path,
    *,
    repo_root: Path | None = None,
) -> TrustStore:
    """Convenience entry point for CLI/bootstrap callers."""
    authority = load_external_authority(checkpoint_path, trust_store_path)
    journal = Journal(journal_path)
    generation = repository_generation(repo_root).id if repo_root is not None else None
    store, _ = authenticate_current_repository(journal, authority, generation=generation)
    return store
