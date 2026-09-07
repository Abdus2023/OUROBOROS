"""M1.15 — checkpoint freshness across trust lifecycle changes."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository
from ourob.trust_checkpoint import issue_current_checkpoint
from ourob.trust_lifecycle import sign_rotation
from ourob.trust_recovery import append_authorized_transition

GENERATION = "a" * 64


def _root_and_journal(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    root_key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", root_key.public_key())
    journal.append(Event("OBSERVATION"))
    return journal, root_key, root


def test_checkpoint_is_current_before_rotation(tmp_path: Path):
    journal, root_key, root = _root_and_journal(tmp_path)
    checkpoint = issue_current_checkpoint(journal, root, root_key, "k0", generation=GENERATION)
    store, records = authenticate_current_repository(
        journal, ExternalTrustAuthority(root, checkpoint), generation=GENERATION
    )
    assert store.epoch == 0
    assert checkpoint.sequence == len(records)


def test_rotation_invalidates_previous_checkpoint(tmp_path: Path):
    journal, root_key, root = _root_and_journal(tmp_path)
    checkpoint = issue_current_checkpoint(journal, root, root_key, "k0", generation=GENERATION)
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(root_key, root, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, root)
    with pytest.raises(TrustBoundaryError, match="current journal head"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(root, checkpoint), generation=GENERATION
        )


def test_rotation_requires_new_checkpoint_signed_by_new_active_key(tmp_path: Path):
    journal, root_key, root = _root_and_journal(tmp_path)
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(root_key, root, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, root)
    with pytest.raises(SignedTrustError, match="active trust key"):
        issue_current_checkpoint(journal, root, root_key, "k0", generation=GENERATION)
    checkpoint = issue_current_checkpoint(journal, root, next_key, "k1", generation=GENERATION)
    store, _ = authenticate_current_repository(
        journal, ExternalTrustAuthority(root, checkpoint), generation=GENERATION
    )
    assert store.active.key_id == "k1"
    assert checkpoint.trust_epoch == 1


def test_old_checkpoint_cannot_authorize_after_generation_change(tmp_path: Path):
    journal, root_key, root = _root_and_journal(tmp_path)
    checkpoint = issue_current_checkpoint(journal, root, root_key, "k0", generation=GENERATION)
    with pytest.raises(TrustBoundaryError, match="generation"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(root, checkpoint), generation="b" * 64
        )
