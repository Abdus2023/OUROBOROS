"""M1.13 — current checkpoint continuity at the external trust boundary."""

import dataclasses
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import TrustStore
from ourob.trust import JournalTrustAnchor
from ourob.trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository
from ourob.trust_checkpoint import sign_trust_state_checkpoint, trust_state_digest

GEN_A = "a" * 64
GEN_B = "b" * 64


def _authority(generation: str, journal: Journal) -> tuple[TrustStore, object]:
    journal.append(Event("RUN_CREATED", "r", generation=generation, data={"task": "fixture"}))
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, JournalTrustAnchor.capture(journal.records(), generation))
    return store, checkpoint


def test_current_boundary_accepts_matching_state_and_head(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority(GEN_A, journal)
    recovered, records = authenticate_current_repository(
        journal, ExternalTrustAuthority(store, checkpoint), generation=GEN_A
    )
    assert len(records) == 1
    assert recovered.to_record() == store.to_record()


def test_current_boundary_rejects_wrong_trust_state_digest(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority(GEN_A, journal)
    assert checkpoint.trust_state_digest == trust_state_digest(store)
    tampered = dataclasses.replace(checkpoint, trust_state_digest="0" * 64)
    with pytest.raises(TrustBoundaryError, match="trust state"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(store, tampered), generation=GEN_A
        )


def test_current_boundary_rejects_wrong_generation(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority(GEN_A, journal)
    with pytest.raises(TrustBoundaryError, match="generation"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(store, checkpoint), generation=GEN_B
        )


def test_current_boundary_rejects_wrong_journal_head(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority(GEN_A, journal)
    wrong_head = dataclasses.replace(checkpoint, sequence=2)
    with pytest.raises(TrustBoundaryError, match="journal head"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(store, wrong_head), generation=GEN_A
        )
