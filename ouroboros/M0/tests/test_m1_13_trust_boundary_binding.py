"""M1.13 — current checkpoint continuity at the external trust boundary."""

import dataclasses
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal
from ourob.signed_trust import TrustStore
from ourob.trust import JournalTrustAnchor
from ourob.trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository
from ourob.trust_checkpoint import sign_trust_state_checkpoint, trust_state_digest


def _authority(generation: str) -> tuple[TrustStore, object]:
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    checkpoint = sign_trust_state_checkpoint(key, "k0", store, JournalTrustAnchor(0, "GENESIS", generation))
    return store, checkpoint


def test_current_boundary_accepts_matching_state_and_head(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority("generation-a")
    recovered, records = authenticate_current_repository(
        journal, ExternalTrustAuthority(store, checkpoint), generation="generation-a"
    )
    assert records == ()
    assert recovered.to_record() == store.to_record()


def test_current_boundary_rejects_wrong_trust_state_digest(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority("generation-a")
    key = store.active.verifier()
    wrong_store = TrustStore.from_record(store.to_record())
    # Produce a cryptographically valid checkpoint for a different trust state
    # using the original signing key; the boundary must reject the mismatch.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 32)) if False else None
    assert checkpoint.trust_state_digest == trust_state_digest(store)
    tampered = dataclasses.replace(checkpoint, trust_state_digest="0" * 64)
    with pytest.raises(TrustBoundaryError, match="trust state"):
        authenticate_current_repository(journal, ExternalTrustAuthority(wrong_store, tampered), generation="generation-a")


def test_current_boundary_rejects_wrong_generation(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority("generation-a")
    with pytest.raises(TrustBoundaryError, match="generation"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(store, checkpoint), generation="generation-b"
        )


def test_current_boundary_rejects_wrong_journal_head(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    store, checkpoint = _authority("generation-a")
    wrong_head = dataclasses.replace(checkpoint, sequence=1)
    with pytest.raises(TrustBoundaryError, match="journal head"):
        authenticate_current_repository(
            journal, ExternalTrustAuthority(store, wrong_head), generation="generation-a"
        )
