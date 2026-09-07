"""M1.14 — authenticated current checkpoint issuance conformance."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.journal import Journal, JournalIntegrityError
from ourob.model import Event
from ourob.signed_trust import SignedTrustError, TrustStore
from ourob.trust_checkpoint import issue_current_checkpoint, trust_state_digest
from ourob.trust_lifecycle import apply_transition, sign_rotation
from ourob.trust_recovery import append_authorized_transition

GENERATION = "a" * 64


def test_issuance_reconstructs_state_from_external_root(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    root_key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", root_key.public_key())
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(root_key, root, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, root)

    checkpoint = issue_current_checkpoint(journal, root, next_key, "k1", generation=GENERATION)

    assert checkpoint.key_id == "k1"
    assert checkpoint.trust_epoch == 1
    assert checkpoint.sequence == len(journal.records())
    assert checkpoint.journal_digest == journal.head_digest()

    recovered = TrustStore.from_record(root.to_record())
    apply_transition(transition, recovered)
    assert checkpoint.trust_state_digest == trust_state_digest(recovered)


def test_issuance_rejects_non_active_signer(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    root_key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", root_key.public_key())
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(root_key, root, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, root)

    with pytest.raises(SignedTrustError, match="active trust key"):
        issue_current_checkpoint(journal, root, root_key, "k0", generation=GENERATION)


def test_issuance_rejects_key_material_mismatch(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    root_key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", root_key.public_key())
    journal.append(Event("OBSERVATION"))

    with pytest.raises(SignedTrustError, match="does not match"):
        issue_current_checkpoint(journal, root, Ed25519PrivateKey.generate(), "k0", generation=GENERATION)


def test_issuance_fails_closed_on_empty_journal(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", key.public_key())

    with pytest.raises(SignedTrustError, match="empty journal"):
        issue_current_checkpoint(journal, root, key, "k0", generation=GENERATION)


def test_issuance_fails_closed_on_invalid_journal(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    key = Ed25519PrivateKey.generate()
    root = TrustStore.genesis("k0", key.public_key())
    journal.path.write_text("not-json\n", encoding="utf-8")

    with pytest.raises(SignedTrustError, match="invalid trust history"):
        issue_current_checkpoint(journal, root, key, "k0", generation=GENERATION)
