"""M1.18 — checkpoint authority state conformance."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.checkpoint_authority import CheckpointAuthorityError, CheckpointAuthorityState, classify_checkpoint, require_current_checkpoint
from ourob.checkpoint_store import publish_checkpoint
from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import TrustStore
from ourob.trust_boundary import ExternalTrustAuthority
from ourob.trust_checkpoint import issue_current_checkpoint
from ourob.trust_lifecycle import sign_revocation, sign_rotation
from ourob.trust_recovery import append_authorized_transition, recover_trust_store

GENERATION = "a" * 64


def _authority(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    journal.append(Event("OBSERVATION"))
    checkpoint = issue_current_checkpoint(journal, store, key, "k0", generation=GENERATION)
    authority = ExternalTrustAuthority(store, checkpoint)
    return journal, key, store, checkpoint, authority


def test_missing_checkpoint_is_absent(tmp_path: Path):
    journal, _, _, _, authority = _authority(tmp_path)
    assert classify_checkpoint(journal, authority, tmp_path / "missing.json", generation=GENERATION) is CheckpointAuthorityState.ABSENT


def test_current_checkpoint_is_current(tmp_path: Path):
    journal, _, _, checkpoint, authority = _authority(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.CURRENT
    require_current_checkpoint(journal, authority, target, generation=GENERATION)


def test_malformed_checkpoint_is_invalid(tmp_path: Path):
    journal, _, _, _, authority = _authority(tmp_path)
    target = tmp_path / "current.json"
    target.write_text("{broken", encoding="utf-8")
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.INVALID


def test_generation_mismatch_is_stale(tmp_path: Path):
    journal, _, _, checkpoint, authority = _authority(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    assert classify_checkpoint(journal, authority, target, generation="b" * 64) is CheckpointAuthorityState.STALE
    with pytest.raises(CheckpointAuthorityError, match="STALE"):
        require_current_checkpoint(journal, authority, target, generation="b" * 64)


def test_rotation_makes_old_checkpoint_stale(tmp_path: Path):
    journal, key, store, checkpoint, authority = _authority(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(key, store, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, store)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.STALE


def test_revoked_signer_is_rejected_as_revoked(tmp_path: Path):
    journal, key, store, checkpoint, authority = _authority(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    next_key = Ed25519PrivateKey.generate()
    rotation = sign_rotation(key, store, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, rotation, store)
    current = recover_trust_store((record.event for record in journal.records()), store)
    revoke = sign_revocation(next_key, current, "k0")
    append_authorized_transition(journal, revoke, store)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.REVOKED
