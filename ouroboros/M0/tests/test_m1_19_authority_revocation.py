"""M1.19 — authenticated revocation propagation."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.checkpoint_authority import CheckpointAuthorityState, classify_checkpoint, require_current_checkpoint, CheckpointAuthorityError
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
    return journal, key, store, checkpoint


def test_revocation_propagates_to_cached_checkpoint(tmp_path: Path):
    journal, key, store, checkpoint = _authority(tmp_path)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)
    next_key = Ed25519PrivateKey.generate()
    rotation = sign_rotation(key, store, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, rotation, store)
    current = recover_trust_store((r.event for r in journal.records()), store)
    revocation = sign_revocation(next_key, current, "k0")
    append_authorized_transition(journal, revocation, store)
    authority = ExternalTrustAuthority(store, checkpoint)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.REVOKED
    with pytest.raises(CheckpointAuthorityError, match="REVOKED"):
        require_current_checkpoint(journal, authority, target, generation=GENERATION)


def test_revocation_does_not_create_new_authority(tmp_path: Path):
    journal, key, store, checkpoint = _authority(tmp_path)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)
    next_key = Ed25519PrivateKey.generate()
    rotation = sign_rotation(key, store, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, rotation, store)
    current = recover_trust_store((r.event for r in journal.records()), store)
    revocation = sign_revocation(next_key, current, "k0")
    append_authorized_transition(journal, revocation, store)
    assert classify_checkpoint(journal, authority=ExternalTrustAuthority(store, checkpoint), checkpoint_path=target, generation=GENERATION) is not CheckpointAuthorityState.CURRENT


def test_rotation_without_reissued_checkpoint_is_not_current(tmp_path: Path):
    journal, key, store, checkpoint = _authority(tmp_path)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)
    next_key = Ed25519PrivateKey.generate()
    rotation = sign_rotation(key, store, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, rotation, store)
    assert classify_checkpoint(journal, ExternalTrustAuthority(store, checkpoint), target, generation=GENERATION) is CheckpointAuthorityState.STALE
