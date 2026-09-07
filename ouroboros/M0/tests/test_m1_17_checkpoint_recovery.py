"""M1.17 — redundant checkpoint recovery conformance."""

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.checkpoint_recovery import (
    CheckpointCandidateStatus,
    CheckpointRecoveryError,
    inspect_checkpoint,
    recover_current_checkpoint,
)
from ourob.checkpoint_store import publish_checkpoint
from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import TrustStore
from ourob.trust_checkpoint import issue_current_checkpoint
from ourob.trust_lifecycle import sign_rotation
from ourob.trust_recovery import append_authorized_transition

GENERATION = "a" * 64


def _state(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    journal.append(Event("OBSERVATION"))
    checkpoint = issue_current_checkpoint(journal, store, key, "k0", generation=GENERATION)
    return journal, key, store, checkpoint


def test_recovery_selects_current_slot_when_other_slot_is_stale(tmp_path: Path):
    journal, key, store, old = _state(tmp_path)
    old_path = tmp_path / "slot-a.json"
    new_path = tmp_path / "slot-b.json"
    publish_checkpoint(old, old_path)

    journal.append(Event("OBSERVATION"))
    current = issue_current_checkpoint(journal, store, key, "k0", generation=GENERATION)
    publish_checkpoint(current, new_path)

    assert inspect_checkpoint(old_path, journal, store, generation=GENERATION).status is CheckpointCandidateStatus.STALE
    assert inspect_checkpoint(new_path, journal, store, generation=GENERATION).status is CheckpointCandidateStatus.CURRENT
    recovered, path = recover_current_checkpoint((old_path, new_path), journal, store, generation=GENERATION)
    assert recovered == current
    assert path == new_path


def test_recovery_fails_closed_when_no_slot_is_current(tmp_path: Path):
    journal, key, store, old = _state(tmp_path)
    path = tmp_path / "slot.json"
    publish_checkpoint(old, path)
    journal.append(Event("OBSERVATION"))
    with pytest.raises(CheckpointRecoveryError, match="no current checkpoint"):
        recover_current_checkpoint((path,), journal, store, generation=GENERATION)


def test_recovery_ignores_invalid_slot_if_another_is_current(tmp_path: Path):
    journal, key, store, current = _state(tmp_path)
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"{truncated")
    valid = tmp_path / "valid.json"
    publish_checkpoint(current, valid)
    result, path = recover_current_checkpoint((invalid, valid), journal, store, generation=GENERATION)
    assert result == current
    assert path == valid
    assert inspect_checkpoint(invalid, journal, store, generation=GENERATION).status is CheckpointCandidateStatus.INVALID


def test_recovery_does_not_select_by_filename_or_mtime(tmp_path: Path):
    journal, key, store, current = _state(tmp_path)
    stale = issue_current_checkpoint(journal, store, key, "k0", generation="b" * 64)
    first = tmp_path / "z-last.json"
    second = tmp_path / "a-first.json"
    publish_checkpoint(current, first)
    publish_checkpoint(stale, second)
    # The stale candidate is lexically first and deliberately published second.
    recovered, path = recover_current_checkpoint((second, first), journal, store, generation=GENERATION)
    assert recovered == current
    assert path == first


def test_rotation_stales_pre_rotation_checkpoint_and_requires_new_current(tmp_path: Path):
    journal, root_key, root, old = _state(tmp_path)
    old_path = tmp_path / "old.json"
    new_path = tmp_path / "new.json"
    publish_checkpoint(old, old_path)
    next_key = Ed25519PrivateKey.generate()
    transition = sign_rotation(root_key, root, "k1", next_key.public_key().public_bytes_raw())
    append_authorized_transition(journal, transition, root)
    current = issue_current_checkpoint(journal, root, next_key, "k1", generation=GENERATION)
    publish_checkpoint(current, new_path)
    assert inspect_checkpoint(old_path, journal, root, generation=GENERATION).status is CheckpointCandidateStatus.STALE
    recovered, path = recover_current_checkpoint((old_path, new_path), journal, root, generation=GENERATION)
    assert recovered == current
    assert path == new_path
