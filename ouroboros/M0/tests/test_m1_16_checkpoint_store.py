"""M1.16 — crash-safe external checkpoint publication."""

import json
import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.checkpoint_store import CheckpointPublicationError, load_checkpoint, publish_checkpoint
from ourob.journal import Journal
from ourob.model import Event
from ourob.signed_trust import TrustStore
from ourob.trust_checkpoint import issue_current_checkpoint

GENERATION = "a" * 64


def _checkpoint(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    key = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", key.public_key())
    journal.append(Event("OBSERVATION"))
    return issue_current_checkpoint(journal, store, key, "k0", generation=GENERATION), journal


def test_publish_round_trip_and_restrictive_mode(tmp_path: Path):
    checkpoint, journal = _checkpoint(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    assert load_checkpoint(target) == checkpoint
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert journal.records()


def test_publication_is_deterministic(tmp_path: Path):
    checkpoint, _ = _checkpoint(tmp_path)
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    publish_checkpoint(checkpoint, first)
    publish_checkpoint(checkpoint, second)
    assert first.read_bytes() == second.read_bytes()


def test_empty_and_truncated_files_are_rejected(tmp_path: Path):
    target = tmp_path / "current.json"
    target.write_bytes(b"")
    with pytest.raises(CheckpointPublicationError):
        load_checkpoint(target)
    target.write_bytes(b'{"schema":')
    with pytest.raises(CheckpointPublicationError):
        load_checkpoint(target)


def test_malformed_checkpoint_is_rejected(tmp_path: Path):
    target = tmp_path / "current.json"
    target.write_text(json.dumps({"schema": "wrong"}), encoding="utf-8")
    with pytest.raises(CheckpointPublicationError):
        load_checkpoint(target)


def test_parent_directory_must_exist(tmp_path: Path):
    checkpoint, _ = _checkpoint(tmp_path)
    with pytest.raises(CheckpointPublicationError, match="parent directory"):
        publish_checkpoint(checkpoint, tmp_path / "missing" / "current.json")


def test_target_symlink_is_rejected(tmp_path: Path):
    checkpoint, _ = _checkpoint(tmp_path)
    real = tmp_path / "real.json"
    real.write_bytes(b"old")
    target = tmp_path / "current.json"
    target.symlink_to(real)
    with pytest.raises(CheckpointPublicationError, match="symlink"):
        publish_checkpoint(checkpoint, target)
    assert real.read_bytes() == b"old"


def test_publication_does_not_leave_temporary_files(tmp_path: Path):
    checkpoint, _ = _checkpoint(tmp_path)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    assert list(tmp_path.glob(".current.json.tmp-*")) == []


def test_failed_fsync_does_not_replace_existing_checkpoint(tmp_path: Path, monkeypatch):
    checkpoint, _ = _checkpoint(tmp_path)
    target = tmp_path / "current.json"
    old = b'{"old":true}\n'
    target.write_bytes(old)

    real_fsync = os.fsync
    calls = {"count": 0}

    def fail_first_fsync(fd):
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("injected fsync failure")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(CheckpointPublicationError):
        publish_checkpoint(checkpoint, target)
    assert target.read_bytes() == old
    assert list(tmp_path.glob(".current.json.tmp-*")) == []


def test_directory_sync_failure_is_reported_and_target_was_replaced(tmp_path: Path, monkeypatch):
    checkpoint, _ = _checkpoint(tmp_path)
    target = tmp_path / "current.json"
    old = b"old\n"
    target.write_bytes(old)

    def fail_directory_sync(_parent):
        raise CheckpointPublicationError("injected directory sync failure")

    monkeypatch.setattr("ourob.checkpoint_store._sync_directory", fail_directory_sync)
    with pytest.raises(CheckpointPublicationError, match="directory sync"):
        publish_checkpoint(checkpoint, target)
    # The rename happened, but the caller receives a fail-closed durability error.
    assert load_checkpoint(target) == checkpoint
    assert list(tmp_path.glob(".current.json.tmp-*")) == []
