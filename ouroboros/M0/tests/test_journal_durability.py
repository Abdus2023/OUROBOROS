"""M1.4 — serialized, fsync'd, fail-closed append."""
import json
import os
import threading

import pytest

import ourob.journal as journal_module
from ourob.journal import Journal, JournalDurabilityError, JournalIntegrityError
from ourob.model import Event

GEN = "g" * 64


def ev(i):
    return Event(f"E{i}", "run", None, GEN, {"i": i})


def test_append_calls_fsync(journal_path, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(journal_module.os, "fsync", lambda fd: (synced.append(fd), real(fd)))
    Journal(journal_path).append(ev(0))
    assert synced, "append must fsync before returning"


def test_append_holds_exclusive_lock(journal_path, monkeypatch):
    calls = []
    real = journal_module.fcntl.flock

    def spy(fd, op):
        calls.append(op)
        return real(fd, op)

    monkeypatch.setattr(journal_module.fcntl, "flock", spy)
    Journal(journal_path).append(ev(0))
    assert calls[0] == journal_module.fcntl.LOCK_EX and calls[-1] == journal_module.fcntl.LOCK_UN


def test_platform_without_fcntl_fails_closed(journal_path, monkeypatch):
    monkeypatch.setattr(journal_module, "fcntl", None)
    with pytest.raises(JournalDurabilityError):
        Journal(journal_path).append(ev(0))
    assert not journal_path.exists()


def test_concurrent_appends_produce_a_single_valid_chain(journal_path):
    journal = Journal(journal_path)
    errors = []

    def worker(n):
        try:
            for i in range(20):
                journal.append(Event(f"T{n}", "run", None, GEN, {"i": i}))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    records = journal.records()
    assert len(records) == 80 and [r.sequence for r in records] == list(range(1, 81))


def test_blank_line_is_corruption(journal_path):
    journal = Journal(journal_path)
    journal.append(ev(0))
    with journal_path.open("a") as fh:
        fh.write("\n")
    with pytest.raises(JournalIntegrityError, match="blank"):
        journal.records()
    with pytest.raises(JournalIntegrityError):
        journal.append(ev(1))


def test_whole_history_rewrite_is_invisible_to_the_chain_alone(journal_path):
    """Documents the M1.4 boundary: integrity != authenticity. M1.5 closes it."""
    from ourob.journal import GENESIS_DIGEST, JOURNAL_VERSION, record_digest
    journal = Journal(journal_path)
    for i in range(3):
        journal.append(ev(i))
    forged = [Event("FORGED", "run", None, GEN, {"i": i}) for i in range(3)]
    previous = GENESIS_DIGEST
    with journal_path.open("w") as fh:
        for i, e in enumerate(forged, start=1):
            body = {"version": JOURNAL_VERSION, "sequence": i, "previous_digest": previous, "timestamp": "t", "event": e.to_record()}
            body["digest"] = record_digest(body)
            fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            previous = body["digest"]
    assert journal.verify()  # the chain alone cannot tell
