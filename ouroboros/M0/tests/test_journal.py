import json

import pytest

from ourob.journal import GENESIS_DIGEST, Journal, JournalIntegrityError
from ourob.model import Event


def events(n):
    return [Event(f"E{i}", "run", None, "g" * 64, {"i": i}) for i in range(n)]


def test_chain_links_and_verifies(journal_path):
    journal = Journal(journal_path)
    for e in events(3):
        journal.append(e)
    records = journal.records()
    assert [r.sequence for r in records] == [1, 2, 3]
    assert records[0].previous_digest == GENESIS_DIGEST
    assert records[1].previous_digest == records[0].digest
    assert records[2].previous_digest == records[1].digest
    assert journal.verify()


def test_modified_history_is_detected(journal_path):
    journal = Journal(journal_path)
    for e in events(3):
        journal.append(e)
    lines = journal_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["event"]["data"]["i"] = 99
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    journal_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(JournalIntegrityError, match="digest mismatch"):
        journal.records()


def test_reordered_records_break_chain(journal_path):
    journal = Journal(journal_path)
    for e in events(3):
        journal.append(e)
    lines = journal_path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    journal_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(JournalIntegrityError):
        journal.records()


def test_missing_record_breaks_chain(journal_path):
    journal = Journal(journal_path)
    for e in events(3):
        journal.append(e)
    lines = journal_path.read_text().splitlines()
    del lines[1]
    journal_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(JournalIntegrityError):
        journal.records()


def test_truncated_tail_is_rejected(journal_path):
    journal = Journal(journal_path)
    for e in events(2):
        journal.append(e)
    text = journal_path.read_text()
    journal_path.write_text(text[:-10])
    with pytest.raises(JournalIntegrityError, match="truncated|malformed"):
        journal.records()


def test_cannot_append_after_corruption(journal_path):
    journal = Journal(journal_path)
    journal.append(events(1)[0])
    journal_path.write_text("not json\n")
    with pytest.raises(JournalIntegrityError):
        journal.append(events(1)[0])


def test_unsupported_version_rejected(journal_path):
    journal = Journal(journal_path)
    journal.append(events(1)[0])
    raw = json.loads(journal_path.read_text())
    raw["version"] = "ourob.journal.v0"
    journal_path.write_text(json.dumps(raw) + "\n")
    with pytest.raises(JournalIntegrityError, match="version"):
        journal.records()
