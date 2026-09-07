"""M1.5 — external trust anchor."""
import json

import pytest

from ourob.journal import GENESIS_DIGEST, JOURNAL_VERSION, Journal, record_digest
from ourob.model import Event
from ourob.trust import JournalTrustAnchor, TrustAnchorError, verify_anchor

GEN = "a" * 64
OTHER = "b" * 64


def fill(journal, n, name="E"):
    for i in range(n):
        journal.append(Event(f"{name}{i}", "run", None, GEN, {"i": i}))


def rewrite(journal_path, events):
    previous = GENESIS_DIGEST
    with journal_path.open("w") as fh:
        for i, e in enumerate(events, start=1):
            body = {"version": JOURNAL_VERSION, "sequence": i, "previous_digest": previous, "timestamp": "t", "event": e.to_record()}
            body["digest"] = record_digest(body)
            fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            previous = body["digest"]


def test_anchor_roundtrip_and_binding_digest():
    a = JournalTrustAnchor(3, "c" * 64, GEN)
    assert JournalTrustAnchor.from_record(a.to_record()) == a
    assert a.binding_digest != JournalTrustAnchor(3, "c" * 64, None).binding_digest
    with pytest.raises(TrustAnchorError):
        JournalTrustAnchor(0, "c" * 64)
    with pytest.raises(TrustAnchorError):
        JournalTrustAnchor(1, "short")


def test_trusted_read_accepts_extended_journal(journal_path):
    journal = Journal(journal_path)
    fill(journal, 3)
    anchor = JournalTrustAnchor.capture(journal.records(), GEN)
    fill(journal, 2)  # legitimate growth after anchoring
    records = journal.read_trusted(anchor, GEN)
    assert len(records) == 5


def test_whole_history_rewrite_rejected(journal_path):
    journal = Journal(journal_path)
    fill(journal, 3)
    anchor = JournalTrustAnchor.capture(journal.records())
    rewrite(journal_path, [Event("FORGED", "run", None, GEN, {"i": i}) for i in range(3)])
    assert journal.verify()  # chain still self-consistent
    with pytest.raises(TrustAnchorError, match="history rewritten"):
        journal.read_trusted(anchor)


def test_truncation_before_checkpoint_rejected(journal_path):
    journal = Journal(journal_path)
    fill(journal, 4)
    anchor = JournalTrustAnchor.capture(journal.records())
    lines = journal_path.read_text().splitlines()
    journal_path.write_text("\n".join(lines[:2]) + "\n")
    with pytest.raises(TrustAnchorError, match="truncated"):
        journal.read_trusted(anchor)


def test_generation_binding_rejected(journal_path):
    journal = Journal(journal_path)
    fill(journal, 2)
    anchor = JournalTrustAnchor.capture(journal.records(), GEN)
    with pytest.raises(TrustAnchorError, match="generation"):
        journal.read_trusted(anchor, OTHER)
    journal.read_trusted(anchor, GEN)   # matching generation passes
    journal.read_trusted(anchor, None)  # caller may opt out of generation check


def test_journal_cannot_supply_its_own_anchor(journal_path):
    """The journal exposes no API that reads an anchor from the journal file."""
    assert not hasattr(Journal, "anchor")
    assert not hasattr(Journal, "write_anchor")
    journal = Journal(journal_path)
    fill(journal, 1)
    with pytest.raises(TrustAnchorError):
        verify_anchor(JournalTrustAnchor(1, "0" * 64), journal.records())
