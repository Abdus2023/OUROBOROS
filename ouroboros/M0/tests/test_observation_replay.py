import json
from pathlib import Path

import pytest

from ourob.journal import (
    Journal,
    JournalIntegrityError,
    observation_audit_record,
    observation_digest,
    record_digest,
    verify_observation_event,
)
from ourob.model import Action, ActionKind, Event, Observation


def _observation() -> Observation:
    action = Action("a1", ActionKind.READ, "filesystem.read", {"path": "x.txt"})
    return Observation.from_action(action, ok=True, generation="g1", result="hello")


def test_observation_digest_is_canonical_and_excludes_raw_result() -> None:
    observation = _observation()
    audit = observation_audit_record(observation)
    assert "result" not in audit
    assert "arguments" not in audit
    assert observation_digest(observation) == record_digest(audit)


def test_journal_observation_replay_integrity_passes(tmp_path: Path) -> None:
    observation = _observation()
    journal = Journal(tmp_path / "journal.jsonl")
    journal.append(Event(
        "ACTION_EXECUTED",
        "run-1",
        observation.action_id,
        observation.generation,
        {
            "observation": observation_audit_record(observation),
            "observation_digest": observation_digest(observation),
        },
    ))
    assert journal.verify()
    assert journal.verify_observations()
    assert verify_observation_event(journal.events()[0]) == observation_audit_record(observation)


def test_journal_observation_replay_rejects_digest_mismatch(tmp_path: Path) -> None:
    observation = _observation()
    journal_path = tmp_path / "journal.jsonl"
    journal = Journal(journal_path)
    journal.append(Event(
        "ACTION_EXECUTED",
        "run-1",
        observation.action_id,
        observation.generation,
        {
            "observation": observation_audit_record(observation),
            "observation_digest": observation_digest(observation),
        },
    ))

    raw = json.loads(journal_path.read_text(encoding="utf-8"))
    raw["event"]["data"]["observation"]["result_digest"] = "tampered"
    body = {key: raw[key] for key in ("version", "sequence", "previous_digest", "timestamp", "event")}
    raw["digest"] = record_digest(body)
    journal_path.write_text(json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    assert journal.verify()
    assert not journal.verify_observations()
    with pytest.raises(JournalIntegrityError, match="observation digest mismatch"):
        verify_observation_event(journal.events()[0])
