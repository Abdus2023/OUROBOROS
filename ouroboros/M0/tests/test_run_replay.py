from pathlib import Path

import pytest

from ourob.bootstrap import Bootstrap
from ourob.journal import Journal, record_digest
from ourob.model import Action, ActionKind, EventName, Plan, RunState
from ourob.replay import ReplayError, reconstruct_run


def kernel_for(repo: Path, journal_path: Path):
    return Bootstrap(repo).kernel(journal=Journal(journal_path))


def write(action_id: str, path: str, content: str = "x\n") -> Action:
    return Action(action_id, ActionKind.WRITE, "filesystem.write", {"path": path, "content": content})


def test_promoted_run_reconstructs_without_execution(repo: Path, journal_path: Path) -> None:
    kernel = kernel_for(repo, journal_path)
    run = kernel.run_plan("replay-1", Plan("write a note", (write("a1", "notes/a.md", "hello\n"),)))

    rebuilt = reconstruct_run(Journal(journal_path), run.id)

    assert rebuilt.state is RunState.PROMOTED
    assert rebuilt.id == run.id
    assert rebuilt.task == run.task
    assert rebuilt.planned == run.planned
    assert rebuilt.actions == run.actions
    assert [o.action_id for o in rebuilt.observations] == ["a1"]
    assert rebuilt.observations[0].result is None
    assert rebuilt.observations[0].result_digest == run.observations[0].result_digest
    assert rebuilt.verification_epoch == run.verification_epoch
    assert rebuilt.verifications == run.verifications


def test_blocked_run_reconstructs_terminal_state(repo: Path, journal_path: Path) -> None:
    kernel = kernel_for(repo, journal_path)
    run = kernel.run_plan(
        "replay-2",
        Plan("protected write", (write("a1", "ouroboros/M0/ourob/kernel.py", "blocked"),)),
    )

    rebuilt = reconstruct_run(Journal(journal_path), run.id)

    assert rebuilt.state is RunState.BLOCKED
    assert len(rebuilt.observations) == 1
    assert not rebuilt.observations[0].ok


def test_replay_rejects_unknown_run(repo: Path, journal_path: Path) -> None:
    kernel = kernel_for(repo, journal_path)
    kernel.run_plan("replay-3", Plan("write", (write("a1", "a.md"),)))
    with pytest.raises(ReplayError, match="has no durable events"):
        reconstruct_run(Journal(journal_path), "missing")


def test_replay_rejects_state_history_tampering(repo: Path, journal_path: Path) -> None:
    kernel = kernel_for(repo, journal_path)
    kernel.run_plan("replay-4", Plan("write", (write("a1", "a.md"),)))
    path = journal_path
    import json
    raw = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    target = next(record for record in raw if record["event"]["name"] == EventName.ACTION_EXECUTED.value)
    target["event"]["data"]["epoch"] = "tampered"
    body = {key: target[key] for key in ("version", "sequence", "previous_digest", "timestamp", "event")}
    target["digest"] = record_digest(body)
    path.write_text("".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in raw), encoding="utf-8")

    with pytest.raises(ReplayError, match="invalid verification epoch"):
        reconstruct_run(Journal(journal_path), "replay-4")
