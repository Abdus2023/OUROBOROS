from __future__ import annotations

import json

import pytest

from ourob.bootstrap import Bootstrap
from ourob.cold_start import ColdStartError, cold_start_run, quarantine_run
from ourob.journal import Journal
from ourob.model import Action, ActionKind, Event, EventName, Plan, RunState


def write(aid: str, path: str) -> Action:
    return Action(aid, ActionKind.WRITE, "filesystem.write", {"path": path, "content": "x\n"})


def test_cold_start_reconstructs_observed_run(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-1", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)
    kernel.execute(run, write("a1", "a.md"))

    fresh = cold_start_run(journal_path, repo, "cold-1")

    assert fresh.run.state is RunState.OBSERVED
    assert fresh.resumable
    assert fresh.requires_reauthorization
    assert not fresh.requires_reconciliation


def test_cold_start_preserves_durable_authorization(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-2", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)

    fresh = cold_start_run(journal_path, repo, "cold-2")

    assert fresh.run.state is RunState.AUTHORIZED
    assert fresh.resumable
    assert not fresh.requires_reauthorization
    assert not fresh.requires_reconciliation


def test_cold_start_marks_executing_run_for_reconciliation(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-3", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)

    action = write("a1", "a.md")
    kernel._emit(EventName.ACTION_PROPOSED, run, action.id, action=action.to_record())

    fresh = cold_start_run(journal_path, repo, "cold-3")

    assert fresh.run.state is RunState.EXECUTING
    assert not fresh.resumable
    assert fresh.requires_reconciliation


def test_quarantine_is_durable_and_replayed(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-3b", "t")
    action = write("a1", "a.md")
    kernel.plan(run, Plan("t", (action,)))
    kernel.authorize(run)
    kernel._emit(EventName.ACTION_PROPOSED, run, action.id, action=action.to_record())

    quarantined = quarantine_run(journal_path, "cold-3b")
    assert quarantined.run.state is RunState.QUARANTINED
    assert quarantined.events[-1].name == EventName.RECOVERY_QUARANTINED.value
    assert quarantined.events[-1].action_id == "a1"

    fresh = cold_start_run(journal_path, repo, "cold-3b")
    assert fresh.run.state is RunState.QUARANTINED
    assert not fresh.resumable
    assert not fresh.requires_reconciliation


def test_quarantine_can_be_explicitly_reconciled_as_not_executed(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-3c", "t")
    action = write("a1", "a.md")
    kernel.plan(run, Plan("t", (action,)))
    kernel.authorize(run)
    kernel._emit(EventName.ACTION_PROPOSED, run, action.id, action=action.to_record())
    quarantine_run(journal_path, "cold-3c")

    recovered = quarantine_run.__globals__["recover_from_journal"](journal_path, "cold-3c")
    Journal(journal_path).append(
        Event(
            EventName.RECOVERY_RECONCILED.value,
            run_id="cold-3c",
            action_id="a1",
            generation=recovered.run.generation,
            data={"disposition": "NOT_EXECUTED"},
        )
    )

    fresh = cold_start_run(journal_path, repo, "cold-3c")
    assert fresh.run.state is RunState.PLANNED
    assert fresh.resumable is False
    assert not fresh.requires_reconciliation


def test_cold_start_rejects_generation_drift(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-4", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)

    (repo / "drift.txt").write_text("out-of-band\n", encoding="utf-8")

    with pytest.raises(ColdStartError, match="differs from current repository generation"):
        cold_start_run(journal_path, repo, "cold-4")


def test_cold_start_refuses_tampered_journal(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    kernel.run_plan("cold-5", Plan("t", (write("a1", "a.md"),)))
    lines = journal_path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["event"]["data"]["evidence_digest"] = "0" * 64
    journal_path.write_text(
        "\n".join(lines[:-1] + [json.dumps(record, sort_keys=True, separators=(",", ":"))]) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(Exception, match="journal integrity"):
        cold_start_run(journal_path, repo, "cold-5")
