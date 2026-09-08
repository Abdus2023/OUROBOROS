from __future__ import annotations

import pytest

from ourob.bootstrap import Bootstrap
from ourob.cold_start import ColdStartError, cold_start_run
from ourob.journal import Journal, record_digest, GENESIS_DIGEST, JOURNAL_VERSION
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


def test_cold_start_preserves_durable_authorization(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-2", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)

    fresh = cold_start_run(journal_path, repo, "cold-2")

    assert fresh.run.state is RunState.AUTHORIZED
    assert fresh.resumable
    assert not fresh.requires_reauthorization


def test_cold_start_quarantines_executing_run(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("cold-3", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)

    # Simulate the durable prefix of a crash after ACTION_PROPOSED but before
    # POLICY_ALLOWED/ACTION_EXECUTED. This state must never be auto-replayed.
    action = write("a1", "a.md")
    kernel._emit(EventName.ACTION_PROPOSED, run, action.id, action=action.to_record())

    with pytest.raises(ColdStartError, match="EXECUTING"):
        cold_start_run(journal_path, repo, "cold-3")


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
    import json
    record = json.loads(lines[-1])
    record["event"]["data"]["evidence_digest"] = "0" * 64
    # Deliberately do not repair the outer chain: cold start must fail before
    # interpreting any recovered state.
    journal_path.write_text("\n".join(lines[:-1] + [json.dumps(record, sort_keys=True, separators=(",", ":"))]) + "\n", encoding="utf-8")

    with pytest.raises(Exception, match="journal integrity"):
        cold_start_run(journal_path, repo, "cold-5")
