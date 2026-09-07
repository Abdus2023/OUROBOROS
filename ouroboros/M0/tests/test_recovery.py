import json

import pytest

from ourob.bootstrap import Bootstrap
from ourob.journal import Journal
from ourob.model import Action, ActionKind, Event, Plan, RunState
from ourob.recovery import RecoveryError, list_runs, recover_from_journal, recover_run

GEN = "a" * 64


def write(aid, path):
    return Action(aid, ActionKind.WRITE, "filesystem.write", {"path": path, "content": "x\n"})


def test_complete_chain_recovers_to_promoted(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.run_plan("run-1", Plan("t", (write("a1", "a.md"), write("a2", "b.md"))))
    assert run.state is RunState.PROMOTED
    recovered = recover_from_journal(journal_path, "run-1")
    assert recovered.state is RunState.PROMOTED
    assert recovered.run.generation == run.generation
    assert recovered.run.verification_epoch == run.verification_epoch
    assert recovered.run.executed_ids == ("a1", "a2")
    assert recovered.evidence is not None and recovered.evidence.digest == kernel.evidence_for(run).digest
    assert list_runs(journal_path) == ("run-1",)


def test_interrupted_run_recovers_to_observed(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    run = kernel.intake("run-2", "t")
    kernel.plan(run, Plan("t", (write("a1", "a.md"),)))
    kernel.authorize(run)
    kernel.execute(run, write("a1", "a.md"))
    recovered = recover_from_journal(journal_path, "run-2")
    assert recovered.state is RunState.OBSERVED
    assert recovered.evidence is None


def test_blocked_run_recovers_to_blocked(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    kernel.run_plan("run-3", Plan("t", (write("a1", "policies/constitution.json"),)))
    assert recover_from_journal(journal_path, "run-3").state is RunState.BLOCKED


def test_no_records_refused(journal_path):
    Journal(journal_path).append(Event("RUN_CREATED", "other", None, GEN, {"task": "t"}))
    with pytest.raises(RecoveryError, match="no durable records"):
        recover_from_journal(journal_path, "missing")


def test_first_event_must_be_run_created():
    with pytest.raises(RecoveryError, match="RUN_CREATED"):
        recover_run([Event("RUN_PLANNED", "r", None, GEN, {})], "r")


def test_forged_authorization_without_plan_refused():
    events = [Event("RUN_CREATED", "r", None, GEN, {"task": "t"}),
              Event("AUTHORIZATION_GRANTED", "r", None, GEN, {})]
    with pytest.raises(RecoveryError, match="INTAKE -> AUTHORIZED"):
        recover_run(events, "r")


def test_action_executed_without_policy_allowed_refused():
    plan = [write("a1", "a.md").to_record()]
    events = [Event("RUN_CREATED", "r", None, GEN, {"task": "t"}),
              Event("RUN_PLANNED", "r", None, GEN, {"actions": plan}),
              Event("AUTHORIZATION_GRANTED", "r", None, GEN, {}),
              Event("ACTION_PROPOSED", "r", "a1", GEN, {"action": plan[0]}),
              Event("ACTION_EXECUTED", "r", "a1", GEN, {"epoch": 1})]
    with pytest.raises(RecoveryError, match="POLICY_ALLOWED"):
        recover_run(events, "r")


def test_gate_results_do_not_imply_verified():
    plan = [write("a1", "a.md").to_record()]
    result = {"gate": "g", "status": "PASS", "evidence_id": "e" * 64, "generation": GEN, "epoch": 1, "message": ""}
    events = [Event("RUN_CREATED", "r", None, GEN, {"task": "t"}),
              Event("RUN_PLANNED", "r", None, GEN, {"actions": plan}),
              Event("AUTHORIZATION_GRANTED", "r", None, GEN, {}),
              Event("ACTION_PROPOSED", "r", "a1", GEN, {"action": plan[0]}),
              Event("POLICY_ALLOWED", "r", "a1", GEN, {}),
              Event("ACTION_EXECUTED", "r", "a1", GEN, {"epoch": 1}),
              Event("VERIFICATION_STARTED", "r", None, GEN, {}),
              Event("GATE_RESULT", "r", None, GEN, {"result": result})]
    assert recover_run(events, "r").state is RunState.VERIFYING
    # And promotion without evidence is refused outright
    with pytest.raises(RecoveryError, match="without durable verification evidence"):
        recover_run(events + [Event("PROMOTION_AUTHORIZED", "r", None, GEN, {})], "r")


def test_tampered_evidence_in_journal_refused(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    kernel.run_plan("run-4", Plan("t", (write("a1", "a.md"),)))
    # Rewrite journal with a tampered evidence digest but valid chain (re-chain lines)
    from ourob.journal import GENESIS_DIGEST, JOURNAL_VERSION, record_digest
    events = Journal(journal_path).events()
    for e in events:
        if e.name == "VERIFICATION_EVIDENCE_CAPTURED":
            e.data["evidence"]["digest"] = "0" * 64
    journal_path.unlink()
    previous = GENESIS_DIGEST
    with journal_path.open("w") as fh:
        for i, e in enumerate(events, start=1):
            body = {"version": JOURNAL_VERSION, "sequence": i, "previous_digest": previous, "timestamp": "t", "event": e.to_record()}
            digest = record_digest(body)
            body["digest"] = digest
            fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            previous = digest
    assert Journal(journal_path).verify()
    with pytest.raises(RecoveryError, match="digest does not match"):
        recover_from_journal(journal_path, "run-4")


def test_cross_run_events_are_ignored_but_isolated(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    kernel.run_plan("run-5", Plan("t", (write("a1", "a.md"),)))
    kernel.run_plan("run-6", Plan("t", (write("a1", "b.md"),)))
    assert recover_from_journal(journal_path, "run-5").state is RunState.PROMOTED
    assert recover_from_journal(journal_path, "run-6").state is RunState.PROMOTED
    assert list_runs(journal_path) == ("run-5", "run-6")


def test_malformed_generation_refused():
    with pytest.raises(RecoveryError, match="generation"):
        recover_run([Event("RUN_CREATED", "r", None, "short", {"task": "t"})], "r")


def test_unknown_event_refused():
    events = [Event("RUN_CREATED", "r", None, GEN, {"task": "t"}), Event("MAGIC_PROMOTE", "r", None, GEN, {})]
    with pytest.raises(RecoveryError, match="unknown journal event"):
        recover_run(events, "r")
