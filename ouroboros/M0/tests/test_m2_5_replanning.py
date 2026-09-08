from __future__ import annotations

import pytest

from ourob.model import RunState
from ourob.planning import PlanningBridge, PlanningRequest, PlanValidator
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def _validator(repo):
    return PlanValidator(
        PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"),
        {"filesystem.read", "filesystem.write"},
    )


def _generation(repo):
    from ourob.generation import repository_generation
    return repository_generation(repo).id


def _request(generation: str, request_id: str, run_id: str) -> PlanningRequest:
    return PlanningRequest(
        request_id, run_id, "repo-m25", generation, 0, "inspect",
        allowed_action_kinds=("READ", "WRITE", "EDIT", "EXECUTE", "VERIFY", "GIT"),
    )


def test_replanning_reuses_same_intake_run_and_counts_attempts(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    bridge = PlanningBridge(kernel, _validator(repo))
    generation = _generation(repo)

    run = kernel.intake("run-m25", "inspect")
    bad_request = _request(generation, "req-1", run.id)
    bad_response = AdversarialPlanner("unknown_skill").plan(bad_request)
    bad = bridge.apply_to_run(run, bad_request, bad_response)

    assert not bad.accepted
    assert bad.attempt == 1
    assert run.planning_attempts == 1
    assert run.state is RunState.INTAKE
    assert run.verification_epoch == 0
    assert run.planned == []

    good_request = _request(generation, "req-2", run.id)
    good_response = DeterministicPlanner().plan(good_request)
    good = bridge.apply_to_run(run, good_request, good_response)

    assert good.accepted
    assert good.attempt == 2
    assert run.planning_attempts == 2
    assert run.state is RunState.PLANNED
    assert run.verification_epoch == 0

    events = journal.events()
    assert events[-2].name == "PLANNING_FAILED"
    assert events[-2].data["attempt"] == 1
    assert events[-1].name == "RUN_PLANNED"


def test_replanning_cannot_rewind_a_planned_run(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    bridge = PlanningBridge(kernel, _validator(repo))
    generation = _generation(repo)
    run = kernel.intake("run-no-rewind", "inspect")
    request = _request(generation, "req-1", run.id)
    bridge.apply_to_run(run, request, DeterministicPlanner().plan(request))
    assert run.state is RunState.PLANNED

    with pytest.raises(ValueError, match="replanning requires INTAKE"):
        bridge.apply_to_run(run, _request(generation, "req-2", run.id), DeterministicPlanner().plan(request))

    assert run.planning_attempts == 1
    assert run.verification_epoch == 0


def test_failed_replanning_does_not_change_generation_or_epoch(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    bridge = PlanningBridge(kernel, _validator(repo))
    generation = _generation(repo)
    run = kernel.intake("run-stability", "inspect")
    request = _request(generation, "req-1", run.id)

    for request_id, attack in (("req-1", "protected_write"), ("req-2", "path_escape")):
        req = _request(generation, request_id, run.id)
        result = bridge.apply_to_run(run, req, AdversarialPlanner(attack).plan(req))
        assert not result.accepted

    assert run.state is RunState.INTAKE
    assert run.planning_attempts == 2
    assert run.generation == generation
    assert run.verification_epoch == 0
