from __future__ import annotations

import pytest

from ourob.bootstrap import Bootstrap
from ourob.generation import repository_generation
from ourob.journal import Journal
from ourob.planning import PlanningBridge, PlanningController, PlanningContext, PlanningRequest, PlanValidator
from ourob.policy import PolicyEngine, load_constitution


def make(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    validator = PlanValidator(
        PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"),
        {"filesystem.read", "filesystem.write"},
    )
    return kernel, PlanningBridge(kernel, validator)


def context(request):
    return PlanningContext(
        repository_id=request.repository_id,
        generation=request.generation,
        mutation_epoch=request.mutation_epoch,
        run_id=request.run_id,
        facts=(),
    )


def test_controller_rejects_mismatched_context_before_model(repo, journal_path):
    kernel, bridge = make(repo, journal_path)
    run = kernel.intake("run-context", "inspect")
    generation = repository_generation(repo).id
    request = PlanningRequest("req-context", run.id, "repo-controller", generation, 0, "inspect")
    bad = PlanningContext("other-repo", generation, 0, run.id, facts=())
    called = False

    def planner(req, ctx):
        nonlocal called
        called = True
        raise AssertionError("planner must not be called")

    with pytest.raises(ValueError, match="does not match request"):
        PlanningController(bridge).run(run, request, planner, bad)
    assert not called
    assert run.planning_attempts == 0
    assert run.state.value == "INTAKE"
    assert not any(event.name == "PLANNING_FAILED" for event in kernel.journal.events())


def test_controller_rejects_stale_context_before_model(repo, journal_path):
    kernel, bridge = make(repo, journal_path)
    run = kernel.intake("run-stale-context", "inspect")
    generation = repository_generation(repo).id
    request = PlanningRequest("req-stale-context", run.id, "repo-controller", generation, 0, "inspect")
    stale = PlanningContext(request.repository_id, "stale-generation", 0, request.run_id, facts=())

    with pytest.raises(ValueError, match="stale"):
        PlanningController(bridge).run(run, request, lambda req, ctx: (_ for _ in ()).throw(AssertionError()), stale)
    assert run.planning_attempts == 0
    assert run.state.value == "INTAKE"
