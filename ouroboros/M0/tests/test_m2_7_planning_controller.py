from __future__ import annotations

import pytest

from ourob.model import RunState
from ourob.planning import PlanningBridge, PlanningController, PlanningRequest, PlanValidator
from ourob.planning.planners import DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution
from ourob.generation import repository_generation
from ourob.journal import Journal
from ourob.bootstrap import Bootstrap


def make(repo, journal_path):
    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    validator = PlanValidator(
        PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"),
        {"filesystem.read", "filesystem.write"},
    )
    return kernel, PlanningBridge(kernel, validator)


def test_controller_drives_accepted_plan_through_kernel(repo, journal_path):
    kernel, bridge = make(repo, journal_path)
    run = kernel.intake("run-controller", "inspect")
    generation = repository_generation(repo).id
    request = PlanningRequest("req-controller", run.id, "repo-controller", generation, 0, "inspect", allowed_action_kinds=("READ",))
    context = __import__("ourob.planning", fromlist=["PlanningContext"]).PlanningContext(
        repository_id=request.repository_id,
        generation=request.generation,
        mutation_epoch=request.mutation_epoch,
        run_id=request.run_id,
        facts=(),
    )

    planner = DeterministicPlanner()
    controller = PlanningController(bridge)
    result = controller.run(run, request, lambda req, ctx: planner.plan(req), context)

    assert result.planning is not None and result.planning.accepted
    assert result.planner_error == ""
    assert result.run.state is RunState.PROMOTED


def test_controller_planner_failure_is_durable_and_has_no_authority(repo, journal_path):
    kernel, bridge = make(repo, journal_path)
    run = kernel.intake("run-controller-fail", "inspect")
    generation = repository_generation(repo).id
    request = PlanningRequest("req-controller-fail", run.id, "repo-controller", generation, 0, "inspect")
    context = __import__("ourob.planning", fromlist=["PlanningContext"]).PlanningContext(
        repository_id=request.repository_id,
        generation=request.generation,
        mutation_epoch=request.mutation_epoch,
        run_id=request.run_id,
        facts=(),
    )

    def unavailable(req, ctx):
        raise RuntimeError("provider unavailable")

    result = PlanningController(bridge).run(run, request, unavailable, context)
    assert result.planning is None
    assert "provider unavailable" in result.planner_error
    assert run.state is RunState.INTAKE
    assert run.planning_attempts == 1
    events = kernel.journal.events()
    assert events[-1].name == "PLANNING_FAILED"
    assert events[-1].data["violations"] == ["PLANNER_ERROR"]
    assert not any(event.name in {"AUTHORIZATION_GRANTED", "ACTION_EXECUTED", "VERIFICATION_STARTED", "PROMOTED"} for event in events)


def test_controller_attempt_budget_is_non_authoritative(repo, journal_path):
    kernel, bridge = make(repo, journal_path)
    run = kernel.intake("run-budget", "inspect")
    generation = repository_generation(repo).id
    request = PlanningRequest("req-budget", run.id, "repo-controller", generation, 0, "inspect")
    context = __import__("ourob.planning", fromlist=["PlanningContext"]).PlanningContext(
        repository_id=request.repository_id,
        generation=request.generation,
        mutation_epoch=request.mutation_epoch,
        run_id=request.run_id,
        facts=(),
    )
    controller = PlanningController(bridge, max_attempts=1)
    with pytest.raises(ValueError):
        controller.run(run, request, lambda req, ctx: (_ for _ in ()).throw(RuntimeError("x")), context)
    assert run.state is RunState.INTAKE
    assert run.planning_attempts == 1
