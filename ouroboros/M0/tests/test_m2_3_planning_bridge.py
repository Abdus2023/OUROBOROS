from __future__ import annotations

import pytest

from ourob.model import Action, ActionKind
from ourob.planning import PlanningBridge, PlanningRequest, PlanValidator
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def request() -> PlanningRequest:
    return PlanningRequest("req-bridge", "run-bridge", "repo-bridge", "fixture-generation", 0, "inspect", allowed_action_kinds=("READ",))


def validator(repo):
    return PlanValidator(PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"), {"filesystem.read", "filesystem.write"})


def test_bridge_only_hands_validated_actions_to_kernel(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    req = request()
    response = DeterministicPlanner().plan(req)
    # Bind the deterministic proposal to the actual repository generation.
    from ourob.generation import repository_generation
    actual = repository_generation(repo).id
    req = PlanningRequest(req.request_id, req.run_id, req.repository_id, actual, 0, req.objective, req.constraints, req.allowed_action_kinds, req.required_gates)
    response = DeterministicPlanner().plan(req)
    result = PlanningBridge(kernel, validator(repo)).apply(req, response)
    assert result.accepted
    assert result.run.state.value == "PLANNED"
    assert all(isinstance(action, Action) for action in result.run.planned)


@pytest.mark.parametrize("attack", ["protected_write", "path_escape", "fake_promotion", "fake_verification", "unknown_skill"])
def test_bridge_refuses_hostile_plans(repo, journal_path, attack):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal
    from ourob.generation import repository_generation

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    actual = repository_generation(repo).id
    req = PlanningRequest("req-attack", "run-attack", "repo-bridge", actual, 0, "inspect", allowed_action_kinds=("READ", "WRITE", "VERIFY", "EXECUTE", "GIT"))
    response = AdversarialPlanner(attack).plan(req)
    with pytest.raises(ValueError):
        PlanningBridge(kernel, validator(repo)).apply(req, response)


def test_bridge_does_not_execute_or_verify(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal
    from ourob.generation import repository_generation

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    actual = repository_generation(repo).id
    req = PlanningRequest("req-no-side-effect", "run-no-side-effect", "repo-bridge", actual, 0, "inspect", allowed_action_kinds=("READ",))
    response = DeterministicPlanner().plan(req)
    PlanningBridge(kernel, validator(repo)).apply(req, response)
    assert not (repo / "README.md").read_text().startswith("pwned")
