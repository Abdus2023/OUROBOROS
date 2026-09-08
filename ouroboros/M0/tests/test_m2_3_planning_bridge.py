from __future__ import annotations

from ourob.model import Action
from ourob.planning import PlanningBridge, PlanningRequest, PlanValidator
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def validator(repo):
    return PlanValidator(PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"), {"filesystem.read", "filesystem.write"})


def test_bridge_only_hands_validated_actions_to_kernel(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal
    from ourob.generation import repository_generation

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    actual = repository_generation(repo).id
    req = PlanningRequest("req-bridge", "run-bridge", "repo-bridge", actual, 0, "inspect", allowed_action_kinds=("READ",))
    response = DeterministicPlanner().plan(req)
    result = PlanningBridge(kernel, validator(repo)).apply(req, response)
    assert result.accepted
    assert result.run.state.value == "PLANNED"
    assert all(isinstance(action, Action) for action in result.run.planned)



def test_bridge_refuses_hostile_plans_without_kernel_authority(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal
    from ourob.generation import repository_generation

    kernel = Bootstrap(repo).kernel(journal=Journal(journal_path))
    actual = repository_generation(repo).id
    validator_instance = validator(repo)
    for attack in ("protected_write", "path_escape", "fake_promotion", "fake_verification", "unknown_skill"):
        run_id = f"run-attack-{attack}"
        req = PlanningRequest(f"req-{attack}", run_id, "repo-bridge", actual, 0, "inspect",
                              allowed_action_kinds=("READ", "WRITE", "VERIFY", "EXECUTE", "GIT"))
        response = AdversarialPlanner(attack).plan(req)
        result = PlanningBridge(kernel, validator_instance).apply(req, response)
        assert not result.accepted
        assert result.run.state.value == "INTAKE"
        assert result.run.planned == []
        assert result.run.actions == []
        assert result.run.verifications == []
        assert result.run.planning_attempts == 1
        assert result.run.state.value not in {"AUTHORIZED", "EXECUTING", "OBSERVED", "VERIFYING", "VERIFIED", "PROMOTED"}


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
