from __future__ import annotations

from ourob.planning import PlanningBridge, PlanningRequest, PlanValidator
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def _validator(repo):
    return PlanValidator(
        PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"),
        {"filesystem.read", "filesystem.write"},
    )


def _request(generation: str, *, run_id: str = "run-m24", epoch: int = 0) -> PlanningRequest:
    return PlanningRequest(
        "req-m24",
        run_id,
        "repo-m24",
        generation,
        epoch,
        "inspect",
        allowed_action_kinds=("READ", "WRITE", "EDIT", "EXECUTE", "VERIFY", "GIT"),
    )


def _generation(repo):
    from ourob.generation import repository_generation
    return repository_generation(repo).id


def test_rejected_plan_is_durable_and_does_not_advance_authority(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    request = _request(_generation(repo))
    response = AdversarialPlanner("protected_write").plan(request)

    result = PlanningBridge(kernel, _validator(repo)).apply(request, response)

    assert not result.accepted
    assert result.run.state.value == "INTAKE"
    assert result.run.verification_epoch == 0
    assert result.run.planned == []
    events = journal.events()
    assert events[-1].name == "PLANNING_FAILED"
    assert "POLICY_DENIED" in events[-1].data["violations"] or "PATH_ESCAPE" in events[-1].data["violations"]
    assert all(event.name not in {"AUTHORIZATION_GRANTED", "ACTION_EXECUTED", "VERIFICATION_STARTED", "PROMOTED"} for event in events)


def test_stale_generation_is_rejected_by_live_bridge(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    request = _request("stale-generation")
    response = DeterministicPlanner().plan(request)

    result = PlanningBridge(kernel, _validator(repo)).apply(request, response)

    assert not result.accepted
    assert result.violations == ("STALE_GENERATION",)
    assert result.run.state.value == "INTAKE"
    assert result.run.verification_epoch == 0
    assert journal.events()[-1].name == "PLANNING_FAILED"


def test_rejected_plan_can_be_replanned_only_with_fresh_request(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    validator = _validator(repo)
    generation = _generation(repo)

    bad_request = _request(generation, run_id="run-bad")
    bad_response = AdversarialPlanner("unknown_skill").plan(bad_request)
    bad = PlanningBridge(kernel, validator).apply(bad_request, bad_response)
    assert not bad.accepted
    assert bad.run.state.value == "INTAKE"

    good_request = _request(generation, run_id="run-good")
    good_response = DeterministicPlanner().plan(good_request)
    good = PlanningBridge(kernel, validator).apply(good_request, good_response)

    assert good.accepted
    assert good.run.state.value == "PLANNED"
    assert good.run.verification_epoch == 0
    names = [event.name for event in journal.events()]
    assert "PLANNING_FAILED" in names
    assert names[-1] == "RUN_PLANNED"
    assert "AUTHORIZATION_GRANTED" not in names
    assert "ACTION_EXECUTED" not in names
    assert "VERIFICATION_STARTED" not in names
    assert "PROMOTED" not in names
