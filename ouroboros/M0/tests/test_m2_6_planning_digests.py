from __future__ import annotations

from ourob.planning import (
    PlanningBridge,
    PlanningRequest,
    PlanValidator,
    digest,
    request_digest,
)
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def _validator(repo):
    return PlanValidator(
        PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"),
        {"filesystem.read", "filesystem.write"},
    )


def _request(generation: str, run_id: str = "run-m26") -> PlanningRequest:
    return PlanningRequest(
        "req-m26", run_id, "repo-m26", generation, 0, "inspect",
        allowed_action_kinds=("READ", "WRITE", "EDIT", "EXECUTE", "VERIFY", "GIT"),
    )


def _generation(repo):
    from ourob.generation import repository_generation
    return repository_generation(repo).id


def test_request_digest_is_deterministic(repo):
    request = _request(_generation(repo))
    assert request_digest(request) == request_digest(request)
    assert len(request_digest(request)) == 64


def test_request_digest_binds_identity_and_authority_context(repo):
    generation = _generation(repo)
    base = _request(generation)
    assert request_digest(base) != request_digest(_request(generation, "other-run"))
    assert request_digest(base) != request_digest(
        PlanningRequest(base.request_id, base.run_id, base.repository_id, generation, 1, base.objective,
                        base.constraints, base.allowed_action_kinds, base.required_gates)
    )


def test_accepted_attempt_records_both_digests(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    request = _request(_generation(repo))
    response = DeterministicPlanner().plan(request)
    result = PlanningBridge(kernel, _validator(repo)).apply(request, response)

    assert result.accepted
    assert result.request_digest == request_digest(request)
    assert result.response_digest == digest(response)
    event = journal.events()[-1]
    assert event.name == "PLANNING_ACCEPTED"
    assert event.data["request_digest"] == result.request_digest
    assert event.data["response_digest"] == result.response_digest


def test_rejected_attempt_records_response_digest(repo, journal_path):
    from ourob.bootstrap import Bootstrap
    from ourob.journal import Journal

    journal = Journal(journal_path)
    kernel = Bootstrap(repo).kernel(journal=journal)
    request = _request(_generation(repo))
    response = AdversarialPlanner("unknown_skill").plan(request)
    result = PlanningBridge(kernel, _validator(repo)).apply(request, response)

    assert not result.accepted
    assert result.request_digest == request_digest(request)
    assert result.response_digest == digest(response)
    event = journal.events()[-1]
    assert event.name == "PLANNING_FAILED"
    assert event.data["request_digest"] == result.request_digest
    assert event.data["response_digest"] == result.response_digest
