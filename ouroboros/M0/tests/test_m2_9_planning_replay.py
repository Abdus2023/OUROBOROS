from __future__ import annotations

import pytest

from ourob.planning import PlanningReplay, PlanningRequest
from ourob.planning.planners import DeterministicPlanner
from ourob.generation import repository_generation


def make_request(repo):
    return PlanningRequest(
        "req-replay", "run-replay", "repo-replay", repository_generation(repo).id, 0,
        "inspect", allowed_action_kinds=("READ",), required_gates=(),
    )


def test_replay_is_deterministic(repo):
    request = make_request(repo)
    response = DeterministicPlanner().plan(request)
    recorded = PlanningReplay.record(request, response)

    replayed = recorded.replay(request)
    assert replayed == response
    assert recorded.request_digest == recorded.request_digest
    assert recorded.response_digest == recorded.response_digest
    assert recorded.response_digest


def test_replay_rejects_changed_generation(repo):
    request = make_request(repo)
    response = DeterministicPlanner().plan(request)
    recorded = PlanningReplay.record(request, response)
    changed = PlanningRequest(
        request.request_id, request.run_id, request.repository_id, "changed-generation", 0,
        request.objective, request.constraints, request.allowed_action_kinds, request.required_gates,
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        recorded.replay(changed)


def test_replay_rejects_changed_epoch(repo):
    request = make_request(repo)
    response = DeterministicPlanner().plan(request)
    recorded = PlanningReplay.record(request, response)
    changed = PlanningRequest(
        request.request_id, request.run_id, request.repository_id, request.generation, 1,
        request.objective, request.constraints, request.allowed_action_kinds, request.required_gates,
    )
    with pytest.raises(ValueError, match="identity mismatch"):
        recorded.replay(changed)


def test_replay_detects_tampered_record(repo):
    request = make_request(repo)
    response = DeterministicPlanner().plan(request)
    recorded = PlanningReplay.record(request, response)
    object.__setattr__(recorded.response, "objective", "tampered")
    with pytest.raises(ValueError, match="response digest mismatch"):
        recorded.replay(request)
