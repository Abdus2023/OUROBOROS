from __future__ import annotations

import pytest

from ourob.planning import PlanValidator, PlanningRequest, PlanningResponse, ProposedAction, digest, parse_response
from ourob.planning.planners import AdversarialPlanner, DeterministicPlanner
from ourob.policy import PolicyEngine, load_constitution


def request() -> PlanningRequest:
    return PlanningRequest("req-1", "run-1", "repo-1", "gen-1", 7, "inspect", ("read-only",), ("READ",), ())


def validator(repo):
    return PlanValidator(PolicyEngine(load_constitution(repo / "policies/constitution.json"), "ouroboros/M0"), {"filesystem.read", "filesystem.write"})


def test_parser_and_digest_are_deterministic():
    raw = {"schema": "ourob.planning.v1", "request_id": "r", "run_id": "run", "repository_id": "repo", "generation": "g", "mutation_epoch": 1, "objective": "x", "actions": []}
    response = parse_response(raw)
    assert digest(response) == digest(parse_response(raw))


def test_valid_proposal_becomes_action(repo):
    req = request()
    response = DeterministicPlanner().plan(req)
    result = validator(repo).validate(req, response)
    assert result.accepted
    assert len(result.normalized_actions) == 1


@pytest.mark.parametrize("attack", ["protected_write", "path_escape", "fake_promotion", "fake_verification", "unknown_skill"])
def test_adversarial_proposals_are_rejected(repo, attack):
    req = request()
    response = AdversarialPlanner(attack).plan(req)
    result = validator(repo).validate(req, response)
    assert not result.accepted
    assert result.normalized_actions == ()


def test_stale_generation_and_epoch_are_rejected(repo):
    req = request()
    response = PlanningResponse(req.request_id, req.run_id, req.repository_id, "gen-2", 8, req.objective)
    result = validator(repo).validate(req, response)
    codes = {v.code for v in result.violations}
    assert {"STALE_GENERATION", "STALE_EPOCH"} <= codes
    assert not result.accepted


def test_cross_run_and_cross_repository_rejected(repo):
    req = request()
    response = PlanningResponse(req.request_id, "run-2", "repo-2", req.generation, req.mutation_epoch, req.objective)
    result = validator(repo).validate(req, response)
    codes = {v.code for v in result.violations}
    assert {"RUN_MISMATCH", "REPOSITORY_MISMATCH"} <= codes
