from __future__ import annotations

import json

import pytest

from ourob.planning import ContextFact, LLMPlanner, PlanningContext, PlanningRequest


class Provider:
    def __init__(self, payload):
        self.payload = payload
        self.prompt = None

    def generate(self, prompt: str) -> str:
        self.prompt = prompt
        return json.dumps(self.payload)


def request() -> PlanningRequest:
    return PlanningRequest("req-1", "run-1", "repo-1", "gen-1", 7, "inspect", ("read-only",), ("READ",), ())


def context(**overrides) -> PlanningContext:
    values = dict(repository_id="repo-1", generation="gen-1", mutation_epoch=7, run_id="run-1")
    values.update(overrides)
    return PlanningContext.build(**values, facts=[ContextFact("README is repository data", "repository-file")])


def test_provider_output_is_downgraded_to_proposal_data():
    provider = Provider({"actions": [{"action_id": "a1", "kind": "READ", "skill": "filesystem.read", "arguments": {"path": "README.md"}, "expected_effect": "inspect"}]})
    response = LLMPlanner(provider).plan(request(), context())
    assert response.actions[0].kind == "READ"
    assert response.actions[0].skill == "filesystem.read"
    assert "[REPOSITORY-OBSERVATIONS]" in provider.prompt
    assert "[repository-file] README is repository data" in provider.prompt


@pytest.mark.parametrize("field,value", [("run_id", "run-2"), ("repository_id", "repo-2"), ("generation", "gen-2"), ("mutation_epoch", 8)])
def test_stale_or_cross_boundary_context_is_rejected(field, value):
    kwargs = {field: value}
    with pytest.raises(ValueError):
        LLMPlanner(Provider({"actions": []})).plan(request(), context(**kwargs))


def test_oversized_model_output_is_rejected():
    provider = Provider({"actions": []})
    with pytest.raises(ValueError, match="exceeds configured limit"):
        LLMPlanner(provider, max_output_chars=1).plan(request(), context())


def test_invalid_model_json_is_rejected():
    class InvalidProvider:
        def generate(self, prompt: str) -> str:
            return "not-json"

    with pytest.raises(ValueError, match="invalid JSON"):
        LLMPlanner(InvalidProvider()).plan(request(), context())


def test_model_cannot_inject_executable_action_object():
    provider = Provider({"actions": [{"action_id": "a1", "kind": "WRITE", "skill": "filesystem.write", "arguments": {"path": "notes/x", "content": "x"}, "expected_effect": "write"}]})
    response = LLMPlanner(provider).plan(request(), context())
    assert not hasattr(response.actions[0], "handler")
    assert type(response.actions[0]).__name__ == "ProposedAction"
