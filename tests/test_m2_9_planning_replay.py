from dataclasses import FrozenInstanceError

from ourob.planning import (
    ContextFact,
    PlanningContext,
    PlanningRequest,
    PlanningResponse,
    ProposedAction,
    PlanningReplay,
    context_digest,
    planning_envelope_digest,
)


def _fixtures():
    request = PlanningRequest(
        request_id="req-1",
        run_id="run-1",
        repository_id="repo-1",
        generation="gen-1",
        mutation_epoch=0,
        objective="inspect README",
        allowed_action_kinds=("READ",),
        required_gates=("tests",),
    )
    context = PlanningContext.build(
        repository_id="repo-1",
        generation="gen-1",
        mutation_epoch=0,
        run_id="run-1",
        facts=(ContextFact("README exists", "[repository-file]"),),
        allowed_action_kinds=("READ",),
        required_gates=("tests",),
    )
    response = PlanningResponse(
        request_id="req-1",
        run_id="run-1",
        repository_id="repo-1",
        generation="gen-1",
        mutation_epoch=0,
        objective="inspect README",
        actions=(ProposedAction("a1", "READ", "filesystem.read", "README.md"),),
        verification_gates=("tests",),
    )
    return request, context, response


def test_replay_is_deterministic():
    request, context, response = _fixtures()
    first = PlanningReplay.record(request, context, response)
    second = PlanningReplay.record(request, context, response)
    assert first == second
    assert first.replay(request, context) == response
    assert planning_envelope_digest(request, context, response) == first.envelope_digest
    assert context_digest(context) == first.context_digest


def test_generation_change_invalidates_replay():
    request, context, response = _fixtures()
    replay = PlanningReplay.record(request, context, response)
    changed = PlanningContext.build(
        repository_id=context.repository_id,
        generation="gen-2",
        mutation_epoch=context.mutation_epoch,
        run_id=context.run_id,
        facts=context.facts,
        allowed_action_kinds=context.allowed_action_kinds,
        required_gates=context.required_gates,
    )
    try:
        replay.replay(request, changed)
    except ValueError as exc:
        assert "context identity" in str(exc)
    else:
        raise AssertionError("stale context replay was accepted")


def test_epoch_change_invalidates_replay():
    request, context, response = _fixtures()
    replay = PlanningReplay.record(request, context, response)
    changed = PlanningContext.build(
        repository_id=context.repository_id,
        generation=context.generation,
        mutation_epoch=1,
        run_id=context.run_id,
        facts=context.facts,
        allowed_action_kinds=context.allowed_action_kinds,
        required_gates=context.required_gates,
    )
    try:
        replay.replay(request, changed)
    except ValueError as exc:
        assert "context identity" in str(exc)
    else:
        raise AssertionError("stale epoch replay was accepted")


def test_recorded_response_is_immutable_and_digest_bound():
    request, context, response = _fixtures()
    replay = PlanningReplay.record(request, context, response)
    try:
        replay.response = response
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("replay response became mutable")
    assert replay.replay(request, context) == response
