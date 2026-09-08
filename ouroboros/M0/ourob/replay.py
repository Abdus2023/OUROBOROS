"""Fail-closed reconstruction of a run from its durable journal."""
from __future__ import annotations

from typing import Any

from .journal import Journal, JournalIntegrityError, verify_observation_event
from .model import Action, ActionKind, EventName, Observation, Run, RunState
from .state import can_transition


class ReplayError(RuntimeError):
    """Raised when durable run history cannot reconstruct a coherent run."""


def _observation_from_record(record: dict[str, Any]) -> Observation:
    try:
        kind = ActionKind(record["kind"]) if record["kind"] is not None else None
    except ValueError as exc:
        raise ReplayError(f"unknown observation action kind: {record.get('kind')!r}") from exc
    return Observation(
        action_id=record["action_id"],
        ok=record["ok"],
        generation=record["generation"],
        result=None,
        error=record["error"],
        skill=record["skill"],
        kind=kind,
        arguments_digest=record["arguments_digest"],
        result_digest=record["result_digest"],
    )


def reconstruct_run(journal: Journal, run_id: str) -> Run:
    """Reconstruct a run using only durable journal records.

    Replay never executes skills and never trusts an in-memory Run. The journal
    chain and every durable observation identity are verified before state is
    reconstructed. Raw action arguments/results are intentionally unavailable
    to replay; their digests remain part of the reconstructed observation.
    """
    if not isinstance(run_id, str) or not run_id:
        raise ReplayError("run id must be non-empty")

    try:
        records = journal.records()
        journal.verify_observations()
    except JournalIntegrityError as exc:
        raise ReplayError("journal integrity verification failed") from exc
    if not journal.verify_observations():
        raise ReplayError("durable observation integrity verification failed")

    events = [record.event for record in records if record.event.run_id == run_id]
    if not events:
        raise ReplayError(f"run {run_id!r} has no durable events")
    if events[0].name != EventName.RUN_CREATED.value:
        raise ReplayError("run history does not begin with RUN_CREATED")

    created = events[0]
    task = created.data.get("task")
    if not isinstance(task, str) or not task:
        raise ReplayError("RUN_CREATED has no valid task")
    if not isinstance(created.generation, str) or not created.generation:
        raise ReplayError("RUN_CREATED has no valid generation")

    run = Run(run_id, task, generation=created.generation)
    run.state = RunState.INTAKE
    planned: dict[str, Action] = {}
    terminal = False

    for event in events[1:]:
        if terminal:
            raise ReplayError(f"event {event.name} occurs after terminal state {run.state.value}")
        name = event.name
        if name == EventName.RUN_PLANNED.value:
            if run.state is not RunState.INTAKE:
                raise ReplayError("RUN_PLANNED is out of order")
            actions = event.data.get("actions")
            claimed_digest = event.data.get("plan_digest")
            if not isinstance(actions, list) or not actions:
                raise ReplayError("RUN_PLANNED has no action list")
            try:
                decoded = [Action.from_record(value) for value in actions]
            except ValueError as exc:
                raise ReplayError("RUN_PLANNED contains an invalid action") from exc
            from .model import plan_digest
            if not isinstance(claimed_digest, str) or plan_digest(decoded) != claimed_digest:
                raise ReplayError("RUN_PLANNED plan digest is inconsistent")
            if len({action.id for action in decoded}) != len(decoded):
                raise ReplayError("RUN_PLANNED contains duplicate action ids")
            run.planned = decoded
            planned = {action.id: action for action in decoded}
            run.state = RunState.PLANNED
            continue

        if name == EventName.AUTHORIZATION_GRANTED.value:
            if run.state not in {RunState.PLANNED, RunState.OBSERVED}:
                raise ReplayError("AUTHORIZATION_GRANTED is out of order")
            if not isinstance(event.data.get("plan_digest"), str):
                raise ReplayError("AUTHORIZATION_GRANTED has no plan digest")
            run.state = RunState.AUTHORIZED
            continue

        if name == EventName.ACTION_EXECUTED.value:
            if run.state is not RunState.AUTHORIZED:
                raise ReplayError("ACTION_EXECUTED is out of order")
            action = planned.get(event.action_id or "")
            if action is None:
                raise ReplayError("ACTION_EXECUTED references an unplanned action")
            record = verify_observation_event(event)
            observation = _observation_from_record(record)
            if observation.action_id != action.id or observation.skill != action.skill or observation.kind is not action.kind:
                raise ReplayError("ACTION_EXECUTED observation disagrees with planned action")
            run.actions.append(action)
            run.observations.append(observation)
            generation = event.generation
            if not isinstance(generation, str) or not generation:
                raise ReplayError("ACTION_EXECUTED has no generation")
            run.generation = generation
            epoch = event.data.get("epoch")
            if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < run.verification_epoch:
                raise ReplayError("ACTION_EXECUTED has invalid verification epoch")
            run.verification_epoch = epoch
            run.state = RunState.OBSERVED
            continue

        if name == EventName.ACTION_FAILED.value:
            if run.state is not RunState.AUTHORIZED:
                raise ReplayError("ACTION_FAILED is out of order")
            action = planned.get(event.action_id or "")
            if action is None:
                raise ReplayError("ACTION_FAILED references an unplanned action")
            record = verify_observation_event(event)
            observation = _observation_from_record(record)
            if observation.ok:
                raise ReplayError("ACTION_FAILED carries a successful observation")
            if observation.action_id != action.id:
                raise ReplayError("ACTION_FAILED observation disagrees with action")
            run.actions.append(action)
            run.observations.append(observation)
            run.state = RunState.FAILED
            terminal = True
            continue

        if name == EventName.POLICY_DENIED.value:
            if run.state is not RunState.AUTHORIZED:
                raise ReplayError("POLICY_DENIED is out of order")
            action = planned.get(event.action_id or "")
            if action is None:
                raise ReplayError("POLICY_DENIED references an unplanned action")
            record = verify_observation_event(event)
            observation = _observation_from_record(record)
            if observation.ok:
                raise ReplayError("POLICY_DENIED carries a successful observation")
            if observation.action_id != action.id:
                raise ReplayError("POLICY_DENIED observation disagrees with action")
            run.observations.append(observation)
            run.state = RunState.BLOCKED
            terminal = True
            continue

        if name == EventName.VERIFICATION_STARTED.value:
            if run.state is not RunState.OBSERVED:
                raise ReplayError("VERIFICATION_STARTED is out of order")
            run.state = RunState.VERIFYING
            continue

        if name == EventName.GATE_RESULT.value:
            if run.state is not RunState.VERIFYING:
                raise ReplayError("GATE_RESULT is out of order")
            from .model import VerificationResult
            try:
                result = VerificationResult.from_record(event.data.get("result"))
            except ValueError as exc:
                raise ReplayError("GATE_RESULT is invalid") from exc
            run.verifications.append(result)
            continue

        if name == EventName.VERIFICATION_EVIDENCE_CAPTURED.value:
            if run.state is not RunState.VERIFYING:
                raise ReplayError("verification evidence is out of order")
            run.state = RunState.VERIFIED
            continue

        if name == EventName.VERIFICATION_FAILED.value:
            if run.state is not RunState.VERIFYING:
                raise ReplayError("VERIFICATION_FAILED is out of order")
            status = event.data.get("status")
            run.state = RunState.BLOCKED if status == "BLOCKED" else RunState.FAILED
            terminal = True
            continue

        if name == EventName.PROMOTION_AUTHORIZED.value:
            if run.state is not RunState.VERIFIED:
                raise ReplayError("PROMOTION_AUTHORIZED is out of order")
            run.state = RunState.PROMOTABLE
            continue

        if name == EventName.PROMOTED.value:
            if run.state is not RunState.PROMOTABLE:
                raise ReplayError("PROMOTED is out of order")
            run.state = RunState.PROMOTED
            terminal = True
            continue

        if name in {
            EventName.ACTION_PROPOSED.value,
            EventName.POLICY_ALLOWED.value,
            EventName.PROMOTION_DENIED.value,
        }:
            continue

        raise ReplayError(f"unsupported durable event during run replay: {name}")

    return run


__all__ = ["ReplayError", "reconstruct_run"]
