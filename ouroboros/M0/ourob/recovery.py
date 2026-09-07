"""Durable journal recovery (M1.1, M1.3).

Reconstructs a ``Run`` exclusively from validated journal records. Recovery
may resume work, but it never manufactures authorization that was not
durably recorded:

* AUTHORIZED requires a durable AUTHORIZATION_GRANTED event.
* VERIFIED requires a durable VERIFICATION_EVIDENCE_CAPTURED event whose
  evidence passes integrity, generation and epoch checks.
* PROMOTABLE / PROMOTED require durable PROMOTION_AUTHORIZED / PROMOTED events
  bound to that exact evidence digest.

Every state change is replayed through the fail-closed state machine, so an
event sequence implying an illegal transition is rejected outright.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import VerificationEvidence
from .journal import Journal, JournalIntegrityError
from .model import Action, Event, EventName, Run, RunState, VerificationResult
from .state import InvalidTransition, transition

GENERATION_HEX_LENGTH = 64


class RecoveryError(RuntimeError):
    pass


@dataclass
class RecoveredRun:
    run: Run
    evidence: VerificationEvidence | None = None
    events: list[Event] = field(default_factory=list)

    @property
    def state(self) -> RunState:
        return self.run.state


def _is_generation(value: Any) -> bool:
    return isinstance(value, str) and len(value) == GENERATION_HEX_LENGTH and all(
        c in "0123456789abcdef" for c in value
    )


def _require_generation(event: Event, run: Run) -> None:
    if not _is_generation(event.generation):
        raise RecoveryError(f"{event.name}: malformed generation {event.generation!r}")


def _step(run: Run, target: RunState, event: Event) -> None:
    try:
        transition(run, target)
    except InvalidTransition as exc:
        raise RecoveryError(f"{event.name}: {exc}") from exc


def _apply(run: Run, event: Event, state: dict[str, Any]) -> None:
    try:
        name = EventName(event.name)
    except ValueError as exc:
        raise RecoveryError(f"unknown journal event: {event.name}") from exc
    _require_generation(event, run)

    if name is EventName.RUN_CREATED:
        raise RecoveryError("RUN_CREATED may only appear once, as the first event")

    if name is EventName.RUN_PLANNED:
        actions = event.data.get("actions")
        if not isinstance(actions, list) or not actions:
            raise RecoveryError("RUN_PLANNED requires a non-empty action list")
        try:
            run.planned = [Action.from_record(a) for a in actions]
        except ValueError as exc:
            raise RecoveryError(f"RUN_PLANNED: {exc}") from exc
        _step(run, RunState.PLANNED, event)
        return

    if name is EventName.AUTHORIZATION_GRANTED:
        _step(run, RunState.AUTHORIZED, event)
        state["evidence"] = None
        return

    if name is EventName.ACTION_PROPOSED:
        if not event.action_id:
            raise RecoveryError("ACTION_PROPOSED requires an action id")
        try:
            action = Action.from_record(event.data.get("action"))
        except ValueError as exc:
            raise RecoveryError(f"ACTION_PROPOSED: {exc}") from exc
        if action.id != event.action_id or action.id not in run.planned_ids:
            raise RecoveryError(f"ACTION_PROPOSED: action {event.action_id} was not part of the durable plan")
        _step(run, RunState.EXECUTING, event)
        state["pending"] = action
        state["evidence"] = None
        return

    if name is EventName.POLICY_ALLOWED:
        if run.state is not RunState.EXECUTING or state.get("pending") is None:
            raise RecoveryError("POLICY_ALLOWED without a pending proposed action")
        state["allowed"] = True
        return

    if name is EventName.POLICY_DENIED:
        if run.state is not RunState.EXECUTING or state.get("pending") is None:
            raise RecoveryError("POLICY_DENIED without a pending proposed action")
        _step(run, RunState.BLOCKED, event)
        state["pending"] = None
        return

    if name is EventName.ACTION_EXECUTED:
        pending = state.get("pending")
        if pending is None or not state.get("allowed"):
            raise RecoveryError("ACTION_EXECUTED without a durable POLICY_ALLOWED decision")
        epoch = event.data.get("epoch")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < run.verification_epoch:
            raise RecoveryError("ACTION_EXECUTED carries an invalid verification epoch")
        run.actions.append(pending)
        run.generation = event.generation or run.generation
        run.verification_epoch = epoch
        _step(run, RunState.OBSERVED, event)
        state["pending"] = None
        state["allowed"] = False
        return

    if name is EventName.ACTION_FAILED:
        if state.get("pending") is None:
            raise RecoveryError("ACTION_FAILED without a pending proposed action")
        _step(run, RunState.FAILED, event)
        state["pending"] = None
        state["allowed"] = False
        return

    if name is EventName.VERIFICATION_STARTED:
        _step(run, RunState.VERIFYING, event)
        state["gate_results"] = []
        return

    if name is EventName.GATE_RESULT:
        if run.state is not RunState.VERIFYING:
            raise RecoveryError("GATE_RESULT outside VERIFYING")
        try:
            result = VerificationResult.from_record(event.data.get("result"))
        except ValueError as exc:
            raise RecoveryError(f"GATE_RESULT: {exc}") from exc
        run.verifications.append(result)
        state.setdefault("gate_results", []).append(result)
        return

    if name is EventName.VERIFICATION_FAILED:
        if run.state is RunState.OBSERVED:
            # Kernel emits VERIFICATION_FAILED then transitions OBSERVED->VERIFYING->FAILED
            _step(run, RunState.VERIFYING, event)
        if run.state is not RunState.VERIFYING:
            raise RecoveryError("VERIFICATION_FAILED outside VERIFYING")
        status = event.data.get("status")
        _step(run, RunState.BLOCKED if status == "BLOCKED" else RunState.FAILED, event)
        return

    if name is EventName.VERIFICATION_EVIDENCE_CAPTURED:
        if run.state is not RunState.VERIFYING:
            raise RecoveryError("VERIFICATION_EVIDENCE_CAPTURED outside VERIFYING")
        try:
            evidence = VerificationEvidence.from_record(event.data.get("evidence"))
        except ValueError as exc:
            raise RecoveryError(f"VERIFICATION_EVIDENCE_CAPTURED: {exc}") from exc
        if evidence.run_id != run.id:
            raise RecoveryError("evidence belongs to another run")
        if evidence.generation != run.generation or evidence.generation != event.generation:
            raise RecoveryError("evidence generation does not match recovered run generation")
        if evidence.epoch != run.verification_epoch:
            raise RecoveryError("evidence epoch does not match recovered run epoch")
        if not evidence.passed:
            raise RecoveryError("captured evidence is incomplete or not all PASS")
        durable_results = {(r.gate, r.evidence_id) for r in state.get("gate_results", [])}
        if {(r.gate, r.evidence_id) for r in evidence.results} != durable_results:
            raise RecoveryError("captured evidence does not match durable GATE_RESULT records")
        state["evidence"] = evidence
        _step(run, RunState.VERIFIED, event)
        return

    if name is EventName.PROMOTION_DENIED:
        if run.state is not RunState.VERIFIED:
            raise RecoveryError("PROMOTION_DENIED outside VERIFIED")
        return

    if name is EventName.PROMOTION_AUTHORIZED:
        evidence = state.get("evidence")
        if evidence is None:
            raise RecoveryError("PROMOTION_AUTHORIZED without durable verification evidence")
        if event.data.get("evidence_digest") != evidence.digest:
            raise RecoveryError("PROMOTION_AUTHORIZED is not bound to the recovered evidence digest")
        if event.data.get("gate_set_digest") != evidence.gate_set_digest:
            raise RecoveryError("PROMOTION_AUTHORIZED gate contract does not match evidence")
        if event.data.get("epoch") != evidence.epoch:
            raise RecoveryError("PROMOTION_AUTHORIZED epoch does not match evidence")
        _step(run, RunState.PROMOTABLE, event)
        return

    if name is EventName.PROMOTED:
        evidence = state.get("evidence")
        if evidence is None or event.data.get("evidence_digest") != evidence.digest:
            raise RecoveryError("PROMOTED without matching durable promotion authorization")
        _step(run, RunState.PROMOTED, event)
        return

    raise RecoveryError(f"unhandled journal event: {event.name}")


def recover_run(events: list[Event], run_id: str) -> RecoveredRun:
    relevant = [e for e in events if e.run_id == run_id]
    if not relevant:
        raise RecoveryError(f"no durable records for run {run_id}")
    first = relevant[0]
    if first.name != EventName.RUN_CREATED.value:
        raise RecoveryError("first durable record for a run must be RUN_CREATED")
    task = first.data.get("task")
    if not isinstance(task, str) or not task:
        raise RecoveryError("RUN_CREATED lacks a task")
    if not _is_generation(first.generation):
        raise RecoveryError("RUN_CREATED lacks a valid generation")
    run = Run(run_id, task, generation=first.generation)
    transition(run, RunState.INTAKE)
    state: dict[str, Any] = {"pending": None, "allowed": False, "evidence": None, "gate_results": []}
    for event in relevant[1:]:
        _apply(run, event, state)
    return RecoveredRun(run, state.get("evidence"), relevant)


def recover_from_journal(journal_path: Path, run_id: str) -> RecoveredRun:
    try:
        events = Journal(journal_path).events()
    except JournalIntegrityError as exc:
        raise RecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_run(events, run_id)


def list_runs(journal_path: Path) -> tuple[str, ...]:
    events = Journal(journal_path).events()
    seen: list[str] = []
    for event in events:
        if event.name == EventName.RUN_CREATED.value and event.run_id and event.run_id not in seen:
            seen.append(event.run_id)
    return tuple(seen)
