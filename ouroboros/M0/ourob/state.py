"""Fail-closed run state machine.

There is deliberately no legal path from BLOCKED, FAILED, PLANNED or any
other non-verified state directly to PROMOTED. Recovery quarantine is an
explicit state: it can only be entered from an interrupted EXECUTING action
and can only leave through an explicit reconciliation event.
"""

from __future__ import annotations

from .model import Run, RunState


class InvalidTransition(RuntimeError):
    pass


ALLOWED_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.NO_TASK: frozenset({RunState.INTAKE}),
    RunState.INTAKE: frozenset({RunState.PLANNED, RunState.BLOCKED}),
    RunState.PLANNED: frozenset({RunState.AUTHORIZED, RunState.BLOCKED}),
    RunState.AUTHORIZED: frozenset({RunState.EXECUTING, RunState.BLOCKED}),
    RunState.EXECUTING: frozenset({RunState.OBSERVED, RunState.FAILED, RunState.BLOCKED, RunState.QUARANTINED}),
    RunState.OBSERVED: frozenset({RunState.AUTHORIZED, RunState.VERIFYING}),
    RunState.VERIFYING: frozenset({RunState.VERIFIED, RunState.FAILED, RunState.BLOCKED}),
    RunState.VERIFIED: frozenset({RunState.PROMOTABLE}),
    RunState.PROMOTABLE: frozenset({RunState.PROMOTED}),
    RunState.PROMOTED: frozenset(),
    RunState.QUARANTINED: frozenset({RunState.PLANNED, RunState.BLOCKED, RunState.FAILED}),
    RunState.BLOCKED: frozenset(),
    RunState.FAILED: frozenset(),
}

TERMINAL_STATES: frozenset[RunState] = frozenset(
    state for state, targets in ALLOWED_TRANSITIONS.items() if not targets
)


def can_transition(current: RunState, target: RunState) -> bool:
    return target in ALLOWED_TRANSITIONS[current]


def transition(run: Run, target: RunState) -> None:
    if not can_transition(run.state, target):
        raise InvalidTransition(f"{run.state} -> {target} is not permitted")
    run.state = target
