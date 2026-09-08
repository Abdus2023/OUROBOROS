"""M2.13 lifecycle audit for durable planning evidence."""
from __future__ import annotations

from ..kernel import Kernel
from ..model import Action, EventName, plan_digest
from .history import PlanningHistory, PlanningHistoryIntegrityError, reconstruct_planning_history
from .bridge import PLANNING_ACCEPTED


def audit_planning_lifecycle(kernel: Kernel, run_id: str) -> PlanningHistory:
    """Bind accepted planning evidence to the durable RUN_PLANNED event."""
    history = reconstruct_planning_history(kernel, run_id)
    records = kernel.journal.records()
    events = [record.event for record in records if record.event.run_id == run_id]
    if history.count and not any(event.name == EventName.RUN_CREATED.value for event in events):
        raise PlanningHistoryIntegrityError("planning evidence exists without RUN_CREATED")
    accepted = history.accepted
    if accepted is None:
        return history

    positions = [
        index for index, event in enumerate(events)
        if event.name == PLANNING_ACCEPTED and event.data.get("attempt") == accepted.attempt
    ]
    if len(positions) != 1:
        raise PlanningHistoryIntegrityError("accepted planning event is not uniquely identifiable")
    prior_plans = [event for event in events[:positions[0]] if event.name == EventName.RUN_PLANNED.value]
    if not prior_plans:
        raise PlanningHistoryIntegrityError("accepted planning attempt has no preceding RUN_PLANNED event")
    planned = prior_plans[-1]
    if planned.generation != accepted.generation:
        raise PlanningHistoryIntegrityError("RUN_PLANNED and PLANNING_ACCEPTED generations differ")

    claimed = planned.data.get("plan_digest")
    if not isinstance(claimed, str) or not claimed:
        actions = planned.data.get("actions")
        if not isinstance(actions, list) or not actions:
            raise PlanningHistoryIntegrityError("RUN_PLANNED has no canonical action list")
        try:
            claimed = plan_digest(tuple(Action.from_record(action) for action in actions))
        except (TypeError, ValueError) as exc:
            raise PlanningHistoryIntegrityError("RUN_PLANNED action list is invalid") from exc

    if not accepted.plan_digest:
        raise PlanningHistoryIntegrityError("accepted planning attempt has no plan identity")
    if accepted.plan_digest != claimed:
        raise PlanningHistoryIntegrityError("accepted plan identity differs from RUN_PLANNED")
    return history


__all__ = ["audit_planning_lifecycle"]
