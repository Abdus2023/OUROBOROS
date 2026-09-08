import pytest

from ourob.model import Action, ActionKind, Event, Plan, plan_digest
from ourob.planning.bridge import PLANNING_ACCEPTED
from ourob.planning.lifecycle import audit_planning_lifecycle
from ourob.planning.history import PlanningHistoryIntegrityError


REQ = "a" * 64
RES = "b" * 64


def _action():
    return Action("read-readme", ActionKind.READ, "filesystem.read", {"path": "README.md"})


def test_accepted_plan_is_bound_to_run_planned(kernel):
    run = kernel.intake("run-lifecycle", "inspect")
    action = _action()
    kernel.plan(run, Plan(run.task, (action,)))
    kernel.journal.append(Event(
        PLANNING_ACCEPTED,
        run.id,
        generation=run.generation,
        data={"attempt": 1, "request_digest": REQ, "response_digest": RES, "plan_digest": plan_digest((action,))},
    ))

    history = audit_planning_lifecycle(kernel, run.id)

    assert history.accepted is not None
    assert history.accepted.plan_digest == plan_digest((action,))


def test_accepted_plan_identity_mismatch_fails_closed(kernel):
    run = kernel.intake("run-lifecycle-mismatch", "inspect")
    action = _action()
    kernel.plan(run, Plan(run.task, (action,)))
    kernel.journal.append(Event(
        PLANNING_ACCEPTED,
        run.id,
        generation=run.generation,
        data={"attempt": 1, "request_digest": REQ, "response_digest": RES, "plan_digest": "c" * 64},
    ))

    with pytest.raises(PlanningHistoryIntegrityError):
        audit_planning_lifecycle(kernel, run.id)


def test_accepted_plan_without_run_planned_fails_closed(kernel):
    run = kernel.intake("run-lifecycle-missing", "inspect")
    kernel.journal.append(Event(
        PLANNING_ACCEPTED,
        run.id,
        generation=run.generation,
        data={"attempt": 1, "request_digest": REQ, "response_digest": RES, "plan_digest": "c" * 64},
    ))

    with pytest.raises(PlanningHistoryIntegrityError):
        audit_planning_lifecycle(kernel, run.id)
