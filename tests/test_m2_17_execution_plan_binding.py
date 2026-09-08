import pytest

from ourob.model import Action, ActionKind, EventName, Plan
from ourob.kernel import KernelError


def _action():
    return Action("read-readme", ActionKind.READ, "filesystem.read", {"path": "README.md"})


def test_action_execution_event_carries_authorized_plan_digest(kernel):
    run = kernel.intake("run-m2-17", "inspect")
    action = _action()
    kernel.plan(run, Plan(run.task, (action,)))
    kernel.authorize(run)
    kernel.execute(run, action)

    events = [e for e in kernel.journal.events() if e.run_id == run.id]
    planned = next(e for e in events if e.name == EventName.RUN_PLANNED.value)
    executed = next(e for e in events if e.name == EventName.ACTION_EXECUTED.value)
    assert executed.data["plan_digest"] == planned.data["plan_digest"]


def test_tampered_plan_cannot_reach_execution(kernel):
    run = kernel.intake("run-m2-17-tamper", "inspect")
    action = _action()
    kernel.plan(run, Plan(run.task, (action,)))
    kernel.authorize(run)
    run.planned[0] = Action(
        action.id, ActionKind.READ, action.skill, {"path": "OTHER.md"}
    )

    with pytest.raises(KernelError):
        kernel.execute(run, run.planned[0])


def test_execution_event_binds_to_exact_plan_not_action_id_only(kernel):
    run = kernel.intake("run-m2-17-id", "inspect")
    first = _action()
    kernel.plan(run, Plan(run.task, (first,)))
    kernel.authorize(run)

    substitute = Action(first.id, ActionKind.READ, first.skill, {"path": "OTHER.md"})
    with pytest.raises(KernelError):
        kernel.execute(run, substitute)
