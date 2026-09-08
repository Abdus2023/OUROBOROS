import pytest

from ourob.model import Event
from ourob.planning.bridge import PLANNING_FAILED, planning_history
from ourob.planning.history import PlanningHistoryIntegrityError


REQ = "1" * 64


def test_planning_history_is_canonical_over_mutable_run_cache(kernel):
    run = kernel.intake("m2-14-cache", "inspect")
    run.planning_attempts = 999
    assert planning_history(kernel, run.id).count == 0

    kernel.journal.append(Event(
        PLANNING_FAILED,
        run.id,
        generation=run.generation,
        data={
            "attempt": 1,
            "request_digest": REQ,
            "response_digest": "",
            "violations": ["PLANNER_ERROR"],
        },
    ))
    run.planning_attempts = 0
    history = planning_history(kernel, run.id)
    assert history.count == 1
    assert history.attempts[0].attempt == 1


def test_corrupt_durable_planning_state_blocks_canonical_read(kernel):
    run = kernel.intake("m2-14-corrupt", "inspect")
    kernel.journal.append(Event(
        PLANNING_FAILED,
        run.id,
        generation=run.generation,
        data={
            "attempt": 2,
            "request_digest": REQ,
            "response_digest": "",
            "violations": ["PLANNER_ERROR"],
        },
    ))
    run.planning_attempts = 0
    with pytest.raises(PlanningHistoryIntegrityError):
        planning_history(kernel, run.id)
