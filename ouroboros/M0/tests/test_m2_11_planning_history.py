import pytest

from ourob.model import Event
from ourob.planning.bridge import PLANNING_ACCEPTED, PLANNING_FAILED
from ourob.planning.history import PlanningHistoryIntegrityError, reconstruct_planning_history


REQ1 = "1" * 64
REQ2 = "2" * 64
REQ3 = "3" * 64
RES1 = "4" * 64
RES2 = "5" * 64
RES3 = "6" * 64


def test_history_is_reconstructed_and_claims_are_audited(kernel):
    run = kernel.intake("run-history", "inspect")
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "attempt": 1, "request_digest": REQ1, "response_digest": RES1,
        "violations": ["BAD_PLAN"],
    }))
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "attempt": 2, "request_digest": REQ2, "response_digest": RES2,
        "violations": ["STALE_EPOCH"],
    }))
    kernel.journal.append(Event(PLANNING_ACCEPTED, run.id, generation=run.generation, data={
        "attempt": 3, "request_digest": REQ3, "response_digest": RES3,
    }))

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 3
    assert [item.attempt for item in history.attempts] == [1, 2, 3]
    assert history.attempts[0].request_digest == REQ1
    assert history.attempts[1].violations == ("STALE_EPOCH",)
    assert history.accepted is history.attempts[2]
    assert history.accepted.response_digest == RES3


def test_inconsistent_attempt_claim_fails_closed(kernel):
    run = kernel.intake("run-history-claim", "inspect")
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "attempt": 7, "request_digest": REQ1, "response_digest": RES1,
    }))

    with pytest.raises(PlanningHistoryIntegrityError):
        reconstruct_planning_history(kernel, run.id)


def test_multiple_accepted_attempts_fail_closed(kernel):
    run = kernel.intake("run-history-accepted", "inspect")
    for attempt, response in ((1, RES1), (2, RES2)):
        kernel.journal.append(Event(PLANNING_ACCEPTED, run.id, generation=run.generation, data={
            "attempt": attempt, "request_digest": REQ1, "response_digest": response,
        }))

    with pytest.raises(PlanningHistoryIntegrityError):
        reconstruct_planning_history(kernel, run.id)


def test_unrelated_events_are_not_part_of_history(kernel):
    run = kernel.intake("run-history-2", "inspect")
    kernel.journal.append(Event("ACTION_EXECUTED", run.id, generation=run.generation))
    kernel.journal.append(Event(PLANNING_FAILED, "other-run", generation=run.generation,
                                data={"request_digest": REQ1, "response_digest": RES1}))

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 0
    assert history.accepted is None


def test_history_is_derived_after_run_counter_is_tampered(kernel):
    run = kernel.intake("run-history-3", "inspect")
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "request_digest": REQ1, "response_digest": RES1,
    }))
    run.planning_attempts = 9000

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 1
    assert history.attempts[0].attempt == 1
