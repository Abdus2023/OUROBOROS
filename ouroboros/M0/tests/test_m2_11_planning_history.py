from ourob.model import Event
from ourob.planning.bridge import PLANNING_ACCEPTED, PLANNING_FAILED
from ourob.planning.history import reconstruct_planning_history


def test_history_is_reconstructed_from_event_order(kernel):
    run = kernel.intake("run-history", "inspect")
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "attempt": 999, "request_digest": "req-1", "response_digest": "res-1",
        "violations": ["BAD_PLAN"],
    }))
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation, data={
        "attempt": 1, "request_digest": "req-2", "response_digest": "res-2",
        "violations": ["STALE_EPOCH"],
    }))
    kernel.journal.append(Event(PLANNING_ACCEPTED, run.id, generation=run.generation, data={
        "attempt": 2, "request_digest": "req-3", "response_digest": "res-3",
    }))

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 3
    assert [item.attempt for item in history.attempts] == [1, 2, 3]
    assert history.attempts[0].request_digest == "req-1"
    assert history.attempts[1].violations == ("STALE_EPOCH",)
    assert history.accepted is history.attempts[2]
    assert history.accepted.response_digest == "res-3"


def test_unrelated_events_are_not_part_of_history(kernel):
    run = kernel.intake("run-history-2", "inspect")
    kernel.journal.append(Event("ACTION_EXECUTED", run.id, generation=run.generation))
    kernel.journal.append(Event(PLANNING_FAILED, "other-run", generation=run.generation,
                                data={"request_digest": "x"}))

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 0
    assert history.accepted is None


def test_history_is_derived_after_run_counter_is_tampered(kernel):
    run = kernel.intake("run-history-3", "inspect")
    kernel.journal.append(Event(PLANNING_FAILED, run.id, generation=run.generation,
                                data={"request_digest": "req", "response_digest": "res"}))
    run.planning_attempts = 9000

    history = reconstruct_planning_history(kernel, run.id)

    assert history.count == 1
    assert history.attempts[0].attempt == 1
