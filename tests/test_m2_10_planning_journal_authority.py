from ourob.planning import planning_attempt_count


def test_planning_attempt_count_is_derived_from_journal(kernel, planning_bridge, planning_request, planning_response):
    run = kernel.intake(planning_request.run_id, planning_request.objective)
    assert planning_attempt_count(kernel, run.id) == 0

    failed = planning_bridge.apply_to_run(run, planning_request, object())
    assert not failed.accepted
    assert planning_attempt_count(kernel, run.id) == 1

    # The mutable cache must not become a second authority source.
    run.planning_attempts = 999
    assert planning_attempt_count(kernel, run.id) == 1


def test_controller_budget_ignores_tampered_run_counter(kernel, planning_bridge, planning_request, planning_context, deterministic_planner):
    from ourob.planning import PlanningController

    run = kernel.intake(planning_request.run_id, planning_request.objective)
    run.planning_attempts = 999
    controller = PlanningController(planning_bridge, max_attempts=1)
    result = controller.run(run, planning_request, deterministic_planner, planning_context)
    assert result.planning is not None
    assert result.planning.accepted


def test_planning_attempt_count_ignores_unrelated_events(kernel):
    from ourob.model import Event

    run = kernel.intake("run-unrelated", "task")
    kernel.journal.append(Event("ACTION_FAILED", run.id, generation=run.generation))
    assert planning_attempt_count(kernel, run.id) == 0
