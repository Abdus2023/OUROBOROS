import pytest

from ourob.model import Run, RunState
from ourob.state import ALLOWED_TRANSITIONS, InvalidTransition, can_transition, transition


def test_happy_path_is_legal():
    run = Run("r", "t")
    for target in (RunState.INTAKE, RunState.PLANNED, RunState.AUTHORIZED, RunState.EXECUTING,
                   RunState.OBSERVED, RunState.VERIFYING, RunState.VERIFIED, RunState.PROMOTABLE, RunState.PROMOTED):
        transition(run, target)
    assert run.state is RunState.PROMOTED


@pytest.mark.parametrize("start", [s for s in RunState if s not in (RunState.PROMOTABLE,)])
def test_no_shortcut_to_promoted(start):
    assert not can_transition(start, RunState.PROMOTED)


def test_terminal_states_have_no_exits():
    for state in (RunState.PROMOTED, RunState.BLOCKED, RunState.FAILED):
        assert ALLOWED_TRANSITIONS[state] == frozenset()


def test_invalid_transition_raises_and_leaves_state_unchanged():
    run = Run("r", "t", state=RunState.PLANNED)
    with pytest.raises(InvalidTransition):
        transition(run, RunState.PROMOTED)
    assert run.state is RunState.PLANNED


def test_observed_may_reauthorize_for_multi_action_runs():
    assert can_transition(RunState.OBSERVED, RunState.AUTHORIZED)
    assert can_transition(RunState.OBSERVED, RunState.VERIFYING)
