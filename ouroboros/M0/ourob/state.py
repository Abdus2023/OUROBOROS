from .model import Run,RunState
class InvalidTransition(RuntimeError): pass
ALLOWED_TRANSITIONS={RunState.NO_TASK:{RunState.INTAKE},RunState.INTAKE:{RunState.PLANNED,RunState.BLOCKED},RunState.PLANNED:{RunState.AUTHORIZED,RunState.BLOCKED},RunState.AUTHORIZED:{RunState.EXECUTING,RunState.BLOCKED},RunState.EXECUTING:{RunState.OBSERVED,RunState.FAILED,RunState.BLOCKED},RunState.OBSERVED:{RunState.AUTHORIZED,RunState.VERIFYING},RunState.VERIFYING:{RunState.VERIFIED,RunState.FAILED,RunState.BLOCKED},RunState.VERIFIED:{RunState.PROMOTABLE},RunState.PROMOTABLE:{RunState.PROMOTED},RunState.PROMOTED:set(),RunState.BLOCKED:set(),RunState.FAILED:set()}
def transition(run:Run,target:RunState)->None:
    if target not in ALLOWED_TRANSITIONS[run.state]: raise InvalidTransition(f'{run.state} -> {target} is not permitted')
    run.state=target
