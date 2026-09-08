"""The OUROBOROS kernel: sole mutation gateway (M0.6, M0.11, M0.13, M1.3, M1.10).

The kernel owns exactly four things: state transitions, action authorization,
skill dispatch and promotion authorization. Every authority-bearing step is
journaled durably *before* the in-memory run advances, so a crash never leaves
the journal claiming less authority than the process had.

M1.10 additionally carries the cold-start trust decision into the kernel:
an authoritative kernel cannot promote unless the external trust boundary
was authenticated during bootstrap.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .evidence import VerificationEvidence, capture_evidence
from .generation import repository_generation
from .journal import Journal
from .model import Action, Event, EventName, Observation, Plan, Run, RunState, VerificationStatus, plan_digest
from .policy import PolicyEngine
from .promotion import PromotionAuthority, PromotionDecision
from .skills import SkillRegistry
from .state import InvalidTransition, transition
from .verify import Verifier


class KernelError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionOutcome:
    observation: Observation
    state: RunState
    reason: str


class Kernel:
    def __init__(
        self,
        repo_root: Path,
        journal: Journal,
        policy: PolicyEngine,
        skills: SkillRegistry,
        verifier: Verifier,
        promotion: PromotionAuthority | None = None,
        *,
        trust_authenticated: bool = False,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.journal = journal
        self.policy = policy
        self.skills = skills
        self.verifier = verifier
        self.promotion = promotion or PromotionAuthority()
        self.trust_authenticated = trust_authenticated
        self._evidence: dict[str, VerificationEvidence] = {}

    def _generation(self) -> str:
        return repository_generation(self.repo_root).id

    def _emit(self, name: EventName, run: Run, action_id: str | None = None, **data) -> None:
        self.journal.append(Event(name.value, run.id, action_id, run.generation, dict(data)))

    def evidence_for(self, run: Run) -> VerificationEvidence | None:
        return self._evidence.get(run.id)

    def _require_state(self, run: Run, *states: RunState) -> None:
        if run.state not in states:
            expected = " or ".join(s.value for s in states)
            raise KernelError(f"run {run.id} is {run.state}, expected {expected}")

    def intake(self, run_id: str, task: str) -> Run:
        if not run_id or not task:
            raise KernelError("intake requires a run id and a task")
        run = Run(run_id, task, generation=self._generation())
        transition(run, RunState.INTAKE)
        self._emit(EventName.RUN_CREATED, run, task=task)
        return run

    def plan(self, run: Run, plan: Plan) -> Run:
        self._require_state(run, RunState.INTAKE)
        if plan.task != run.task:
            raise KernelError("plan task does not match run task")
        ids = [a.id for a in plan.actions]
        if not ids or len(ids) != len(set(ids)):
            raise KernelError("plan requires a non-empty list of uniquely identified actions")
        self._emit(EventName.RUN_PLANNED, run,
                   actions=[a.to_record() for a in plan.actions],
                   plan_digest=plan_digest(plan.actions))
        run.planned = list(plan.actions)
        transition(run, RunState.PLANNED)
        return run

    def authorize(self, run: Run) -> Run:
        self._require_state(run, RunState.PLANNED, RunState.OBSERVED)
        self._emit(EventName.AUTHORIZATION_GRANTED, run, previous_state=run.state.value)
        transition(run, RunState.AUTHORIZED)
        return run

    def execute(self, run: Run, action: Action) -> ExecutionOutcome:
        if run.state is RunState.OBSERVED:
            self.authorize(run)
        self._require_state(run, RunState.AUTHORIZED)
        planned = {a.id: a for a in run.planned}
        if action.id not in planned or planned[action.id] != action:
            raise KernelError(f"action {action.id} was not part of the authorized plan")
        if action.id in run.executed_ids:
            raise KernelError(f"action {action.id} has already been executed")
        self._evidence.pop(run.id, None)
        self._emit(EventName.ACTION_PROPOSED, run, action.id, action=action.to_record())
        transition(run, RunState.EXECUTING)
        decision = self.policy.evaluate(action)
        if not decision.allowed:
            self._emit(EventName.POLICY_DENIED, run, action.id, reason=decision.reason, mutation_class=decision.mutation_class.value)
            transition(run, RunState.BLOCKED)
            observation = Observation(action.id, False, run.generation, None, decision.reason)
            run.observations.append(observation)
            return ExecutionOutcome(observation, run.state, decision.reason)
        self._emit(EventName.POLICY_ALLOWED, run, action.id, reason=decision.reason, mutation_class=decision.mutation_class.value)
        raw = self.skills.execute(action)
        new_generation = self._generation()
        observation = Observation(action.id, raw.ok, new_generation, raw.result, raw.error)
        run.actions.append(action)
        run.observations.append(observation)
        if not observation.ok:
            self._emit(EventName.ACTION_FAILED, run, action.id, error=observation.error or "")
            transition(run, RunState.FAILED)
            return ExecutionOutcome(observation, run.state, observation.error or "action failed")
        mutated = new_generation != run.generation
        run.generation = new_generation
        if mutated:
            run.verification_epoch += 1
        self._emit(EventName.ACTION_EXECUTED, run, action.id, ok=True, mutated=mutated, epoch=run.verification_epoch,
                   result=observation.result if isinstance(observation.result, (str, int, float, bool, list, dict)) else None)
        transition(run, RunState.OBSERVED)
        return ExecutionOutcome(observation, run.state, "observed")

    def execute_all(self, run: Run, actions: Iterable[Action] | None = None) -> list[ExecutionOutcome]:
        outcomes: list[ExecutionOutcome] = []
        for action in (list(actions) if actions is not None else list(run.planned)):
            outcome = self.execute(run, action)
            outcomes.append(outcome)
            if run.state is not RunState.OBSERVED:
                break
        return outcomes

    def verify(self, run: Run) -> VerificationEvidence | None:
        self._require_state(run, RunState.OBSERVED)
        self._evidence.pop(run.id, None)
        current = self._generation()
        if current != run.generation:
            self._emit(EventName.VERIFICATION_FAILED, run, reason="out-of-band repository mutation detected", status=VerificationStatus.INVALID.value)
            transition(run, RunState.VERIFYING)
            transition(run, RunState.FAILED)
            return None
        self._emit(EventName.VERIFICATION_STARTED, run, epoch=run.verification_epoch, gate_set_digest=self.verifier.gate_set_digest,
                   trust_authenticated=self.trust_authenticated)
        transition(run, RunState.VERIFYING)
        report = self.verifier.verify(run.verification_epoch)
        for result in report.results:
            run.verifications.append(result)
            self._emit(EventName.GATE_RESULT, run, result=result.to_record())
        evidence = capture_evidence(run, report.results, self.verifier.gate_names, self.verifier.gate_set_digest)
        if report.generation != run.generation or not evidence.passed:
            statuses = {r.status for r in report.results}
            blocked = VerificationStatus.BLOCKED in statuses
            self._emit(EventName.VERIFICATION_FAILED, run,
                       reason="verification gates did not all pass" if not blocked else "verification blocked",
                       status=(VerificationStatus.BLOCKED if blocked else VerificationStatus.FAIL).value,
                       gates={r.gate: r.status.value for r in report.results})
            transition(run, RunState.BLOCKED if blocked else RunState.FAILED)
            return None
        self._emit(EventName.VERIFICATION_EVIDENCE_CAPTURED, run, evidence=evidence.to_record())
        self._evidence[run.id] = evidence
        transition(run, RunState.VERIFIED)
        return evidence

    def promote(self, run: Run) -> PromotionDecision:
        self._require_state(run, RunState.VERIFIED)
        evidence = self._evidence.get(run.id)
        decision = self.promotion.authorize(run, evidence, self.repo_root, self.verifier.gate_set_digest,
                                            trust_authenticated=self.trust_authenticated)
        if not decision.allowed:
            self._emit(EventName.PROMOTION_DENIED, run, reason=decision.reason)
            return decision
        assert evidence is not None
        self._emit(EventName.PROMOTION_AUTHORIZED, run, evidence_digest=evidence.digest,
                   gate_set_digest=evidence.gate_set_digest, epoch=evidence.epoch,
                   trust_authenticated=self.trust_authenticated)
        transition(run, RunState.PROMOTABLE)
        self._emit(EventName.PROMOTED, run, evidence_digest=evidence.digest)
        transition(run, RunState.PROMOTED)
        return decision

    def run_plan(self, run_id: str, plan: Plan) -> Run:
        """Drive a plan through the complete lifecycle. Stops at the first
        BLOCKED/FAILED state; never skips a stage."""
        run = self.intake(run_id, plan.task)
        self.plan(run, plan)
        self.authorize(run)
        self.execute_all(run)
        if run.state is RunState.OBSERVED:
            self.verify(run)
        if run.state is RunState.VERIFIED:
            self.promote(run)
        return run


__all__ = ["Kernel", "KernelError", "ExecutionOutcome", "InvalidTransition"]
