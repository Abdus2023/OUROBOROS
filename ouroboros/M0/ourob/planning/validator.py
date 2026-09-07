"""Validation converts untrusted proposals into executable Actions only when safe."""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Iterable

from ..model import Action, ActionKind
from ..policy import PolicyEngine
from .model import PlanValidation, PlanViolation, PlanningRequest, PlanningResponse


def canonical_response(response: PlanningResponse) -> bytes:
    payload = {
        "request_id": response.request_id,
        "run_id": response.run_id,
        "repository_id": response.repository_id,
        "generation": response.generation,
        "mutation_epoch": response.mutation_epoch,
        "objective": response.objective,
        "assumptions": list(response.assumptions),
        "actions": [
            {"action_id": a.action_id, "kind": a.kind, "skill": a.skill, "target": a.target,
             "arguments": dict(a.arguments), "expected_effect": a.expected_effect}
            for a in response.actions
        ],
        "verification_gates": list(response.verification_gates),
        "rollback_strategy": response.rollback_strategy,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(response: PlanningResponse) -> str:
    return hashlib.sha256(canonical_response(response)).hexdigest()


class PlanValidator:
    """Pure boundary validator. Policy is re-evaluated for every normalized Action."""

    def __init__(self, policy: PolicyEngine, allowed_skills: Iterable[str] = (), max_actions: int = 64):
        self.policy = policy
        self.allowed_skills = frozenset(allowed_skills)
        self.max_actions = max_actions

    def validate(self, request: PlanningRequest, response: PlanningResponse) -> PlanValidation:
        violations: list[PlanViolation] = []
        if response.request_id != request.request_id:
            violations.append(PlanViolation("REQUEST_MISMATCH", "response belongs to another planning request"))
        if response.run_id != request.run_id:
            violations.append(PlanViolation("RUN_MISMATCH", "response belongs to another run"))
        if response.repository_id != request.repository_id:
            violations.append(PlanViolation("REPOSITORY_MISMATCH", "response belongs to another repository"))
        if response.generation != request.generation:
            violations.append(PlanViolation("STALE_GENERATION", "plan generation differs from current generation"))
        if response.mutation_epoch != request.mutation_epoch:
            violations.append(PlanViolation("STALE_EPOCH", "plan mutation epoch differs from current epoch"))
        if response.objective != request.objective:
            violations.append(PlanViolation("OBJECTIVE_MISMATCH", "response objective differs from request"))
        if len(response.actions) > self.max_actions:
            violations.append(PlanViolation("ACTION_BUDGET", "plan exceeds maximum action budget"))

        seen: set[str] = set()
        normalized: list[Action] = []
        for proposal in response.actions:
            if proposal.action_id in seen:
                violations.append(PlanViolation("DUPLICATE_ACTION_ID", f"duplicate action id: {proposal.action_id}", proposal.action_id))
                continue
            seen.add(proposal.action_id)
            try:
                kind = ActionKind(proposal.kind)
            except ValueError:
                violations.append(PlanViolation("UNKNOWN_ACTION_KIND", f"unknown action kind: {proposal.kind!r}", proposal.action_id))
                continue
            if request.allowed_action_kinds and kind.value not in request.allowed_action_kinds:
                violations.append(PlanViolation("ACTION_KIND_DENIED", f"action kind not allowed: {kind.value}", proposal.action_id))
                continue
            if self.allowed_skills and proposal.skill not in self.allowed_skills:
                violations.append(PlanViolation("UNKNOWN_SKILL", f"skill not available: {proposal.skill}", proposal.action_id))
                continue
            if kind in {ActionKind.WRITE, ActionKind.EDIT}:
                path = proposal.arguments.get("path")
                if not isinstance(path, str) or not path:
                    violations.append(PlanViolation("MISSING_PATH", "mutation requires a path", proposal.action_id))
                    continue
                p = PurePosixPath(path)
                if p.is_absolute() or ".." in p.parts:
                    violations.append(PlanViolation("PATH_ESCAPE", f"path is not repository-relative: {path}", proposal.action_id))
                    continue
            action = Action(proposal.action_id, kind, proposal.skill, dict(proposal.arguments), proposal.expected_effect)
            decision = self.policy.evaluate(action)
            if not decision.allowed:
                violations.append(PlanViolation("POLICY_DENIED", decision.reason, proposal.action_id))
                continue
            normalized.append(action)

        if violations:
            return PlanValidation(False, tuple(violations), ())
        return PlanValidation(True, (), tuple(normalized))
