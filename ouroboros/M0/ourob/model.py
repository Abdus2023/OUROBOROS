"""Core domain objects for the OUROBOROS M0 kernel.

State, actions, observations, verification results and journal events are
explicit, mostly immutable domain objects. Nothing in this module performs
I/O or makes authority decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RunState(StrEnum):
    NO_TASK = "NO_TASK"
    INTAKE = "INTAKE"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    OBSERVED = "OBSERVED"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    PROMOTABLE = "PROMOTABLE"
    PROMOTED = "PROMOTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


class ActionKind(StrEnum):
    READ = "READ"
    SEARCH = "SEARCH"
    WRITE = "WRITE"
    EDIT = "EDIT"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    GIT = "GIT"


class VerificationStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_RUN = "NOT_RUN"
    STALE = "STALE"
    INVALID = "INVALID"
    SKIPPED = "SKIPPED"


class EventName(StrEnum):
    """Durable journal event names emitted by the kernel."""

    RUN_CREATED = "RUN_CREATED"
    RUN_PLANNED = "RUN_PLANNED"
    AUTHORIZATION_GRANTED = "AUTHORIZATION_GRANTED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_ALLOWED = "POLICY_ALLOWED"
    POLICY_DENIED = "POLICY_DENIED"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_FAILED = "ACTION_FAILED"
    VERIFICATION_STARTED = "VERIFICATION_STARTED"
    GATE_RESULT = "GATE_RESULT"
    VERIFICATION_EVIDENCE_CAPTURED = "VERIFICATION_EVIDENCE_CAPTURED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    PROMOTION_AUTHORIZED = "PROMOTION_AUTHORIZED"
    PROMOTION_DENIED = "PROMOTION_DENIED"
    PROMOTED = "PROMOTED"


@dataclass(frozen=True)
class Action:
    id: str
    kind: ActionKind
    skill: str
    arguments: dict[str, Any]
    rationale: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "skill": self.skill,
            "arguments": dict(self.arguments),
            "rationale": self.rationale,
        }

    @classmethod
    def from_record(cls, record: Any) -> "Action":
        if not isinstance(record, dict):
            raise ValueError("action record must be an object")
        action_id = record.get("id")
        skill = record.get("skill")
        arguments = record.get("arguments", {})
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("action record requires a non-empty id")
        if not isinstance(skill, str) or not skill:
            raise ValueError("action record requires a non-empty skill")
        if not isinstance(arguments, dict):
            raise ValueError("action arguments must be an object")
        try:
            kind = ActionKind(record.get("kind"))
        except ValueError as exc:
            raise ValueError(f"unknown action kind: {record.get('kind')!r}") from exc
        rationale = record.get("rationale", "")
        if not isinstance(rationale, str):
            raise ValueError("action rationale must be a string")
        return cls(action_id, kind, skill, dict(arguments), rationale)


@dataclass(frozen=True)
class Observation:
    action_id: str
    ok: bool
    generation: str
    result: Any = None
    error: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    gate: str
    status: VerificationStatus
    evidence_id: str
    generation: str
    epoch: int
    message: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "status": self.status.value,
            "evidence_id": self.evidence_id,
            "generation": self.generation,
            "epoch": self.epoch,
            "message": self.message,
        }

    @classmethod
    def from_record(cls, record: Any) -> "VerificationResult":
        if not isinstance(record, dict):
            raise ValueError("verification result record must be an object")
        gate = record.get("gate")
        evidence_id = record.get("evidence_id")
        generation = record.get("generation")
        epoch = record.get("epoch")
        message = record.get("message", "")
        if not isinstance(gate, str) or not gate:
            raise ValueError("verification result requires a gate name")
        if not isinstance(evidence_id, str) or not evidence_id:
            raise ValueError("verification result requires an evidence id")
        if not isinstance(generation, str) or not generation:
            raise ValueError("verification result requires a generation")
        if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
            raise ValueError("verification result epoch must be a non-negative integer")
        if not isinstance(message, str):
            raise ValueError("verification result message must be a string")
        try:
            status = VerificationStatus(record.get("status"))
        except ValueError as exc:
            raise ValueError(f"unknown verification status: {record.get('status')!r}") from exc
        return cls(gate, status, evidence_id, generation, epoch, message)


@dataclass(frozen=True)
class Event:
    name: str
    run_id: str | None = None
    action_id: str | None = None
    generation: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "run_id": self.run_id,
            "action_id": self.action_id,
            "generation": self.generation,
            "data": dict(self.data),
        }

    @classmethod
    def from_record(cls, record: Any) -> "Event":
        if not isinstance(record, dict):
            raise ValueError("event record must be an object")
        name = record.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError("event record requires a name")
        data = record.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("event data must be an object")
        for key in ("run_id", "action_id", "generation"):
            value = record.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"event {key} must be a string or null")
        return cls(name, record.get("run_id"), record.get("action_id"), record.get("generation"), dict(data))


@dataclass(frozen=True)
class Plan:
    """A planner proposal. Plans carry no authority of their own."""

    task: str
    actions: tuple[Action, ...]

    def to_record(self) -> dict[str, Any]:
        return {"task": self.task, "actions": [a.to_record() for a in self.actions]}

    @classmethod
    def from_record(cls, record: Any) -> "Plan":
        if not isinstance(record, dict):
            raise ValueError("plan record must be an object")
        task = record.get("task")
        actions = record.get("actions")
        if not isinstance(task, str) or not task:
            raise ValueError("plan requires a task")
        if not isinstance(actions, list):
            raise ValueError("plan actions must be a list")
        return cls(task, tuple(Action.from_record(a) for a in actions))


@dataclass
class Run:
    id: str
    task: str
    state: RunState = RunState.NO_TASK
    generation: str = ""
    verification_epoch: int = 0
    planned: list[Action] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    verifications: list[VerificationResult] = field(default_factory=list)

    @property
    def planned_ids(self) -> tuple[str, ...]:
        return tuple(a.id for a in self.planned)

    @property
    def executed_ids(self) -> tuple[str, ...]:
        return tuple(a.id for a in self.actions)
