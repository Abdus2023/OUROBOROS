"""Journal-derived planning history and consistency checks (M2.12).

Planning history is reconstructed exclusively from durable journal events.
The reconstruction is informational: it grants no authority and never
replaces current validation or kernel authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from .bridge import PLANNING_ACCEPTED, PLANNING_FAILED


PLANNING_ATTEMPT_EVENTS = frozenset({PLANNING_FAILED, PLANNING_ACCEPTED})


class PlanningHistoryIntegrityError(ValueError):
    """Raised when durable planning evidence contradicts its lifecycle."""


@dataclass(frozen=True)
class PlanningAttempt:
    """One durable planning attempt reconstructed from a journal event."""

    attempt: int
    event_name: str
    run_id: str
    generation: str | None
    request_digest: str
    response_digest: str
    violations: tuple[str, ...] = ()
    data: tuple[tuple[str, Any], ...] = ()

    @property
    def accepted(self) -> bool:
        return self.event_name == PLANNING_ACCEPTED


@dataclass(frozen=True)
class PlanningHistory:
    """Deterministic, internally consistent planning history for one run."""

    run_id: str
    attempts: tuple[PlanningAttempt, ...]

    @property
    def count(self) -> int:
        return len(self.attempts)

    @property
    def accepted(self) -> PlanningAttempt | None:
        accepted = [attempt for attempt in self.attempts if attempt.accepted]
        return accepted[0] if accepted else None


def _require_digest(value: Any, field: str, *, required: bool) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value:
        raise PlanningHistoryIntegrityError(f"{field} must be a non-empty string")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise PlanningHistoryIntegrityError(f"{field} must be a lowercase SHA-256 digest")
    return value


def reconstruct_planning_history(kernel: Kernel, run_id: str) -> PlanningHistory:
    """Reconstruct and audit planning attempts for ``run_id``.

    Journal order is authoritative for reconstruction. The durable ``attempt``
    claim must agree with that order; it cannot redefine it. Exactly one
    accepted attempt is permitted, and it must terminate the planning-attempt
    sequence.
    """
    attempts: list[PlanningAttempt] = []
    accepted_seen = False

    for event in kernel.journal.events():
        if event.run_id != run_id or event.name not in PLANNING_ATTEMPT_EVENTS:
            continue

        data = dict(event.data)
        claimed_attempt = data.pop("attempt", None)
        expected_attempt = len(attempts) + 1
        if claimed_attempt is not None and (
            not isinstance(claimed_attempt, int)
            or isinstance(claimed_attempt, bool)
            or claimed_attempt != expected_attempt
        ):
            raise PlanningHistoryIntegrityError(
                f"planning attempt claim {claimed_attempt!r} != journal position {expected_attempt}"
            )

        if event.name == PLANNING_ACCEPTED and accepted_seen:
            raise PlanningHistoryIntegrityError("multiple accepted planning attempts")
        if accepted_seen:
            raise PlanningHistoryIntegrityError("planning attempt recorded after acceptance")

        request_hash = _require_digest(data.pop("request_digest", None), "request_digest", required=True)
        response_hash = _require_digest(
            data.pop("response_digest", None),
            "response_digest",
            required=event.name == PLANNING_ACCEPTED,
        )

        raw_violations = data.pop("violations", ())
        if not isinstance(raw_violations, (list, tuple)) or any(
            not isinstance(value, str) for value in raw_violations
        ):
            raise PlanningHistoryIntegrityError("violations must be a sequence of strings")
        violations = tuple(raw_violations)
        if event.name == PLANNING_ACCEPTED and violations:
            raise PlanningHistoryIntegrityError("accepted planning attempt contains violations")

        attempt = PlanningAttempt(
            attempt=expected_attempt,
            event_name=event.name,
            run_id=run_id,
            generation=event.generation,
            request_digest=request_hash,
            response_digest=response_hash,
            violations=violations,
            data=tuple(sorted(data.items(), key=lambda item: item[0])),
        )
        attempts.append(attempt)
        accepted_seen = accepted_seen or attempt.accepted

    return PlanningHistory(run_id, tuple(attempts))


__all__ = [
    "PlanningAttempt",
    "PlanningHistory",
    "PlanningHistoryIntegrityError",
    "PLANNING_ATTEMPT_EVENTS",
    "reconstruct_planning_history",
]
