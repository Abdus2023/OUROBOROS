"""Journal-derived planning history (M2.11).

Planning history is reconstructed exclusively from durable journal events.
The reconstruction is informational: it grants no authority and never
replaces current validation or kernel authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..kernel import Kernel
from ..model import Event
from .bridge import PLANNING_ACCEPTED, PLANNING_FAILED


PLANNING_ATTEMPT_EVENTS = frozenset({PLANNING_FAILED, PLANNING_ACCEPTED})


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
    """Deterministic planning history for one run."""

    run_id: str
    attempts: tuple[PlanningAttempt, ...]

    @property
    def count(self) -> int:
        return len(self.attempts)

    @property
    def accepted(self) -> PlanningAttempt | None:
        accepted = [attempt for attempt in self.attempts if attempt.accepted]
        return accepted[-1] if accepted else None


def reconstruct_planning_history(kernel: Kernel, run_id: str) -> PlanningHistory:
    """Reconstruct all planning attempts for ``run_id`` from the journal.

    Event sequence is authoritative. Attempt numbers in event payloads are
    treated as claims and are deliberately not trusted for reconstruction.
    """
    attempts: list[PlanningAttempt] = []
    for event in kernel.journal.events():
        if event.run_id != run_id or event.name not in PLANNING_ATTEMPT_EVENTS:
            continue
        data = dict(event.data)
        raw_violations = data.pop("violations", ())
        violations = tuple(str(value) for value in raw_violations) if isinstance(raw_violations, (list, tuple)) else ()
        request_hash = data.pop("request_digest", "")
        response_hash = data.pop("response_digest", "")
        attempts.append(
            PlanningAttempt(
                attempt=len(attempts) + 1,
                event_name=event.name,
                run_id=run_id,
                generation=event.generation,
                request_digest=request_hash if isinstance(request_hash, str) else "",
                response_digest=response_hash if isinstance(response_hash, str) else "",
                violations=violations,
                data=tuple(sorted(data.items(), key=lambda item: item[0])),
            )
        )
    return PlanningHistory(run_id, tuple(attempts))


__all__ = ["PlanningAttempt", "PlanningHistory", "PLANNING_ATTEMPT_EVENTS", "reconstruct_planning_history"]
