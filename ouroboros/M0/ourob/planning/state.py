"""Canonical, journal-derived planning state (M2.15)."""
from __future__ import annotations

from ..kernel import Kernel
from .history import PlanningHistory, PlanningHistoryIntegrityError, reconstruct_planning_history


def planning_state(kernel: Kernel, run_id: str, *, generation: str | None = None,
                   mutation_epoch: int | None = None) -> PlanningHistory:
    """Reconstruct planning state and optionally bind it to a live boundary.

    The journal is authoritative. ``Run`` counters are deliberately ignored.
    When a generation/epoch is supplied, every durable planning attempt must
    agree with that boundary. Legacy records without an epoch remain readable,
    but cannot silently masquerade as a different epoch.
    """
    history = reconstruct_planning_history(kernel, run_id)
    if generation is None and mutation_epoch is None:
        return history

    for attempt in history.attempts:
        if generation is not None and attempt.generation != generation:
            raise PlanningHistoryIntegrityError(
                "planning history generation does not match the live boundary"
            )
        if mutation_epoch is not None:
            values = dict(attempt.data)
            recorded = values.get("mutation_epoch")
            if recorded is not None and recorded != mutation_epoch:
                raise PlanningHistoryIntegrityError(
                    "planning history mutation epoch does not match the live boundary"
                )
    return history


def planning_attempt_count(kernel: Kernel, run_id: str) -> int:
    """Return the journal-derived number of planning attempts."""
    return planning_state(kernel, run_id).count


__all__ = ["planning_state", "planning_attempt_count"]
