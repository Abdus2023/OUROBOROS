"""Fail-closed cold-start recovery controller.

Recovery is deliberately read-only with respect to the journal: it first
reconstructs durable state, then applies the cold-start boundary before a
kernel is allowed to resume work.

An ``EXECUTING`` run is unrecoverable as an automatically resumable run. The
journal proves that an action was proposed, but absence of ``ACTION_EXECUTED``
does not prove that no side effect occurred before a process crash. Such a
run is therefore quarantined instead of replaying the action.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .generation import repository_generation
from .journal import Journal, JournalIntegrityError
from .model import RunState
from .recovery import RecoveredRun, RecoveryError, recover_from_journal


class ColdStartError(RuntimeError):
    """The durable state cannot safely enter a fresh runtime."""


@dataclass(frozen=True)
class ColdStartResult:
    """A verified durable run plus its cold-start disposition."""

    recovered: RecoveredRun
    resumable: bool
    requires_reauthorization: bool = False

    @property
    def run(self):
        return self.recovered.run


def cold_start_run(journal_path: Path, repo_root: Path, run_id: str) -> ColdStartResult:
    """Recover one run and enforce the process-boundary safety rules.

    Terminal states are returned as-is. ``OBSERVED`` is resumable through the
    normal kernel path, which requires durable plan validation and emits a new
    authorization event before the next action. ``AUTHORIZED`` is also
    resumable because the authorization itself is durable and has not crossed
    an execution boundary yet.

    ``EXECUTING`` is never resumed automatically because an action may have
    reached the mutation boundary immediately before the crash while its
    ``ACTION_EXECUTED`` record was still unwritten.
    """
    try:
        recovered = recover_from_journal(journal_path, run_id)
    except RecoveryError:
        raise
    except JournalIntegrityError as exc:
        raise ColdStartError(f"journal integrity failure: {exc}") from exc

    run = recovered.run
    current_generation = repository_generation(Path(repo_root).resolve()).id
    if run.state is RunState.EXECUTING:
        raise ColdStartError(
            f"run {run.id} stopped in EXECUTING; automatic replay is unsafe because mutation may have occurred"
        )

    if run.state in {RunState.AUTHORIZED, RunState.OBSERVED} and run.generation != current_generation:
        raise ColdStartError(
            f"run {run.id} generation {run.generation} differs from current repository generation {current_generation}"
        )

    return ColdStartResult(
        recovered=recovered,
        resumable=run.state in {RunState.AUTHORIZED, RunState.OBSERVED},
        requires_reauthorization=run.state is RunState.OBSERVED,
    )


__all__ = ["ColdStartError", "ColdStartResult", "cold_start_run"]
