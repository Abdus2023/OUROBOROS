"""Fail-closed cold-start recovery and quarantine controller.

Cold start reconstructs durable state without replaying capabilities. An
interrupted ``EXECUTING`` action is not retried: it can be durably quarantined
and must then be explicitly reconciled before the run can continue.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .generation import repository_generation
from .journal import Journal
from .model import Event, EventName, RunState
from .recovery import RecoveredRun, RecoveryError, recover_from_journal, recover_run


class ColdStartError(RuntimeError):
    """The durable state cannot safely enter a fresh runtime."""


@dataclass(frozen=True)
class ColdStartResult:
    """A verified durable run plus its cold-start disposition."""

    recovered: RecoveredRun
    resumable: bool
    requires_reauthorization: bool = False
    requires_reconciliation: bool = False

    @property
    def run(self):
        return self.recovered.run


def cold_start_run(journal_path: Path, repo_root: Path, run_id: str) -> ColdStartResult:
    """Recover one run and enforce the process-boundary safety rules.

    ``EXECUTING`` is reported as requiring reconciliation; it is never
    automatically resumed. ``OBSERVED`` is resumable through the normal
    kernel path, while ``AUTHORIZED`` preserves its durable authorization.
    """
    recovered = recover_from_journal(journal_path, run_id)
    run = recovered.run
    current_generation = repository_generation(Path(repo_root).resolve()).id

    if run.state is RunState.EXECUTING:
        return ColdStartResult(
            recovered=recovered,
            resumable=False,
            requires_reconciliation=True,
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


def quarantine_run(journal_path: Path, run_id: str) -> RecoveredRun:
    """Durably quarantine an interrupted ``EXECUTING`` run.

    The append is serialized with journal integrity verification. The
    validator reconstructs the current run while holding the journal lock, so
    a second recovery worker cannot race a quarantine decision. No skill or
    action is executed by this operation.
    """
    journal = Journal(journal_path)
    holder: dict[str, RecoveredRun] = {}

    def validate(records) -> None:
        recovered = recover_run([record.event for record in records], run_id)
        if recovered.run.state is not RunState.EXECUTING:
            raise ColdStartError(
                f"run {run_id} is not EXECUTING; cannot quarantine state {recovered.run.state}"
            )
        holder["recovered"] = recovered

    recovered_before = None
    try:
        journal.append_checked(
            Event(
                EventName.RECOVERY_QUARANTINED.value,
                run_id=run_id,
                action_id=None,
                generation=None,
                data={"reason": "interrupted_execution"},
            ),
            validate,
        )
        recovered_before = holder["recovered"]
    except RecoveryError as exc:
        raise ColdStartError(str(exc)) from exc

    # The event is intentionally reread from the validated journal so the
    # returned object is the exact durable post-quarantine state.
    return recover_from_journal(journal_path, run_id)


__all__ = ["ColdStartError", "ColdStartResult", "cold_start_run", "quarantine_run"]
