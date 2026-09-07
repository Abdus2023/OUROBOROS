"""Promotion authority (M0.9, M0.17–M0.23).

Promotion is authorized only by an integrity-checked ``VerificationEvidence``
whose generation, epoch and gate contract all match the current kernel state
and the current repository. The authority does not mutate the run; it returns
a decision that the kernel enacts.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .evidence import VerificationEvidence
from .generation import repository_generation
from .model import Run, RunState


@dataclass(frozen=True)
class PromotionDecision:
    allowed: bool
    reason: str


class PromotionAuthority:
    def authorize(
        self,
        run: Run,
        evidence: VerificationEvidence | None,
        repo_root: Path,
        current_gate_set_digest: str,
    ) -> PromotionDecision:
        if run.state is not RunState.VERIFIED:
            return PromotionDecision(False, f"run is not VERIFIED: {run.state}")
        if evidence is None:
            return PromotionDecision(False, "no verification evidence captured")
        if evidence.run_id != run.id:
            return PromotionDecision(False, "evidence belongs to another run")
        if not evidence.results:
            return PromotionDecision(False, "verification evidence is empty")
        if not evidence.integrity_valid():
            return PromotionDecision(False, "verification evidence digest is invalid")
        if evidence.gate_set_digest != current_gate_set_digest:
            return PromotionDecision(False, "verification gate contract changed since verification")
        if evidence.generation != run.generation:
            return PromotionDecision(False, "evidence generation does not match run generation")
        if evidence.epoch != run.verification_epoch:
            return PromotionDecision(False, "evidence epoch is stale")
        if not evidence.complete:
            return PromotionDecision(False, "verification evidence does not cover every required gate")
        if not evidence.passed:
            return PromotionDecision(False, "verification evidence is not all PASS")
        current = repository_generation(repo_root).id
        if current != evidence.generation:
            return PromotionDecision(False, "repository generation changed before promotion")
        return PromotionDecision(True, "integrity-checked verification evidence authorizes promotion")
