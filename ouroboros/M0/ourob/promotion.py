from __future__ import annotations
from dataclasses import dataclass
from .evidence import VerificationEvidence
from .generation import repository_generation
from .model import Run,RunState
from .state import transition
@dataclass(frozen=True)
class PromotionDecision: allowed:bool; reason:str
class PromotionAuthority:
    def authorize(self,run:Run,evidence:VerificationEvidence,repo_root):
        current=repository_generation(repo_root).id
        if run.state is not RunState.VERIFIED: return PromotionDecision(False,f'run is not VERIFIED: {run.state}')
        if evidence.run_id!=run.id: return PromotionDecision(False,'evidence belongs to another run')
        if not evidence.integrity_valid(): return PromotionDecision(False,'verification evidence digest is invalid')
        if evidence.generation!=run.generation or evidence.generation!=current: return PromotionDecision(False,'evidence generation is stale')
        if evidence.epoch!=run.verification_epoch: return PromotionDecision(False,'evidence epoch is stale')
        if not evidence.passed: return PromotionDecision(False,'verification evidence is incomplete or not all PASS')
        if not evidence.is_current(repo_root): return PromotionDecision(False,'repository generation changed before promotion')
        transition(run,RunState.PROMOTABLE); transition(run,RunState.PROMOTED); return PromotionDecision(True,'integrity-checked verification evidence authorizes promotion')
