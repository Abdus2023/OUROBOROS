from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from .generation import repository_generation
from .model import Run,VerificationResult,VerificationStatus
@dataclass(frozen=True)
class VerificationEvidence:
    run_id:str; generation:str; epoch:int; results:tuple[VerificationResult,...]; required_gates:tuple[str,...]; digest:str
    @property
    def passed(self):
        required=tuple(sorted(set(self.required_gates))); actual=tuple(sorted(r.gate for r in self.results))
        return bool(required) and actual==required and len(actual)==len(set(actual)) and all(r.status is VerificationStatus.PASS and r.generation==self.generation and r.epoch==self.epoch for r in self.results)
    def canonical_bytes(self):
        gate_text='\0'.join(sorted(self.required_gates))
        h=f'{self.run_id}\0{self.generation}\0{self.epoch}\0{gate_text}\0'.encode()
        body='\n'.join('\0'.join((r.gate,r.status.value,r.evidence_id,r.generation,str(r.epoch),r.message)) for r in sorted(self.results,key=lambda x:x.gate))+'\n'
        return h+body.encode()
    def recompute_digest(self): return sha256(self.canonical_bytes()).hexdigest()
    def integrity_valid(self): return self.digest==self.recompute_digest()
    def is_current(self,root): return repository_generation(root).id==self.generation
def capture_evidence(run:Run,results,required_gates):
    e=VerificationEvidence(run.id,run.generation,run.verification_epoch,tuple(results),tuple(required_gates),'')
    return VerificationEvidence(e.run_id,e.generation,e.epoch,e.results,e.required_gates,e.recompute_digest())
