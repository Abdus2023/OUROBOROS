from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import subprocess,sys
from pathlib import Path
from .generation import repository_generation
from .model import VerificationResult,VerificationStatus
@dataclass(frozen=True)
class Gate: name:str; command:tuple[str,...]; required:bool=True
@dataclass(frozen=True)
class VerificationReport:
    generation:str; epoch:int; results:tuple[VerificationResult,...]
    @property
    def passed(self): return bool(self.results) and all(r.status is VerificationStatus.PASS for r in self.results)
DEFAULT_GATES=(Gate('compileall',(sys.executable,'-m','compileall','-q','ouroboros')),)
def _validate(gates):
    names=[g.name for g in gates]
    if len(names)!=len(set(names)): raise ValueError('duplicate gate names are not permitted')
    if any(not n or '\0' in n or '\n' in n for n in names): raise ValueError('invalid gate name')
    if any(not g.command or any(not isinstance(x,str) for x in g.command) for g in gates): raise ValueError('invalid gate command')
class Verifier:
    def __init__(self,repo_root:Path,gates=DEFAULT_GATES): self.repo_root=Path(repo_root).resolve(); self.gates=tuple(gates); _validate(self.gates)
    def verify(self,epoch):
        generation=repository_generation(self.repo_root).id; results=[]
        for gate in self.gates:
            try: c=subprocess.run(gate.command,cwd=self.repo_root,capture_output=True,text=True,timeout=120,check=False); status=VerificationStatus.PASS if c.returncode==0 else VerificationStatus.FAIL; message=(c.stdout+c.stderr).strip()
            except FileNotFoundError as exc: status=VerificationStatus.BLOCKED if gate.required else VerificationStatus.NOT_RUN; message=str(exc)
            except subprocess.TimeoutExpired as exc: status=VerificationStatus.FAIL; message=f'timeout: {exc}'
            evidence_id=sha256(f'{generation}\0{epoch}\0{gate.name}\0{status}\0{message}'.encode()).hexdigest(); results.append(VerificationResult(gate.name,status,evidence_id,generation,epoch,message))
        if repository_generation(self.repo_root).id!=generation: results=[VerificationResult(r.gate,VerificationStatus.STALE,r.evidence_id,generation,epoch,'repository changed during verification') for r in results]
        return VerificationReport(generation,epoch,tuple(results))
