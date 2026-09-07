from __future__ import annotations
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from .model import Action,ActionKind
class MutationClass(StrEnum): ORDINARY='ORDINARY'; CAPABILITY='CAPABILITY'; POLICY='POLICY'; VERIFIER='VERIFIER'; KERNEL='KERNEL'; BOOTSTRAP='BOOTSTRAP'
@dataclass(frozen=True)
class PolicyDecision: allowed:bool; reason:str; mutation_class:MutationClass
PROTECTED_PREFIXES={MutationClass.KERNEL:('ourob/kernel/','ourob/kernel.py'),MutationClass.BOOTSTRAP:('bootstrap/','ourob/bootstrap.py'),MutationClass.POLICY:('policies/','ourob/policy.py'),MutationClass.VERIFIER:('verification/','ourob/verify.py')}
class PolicyEngine:
    def classify(self,path):
        n=PurePosixPath(path).as_posix().lstrip('./')
        for c,prefixes in PROTECTED_PREFIXES.items():
            if any(n==p.rstrip('/') or n.startswith(p) for p in prefixes): return c
        if n.startswith('skills/') or n.startswith('ourob/skills/'): return MutationClass.CAPABILITY
        return MutationClass.ORDINARY
    def evaluate(self,action):
        if action.kind not in {ActionKind.WRITE,ActionKind.EDIT}: return PolicyDecision(True,'non-mutating action',MutationClass.ORDINARY)
        path=str(action.arguments.get('path',''))
        if not path: return PolicyDecision(False,'mutation requires a repository-relative path',MutationClass.ORDINARY)
        c=self.classify(path)
        return PolicyDecision(c is MutationClass.ORDINARY,f'ordinary repository mutation allowed' if c is MutationClass.ORDINARY else f'elevated authorization required for {c} mutation: {path}',c)
