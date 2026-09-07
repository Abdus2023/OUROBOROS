from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any,Callable
from .model import Action,ActionKind,Observation
@dataclass(frozen=True)
class Skill: name:str; kinds:frozenset[ActionKind]; handler:Callable[[Action],Any]
class SkillRegistry:
    def __init__(self): self._skills={}
    def register(self,skill):
        if skill.name in self._skills: raise ValueError(f'skill already registered: {skill.name}')
        self._skills[skill.name]=skill
    def has(self,name): return name in self._skills
    def names(self): return tuple(sorted(self._skills))
    def execute(self,action):
        skill=self._skills.get(action.skill)
        if skill is None: return Observation(action.id,False,'',None,f'unknown skill: {action.skill}')
        if action.kind not in skill.kinds: return Observation(action.id,False,'',None,f'skill does not support {action.kind}')
        try: return Observation(action.id,True,'',skill.handler(action),None)
        except Exception as exc: return Observation(action.id,False,'',None,f'{type(exc).__name__}: {exc}')
def filesystem_skills(repo_root):
    root=Path(repo_root).resolve(); registry=SkillRegistry()
    def safe(action):
        target=(root/Path(str(action.arguments['path']))).resolve()
        try: rel=target.relative_to(root)
        except ValueError as exc: raise ValueError('path escapes repository root') from exc
        return target,rel
    def read(action): return safe(action)[0].read_text(encoding='utf-8')
    def write(action):
        target,rel=safe(action); target.parent.mkdir(parents=True,exist_ok=True); target.write_text(str(action.arguments.get('content','')),encoding='utf-8'); return rel.as_posix()
    registry.register(Skill('filesystem.read',frozenset({ActionKind.READ}),read)); registry.register(Skill('filesystem.write',frozenset({ActionKind.WRITE,ActionKind.EDIT}),write)); return registry
