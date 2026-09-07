from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

class RunState(StrEnum):
    NO_TASK='NO_TASK'; INTAKE='INTAKE'; PLANNED='PLANNED'; AUTHORIZED='AUTHORIZED'; EXECUTING='EXECUTING'; OBSERVED='OBSERVED'; VERIFYING='VERIFYING'; VERIFIED='VERIFIED'; PROMOTABLE='PROMOTABLE'; PROMOTED='PROMOTED'; BLOCKED='BLOCKED'; FAILED='FAILED'
class ActionKind(StrEnum):
    READ='READ'; SEARCH='SEARCH'; WRITE='WRITE'; EDIT='EDIT'; EXECUTE='EXECUTE'; VERIFY='VERIFY'; GIT='GIT'
class VerificationStatus(StrEnum):
    PASS='PASS'; FAIL='FAIL'; BLOCKED='BLOCKED'; INCONCLUSIVE='INCONCLUSIVE'; NOT_RUN='NOT_RUN'; STALE='STALE'; INVALID='INVALID'; SKIPPED='SKIPPED'
@dataclass(frozen=True)
class Action:
    id:str; kind:ActionKind; skill:str; arguments:dict[str,Any]; rationale:str=''
@dataclass(frozen=True)
class Observation:
    action_id:str; ok:bool; generation:str; result:Any=None; error:str|None=None
@dataclass(frozen=True)
class VerificationResult:
    gate:str; status:VerificationStatus; evidence_id:str; generation:str; epoch:int; message:str=''
@dataclass(frozen=True)
class Event:
    name:str; run_id:str|None=None; action_id:str|None=None; generation:str|None=None; data:dict[str,Any]=field(default_factory=dict)
@dataclass
class Run:
    id:str; task:str; state:RunState=RunState.NO_TASK; generation:str=''; verification_epoch:int=0; actions:list[Action]=field(default_factory=list); observations:list[Observation]=field(default_factory=list); verifications:list[VerificationResult]=field(default_factory=list)
