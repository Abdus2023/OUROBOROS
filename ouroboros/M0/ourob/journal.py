"""Append-only, hash-chained JSONL journal.

M1.8 adds ``append_checked`` so security-sensitive check-then-append
operations validate the complete current chain while holding the same lock
that serializes the durable append.
"""
from __future__ import annotations
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator
from .model import Event
if TYPE_CHECKING:
    from .signed_trust import SignedCheckpoint, TrustStore
    from .trust import JournalTrustAnchor
try:
    import fcntl
except ImportError:
    fcntl = None
JOURNAL_VERSION = "ourob.journal.v1"
GENESIS_DIGEST = "GENESIS"
class JournalIntegrityError(RuntimeError): pass
class JournalDurabilityError(RuntimeError): pass
@dataclass(frozen=True)
class JournalRecord:
    version: str; sequence: int; previous_digest: str; timestamp: str; event: Event; digest: str
    def body(self) -> dict[str, Any]: return {"version":self.version,"sequence":self.sequence,"previous_digest":self.previous_digest,"timestamp":self.timestamp,"event":self.event.to_record()}
    def to_record(self) -> dict[str, Any]:
        record=self.body(); record["digest"]=self.digest; return record
def canonical_json(value: Any) -> bytes: return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")
def record_digest(body: dict[str, Any]) -> str: return sha256(canonical_json(body)).hexdigest()
def _parse_record(line: str,line_number: int) -> dict[str, Any]:
    try: parsed=json.loads(line)
    except json.JSONDecodeError as exc: raise JournalIntegrityError(f"malformed journal record at line {line_number}: {exc.msg}") from exc
    if not isinstance(parsed,dict): raise JournalIntegrityError(f"journal record at line {line_number} is not an object")
    return parsed
def _validate_record(raw: dict[str, Any],expected_sequence: int,expected_previous: str,line_number: int) -> JournalRecord:
    if raw.get("version")!=JOURNAL_VERSION: raise JournalIntegrityError(f"unsupported journal version at line {line_number}: {raw.get('version')!r}")
    sequence=raw.get("sequence")
    if not isinstance(sequence,int) or isinstance(sequence,bool) or sequence!=expected_sequence: raise JournalIntegrityError(f"invalid journal sequence at line {line_number}: expected {expected_sequence}, found {sequence!r}")
    previous=raw.get("previous_digest")
    if previous!=expected_previous: raise JournalIntegrityError(f"broken journal hash chain at line {line_number}")
    timestamp=raw.get("timestamp")
    if not isinstance(timestamp,str) or not timestamp: raise JournalIntegrityError(f"missing journal timestamp at line {line_number}")
    digest=raw.get("digest")
    if not isinstance(digest,str) or not digest: raise JournalIntegrityError(f"missing journal digest at line {line_number}")
    try: event=Event.from_record(raw.get("event"))
    except ValueError as exc: raise JournalIntegrityError(f"invalid journal event at line {line_number}: {exc}") from exc
    body={"version":raw.get("version"),"sequence":sequence,"previous_digest":previous,"timestamp":timestamp,"event":event.to_record()}
    if record_digest(body)!=digest: raise JournalIntegrityError(f"journal record digest mismatch at line {line_number}")
    extra=set(raw)-set(body)-{"digest"}
    if extra: raise JournalIntegrityError(f"unexpected journal fields at line {line_number}: {sorted(extra)}")
    return JournalRecord(body["version"],sequence,previous,timestamp,event,digest)
class Journal:
    def __init__(self,path: Path): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
    def records(self)->list[JournalRecord]:
        if not self.path.exists(): return []
        records=[]; previous=GENESIS_DIGEST
        with self.path.open("r",encoding="utf-8") as handle:
            for line_number,line in enumerate(handle,start=1):
                if not line.endswith("\n"): raise JournalIntegrityError(f"truncated journal record at line {line_number}")
                if not line.strip(): raise JournalIntegrityError(f"blank journal line at line {line_number}")
                record=_validate_record(_parse_record(line.strip(),line_number),len(records)+1,previous,line_number); records.append(record); previous=record.digest
        return records
    def events(self)->list[Event]: return [r.event for r in self.records()]
    def read(self)->list[dict[str,Any]]: return [r.to_record() for r in self.records()]
    def verify(self)->bool:
        try: self.records()
        except JournalIntegrityError: return False
        return True
    def head_digest(self)->str:
        records=self.records(); return records[-1].digest if records else GENESIS_DIGEST
    def read_trusted(self,anchor:"JournalTrustAnchor",generation:str|None=None)->list[JournalRecord]:
        from .trust import verify_anchor
        records=self.records(); verify_anchor(anchor,records,generation); return records
    def read_signed_trusted(self,checkpoint:"SignedCheckpoint",store:"TrustStore",generation:str|None=None)->list[JournalRecord]:
        from .signed_trust import verify_signed_anchor
        records=self.records(); verify_signed_anchor(checkpoint,store,records,generation); return records
    def read_historical_signed_trusted(self,checkpoint:"SignedCheckpoint",store:"TrustStore",generation:str|None=None)->list[JournalRecord]:
        from .signed_trust import verify_signed_anchor
        records=self.records(); verify_signed_anchor(checkpoint,store,records,generation,historical=True); return records
    @property
    def lock_path(self)->Path: return self.path.with_name(self.path.name+".lock")
    @contextmanager
    def _exclusive(self)->Iterator[None]:
        if fcntl is None: raise JournalDurabilityError("journal append requires POSIX fcntl locking; refusing to degrade")
        with self.lock_path.open("a+b") as lock_handle:
            fcntl.flock(lock_handle.fileno(),fcntl.LOCK_EX)
            try: yield
            finally: fcntl.flock(lock_handle.fileno(),fcntl.LOCK_UN)
    def _append_locked(self,event:Event,existing:list[JournalRecord])->JournalRecord:
        sequence=len(existing)+1; previous=existing[-1].digest if existing else GENESIS_DIGEST
        body={"version":JOURNAL_VERSION,"sequence":sequence,"previous_digest":previous,"timestamp":datetime.now(timezone.utc).isoformat(),"event":event.to_record()}
        record=JournalRecord(JOURNAL_VERSION,sequence,previous,body["timestamp"],event,record_digest(body))
        with self.path.open("a",encoding="utf-8") as handle:
            handle.write(canonical_json(record.to_record()).decode("utf-8")+"\n"); handle.flush(); os.fsync(handle.fileno())
        return record
    def append(self,event:Event)->JournalRecord:
        with self._exclusive(): return self._append_locked(event,self.records())
    def append_checked(self,event:Event,validator:Callable[[list[JournalRecord]],None])->JournalRecord:
        with self._exclusive():
            existing=self.records(); validator(existing); return self._append_locked(event,existing)
    def extend(self,events:Iterable[Event])->None:
        for event in events: self.append(event)
