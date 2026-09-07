from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime,timezone
from pathlib import Path
from .model import Event
class Journal:
    def __init__(self,path:Path): self.path=path; self.path.parent.mkdir(parents=True,exist_ok=True)
    def append(self,event:Event):
        record={'event':event.name,'timestamp':datetime.now(timezone.utc).isoformat(),**{k:v for k,v in asdict(event).items() if k!='name' and v is not None}}
        with self.path.open('a',encoding='utf-8') as h: h.write(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n'); h.flush()
    def read(self):
        if not self.path.exists(): return []
        with self.path.open(encoding='utf-8') as h: return [json.loads(x) for x in h if x.strip()]
