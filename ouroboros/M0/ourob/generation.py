from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
DEFAULT_EXCLUDED_NAMES=frozenset({'.git','.ourob','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache'})
@dataclass(frozen=True)
class ManifestEntry:
    path:str; digest:str; size:int
@dataclass(frozen=True)
class RepositoryGeneration:
    id:str; entries:tuple[ManifestEntry,...]
def build_manifest(root:Path,excluded=DEFAULT_EXCLUDED_NAMES):
    entries=[]
    for p in sorted(root.rglob('*')):
        if not p.is_file() or any(part in excluded for part in p.relative_to(root).parts): continue
        data=p.read_bytes(); entries.append(ManifestEntry(p.relative_to(root).as_posix(),sha256(data).hexdigest(),len(data)))
    return tuple(entries)
def canonical_manifest(entries):
    return ('\n'.join(f'{e.path}\0{e.digest}\0{e.size}' for e in entries)+'\n').encode() if entries else b''
def repository_generation(root,excluded=DEFAULT_EXCLUDED_NAMES):
    entries=build_manifest(Path(root),excluded)
    return RepositoryGeneration(sha256(canonical_manifest(entries)).hexdigest(),entries)
