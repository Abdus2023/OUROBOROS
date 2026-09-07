"""Repository generation identity (M0.7 / M0.16).

A generation is the SHA-256 of the canonical repository manifest. Runtime
state such as ``.git``, ``.ourob`` and caches is excluded so that the journal
does not recursively invalidate the generation it describes.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable

DEFAULT_EXCLUDED_NAMES: frozenset[str] = frozenset(
    {".git", ".ourob", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}
)


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    digest: str
    size: int


@dataclass(frozen=True)
class RepositoryGeneration:
    id: str
    entries: tuple[ManifestEntry, ...]

    def as_dict(self) -> dict[str, str]:
        return {entry.path: entry.digest for entry in self.entries}


def build_manifest(root: Path, excluded: Iterable[str] = DEFAULT_EXCLUDED_NAMES) -> tuple[ManifestEntry, ...]:
    root = Path(root)
    excluded_set = frozenset(excluded)
    entries: list[ManifestEntry] = []
    for candidate in sorted(root.rglob("*")):
        relative = candidate.relative_to(root)
        if any(part in excluded_set for part in relative.parts):
            continue
        if candidate.is_symlink() or not candidate.is_file():
            continue
        data = candidate.read_bytes()
        entries.append(ManifestEntry(relative.as_posix(), sha256(data).hexdigest(), len(data)))
    return tuple(entries)


def canonical_manifest(entries: Iterable[ManifestEntry]) -> bytes:
    lines = [f"{entry.path}\0{entry.digest}\0{entry.size}" for entry in sorted(entries, key=lambda e: e.path)]
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def repository_generation(root: Path, excluded: Iterable[str] = DEFAULT_EXCLUDED_NAMES) -> RepositoryGeneration:
    entries = build_manifest(Path(root), excluded)
    return RepositoryGeneration(sha256(canonical_manifest(entries)).hexdigest(), entries)


def generation_id(root: Path) -> str:
    return repository_generation(root).id
