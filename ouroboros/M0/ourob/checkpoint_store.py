"""M1.16 crash-safe publication of the external current checkpoint.

The checkpoint is an authorization artifact, not ordinary repository state.
Publication therefore uses a same-directory temporary file, durable flush,
atomic replacement, and directory synchronization where the platform permits
it. A partial write must never become the published checkpoint.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from pathlib import Path
from typing import Final

from .trust_checkpoint import TrustStateBoundCheckpoint

CHECKPOINT_FILE_MODE: Final[int] = 0o600


class CheckpointPublicationError(RuntimeError):
    """Raised when a checkpoint cannot be safely published or loaded."""


def _canonical_json(record: dict) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _reject_symlink(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return
    if stat.S_ISLNK(mode):
        raise CheckpointPublicationError("checkpoint target must not be a symlink")


def _sync_directory(parent: Path) -> None:
    """Persist the rename; fail closed when directory fsync is unavailable."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(parent, flags)
    except OSError as exc:
        raise CheckpointPublicationError("cannot open checkpoint directory for synchronization") from exc
    try:
        os.fsync(fd)
    except OSError as exc:
        raise CheckpointPublicationError("cannot synchronize checkpoint directory") from exc
    finally:
        os.close(fd)


def publish_checkpoint(
    checkpoint: TrustStateBoundCheckpoint,
    path: Path,
    *,
    mode: int = CHECKPOINT_FILE_MODE,
) -> None:
    """Atomically publish a validated checkpoint without exposing partial bytes."""
    if not isinstance(checkpoint, TrustStateBoundCheckpoint):
        raise CheckpointPublicationError("publication requires a trust-state-bound checkpoint")
    if not isinstance(path, Path):
        path = Path(path)
    parent = path.parent
    if not parent.is_dir():
        raise CheckpointPublicationError("checkpoint parent directory must already exist")
    if mode & ~0o777:
        raise CheckpointPublicationError("invalid checkpoint file mode")
    if mode & 0o077:
        raise CheckpointPublicationError("checkpoint publication must not grant group/world access")
    _reject_symlink(path)

    try:
        payload = _canonical_json(checkpoint.to_record())
    except Exception as exc:
        raise CheckpointPublicationError("checkpoint serialization failed") from exc

    temp = parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    fd = -1
    replaced = False
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            fd = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        replaced = True
        _sync_directory(parent)
    except OSError as exc:
        raise CheckpointPublicationError("checkpoint publication failed") from exc
    finally:
        if fd != -1:
            try:
                os.close(fd)
            except OSError:
                pass
        if not replaced:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def load_checkpoint(path: Path) -> TrustStateBoundCheckpoint:
    """Load and structurally validate a published checkpoint."""
    path = Path(path)
    try:
        if path.is_symlink():
            raise CheckpointPublicationError("checkpoint target must not be a symlink")
        raw = path.read_bytes()
        if not raw:
            raise CheckpointPublicationError("checkpoint file is empty")
        record = json.loads(raw.decode("utf-8"))
        return TrustStateBoundCheckpoint.from_record(record)
    except CheckpointPublicationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CheckpointPublicationError("checkpoint file is malformed or unreadable") from exc
