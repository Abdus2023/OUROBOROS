"""Append-only, hash-chained JSONL journal (M0.3 + M1.2).

Every record carries a monotonically increasing sequence number, the digest
of the previous record (GENESIS for the first), a UTC timestamp, the event
payload and its own SHA-256 digest. Reading the journal validates the whole
chain and fails closed on any inconsistency, so recovery can distinguish an
interrupted runtime from a modified history.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from .model import Event

JOURNAL_VERSION = "ourob.journal.v1"
GENESIS_DIGEST = "GENESIS"


class JournalIntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class JournalRecord:
    version: str
    sequence: int
    previous_digest: str
    timestamp: str
    event: Event
    digest: str

    def body(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "sequence": self.sequence,
            "previous_digest": self.previous_digest,
            "timestamp": self.timestamp,
            "event": self.event.to_record(),
        }

    def to_record(self) -> dict[str, Any]:
        record = self.body()
        record["digest"] = self.digest
        return record


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_digest(body: dict[str, Any]) -> str:
    return sha256(canonical_json(body)).hexdigest()


def _parse_record(line: str, line_number: int) -> dict[str, Any]:
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:
        raise JournalIntegrityError(f"malformed journal record at line {line_number}: {exc.msg}") from exc
    if not isinstance(parsed, dict):
        raise JournalIntegrityError(f"journal record at line {line_number} is not an object")
    return parsed


def _validate_record(raw: dict[str, Any], expected_sequence: int, expected_previous: str, line_number: int) -> JournalRecord:
    version = raw.get("version")
    if version != JOURNAL_VERSION:
        raise JournalIntegrityError(f"unsupported journal version at line {line_number}: {version!r}")
    sequence = raw.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence != expected_sequence:
        raise JournalIntegrityError(
            f"invalid journal sequence at line {line_number}: expected {expected_sequence}, found {sequence!r}"
        )
    previous = raw.get("previous_digest")
    if previous != expected_previous:
        raise JournalIntegrityError(f"broken journal hash chain at line {line_number}")
    timestamp = raw.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp:
        raise JournalIntegrityError(f"missing journal timestamp at line {line_number}")
    digest = raw.get("digest")
    if not isinstance(digest, str) or not digest:
        raise JournalIntegrityError(f"missing journal digest at line {line_number}")
    try:
        event = Event.from_record(raw.get("event"))
    except ValueError as exc:
        raise JournalIntegrityError(f"invalid journal event at line {line_number}: {exc}") from exc
    body = {
        "version": version,
        "sequence": sequence,
        "previous_digest": previous,
        "timestamp": timestamp,
        "event": event.to_record(),
    }
    if record_digest(body) != digest:
        raise JournalIntegrityError(f"journal record digest mismatch at line {line_number}")
    extra = set(raw) - set(body) - {"digest"}
    if extra:
        raise JournalIntegrityError(f"unexpected journal fields at line {line_number}: {sorted(extra)}")
    return JournalRecord(version, sequence, previous, timestamp, event, digest)


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- reading -----------------------------------------------------------

    def records(self) -> list[JournalRecord]:
        """Read and validate the full hash chain. Fails closed on corruption."""
        if not self.path.exists():
            return []
        records: list[JournalRecord] = []
        previous = GENESIS_DIGEST
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.endswith("\n"):
                    raise JournalIntegrityError(f"truncated journal record at line {line_number}")
                stripped = line.strip()
                if not stripped:
                    raise JournalIntegrityError(f"blank journal line at line {line_number}")
                raw = _parse_record(stripped, line_number)
                record = _validate_record(raw, len(records) + 1, previous, line_number)
                records.append(record)
                previous = record.digest
        return records

    def events(self) -> list[Event]:
        return [record.event for record in self.records()]

    def read(self) -> list[dict[str, Any]]:
        return [record.to_record() for record in self.records()]

    def verify(self) -> bool:
        try:
            self.records()
        except JournalIntegrityError:
            return False
        return True

    # -- writing -----------------------------------------------------------

    def append(self, event: Event) -> JournalRecord:
        existing = self.records()  # refuses to append after corruption
        sequence = len(existing) + 1
        previous = existing[-1].digest if existing else GENESIS_DIGEST
        body = {
            "version": JOURNAL_VERSION,
            "sequence": sequence,
            "previous_digest": previous,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event.to_record(),
        }
        record = JournalRecord(
            JOURNAL_VERSION, sequence, previous, body["timestamp"], event, record_digest(body)
        )
        line = canonical_json(record.to_record()).decode("utf-8") + "\n"
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
        return record

    def extend(self, events: Iterable[Event]) -> None:
        for event in events:
            self.append(event)
