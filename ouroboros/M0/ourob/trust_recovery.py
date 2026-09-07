"""M1.7/M1.8/M1.20/M1.21 authenticated trust-state recovery and authorization."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .emergency_recovery import (
    EmergencyRecoveryAuthority,
    EmergencyRecoveryStatement,
    RecoveryRootTransition,
    apply_emergency_recovery,
    apply_recovery_root_rotation,
    verify_emergency_recovery,
    verify_recovery_root_rotation,
)
from .journal import Journal, JournalIntegrityError, JournalRecord
from .model import Event, EventName
from .signed_trust import SignedTrustError, TrustStore
from .trust_lifecycle import TrustTransition, apply_transition, verify_transition


class TrustRecoveryError(RuntimeError):
    pass


def trust_transition_event(statement: TrustTransition) -> Event:
    return Event(EventName.TRUST_TRANSITION_AUTHORIZED.value, data={"transition": statement.to_record()})


def emergency_recovery_event(statement: EmergencyRecoveryStatement) -> Event:
    return Event(EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value, data={"recovery": statement.to_record()})


def recovery_root_rotation_event(statement: RecoveryRootTransition) -> Event:
    return Event(EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value, data={"transition": statement.to_record()})


def recover_recovery_authority(
    events: Iterable[Event],
    initial_authority: EmergencyRecoveryAuthority,
) -> EmergencyRecoveryAuthority:
    """Replay recovery-root lifecycle from an externally provisioned root."""
    authority = initial_authority
    seen: set[str] = set()
    for event in events:
        if event.name != EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value:
            continue
        if event.run_id is not None or event.action_id is not None or event.generation is not None:
            raise TrustRecoveryError("recovery-root transition event must not be run-scoped")
        try:
            statement = RecoveryRootTransition.from_record(event.data.get("transition"))
            if statement.binding_digest in seen:
                raise TrustRecoveryError("recovery-root transition replay detected")
            verify_recovery_root_rotation(statement, authority)
            authority = apply_recovery_root_rotation(statement, authority)
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
        seen.add(statement.binding_digest)
    return authority


def recover_trust_store(
    events: Iterable[Event],
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
) -> TrustStore:
    """Replay trust state using external genesis and the ordered recovery-root history."""
    event_list = tuple(events)
    store = TrustStore.from_record(initial_store.to_record())
    recovery = recovery_authority
    seen_bindings: set[str] = set()
    seen_recovery_roots: set[str] = set()
    for event in event_list:
        if event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("recovery-root transition event must not be run-scoped")
            if recovery is None:
                raise TrustRecoveryError("recovery-root history requires an externally provisioned recovery authority")
            try:
                statement = RecoveryRootTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen_recovery_roots:
                    raise TrustRecoveryError("recovery-root transition replay detected")
                recovery = apply_recovery_root_rotation(statement, recovery)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
            seen_recovery_roots.add(statement.binding_digest)
        elif event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("trust transition event must not be run-scoped")
            try:
                statement = TrustTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen_bindings:
                    raise TrustRecoveryError("trust transition replay detected")
                apply_transition(statement, store)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
            seen_bindings.add(statement.binding_digest)
        elif event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("emergency recovery event must not be run-scoped")
            if recovery is None:
                raise TrustRecoveryError("emergency recovery requires an externally provisioned recovery authority")
            try:
                statement = EmergencyRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen_bindings:
                    raise TrustRecoveryError("emergency recovery replay detected")
                apply_emergency_recovery(statement, store, recovery)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc
            seen_bindings.add(statement.binding_digest)
    return store


def recover_trust_store_from_journal(journal_path: Path, initial_store: TrustStore, recovery_authority: EmergencyRecoveryAuthority | None = None) -> TrustStore:
    try:
        events = Journal(journal_path).events()
    except JournalIntegrityError as exc:
        raise TrustRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_trust_store(events, initial_store, recovery_authority)


def append_authorized_transition(journal: Journal, statement: TrustTransition, initial_store: TrustStore) -> JournalRecord:
    event = trust_transition_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store)
            verify_transition(statement, current)
            if any(record.event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value and record.event.data.get("transition") == statement.to_record() for record in existing):
                raise TrustRecoveryError("trust transition replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
    return journal.append_checked(event, validate)


def append_authorized_emergency_recovery(journal: Journal, statement: EmergencyRecoveryStatement, initial_store: TrustStore, recovery_authority: EmergencyRecoveryAuthority) -> JournalRecord:
    event = emergency_recovery_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store, recovery_authority)
            current_recovery = recover_recovery_authority((record.event for record in existing), recovery_authority)
            verify_emergency_recovery(statement, current, current_recovery)
            if any(record.event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value and record.event.data.get("recovery") == statement.to_record() for record in existing):
                raise TrustRecoveryError("emergency recovery replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc
    return journal.append_checked(event, validate)


def append_authorized_recovery_root_rotation(journal: Journal, statement: RecoveryRootTransition, recovery_authority: EmergencyRecoveryAuthority) -> JournalRecord:
    """Atomically authorize recovery-root rotation against the current journal."""
    event = recovery_root_rotation_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_recovery_authority((record.event for record in existing), recovery_authority)
            verify_recovery_root_rotation(statement, current)
            if any(record.event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value and record.event.data.get("transition") == statement.to_record() for record in existing):
                raise TrustRecoveryError("recovery-root transition replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
    return journal.append_checked(event, validate)
