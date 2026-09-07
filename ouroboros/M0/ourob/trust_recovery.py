"""M1.7/M1.8/M1.20/M1.21/M1.22 authenticated trust-state recovery and authorization."""
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
from .recovery_of_recovery import (
    RecoveryOfRecoveryAuthority,
    RecoveryOfRecoveryStatement,
    apply_recovery_of_recovery,
    verify_recovery_of_recovery,
)
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


def recovery_of_recovery_event(statement: RecoveryOfRecoveryStatement) -> Event:
    return Event(EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value, data={"recovery": statement.to_record()})


def recover_recovery_authority(
    events: Iterable[Event],
    initial_authority: EmergencyRecoveryAuthority,
    recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None,
) -> EmergencyRecoveryAuthority:
    """Replay recovery-root lifecycle strictly in journal order."""
    authority = initial_authority
    seen: set[str] = set()
    used_key_ids: set[str] = {authority.key_id}
    seen_break_glass: set[str] = set()
    for event in events:
        if event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("recovery-root transition event must not be run-scoped")
            try:
                statement = RecoveryRootTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen:
                    raise TrustRecoveryError("recovery-root transition replay detected")
                if statement.replacement_key_id in used_key_ids:
                    raise TrustRecoveryError("recovery-root replacement key id was already used")
                authority = apply_recovery_root_rotation(statement, authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
            seen.add(statement.binding_digest)
            used_key_ids.add(statement.replacement_key_id)
        elif event.name == EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("recovery-of-recovery event must not be run-scoped")
            if recovery_of_recovery_authority is None:
                raise TrustRecoveryError("recovery-of-recovery requires an externally provisioned quorum authority")
            try:
                statement = RecoveryOfRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen_break_glass:
                    raise TrustRecoveryError("recovery-of-recovery replay detected")
                if statement.replacement_key_id in used_key_ids:
                    raise TrustRecoveryError("recovery-of-recovery replacement key id was already used")
                authority = apply_recovery_of_recovery(statement, recovery_of_recovery_authority, authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated recovery-of-recovery statement: {exc}") from exc
            seen_break_glass.add(statement.binding_digest)
            used_key_ids.add(statement.replacement_key_id)
    return authority


def recover_trust_store(
    events: Iterable[Event],
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
    recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None,
) -> TrustStore:
    """Replay trust and recovery state as one ordered state machine.

    Recovery-root changes are interleaved with trust mutations. An emergency
    recovery event is authorized by the recovery root current at that exact
    journal position; a later root replacement is never retroactive.
    """
    store = TrustStore.from_record(initial_store.to_record())
    authority = recovery_authority
    event_list = tuple(events)
    seen_trust_bindings: set[str] = set()
    seen_recovery_bindings: set[str] = set()
    seen_break_glass: set[str] = set()
    used_recovery_key_ids: set[str] = {authority.key_id} if authority is not None else set()

    for event in event_list:
        if event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value:
            if authority is None:
                raise TrustRecoveryError("recovery-root history requires an externally provisioned recovery authority")
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("recovery-root transition event must not be run-scoped")
            try:
                statement = RecoveryRootTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen_recovery_bindings:
                    raise TrustRecoveryError("recovery-root transition replay detected")
                if statement.replacement_key_id in used_recovery_key_ids:
                    raise TrustRecoveryError("recovery-root replacement key id was already used")
                authority = apply_recovery_root_rotation(statement, authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
            seen_recovery_bindings.add(statement.binding_digest)
            used_recovery_key_ids.add(statement.replacement_key_id)

        elif event.name == EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value:
            if authority is None:
                raise TrustRecoveryError("recovery-of-recovery requires an externally provisioned recovery authority")
            if recovery_of_recovery_authority is None:
                raise TrustRecoveryError("recovery-of-recovery requires an externally provisioned quorum authority")
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("recovery-of-recovery event must not be run-scoped")
            try:
                statement = RecoveryOfRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen_break_glass:
                    raise TrustRecoveryError("recovery-of-recovery replay detected")
                if statement.replacement_key_id in used_recovery_key_ids:
                    raise TrustRecoveryError("recovery-of-recovery replacement key id was already used")
                authority = apply_recovery_of_recovery(statement, recovery_of_recovery_authority, authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated recovery-of-recovery statement: {exc}") from exc
            seen_break_glass.add(statement.binding_digest)
            used_recovery_key_ids.add(statement.replacement_key_id)

        elif event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("trust transition event must not be run-scoped")
            try:
                statement = TrustTransition.from_record(event.data.get("transition"))
                if statement.binding_digest in seen_trust_bindings:
                    raise TrustRecoveryError("trust transition replay detected")
                apply_transition(statement, store)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
            seen_trust_bindings.add(statement.binding_digest)

        elif event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value:
            if event.run_id is not None or event.action_id is not None or event.generation is not None:
                raise TrustRecoveryError("emergency recovery event must not be run-scoped")
            if authority is None:
                raise TrustRecoveryError("emergency recovery requires an externally provisioned recovery authority")
            try:
                statement = EmergencyRecoveryStatement.from_record(event.data.get("recovery"))
                if statement.binding_digest in seen_trust_bindings:
                    raise TrustRecoveryError("emergency recovery replay detected")
                apply_emergency_recovery(statement, store, authority)
            except (SignedTrustError, ValueError, TypeError) as exc:
                raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc
            seen_trust_bindings.add(statement.binding_digest)

    return store


def recover_trust_store_from_journal(
    journal_path: Path,
    initial_store: TrustStore,
    recovery_authority: EmergencyRecoveryAuthority | None = None,
    recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None,
) -> TrustStore:
    try:
        events = Journal(journal_path).events()
    except JournalIntegrityError as exc:
        raise TrustRecoveryError(f"journal integrity failure: {exc}") from exc
    return recover_trust_store(events, initial_store, recovery_authority, recovery_of_recovery_authority)


def append_authorized_transition(journal: Journal, statement: TrustTransition, initial_store: TrustStore, recovery_authority: EmergencyRecoveryAuthority | None = None, recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None) -> JournalRecord:
    event = trust_transition_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store, recovery_authority, recovery_of_recovery_authority)
            verify_transition(statement, current)
            if any(record.event.name == EventName.TRUST_TRANSITION_AUTHORIZED.value and record.event.data.get("transition") == statement.to_record() for record in existing):
                raise TrustRecoveryError("trust transition replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated trust transition: {exc}") from exc
    return journal.append_checked(event, validate)


def append_authorized_emergency_recovery(journal: Journal, statement: EmergencyRecoveryStatement, initial_store: TrustStore, recovery_authority: EmergencyRecoveryAuthority, recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None) -> JournalRecord:
    event = emergency_recovery_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_trust_store((record.event for record in existing), initial_store, recovery_authority, recovery_of_recovery_authority)
            current_recovery = recover_recovery_authority((record.event for record in existing), recovery_authority, recovery_of_recovery_authority)
            verify_emergency_recovery(statement, current, current_recovery)
            if any(record.event.name == EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value and record.event.data.get("recovery") == statement.to_record() for record in existing):
                raise TrustRecoveryError("emergency recovery replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated emergency recovery: {exc}") from exc
    return journal.append_checked(event, validate)


def append_authorized_recovery_root_rotation(journal: Journal, statement: RecoveryRootTransition, recovery_authority: EmergencyRecoveryAuthority, recovery_of_recovery_authority: RecoveryOfRecoveryAuthority | None = None) -> JournalRecord:
    """Atomically authorize recovery-root rotation against the current journal."""
    event = recovery_root_rotation_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_recovery_authority((record.event for record in existing), recovery_authority, recovery_of_recovery_authority)
            verify_recovery_root_rotation(statement, current)
            if any(record.event.name == EventName.RECOVERY_ROOT_ROTATION_AUTHORIZED.value and record.event.data.get("transition") == statement.to_record() for record in existing):
                raise TrustRecoveryError("recovery-root transition replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated recovery-root transition: {exc}") from exc
    return journal.append_checked(event, validate)


def append_authorized_recovery_of_recovery(
    journal: Journal,
    statement: RecoveryOfRecoveryStatement,
    recovery_authority: EmergencyRecoveryAuthority,
    recovery_of_recovery_authority: RecoveryOfRecoveryAuthority,
) -> JournalRecord:
    """Atomically authorize break-glass recovery-root replacement."""
    event = recovery_of_recovery_event(statement)
    def validate(existing: list[JournalRecord]) -> None:
        try:
            current = recover_recovery_authority((record.event for record in existing), recovery_authority, recovery_of_recovery_authority)
            verify_recovery_of_recovery(statement, recovery_of_recovery_authority, current)
            if any(record.event.name == EventName.RECOVERY_OF_RECOVERY_AUTHORIZED.value and record.event.data.get("recovery") == statement.to_record() for record in existing):
                raise TrustRecoveryError("recovery-of-recovery replay detected")
        except TrustRecoveryError:
            raise
        except (SignedTrustError, ValueError, TypeError) as exc:
            raise TrustRecoveryError(f"invalid authenticated recovery-of-recovery statement: {exc}") from exc
    return journal.append_checked(event, validate)
