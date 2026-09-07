"""M1.20 — external emergency recovery conformance."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.checkpoint_authority import CheckpointAuthorityError, CheckpointAuthorityState, classify_checkpoint, require_current_checkpoint
from ourob.checkpoint_store import publish_checkpoint
from ourob.emergency_recovery import EmergencyRecoveryAuthority, EmergencyRecoveryStatement, sign_emergency_recovery
from ourob.journal import Journal
from ourob.model import Event, EventName
from ourob.signed_trust import KeyState, TrustStore
from ourob.trust_boundary import ExternalTrustAuthority, TrustBoundaryError, authenticate_current_repository
from ourob.trust_checkpoint import issue_current_checkpoint
from ourob.trust_recovery import TrustRecoveryError, append_authorized_emergency_recovery, recover_trust_store

GENERATION = "b" * 64


def _fixture(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    active_private = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("k0", active_private.public_key())
    journal.append(Event("OBSERVATION"))
    recovery_private = Ed25519PrivateKey.generate()
    recovery = EmergencyRecoveryAuthority.from_public_key("emergency-root", recovery_private.public_key())
    checkpoint = issue_current_checkpoint(journal, store, active_private, "k0", generation=GENERATION)
    return journal, store, active_private, recovery_private, recovery, checkpoint


def test_emergency_recovery_replaces_active_and_revokes_compromised_key(tmp_path: Path):
    journal, store, _, recovery_private, recovery, _ = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="active-key-compromise")
    append_authorized_emergency_recovery(journal, statement, store, recovery)
    recovered = recover_trust_store((r.event for r in journal.records()), store, recovery)
    assert recovered.epoch == 1
    assert recovered.keys["k0"].state is KeyState.REVOKED
    assert recovered.active.key_id == "k1"


def test_cached_checkpoint_becomes_revoked_after_emergency_recovery(tmp_path: Path):
    journal, store, _, recovery_private, recovery, checkpoint = _fixture(tmp_path)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="compromise")
    append_authorized_emergency_recovery(journal, statement, store, recovery)
    authority = ExternalTrustAuthority(store, checkpoint, recovery)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.REVOKED
    with pytest.raises(CheckpointAuthorityError, match="REVOKED"):
        require_current_checkpoint(journal, authority, target, generation=GENERATION)


def test_reissued_checkpoint_by_replacement_key_is_current(tmp_path: Path):
    journal, store, _, recovery_private, recovery, old_checkpoint = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="compromise")
    append_authorized_emergency_recovery(journal, statement, store, recovery)
    checkpoint = issue_current_checkpoint(journal, store, replacement, "k1", generation=GENERATION, recovery_authority=recovery)
    authority = ExternalTrustAuthority(store, checkpoint, recovery)
    target = tmp_path / "current.json"
    publish_checkpoint(checkpoint, target)
    assert old_checkpoint.binding_digest != checkpoint.binding_digest
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.CURRENT


def test_missing_recovery_root_fails_closed(tmp_path: Path):
    journal, store, _, recovery_private, recovery, checkpoint = _fixture(tmp_path)
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", Ed25519PrivateKey.generate().public_key().public_bytes_raw(), reason="compromise")
    append_authorized_emergency_recovery(journal, statement, store, recovery)
    with pytest.raises(TrustBoundaryError):
        authenticate_current_repository(journal, ExternalTrustAuthority(store, checkpoint), generation=GENERATION)
    with pytest.raises(TrustRecoveryError, match="externally provisioned recovery authority"):
        recover_trust_store((r.event for r in journal.records()), store)


def test_forged_recovery_statement_is_rejected(tmp_path: Path):
    journal, store, _, _, recovery, _ = _fixture(tmp_path)
    forged_private = Ed25519PrivateKey.generate()
    forged_authority = EmergencyRecoveryAuthority.from_public_key("forged", forged_private.public_key())
    statement = sign_emergency_recovery(forged_private, forged_authority, store, "k1", Ed25519PrivateKey.generate().public_key().public_bytes_raw(), reason="forged")
    with pytest.raises(TrustRecoveryError):
        append_authorized_emergency_recovery(journal, statement, store, recovery)


def test_wrong_expected_active_key_is_rejected(tmp_path: Path):
    journal, store, _, recovery_private, recovery, _ = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    valid = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="compromise")
    forged = EmergencyRecoveryStatement(valid.recovery_key_id, "wrong-active", valid.from_epoch, valid.to_epoch, valid.replacement_key_id, valid.replacement_public_key, valid.reason, valid.signature, valid.algorithm)
    with pytest.raises(TrustRecoveryError):
        append_authorized_emergency_recovery(journal, forged, store, recovery)


def test_replay_and_replacement_key_reuse_are_rejected(tmp_path: Path):
    journal, store, _, recovery_private, recovery, _ = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="compromise")
    append_authorized_emergency_recovery(journal, statement, store, recovery)
    with pytest.raises(TrustRecoveryError):
        append_authorized_emergency_recovery(journal, statement, store, recovery)
    current = recover_trust_store((r.event for r in journal.records()), store, recovery)
    next_statement = sign_emergency_recovery(recovery_private, recovery, current, "k1", replacement.public_key().public_bytes_raw(), reason="reuse")
    events = [r.event for r in journal.records()]
    events.append(Event(EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value, data={"recovery": next_statement.to_record()}))
    with pytest.raises(TrustRecoveryError):
        recover_trust_store(events, store, recovery)


def test_recovery_event_cannot_be_run_scoped(tmp_path: Path):
    _, store, _, recovery_private, recovery, _ = _fixture(tmp_path)
    replacement = Ed25519PrivateKey.generate()
    statement = sign_emergency_recovery(recovery_private, recovery, store, "k1", replacement.public_key().public_bytes_raw(), reason="compromise")
    bad = Event(EventName.TRUST_EMERGENCY_RECOVERY_AUTHORIZED.value, run_id="r1", data={"recovery": statement.to_record()})
    with pytest.raises(TrustRecoveryError, match="must not be run-scoped"):
        recover_trust_store([bad], store, recovery)
