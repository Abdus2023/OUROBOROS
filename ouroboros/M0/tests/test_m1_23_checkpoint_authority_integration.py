"""M1.23 — checkpoint authority must share the authoritative replay path."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ourob.authoritative_recovery import AuthoritativeRecoveryError, recovery_quorum_lifecycle_event
from ourob.checkpoint_authority import CheckpointAuthorityState, classify_checkpoint
from ourob.checkpoint_recovery import CheckpointRecoveryError, recover_current_checkpoint
from ourob.checkpoint_store import publish_checkpoint
from ourob.emergency_recovery import EmergencyRecoveryAuthority
from ourob.journal import Journal
from ourob.model import Event
from ourob.recovery_of_recovery import RecoveryOfRecoveryAuthority
from ourob.recovery_of_recovery_lifecycle import RecoveryOfRecoveryOperation, sign_lifecycle_statement
from ourob.signed_trust import TrustStore
from ourob.trust_boundary import ExternalTrustAuthority
from ourob.trust_checkpoint import issue_current_checkpoint

GENERATION = "a" * 64


def _fixture(tmp_path: Path):
    journal = Journal(tmp_path / "journal.jsonl")
    trust_private = Ed25519PrivateKey.generate()
    store = TrustStore.genesis("trust-0", trust_private.public_key())
    recovery_private = Ed25519PrivateKey.generate()
    recovery = EmergencyRecoveryAuthority.from_public_key("recovery-0", recovery_private.public_key())
    quorum_private = [Ed25519PrivateKey.generate() for _ in range(3)]
    quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"q{i}": key.public_key() for i, key in enumerate(quorum_private)}, 2
    )
    journal.append(Event("OBSERVATION"))
    return journal, store, trust_private, recovery, quorum, quorum_private


def _quorum_rotation(journal: Journal, quorum: RecoveryOfRecoveryAuthority, quorum_private):
    replacement = Ed25519PrivateKey.generate()
    statement = sign_lifecycle_statement(
        [("q0", quorum_private[0]), ("q1", quorum_private[1])],
        quorum,
        RecoveryOfRecoveryOperation.ROTATE_SIGNER,
        target_key_id="q1",
        replacement_key_id="q3",
        replacement_public_key=replacement.public_key().public_bytes_raw(),
        reason="replace quorum signer",
    )
    journal.append(recovery_quorum_lifecycle_event(statement))
    current_quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {
            "q0": quorum_private[0].public_key(),
            "q2": quorum_private[2].public_key(),
            "q3": replacement.public_key(),
        },
        2,
        epoch=1,
    )
    return current_quorum


def test_quorum_lifecycle_requires_external_quorum_for_checkpoint_classification(tmp_path: Path):
    journal, store, trust_private, recovery, quorum, quorum_private = _fixture(tmp_path)
    _quorum_rotation(journal, quorum, quorum_private)
    checkpoint = issue_current_checkpoint(journal, store, trust_private, "trust-0", generation=GENERATION)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)

    with_quorum = ExternalTrustAuthority(store, checkpoint, recovery, quorum)
    assert classify_checkpoint(journal, with_quorum, target, generation=GENERATION) is CheckpointAuthorityState.CURRENT

    without_quorum = ExternalTrustAuthority(store, checkpoint, recovery)
    assert classify_checkpoint(journal, without_quorum, target, generation=GENERATION) is CheckpointAuthorityState.INVALID


def test_checkpoint_recovery_cannot_bypass_quorum_history(tmp_path: Path):
    journal, store, trust_private, recovery, quorum, quorum_private = _fixture(tmp_path)
    _quorum_rotation(journal, quorum, quorum_private)
    checkpoint = issue_current_checkpoint(journal, store, trust_private, "trust-0", generation=GENERATION)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)

    with pytest.raises(CheckpointRecoveryError, match="no current checkpoint authenticated"):
        recover_current_checkpoint(
            (target,), journal, store, generation=GENERATION, recovery=recovery
        )

    recovered, path = recover_current_checkpoint(
        (target,), journal, store, generation=GENERATION,
        recovery=recovery, recovery_quorum=quorum,
    )
    assert recovered == checkpoint
    assert path == target


def test_checkpoint_authority_does_not_accept_malformed_quorum_history(tmp_path: Path):
    journal, store, trust_private, recovery, quorum, quorum_private = _fixture(tmp_path)
    _quorum_rotation(journal, quorum, quorum_private)
    checkpoint = issue_current_checkpoint(journal, store, trust_private, "trust-0", generation=GENERATION)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)

    # Supplying a different genesis quorum cannot replace the externally
    # provisioned root used to authenticate the journal's lifecycle history.
    rogue_private = [Ed25519PrivateKey.generate() for _ in range(3)]
    rogue_quorum = RecoveryOfRecoveryAuthority.from_public_keys(
        {f"q{i}": key.public_key() for i, key in enumerate(rogue_private)}, 2
    )
    authority = ExternalTrustAuthority(store, checkpoint, recovery, rogue_quorum)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.INVALID


def test_authoritative_replay_error_is_not_downgraded_to_stale(tmp_path: Path):
    journal, store, trust_private, recovery, quorum, quorum_private = _fixture(tmp_path)
    _quorum_rotation(journal, quorum, quorum_private)
    checkpoint = issue_current_checkpoint(journal, store, trust_private, "trust-0", generation=GENERATION)
    target = tmp_path / "checkpoint.json"
    publish_checkpoint(checkpoint, target)

    # The public classification surface must fail closed as INVALID when its
    # authority history cannot be reconstructed; it must not call such history STALE.
    authority = ExternalTrustAuthority(store, checkpoint, recovery)
    assert classify_checkpoint(journal, authority, target, generation=GENERATION) is CheckpointAuthorityState.INVALID
