# OUROBOROS

Deterministic self-hosting autonomous engineering runtime.

The repository is simultaneously the runtime source, capability registry, policy/constitution, durable state journal, verification system, and bootstrap image.

## Layout

```text
ouroboros/M0/ourob/      implementation (kernel, policy, skills, verify, evidence, promotion, bootstrap, recovery, trust, signed_trust, trust_lifecycle, trust_recovery, trust_boundary, planner, cli)
ouroboros/M0/tests/      conformance suite
policies/constitution.json   normative policy data (interpreter lives in ourob/policy.py)
verification/gates.json      declared verification contract
skills/manifest.json         repository-declared capabilities
docs/                        design log
```

## Core invariants

- The planner proposes; it never mutates the repository and has no promotion authority.
- The kernel is the sole mutation gateway and evaluates policy before mutation.
- Verification produces immutable evidence bound to run, generation, epoch, gate identity and gate configuration.
- Promotion consumes the exact evidence object and rejects stale, incomplete, tampered or contract-mismatched evidence.
- Cold `Bootstrap` reconstructs capabilities strictly from `skills/manifest.json` and reports `trusted` only if the generation is unchanged across reconstruction.
- Authoritative cold bootstrap additionally requires an **externally provisioned** public trust store and a **generation-bound signed checkpoint over the current journal head**. Repository state alone cannot become its own root of trust.
- `recovery` replays the journal through the fail-closed state machine: no durable event → no recovered authority.
- Journal appends are serialized under `flock` and `fsync`'d before the lock is released (M1.4).
- `Journal.read_trusted(anchor)` validates the chain against an anchor held **outside** the journal (M1.5); `read_signed_trusted(checkpoint, store)` additionally requires an Ed25519 signature from an externally provisioned trust store with ACTIVE/RETIRED/REVOKED key states and trust-epoch binding (M1.6).
- `trust_lifecycle` adds M1.7 signed rotation/revocation statements. A trust-store transition is accepted only when the current ACTIVE key authorizes the exact epoch transition and target; private signing keys remain outside the repository.
- `trust_recovery` reconstructs trust-state evolution from a separately provisioned genesis trust store and durable signed lifecycle events. The repository cannot select its own trust root or trust epoch.
- M1.8 `append_authorized_transition()` reconstructs current trust state and verifies the next transition **while holding the journal append lock**, preventing concurrent check-then-append races from creating conflicting trust epochs.
- M1.9 `trust_boundary.authenticate_current_repository()` authenticates the external root, replays durable trust transitions, verifies the signed checkpoint, and requires exact current journal-head and repository-generation binding. Older checkpoints remain historical-audit material and cannot authorize current bootstrap.
- Hash-chain integrity, signature authenticity, trust-state authorization, and current-generation binding are separate gates; passing one does not imply the others.

## M1.9 authoritative cold bootstrap

Current authority is deliberately a two-world protocol:

```text
EXTERNAL AUTHORITY                         REPOSITORY
(private keys never here)                 (untrusted until authenticated)
        │                                      │
        ├── genesis TrustStore ────────────────┤
        │                                      │
        └── signed checkpoint ────────────────►│
                                               │
                                      validate journal chain
                                               │
                                      replay signed transitions
                                               │
                                      verify checkpoint signature
                                               │
                                      require current head
                                               │
                                      require current generation
                                               │
                                               ▼
                                      AUTHORITATIVE BOOTSTRAP
```

A checkpoint over an older journal prefix is still useful for explicit historical audit, but it cannot satisfy the current bootstrap boundary. A generation-less checkpoint is also rejected for current authority. The bootstrap path therefore cannot silently downgrade from authenticated authority to repository-derived trust.

CLI examples:

```bash
# Diagnostic/content bootstrap; no external authority supplied.
python -m ourob bootstrap

# Authoritative cold bootstrap.
python -m ourob bootstrap \
  --trust-checkpoint /secure/ourob/current-checkpoint.json \
  --trust-store /secure/ourob/genesis-trust-store.json

# Engineering execution requires the same authoritative boundary.
python -m ourob run --run-id r1 --task "..." --plan plan.json \
  --trust-checkpoint /secure/ourob/current-checkpoint.json \
  --trust-store /secure/ourob/genesis-trust-store.json
```

The external files are inputs, not repository state. OUROBOROS never writes private trust material and never treats a repository-stored checkpoint or trust store as authoritative merely because it is present.

## M1.7/M1.8 trust lifecycle and recovery

The trust store is **not** its own root of trust. A lifecycle mutation must carry an authorization signed by the current ACTIVE key:

```text
external ACTIVE key
       │
       │ signed TrustTransition
       ▼
verify signer + current epoch + operation invariants
       │
       ▼
append_checked() under journal lock
       │
       ▼
durable TRUST_TRANSITION_AUTHORIZED event
       │
       ▼
replay from externally provisioned genesis store
       │
       ├── ROTATE → epoch + 1, old key RETIRED, fresh key ACTIVE
       └── REVOKE → same epoch, target key REVOKED
```

`recover_trust_store(events, initial_store)` treats `initial_store` as an external root and applies only authenticated lifecycle statements. It refuses run-scoped trust-transition events, duplicate statements, invalid signatures, stale/future epochs, and transitions inconsistent with the current authoritative key state.

`append_authorized_transition(journal, statement, initial_store)` is the durable authorization boundary: it validates the complete existing chain, reconstructs the current trust state from the external root, verifies the proposed signed transition, and only then performs the durable append. A failed validation produces no new record.

Current run recovery and historical audit remain distinct: retired keys may be used only by explicit signed-checkpoint historical verification, and revoked keys never authenticate historical checkpoints.

The runtime never generates or persists private trust keys. The external authority signs checkpoints and lifecycle statements; OUROBOROS verifies them using provisioned public trust state.

## Quick start

```bash
cd ouroboros/M0
python -m pytest -q
python -m ourob --help
python -m ourob bootstrap
python -m ourob journal --anchor
python -m ourob recover --run r1 --checkpoint cp.json --trust-store store.json
```

## Status

M0 (deterministic self-hosting kernel), M1.1–M1.6 (durable, tamper-evident, externally anchored, signature-authenticated recovery), M1.7/M1.8 (authenticated lifecycle, durable trust-state replay, and atomic trust-transition authorization), and M1.9 (authoritative cold-start/current-generation trust boundary) are implemented at source level. Requires `cryptography` for signed trust. Execution/CI evidence must be established by the repository's declared verification gates before a release is considered verified. No test/CI result is claimed here without execution evidence. See `docs/OUROBOROS_DESIGN_LOG.md` for the invariant list and next hardening slices.
