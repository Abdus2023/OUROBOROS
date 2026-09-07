# OUROBOROS

Repository-native autonomous engineering runtime.

The repository is simultaneously the runtime source, capability registry, policy/constitution, state journal, verification system, and bootstrap image — and the runtime can engineer this repository without ever being able to declare its own changes valid.

## Layout

```
ouroboros/M0/ourob/      implementation (kernel, policy, skills, verify, evidence, promotion, bootstrap, recovery, trust, signed_trust, trust_lifecycle, planner, cli)
ouroboros/M0/tests/      conformance suite (M1.7 adds authenticated lifecycle coverage)
policies/constitution.json   normative policy data (interpreter lives in ourob/policy.py)
verification/gates.json      declared verification contract
skills/manifest.json         repository-declared capabilities
.ourob/journal.jsonl         hash-chained append-only journal (runtime state, git-ignored)
docs/                        design log
```

## M0 lifecycle

`INTAKE → PLANNED → AUTHORIZED → EXECUTING → OBSERVED → VERIFYING → VERIFIED → PROMOTABLE → PROMOTED`

- Every repository mutation passes through `Kernel.execute()`, is policy-evaluated, observed and journaled.
- Kernel / bootstrap / policy / verifier surfaces are denied on the ordinary mutation path.
- Each mutation advances the repository generation and verification epoch, invalidating prior evidence.
- `VerificationEvidence` binds run, generation, epoch, the canonical gate contract and every gate result under one digest.
- `PromotionAuthority` accepts only integrity-checked, complete, current evidence.
- Cold `Bootstrap` reconstructs capabilities strictly from `skills/manifest.json` and reports `trusted` only if the generation is unchanged across reconstruction.
- `recovery` replays the journal through the fail-closed state machine: no durable event → no recovered authority.
- Journal appends are serialized under `flock` and `fsync`'d before the lock is released (M1.4).
- `Journal.read_trusted(anchor)` validates the chain against an anchor held **outside** the journal (M1.5); `read_signed_trusted(checkpoint, store)` additionally requires an Ed25519 signature from an externally provisioned trust store with ACTIVE/RETIRED/REVOKED key states and trust-epoch binding (M1.6).
- `trust_lifecycle` adds M1.7 signed rotation/revocation statements. A trust-store transition is accepted only when the current ACTIVE key authorizes the exact epoch transition and target; private signing keys remain outside the repository.
- Hash-chain integrity, signature authenticity, and trust-state authorization are separate gates; passing one does not imply the others.

## M1.7 trust lifecycle

The trust store is **not** its own root of trust. A lifecycle mutation must carry an authorization signed by the current ACTIVE key:

```text
current ACTIVE key
       │
       │ signed TrustTransition
       ▼
verify signer + current epoch + operation invariants
       │
       ▼
apply exactly one authenticated transition
       │
       ├── ROTATE → epoch + 1, old key RETIRED, fresh key ACTIVE
       └── REVOKE → same epoch, target key REVOKED
```

A rotation statement is bound to the current epoch, next epoch, fresh key id and complete public-key material. A revocation statement is bound to the current epoch and a non-active target. Statements are immutable and replay-resistant through signer-state and epoch checks.

The runtime never generates or persists private trust keys. The external authority signs statements; OUROBOROS verifies them using its provisioned public trust state.

## Quick start

```bash
cd ouroboros/M0 && python -m pytest -q          # conformance suite
export PYTHONPATH=ouroboros/M0                  # or: pip install -e ouroboros/M0
python -m ourob bootstrap                       # cold-start and report trust
python -m ourob generation                      # current repository generation
python -m ourob run --run-id r1 --task "Add a greet capability" --add-capability greet
python -m ourob skills --call greet --arguments '{"name":"World"}'   # → Hello, World!
python -m ourob journal --verify
python -m ourob journal --anchor > /secure/anchor.json      # store OUTSIDE the repository
python -m ourob recover --run r1                            # chain-integrity only
python -m ourob recover --run r1 --anchor /secure/anchor.json
python -m ourob recover --run r1 --checkpoint cp.json --trust-store store.json   # signed
```

`python -m ourob run` drives a plan through the full lifecycle and exits non-zero unless the run reaches `PROMOTED`. Plans targeting protected surfaces end in `BLOCKED` and the file is never written.

## Status

M0 (deterministic self-hosting kernel), M1.1–M1.6 (durable, tamper-evident, externally anchored, signature-authenticated recovery), and the M1.7 authenticated trust lifecycle foundation are implemented. Requires `cryptography` for M1.6/M1.7. M1.7 deliberately keeps trust-root provisioning outside repository-controlled state; the next hardening slice is integration of signed lifecycle statements with durable trust-state provisioning/recovery and current-vs-historical audit separation. See `docs/OUROBOROS_DESIGN_LOG.md` for the invariant list.
