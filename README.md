# OUROBOROS

Repository-native autonomous engineering runtime.

The repository is simultaneously the runtime source, capability registry, policy/constitution, state journal, verification system, and bootstrap image — and the runtime can engineer this repository without ever being able to declare its own changes valid.

## Layout

```
ouroboros/M0/ourob/      implementation (kernel, policy, skills, verify, evidence, promotion, bootstrap, recovery, trust, signed_trust, planner, cli)
ouroboros/M0/tests/      conformance suite (149 tests)
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
- `Journal.read_trusted(anchor)` validates the chain against an anchor held **outside** the journal (M1.5); `read_signed_trusted(checkpoint, store)` additionally requires an Ed25519 signature from an externally provisioned trust store with ACTIVE/RETIRED/REVOKED key states and trust-epoch binding (M1.6). Hash-chain integrity ≠ authenticity.

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

M0 (deterministic self-hosting kernel) and M1.1–M1.6 (durable, tamper-evident, externally anchored, signature-authenticated recovery) are implemented. Requires `cryptography` for M1.6. See `docs/OUROBOROS_DESIGN_LOG.md` for the invariant list and next slice (M1.7: authenticated rotation/revocation statements).
