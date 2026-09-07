# OUROBOROS CI

## Status

OUROBOROS now has a repository-native GitHub Actions workflow at `.github/workflows/ci.yml`.

The workflow is intentionally **read-only** with respect to the repository: its GitHub token has `contents: read` permission and the workflow contains no repository mutation or deployment step.

## Required gates

The CI mirrors the normative gates declared in `verification/gates.json`:

1. `compileall` — compile the repository Python tree.
2. `bootstrap` — cold-start the runtime against the checked-out repository.
3. `tests` — run the complete M0 conformance suite.

The source-of-truth gate contract currently declares these three gates as required.

## Jobs

### Compile / Import

Runs on Python 3.13 and verifies that the runtime compiles and its core modules import successfully.

### Full Conformance Tests

Runs the complete `ouroboros/M0/tests` suite with pytest 9.x and publishes the test log as a short-retention CI artifact.

### Trust / Checkpoint / Recovery Conformance

Runs the security-sensitive conformance slice selected by `trust`, `checkpoint`, or `recovery`. This is deliberately separate from the full suite so that trust-boundary regressions are visible as a dedicated CI job.

### Verification Gates

Runs only after both conformance jobs succeed. It executes the three required gates again in their normative order and emits a machine-readable `ourob.ci-verification.v1` record containing the exact commit and Python version.

## Fail-closed properties

- A failed compile gate fails the workflow.
- A failed bootstrap gate fails the workflow.
- A failed test gate fails the workflow.
- The security-sensitive conformance job is independently required.
- The final verification-gates job depends on both conformance jobs.
- CI does not create trust roots, sign checkpoints, modify the journal, or promote repository state.
- CI artifacts are evidence of the CI execution; they are not an OUROBOROS trust root.

## Reproducibility

The workflow fixes the runtime to Python 3.13, uses deterministic environment settings (`PYTHONHASHSEED=0`, UTC), disables pytest's cache provider, and records the exact Git commit SHA.

The project itself currently requires Python >=3.11 and declares `cryptography>=41` plus an optional pytest test dependency. CI additionally constrains pytest to the 9.x series.

## Supply-chain boundary

The workflow uses the standard GitHub-maintained checkout, Python setup, and artifact actions. Action references are currently major-version references (`@v4` / `@v5`), not immutable commit pins. Immutable SHA pinning is a separate supply-chain-hardening task and is intentionally not conflated with test correctness.

## What CI does not prove

A green CI run does **not** by itself establish external trust authority. In particular, CI cannot manufacture the external genesis trust store, the emergency recovery root, or the recovery-of-recovery quorum. Those remain outside repository control by design.

Likewise, a CI artifact must not be treated as a current signed checkpoint unless it independently satisfies the OUROBOROS checkpoint and external-trust contracts.
