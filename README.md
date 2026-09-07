# OUROBOROS

Repository-native autonomous engineering runtime.

The repository is simultaneously the runtime source, capability registry, policy/constitution, state model, verification system, and bootstrap image.

## M0 lifecycle

`INTAKE → PLANNED → AUTHORIZED → EXECUTING → OBSERVED → VERIFYING → VERIFIED → PROMOTABLE → PROMOTED`

Core invariant: every repository mutation passes through the kernel, is policy evaluated, observed, journaled, and invalidates prior verification by advancing repository generation.

M0 focuses on deterministic self-extension before introducing optional LLM planning.
