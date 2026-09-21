# Changelog

## 0.4.0.0 - 2026-09-21

- Route supported `gfx` targets through an exact-match registry so RDNA 3.5,
  RDNA 4, and CDNA 5 proposal guidance can be loaded without treating
  `gfx1250` as RDNA 4.
- Bind the architecture registry, selected knowledge card, declared ROCm
  component versions, and observed tool identities into capability and
  preflight reports.
- Keep unknown targets on the generic measured playbook and make architecture
  knowledge proposal-only; native load, correctness, benchmark, and promotion
  gates remain authoritative.
- Add compact architecture cards, component-capture guidance, and regression
  tests for exact routing, content hashes, and safe fallback behavior.

## 0.3.0.0 - 2026-09-18

- Add schema-v2 `optimization_surface` contracts while preserving schema-v1
  evidence without inferring a stronger historical claim.
- Add fail-closed AMDGCN source-assembly controller gates for fresh compilation,
  real code-object kinds, non-empty in-window instruction diffs, ABI/resources,
  native loading, parent profiles, and post-benchmark candidate profiles.
- Add generic capability probing, assembly/link, normalized disassembly,
  instruction diff, resource scan, and profile-evidence tools and schemas.
- Re-profile only performance-qualified ASM candidates; a missing or failed fresh
  profile blocks promotion.
- Keep fixed launchers, operator contracts, workload/reference harnesses, public
  API acceptance, and private machine data in the consuming project rather than
  the reusable skill.
- Add controller-v2 lineage verification and unit coverage while keeping
  controller-v1 evidence readable.

## 0.2.0.0 - 2026-09-17

- Add a controller-owned baseline and candidate state machine that directly
  invokes frozen project adapters and prevents benchmark invocation before a
  correctness receipt exists.
- Bind contracts, preflight and environment declarations, proposals, K0, parents,
  candidates, adapter executables, requests, responses, logs, and raw timing
  samples into controller receipts with phase-boundary drift checks.
- Enforce wall-clock and per-stream output limits, persistently revalidate adapter
  outputs, and make fixed-input gate decisions byte-for-byte deterministic.
- Require binary-mode oracle execution to use only frozen K0; candidate execution
  belongs to replay and is compared against K0 observations.
- Distinguish controller-bound lineage from the legacy public gate and lineage
  interfaces, and document the process-binding, Python-token, environment, and
  same-user threat-model boundaries.
- Add controller failure classification and end-to-end controller tests.
- Introduce the strict `asmevo.adapter.v1` request/response ABI. Version 0.1
  preflight and lineage evidence remains legacy and must be re-created rather
  than upgraded in place for a controller-bound run.

## 0.1.0.0 - 2026-09-17

- Extract the AsmEvo optimization workflow into a reusable Codex skill.
- Add deterministic preflight, candidate-gating, and verified-lineage helpers.
- Bind ready preflight reports, workload contracts, environment manifests, and
  artifact identities; force binary static checks and serialize concurrent
  lineage updates.
- Document source, binary, and audit modes with explicit trust boundaries.
- Add unit tests and continuous validation.
