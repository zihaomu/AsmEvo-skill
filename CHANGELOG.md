# Changelog

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
