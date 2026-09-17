---
name: asmevo
description: Apply or resume an AsmEvo-style correctness-gated optimization loop for AMDGCN assembly or compiled AMDGPU HSACO/code objects, using the original artifact as oracle when source is absent. Use when asked to run AsmEvo, optimize AMDGCN assembly or an AMDGPU code object, or verify measured AMD-kernel speedups through external gates. Explicit invocations may use source mode for HIP or Triton candidates with an independent reference. Do not use for NVIDIA/CUDA/PTX/SASS, ordinary source-only tuning, trace-only analysis, one-off benchmarking, ROCm setup, or formal-equivalence claims.
---

# AsmEvo

Run a profiling-guided optimization loop in which deterministic gates, not the
model, decide correctness and performance. Treat the original implementation or
binary as immutable evidence.

This skill extracts the reusable workflow from the AsmEvo paper. It does not
pretend to provide a universal HSACO rewriter or dispatch-capture runtime. Use a
project's existing build, launch, profiling, and comparison tools when present.

## Non-negotiable trust boundary

- The agent may analyze, propose, and apply localized candidate edits.
- Deterministic tools own build validity, ABI/resource checks, functional
  equivalence, timing, and commit decisions.
- Never accept correctness from code inspection, model judgment, or a candidate's
  own self-report.
- Never time a candidate before it passes the required correctness gates.
- Never overwrite the original artifact or continue from an unverified candidate.
- Never report an optimization unless fresh measurements show that the configured
  acceptance threshold was met.
- The helpers validate evidence structure and promotion arithmetic; they do not
  authenticate measurements. Require raw evidence from the authorized oracle and
  benchmark adapters, not values manually asserted by the agent.

## Select the operating mode

Choose the strongest mode the available evidence supports.

1. **Source mode**: editable HIP, Triton, native extension, or assembly exists and
   an independent reference implementation can be executed. Use that reference as
   the behavioral oracle.
2. **Binary mode**: only an AMDGPU code object such as `.hsaco` or `.co` is
   available. Use the unmodified binary as the oracle. Before modifying anything,
   read [references/binary-backend.md](references/binary-backend.md).
3. **Audit mode**: the user asks for analysis only, or required GPU/build/replay
   capabilities are missing. Inspect artifacts, identify likely hot windows, and
   return an executable optimization plan. Do not claim measured improvement.

Do not silently downgrade binary mode to source mode. State which mode is active,
which oracle is authoritative, and which guarantees are unavailable.

## Preflight

Establish the following before searching:

- target artifact and immutable SHA-256 identity;
- target GPU architecture and wave mode, independently detected rather than
  inferred from the presence of a device node;
- compiler, ROCm, driver, and code-object versions where observable;
- authoritative correctness command or replay harness;
- candidate build/rebuild command;
- static ABI/resource-consistency command for binary mode;
- benchmark command, raw timing format, warmup policy, and noise controls;
- profiler or static evidence used to select the first hot window;
- writable private run directory that is not a published artifact directory.

Use `scripts/preflight.py` to record artifact identity, required executable
availability, and the architecture reported by an independent GPU inventory
tool. Pass that reported value with `--detected-arch`; `/dev/dxg`, `/dev/kfd`, or
a render node alone does not prove the requested architecture. If the project
lacks a command contract, read
[references/adapter-contract.md](references/adapter-contract.md) and create the
smallest project-local adapter needed for the requested run.

For real-dispatch captures, treat kernargs and device-memory snapshots as sensitive
data. Keep them in an authorized private workspace and never commit them.

## Establish the baseline

1. Copy `assets/contract-template.json` into the private run directory. Freeze its
   mode, target architecture, environment identity, ordered cases, comparison
   rules, and performance thresholds before evaluating candidates.
2. Freeze the original artifact as `K0`; record its content hash.
3. Run the oracle on every frozen case before changing code.
4. Record raw baseline timing samples after warmup. Do not retain only a summary.
5. In binary mode, prove no-edit round-trip fidelity before attempting an edit.
6. Initialize a verified lineage with
   `scripts/lineage.py init --contract ... --preflight ...
   --environment-manifest ...`. Initialization must reject a blocked, mismatched,
   or incomplete preflight report or an environment-manifest hash mismatch.
7. Capture the full environment manifest next to the run evidence and bind its
   identity in the frozen contract.

If the baseline is incorrect, unstable, or cannot round-trip, stop optimization and
report that failure. The search cannot repair an untrusted baseline.

## Run the search loop

Repeat within the user's time or attempt budget:

1. Profile the current verified best and identify one stall-dominant instruction
   window or one source-level bottleneck.
2. Form a falsifiable optimization hypothesis tied to the evidence.
3. Read [references/optimization-playbook.md](references/optimization-playbook.md)
   only for the observed bottleneck class.
4. Create one localized candidate edit. Preserve a clean diff against its verified
   parent and record the rationale.
5. Build or rebuild the complete kernel artifact.
6. Run gates in this exact order:
   - assembly/build validity;
   - ABI, descriptor, metadata, and resource consistency when applicable;
   - functional equivalence for every configured case, including guards;
   - warmup and stable timing under the same launch conditions;
   - variance-aware improvement threshold against the current verified best.
7. Materialize the evidence in the format described by
   [references/acceptance-contract.md](references/acceptance-contract.md), then run
   `scripts/gate.py`.
8. Pass the original evaluation JSON—not an editable decision—to
   `scripts/lineage.py record --evaluation ...`. The lineage helper reruns the
   deterministic gate; only accepted candidates become verified lineage nodes.
9. Re-profile after an accepted edit. On rejection, reset fully to a verified node
   before trying another direction.

Prefer many small, attributable edits over a large rewrite. Stop repeating a
direction after the same failure signature recurs; summarize the exhausted
hypothesis and redirect to a different bottleneck.

## Multi-start and composition

Use parallel workers only when they have isolated workspaces, separate candidate
identities, and non-conflicting GPU allocation. Use one shared lineage state only
through `lineage.py`, whose record operation is file-locked. Assign orthogonal directions such
as latency hiding, dependency reduction, register-pressure control, memory access,
or instruction simplification.

Start every worker from a verified node. Treat worker results as untrusted until
the controller runs the full gate. When combining successful edits:

- require a common verified base;
- prefer disjoint or clearly complementary edit windows;
- apply one edit at a time;
- rebuild and reverify after every step;
- keep the composition only if it is correct and improves over both parents.

## Interpret failures

Return structured failure classes to the search loop. Use the exact categories in
[references/failure-taxonomy.md](references/failure-taxonomy.md). Do not flatten
assembly failure, ABI inconsistency, divergence, runtime failure, noise, and lack
of speedup into a generic retry.

Infrastructure failures may be retried within a bounded budget. Semantic
divergence requires a new candidate. Repeated timing noise requires stabilizing the
environment, not selecting the fastest outlier.

## Completion contract

An optimization result is complete only when the user receives:

- original and optimized artifact identities;
- operating mode and oracle description;
- frozen workload-contract, preflight-report, and environment-manifest SHA-256s;
- exact build, verification, and benchmark commands;
- evaluated shapes, dtypes, strides, seeds, and launch configurations;
- ABI/resource comparison where applicable;
- raw timing samples and the gate decision;
- verified speedup relative to `K0` and the parent candidate;
- candidate lineage and localized edit rationale;
- explicit guarantee boundary and untested cases;
- a loadable replacement artifact only when the native application path was also
  verified.

Call the result **empirically verified for the evaluated cases**, not formally
equivalent. If hardware or a required backend is unavailable, return audit-mode
findings and the missing prerequisite instead of manufacturing a result.

## Sources

- [AsmEvo paper](https://arxiv.org/abs/2608.20711)
- [AMDGPU backend and code-object ABI guide](https://rocm.docs.amd.com/projects/llvm-project/en/latest/LLVM/llvm/html/AMDGPUUsage.html)
