---
name: asmevo
description: Apply or resume an AsmEvo-style correctness-gated optimization loop for AMDGCN assembly or compiled AMDGPU HSACO/code objects, using the original artifact as oracle when source is absent. Use when asked to run AsmEvo, optimize AMDGCN assembly or an AMDGPU code object, or verify measured AMD-kernel speedups through external gates. Explicit invocations may use source mode for HIP or Triton candidates with an independent reference. Do not use for NVIDIA/CUDA/PTX/SASS, ordinary source-only tuning, trace-only analysis, one-off benchmarking, ROCm setup, or formal-equivalence claims.
---

# AsmEvo

Run a profiling-guided optimization loop in which an executable controller, not
the model, orders correctness and performance work. Treat the original
implementation or binary as hash-bound, tamper-detected evidence.

This skill extracts the reusable workflow from the AsmEvo paper. It does not
pretend to provide a universal HSACO rewriter or dispatch-capture runtime. Use a
project's existing build, launch, profiling, and comparison tools when present.

## Non-negotiable trust boundary

- The agent may analyze, propose, and apply localized candidate edits.
- `scripts/controller.py` owns adapter invocation, gate order, correctness
  receipts, timing authorization, and lineage submission.
- Authorized deterministic adapters own build validity, ABI/resource checks,
  functional equivalence, and hardware timing.
- Never accept correctness from code inspection, model judgment, or a candidate's
  own self-report.
- Never time a candidate before it passes the required correctness gates.
- Never overwrite the original artifact or continue from an unverified candidate.
- Never report an optimization unless fresh measurements show that the configured
  acceptance threshold was met.
- `gate.py` and `lineage.py` remain low-level interfaces. Caller-supplied
  evaluation JSON is not controller-backed evidence and must not support an
  empirical optimization claim.
- For cooperative public-CLI use, the controller enforces invocation order and
  binds bytes. Its module-private token prevents accidental low-level bypass, not
  a same-user caller that can import Python. It also does not authenticate a
  malicious adapter, operating system, GPU, or remote worker. These remain in the
  trusted computing base.

## Select the optimization surface

Freeze `optimization_surface` before preflight. Use `launch_config`,
`hip_source`, `triton_source`, `amdgcn_assembly`, `hsaco_binary`, or
`audit_only`. Do not infer a stronger surface from an old run.

Choose the strongest mode the available evidence supports:

1. **Source mode**: editable HIP, Triton, native extension, or assembly exists and
   an independent reference implementation can be executed. Use that reference as
   the behavioral oracle.
2. **Binary mode**: only an AMDGPU code object such as `.hsaco` or `.co` is
   available. Use the unmodified binary as the oracle. Before modifying anything,
   read [references/binary-backend.md](references/binary-backend.md).
3. **Audit mode**: the user asks for analysis only, or required GPU/build/replay
   capabilities are missing. Inspect artifacts, identify likely hot windows, and
   return an executable optimization plan. Do not claim measured improvement.

`amdgcn_assembly` is source mode with a fixed host contract and a real, freshly
assembled object or code object. Before using it, read
[references/assembly-backend.md](references/assembly-backend.md) and
[references/profiling-contract.md](references/profiling-contract.md).
`hsaco_binary` remains binary mode and additionally requires verified binary
round-trip capability. Parameter search and precompiled entry selection can
never satisfy either ASM surface.

Do not silently downgrade binary mode to source mode. State which mode is active,
which oracle is authoritative, and which guarantees are unavailable.

## Preflight

Establish the following before searching:

- target artifact and tamper-detected SHA-256 identity;
- target GPU architecture and wave mode, independently detected rather than
  inferred from the presence of a device node;
- compiler, ROCm, driver, and code-object versions where observable;
- authoritative correctness command or replay harness;
- candidate build/rebuild command;
- static ABI/resource-consistency command for binary mode;
- benchmark command, raw timing format, warmup policy, and noise controls;
- profiler or static evidence used to select the first hot window;
- writable private run directory that is not a published artifact directory.

Use `scripts/capability_probe.py` to bind ROCm/LLVM/profiler tool paths, versions,
hashes, and live features. Then use `scripts/preflight.py` to record artifact
identity, resolved adapter paths and hashes, the chosen surface, and the
architecture reported by an independent GPU inventory tool. Pass that reported
value with `--detected-arch`; `/dev/dxg`, `/dev/kfd`, or a render node alone does
not prove the requested architecture. If the project lacks a command contract,
read [references/adapter-contract.md](references/adapter-contract.md) and create
the smallest project-local adapter needed for the requested run.

For architecture-sensitive proposals, read
[references/architecture-and-rocm-context.md](references/architecture-and-rocm-context.md).
Resolve `assets/architectures/targets.json` by exact target only, then load the
single referenced architecture card. Never classify RDNA or CDNA from a `gfx`
prefix: `gfx1201` is routed to RDNA 4 while `gfx1250` is routed to CDNA 5. If no
exact entry exists, use only the generic measured playbook. Record observable
ROCm, HIP, LLVM, ROCr, profiler, driver, firmware, and code-object labels with
repeated `--component NAME=VERSION` arguments; treat those labels as context, not
compatibility proof. Architecture knowledge may shape proposals but cannot
change assembly, correctness, native-load, benchmark, or promotion gates.

For real-dispatch captures, treat kernargs and device-memory snapshots as sensitive
data. Keep them in an authorized private workspace and never commit them.

## Establish the baseline

1. Copy `assets/contract-template.json` into the private run directory. Freeze its
   mode, `optimization_surface`, target architecture, environment identity,
   ordered cases, comparison rules, and performance thresholds before evaluating
   candidates.
2. Freeze the original artifact as `K0`; record its content hash.
3. Capture the full environment manifest next to the run evidence and bind its
   identity in the frozen contract.
4. Initialize only through `scripts/controller.py init`. It directly runs the
   source oracle, or the binary recover/rebuild/round-trip/static/oracle/replay/
   compare chain, mints a correctness receipt, and only then invokes the baseline
   benchmark.
5. Confirm a schema-v2 run reports `record_policy: controller-v2` and preserves
   raw baseline timing samples. Schema-v1 evidence remains readable as legacy and
   must not be relabeled as ASM. Do not use the legacy
   `lineage.py init --baseline-median-ms` path for a measured claim.

Read [references/controller-contract.md](references/controller-contract.md) for
the exact state machine and commands.

If the baseline is incorrect, unstable, or cannot round-trip, stop optimization and
report that failure. The search cannot repair an untrusted baseline.

## Run the search loop

Repeat within the user's time or attempt budget:

1. Profile the current verified best and identify one stall-dominant instruction
   window or one source-level bottleneck. For `amdgcn_assembly`, the proposal must
   bind the exact profile evidence SHA-256.
2. Form a falsifiable optimization hypothesis tied to the evidence.
3. Read [references/optimization-playbook.md](references/optimization-playbook.md)
   only for the observed bottleneck class.
4. Create one localized candidate edit. Preserve a clean diff against its verified
   parent and record the rationale.
5. Submit only the proposal and descriptive edit metadata to
   `scripts/controller.py evaluate`. Pass `--profile-evidence` for
   `amdgcn_assembly`. Never assemble an evaluation JSON or pass correctness or
   timing values from the model.
6. Let the controller run build/rebuild, mandatory binary static checks, and every
   frozen correctness case. It writes a hash-bound correctness receipt before it
   can spawn the benchmark adapter.
7. Let the controller re-hash frozen inputs and the candidate before and after
   timing, run the deterministic verdict, and atomically record the attempt.
8. Distinguish branch acceptance from global-best promotion. A candidate may be a
   verified branch node while `best_id` remains a faster node from another branch.
9. The controller re-profiles only a performance-qualified ASM candidate and
   withholds acceptance if that profile fails. On rejection, start the next
   proposal from a verified node rather than from rejected bytes.

Prefer many small, attributable edits over a large rewrite. Stop repeating a
direction after the same failure signature recurs; summarize the exhausted
hypothesis and redirect to a different bottleneck.

## Multi-start and composition

Use parallel workers only when they have isolated workspaces, separate candidate
identities, and non-conflicting GPU allocation. Use one shared lineage state only
through the controller; its final lineage record is file-locked. Assign orthogonal
directions such as latency hiding, dependency reduction, register-pressure
control, memory access, or instruction simplification.

Start every worker from a controller-bound node. Treat worker proposals as
untrusted until the controller runs the full gate. When combining successful edits:

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
- baseline and per-candidate correctness-receipt SHA-256s;
- adapter executable identities and ordered phase evidence;
- exact build, verification, and benchmark commands;
- evaluated shapes, dtypes, strides, seeds, and launch configurations;
- ABI/resource comparison where applicable;
- optimization surface, normalized instruction diff, and parent/candidate
  profile evidence for an ASM claim;
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
