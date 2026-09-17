# Profiling-guided AMDGPU optimization playbook

Open only the section matching observed evidence. These are hypotheses to test,
not transformations that are correct by construction.

## Long-latency memory stalls

Evidence: sampled waits around global/buffer loads, low VALU utilization, long
dependency distance from load to first use.

Candidate directions:

- move independent address or arithmetic work into the latency window;
- issue independent loads earlier while keeping live ranges bounded;
- tighten overly conservative wait placement only after tracing all outstanding
  operations and consumers;
- test architecture-valid cache hints or load variants when the access policy is
  known;
- reduce redundant address generation or conversion work.

Hazards: aliasing, memory ordering, wait-counter domains, increased VGPR pressure,
and reading data before it is ready.

## Dependency-bound arithmetic

Evidence: a serial VALU/MFMA chain dominates samples while issue slots are idle.

Candidate directions:

- interleave independent accumulators or address chains;
- reassociate only when the workload's floating-point contract allows it;
- replace a longer instruction sequence with an architecture-supported equivalent;
- hoist loop-invariant scalar work.

Hazards: changed rounding, NaN/Inf behavior, SCC/VCC or EXEC side effects, and
longer live ranges.

## Register pressure or occupancy limit

Evidence: occupancy is capped by VGPR/SGPR/AGPR or scratch use; spills appear in
the instruction stream or profiler.

Candidate directions:

- shorten live ranges and reuse dead temporaries;
- remove redundant materialization and conversions;
- split a transformation that creates too many simultaneous values;
- trade a small amount of recomputation for a proven occupancy gain.

Hazards: hidden register pairs, accumulator layout, new spills, descriptor/resource
desynchronization, and an occupancy increase that does not improve latency.

## LDS, barriers, or synchronization

Evidence: workgroups spend substantial time at barriers, LDS conflicts, or serial
producer/consumer boundaries.

Candidate directions:

- eliminate a provably redundant barrier;
- reschedule independent work before the barrier;
- adjust an LDS access pattern only when the mapping and bank behavior are known;
- test double-buffer overlap when resource headroom exists.

Hazards: cross-wave visibility, barrier divergence, LDS size growth, bank conflicts,
and changed workgroup assumptions.

## Instruction and control overhead

Evidence: hot-window samples show repeated conversions, mask manipulation, address
setup, or branches rather than useful compute.

Candidate directions:

- fold constants and reuse already available values;
- remove instructions proven dead across all EXEC-mask paths;
- simplify address arithmetic without changing overflow behavior;
- reduce branch overhead while preserving lane masks and reconvergence state.

Hazards: implicit condition-code uses, partial-lane execution, PC-relative control
flow, undefined upper bits, and code-size changes.

## Selection rule

Change one mechanism at a time. Record the profile symptom, expected counter or
latency effect, edited window, and possible correctness hazard before editing.
After an accepted candidate, profile again; the next bottleneck may differ.
