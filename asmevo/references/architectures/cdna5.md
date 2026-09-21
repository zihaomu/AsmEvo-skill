# CDNA 5 proposal context

Load this card only when the exact target registry maps the live target to
CDNA 5. It is proposal guidance, never correctness or performance evidence.

## Decision-changing context

- The registry maps `gfx1250` to CDNA 5 and representative Instinct MI450-series
  products. Never route it to RDNA 4 from the shared `gfx12` prefix.
- AMD describes MI455X as CDNA 5 with Wave32-capable matrix cores. Still read the
  final kernel descriptor: the architecture label is not a substitute for live
  wave-mode or ABI evidence.
- Do not apply RDNA WMMA layouts, Radeon cache assumptions, or consumer-GPU
  occupancy heuristics. Derive matrix operands, accumulator layout, memory
  behavior, and resource limits from CDNA 5 documentation plus live artifacts.
- Treat emerging datatype and matrix instructions as unavailable until the bound
  assembler accepts them and the rebuilt object loads natively.
- Prefer local, profile-backed changes because compiler, runtime, profiler, and
  library support may mature at different rates for a new target.

## Required live checks

1. Independent inventory reports `gfx1250` on the target system.
2. The selected compiler/assembler supports `gfx1250` and the proposed opcode.
3. The rebuilt object reports the expected target, descriptor, and wave mode.
4. Native load and the frozen correctness cases pass before timing.
5. Performance is measured on the same recorded software stack.

## Sources

- [AMD CDNA architecture](https://www.amd.com/en/technologies/cdna.html)
- [TheRock exact target registry](https://github.com/ROCm/TheRock/blob/main/cmake/therock_amdgpu_targets.cmake)
- [LLVM AMDGPU backend guide](https://rocm.docs.amd.com/projects/llvm-project/en/latest/LLVM/llvm/html/AMDGPUUsage.html)
