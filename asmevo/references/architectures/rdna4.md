# RDNA 4 proposal context

Load this card only when the exact target registry maps the live target to
RDNA 4. It is proposal guidance, never correctness or performance evidence.

## Decision-changing context

- The registry currently maps `gfx1200` and `gfx1201` here. `gfx1250` is not
  RDNA 4 even though all three targets begin with `gfx12`.
- RDNA 4 WMMA operand layout differs from RDNA 3: AMD documents a simplified
  VGPR mapping and `gfx12`-specific intrinsic forms. Do not reuse an RDNA 3
  matrix-fragment layout without regenerating and checking it.
- For matrix kernels, bind any layout hypothesis to the exact instruction form,
  lane mapping, accumulator representation, and disassembly produced by the
  selected toolchain.
- For non-matrix kernels, keep the generic evidence-led playbook. A generation
  label alone does not justify cache, wait-counter, or scheduling changes.
- Recheck VGPR pressure, occupancy, spills, and instruction count after every
  edit; improved matrix packing can shift the limiting resource.

## Required live checks

1. Independent inventory reports the exact target.
2. The selected compiler/assembler accepts that exact target and instruction set.
3. The rebuilt object reports the expected target, descriptor, and wave mode.
4. Native load and the frozen correctness cases pass before timing.
5. Performance is measured on the same recorded software stack.

## Sources

- [TheRock exact target registry](https://github.com/ROCm/TheRock/blob/main/cmake/therock_amdgpu_targets.cmake)
- [AMD RDNA 4 matrix-core guide](https://gpuopen.com/learn/using_matrix_core_amd_rdna4/)
- [LLVM AMDGPU backend guide](https://rocm.docs.amd.com/projects/llvm-project/en/latest/LLVM/llvm/html/AMDGPUUsage.html)
