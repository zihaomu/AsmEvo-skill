# RDNA 3.5 proposal context

Load this card only when the exact target registry maps the live target to
RDNA 3.5. It is proposal guidance, never correctness or performance evidence.

## Decision-changing context

- The registry currently maps `gfx1150`, `gfx1151`, `gfx1152`, and `gfx1153`
  here. Do not extend that set by prefix inference.
- Treat wave size, enabled ISA features, register allocation, and code-object
  ABI as properties of the actual kernel descriptor and toolchain output.
- Prefer hypotheses grounded in the current profile and disassembly: shorten
  live ranges, expose independent work, remove redundant address arithmetic,
  or change scheduling one local window at a time.
- Do not transplant RDNA 4 WMMA operand layouts or `gfx12`-specific instruction
  assumptions. Re-derive matrix layouts from the exact instruction form and
  generated object.
- Recheck occupancy and spills after every edit. An instruction reduction that
  raises VGPR pressure can still regress the kernel.

## Required live checks

1. Independent inventory reports the exact target.
2. The selected compiler/assembler accepts that exact target.
3. The rebuilt object reports the expected target and kernel descriptor.
4. Native load and the frozen correctness cases pass before timing.
5. Performance is measured on the same recorded software stack.

## Sources

- [TheRock supported targets](https://github.com/ROCm/TheRock/blob/main/SUPPORTED_GPUS.md)
- [LLVM AMDGPU backend guide](https://rocm.docs.amd.com/projects/llvm-project/en/latest/LLVM/llvm/html/AMDGPUUsage.html)
