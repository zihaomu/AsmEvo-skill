# Binary-mode backend requirements

Binary mode targets the already compiled AMDGPU artifact. Enable it only when all
required capabilities below are executable and have been validated on the target
code-object version and GPU architecture.

## Fail-closed capability set

The backend must provide:

| Capability | Required evidence |
|---|---|
| `recover` | ELF sections, notes, symbols, kernel descriptors, metadata, and AMDGCN body are represented in a rebuildable form |
| `roundtrip` | an unmodified recovery can be rebuilt and compared with `K0`, masking only documented linker-derived fields |
| `rebuild` | a changed body becomes a loadable code object without changing the frozen host interface |
| `static_check` | kernarg layout, symbols, launch semantics, descriptors, metadata, and declared resources are consistent |
| `oracle` | only frozen `K0` executes to produce reference observations for the evaluation contract |
| `replay` | the rebuilt round-trip artifact or a candidate runs with identical launch geometry and initial state |
| `compare` | all observable outputs, exact state, and guard regions are checked |
| `benchmark` | stable raw timing samples are collected after correctness succeeds |

If any capability is absent, switch to audit mode. Do not call the run a binary
optimization and do not patch a production artifact.

## Controller execution roles

Use `scripts/controller.py` for every measured binary run. During initialization
it executes this prefix:

```text
recover K0 -> rebuild without edits -> roundtrip -> static_check
  -> oracle(K0) -> replay(rebuilt roundtrip) -> compare
```

During candidate evaluation it executes:

```text
rebuild(proposal) -> static_check(candidate)
  -> oracle(K0) -> replay(candidate) -> compare
```

The `oracle` adapter must always receive the frozen original artifact. It must
never execute the candidate or use candidate-produced state as the reference.
Only `replay` receives candidate bytes. The controller binds both observation
artifacts into the `compare` request, writes a correctness receipt after comparison
passes, and invokes `benchmark` only after that receipt exists.

Direct `gate.py` or public `lineage.py` commands do not enforce this execution
chain and remain legacy low-level interfaces. A binary result is controller-bound
only when its lineage contains the matching baseline and candidate receipts.

## Recovery and round-trip

Raw disassembly is insufficient. Preserve or reconstruct:

- target triple, target ID, and code-object version;
- sections, symbols, notes, and relocations used by the loader;
- kernel descriptor and `.amdhsa_kernel` declarations;
- AMDGPU metadata and kernarg argument layout;
- the AMDGCN instruction body;
- symbolic PC-relative branches so code movement cannot silently corrupt control
  flow.

Before the first edit, rebuild the recovered representation with no semantic
change. Compare the instruction body, descriptor, symbols, and metadata against
`K0`. Any unexplained mismatch blocks the search.

## Oracle acquisition

Choose one tier per launch contract.

### Tier 1: inferred synthetic launch

Use only when argument offsets, scalar types, pointer roles, allocation sizes,
strides, and launch dimensions are known with enough confidence to build the
complete observable state. Generate deterministic cases covering representative
shapes, dtypes, boundaries, and seeds. Surround writable allocations with canary
regions.

Metadata describes layout, not full application semantics. If pointer targets or
buffer sizes are ambiguous, Tier 1 is not sufficient.

### Tier 2: captured real dispatch

Use for mixed dtype, non-contiguous layouts, block tables, nested pointers, opaque
workspaces, or application-owned state. Capture:

- the complete kernarg buffer;
- grid and workgroup dimensions;
- every referenced device-memory region;
- pre-dispatch memory state;
- `K0` post-dispatch reference state.

Restore the same pre-state for every candidate. Absolute or nested pointers
require restoring referenced regions at compatible virtual addresses; copying
bytes to unrelated allocations is not equivalent replay.

Captures may contain model weights, prompts, user data, or other secrets. Store
them only in an authorized private location and exclude them from version control.

## Metadata-aware rebuild

After each edit, rescan actual VGPR, SGPR, AGPR, LDS, private/scratch, and other
architecture-visible resource usage. Regenerate both descriptor fields and
metadata while freezing:

- exported symbols;
- kernarg offsets, sizes, alignment, and total segment size;
- launch semantics and workgroup contract;
- target architecture and code-object ABI.

An in-place machine-code patch is allowed only when the deterministic backend
proves that the edit is resource-neutral and size-non-increasing. Textual
inspection by the agent is not proof. Patched candidates still pass every normal
gate.

## Native-path validation

Replay-harness success alone does not establish a drop-in replacement. Before
delivery, load the optimized artifact through the original application or library
path with recompilation disabled, then rerun its native tests and launch contract.

Describe all conclusions as empirical and limited to the captured or generated
cases. Binary mode is not formal equivalence verification.

For a cooperative caller, controller binding enforces the adapter invocation
order and binds the recorded bytes. It is not authentication against a same-user
Python caller and does not establish that the adapters, runtime, driver, GPU, or
remote worker are honest. The environment manifest similarly binds a declared
identity; it does not validate the live `PATH`, `PYTHONPATH`, `LD_PRELOAD`, or
other process-injection state.
