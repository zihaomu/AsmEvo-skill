# AMDGCN source-assembly backend

Use this backend only when a candidate actually changes AMDGCN assembly and a
fresh object or code object is produced from that source. Selecting launch
parameters, choosing an already compiled entry point, or writing a manifest is
not assembly optimization.

## Boundary

The skill provides generic probing, assembly, disassembly, diff, resource, gate,
and lineage tools. The consuming project remains responsible for the fixed host
launcher, exact kernarg layout, independent reference, native load path,
workload, and benchmark. Those items must stay in the project or private run
environment; do not copy operator-specific integration into this skill.

Declare this surface in a schema-v2 contract:

```json
{
  "schema_version": 2,
  "mode": "source",
  "optimization_surface": "amdgcn_assembly"
}
```

Preflight requires `build`, `disassemble`, `static_check`, `native_load`,
`oracle`, `profile`, and `benchmark` adapters, plus independently identified
assembler, linker, objdump, and profiler executables. A missing executable,
adapter, exact target architecture, or native-load capability blocks the run.

## Proposal

Use `assets/schemas/asm-candidate.schema.json`. A proposal binds one verified
parent and its profile evidence, identifies one or more PC windows, and records a
falsifiable hypothesis. It never carries self-reported correctness or speed.

The `source_path` is resolved next to the proposal unless absolute. The
controller snapshots both source and proposal before build. The edited windows
on the CLI, when supplied, must exactly equal the proposal windows.

## Build and analysis tools

- `scripts/assemble.py` invokes explicit assembler and linker executables and
  refuses to overwrite an output. Its successful report always states
  `compiled: true` and `precompiled_variant: false`.
- `scripts/disassemble.py` preserves raw objdump output and emits normalized,
  hash-bound instruction records.
- `scripts/code_object_diff.py` requires a non-empty normalized instruction diff
  whose changed PCs remain in the declared windows.
- `scripts/resource_check.py` scans the final artifact. Unavailable resource
  values remain unavailable; the tool never guesses them.

These helpers are building blocks for a project adapter. The controller invokes
the adapter ABI, not these tools directly, because only the project knows how to
load the result through its real host path.

## Mandatory response claims

The build response must echo the controller binding, bind
`candidate_sha256`, and include:

```json
{
  "compiled": true,
  "precompiled_variant": false,
  "artifact_kind": "hsaco"
}
```

`artifact_kind` may be `elf_object`, `code_object`, or `hsaco`. The disassembly
response must bind the same kind and include `instruction_diff.nonempty: true`
and `instruction_diff.within_declared_windows: true`. The static response must
include `abi_consistent: true` and `resource_consistent: true`. `ok: true` alone
is insufficient for those phases.

## Controller order

Baseline:

```text
disassemble -> static check -> native load -> correctness
-> correctness receipt -> benchmark -> baseline profile -> lineage
```

Candidate:

```text
verified parent profile -> proposal -> build -> disassemble/diff
-> static check -> native load -> correctness -> correctness receipt
-> benchmark -> if performance-qualified, fresh profile -> lineage
```

Candidates that fail correctness are never benchmarked. Candidates that do not
clear the performance threshold are not re-profiled. A performance-qualified
candidate is not accepted until its fresh, artifact-bound profile is complete;
the next proposal must use that accepted candidate and profile as its parent.

## Claim boundary

Call a result assembly-optimized only when the final lineage contains a real
compiled artifact, non-empty in-window instruction diff, static ABI/resource
receipt, native-load success, correctness receipt, raw timing, and both parent
and accepted-candidate profile identities. Otherwise report the actual surface
or an audit result.
