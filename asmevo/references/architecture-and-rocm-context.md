# Architecture and ROCm context

Use this layer to improve proposal quality without turning architecture notes into
another correctness oracle.

## Exact architecture routing

1. Obtain the exact target from an independent inventory tool such as
   `offload-arch`, `rocminfo`, or the project's trusted inventory adapter.
2. Resolve only exact entries in `assets/architectures/targets.json`.
3. If the target is known, load the referenced architecture card and bind its
   hash in the capability or preflight report.
4. If the target is unknown, do not infer RDNA/CDNA from a `gfx` prefix. Continue
   with generic, profile-backed hypotheses and live gates.

This rule is intentionally strict: `gfx1201` maps to RDNA 4 while `gfx1250` maps
to CDNA 5. A broad `gfx12*` rule would silently select the wrong knowledge.

## Component-level software context

An umbrella ROCm version is insufficient for reproducibility. Record the
components that are observable and relevant to the run:

- ROCm distribution/build;
- HIP runtime;
- LLVM/compiler and assembler;
- ROCr/HSA runtime;
- profiler;
- kernel driver and firmware;
- code-object version.

Pass known labels to `capability_probe.py` or `preflight.py` with repeated
`--component NAME=VERSION` arguments. These labels are declared context. Tool
paths, hashes, and versions observed by the probe are stronger identities, but
neither proves that the combined stack supports a target.

Never infer compatibility from version strings alone. Require exact-target
assembly, object inspection, native load, frozen correctness, and measured
performance. Architecture and software-stack context may change which candidate
is proposed; it never changes the gate order or acceptance threshold.
