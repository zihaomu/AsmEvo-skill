# AsmEvo Skill

A reusable Codex skill that turns the core idea of
[AsmEvo](https://arxiv.org/abs/2608.20711) into an executable workflow:
model-guided AMDGPU optimization behind a controller-owned correctness-before-
timing gate.

This repository is an independent workflow extraction, not the paper authors'
official implementation. It deliberately does **not** claim to include a
universal HSACO rewriter, dispatch-capture runtime, or formal equivalence checker.
Those project-specific capabilities are supplied through explicit adapters; the
skill fails closed when they are unavailable.

## What it provides

- source, binary, and audit operating modes;
- a fixed controller state machine that invokes project adapters directly;
- hash-bound preflight, workload, environment, artifact, and receipt identities;
- correctness receipts that authorize benchmarking only after every frozen case
  passes;
- controller-bound candidate lineage, with legacy low-level tooling kept separate;
- numeric, exact-state, and memory-canary gates;
- variance-aware performance acceptance from raw samples;
- contracts for recovery, round-trip, metadata-aware rebuild, replay, and native
  path validation;
- a profiling-guided AMDGCN optimization playbook.

The four Python helpers use only the Linux Python standard library:

- `preflight.py` records artifact identity, checks required capabilities, and
  distinguishes a visible device node from a verified target architecture;
- `controller.py` is the recommended entry point: it initializes a measured
  baseline, evaluates candidates in a fixed order, and submits bound evidence;
- `gate.py` computes the deterministic verdict from an evaluation document;
- `lineage.py` locks and records lineage state. Its public `init` and `record`
  commands are legacy low-level interfaces and do not create controller-bound
  evidence.

Runtime requirements are Linux and Python 3.10 or newer.

## Install in Codex

Ask Codex:

```text
Use $skill-installer to install the asmevo skill from zihaomu/AsmEvo-skill, path asmevo.
```

Or run the bundled installer directly:

```bash
python3 "${CODEX_HOME:-${HOME}/.codex}/skills/.system/skill-installer/scripts/install-skill-from-github.py" \
  --repo zihaomu/AsmEvo-skill \
  --path asmevo
```

Restart Codex after installation so the new skill is discovered.

Merging this repository's PR does not update an already installed local copy.
After the change is merged, reinstall the `asmevo` subdirectory and restart Codex;
check `~/.codex/skills/asmevo/VERSION` (or the corresponding `CODEX_HOME`) to
confirm the installed version.

## Use

Invoke the skill explicitly for the first run:

```text
Use $asmevo to optimize this gfx942 AMDGCN assembly. Treat kernel.hsaco as the
frozen K0 behavior oracle, use ./replay as the capture harness, and stop after 30
attempts.
```

For a source-backed run, provide an independent oracle plus build and benchmark
commands. For a binary-only run, recovery, no-edit round-trip, metadata-aware
rebuild, static ABI/resource checking, the unmodified-binary oracle, replay,
comparison, and benchmark capabilities are all mandatory. A matching architecture
reported by an independent GPU inventory tool is also required; a device node is
not enough.

For measured runs, use `scripts/controller.py init`, followed by
`scripts/controller.py evaluate`. In binary mode the `oracle` adapter always runs
the frozen original `K0`; it never executes a candidate. The `replay` adapter runs
the rebuilt round-trip artifact during initialization and the candidate during
evaluation, and `compare` checks those observations against the K0 oracle output.
See [`controller-contract.md`](asmevo/references/controller-contract.md) for the
commands and receipt lifecycle.

## Validate

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q asmevo/scripts tests
python3 asmevo/scripts/gate.py asmevo/assets/evaluation-template.json
python3 asmevo/scripts/controller.py --help
```

## Design boundary

The language model proposes localized edits and hypotheses. The controller owns
adapter invocation order, evidence capture, correctness receipts, benchmark
authorization, and lineage submission. “Controller-bound” means that the recorded
phase chain and bytes are hash-bound to the frozen identities; it does not prove
that an adapter, OS, driver, GPU, or remote worker reported truthfully.

The module-private Python token shared by `controller.py` and `lineage.py`
prevents the public CLI and ordinary accidental misuse from entering the
controller-only record path. It is not a security boundary against a malicious
process running as the same user or a model that can import and call the Python
modules. Such a threat model requires OS isolation and independently authenticated
measurement services.

Likewise, the environment-manifest hash binds the bytes of the declared manifest;
it does not verify the live process environment or detect an unrecorded change to
`PATH`, `PYTHONPATH`, `LD_PRELOAD`, or equivalent injection mechanisms. Capture
those values in the manifest and use an isolated execution environment when they
matter. Results remain empirically verified only for the recorded cases, never
formally equivalent. Direct `gate.py` and public `lineage.py` workflows remain
available for legacy inspection, but cannot support a controller-bound measured
claim.

See [`asmevo/SKILL.md`](asmevo/SKILL.md) for the full workflow and the reference
contracts under [`asmevo/references`](asmevo/references).
