# AsmEvo Skill

A reusable Codex skill that turns the core idea of
[AsmEvo](https://arxiv.org/abs/2608.20711) into an executable workflow:
model-guided AMDGPU optimization with deterministic correctness and performance
gates.

This repository is an independent workflow extraction, not the paper authors'
official implementation. It deliberately does **not** claim to include a
universal HSACO rewriter, dispatch-capture runtime, or formal equivalence checker.
Those project-specific capabilities are supplied through explicit adapters; the
skill fails closed when they are unavailable.

## What it provides

- source, binary, and audit operating modes;
- immutable preflight report, workload contract, original-artifact identity, and
  verified candidate lineage;
- correctness-before-timing promotion rules;
- numeric, exact-state, and memory-canary gates;
- variance-aware performance acceptance from raw samples;
- contracts for recovery, round-trip, metadata-aware rebuild, replay, and native
  path validation;
- a profiling-guided AMDGCN optimization playbook.

The three small Python helpers use only the Linux Python standard library:

- `preflight.py` records artifact identity, checks required capabilities, and
  distinguishes a visible device node from a verified target architecture;
- `gate.py` converts evaluation evidence into a deterministic decision;
- `lineage.py` reruns the gate, locks concurrent updates, and records attempts
  without letting an unverified candidate become a parent.

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

## Use

Invoke the skill explicitly for the first run:

```text
Use $asmevo to optimize this gfx942 AMDGCN assembly. Treat kernel.hsaco as the
immutable oracle, use ./replay as the capture harness, and stop after 30 attempts.
```

For a source-backed run, provide an independent oracle plus build and benchmark
commands. For a binary-only run, recovery, no-edit round-trip, metadata-aware
rebuild, static ABI/resource checking, the unmodified-binary oracle, replay,
comparison, and benchmark capabilities are all mandatory. A matching architecture
reported by an independent GPU inventory tool is also required; a device node is
not enough.

## Validate

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q asmevo/scripts tests
python3 asmevo/scripts/gate.py asmevo/assets/evaluation-template.json
```

## Design boundary

The language model proposes localized edits and hypotheses. External tools own
assembly/build validity, ABI and resource consistency, functional equivalence,
timing, promotion, and lineage. A result should be described as empirically
verified only for the recorded cases, never as formally equivalent. The bundled
helpers validate evidence structure and decision logic; they do not authenticate
manually entered timing or correctness claims, so project adapters must produce
the raw evidence.

See [`asmevo/SKILL.md`](asmevo/SKILL.md) for the full workflow and the reference
contracts under [`asmevo/references`](asmevo/references).
