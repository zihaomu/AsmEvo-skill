# Project adapter contract

The skill orchestrates project-specific commands; it does not assume one build
system or benchmark framework. Prefer existing project commands. Add wrapper
executables only when the project has no stable interface.

## Capability wrappers

Each wrapper should be a directly executable file or a command already available
on `PATH`. Avoid shell command strings embedded in JSON. A wrapper owns its working
directory, environment setup, timeouts, and tool-specific flags.

Source mode requires:

- `build`: produce one candidate artifact from the edited source;
- `oracle`: compare the candidate with the independent reference over the frozen
  case set and emit machine-readable evidence;
- `benchmark`: emit raw baseline, parent, and candidate latency samples.

Binary mode additionally requires every capability listed in
[binary-backend.md](binary-backend.md).

Run the installed skill's `scripts/preflight.py` by absolute path, with one
`--capability NAME=EXECUTABLE` argument per capability. Example:

```bash
ASMEVO_SKILL_ROOT="${CODEX_HOME:-${HOME}/.codex}/skills/asmevo"
python3 "$ASMEVO_SKILL_ROOT/scripts/preflight.py" \
  --mode source \
  --artifact build/original.hsaco \
  --target-arch gfx942 \
  --detected-arch gfx942 \
  --require-gpu \
  --capability build=./tools/build-candidate \
  --capability oracle=./tools/check-candidate \
  --capability benchmark=./tools/benchmark-candidate \
  --output run/preflight.json
```

`ASMEVO_SKILL_ROOT` must be the absolute directory containing this skill's
`SKILL.md`. When developing from a checkout, point it at that checkout's `asmevo/`
directory instead. Keep artifact and run paths relative to the target project.

The preflight resolves executables but does not run them. Obtain each
`--detected-arch` value from an independent inventory tool such as the project's
validated `rocminfo` parser; never copy the requested target into this field by
assumption. A device node alone is not architecture evidence. Binary mode fails
closed when the target architecture is not confirmed or any mandatory capability
is missing. Source and binary modes always require a matching `--detected-arch`;
`--require-gpu` additionally requires a local device node and is useful when the
adapters are not executing against an authorized remote worker.

## Evidence rules

Wrappers should write files into a candidate-specific run directory and print a
small JSON summary to stdout. Preserve full logs separately. Every summary should
contain:

- schema version;
- candidate and parent IDs;
- canonical proposal SHA-256 and final artifact SHA-256 when a build succeeds;
- start/end timestamps and exit status;
- exact cases or launch IDs evaluated;
- frozen workload-contract SHA-256;
- paths to raw logs and machine-readable results;
- environment fingerprint or reference to it.

The oracle wrapper, not the agent, computes numeric errors and exact-state checks.
The benchmark wrapper, not the agent, captures event timings and synchronizes the
device.

## Source-mode integration

For a project such as `radeon-kernels`, reuse the existing high-level reference
and compilation path, but keep promotion separate from “fastest observed median.”
Convert raw timing samples into the gate input and apply the configured stability
and improvement policy before updating the verified lineage.

Source mode is AsmEvo-inspired optimization. It is not the paper's source-free
binary setting, even when the compiled ISA is inspected after each source edit.

## Command safety

- Treat every candidate as untrusted code.
- Use a bounded timeout for build, correctness, and benchmark commands.
- Run production dispatch capture only with explicit authorization for the target
  application and data.
- Do not pass secrets through command-line arguments or commit capture data.
- Allocate a unique workspace and GPU lease per parallel worker.
- Preserve failed logs; never discard failures or retain only the fastest run.
