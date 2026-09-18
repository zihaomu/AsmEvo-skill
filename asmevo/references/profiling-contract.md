# Profiling evidence contract

Profile evidence is a required input to AMDGCN assembly search. It selects the
window and hypothesis; it is not a model-authored performance claim.

## Required identity

Use `assets/schemas/profile-evidence.schema.json`. A complete document binds:

- artifact, exact target architecture, frozen contract, and environment hashes;
- exported kernel symbol, dispatch count, and sampled time;
- one or more PC hotspot windows;
- observed counters and a separate list of unavailable counters;
- final-artifact resource values;
- a deterministic bottleneck class and its classification inputs;
- profiler executable identity, command, summary identity, and every raw file.

The controller rejects a profile whose artifact, target architecture, contract,
or environment does not match the verified parent. Do not copy a profile across
architectures or across rebuilt artifacts, even when source text is identical.

## Capture helper

`scripts/profile.py` runs one explicit profiler command without a shell, stores
stdout and stderr in a new private raw directory, and combines those files with a
project-produced JSON summary. The project owns translation from its profiler's
native format into the summary because counter names and availability vary by
GPU and ROCm version.

The summary must contain positive `dispatch_count` and `sampled_time_ms`, at
least one hotspot, a resource object, and a non-empty `bottleneck_class`. Put
missing counters in `unavailable_counters`; never synthesize a value or let the
model infer one from architecture folklore.

## Search lifecycle

1. Profile the verified parent.
2. Hash the profile evidence and bind it in the proposal.
3. Build and verify one local edit against that profile.
4. Run correctness, then benchmark.
5. Only if the timing gate qualifies the candidate, capture a new profile.
6. Accept the candidate only after the new profile is valid and bound.
7. Use the accepted candidate's profile for its children.

This ordering keeps correctness-before-timing intact and avoids profiling
candidates that cannot be promoted.

## Sensitive data

Profiler traces, dispatch captures, kernargs, buffer snapshots, model inputs, and
machine locations may be sensitive. Keep raw evidence in the authorized run
directory. The reusable skill contains schemas and tools only; it must not embed
private captures, hostnames, GPU UUIDs, or operator workloads.
