# Methodology

How the analysis works, stage by stage, and how to read the output.

The tool answers one question: **can a modelled fault make secure-boot /
image-verification code accept an image it should reject, and if so where and
how reliably?** It models faults in an emulator (Unicorn + Capstone). It does
not drive hardware.

## 1. Detect

Identify the architecture, load base, entry point, and initial stack pointer
from the image itself — ELF header, Cortex-M vector table, or Capstone
multi-ISA scoring. Override any of these on the command line (`--arch`,
`--base`, `--entry`, `--stack`).

## 2. Discover

Run the unfaulted firmware and map every peripheral access. When a run hangs
or crashes, diagnose why (status-register poll loops, wild jumps, missing ROM)
and report what to model. Use `--discover`.

## 3. Model the harness

Real firmware reads peripherals and calls hardware routines the emulator does
not implement. Three tools bridge that:

- `--mmio ADDR=VAL` / `--mmio-region ADDR:SIZE` — give a peripheral register
  the value firmware expects (a ready/status bit, a region to pre-map).
- `--stub ADDR=RET` — skip a function (a hash/PKA engine, an I2C driver, a
  delay loop) and return a chosen value.
- `--entry` / `--sp` / `--reg` — start emulation directly at the verification
  routine with a chosen register context.

`--calibrate-stubs` measures the condition flags each stubbed function really
leaves on return (short calls run for real; long ones are cut), so a compare
that follows the call sees correct flags.

## 4. Baseline (two-way oracle)

A golden run with an image that must **FAIL** verification. The sweep is
refused until the baseline reaches the fail branch, because results against a
broken baseline are meaningless.

`--genuine <image>` (or `--genuine-stub ADDR=VAL`) adds the other direction: a
genuine image must reach SUCCESS unfaulted. With both, the harness is known to
distinguish accept from reject, so the sweep measures a real FAIL→SUCCESS
bypass. An unsound oracle refuses to sweep (override with `--force`).

## 5. Sweep

Re-run once per executed instruction with a single fault:

- **skip** — the instruction is not executed (classic glitch).
- **bitflip** (`--bitflip`) — one bit of the instruction encoding is flipped,
  swept over every bit (catches `bne`→`beq`, corrupted immediates, wrong
  destination registers).
- **data faults** (`--data-faults`) — the instruction executes, then its result
  register is forced to all-zeros / all-ones (compares get flags cleared /
  set), modelling a glitch that corrupts a load or write-back.

Plus an optional randomized multi-glitch campaign (`--campaign N`).

Two extra single-glitch models find bypasses the basic sweep cannot:

- **Wide-glitch skip windows** (`--skip-window N`) — one glitch that removes up
  to N consecutive instructions (a burst). Finds bypasses that need neither a
  single precise skip nor two independent faults, including ones that skip onto
  code the golden run never reached.
- **Iteration-aware sweeps** (`--iterations N`) — for instructions run more than
  once, fault visits 0..N-1. Catches bypasses that need glitching a specific
  pass of a compare/verify loop (e.g. a byte-by-byte hash check), which the
  first-visit sweep never tries.

## 6. Characterize

Every fault that flips FAIL into SUCCESS is placed on the execution timeline as
a **glitch window**: instruction index from entry, approximate cycle offset,
and window width. Optional JSON export with `--json`.

## 7. Validate robustness

Re-test every finding under several stubbed mismatch values
(`--stub ADDR=V1,V2,..` or `rand:N`) and random entry-register contexts
(`--vary-regs N`). Findings are classified:

- **robust** — works regardless of harness assumptions.
- **context-dependent** — kept, with a success rate.
- **value-dependent** — dropped as a harness artifact (e.g. a stubbed hash of
  `0x0000` matching a zeroed buffer).

A stub value that makes the image verify is excluded automatically.

## 8. Order (multi-fault resistance)

`--double` runs an exhaustive double-fault search and reports the
fault-resistance order: **1** (one fault bypasses), **2** (only pairs do), or
**>2**. Second glitches are taken from the path the first one produces, so
redundant checks the unfaulted run never reaches are covered. Pairs are grouped
by the second-glitch target to show what to harden.

- `--double-models skip,bitflip,data` lets each glitch of a pair be any
  modelled mechanism (an image that resists two skips may still fall to a mixed
  pair).
- `--double-max-runs N` caps the work; a truncated search reports the order as
  not established.

## 9. Rank bench targets

`--rank` scores each instruction by the share of modelled fault mechanisms that
bypass, using robust findings only, and groups contiguous targets into **hot
zones**. A physical glitch produces a spread of effects, so high-score
instructions in wide zones are the most forgiving targets.

## 10. Explain divergence

`--explain` diffs each single-fault bypass against the golden run and reports
where control flow first diverged: the branch or guard the glitch subverted and
where execution went instead. Different faults that subvert the same branch
collapse to one mechanism, which is the right unit for remediation.

## 11. Report

`--report PATH` writes a Markdown assessment report: summary, harness and
evidence trail (hashes, versions, self-test, oracle status), findings with
robust and context-dependent mechanisms, rule-based weakness patterns
(instruction class + role of the value + which mechanisms bypass) with
remediation, bench plan, multi-fault resistance, and the exact reproduction
command.

## 12. Retest

`--compare old.json` compares with a previous build's findings after a fix.
Findings are matched by aligning the two execution sequences (addresses
normalised away), not by address, so inserted or moved code is handled. Old
findings become closed / reduced / still exploitable / still context-dependent
/ code changed (never counted as closed); new findings are flagged as
regressions or new code.

## Engine

Every faulted run starts from an identical machine state. By default one
Unicorn instance per configuration is built once and restored between runs
(registers from a CPU context; memory through write-protect dirty-page
tracking; lazily mapped pages unmapped; fault patches undone; translated code
dropped for every restored range). That is about 10x faster than rebuilding the
instance each run and gives identical results.

- `--verify-fast N` checks fast-reset equivalence on the target being analysed.
- `--no-fast-reset` falls back to fresh instances.
- `--fast-recycle N` rebuilds the instance every N runs (default 20000; 0 =
  never) to bound accumulated native state.

Lazily mapped pages (unmodelled data memory) are read/write but never
executable, so a wild jump into them crashes instead of silently running zeros.

## Self-test

Results depend on emulator behaviours found empirically on specific
Unicorn/Capstone versions (Thumb entry bit, T-bit on PC redirects, FPU enable,
write-protect hooks not retrying, code-cache eviction, no read hooks over
flash). `--selftest` checks each one and the end-to-end answers that depend on
them (23 known-answer tests). It runs automatically before an analysis when the
installed versions differ from the tested ones, and the analysis stops if it
fails.

## Good practice

- **Validate the oracle both ways.** Pass `--genuine` (or `--genuine-stub`) so
  the tool confirms a genuine image reaches SUCCESS and a tampered one FAIL
  before sweeping.
- **Never trust a single stubbed mismatch value.** Give `--stub` several values
  or `rand:N`; the robustness check drops value-dependent artifacts.
- **Vary the entry register state** with `--vary-regs` to expose findings that
  only work because of the harness, then check what the real callers leave in
  those registers.
