# Usage

```
python3 secureboot_fi_emulator.py [options] [firmware]
```

`firmware` is a raw binary image. Omit it with `--demo` (built-in synthetic
example) or `--selftest`.

See [methodology.md](methodology.md) for what each stage does and how to read
results. The grouped reference below is the practical path; run `--help` for
the authoritative, always-current list.

## Modes

| Flag | What it does |
|------|--------------|
| `--selftest` | Run the known-answer tests on your machine and exit. Also runs automatically when installed Unicorn/Capstone versions differ from the tested ones. |
| `--demo` | Run the self-contained synthetic vulnerable example. |
| `--detect` | Only run architecture detection and exit. |
| `--discover` | Only map peripheral accesses of the unfaulted run, diagnose the baseline, and exit. |
| `--list-branches` | Only print static decision points and exit (helps pick success/fail markers). |

## Target description

| Flag | Meaning |
|------|---------|
| `--arch` | `auto` \| `arm-thumb` \| `arm` \| `arm64` \| `x86` \| `x86-64` (default auto). |
| `--base BASE` | Load/base address (default: detected, else `0x08000000`). |
| `--entry ENTRY` | Entry point (default: detected, else base). |
| `--sp SP` / `--stack STACK` | Initial stack pointer / stack-RAM base. |
| `--reg NAME=VAL` | Preset a register (e.g. `lr=0` when harnessing a function directly). Repeatable. |
| `--success ADDR` / `--fail ADDR` | Address meaning "verification passed" / "failed". Repeatable. |
| `--max-instr N` | Per-run instruction budget (default 20000). |

## Harness modelling

| Flag | Meaning |
|------|---------|
| `--mmio ADDR=VAL` | Value firmware reads from a peripheral register. Repeatable. |
| `--mmio-region ADDR:SIZE` | Pre-map a peripheral region. Repeatable. |
| `--stub ADDR=RET[,RET2..]` or `ADDR=rand:N` | Skip the function at ADDR and return a value. Several values (or `rand:N`) enable the robustness check. |
| `--stub-flags ADDR=NZCV` | Condition flags the stub leaves on return (NZCV nibble). |
| `--calibrate-stubs` | Measure each stubbed function's real exit flags automatically. |
| `--calibrate-budget N` | Per-call budget for calibration (default 500000). |
| `--no-automap` | Crash on unmapped data accesses instead of mapping a zero page. |

## Oracle

| Flag | Meaning |
|------|---------|
| `--genuine PATH` | A genuine (accepted) image that must reach SUCCESS unfaulted — proves the harness distinguishes accept from reject. |
| `--genuine-stub ADDR=VAL` | Model a matching measurement on the current image instead of a separate file. |
| `--force` | Sweep even when the baseline does not reach FAIL or the oracle is unsound. |

## Fault models and searches

| Flag | Meaning |
|------|---------|
| `--bitflip` | Also sweep single-bit instruction-encoding flips. Implies `--characterize`. |
| `--data-faults` | Also sweep data faults (result forced to zeros / ones). Implies `--characterize`. |
| `--campaign N` / `--max-glitches N` | Randomized multi-glitch campaign (iterations / max simultaneous skips). |
| `--skip-window N` | Single wide glitch skipping up to N consecutive instructions (N≥2). |
| `--iterations N` | Iteration-aware sweep: fault visits 0..N-1 of looping instructions. |
| `--double` | Exhaustive double-fault search; reports fault-resistance order (1, 2, >2). |
| `--double-models LIST` | Fault models for pairs, from `skip,bitflip,data` (default skip). Implies `--double`. |
| `--double-max-runs N` | Cap on pair runs (default 200000). |
| `--double-window N` | Limit pairs to at most N executed instructions apart. |

## Robustness, ranking, explanation

| Flag | Meaning |
|------|---------|
| `--vary-regs N` | Re-test findings under N random entry-register contexts. |
| `--characterize` | Map bypasses onto the execution timeline as glitch windows. |
| `--rank` | Rank instructions as bench glitch targets and list hot zones. |
| `--explain` | For each single-fault bypass, report the branch it subverts and where execution went. |
| `--seed SEED` | Seed for `rand:N` stub values and `--vary-regs`. |

## Output

| Flag | Meaning |
|------|---------|
| `--report PATH` | Write a Markdown assessment report. Implies `--characterize`. |
| `--json PATH` | Write the characterization result to JSON. |
| `--compare OLD_JSON` | Retest against a previous run's JSON; classify each old finding and flag regressions. |

## Engine

| Flag | Meaning |
|------|---------|
| `--no-fast-reset` | Build a fresh Unicorn instance per run (slower reference behaviour). |
| `--fast-recycle N` | Rebuild the persistent instance every N runs (default 20000; 0 = never). |
| `--verify-fast N` | Run N random faults on the fast-reset engine and on fresh instances and require identical results before analysing. |

## Full `--help`

```
python3 secureboot_fi_emulator.py --help
```

Run it for the authoritative, always-current option list.
