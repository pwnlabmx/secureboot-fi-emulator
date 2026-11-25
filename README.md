# secureboot-fi-emulator

Emulation-based **fault-injection (FI) viability analysis** for secure-boot and
image-verification code.

Before you put a glitcher (voltage, clock, or EM) on a board, this tool answers
two questions about a boot ROM or bootloader, statically, in an emulator:

1. Can a single fault make it **accept an image it should reject**?
2. If so, **which instruction** should the glitch hit, and **how wide** is the
   window?

It is an assessment tool. It models faults in an emulator (Unicorn + Capstone);
it does **not** drive hardware. Findings point at the compare or branch that
needs hardening (redundant checks, fail-closed defaults, flow-integrity
counters, random delays).

## Features

- **Architecture auto-detection** from the image (ELF header, Cortex-M vector
  table, or Capstone multi-ISA scoring). Supports ARM Thumb (Cortex-M), ARM
  A32, AArch64, x86, and x86-64.
- **Peripheral discovery** of an unfaulted run, with diagnosis of why a run
  hangs or crashes and what to model.
- **Fault models**: instruction skip, single-bit encoding flips, and data
  faults (result forced to all-zeros / all-ones).
- **Two-way oracle validation** — refuses to sweep a harness that cannot tell
  an accepted image from a rejected one.
- **Single-fault sweep** over every executed instruction, placed on the
  execution timeline as glitch windows.
- **Wide-glitch skip windows** (one glitch removing several consecutive
  instructions) and **iteration-aware sweeps** (glitching a specific pass of a
  compare/verify loop).
- **Double-fault search** reporting the fault-resistance order (1, 2, or >2).
- **Robustness validation** across stub values and entry-register contexts, so
  harness artifacts are dropped.
- **Divergence analysis** — for each bypass, the branch it subverts and where
  execution went instead.
- **Bench-target ranking** and a **Markdown assessment report** with weakness
  patterns, remediation, and the exact reproduction command.
- **Retest / regression comparison** between two builds by aligning execution
  sequences (robust to shifted addresses).
- **Deterministic fast-reset engine** (~10x faster than rebuilding per run)
  with a self-verification mode.
- **23 known-answer self-tests** that run automatically when the installed
  Unicorn/Capstone versions differ from the tested ones.

## Install

Requires Python 3.9+.

```bash
pip install -r requirements.txt
```

Verify the installation (runs the known-answer tests against your Unicorn /
Capstone build):

```bash
python3 secureboot_fi_emulator.py --selftest
```

Run the self-contained synthetic example (no firmware needed):

```bash
python3 secureboot_fi_emulator.py --demo
```

## Quick start

```bash
# 1. Identify the image
python3 secureboot_fi_emulator.py fw.bin --detect

# 2. Run it unfaulted and see what peripherals it touches
python3 secureboot_fi_emulator.py fw.bin --discover --max-instr 2000000

# 3. List decision points (branches) to pick success/fail markers
python3 secureboot_fi_emulator.py fw.bin --list-branches

# 4. Set up the harness and sweep
python3 secureboot_fi_emulator.py fw.bin \
    --entry <verify_fn> --reg lr=0 --stub <hash_fn>=rand:8 \
    --calibrate-stubs --success <boot_branch> --fail <reject_branch> \
    --genuine genuine_fw.bin \
    --bitflip --data-faults --vary-regs 16 --double --rank \
    --verify-fast 200 --json findings.json --report findings.md

# 5. After a fix, retest against the earlier findings
python3 secureboot_fi_emulator.py fw_fixed.bin <same harness and models> \
    --compare findings.json --report retest.md
```

See [`docs/usage.md`](docs/usage.md) for the full CLI reference and
[`docs/methodology.md`](docs/methodology.md) for how each stage works and how to
read the output.

## Library use

The engine is importable:

```python
from secureboot_fi_emulator import EmulatorConfig, SecureBootEmulator, FaultModel

cfg = EmulatorConfig(arch="arm-thumb", load_addr=0x08000000, entry=0x08000000,
                     success_addrs=(0x08000100,), fail_addrs=(0x08000200,))
emu = SecureBootEmulator(open("fw.bin", "rb").read(), cfg)
emu.golden_run()
for win in emu.sweep_single_skip():
    print(win)
```

Key methods: `golden_run()`, `validate_oracle()`, `sweep_single_skip()`,
`sweep_skip_window()`, `sweep_iterations()`, `explain()`, `random_campaign()`,
`characterize()`, `discover_mmio()`, `diagnose()`, `assess_robustness()`,
`double_fault_sweep()`, `calibrate_stubs()`, `rank_bench_targets()`,
`write_report()`, `retest_snapshot()`, `compare_snapshots()`,
`detect_architecture()`.

## How it reads

The tool never claims a hardware result. It reports what an emulator shows:
which modelled faults, at which instructions, flip a rejected image into an
accepted one, with the robustness of each finding across harness assumptions.
A physical glitch produces a spread of effects, so the bench-target ranking
favours high-scoring instructions inside wide windows. Validate the oracle both
ways and vary the harness assumptions before trusting any finding — the tool
enforces the first and makes the second easy.

## Limitations

- It models faults; it does not prove a given glitcher can land them on real
  silicon. It narrows where to aim and what to harden.
- Results depend on emulator behaviours verified empirically on specific
  Unicorn/Capstone versions; the self-test gates this and the analysis stops if
  it fails.
- Markers (success/fail addresses) must be chosen correctly from the
  disassembly; the oracle check catches a broken harness but not a semantically
  wrong-but-reachable marker.

## Contributing

Issues and pull requests welcome. Please run `--selftest` and `--demo` before
submitting, and add a known-answer test for any new fault model or analysis
stage.

## Credits

Developed at PWNLab.

## License

MIT — see [LICENSE](LICENSE).
