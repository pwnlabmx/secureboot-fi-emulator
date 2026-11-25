# Examples

## Built-in synthetic example

The tool ships a self-contained vulnerable example — no external firmware
needed:

```bash
python3 ../secureboot_fi_emulator.py --demo
```

It builds a tiny Thumb "secure boot" that compares a computed value against an
expected one and branches to accept/reject, then runs the full pipeline against
it and shows the instruction-skip bypasses, their glitch windows, and the
reproduction command. Use it to see the expected output shape before pointing
the tool at a real image.

## Verifying your install

```bash
python3 ../secureboot_fi_emulator.py --selftest
```

Runs the known-answer tests against your Unicorn/Capstone build. If your
versions differ from the ones the fault models were verified against, the
self-test runs automatically before any analysis and stops it on failure.

## A real image, end to end

```bash
# Identify, then look at an unfaulted run
python3 ../secureboot_fi_emulator.py fw.bin --detect
python3 ../secureboot_fi_emulator.py fw.bin --discover --max-instr 2000000

# Pick success/fail markers from the decision points
python3 ../secureboot_fi_emulator.py fw.bin --list-branches

# Harness the verify routine and sweep, with robustness + report
python3 ../secureboot_fi_emulator.py fw.bin \
    --entry 0x0800b4b8 --reg lr=0 \
    --stub 0x0800e88c=rand:8 --calibrate-stubs \
    --success 0x0800b50a --fail 0x0800b4c4 --fail 0x0800b4ea \
    --genuine genuine_fw.bin \
    --bitflip --data-faults --vary-regs 16 --double --rank --explain \
    --verify-fast 200 --json findings.json --report findings.md
```

Addresses above are illustrative — replace them with the entry, stub, and
branch addresses you find for your own image. Do not commit real firmware
images or findings from a third party's device to a public repository.
