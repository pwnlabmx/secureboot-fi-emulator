#!/usr/bin/env python3
r"""
secureboot_fi_emulator.py
=========================

Emulation-based fault-injection (FI) viability analysis for secure-boot and
image-verification code.

Before you put a glitcher (voltage, clock or EM) on a board, this answers two
questions about a boot ROM or bootloader: can a single fault make it accept an
image it should reject, and if so, which instruction should the glitch hit and
how wide is the window? Findings point at the compare or branch that
needs hardening (redundant checks, fail-closed defaults, flow-integrity
counters, random delays). It is an assessment tool: it models faults in an
emulator, it does not drive hardware.

How it works
------------
  1. Detect     Identify the architecture, load base, entry point and initial
                SP from the image itself (ELF header, Cortex-M vector table,
                or Capstone multi-ISA scoring).
  2. Discover   Run the unfaulted firmware and map every peripheral access.
                Diagnose why a run hangs or crashes (status-register poll
                loops, wild jumps, missing ROM) and say what to model.
  3. Model      Give peripherals the values firmware expects (--mmio), stub
                functions that drive hardware or burn time (--stub: hash/PKA
                engines, I2C drivers, delay loops), or start the emulation at
                the verification routine itself (--entry/--sp/--reg).
                --calibrate-stubs measures the condition flags each stubbed
                function really leaves on return (short calls run for real,
                long ones are cut) so a skipped compare after the call sees
                the right flags.
  4. Baseline   Golden run with an image that must FAIL verification. The
                sweep is refused until the baseline reaches the fail branch,
                because results against a broken baseline are meaningless.
  5. Sweep      Re-run once per executed instruction with a single fault:
                  skip     the instruction is not executed (classic glitch)
                  bitflip  one bit of its encoding is flipped, swept over
                           every bit (catches bne->beq, corrupted immediates,
                           wrong destination registers)
                  result_zero / result_ones  (--data-faults)
                           the instruction executes, then its result register
                           is forced to all zeros / all ones, as when a glitch
                           corrupts a load or write-back; compares get their
                           flags cleared / set instead
                plus an optional randomized multi-glitch campaign.
  6. Report     Every fault that flips FAIL into SUCCESS, placed on the
                execution timeline as glitch windows (instruction index from
                entry, approximate cycle offset, window width), with an
                optional JSON export.
  7. Validate   Re-test every finding under several stubbed mismatch values
                (--stub ADDR=V1,V2,.. or rand:N) and random entry-register
                contexts (--vary-regs N). Findings are classified robust,
                context-dependent (kept, with a success rate) or
                value-dependent (dropped as harness artifacts).
  8. Order      Exhaustive double-fault search (--double): the fault-resistance
                order is 1 (one fault bypasses), 2 (only pairs do) or >2.
                Skip-only by default; --double-models skip,bitflip,data lets
                each glitch of a pair be any modelled mechanism, since an
                image that resists two skips may still fall to a mixed pair.
                Second glitches are taken from the path the first one
                produces, so redundant checks the unfaulted run never reaches
                are covered. Pairs are grouped by the second-glitch target to
                show what to harden. --double-max-runs caps the work; a
                truncated search reports the order as not established.
                --skip-window N instead models one wide glitch that removes up
                to N consecutive instructions (a burst), finding bypasses that
                need neither a single precise skip nor two independent faults,
                including ones that skip onto code the golden run never reached.
                --iterations N sweeps loop passes: for instructions run more
                than once it faults visits 0..N-1, catching bypasses that need
                glitching a specific pass of a compare/verify loop, which the
                first-visit sweeps never try.
  9. Rank       Bench target ranking (--rank): each instruction is scored by
                the share of modelled fault mechanisms (skip, encoding bits,
                zero/ones data faults) that bypass, using robust findings
                only, and contiguous targets are grouped into hot zones. A
                physical glitch produces a spread of effects, so high-score
                instructions in wide zones are the most forgiving targets.
 10. Report     Markdown assessment report (--report): summary, harness and
                evidence trail (hashes, versions, self-test), findings with
                robust and context-dependent mechanisms, rule-based weakness
                patterns (instruction class + role of the value + which
                mechanisms bypass) with remediation, bench plan, multi-fault
                resistance and the exact reproduction command.
 11. Retest     Compare with a previous build's --json output (--compare),
                e.g. after a fix. Findings are matched by aligning the
                two execution sequences (addresses normalised away), not by
                address, so inserted or moved code is handled. Old findings
                become closed / reduced / still exploitable / still
                context-dependent / code changed (never counted as closed);
                new findings are flagged as regressions or new code.

Typical workflow
----------------
  python3 secureboot_fi_emulator.py --selftest  # verify this installation
  python3 secureboot_fi_emulator.py fw.bin --detect
  python3 secureboot_fi_emulator.py fw.bin --discover --max-instr 2000000
  python3 secureboot_fi_emulator.py fw.bin --discover --mmio 0x40021000=0x03030003
  python3 secureboot_fi_emulator.py fw.bin --list-branches
  python3 secureboot_fi_emulator.py fw.bin \
      --entry <verify_fn> --reg lr=0 --stub <hash_fn>=rand:8 \
      --calibrate-stubs --success <boot_branch> --fail <reject_branch> \
      --genuine genuine_fw.bin \
      --bitflip --data-faults --vary-regs 16 --double --rank \
      --verify-fast 200 --json findings.json --report findings.md
  python3 secureboot_fi_emulator.py fw_fixed.bin <same harness and models> \
      --compare findings.json --report retest.md     # after a fix
  python3 secureboot_fi_emulator.py --demo      # self-contained example

Use as a library through EmulatorConfig and SecureBootEmulator: golden_run(),
validate_oracle(), sweep_single_skip(), sweep_skip_window(), sweep_iterations(), explain(), random_campaign(), characterize(), discover_mmio(),
diagnose(), assess_robustness(), double_fault_sweep(), calibrate_stubs(),
rank_bench_targets(), write_report(), retest_snapshot(), compare_snapshots(),
detect_architecture(). The library also accepts mmio_read_fn for
peripherals whose value must change over time.

Good practice
-------------
  * Validate the oracle both ways: a genuine image must reach SUCCESS and a
    tampered one FAIL before any sweep is trusted. Pass --genuine <image>
    (or --genuine-stub ADDR=VAL to model a matching measurement) and the
    tool checks both directions unfaulted and refuses to sweep a harness that
    cannot tell the two apart (override with --force). Without it only the
    tamper->FAIL direction is checked.
  * Never trust a single stubbed mismatch value: give --stub several values
    or rand:N. Some apparent bypasses only work for one value (for example a
    stubbed hash of 0x0000 matching a zeroed buffer); the robustness check
    drops them. A value that makes the image verify is excluded automatically.
  * Use --vary-regs to expose findings that only work because of the
    harness's entry register state, then check what the real callers leave
    in those registers.

Engine
------
Every faulted run starts from an identical machine state. By default one
Unicorn instance per configuration is built once and restored between runs
(registers from a CPU context; memory through write-protect dirty-page
tracking; lazily mapped pages unmapped; fault patches undone; translated
code dropped for every restored range). That is about 10x faster than
rebuilding the instance each run and gives identical results;
--verify-fast N checks this on the target being analysed, --no-fast-reset
falls back to fresh instances. The instance is rebuilt every 20000 runs
(--fast-recycle N, 0 = never): one Unicorn instance segfaulted natively
after ~233000 patch/restore cycles in a long mixed-model double search.
Lazily mapped pages (unmodelled data memory) are read/write but never
executable, so a wild jump into them crashes instead of running zeros.

Self-test
---------
Results depend on emulator behaviours found empirically on unicorn 2.1.4
and capstone 5.0.7 (Thumb entry bit, T-bit on PC redirects, FPU enable,
write-protect hooks not retrying, code-cache eviction, no read hooks over
flash). --selftest checks each one, and the end-to-end answers that depend
on them, with 23 known-answer tests; it runs automatically before an
analysis when the installed versions differ from those, and the analysis
stops if it fails.

Supported targets
-----------------
ARM Thumb (Cortex-M, the default), ARM A32, AArch64, x86 and x86-64.
Cortex-M4F/M7 hard-float code is supported (the FPU is enabled in the
emulated core). Unmapped data accesses are mapped lazily as zero pages;
instruction fetches from unmapped memory remain crashes.

Limitations
-----------
  * Emulation, not silicon: results show a fault is logically sufficient,
    not that a specific glitch produces it on a specific chip.
  * Cycle offsets are coarse estimates. The instruction index is the
    deterministic quantity; calibrate timing on the bench.
  * No interrupts or DMA. IRQ-driven drivers must be stubbed or modelled.
  * Faults inside a stubbed function (e.g. a CRC loop) are not explored.
  * A stub only models the return value and, if calibrated or given, the
    exit flags. Other scratch registers keep their pre-call values.
  * The double-fault search covers instruction skips only; bit-flip pairs
    are not searched exhaustively.
  * MMIO values set from the CLI are fixed; use mmio_read_fn for
    peripherals that must change state.

Dependencies: unicorn (2.x), capstone. keystone-engine only for --demo.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import random
import struct
import sys
import dataclasses
import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import capstone
import unicorn
from unicorn import (
    UC_ARCH_ARM,
    UC_ARCH_ARM64,
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_UNMAPPED,
    UC_MODE_32,
    UC_MODE_64,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    Uc,
    UcError,
)


# --------------------------------------------------------------------------- #
# Architecture description
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ArchSpec:
    """Maps an architecture name to Unicorn/Capstone constants and registers."""

    name: str
    uc_arch: int
    uc_mode: int
    cs_arch: int
    cs_mode: int
    pc_reg: int
    sp_reg: int
    # Named general-purpose registers to dump in reports.
    gpr: Dict[str, int]
    # Encoding of a "do nothing" instruction, used by the NOP-patch skip model.
    nop_bytes: bytes
    # ARM Thumb needs the entry address LSB set so Unicorn decodes 2-byte
    # Thumb instructions instead of 4-byte ARM, even with UC_MODE_THUMB.
    thumb: bool = False
    # Calling convention, used by function stubs: the return-value register,
    # and the link register (None = return address is on the stack, x86).
    ret_reg: Optional[int] = None
    lr_reg: Optional[int] = None


def _arm_specs() -> Dict[str, ArchSpec]:
    from unicorn import arm_const as a

    thumb_gpr = {f"r{i}": getattr(a, f"UC_ARM_REG_R{i}") for i in range(13)}
    thumb_gpr.update(
        sp=a.UC_ARM_REG_SP, lr=a.UC_ARM_REG_LR, pc=a.UC_ARM_REG_PC, cpsr=a.UC_ARM_REG_CPSR
    )
    arm_thumb = ArchSpec(
        name="arm-thumb",
        uc_arch=UC_ARCH_ARM,
        uc_mode=UC_MODE_THUMB,
        cs_arch=capstone.CS_ARCH_ARM,
        cs_mode=capstone.CS_MODE_THUMB,
        pc_reg=a.UC_ARM_REG_PC,
        sp_reg=a.UC_ARM_REG_SP,
        gpr=thumb_gpr,
        nop_bytes=b"\x00\xbf",  # thumb: nop
        thumb=True,
        ret_reg=a.UC_ARM_REG_R0,
        lr_reg=a.UC_ARM_REG_LR,
    )
    arm_a32 = ArchSpec(
        name="arm",
        uc_arch=UC_ARCH_ARM,
        uc_mode=UC_MODE_ARM,
        cs_arch=capstone.CS_ARCH_ARM,
        cs_mode=capstone.CS_MODE_ARM,
        pc_reg=a.UC_ARM_REG_PC,
        sp_reg=a.UC_ARM_REG_SP,
        gpr=dict(thumb_gpr),
        nop_bytes=b"\x00\xf0\x20\xe3",  # arm: nop (mov r0,r0 style / nop)
        ret_reg=a.UC_ARM_REG_R0,
        lr_reg=a.UC_ARM_REG_LR,
    )
    return {"arm-thumb": arm_thumb, "thumb": arm_thumb, "arm": arm_a32}


def _arm64_spec() -> Dict[str, ArchSpec]:
    from unicorn import arm64_const as a

    gpr = {f"x{i}": getattr(a, f"UC_ARM64_REG_X{i}") for i in range(31)}
    gpr.update(sp=a.UC_ARM64_REG_SP, pc=a.UC_ARM64_REG_PC)
    return {
        "arm64": ArchSpec(
            name="arm64",
            uc_arch=UC_ARCH_ARM64,
            uc_mode=UC_MODE_ARM,
            cs_arch=capstone.CS_ARCH_ARM64,
            cs_mode=capstone.CS_MODE_ARM,
            pc_reg=a.UC_ARM64_REG_PC,
            sp_reg=a.UC_ARM64_REG_SP,
            gpr=gpr,
            nop_bytes=b"\x1f\x20\x03\xd5",  # aarch64 nop
            ret_reg=a.UC_ARM64_REG_X0,
            lr_reg=a.UC_ARM64_REG_X30,
        )
    }


def _x86_specs() -> Dict[str, ArchSpec]:
    from unicorn import x86_const as a

    g32 = dict(
        eax=a.UC_X86_REG_EAX, ebx=a.UC_X86_REG_EBX, ecx=a.UC_X86_REG_ECX,
        edx=a.UC_X86_REG_EDX, esi=a.UC_X86_REG_ESI, edi=a.UC_X86_REG_EDI,
        esp=a.UC_X86_REG_ESP, ebp=a.UC_X86_REG_EBP, eip=a.UC_X86_REG_EIP,
        eflags=a.UC_X86_REG_EFLAGS,
    )
    g64 = dict(
        rax=a.UC_X86_REG_RAX, rbx=a.UC_X86_REG_RBX, rcx=a.UC_X86_REG_RCX,
        rdx=a.UC_X86_REG_RDX, rsi=a.UC_X86_REG_RSI, rdi=a.UC_X86_REG_RDI,
        rsp=a.UC_X86_REG_RSP, rbp=a.UC_X86_REG_RBP, rip=a.UC_X86_REG_RIP,
    )
    return {
        "x86": ArchSpec("x86", UC_ARCH_X86, UC_MODE_32, capstone.CS_ARCH_X86,
                        capstone.CS_MODE_32, a.UC_X86_REG_EIP, a.UC_X86_REG_ESP,
                        g32, b"\x90", ret_reg=a.UC_X86_REG_EAX),
        "x86-64": ArchSpec("x86-64", UC_ARCH_X86, UC_MODE_64, capstone.CS_ARCH_X86,
                           capstone.CS_MODE_64, a.UC_X86_REG_RIP, a.UC_X86_REG_RSP,
                           g64, b"\x90", ret_reg=a.UC_X86_REG_RAX),
    }


def arch_registry() -> Dict[str, ArchSpec]:
    reg: Dict[str, ArchSpec] = {}
    reg.update(_arm_specs())
    reg.update(_arm64_spec())
    reg.update(_x86_specs())
    return reg


def _unique_specs() -> List[ArchSpec]:
    """Deduplicated list of concrete specs (drops name aliases)."""
    seen: Dict[str, ArchSpec] = {}
    for spec in arch_registry().values():
        seen.setdefault(spec.name, spec)
    return list(seen.values())


# --------------------------------------------------------------------------- #
# Architecture detection
#
# Three independent signals, strongest first:
#   1. ELF header            - authoritative when the image is an ELF.
#   2. Cortex-M vector table - a raw image whose first words look like an
#      initial-SP + reset-vector pair. Strong for the IoT/embedded targets
#      this tool is aimed at, and it also recovers the base and entry.
#   3. Capstone multi-arch scoring - disassemble under each candidate ISA and
#      score by valid-instruction coverage and branch-target sanity.
#
# Detection is heuristic. The result carries a confidence and the full score
# table so you can sanity-check it, and --arch always overrides it.
# --------------------------------------------------------------------------- #
ELF_MACHINE_TO_ARCH = {
    0x28: "arm",      # EM_ARM (thumb vs arm decided by the entry LSB)
    0xB7: "arm64",    # EM_AARCH64
    0x03: "x86",      # EM_386
    0x3E: "x86-64",   # EM_X86_64
}


@dataclass
class DetectionResult:
    arch: str                                   # key into arch_registry()
    confidence: float                           # 0.0 .. 1.0
    method: str                                 # elf | cortex-m-vector | capstone
    base_addr: Optional[int] = None             # recovered when possible
    entry: Optional[int] = None                 # plain address (no thumb bit)
    endianness: str = "little"
    initial_sp: Optional[int] = None            # from the vector table (Cortex-M)
    candidates: List[Tuple[str, float]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def summary(self) -> str:
        out = [
            f"detected arch : {self.arch}  "
            f"(confidence {self.confidence:.0%}, via {self.method})"
        ]
        if self.base_addr is not None:
            out.append(f"  base address : 0x{self.base_addr:08x}")
        if self.entry is not None:
            out.append(f"  entry point  : 0x{self.entry:08x}")
        if self.initial_sp is not None:
            out.append(f"  initial SP   : 0x{self.initial_sp:08x}")
        out.append(f"  endianness   : {self.endianness}")
        if self.candidates:
            ranked = ", ".join(f"{n}={s:.2f}" for n, s in self.candidates[:6])
            out.append(f"  arch scores  : {ranked}")
        for n in self.notes:
            out.append(f"  note         : {n}")
        return "\n".join(out)


def _elf_load_base(data: bytes, ei_class: int, e: str) -> Optional[int]:
    """Minimum p_vaddr across PT_LOAD program headers."""
    try:
        if ei_class == 1:  # ELF32
            e_phoff = struct.unpack_from(e + "I", data, 28)[0]
            e_phentsize = struct.unpack_from(e + "H", data, 42)[0]
            e_phnum = struct.unpack_from(e + "H", data, 44)[0]
            vaddr_off, ptype_off = 8, 0
        else:              # ELF64
            e_phoff = struct.unpack_from(e + "Q", data, 32)[0]
            e_phentsize = struct.unpack_from(e + "H", data, 54)[0]
            e_phnum = struct.unpack_from(e + "H", data, 56)[0]
            vaddr_off, ptype_off = 16, 0
        bases = []
        for i in range(e_phnum):
            ph = e_phoff + i * e_phentsize
            p_type = struct.unpack_from(e + "I", data, ph + ptype_off)[0]
            if p_type == 1:  # PT_LOAD
                if ei_class == 1:
                    vaddr = struct.unpack_from(e + "I", data, ph + vaddr_off)[0]
                else:
                    vaddr = struct.unpack_from(e + "Q", data, ph + vaddr_off)[0]
                bases.append(vaddr)
        return min(bases) if bases else None
    except Exception:
        return None


def _detect_elf(data: bytes) -> Optional[DetectionResult]:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]          # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]           # 1 = little, 2 = big
    endian = "little" if ei_data == 1 else "big"
    e = "<" if ei_data == 1 else ">"
    machine = struct.unpack_from(e + "H", data, 18)[0]
    entry = (struct.unpack_from(e + "I", data, 24)[0] if ei_class == 1
             else struct.unpack_from(e + "Q", data, 24)[0])
    arch = ELF_MACHINE_TO_ARCH.get(machine)
    notes = ["ELF header is authoritative"]
    if arch is None:
        return DetectionResult("?", 0.0, "elf", endianness=endian,
                               notes=[f"unsupported ELF e_machine=0x{machine:x}"])
    if arch == "arm":
        arch = "arm-thumb" if (entry & 1) else "arm"
        notes.append("thumb/arm chosen from entry LSB")
    base = _elf_load_base(data, ei_class, e)
    if arch not in ("x86", "x86-64"):
        notes.append("ELF images should be loaded by segment, not as a flat "
                     "blob; set load_addr/extra_maps accordingly")
    return DetectionResult(arch, 0.99, "elf", base_addr=base,
                           entry=entry & ~1 if arch == "arm-thumb" else entry,
                           endianness=endian, notes=notes)


def _detect_cortex_m(data: bytes) -> Optional[DetectionResult]:
    """ARMv6-M/v7-M/v8-M images start with a vector table: word[0] is the
    initial SP (a RAM address), word[1] is the reset handler (a Thumb address,
    LSB set), followed by exception handlers (also Thumb, LSB set)."""
    if len(data) < 0x40:
        return None
    sp = struct.unpack_from("<I", data, 0)[0]
    reset = struct.unpack_from("<I", data, 4)[0]

    sp_ok = (0x20000000 <= sp <= 0x20080000) or (0x10000000 <= sp <= 0x10020000)
    reset_thumb = bool(reset & 1)
    if not (sp_ok and reset_thumb):
        return None

    handlers = []
    for i in range(1, 16):
        off = 4 * i
        if off + 4 > len(data):
            break
        handlers.append(struct.unpack_from("<I", data, off)[0])
    nonzero = [h for h in handlers if h not in (0, 0xFFFFFFFF)]
    thumb_ratio = (sum(1 for h in nonzero if h & 1) / len(nonzero)
                   if nonzero else 0.0)

    # Recover the base. The vector table sits at image offset 0, so the base
    # must satisfy base <= every target < base + len(image). Among those, take
    # the most-aligned candidate (flash bases are large powers of two, e.g.
    # 0x08000000). Rounding the lowest handler down to a page is wrong for a
    # full flash dump whose handlers live deep in the image.
    targets = [h & ~1 for h in nonzero]
    base = None
    if targets:
        lo, hi = min(targets), max(targets)
        for k in range(28, 11, -1):           # 256 MB alignment down to 4 KB
            cand = lo & ~((1 << k) - 1)
            if hi < cand + len(data):
                base = cand
                break
    entry = reset & ~1

    confidence = 0.6
    if thumb_ratio >= 0.8:
        confidence += 0.25
    if base is not None:
        confidence += 0.1
    confidence = min(confidence, 0.95)

    notes = [f"vector table: SP=0x{sp:08x}, reset=0x{reset:08x}, "
             f"{len(nonzero)} handlers ({thumb_ratio:.0%} Thumb)"]
    if base is None:
        notes.append("could not infer base from vector targets; defaulting")
    return DetectionResult("arm-thumb", confidence, "cortex-m-vector",
                           base_addr=base, entry=entry, endianness="little",
                           initial_sp=sp, notes=notes)


def _score_arch_capstone(data: bytes, spec: ArchSpec,
                         window: int = 0x4000, n_windows: int = 3) -> float:
    """Disassemble several windows under `spec` and return a 0..1 score built
    from valid-instruction coverage and in-range branch targets."""
    size = len(data)
    if size < 16:
        return 0.0
    try:
        cs = capstone.Cs(spec.cs_arch, spec.cs_mode)
        cs.detail = True
    except Exception:
        return 0.0

    step = 2 if spec.thumb else (1 if spec.name.startswith("x86") else 4)
    if size <= window:
        starts = [0]
    else:
        starts = sorted({min(size - window, (size // n_windows) * i)
                         for i in range(n_windows)})

    valid_bytes = total_bytes = n_branch = n_branch_ok = 0
    for ws in starts:
        blob = data[ws:ws + window]
        base = ws
        off, L = 0, len(blob)
        while off < L - 1:
            insn = next(iter(cs.disasm(blob[off:off + 16], base + off, count=1)),
                        None)
            if insn is None:
                off += step
                total_bytes += step
                continue
            valid_bytes += insn.size
            total_bytes += insn.size
            try:
                if (capstone.CS_GRP_JUMP in insn.groups
                        or capstone.CS_GRP_CALL in insn.groups):
                    for op in insn.operands:
                        if op.type == capstone.CS_OP_IMM:
                            n_branch += 1
                            if 0 <= op.imm < size:
                                n_branch_ok += 1
                            break
            except Exception:
                pass
            off += insn.size

    if total_bytes == 0:
        return 0.0
    valid_ratio = valid_bytes / total_bytes
    branch_sanity = (n_branch_ok / n_branch) if n_branch >= 4 else 0.5
    return round(valid_ratio * (0.4 + 0.6 * branch_sanity), 4)


def detect_architecture(data: bytes) -> DetectionResult:
    """Best-effort architecture detection for a firmware image."""
    elf = _detect_elf(data)
    if elf is not None:
        # Still attach capstone scores for transparency.
        elf.candidates = sorted(
            ((s.name, _score_arch_capstone(data, s)) for s in _unique_specs()),
            key=lambda x: -x[1],
        )
        return elf

    scores = sorted(
        ((s.name, _score_arch_capstone(data, s)) for s in _unique_specs()),
        key=lambda x: -x[1],
    )
    best_name, best_score = scores[0]
    second = scores[1][1] if len(scores) > 1 else 0.0

    cortex = _detect_cortex_m(data)
    if cortex is not None:
        cortex.candidates = scores
        if best_name == "arm-thumb":
            cortex.confidence = min(0.97, cortex.confidence + 0.05)
            cortex.notes.append("capstone scoring agrees (arm-thumb)")
        else:
            cortex.notes.append(
                f"capstone top pick was {best_name}; trusting the vector table")
        return cortex

    margin = (best_score - second) / best_score if best_score > 0 else 0.0
    confidence = max(0.0, min(0.9, 0.5 * best_score + 0.5 * margin))
    notes = []
    if margin < 0.1:
        notes.append("top two arches scored close; detection is ambiguous, "
                     "consider passing --arch explicitly")
    if best_score < 0.4:
        notes.append("low absolute score; image may be encrypted, compressed, "
                     "or an unsupported ISA")
    return DetectionResult(best_name, confidence, "capstone-score",
                           candidates=scores, notes=notes)


# --------------------------------------------------------------------------- #
# Fault models
# --------------------------------------------------------------------------- #
class FaultModel(Enum):
    SKIP = "skip"            # skip the whole instruction (the classic glitch)
    BITFLIP = "bitflip"      # flip one bit of the instruction encoding
    SET_REG = "set_reg"      # force a register to a value just before the insn
    FLIP_ZERO = "flip_zero"  # toggle the Zero flag before the insn (ARM only)
    # Data faults: the instruction executes, then its result is corrupted, as
    # when a glitch disturbs a bus read or register write-back (a flash load
    # returning all zeros or all ones). Applied to the destination general-
    # purpose register(s); for compare/test instructions, which only write
    # flags, the NZCV flags are cleared (zero) or set (ones) instead.
    RESULT_ZERO = "result_zero"
    RESULT_ONES = "result_ones"


DATA_FAULT_MODELS = (FaultModel.RESULT_ZERO, FaultModel.RESULT_ONES)


@dataclass
class Fault:
    """A single fault to apply at a given address.

    nth:  apply on the nth time the address is reached (0 = first visit). Lets
          you target a specific loop iteration.
    bit:  for BITFLIP, the bit position within the instruction encoding
          (0 = LSB of the first byte).
    width: for SKIP, how many consecutive executed instructions a single wide
          glitch removes (1 = classic one-instruction skip). width > 1 skips
          this instruction and the next width-1 instructions in execution
          order, whatever addresses they turn out to be, modelling a glitch
          that stays active across several fetches.
    """

    address: int
    model: FaultModel = FaultModel.SKIP
    nth: int = 0
    reg: Optional[str] = None     # for SET_REG
    value: int = 0                # for SET_REG
    bit: Optional[int] = None     # for BITFLIP
    width: int = 1                # for SKIP: consecutive instructions removed

    def __repr__(self) -> str:
        extra = ""
        if self.model is FaultModel.SET_REG:
            extra = f" {self.reg}=0x{self.value:x}"
        if self.model is FaultModel.BITFLIP and self.bit is not None:
            extra = f" bit{self.bit}"
        if self.model is FaultModel.SKIP and self.width > 1:
            extra += f" width{self.width}"
        if self.nth:
            extra += f" @visit#{self.nth}"
        return f"{self.model.value}@0x{self.address:08x}{extra}"


# --------------------------------------------------------------------------- #
# Outcome oracle
# --------------------------------------------------------------------------- #
class Outcome(Enum):
    SUCCESS = "SUCCESS"   # reached the "verification passed" branch
    FAIL = "FAIL"         # reached the "verification failed" branch
    CRASH = "CRASH"       # invalid memory access / illegal instruction
    HANG = "HANG"         # exceeded instruction budget
    UNKNOWN = "UNKNOWN"   # ended without hitting any marker


@dataclass
class RunResult:
    outcome: Outcome
    instr_count: int
    faults: List[Fault] = field(default_factory=list)
    final_regs: Dict[str, int] = field(default_factory=dict)
    trace: List[Tuple[int, int]] = field(default_factory=list)  # (addr, size)
    error: Optional[str] = None
    last_pc: Optional[int] = None   # last instruction reached (crash/hang site)


@dataclass
class OracleResult:
    """Outcome of a two-way oracle check. `sound` means the harness
    distinguishes a rejected image from an accepted one: the tamper image
    (the one under analysis) reaches FAIL unfaulted AND a genuine image
    reaches SUCCESS unfaulted. When no genuine reference is supplied only the
    tamper direction is checked (`genuine_outcome is None`), which catches the
    common misconfiguration where the fail marker is never reached but leaves
    the success side unverified."""

    sound: bool
    tamper_outcome: Outcome
    genuine_outcome: Optional[Outcome]
    messages: List[str] = field(default_factory=list)
    one_way: bool = False   # True when no genuine reference was available

    def to_dict(self) -> dict:
        return {
            "sound": self.sound,
            "one_way": self.one_way,
            "tamper_outcome": self.tamper_outcome.value,
            "genuine_outcome": (self.genuine_outcome.value
                                if self.genuine_outcome is not None else None),
            "messages": list(self.messages),
        }


@dataclass
class Divergence:
    """Where a faulted run's control flow left the unfaulted (golden) path.

    `split_addr` is the last instruction the two runs executed in common;
    from there the glitch sent execution to `faulted_next` instead of the
    golden `golden_next`. This is the control-flow "mechanism of action" of a
    bypass: the specific branch or guard the fault subverted, in terms of
    where execution actually went."""

    split_addr: Optional[int]
    split_text: str
    golden_next: Optional[int]
    faulted_next: Optional[int]
    faulted_outcome: Outcome
    note: str

    def to_dict(self) -> dict:
        return {
            "split_addr": self.split_addr,
            "split_text": self.split_text,
            "golden_next": self.golden_next,
            "faulted_next": self.faulted_next,
            "faulted_outcome": self.faulted_outcome.value,
            "note": self.note,
        }


# --------------------------------------------------------------------------- #
# Glitch-window characterization
# --------------------------------------------------------------------------- #
@dataclass
class GlitchFinding:
    """One fault that flips the boot decision, placed on the execution
    timeline so it can be translated into a bench glitch schedule."""

    model: str
    address: int
    instr_index: int        # position in the golden execution order (0-based)
    cycle_offset: int       # approx. cumulative cycles from entry to this insn
    disasm: str
    bit: Optional[int] = None

    def to_dict(self) -> dict:
        d = {
            "model": self.model,
            "address": f"0x{self.address:08x}",
            "instr_index": self.instr_index,
            "approx_cycle_offset": self.cycle_offset,
            "disasm": self.disasm,
        }
        if self.bit is not None:
            d["bit"] = self.bit
        return d


@dataclass
class GlitchWindow:
    """A contiguous run of exploitable instructions. On a bench you aim the
    trigger delay somewhere in this window; `width` is how forgiving it is."""

    model: str
    start_index: int
    end_index: int
    start_addr: int
    end_addr: int
    width: int
    cycle_start: int
    cycle_end: int

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "instr_index_range": [self.start_index, self.end_index],
            "address_range": [f"0x{self.start_addr:08x}",
                              f"0x{self.end_addr:08x}"],
            "width_instructions": self.width,
            "approx_cycle_range": [self.cycle_start, self.cycle_end],
        }


@dataclass
class Characterization:
    golden_outcome: str
    total_instructions: int
    findings: List[GlitchFinding] = field(default_factory=list)
    windows: List[GlitchWindow] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "golden_outcome": self.golden_outcome,
            "golden_instruction_count": self.total_instructions,
            "fault_injection_viable": bool(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "glitch_windows": [w.to_dict() for w in self.windows],
        }


# --------------------------------------------------------------------------- #
# Finding robustness
#
# A bypass found against ONE harness configuration can be an artifact:
#   value-dependent    it only works for a particular stubbed value (e.g. a
#                      stubbed hash of 0x0000 happens to equal a zeroed
#                      buffer). Real tampered images produce arbitrary values,
#                      so these are dropped.
#   context-dependent  it bypasses for every stub value but only for some
#                      entry register states (e.g. skipping a call works only
#                      because r0 happened to be 0 when the harness started).
#                      Kept, but flagged with its success rate: check what the
#                      real callers leave in those registers.
#   robust             bypasses under every stub value and every valid
#                      register context.
# --------------------------------------------------------------------------- #
ROBUST, CONTEXT_DEP, VALUE_DEP = "robust", "context-dependent", "value-dependent"


@dataclass
class RobustFinding:
    model: str
    address: int
    bit: Optional[int]
    disasm: str
    instr_index: Optional[int]
    status: str
    variants_hit: int
    variants_total: int
    contexts_hit: int = 0
    contexts_valid: int = 0
    hit_variants: List[int] = field(default_factory=list)  # variant indices

    def to_dict(self) -> dict:
        d = {"model": self.model, "address": f"0x{self.address:08x}",
             "disasm": self.disasm, "status": self.status,
             "instr_index": self.instr_index,
             "stub_variants_bypassed": f"{self.variants_hit}/{self.variants_total}"}
        if self.bit is not None:
            d["bit"] = self.bit
        if self.contexts_valid:
            d["register_contexts_bypassed"] = (f"{self.contexts_hit}/"
                                               f"{self.contexts_valid}")
        return d


@dataclass
class RobustnessReport:
    stub_variants: List[Dict[int, int]]
    excluded_variants: List[Dict[int, int]]
    contexts_requested: int
    contexts_valid: int
    findings: List[RobustFinding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def by_status(self, status: str) -> List[RobustFinding]:
        return [f for f in self.findings if f.status == status]

    def to_dict(self) -> dict:
        fmt = lambda v: {f"0x{a:08x}": f"0x{x:x}" for a, x in v.items()}
        return {
            "stub_variants": [fmt(v) for v in self.stub_variants],
            "excluded_stub_variants": [fmt(v) for v in self.excluded_variants],
            "register_contexts": {"requested": self.contexts_requested,
                                  "valid": self.contexts_valid},
            "summary": {s: len(self.by_status(s))
                        for s in (ROBUST, CONTEXT_DEP, VALUE_DEP)},
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }


# --------------------------------------------------------------------------- #
# Fault-resistance order (exhaustive double-fault search)
#
# The order is the minimum number of instruction-skip faults that bypasses
# verification: 1 if any single skip works, 2 if only pairs work, ">2" if no
# pair works. Hardened code (redundant checks) aims for >= 2. Second faults
# are drawn from the path the FIRST fault actually produces, not from the
# unfaulted path: a redundant check that the unfaulted run never reaches only
# becomes a candidate once the first check has been glitched.
# --------------------------------------------------------------------------- #
@dataclass
class FaultPair:
    first: int
    second: int
    second_visit: int      # nth visit of `second` the fault hits (0 = first)
    gap: int               # instructions executed between the two glitches
    first_index: int       # trigger delay of the first glitch (golden path)
    first_disasm: str
    second_disasm: str
    off_golden_path: bool  # second target is never executed without a fault
    first_model: str = "skip"
    first_bit: Optional[int] = None
    second_model: str = "skip"
    second_bit: Optional[int] = None

    @staticmethod
    def mech_label(model: str, bit: Optional[int]) -> str:
        return {"skip": "skip", "result_zero": "result=0",
                "result_ones": "result=~0"}.get(model, f"bitflip b{bit}")

    def to_dict(self) -> dict:
        return {"first": f"0x{self.first:08x}", "first_disasm": self.first_disasm,
                "first_instr_index": self.first_index,
                "first_fault": self.mech_label(self.first_model, self.first_bit),
                "second": f"0x{self.second:08x}", "second_disasm": self.second_disasm,
                "second_fault": self.mech_label(self.second_model, self.second_bit),
                "second_visit": self.second_visit,
                "gap_instructions": self.gap,
                "second_off_golden_path": self.off_golden_path}


@dataclass
class DoubleFaultResult:
    order: str                          # "1", "2" or ">2"
    single_targets: List[int]
    pairs: List[FaultPair]
    firsts_tested: int
    pair_runs: int
    window: Optional[int]
    stub_variants_checked: int = 1
    dropped_value_dependent: int = 0
    truncated: bool = False
    models: List[str] = field(default_factory=lambda: ["skip"])

    def to_dict(self) -> dict:
        return {"fault_order": self.order, "models": self.models,
                "single_skip_targets": [f"0x{a:08x}" for a in self.single_targets],
                "double_fault_pairs": [p.to_dict() for p in self.pairs],
                "first_faults_tested": self.firsts_tested,
                "pair_runs": self.pair_runs,
                "max_gap_instructions": self.window,
                "stub_variants_checked": self.stub_variants_checked,
                "value_dependent_pairs_dropped": self.dropped_value_dependent,
                "search_truncated": self.truncated}


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class EmulatorConfig:
    arch: str = "arm-thumb"

    # Memory layout.
    load_addr: int = 0x08000000      # where the firmware image is mapped
    load_size: int = 0x00100000      # size of the mapped flash region (rounded up)
    stack_addr: int = 0x20000000     # base of a mapped RAM/stack region
    stack_size: int = 0x00010000
    extra_maps: List[Tuple[int, int]] = field(default_factory=list)  # (addr, size)

    entry: int = 0x08000000          # where execution starts (plain address)
    initial_sp: Optional[int] = None  # defaults to top of stack region

    # Outcome oracle. Provide addresses you recovered statically, and/or
    # register predicates evaluated when execution stops.
    success_addrs: Tuple[int, ...] = ()
    fail_addrs: Tuple[int, ...] = ()
    success_fn: Optional[Callable[[Dict[str, int]], bool]] = None
    fail_fn: Optional[Callable[[Dict[str, int]], bool]] = None

    # Pre-seed registers before every run (e.g. r0=ptr to image header).
    initial_regs: Dict[str, int] = field(default_factory=dict)

    max_instr: int = 20000           # per-run instruction budget (anti-hang)

    # The skip model. "pc" advances PC in the code hook (no memory mutation,
    # fastest). "nop" patches the instruction bytes to a NOP for the run.
    skip_method: str = "pc"

    # --- Peripheral (MMIO) modeling & robust memory handling ---
    # Real firmware constantly touches peripheral registers (clock, flash,
    # crypto, GPIO) and RAM regions you have not mapped. Without this the
    # golden run crashes on the first such access. These options keep
    # emulation alive and let you model what peripherals return.
    #
    # auto_map_unmapped: lazily map a zero page on any access to unmapped
    #   memory and continue, instead of crashing. Models a CPU that keeps
    #   running. Strays are recorded and surfaced by discover_mmio().
    auto_map_unmapped: bool = True
    unmapped_fill: int = 0x00         # byte value for lazily-mapped pages
    # mmio_regions: (addr, size) ranges to pre-map as peripheral space.
    mmio_regions: List[Tuple[int, int]] = field(default_factory=list)
    # mmio_reads: fixed value returned when the firmware reads this address
    #   (e.g. {0x40000000: 1} to make a "ready" bit set so a poll loop exits).
    mmio_reads: Dict[int, int] = field(default_factory=dict)
    # mmio_read_fn: handler(address, size) -> value|None, consulted for reads
    #   inside declared mmio_regions when the address is not in mmio_reads.
    mmio_read_fn: Optional[Callable[[int, int], Optional[int]]] = None
    # mmio_default: value for MMIO-region reads not covered above
    #   (None = whatever the page holds, i.e. 0).
    mmio_default: Optional[int] = None

    # stubs: {function_address: return_value}. When execution reaches the
    #   address, the function is not run: the return register is set and
    #   control returns to the caller. Use it for HAL/ROM routines that drive
    #   hardware you cannot emulate (hash engine, PKA, OTP reads), and to force
    #   the "signature invalid" baseline, e.g. {verify_signature: 0}.
    stubs: Dict[int, int] = field(default_factory=dict)

    # stub_exit_flags: {function_address: NZCV} condition flags a stub leaves
    #   on return (bit 3 = N, 2 = Z, 1 = C, 0 = V; x86 maps to SF/ZF/CF/OF).
    #   A caller may branch on flags the callee left if the compare after the
    #   call is skipped, so a stub that keeps the CALLER's flags can hide
    #   real single-fault bypasses. Measure them with calibrate_stubs().
    stub_exit_flags: Dict[int, int] = field(default_factory=dict)

    # stub_try_real_budget: calibration mode. Stubbed functions execute for
    #   real; calls that finish within this many instructions are logged with
    #   their exit flags, longer calls are cut and returned as stubs.
    stub_try_real_budget: Optional[int] = None

    # fast_reset: reuse one Unicorn instance per configuration and restore it
    #   between runs instead of rebuilding it (see the fast-reset engine).
    fast_reset: bool = True

    # fast_recycle: rebuild the persistent fast-reset instance after this many
    #   runs. Unicorn accumulates native state (translated-block cache, page
    #   tables) across hundreds of thousands of patch/restore cycles and was
    #   observed to segfault after ~233,000 runs in one instance; recycling
    #   bounds that state. 0 disables recycling.
    fast_recycle: int = 20_000


def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping/adjacent [begin, end) intervals."""
    out: List[Tuple[int, int]] = []
    for b, e in sorted(ranges):
        if out and b <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((b, e))
    return out


# --------------------------------------------------------------------------- #
# The emulator
# --------------------------------------------------------------------------- #
class SecureBootEmulator:
    def __init__(self, firmware: bytes, cfg: EmulatorConfig):
        self.fw = firmware
        self.cfg = cfg
        registry = arch_registry()
        # arch="auto" triggers detection from the image itself.
        self.detection: Optional[DetectionResult] = None
        if cfg.arch == "auto":
            self.detection = detect_architecture(firmware)
            if self.detection.arch not in registry:
                raise ValueError(
                    "could not detect a supported architecture; set "
                    "cfg.arch explicitly. " + "; ".join(self.detection.notes)
                )
            cfg.arch = self.detection.arch
        if cfg.arch not in registry:
            raise ValueError(
                f"unknown arch '{cfg.arch}'. known: {sorted(registry)}"
            )
        self.spec = registry[cfg.arch]
        self.cs = capstone.Cs(self.spec.cs_arch, self.spec.cs_mode)
        self.cs.detail = False
        self._golden: Optional[RunResult] = None
        self._oracle: Optional[OracleResult] = None
        self._stub_log: Optional[list] = None   # filled in calibration mode

    # -- memory / uc setup ------------------------------------------------- #
    def _page_align(self, size: int, page: int = 0x1000) -> int:
        return (size + page - 1) & ~(page - 1)

    def _new_uc(self, mmio_log: Optional[list] = None,
                track: Optional[dict] = None) -> Uc:
        uc = Uc(self.spec.uc_arch, self.spec.uc_mode)

        # Enable the FPU. Unicorn models an A-profile core, where VFP is gated
        # by CPACR (cp10/cp11 access) and FPEXC.EN. Cortex-M4F/M7 firmware
        # enables its FPU through the memory-mapped SCB->CPACR instead, which
        # Unicorn never sees, so the first vmsr/vldr would fault.
        if self.spec.uc_arch == UC_ARCH_ARM:
            from unicorn import arm_const as _a
            try:
                uc.reg_write(_a.UC_ARM_REG_C1_C0_2, 0x00F00000)
                uc.reg_write(_a.UC_ARM_REG_FPEXC, 0x40000000)
            except UcError:
                pass

        # Map and load the firmware region.
        fw_region = self._page_align(max(self.cfg.load_size, len(self.fw)))
        uc.mem_map(self.cfg.load_addr, fw_region)
        uc.mem_write(self.cfg.load_addr, self.fw)

        # Map stack / RAM.
        uc.mem_map(self.cfg.stack_addr, self._page_align(self.cfg.stack_size))
        for addr, size in self.cfg.extra_maps:
            uc.mem_map(addr, self._page_align(size))

        sp = self.cfg.initial_sp
        if sp is None:
            sp = self.cfg.stack_addr + self.cfg.stack_size - 0x10
        uc.reg_write(self.spec.sp_reg, sp)

        for name, val in self.cfg.initial_regs.items():
            uc.reg_write(self._reg(name), val)

        self._install_memory_model(uc, mmio_log, track)
        return uc

    # -- peripheral / MMIO modeling ---------------------------------------- #
    def _mmio_value(self, address: int, size: int) -> Optional[int]:
        """Modeled value for a read inside MMIO space (None = leave as-is)."""
        if address in self.cfg.mmio_reads:
            return self.cfg.mmio_reads[address]
        if self.cfg.mmio_read_fn is not None:
            v = self.cfg.mmio_read_fn(address, size)
            if v is not None:
                return v
        return self.cfg.mmio_default

    def _install_memory_model(self, uc: Uc, mmio_log: Optional[list],
                              track: Optional[dict] = None) -> None:
        cfg = self.cfg

        # Pre-map declared MMIO regions plus the page of every modeled address.
        ranges: List[Tuple[int, int]] = []

        def _premap(base: int, size: int) -> None:
            b = base & ~0xFFF
            end = (base + max(size, 1) + 0xFFF) & ~0xFFF
            try:
                uc.mem_map(b, end - b)
            except UcError:
                pass  # already mapped (overlaps firmware/RAM) - fine
            ranges.append((b, end))

        for a, s in cfg.mmio_regions:
            _premap(a, s)
        for a in cfg.mmio_reads:
            _premap(a, 1)

        if ranges:
            merged = _merge_ranges(ranges)

            def on_read(uc_, access, address, size, value, _ud):
                v = self._mmio_value(address, size)
                if v is not None:
                    mask = (1 << (size * 8)) - 1
                    try:
                        uc_.mem_write(address,
                                      int(v & mask).to_bytes(size, "little"))
                        if track is not None:   # host writes bypass write-protect
                            track["dirty"].add(address & ~(track["page"] - 1))
                    except Exception:
                        pass

            for b, e in merged:
                uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=b, end=e - 1)

        # Lazy-map any stray access so emulation survives instead of crashing.
        if cfg.auto_map_unmapped:
            fill = cfg.unmapped_fill & 0xFF

            def on_unmapped(uc_, access, address, size, value, _ud):
                # Never map on instruction FETCH: a fault that sends PC into
                # unmapped space must stay a CRASH. Silently executing a fresh
                # zero page would mask wild jumps and burn the instr budget.
                if access == unicorn.UC_MEM_FETCH_UNMAPPED:
                    if mmio_log is not None and len(mmio_log) < 50000:
                        mmio_log.append((uc_.reg_read(self.spec.pc_reg),
                                         address, size, "wild-fetch", None))
                    return False
                page = address & ~0xFFF
                try:
                    # Data only: a lazily mapped page holds no modelled code,
                    # and Cortex-M peripheral/device regions are execute-never.
                    # A later jump into it must crash, not run zero bytes.
                    uc_.mem_map(page, 0x1000,
                                unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE)
                    if track is not None:
                        track["lazy"].add(page)
                    if fill:
                        uc_.mem_write(page, bytes([fill]) * 0x1000)
                except UcError:
                    pass
                return True  # handled -> Unicorn retries the access

            uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

        # Discovery mode only: log every access outside flash/RAM (i.e. to
        # peripheral space) so poll loops and register writes are visible.
        if mmio_log is not None:
            known = [(cfg.load_addr,
                      cfg.load_addr + self._page_align(max(cfg.load_size,
                                                           len(self.fw)))),
                     (cfg.stack_addr,
                      cfg.stack_addr + self._page_align(cfg.stack_size))]
            known += [(a, a + self._page_align(sz)) for a, sz in cfg.extra_maps]

            def on_access(uc_, access, address, size, value, _ud):
                for b, e in known:
                    if b <= address < e:
                        return
                if len(mmio_log) < 50000:
                    kind = "write" if access == unicorn.UC_MEM_WRITE else "read"
                    mmio_log.append((uc_.reg_read(self.spec.pc_reg), address,
                                     size, kind,
                                     value if kind == "write" else None))

            # Hook only the GAPS between known regions. A memory-read hook that
            # covers the executing flash derails Unicorn 2.x on real Cortex-M
            # images (observed: UC_ERR_INSN_INVALID inside the C-runtime copy
            # loop), which would make discovery report a bogus path.
            top = 0xFFFFFFFFFFFFFFFF if self.spec.name in ("arm64", "x86-64") \
                else 0xFFFFFFFF
            cursor = 0
            for b, e in _merge_ranges(known):
                if b > cursor:
                    uc.hook_add(UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
                                on_access, begin=cursor, end=b - 1)
                cursor = max(cursor, e)
            if cursor <= top:
                uc.hook_add(UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE,
                            on_access, begin=cursor, end=top)

    def _reg(self, name: str) -> int:
        key = name.lower()
        if key not in self.spec.gpr:
            raise ValueError(f"register '{name}' not known for {self.spec.name}")
        return self.spec.gpr[key]

    def _dump_regs(self, uc: Uc) -> Dict[str, int]:
        return {n: uc.reg_read(c) for n, c in self.spec.gpr.items()}

    # -- oracle ------------------------------------------------------------ #
    def _check_markers(self, address: int) -> Optional[Outcome]:
        if address in self.cfg.success_addrs:
            return Outcome.SUCCESS
        if address in self.cfg.fail_addrs:
            return Outcome.FAIL
        return None

    def _check_predicates(self, regs: Dict[str, int]) -> Optional[Outcome]:
        if self.cfg.success_fn and self.cfg.success_fn(regs):
            return Outcome.SUCCESS
        if self.cfg.fail_fn and self.cfg.fail_fn(regs):
            return Outcome.FAIL
        return None

    # -- core run ---------------------------------------------------------- #
    def run(self, faults: Sequence[Fault] = (), record_trace: bool = False,
            mmio_log: Optional[list] = None) -> RunResult:
        """Run the firmware once, applying `faults`. Returns a RunResult.

        mmio_log: if a list is passed (discovery mode), every access outside
        flash/RAM is appended as (pc, address, size, kind, value) with kind in
        read | write | wild-fetch. Used by discover_mmio().

        Runs on the fast-reset engine (one persistent Unicorn instance,
        restored between runs) unless cfg.fast_reset is off or the run needs
        discovery logging or stub calibration, which use a fresh instance.
        """
        fast = (self.cfg.fast_reset and mmio_log is None
                and self.cfg.stub_try_real_budget is None)
        uc = self._fast_acquire() if fast else self._new_uc(mmio_log=mmio_log)
        patches: List[Tuple[int, bytes]] = []
        try:
            # NOP-patch skip model: patch instruction bytes before the run.
            if self.cfg.skip_method == "nop":
                for f in faults:
                    if f.model is FaultModel.SKIP and f.width <= 1:
                        self._patch(uc, f.address, self.spec.nop_bytes, patches)
                    # width>1 (wide-glitch window) is always handled in
                    # _on_code so the skip follows real execution order.

            # BITFLIP: corrupt one bit of the instruction encoding in place.
            # This models a glitch that mangles the fetched/decoded instruction
            # rather than skipping it, and catches bypasses skip cannot (e.g.
            # turning a bne into beq, or flipping an immediate). The patch is
            # undone after the run.
            for f in faults:
                if f.model is FaultModel.BITFLIP and f.bit is not None:
                    size = self._insn_size(f.address)
                    b = f.bit % (size * 8)
                    buf = bytearray(uc.mem_read(f.address, size))
                    buf[b // 8] ^= (1 << (b % 8))
                    self._patch(uc, f.address, bytes(buf), patches)

            fault_map: Dict[int, List[Fault]] = {}
            for f in faults:
                fault_map.setdefault(f.address, []).append(f)

            state = {
                "count": 0,
                "outcome": Outcome.UNKNOWN,
                "trace": [],
                "visits": {},  # address -> times seen
                "last_pc": None,
                "stub_active": None,
                "post": None,          # pending data fault for the previous insn
                "skip_remaining": 0,   # instructions left in a wide-glitch skip
            }
            ctx = {"state": state, "fault_map": fault_map,
                   "record_trace": record_trace}
            if fast:
                self._fast_ctx = ctx
            else:
                uc.hook_add(UC_HOOK_CODE,
                            lambda uc_, a, sz, _ud: self._on_code(uc_, a, sz, ctx))

            # Thumb: set the entry LSB so Unicorn decodes 2-byte Thumb, not ARM.
            begin = (self.cfg.entry | 1) if self.spec.thumb else self.cfg.entry
            try:
                # count acts as a hard backstop in addition to the hook budget.
                uc.emu_start(begin, until=0xFFFFFFFFFFFFFFFF,
                             count=self.cfg.max_instr + 8)
            except UcError as e:
                if state["outcome"] in (Outcome.UNKNOWN,):
                    state["outcome"] = Outcome.CRASH
                regs = self._dump_regs(uc)
                return RunResult(state["outcome"], state["count"], list(faults),
                                 regs, state["trace"], error=str(e),
                                 last_pc=state["last_pc"])

            regs = self._dump_regs(uc)
            if state["outcome"] in (Outcome.UNKNOWN,):
                pred = self._check_predicates(regs)
                if pred is not None:
                    state["outcome"] = pred

            return RunResult(state["outcome"], state["count"], list(faults),
                             regs, state["trace"], last_pc=state["last_pc"])
        finally:
            if fast:
                self._fast_release(uc, patches)

    def _on_code(self, uc_: Uc, address: int, size: int, ctx: dict) -> None:
        """Per-instruction logic shared by the fresh and fast-reset engines."""
        state = ctx["state"]
        state["count"] += 1
        state["last_pc"] = address
        if state["count"] > self.cfg.max_instr:
            state["outcome"] = Outcome.HANG
            uc_.emu_stop()
            return

        # A data fault fires after its instruction has written back, i.e.
        # at the next instruction boundary, before anything else here.
        if state["post"] is not None:
            model_, target_ = state["post"]
            state["post"] = None
            self._apply_result_fault(uc_, model_, target_)

        if ctx["record_trace"]:
            state["trace"].append((address, size))

        # Oracle first: stop the moment we reach a decision marker.
        marker = self._check_markers(address)
        if marker is not None:
            state["outcome"] = marker
            uc_.emu_stop()
            return

        # Inside a wide-glitch skip window: remove this instruction too. The
        # marker check above still runs, so a window that skips onto a SUCCESS
        # or FAIL marker is detected. Markers aside, the glitch stays active
        # for `width` consecutive fetches whatever addresses they are.
        if state["skip_remaining"] > 0:
            state["skip_remaining"] -= 1
            new_pc = address + size
            if self.spec.thumb:
                new_pc |= 1
            uc_.reg_write(self.spec.pc_reg, new_pc)
            return

        # Apply any fault registered at this address.
        redirected = False
        flist = ctx["fault_map"].get(address)
        if flist:
            visit = state["visits"].get(address, 0)
            for f in flist:
                if f.nth != visit:
                    continue
                if f.model is FaultModel.SKIP and f.width > 1:
                    # Wide glitch: skip this instruction (PC advance) and arm
                    # the window for the next width-1 instructions.
                    state["skip_remaining"] = f.width - 1
                    new_pc = address + size
                    if self.spec.thumb:
                        new_pc |= 1
                    uc_.reg_write(self.spec.pc_reg, new_pc)
                    redirected = True
                elif f.model is FaultModel.SKIP and self.cfg.skip_method == "pc":
                    # Advance PC past this instruction: the glitch skip.
                    # Thumb: keep the T-bit set or execution decodes as ARM.
                    new_pc = address + size
                    if self.spec.thumb:
                        new_pc |= 1
                    uc_.reg_write(self.spec.pc_reg, new_pc)
                    redirected = True
                elif f.model is FaultModel.SET_REG:
                    uc_.reg_write(self._reg(f.reg), f.value)
                elif f.model in DATA_FAULT_MODELS:
                    state["post"] = (f.model, address)
                elif f.model is FaultModel.FLIP_ZERO:
                    self._flip_zero_flag(uc_)
            state["visits"][address] = visit + 1

        # Function stubs.
        if redirected:
            return
        if self.cfg.stub_try_real_budget is not None:
            self._stub_try_real(uc_, address, state, self.cfg.stubs)
        elif address in self.cfg.stubs:
            self._return_from_stub(uc_, self.cfg.stubs[address], address)

    # -- fast-reset engine ------------------------------------------------- #
    # Building a Unicorn instance and copying a 1 MB image into it costs
    # ~3.5 ms, typically more than the faulted run itself. The fast engine
    # builds one instance, snapshots it, and restores it after every run:
    #   registers   CPU context save/restore
    #   memory      every region mapped at build time is write-protected;
    #               the first write to a page traps, the hook unlocks the page
    #               and performs the write itself, and the page is marked
    #               dirty. After the run, dirty pages are rewritten from the
    #               pristine copy and re-protected (cost ~ pages written).
    #   lazy pages  pages mapped on demand during the run are unmapped
    #   patches     bit-flip / NOP patches are undone
    #   code cache  translated blocks of every restored range are dropped
    # Unicorn's own CPU+memory snapshots segfault when memory is mapped after
    # the snapshot (lazy mapping does exactly that), so they are not used.
    def _patch(self, uc: Uc, address: int, data: bytes,
               patches: List[Tuple[int, bytes]]) -> None:
        try:
            orig = bytes(uc.mem_read(address, len(data)))
        except UcError:
            return          # nothing mapped there: the patch cannot apply
        patches.append((address, orig))
        uc.mem_write(address, data)
        uc.ctl_remove_cache(address, address + len(data))

    def _fast_acquire(self) -> Uc:
        uc = self.__dict__.get("_fast_uc")
        n = self.__dict__.get("_fast_runs", 0)
        if uc is not None and self.cfg.fast_recycle and n >= self.cfg.fast_recycle:
            self.close()            # bound Unicorn's accumulated native state
            uc, n = None, 0
        if uc is None:
            uc = self._fast_build()
            self._fast_uc = uc
        self._fast_runs = n + 1
        return uc

    def _fast_build(self) -> Uc:
        track = {"dirty": set(), "lazy": set()}
        uc = self._new_uc(mmio_log=None, track=track)
        ps = uc.ctl_get_page_size()
        track["page"] = ps
        pristine = []
        for b, e, _perms in uc.mem_regions():
            pristine.append((b, e + 1, bytes(uc.mem_read(b, e + 1 - b))))
            uc.mem_protect(b, e + 1 - b, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)

        def on_write_prot(uc_, access, address, size, value, _ud):
            p, last = address & ~(ps - 1), (address + size - 1) & ~(ps - 1)
            while p <= last:
                if p not in track["dirty"]:
                    track["dirty"].add(p)
                    uc_.mem_protect(p, ps, unicorn.UC_PROT_ALL)
                p += ps
            # Unicorn does not retry the access, so perform it here.
            uc_.mem_write(address,
                          (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little"))
            return True

        uc.hook_add(unicorn.UC_HOOK_MEM_WRITE_PROT, on_write_prot)
        uc.hook_add(UC_HOOK_CODE,
                    lambda uc_, a, sz, _ud: self._on_code(uc_, a, sz, self._fast_ctx))
        self._fast_track = track
        self._fast_pristine = pristine
        self._fast_ctx0 = uc.context_save()
        self._fast_ctx = None
        return uc

    def _fast_release(self, uc: Uc, patches: List[Tuple[int, bytes]]) -> None:
        track, ps = self._fast_track, self._fast_track["page"]
        for address, orig in reversed(patches):
            uc.mem_write(address, orig)
            uc.ctl_remove_cache(address, address + len(orig))
        for p in track["dirty"]:
            for b, e, data in self._fast_pristine:
                if b <= p < e:
                    uc.mem_write(p, data[p - b:p - b + ps])
                    uc.mem_protect(p, ps, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
                    break
            uc.ctl_remove_cache(p, p + ps)
        for p in track["lazy"]:
            uc.mem_unmap(p, 0x1000)
            uc.ctl_remove_cache(p, p + 0x1000)
        track["dirty"].clear()
        track["lazy"].clear()
        uc.context_restore(self._fast_ctx0)
        self._fast_ctx = None

    def close(self) -> None:
        """Release the persistent fast-reset instance (rebuilt on demand)."""
        self.__dict__.pop("_fast_uc", None)
        self._fast_runs = 0

    def verify_fast_reset(self, n: int = 200, seed: int = 0) -> List[str]:
        """Self-check: run `n` random single and double faults (all models)
        in random order on the fast engine and on fresh instances, and return
        a description of every run whose outcome, instruction count, last PC
        or final registers differ. An empty list means equivalent."""
        if self._golden is None:
            self.golden_run()
        fresh = SecureBootEmulator(self.fw, dataclasses.replace(self.cfg, fast_reset=False))
        addrs = sorted({a for a, _ in self._golden.trace})
        rng = random.Random(seed)
        models = [FaultModel.SKIP, FaultModel.BITFLIP] + list(DATA_FAULT_MODELS)

        def one(a):
            m = rng.choice(models)
            bit = rng.randrange(self._insn_size(a) * 8) if m is FaultModel.BITFLIP else None
            return Fault(a, m, bit=bit)

        mismatches = []
        for i in range(n):
            k = rng.choice((0, 1, 1, 2))
            faults = [one(rng.choice(addrs)) for _ in range(k)]
            a, b = self.run(faults=faults), fresh.run(faults=faults)
            if (a.outcome, a.instr_count, a.last_pc, a.final_regs) != \
               (b.outcome, b.instr_count, b.last_pc, b.final_regs):
                mismatches.append(f"run {i} {faults}: fast {a.outcome.value}/"
                                  f"{a.instr_count} vs fresh {b.outcome.value}/"
                                  f"{b.instr_count}")
        return mismatches

    # -- condition flags as an NZCV nibble -------------------------------- #
    _X86_NZCV_BITS = (7, 6, 0, 11)   # SF, ZF, CF, OF

    def _flags_reg(self) -> Optional[int]:
        if self.spec.uc_arch == UC_ARCH_ARM:
            from unicorn import arm_const as _a
            return _a.UC_ARM_REG_CPSR
        if self.spec.uc_arch == UC_ARCH_ARM64:
            from unicorn import arm64_const as _a
            return _a.UC_ARM64_REG_NZCV
        if self.spec.uc_arch == UC_ARCH_X86:
            from unicorn import x86_const as _a
            return (_a.UC_X86_REG_RFLAGS if self.spec.name == "x86-64"
                    else _a.UC_X86_REG_EFLAGS)
        return None

    def _read_nzcv(self, uc: Uc) -> Optional[int]:
        reg = self._flags_reg()
        if reg is None:
            return None
        v = uc.reg_read(reg)
        if self.spec.uc_arch == UC_ARCH_X86:
            return sum(((v >> b) & 1) << (3 - i)
                       for i, b in enumerate(self._X86_NZCV_BITS))
        return (v >> 28) & 0xF

    def _write_nzcv(self, uc: Uc, nzcv: int) -> None:
        reg = self._flags_reg()
        if reg is None:
            return
        v = uc.reg_read(reg)
        if self.spec.uc_arch == UC_ARCH_X86:
            for i, b in enumerate(self._X86_NZCV_BITS):
                v = (v & ~(1 << b)) | (((nzcv >> (3 - i)) & 1) << b)
        else:
            v = (v & 0x0FFFFFFF) | ((nzcv & 0xF) << 28)
        uc.reg_write(reg, v)

    def _stub_try_real(self, uc: Uc, address: int, state: dict,
                       stubs: Dict[int, int]) -> None:
        """Calibration mode: let stubbed functions run; log the exit state
        of calls that finish within budget, cut the rest."""
        spec, act = self.spec, state["stub_active"]
        budget = self.cfg.stub_try_real_budget
        log = self._stub_log if self._stub_log is not None else []
        if act is not None:
            if address == act["ret"] and uc.reg_read(spec.sp_reg) == act["sp_after"]:
                log.append((act["addr"], "completed", self._read_nzcv(uc),
                            state["count"] - act["start"]))
                state["stub_active"] = None
            elif state["count"] - act["start"] > budget:
                for n, v in act["regs"].items():
                    uc.reg_write(spec.gpr[n], v)
                if spec.ret_reg is not None:
                    uc.reg_write(spec.ret_reg, stubs[act["addr"]])
                uc.reg_write(spec.sp_reg, act["sp_after"])
                uc.reg_write(spec.pc_reg, act["ret_pc"])
                log.append((act["addr"], "cut", None, budget))
                state["stub_active"] = None
                return
            if state["stub_active"] is not None:
                if address in stubs and address != act["addr"]:
                    self._return_from_stub(uc, stubs[address], address)  # nested
                return
        if address in stubs:
            regs = {n: uc.reg_read(c) for n, c in spec.gpr.items()
                    if n not in ("pc", "cpsr", "eflags", "eip", "rip")}
            sp = uc.reg_read(spec.sp_reg)
            if spec.lr_reg is not None:
                ret_pc = uc.reg_read(spec.lr_reg)
                ret, sp_after = ret_pc & ~1, sp
            else:
                width = 8 if spec.name == "x86-64" else 4
                ret_pc = int.from_bytes(uc.mem_read(sp, width), "little")
                ret, sp_after = ret_pc, sp + width
            state["stub_active"] = dict(addr=address, ret=ret, ret_pc=ret_pc,
                                        sp_after=sp_after, start=state["count"],
                                        regs=regs)

    def calibrate_stubs(self, per_call_budget: int = 500_000) -> Dict[int, dict]:
        """Measure the condition flags each stubbed function really leaves.

        Runs the unfaulted path with stubbed functions executing for real.
        Calls that return within `per_call_budget` instructions report their
        exit flags; longer calls (a CRC over a whole image) are cut and
        returned with the stub value, registers restored to call entry, so
        later, shorter calls to the same function still get measured.
        Returns {address: {calls, completed, cut, exit_flags: [NZCV..],
        max_instructions}}."""
        cfg = dataclasses.replace(
            self.cfg, stub_try_real_budget=per_call_budget,
            max_instr=self.cfg.max_instr + per_call_budget * 32)
        emu = SecureBootEmulator(self.fw, cfg)
        emu._stub_log = []
        emu.run()
        out: Dict[int, dict] = {}
        for addr in self.cfg.stubs:
            calls = [l for l in emu._stub_log if l[0] == addr]
            done = [l for l in calls if l[1] == "completed"]
            out[addr] = {"calls": len(calls), "completed": len(done),
                         "cut": len(calls) - len(done),
                         "exit_flags": sorted({l[2] for l in done if l[2] is not None}),
                         "max_instructions": max((l[3] for l in done), default=0)}
        return out

    def _return_from_stub(self, uc: Uc, value: int,
                          address: Optional[int] = None) -> None:
        """Emulate `return value;` from the current function entry, leaving
        the modeled exit flags if any are configured for this stub."""
        spec = self.spec
        if address is not None and address in self.cfg.stub_exit_flags:
            self._write_nzcv(uc, self.cfg.stub_exit_flags[address])
        if spec.ret_reg is not None:
            uc.reg_write(spec.ret_reg, value)
        if spec.lr_reg is not None:
            # ARM/AArch64: return to LR. A Thumb LR already carries the T-bit.
            uc.reg_write(spec.pc_reg, uc.reg_read(spec.lr_reg))
        else:
            # x86: pop the return address off the stack.
            width = 8 if spec.name == "x86-64" else 4
            sp = uc.reg_read(spec.sp_reg)
            ret = int.from_bytes(uc.mem_read(sp, width), "little")
            uc.reg_write(spec.sp_reg, sp + width)
            uc.reg_write(spec.pc_reg, ret)

    def _flip_zero_flag(self, uc: Uc) -> None:
        if self.spec.name.startswith("arm") and "cpsr" in self.spec.gpr:
            cpsr = uc.reg_read(self.spec.gpr["cpsr"])
            uc.reg_write(self.spec.gpr["cpsr"], cpsr ^ (1 << 30))  # Z bit
        elif self.spec.name.startswith("x86") and "eflags" in self.spec.gpr:
            fl = uc.reg_read(self.spec.gpr["eflags"])
            uc.reg_write(self.spec.gpr["eflags"], fl ^ (1 << 6))   # ZF

    # -- golden baseline --------------------------------------------------- #
    def golden_run(self) -> RunResult:
        """Run with no faults and capture the execution trace."""
        self._golden = self.run(faults=(), record_trace=True)
        return self._golden

    def validate_oracle(self, genuine_firmware: Optional[bytes] = None,
                        genuine_stubs: Optional[Dict[int, int]] = None
                        ) -> OracleResult:
        """Check the harness can tell a rejected image from an accepted one.

        Without this, a misconfigured harness (wrong success/fail address, a
        stub that derails, an oracle that never reaches its fail branch) still
        produces a sweep full of "bypasses" that mean nothing. The sweep looks
        for faults that turn FAIL into SUCCESS, so both ends of that must be
        real first.

        Two directions are checked, both with NO faults:
          * the image under analysis (the tamper image) must reach a FAIL
            marker, and
          * a genuine image must reach a SUCCESS marker. The genuine reference
            is either `genuine_firmware` (a separate accepted image, run under
            the same harness) or `genuine_stubs` (the same image run with stub
            return values that model a matching measurement, e.g. the real
            hash of the image). With neither, only the tamper direction is
            checked and the result is marked one-way.

        Never raises on an unsound oracle; it returns the verdict so the caller
        can warn or refuse to sweep. Does not disturb the fast-reset state of
        this instance (the genuine reference runs on a sibling instance)."""
        msgs: List[str] = []
        if not self.cfg.success_addrs and self.cfg.success_fn is None:
            msgs.append("no success marker configured: the sweep has no "
                        "SUCCESS branch to aim for.")
        if not self.cfg.fail_addrs and self.cfg.fail_fn is None:
            msgs.append("no fail marker configured: cannot confirm the "
                        "unfaulted image is rejected.")

        tamper = self.run(faults=())
        if tamper.outcome is Outcome.SUCCESS:
            msgs.append("the image under analysis already reaches SUCCESS with "
                        "no fault: it is not a rejected image, so every "
                        "'bypass' is spurious. Supply a tampered image whose "
                        "signature or hash does not match.")
        elif tamper.outcome is not Outcome.FAIL:
            where = (self.disasm_at(tamper.last_pc)
                     if tamper.last_pc is not None else "<none>")
            msgs.append(f"the image under analysis ends {tamper.outcome.value} "
                        f"(not FAIL) unfaulted at {where}: the fail branch is "
                        f"never reached, so the oracle is not established. "
                        f"Check the fail marker and run --discover.")

        genuine_outcome: Optional[Outcome] = None
        one_way = genuine_firmware is None and genuine_stubs is None
        if not one_way:
            if genuine_firmware is not None:
                sib_cfg = dataclasses.replace(self.cfg, fast_reset=False)
                sibling = SecureBootEmulator(genuine_firmware, sib_cfg)
            else:
                sib_cfg = dataclasses.replace(
                    self.cfg, stubs=dict(genuine_stubs), fast_reset=False)
                sibling = SecureBootEmulator(self.fw, sib_cfg)
            genuine_outcome = sibling.run(faults=()).outcome
            if genuine_outcome is not Outcome.SUCCESS:
                msgs.append(f"the genuine reference ends "
                            f"{genuine_outcome.value} (not SUCCESS) with no "
                            f"fault: an accepted image does not pass the "
                            f"harness, so the success marker or the genuine "
                            f"input is wrong.")

        sound = (tamper.outcome is Outcome.FAIL
                 and (one_way or genuine_outcome is Outcome.SUCCESS))
        if sound and one_way:
            msgs.append("tamper image is correctly rejected; no genuine "
                        "reference given, so the SUCCESS side is unverified "
                        "(pass --genuine for a two-way check).")
        elif sound:
            msgs.append("oracle sound: tamper image rejected (FAIL) and "
                        "genuine image accepted (SUCCESS) unfaulted.")
        self._oracle = OracleResult(sound, tamper.outcome, genuine_outcome,
                                    msgs, one_way)
        return self._oracle

    # -- peripheral discovery & golden-run diagnosis ----------------------- #
    POLL_THRESHOLD = 16   # reads of one register from one PC => poll loop

    def discover_mmio(self) -> Tuple[RunResult, List[dict]]:
        """Run the unfaulted firmware with access logging and summarise every
        peripheral access (anything outside flash/RAM): address, read/write
        counts, the PCs touching it, values written, and whether it looks like
        a status-register poll loop. Returns (run_result, accesses) with the
        accesses sorted by first appearance."""
        log: list = []
        res = self.run(faults=(), mmio_log=log)
        agg: Dict[int, dict] = {}
        order: List[int] = []
        for pc, addr, size, kind, value in log:
            e = agg.get(addr)
            if e is None:
                e = agg[addr] = {"address": addr, "size": size, "reads": 0,
                                 "writes": 0, "wild_fetch": False,
                                 "read_pcs": {}, "written": []}
                order.append(addr)
            if kind == "read":
                e["reads"] += 1
                e["read_pcs"][pc] = e["read_pcs"].get(pc, 0) + 1
            elif kind == "write":
                e["writes"] += 1
                if value is not None and len(e["written"]) < 4 \
                        and value not in e["written"]:
                    e["written"].append(value)
            else:
                e["wild_fetch"] = True
                e["fetch_pc"] = pc

        accesses = []
        for addr in order:
            e = agg[addr]
            top = max(e["read_pcs"].items(), key=lambda kv: kv[1]) \
                if e["read_pcs"] else (None, 0)
            e["poll_pc"], e["poll_reads"] = top
            # A poll re-reads a status register without writing it. A data
            # register (SPI/UART DR) is read once per byte but also written
            # once per byte by the same transfer helper: not a poll.
            e["poll"] = (top[1] >= self.POLL_THRESHOLD
                         and e["writes"] * 4 < e["reads"])
            e["modeled"] = addr in self.cfg.mmio_reads
            accesses.append(e)
        return res, accesses

    def diagnose(self, golden: RunResult, accesses: List[dict]) -> List[str]:
        """Explain why the golden run did not reach the FAIL branch and say
        what to model. Empty list = nothing to report."""
        hints: List[str] = []
        if golden.outcome is Outcome.FAIL:
            return hints
        where = (self.disasm_at(golden.last_pc) if golden.last_pc is not None
                 else "<no instruction executed>")

        unmodeled_polls = [a for a in accesses if a["poll"] and not a["modeled"]]
        wild = [a for a in accesses if a["wild_fetch"]]

        if golden.outcome is Outcome.HANG and unmodeled_polls:
            for a in unmodeled_polls:
                hints.append(
                    f"golden run is stuck polling peripheral register "
                    f"0x{a['address']:08x} ({a['poll_reads']} reads from "
                    f"{self.disasm_at(a['poll_pc'])}). Model the value that "
                    f"ends the loop, e.g. --mmio 0x{a['address']:08x}=0x1 "
                    f"(set whichever ready/done bit the code tests).")
        elif golden.outcome is Outcome.HANG:
            hints.append(f"golden run exhausted the instruction budget "
                         f"(last at {where}). Raise --max-instr if the boot "
                         f"path is long, or check for a non-peripheral loop.")
        elif golden.outcome is Outcome.CRASH:
            if wild:
                hints.append(f"golden run jumped to unmapped address "
                             f"0x{wild[0]['address']:08x} (last executed: "
                             f"{where}). Usually a call into "
                             f"ROM or another image: map it with extra_maps, "
                             f"or stub the call target with --stub.")
            elif golden.error and "FETCH_PROT" in golden.error:
                hints.append(f"golden run jumped into memory that is only mapped "
                             f"lazily as data (last executed: {where}). If the "
                             f"firmware really runs code there (e.g. functions "
                             f"copied to RAM), map that RAM explicitly with a "
                             f"larger --stack region or extra_maps.")
            else:
                hints.append(f"golden run crashed at {where}: {golden.error}. "
                             f"Check base/entry, or the instruction needs a "
                             f"peripheral or CPU feature Unicorn lacks.")
        elif golden.outcome is Outcome.SUCCESS:
            hints.append("golden run reached SUCCESS: with the current model "
                         "the image verifies. Make verification fail, e.g. "
                         "--stub <verify_fn>=0 or --mmio <hash/PKA result "
                         "register>=<mismatch value>, so the sweep measures "
                         "a real bypass.")
        else:
            hints.append(f"golden run ended without reaching a marker "
                         f"(last at {where}). Check --success/--fail.")

        reads = [a for a in accesses if a["reads"] and not a["modeled"]]
        if reads and golden.outcome is not Outcome.HANG:
            regs = ", ".join(f"0x{a['address']:08x}" for a in reads[:6])
            hints.append(f"unmodeled peripheral reads returned 0 from: {regs}. "
                         f"If any feeds the verification result, model it.")
        return hints

    # -- single-instruction skip sweep ------------------------------------ #
    def sweep_single_skip(
        self,
        model: FaultModel = FaultModel.SKIP,
        addr_filter: Optional[Callable[[int], bool]] = None,
    ) -> List[RunResult]:
        """Skip each instruction the golden run executed, one at a time.

        Returns the RunResults whose outcome became SUCCESS - i.e. the
        single-glitch targets that flip the boot decision.
        """
        if self._golden is None:
            self.golden_run()

        # Unique executed addresses, in first-seen order.
        seen = []
        seen_set = set()
        for addr, _sz in self._golden.trace:
            if addr not in seen_set:
                seen_set.add(addr)
                seen.append(addr)

        wins: List[RunResult] = []
        for addr in seen:
            if addr_filter and not addr_filter(addr):
                continue
            res = self.run(faults=[Fault(addr, model)])
            if res.outcome is Outcome.SUCCESS:
                wins.append(res)
        return wins

    # -- wide-glitch (multi-instruction skip window) sweep ----------------- #
    def sweep_skip_window(
        self,
        max_width: int = 4,
        addr_filter: Optional[Callable[[int], bool]] = None,
    ) -> List[RunResult]:
        """A single wide glitch that removes several consecutive instructions.

        Unlike the double-fault search (two independent, precisely placed
        faults), this models one glitch that stays active across a burst of
        fetches, which is what a real voltage or clock glitch often does. For
        each instruction the golden run executes, it finds the smallest window
        width in 2..max_width that reaches SUCCESS (width 1 is the ordinary
        single skip, already covered by sweep_single_skip).

        Returns one RunResult per starting instruction that becomes
        exploitable, each carrying the minimal width on its fault. A window
        can reach code the golden path never ran and that the single-skip
        sweep therefore cannot target on its own."""
        if self._golden is None:
            self.golden_run()
        if max_width < 2:
            return []
        seen = []
        seen_set = set()
        for addr, _sz in self._golden.trace:
            if addr not in seen_set:
                seen_set.add(addr)
                seen.append(addr)

        wins: List[RunResult] = []
        for addr in seen:
            if addr_filter and not addr_filter(addr):
                continue
            for w in range(2, max_width + 1):
                res = self.run(faults=[Fault(addr, FaultModel.SKIP, width=w)])
                if res.outcome is Outcome.SUCCESS:
                    wins.append(res)
                    break
        return wins

    # -- control-flow divergence ("why does this fault work") -------------- #
    def explain(self, faults: Sequence[Fault]) -> Divergence:
        """Diff a faulted run's trace against the golden run to find the point
        where control flow first diverged: the branch or guard the fault
        subverted, and where execution went instead. Pure trace comparison, so
        it reports what actually happened, not a guess. Re-runs the faults with
        tracing on (cheap: only done for a confirmed finding)."""
        if self._golden is None:
            self.golden_run()
        r = self.run(faults=faults, record_trace=True)
        gt = [a for a, _ in self._golden.trace]
        ft = [a for a, _ in r.trace]
        n = min(len(gt), len(ft))
        i = 0
        while i < n and gt[i] == ft[i]:
            i += 1
        if i == 0:
            return Divergence(None, "", gt[0] if gt else None,
                              ft[0] if ft else None, r.outcome,
                              "diverged before the first instruction")
        gnext0 = gt[i] if i < len(gt) else None
        fnext0 = ft[i] if i < len(ft) else None
        if gnext0 is None and fnext0 is None:
            # identical control-flow path: the fault changed data/flags or
            # nothing, not the branches taken.
            return Divergence(gt[i - 1], self._insn_text(gt[i - 1])[0],
                              None, None, r.outcome,
                              "took the same control-flow path as the golden "
                              "run (the fault had no effect on which branches "
                              "were taken)" + (" but still reached SUCCESS"
                              if r.outcome is Outcome.SUCCESS else ""))
        split = gt[i - 1]
        split_text = self._insn_text(split)[0]
        gnext = gt[i] if i < len(gt) else None
        fnext = ft[i] if i < len(ft) else None

        faulted_addrs = {f.address for f in faults}
        if gnext is not None and gnext in faulted_addrs:
            # the glitch removed the instruction the golden run executed next
            skipped = self._insn_text(gnext)[0]
            note = (f"the glitch skipped `{skipped}` at 0x{gnext:08x}; "
                    f"execution continued to 0x{fnext:08x}"
                    if fnext is not None else
                    f"the glitch skipped `{skipped}` at 0x{gnext:08x}")
        else:
            note = (f"after `{split_text}` at 0x{split:08x} the glitch sent "
                    f"execution to 0x{fnext:08x} instead of 0x{gnext:08x}"
                    if fnext is not None and gnext is not None else
                    f"execution left the golden path after 0x{split:08x}")
        if r.outcome is Outcome.SUCCESS:
            note += " and reached SUCCESS"
        return Divergence(split, split_text, gnext, fnext, r.outcome, note)

    # -- iteration-aware (loop) skip sweep --------------------------------- #
    def sweep_iterations(
        self,
        max_iters: int = 8,
        model: FaultModel = FaultModel.SKIP,
        addr_filter: Optional[Callable[[int], bool]] = None,
    ) -> List[RunResult]:
        """Fault specific loop iterations, not just the first visit.

        sweep_single_skip faults each instruction only on its first execution
        (nth=0). Real secure boot often rejects an image inside a loop (a
        byte-by-byte hash or signature compare), where the reject happens on a
        later pass and only glitching THAT iteration bypasses. For every
        instruction the golden run executes more than once, this faults visits
        0..min(visits, max_iters)-1 and returns every (address, visit) that
        reaches SUCCESS. Findings with nth>0 are ones the first-visit sweeps
        cannot reach."""
        if self._golden is None:
            self.golden_run()
        from collections import Counter
        visits = Counter(a for a, _ in self._golden.trace)
        order, seen = [], set()
        for a, _ in self._golden.trace:
            if a not in seen:
                seen.add(a)
                order.append(a)
        wins: List[RunResult] = []
        for addr in order:
            if visits[addr] < 2:
                continue
            if addr_filter and not addr_filter(addr):
                continue
            for nth in range(min(visits[addr], max_iters)):
                res = self.run(faults=[Fault(addr, model, nth=nth)])
                if res.outcome is Outcome.SUCCESS:
                    wins.append(res)
        return wins

    # -- randomized multi-glitch campaign ---------------------------------- #
    def random_campaign(
        self,
        iterations: int = 5000,
        max_glitches: int = 2,
        model: FaultModel = FaultModel.SKIP,
        seed: Optional[int] = None,
    ) -> List[RunResult]:
        """Loop: each iteration skips a random set of 1..max_glitches
        instructions and keeps the runs that reach SUCCESS. De-duplicates by
        the set of skipped addresses.

        The target pool is the golden path PLUS every instruction executed
        after any single skip. Drawing only from the golden path would make
        redundant checks the unfaulted run never reaches unreachable as
        targets, so the campaign could never find a bypass of hardened code.
        For an exhaustive two-fault answer use double_fault_sweep()."""
        if self._golden is None:
            self.golden_run()

        rng = random.Random(seed)
        markers = set(self.cfg.success_addrs) | set(self.cfg.fail_addrs)
        golden_addrs = {addr for addr, _ in self._golden.trace}
        reach = set(golden_addrs)
        for a in golden_addrs - markers:
            r = self.run(faults=[Fault(a, model)], record_trace=True)
            reach.update(x for x, _ in r.trace)
        pool = sorted(reach - markers)
        if not pool:
            return []

        wins: Dict[frozenset, RunResult] = {}
        for _ in range(iterations):
            k = rng.randint(1, max_glitches)
            k = min(k, len(pool))
            targets = rng.sample(pool, k)
            key = frozenset(targets)
            if key in wins:
                continue
            faults = [Fault(a, model) for a in targets]
            res = self.run(faults=faults)
            if res.outcome is Outcome.SUCCESS:
                wins[key] = res
        return list(wins.values())

    # -- static branch / decision-point detector --------------------------- #
    def detect_decision_points(
        self, start: Optional[int] = None, length: Optional[int] = None
    ) -> List[Tuple[int, str, str]]:
        """Disassemble the firmware and flag the instructions that typically
        implement a verification decision: compares/tests and conditional
        branches. Use this to locate the secure-boot success/fail branches
        when you don't already have addresses from Ghidra/IDA.

        Returns a list of (address, mnemonic, op_str).
        """
        start = self.cfg.load_addr if start is None else start
        if length is None:
            length = len(self.fw) - (start - self.cfg.load_addr)
        code = self.fw[start - self.cfg.load_addr: start - self.cfg.load_addr + length]

        decision_prefixes = (
            "cmp", "cmn", "tst", "teq",          # comparisons
            "cbz", "cbnz",                        # compare-and-branch (thumb)
            "it",                                 # if-then (thumb)
        )
        cond_suffixes = (
            "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le",
        )
        points: List[Tuple[int, str, str]] = []
        for insn in self.cs.disasm(code, start):
            m = insn.mnemonic
            root = m.split(".")[0]              # strip Thumb ".w" width suffix
            # Conditional branch: b<cond>, e.g. bne/beq. Excludes b, bl, blx,
            # bx, bic (none of whose tails are condition codes).
            is_cond_branch = root.startswith("b") and root[1:] in cond_suffixes
            if root.startswith(decision_prefixes) or is_cond_branch:
                points.append((insn.address, m, insn.op_str))
        return points

    # -- disassembly helper ------------------------------------------------ #
    def disasm_at(self, address: int, n: int = 1) -> str:
        off = address - self.cfg.load_addr
        if off < 0 or off >= len(self.fw):
            return f"0x{address:08x}: <outside firmware image>"
        code = self.fw[off: off + 4 * n + 4]
        out = []
        for insn in self.cs.disasm(code, address):
            out.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}".rstrip())
            if len(out) >= n:
                break
        return "\n".join(out) if out else f"0x{address:08x}: <no insn>"

    def _insn_text(self, address: int) -> Tuple[str, int]:
        """Return (mnemonic op_str, size) for the instruction at `address`."""
        off = address - self.cfg.load_addr
        if 0 <= off < len(self.fw):
            for insn in self.cs.disasm(self.fw[off: off + 8], address):
                return f"{insn.mnemonic} {insn.op_str}".strip(), insn.size
        fixed = 2 if self.spec.thumb else (1 if self.spec.name.startswith("x86") else 4)
        return "<unknown>", fixed

    def _insn_size(self, address: int) -> int:
        return self._insn_text(address)[1]

    # -- data-fault targets ------------------------------------------------ #
    _FLAG_REGS = {"cpsr", "apsr", "nzcv", "eflags", "rflags"}
    _NO_CORRUPT = {"pc", "sp", "lr", "x30", "eip", "rip", "esp", "rsp"}
    _FLAGS_ONLY = ("cmp", "cmn", "tst", "teq", "test")

    def _dest_regs(self, address: int) -> Tuple[List[str], bool]:
        """(general-purpose registers the instruction writes, writes flags).
        PC/SP/LR are excluded: corrupting them is a control-flow fault, which
        skip and bitflip already cover."""
        cache = self.__dict__.setdefault("_dest_cache", {})
        if address in cache:
            return cache[address]
        if not hasattr(self, "_cs_detail"):
            self._cs_detail = capstone.Cs(self.spec.cs_arch, self.spec.cs_mode)
            self._cs_detail.detail = True
        result: Tuple[List[str], bool] = ([], False)
        off = address - self.cfg.load_addr
        if 0 <= off < len(self.fw):
            for insn in self._cs_detail.disasm(self.fw[off:off + 16], address):
                try:
                    _, w = insn.regs_access()
                except Exception:
                    break
                names = [insn.reg_name(x) for x in w]
                flags = any(n in self._FLAG_REGS for n in names)
                if insn.mnemonic.split(".")[0] in self._FLAGS_ONLY:
                    result = ([], flags)
                else:
                    result = ([n for n in names if n in self.spec.gpr
                               and n not in self._NO_CORRUPT
                               and n not in self._FLAG_REGS], flags)
                break
        cache[address] = result
        return result

    def data_fault_applicable(self, address: int) -> bool:
        gprs, flags = self._dest_regs(address)
        return bool(gprs) or flags

    def _apply_result_fault(self, uc: Uc, model: FaultModel, address: int) -> None:
        gprs, flags = self._dest_regs(address)
        ones = model is FaultModel.RESULT_ONES
        if gprs:
            width = 64 if self.spec.name in ("arm64", "x86-64") else 32
            for n in gprs:
                uc.reg_write(self.spec.gpr[n], (1 << width) - 1 if ones else 0)
        elif flags:
            self._write_nzcv(uc, 0xF if ones else 0x0)

    def _insn_cost(self, mnemonic: str) -> int:
        """Coarse, ARM-family-ish cycle estimate. Instruction INDEX is the
        deterministic quantity; this is only a rough timing aid for setting a
        bench trigger delay, and is not cycle-accurate."""
        m = mnemonic.split(".")[0].lower()
        if m[:3] in ("ldr", "str", "ldm", "stm", "ldp", "stp") or m in ("push", "pop"):
            return 2
        if m[:3] in ("mul", "mla", "mls", "div") or m in ("udiv", "sdiv"):
            return 2
        if m and (m[0] == "b" or m in ("ret", "cbz", "cbnz", "ldr")):  # branch taken
            return 2
        return 1

    # -- glitch-window characterization ------------------------------------ #
    def characterize(
        self,
        models: Sequence[FaultModel] = (FaultModel.SKIP,),
        addr_filter: Optional[Callable[[int], bool]] = None,
    ) -> Characterization:
        """Sweep single faults over the golden trace and place every bypass on
        the execution timeline, grouping contiguous exploitable instructions
        into glitch windows (with widths + approximate cycle offsets) that map
        onto a bench campaign. Supports SKIP and BITFLIP."""
        if self._golden is None:
            self.golden_run()

        trace = self._golden.trace
        # Execution-order timeline: first index + cumulative cycle offset.
        first_index: Dict[int, int] = {}
        cycle_at_index: List[int] = []
        cyc = 0
        for i, (addr, _sz) in enumerate(trace):
            first_index.setdefault(addr, i)
            cycle_at_index.append(cyc)
            mnem, _ = self._insn_text(addr)
            cyc += self._insn_cost(mnem)

        # Unique executed addresses in first-seen order.
        ordered_addrs: List[int] = []
        _seen = set()
        for addr, _sz in trace:
            if addr not in _seen:
                _seen.add(addr)
                ordered_addrs.append(addr)

        findings: List[GlitchFinding] = []
        for model in models:
            for addr in ordered_addrs:
                if addr_filter and not addr_filter(addr):
                    continue
                idx = first_index[addr]
                cyc_off = cycle_at_index[idx]
                dis, _ = self._insn_text(addr)
                if model in DATA_FAULT_MODELS and not self.data_fault_applicable(addr):
                    continue
                if model is FaultModel.BITFLIP:
                    nbits = self._insn_size(addr) * 8
                    for bit in range(nbits):
                        res = self.run(faults=[Fault(addr, model, bit=bit)])
                        if res.outcome is Outcome.SUCCESS:
                            findings.append(GlitchFinding(
                                model.value, addr, idx, cyc_off, dis, bit=bit))
                else:
                    res = self.run(faults=[Fault(addr, model)])
                    if res.outcome is Outcome.SUCCESS:
                        findings.append(GlitchFinding(
                            model.value, addr, idx, cyc_off, dis))

        windows = self._group_windows(findings, first_index, cycle_at_index)
        return Characterization(
            golden_outcome=self._golden.outcome.value,
            total_instructions=self._golden.instr_count,
            findings=findings,
            windows=windows,
        )

    def _group_windows(
        self, findings: List[GlitchFinding], first_index: Dict[int, int],
        cycle_at_index: List[int],
    ) -> List[GlitchWindow]:
        """Collapse exploitable instruction indices into contiguous windows,
        per fault model."""
        index_to_addr = {v: k for k, v in first_index.items()}
        windows: List[GlitchWindow] = []
        by_model: Dict[str, set] = {}
        for f in findings:
            by_model.setdefault(f.model, set()).add(f.instr_index)
        for model, idx_set in by_model.items():
            idxs = sorted(idx_set)
            run = [idxs[0]]
            for i in idxs[1:]:
                if i == run[-1] + 1:
                    run.append(i)
                else:
                    windows.append(self._mk_window(model, run, index_to_addr,
                                                   cycle_at_index))
                    run = [i]
            windows.append(self._mk_window(model, run, index_to_addr,
                                           cycle_at_index))
        windows.sort(key=lambda w: (w.model, w.start_index))
        return windows

    def _mk_window(self, model, run, index_to_addr, cycle_at_index) -> GlitchWindow:
        s, e = run[0], run[-1]
        return GlitchWindow(
            model=model, start_index=s, end_index=e,
            start_addr=index_to_addr[s], end_addr=index_to_addr[e],
            width=len(run),
            cycle_start=cycle_at_index[s], cycle_end=cycle_at_index[e],
        )

    # -- finding robustness ------------------------------------------------ #
    _PINNED_REGS = {"sp", "pc", "lr", "cpsr", "x30", "eip", "rip", "esp",
                    "rsp", "eflags"}

    def _variant(self, stubs: Dict[int, int],
                 regs: Optional[Dict[str, int]] = None) -> "SecureBootEmulator":
        cfg = dataclasses.replace(
            self.cfg, stubs=dict(stubs),
            initial_regs={**self.cfg.initial_regs, **(regs or {})})
        return SecureBootEmulator(self.fw, cfg)

    def assess_robustness(
        self,
        stub_variants: Optional[Sequence[Dict[int, int]]] = None,
        models: Sequence[FaultModel] = (FaultModel.SKIP,),
        n_contexts: int = 0,
        seed: int = 0,
    ) -> RobustnessReport:
        """Classify every bypass as robust / context-dependent /
        value-dependent (see the RobustFinding notes above).

        stub_variants: alternative `stubs` dicts, typically the same stubbed
            function returning several different mismatch values. Each one
            must still give a FAIL baseline; variants that do not (e.g. a
            value that equals the genuine hash) are excluded and reported.
        n_contexts: random entry-register contexts used to re-test the
            findings that survive every variant. Registers pinned with
            initial_regs, plus sp/pc/lr/flags, are never randomized. Contexts
            whose own baseline does not FAIL are discarded, not held against
            a finding.
        """
        variants = list(stub_variants) if stub_variants else [dict(self.cfg.stubs)]
        notes: List[str] = []

        # 1. Per-variant characterization (baseline must FAIL).
        valid, excluded = [], []
        per_variant: List[Dict[Tuple[str, int, Optional[int]], GlitchFinding]] = []
        for v in variants:
            emu = self._variant(v)
            g = emu.golden_run()
            if g.outcome is not Outcome.FAIL:
                excluded.append(v)
                notes.append(
                    "stub variant " + ", ".join(f"0x{a:08x}=0x{x:x}" for a, x in v.items())
                    + f" excluded: its baseline is {g.outcome.value}, not FAIL")
                continue
            ch = emu.characterize(models=models)
            valid.append(v)
            per_variant.append({(f.model, f.address, f.bit): f for f in ch.findings})
        report = RobustnessReport(valid, excluded, n_contexts, 0, notes=notes)
        if not valid:
            notes.append("no stub variant produced a FAIL baseline; nothing to assess")
            return report

        all_keys = set().union(*per_variant)
        robust_keys = set.intersection(*(set(p) for p in per_variant))

        def info(key):
            for p in per_variant:
                if key in p:
                    return p[key]

        # 2. Register-context re-test of the findings that survive every value.
        ctx_hits = {k: 0 for k in robust_keys}
        free = [n for n in self.spec.gpr
                if n not in self._PINNED_REGS and n not in self.cfg.initial_regs]
        width = 64 if self.spec.name in ("arm64", "x86-64") else 32
        rng = random.Random(seed)
        n_valid = 0
        for i in range(n_contexts if robust_keys else 0):
            regs = {n: rng.getrandbits(width) for n in free}
            emu = self._variant(valid[i % len(valid)], regs)
            if emu.run().outcome is not Outcome.FAIL:
                continue
            n_valid += 1
            for k in robust_keys:
                model, addr, bit = k
                r = emu.run(faults=[Fault(addr, FaultModel(model), bit=bit)])
                if r.outcome is Outcome.SUCCESS:
                    ctx_hits[k] += 1
        report.contexts_valid = n_valid
        if n_contexts and robust_keys and n_valid == 0:
            notes.append("no random register context kept the baseline at FAIL: "
                         "the entry point probably reads argument registers. "
                         "Pin them with --reg / initial_regs.")
        elif n_contexts and n_valid < n_contexts:
            notes.append(f"{n_contexts - n_valid} of {n_contexts} register contexts "
                         f"changed the baseline itself and were discarded")

        # 3. Classify.
        for key in all_keys:
            f = info(key)
            hits = [i for i, p in enumerate(per_variant) if key in p]
            if key not in robust_keys:
                status, ch_, cv = VALUE_DEP, 0, 0
            else:
                ch_, cv = ctx_hits[key], n_valid
                status = ROBUST if ch_ == cv else CONTEXT_DEP
            report.findings.append(RobustFinding(
                model=key[0], address=key[1], bit=key[2], disasm=f.disasm,
                instr_index=f.instr_index, status=status,
                variants_hit=len(hits), variants_total=len(valid),
                contexts_hit=ch_, contexts_valid=cv, hit_variants=hits))
        report.findings.sort(key=lambda r: (r.instr_index if r.instr_index is not None
                                            else 1 << 30, r.model, r.bit or 0))
        return report

    # -- fault-resistance order -------------------------------------------- #
    def _mechanism_faults(self, address: int, models: Sequence[FaultModel],
                          nth: int = 0) -> List[Fault]:
        """Every single fault the given models define at one instruction."""
        out: List[Fault] = []
        for m in models:
            if m is FaultModel.SKIP:
                out.append(Fault(address, m, nth=nth))
            elif m is FaultModel.BITFLIP:
                out += [Fault(address, m, nth=nth, bit=b)
                        for b in range(self._insn_size(address) * 8)]
            elif m in DATA_FAULT_MODELS and self.data_fault_applicable(address):
                out.append(Fault(address, m, nth=nth))
        return out

    def double_fault_sweep(
        self,
        window: Optional[int] = None,
        stub_variants: Optional[Sequence[Dict[int, int]]] = None,
        max_pair_runs: int = 200_000,
        models: Sequence[FaultModel] = (FaultModel.SKIP,),
        progress: bool = False,
    ) -> DoubleFaultResult:
        """Exhaustive two-fault search, path-adaptive, over any fault models.

        For every fault mechanism at every instruction of the golden path
        (that does not already bypass on its own), run with that one fault
        and take second faults (every mechanism) from the instructions THAT
        faulted run executes afterwards, hitting the visit that occurs
        there. This reaches redundant checks the unfaulted run never
        executes. `window` limits the gap (in executed instructions) between
        the two glitches. With several stub_variants a pair must bypass under
        all of them (value-dependent pairs dropped). With models=(SKIP,) this
        is the classic two-skip search.
        """
        if self._golden is None:
            self.golden_run()
        models = tuple(models)
        markers = set(self.cfg.success_addrs) | set(self.cfg.fail_addrs)
        first_idx: Dict[int, int] = {}
        for i, (a, _) in enumerate(self._golden.trace):
            first_idx.setdefault(a, i)
        golden_addrs = set(first_idx)

        # Single-fault winners, per mechanism: pairs containing one are not
        # genuinely double.
        ch = self.characterize(models=models)
        single_keys = {(f.model, f.address, f.bit) for f in ch.findings}
        singles = sorted({f.address for f in ch.findings})
        key = lambda f: (f.model.value, f.address, f.bit)

        others = [self._variant(v) for v in (stub_variants or [])[1:]]
        pairs: List[FaultPair] = []
        runs = dropped = firsts = 0
        truncated = False
        next_note = 25_000

        for a in first_idx:                       # first-seen order
            if a in markers:
                continue
            for f1 in self._mechanism_faults(a, models):
                if key(f1) in single_keys:
                    continue
                r1 = self.run(faults=[f1], record_trace=True)
                if r1.outcome is Outcome.SUCCESS:
                    continue
                firsts += 1
                tr = r1.trace
                k = next((i for i, (x, _) in enumerate(tr) if x == a), None)
                if k is None:
                    continue
                visits: Dict[int, int] = {}
                for x, _ in tr[:k + 1]:
                    visits[x] = visits.get(x, 0) + 1
                tried = set()
                for pos in range(k + 1, len(tr)):
                    b = tr[pos][0]
                    gap = pos - k
                    nth = visits.get(b, 0)
                    visits[b] = nth + 1
                    if window is not None and gap > window:
                        break
                    if b in tried or b in markers:
                        continue
                    tried.add(b)
                    for f2 in self._mechanism_faults(b, models, nth=nth):
                        if (f2.model.value, b, f2.bit) in single_keys:
                            continue
                        if runs >= max_pair_runs:
                            truncated = True
                            break
                        runs += 1
                        if progress and runs >= next_note:
                            print(f"  double-fault search: {runs} pair runs, "
                                  f"{len(pairs)} pairs so far", file=sys.stderr)
                            next_note += 25_000
                        faults = [f1, f2]
                        if self.run(faults=faults).outcome is not Outcome.SUCCESS:
                            continue
                        if any(o.run(faults=faults).outcome is not Outcome.SUCCESS
                               for o in others):
                            dropped += 1
                            continue
                        pairs.append(FaultPair(
                            first=a, second=b, second_visit=nth, gap=gap,
                            first_index=first_idx[a],
                            first_disasm=self._insn_text(a)[0],
                            second_disasm=self._insn_text(b)[0],
                            off_golden_path=b not in golden_addrs,
                            first_model=f1.model.value, first_bit=f1.bit,
                            second_model=f2.model.value, second_bit=f2.bit))
                    if truncated:
                        break
                if truncated:
                    break
            if truncated:
                break

        pairs.sort(key=lambda p: (p.first_index, p.gap, p.first_model,
                                  p.first_bit or 0, p.second_model,
                                  p.second_bit or 0))
        order = "1" if singles else ("2" if pairs else ">2")
        return DoubleFaultResult(order=order, single_targets=singles, pairs=pairs,
                                 firsts_tested=firsts, pair_runs=runs, window=window,
                                 stub_variants_checked=1 + len(others),
                                 dropped_value_dependent=dropped,
                                 truncated=truncated,
                                 models=[m.value for m in models])


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def print_characterization(ch: Characterization) -> None:
    """Bench-oriented view: exploitable windows (where to aim the trigger and
    how wide the window is) plus the per-instruction findings."""
    line = "=" * 70
    print(f"\n{line}")
    print("GLITCH-WINDOW CHARACTERIZATION  (bench targeting)")
    print(line)
    if not ch.windows:
        print("\n  no exploitable instructions found under the swept model(s).")
        return
    print(f"\n  golden execution: {ch.total_instructions} instructions "
          f"(index 0 = entry). 'index' = trigger delay in instructions; the "
          f"approx cycle offset is a rough timing aid, not cycle-accurate.\n")
    for w in ch.windows:
        if w.width == 1:
            where = f"instruction #{w.start_index}"
        else:
            where = (f"instructions #{w.start_index}-#{w.end_index} "
                     f"(width {w.width})")
        print(f"  [{w.model}] {where}")
        print(f"      address range : 0x{w.start_addr:08x} - 0x{w.end_addr:08x}")
        print(f"      trigger delay : {w.start_index}-{w.end_index} instructions "
              f"from entry (~{w.cycle_start}-{w.cycle_end} cycles)")
        print(f"      window width  : {w.width} instruction(s) -> a glitch "
              f"anywhere in this window bypasses verification")
    # Highlight the widest window: the easiest to land on a bench.
    widest = max(ch.windows, key=lambda w: w.width)
    if widest.width > 1:
        print(f"\n  widest window : {widest.width} instructions "
              f"[{widest.model}] around index #{widest.start_index}; "
              f"start here, it is the most forgiving target.")


def print_oracle(res: "OracleResult") -> None:
    """Print the two-way oracle verdict."""
    line = "=" * 70
    print(line)
    print("ORACLE VALIDATION  (unfaulted, before any sweep)")
    print(line)
    verdict = "SOUND" if res.sound else "UNSOUND"
    if res.sound and res.one_way:
        verdict = "SOUND (one-way: SUCCESS side unverified)"
    print(f"  verdict           : {verdict}")
    print(f"  tamper image      : {res.tamper_outcome.value} "
          f"(want FAIL)")
    if res.genuine_outcome is not None:
        print(f"  genuine reference : {res.genuine_outcome.value} "
              f"(want SUCCESS)")
    for m in res.messages:
        print(f"  - {m}")
    print()


def print_hardware(accesses: List[dict], hints: List[str],
                   cfg: "EmulatorConfig") -> None:
    """Peripheral map of the unfaulted run plus golden-run diagnosis."""
    line = "=" * 70
    print(line)
    print("HARDWARE ENVIRONMENT  (peripheral accesses, unfaulted run)")
    print(line)
    if not accesses:
        print("  no accesses outside flash/RAM.")
    for a in accesses[:25]:
        tags = []
        if a["poll"]:
            tags.append("POLL LOOP")
        if a["modeled"]:
            tags.append(f"modeled=0x{cfg.mmio_reads[a['address']]:x}")
        if a["wild_fetch"]:
            tags.append("WILD FETCH")
        wr = (" wrote " + ",".join(f"0x{v:x}" for v in a["written"])
              if a["written"] else "")
        print(f"  0x{a['address']:08x}  r={a['reads']:<6} w={a['writes']:<4}"
              f"{wr}  {' | '.join(tags)}".rstrip())
    if len(accesses) > 25:
        print(f"  ... {len(accesses) - 25} more")
    if cfg.stubs:
        print("\n  stubbed functions: " + ", ".join(
            f"0x{a:08x}->0x{v:x}" + (f" flags=0b{cfg.stub_exit_flags[a]:04b}"
                                     if a in cfg.stub_exit_flags else "")
            for a, v in cfg.stubs.items()))
        unmodeled = [a for a in cfg.stubs if a not in cfg.stub_exit_flags]
        if unmodeled:
            print("  * stub(s) " + ", ".join(f"0x{a:08x}" for a in unmodeled)
                  + " return with the CALLER's flags. A skipped compare after "
                    "the call would see the wrong flags, which can hide real "
                    "bypasses. Use --calibrate-stubs or --stub-flags.")
    if hints:
        print("\n  diagnosis:")
        for h in hints:
            print(f"  * {h}")
    print()


def print_double_fault(res: DoubleFaultResult, max_pairs: int = 25) -> None:
    line = "=" * 70
    skip_only = res.models == ["skip"]
    fault = "skip" if skip_only else "fault"
    print(f"\n{line}")
    print(f"FAULT-RESISTANCE ORDER  (models: {', '.join(res.models)}; exhaustive pairs)")
    print(line)
    scope = (f"gap <= {res.window} instructions" if res.window is not None
             else "any gap")
    print(f"  first faults tested : {res.firsts_tested}   pair runs: "
          f"{res.pair_runs}   ({scope})")
    if res.stub_variants_checked > 1:
        print(f"  stub variants       : {res.stub_variants_checked} "
              f"({res.dropped_value_dependent} value-dependent pair(s) dropped)")
    if res.order == "1":
        print(f"\n  ORDER 1: a single {fault} bypasses verification "
              f"({len(res.single_targets)} instruction(s), see the single sweep).")
        if res.pairs:
            print(f"  Fixing those alone is not enough: {len(res.pairs)} "
                  f"additional pair(s) bypass without using them.")
    elif res.truncated:
        print(f"\n  ORDER NOT ESTABLISHED: no single {fault} works and the pair "
              f"search was truncated after {res.pair_runs} runs "
              f"({len(res.pairs)} pair(s) found so far).")
    elif res.order == "2":
        print(f"\n  ORDER 2: no single {fault} works, but {len(res.pairs)} pair(s) "
              f"of {fault}s bypass verification.")
    else:
        print(f"\n  ORDER >2: no single {fault} and no pair of {fault}s bypasses "
              "verification" + (" within the gap limit." if res.window is not None
                                else "."))
    if res.pairs:
        # Remediation view: which second-glitch targets carry the pairs.
        by_second: Dict[Tuple[int, str], int] = {}
        for p in res.pairs:
            k = (p.second, p.second_disasm)
            by_second[k] = by_second.get(k, 0) + 1
        print(f"\n  pairs funnel into {len(by_second)} second-glitch target(s); "
              f"hardening these closes every pair:")
        for (a, dis), n in sorted(by_second.items(), key=lambda kv: -kv[1]):
            print(f"    0x{a:08x} {dis:<26} <- {n} pair(s)")
        print("\n  glitch 1 (trigger index)              -> glitch 2 (gap after glitch 1)")
        for p in res.pairs[:max_pairs]:
            visit = f", visit {p.second_visit + 1}" if p.second_visit else ""
            off = "  [off golden path]" if p.off_golden_path else ""
            m1 = "" if skip_only else f" [{FaultPair.mech_label(p.first_model, p.first_bit)}]"
            m2 = "" if skip_only else f" [{FaultPair.mech_label(p.second_model, p.second_bit)}]"
            print(f"  #{p.first_index:<4} 0x{p.first:08x} {p.first_disasm:<22}{m1} -> "
                  f"0x{p.second:08x} {p.second_disasm:<22}{m2} +{p.gap}{visit}{off}")
        if len(res.pairs) > max_pairs:
            print(f"  ... {len(res.pairs) - max_pairs} more")
        off = sum(p.off_golden_path for p in res.pairs)
        if off:
            print(f"\n  {off} pair(s) hit a second target the unfaulted run never "
                  f"executes (e.g. a redundant check); trace-based single and "
                  f"random sweeps cannot see these.")
    if res.truncated:
        print("\n  note: pair search hit max_pair_runs and was truncated; the "
              "order is not established. Narrow it with --double-window.")


# --------------------------------------------------------------------------- #
# Bench target ranking
#
# A physical glitch does not choose a fault model: depending on voltage,
# width and timing it produces a spread of effects (skipped instructions,
# corrupted encodings, corrupted loads). An instruction where most modelled
# mechanisms bypass verification will succeed under far more glitch
# parameters than one that needs one specific bit-flip. The score is the mean,
# over the fault-mechanism families that were run, of the share of that
# family's trials that bypass:
#   skip     1 trial
#   bitflip  every bit of the encoding (share of bits that bypass)
#   data     result forced to zero and to ones (where applicable)
# It ranks sensitivity; it is not a success probability, and it says nothing
# about how observable a trigger point is.
# --------------------------------------------------------------------------- #
@dataclass
class BenchTarget:
    address: int
    instr_index: int
    disasm: str
    skip: Optional[bool]
    bitflip_hits: Optional[int]
    bitflip_bits: int
    zero: Optional[bool]          # None: model not run or not applicable
    ones: Optional[bool]
    score: float
    status: str                   # robust | context-dependent | unvalidated
    context_rate: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"address": f"0x{self.address:08x}", "instr_index": self.instr_index,
             "disasm": self.disasm, "score": round(self.score, 3),
             "status": self.status}
        if self.skip is not None:
            d["skip"] = self.skip
        if self.bitflip_hits is not None:
            d["bitflip"] = f"{self.bitflip_hits}/{self.bitflip_bits}"
        if self.zero is not None:
            d["result_zero"] = self.zero
        if self.ones is not None:
            d["result_ones"] = self.ones
        if self.context_rate:
            d["register_contexts_bypassed"] = self.context_rate
        return d


@dataclass
class HotZone:
    start_index: int
    end_index: int
    start_addr: int
    end_addr: int
    width: int
    score_sum: float

    def to_dict(self) -> dict:
        return {"instr_index_range": [self.start_index, self.end_index],
                "address_range": [f"0x{self.start_addr:08x}", f"0x{self.end_addr:08x}"],
                "width_instructions": self.width,
                "cumulative_score": round(self.score_sum, 3)}


@dataclass
class BenchRanking:
    models: List[str]
    validated: bool
    targets: List[BenchTarget]
    zones: List[HotZone]

    def to_dict(self) -> dict:
        return {"models": self.models, "validated": self.validated,
                "targets": [t.to_dict() for t in self.targets],
                "hot_zones": [z.to_dict() for z in self.zones]}


def rank_bench_targets(emu: "SecureBootEmulator", models: Sequence[FaultModel],
                       source) -> BenchRanking:
    """Rank instructions by fault-mechanism sensitivity.

    source: a RobustnessReport (robust and context-dependent findings are
    used, value-dependent ones dropped) or a Characterization (findings used
    as-is and marked unvalidated)."""
    if emu._golden is None:
        emu.golden_run()
    first_idx: Dict[int, int] = {}
    for i, (a, _) in enumerate(emu._golden.trace):
        first_idx.setdefault(a, i)

    validated = isinstance(source, RobustnessReport)
    rows = []   # (model, address, bit, status, context_rate)
    if validated:
        for f in source.findings:
            if f.status == VALUE_DEP:
                continue
            rate = (f"{f.contexts_hit}/{f.contexts_valid}"
                    if f.status == CONTEXT_DEP else None)
            rows.append((f.model, f.address, f.bit, f.status, rate))
    else:
        for f in source.findings:
            rows.append((f.model, f.address, f.bit, "unvalidated", None))

    run = {m.value for m in models}
    by_addr: Dict[int, dict] = {}
    for model, addr, bit, status, rate in rows:
        e = by_addr.setdefault(addr, {"skip": False, "bits": set(), "zero": False,
                                      "ones": False, "status": set(), "rate": set()})
        if model == FaultModel.SKIP.value:
            e["skip"] = True
        elif model == FaultModel.BITFLIP.value:
            e["bits"].add(bit)
        elif model == FaultModel.RESULT_ZERO.value:
            e["zero"] = True
        elif model == FaultModel.RESULT_ONES.value:
            e["ones"] = True
        e["status"].add(status)
        if rate:
            e["rate"].add(rate)

    targets: List[BenchTarget] = []
    for addr, e in by_addr.items():
        nbits = emu._insn_size(addr) * 8
        data_ok = emu.data_fault_applicable(addr)
        fam = []
        skip = e["skip"] if FaultModel.SKIP.value in run else None
        if skip is not None:
            fam.append(1.0 if skip else 0.0)
        bf = len(e["bits"]) if FaultModel.BITFLIP.value in run else None
        if bf is not None:
            fam.append(bf / nbits)
        data_run = all(m.value in run for m in DATA_FAULT_MODELS) and data_ok
        zero = e["zero"] if data_run else None
        ones = e["ones"] if data_run else None
        if data_run:
            fam.append((zero + ones) / 2)
        score = sum(fam) / len(fam) if fam else 0.0
        if score <= 0:
            continue
        status = (CONTEXT_DEP if CONTEXT_DEP in e["status"] else
                  ROBUST if ROBUST in e["status"] else "unvalidated")
        targets.append(BenchTarget(
            address=addr, instr_index=first_idx.get(addr, -1),
            disasm=emu._insn_text(addr)[0], skip=skip, bitflip_hits=bf,
            bitflip_bits=nbits, zero=zero, ones=ones, score=score, status=status,
            context_rate=", ".join(sorted(e["rate"])) or None))
    targets.sort(key=lambda t: (-t.score, t.instr_index))

    zones: List[HotZone] = []
    for t in sorted(targets, key=lambda t: t.instr_index):
        z = zones[-1] if zones else None
        if z is not None and t.instr_index == z.end_index + 1:
            z.end_index, z.end_addr = t.instr_index, t.address
            z.width += 1
            z.score_sum += t.score
        else:
            zones.append(HotZone(t.instr_index, t.instr_index, t.address,
                                 t.address, 1, t.score))
    zones.sort(key=lambda z: (-z.score_sum, z.start_index))
    return BenchRanking([m.value for m in models], validated, targets, zones)


def print_bench_ranking(r: BenchRanking, top: int = 15) -> None:
    line = "=" * 70
    print(f"\n{line}")
    print("BENCH TARGET RANKING  (" + ("robust findings" if r.validated
          else "UNVALIDATED: run with several --stub values / --vary-regs")
          + f"; models: {', '.join(r.models)})")
    print(line)
    if not r.targets:
        print("  no exploitable instruction to rank.")
        return
    print("  score = share of modelled fault mechanisms at the instruction that "
          "bypass\n  (skip; bit-flip weighted by share of encoding bits; data "
          "zero/ones). Relative\n  sensitivity, not a success probability.\n")
    yn = lambda v: "-" if v is None else ("yes" if v else "no")
    print(f"  {'rank':<4} {'idx':<5} {'address':<10}  {'instruction':<24} "
          f"{'skip':<4} {'bitflip':<7} {'zero':<4} {'ones':<4} score")
    for i, t in enumerate(r.targets[:top], 1):
        bf = "-" if t.bitflip_hits is None else f"{t.bitflip_hits}/{t.bitflip_bits}"
        note = f"  [context-dependent {t.context_rate}]" if t.status == CONTEXT_DEP else ""
        print(f"  {i:<4} #{t.instr_index:<4} 0x{t.address:08x}  {t.disasm[:24]:<24} "
              f"{yn(t.skip):<4} {bf:<7} {yn(t.zero):<4} {yn(t.ones):<4} "
              f"{t.score:.2f}{note}")
    if len(r.targets) > top:
        print(f"  ... {len(r.targets) - top} more")
    print("\n  hot zones (contiguous exploitable instructions; a glitch landing "
          "anywhere\n  inside still bypasses, so wide zones forgive timing "
          "error):")
    for z in r.zones[:5]:
        span = (f"#{z.start_index}" if z.width == 1
                else f"#{z.start_index}-#{z.end_index}")
        print(f"    {span:<10} 0x{z.start_addr:08x}-0x{z.end_addr:08x}  "
              f"width {z.width:<3} cumulative score {z.score_sum:.2f}")
    print("\n  Choose among top targets by trigger observability too (an "
          "instruction right\n  after a visible event is easier to time).")


def print_robustness(rep: RobustnessReport, max_dropped: int = 15) -> None:
    line = "=" * 70
    nv = len(rep.stub_variants)
    print(f"\n{line}")
    print(f"FINDING ROBUSTNESS  ({nv} stub variant{'s' * (nv != 1)}, "
          f"{rep.contexts_valid} register context"
          f"{'s' * (rep.contexts_valid != 1)})")
    print(line)
    rob, ctx, val = (rep.by_status(s) for s in (ROBUST, CONTEXT_DEP, VALUE_DEP))
    print(f"  robust            : {len(rob):<4} bypass under every stub value and "
          f"register context")
    print(f"  context-dependent : {len(ctx):<4} kept; bypass only for some entry "
          f"register states")
    print(f"  value-dependent   : {len(val):<4} dropped; artifacts of specific "
          f"stub values")

    # Which stub addresses actually vary between variants (for labels).
    varying = [a for a in (rep.stub_variants[0] if rep.stub_variants else {})
               if len({v.get(a) for v in rep.stub_variants}) > 1]

    def grouped(items):
        g: Dict[Tuple[int, str], List[RobustFinding]] = {}
        for f in items:
            g.setdefault((f.address, f.model), []).append(f)
        return sorted(g.items(), key=lambda kv: (kv[1][0].instr_index or 0,
                                                 kv[0][1]))

    def label(fs: List[RobustFinding]) -> str:
        f = fs[0]
        idx = f"#{f.instr_index:<4}" if f.instr_index is not None else "#?   "
        bits = (" bits " + ",".join(str(x.bit) for x in fs)
                if f.model == FaultModel.BITFLIP.value else "")
        return (f"{idx}[{f.model:11}] 0x{f.address:08x}: {f.disasm}{bits}")

    if rob:
        print("\n  robust:")
        for _, fs in grouped(rob):
            print("    " + label(fs))
    if ctx:
        print("\n  context-dependent (verify what real callers leave in "
              "registers):")
        for _, fs in grouped(ctx):
            rates = ", ".join(f"{x.contexts_hit}/{x.contexts_valid}" for x in fs)
            print(f"    {label(fs)}   contexts {rates}")
    if val:
        print("\n  value-dependent, dropped:")
        shown = 0
        for _, fs in grouped(val):
            if shown >= max_dropped:
                print(f"    ... {len(grouped(val)) - shown} more")
                break
            f0, n = fs[0], len(rep.stub_variants)
            idx = f"#{f0.instr_index:<4}" if f0.instr_index is not None else "#?   "
            if f0.model == FaultModel.BITFLIP.value:
                what = " bits " + ",".join(f"{x.bit}({x.variants_hit}/{n})" for x in fs)
            else:
                what = f"   ({f0.variants_hit}/{n} values)"
            # Name the exact values only when every entry shares one small set.
            sets = {tuple(x.hit_variants) for x in fs}
            who = ""
            if varying and len(sets) == 1 and len(next(iter(sets))) <= 3:
                who = "   only with " + "; ".join(
                    ", ".join(f"0x{a:08x}=0x{rep.stub_variants[i][a]:x}" for a in varying)
                    for i in next(iter(sets)))
            print(f"    {idx}[{f0.model:11}] 0x{f0.address:08x}: {f0.disasm}{what}{who}")
            shown += 1
    for n in rep.notes:
        print(f"  note: {n}")
    if rob or ctx:
        print(f"\n  VERDICT: {len(rob)} robust single-fault bypass(es)"
              + (f", {len(ctx)} more depend on entry register state." if ctx else "."))
    else:
        print("\n  VERDICT: no bypass survives robustness checks.")


def print_report(emu: SecureBootEmulator, golden: RunResult,
                 single_wins: List[RunResult],
                 campaign_wins: Optional[List[RunResult]] = None,
                 hints: Optional[List[str]] = None) -> None:
    line = "=" * 70
    print(line)
    print("SECURE-BOOT FAULT-INJECTION VIABILITY REPORT")
    print(line)

    print(f"\n[golden run] no faults")
    print(f"  outcome      : {golden.outcome.value}")
    print(f"  instructions : {golden.instr_count}")
    if golden.outcome is not Outcome.FAIL:
        if hints:
            print("  WARNING: baseline did not reach the FAIL branch; see the "
                  "diagnosis in HARDWARE ENVIRONMENT. Results below are not "
                  "trustworthy until the baseline FAILs.")
        else:
            print("  WARNING: baseline did not reach the FAIL branch. The "
                  "oracle (success/fail addresses or predicates) is probably "
                  "wrong, or the image you loaded is already valid. Fix this "
                  "before trusting the sweep.")

    print(f"\n[single instruction-skip sweep]")
    if not single_wins:
        print("  no single skip flipped FAIL -> SUCCESS in the swept range.")
    else:
        print(f"  {len(single_wins)} single-skip glitch target(s) flip the boot "
              f"decision to SUCCESS:\n")
        for res in single_wins:
            f = res.faults[0]
            print(f"  * skip @ 0x{f.address:08x}")
            print("      " + emu.disasm_at(f.address, 1).replace("\n", "\n      "))
            print(f"      reached SUCCESS after {res.instr_count} instructions")

    if campaign_wins is not None:
        print(f"\n[randomized multi-glitch campaign]")
        single_addrs = {r.faults[0].address for r in single_wins}
        # Keep only combos that genuinely REQUIRE >1 glitch: none of their
        # skipped addresses is already a standalone single-skip bypass.
        multi = [
            r for r in campaign_wins
            if len(r.faults) > 1
            and not any(f.address in single_addrs for f in r.faults)
        ]
        if not multi:
            print("  no multi-glitch-only bypass found "
                  "(every winning combo already contains a single-skip target "
                  "above).")
        else:
            print(f"  {len(multi)} multi-instruction skip combination(s) reach "
                  f"SUCCESS:\n")
            for res in sorted(multi, key=lambda r: len(r.faults)):
                addrs = ", ".join(f"0x{f.address:08x}" for f in res.faults)
                print(f"  * skip {{{addrs}}}  ({len(res.faults)} glitches)")

    print(f"\n{line}")
    viable = bool(single_wins) or bool(
        [r for r in (campaign_wins or []) if len(r.faults) > 1]
    )
    if viable:
        n = len(single_wins)
        print(f"VERDICT: FAULT INJECTION IS VIABLE.")
        if n:
            print(f"  {n} single-instruction-skip target(s) bypass verification. "
                  f"A single, well-timed glitch is sufficient.")
        else:
            print("  Only multi-glitch bypasses were found; a single glitch was "
                  "not sufficient in the swept range.")
        print("  Hardening: add redundant checks / flow-integrity counters around "
              "the targets above so no single skipped branch reaches the success "
              "path.")
    else:
        print("VERDICT: no instruction-skip bypass found in the analyzed range.")
        print("  This is NOT proof of resistance - widen the swept range, add "
              "register-corruption / flag-flip models, or try more glitches.")
    print(line)


# --------------------------------------------------------------------------- #
# Built-in demo: a synthetic, deliberately-glitchable Thumb secure-boot stub
# --------------------------------------------------------------------------- #
def build_demo_firmware() -> Tuple[bytes, int, int, int, int]:
    """Assemble a tiny Cortex-M 'secure boot' routine with a signature check
    that is supposed to FAIL. Returns (bytes, base, entry, success_addr,
    fail_addr).

    The routine:
        start:  movs r1, #0      ; computed signature-valid flag = 0 (INVALID)
                movs r2, #1      ; expected = 1 (VALID)
                cmp  r1, r2      ; valid?
                bne  fail        ; no -> fail          <-- the glitch target
        good:   movs r0, #0xA5   ; SUCCESS marker, boot the app
                b    done
        fail:   movs r0, #0xDE   ; FAIL marker, halt/reset
        done:   nop
    """
    import keystone

    base = 0x08000000
    asm = (
        "movs r1, #0\n"       # 0x00
        "movs r2, #1\n"       # 0x02
        "cmp  r1, r2\n"       # 0x04
        "bne  fail\n"         # 0x06   (2 bytes)
        "good:\n"
        "movs r0, #0xA5\n"    # 0x08  <- success branch
        "b    done\n"         # 0x0a
        "fail:\n"
        "movs r0, #0xDE\n"    # 0x0c  <- fail branch
        "done:\n"
        "nop\n"               # 0x0e
    )
    ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)
    encoding, _ = ks.asm(asm, base)
    fw = bytes(encoding)
    entry = base
    success_addr = base + 0x08   # 'good'
    fail_addr = base + 0x0C      # 'fail'
    return fw, base, entry, success_addr, fail_addr


def run_demo() -> int:
    print("Building synthetic vulnerable Thumb secure-boot stub...\n")
    fw, base, entry, success_addr, fail_addr = build_demo_firmware()

    cfg = EmulatorConfig(
        arch="arm-thumb",
        load_addr=base,
        entry=entry,
        stack_addr=0x20000000,
        success_addrs=(success_addr,),
        fail_addrs=(fail_addr,),
        max_instr=1000,
    )
    emu = SecureBootEmulator(fw, cfg)

    print("Static decision points (candidate secure-boot branches):")
    for addr, m, ops in emu.detect_decision_points():
        print(f"  0x{addr:08x}: {m} {ops}".rstrip())
    print()

    golden = emu.golden_run()
    single_wins = emu.sweep_single_skip()
    campaign_wins = emu.random_campaign(iterations=500, max_glitches=2, seed=1)

    print_report(emu, golden, single_wins, campaign_wins)
    ch = emu.characterize(models=(FaultModel.SKIP, FaultModel.BITFLIP))
    print_characterization(ch)
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Assessment report
#
# Turns the analysis into a reviewable document. Weakness patterns are
# detected by explicit rules over the robust findings (which fault mechanisms
# bypass at which class of instruction), each listed with the instructions
# that triggered it, so every claim in the report can be traced to evidence.
# --------------------------------------------------------------------------- #
_COND_SUFFIXES = ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
                  "hi", "ls", "ge", "lt", "gt", "le")


def classify_instruction(emu: "SecureBootEmulator", address: int) -> str:
    """call | cond-branch | branch | compare | mov-imm | move | load | other"""
    text = emu._insn_text(address)[0]
    mn, _, ops = text.partition(" ")
    root = mn.split(".")[0].lower()
    if emu.spec.uc_arch == UC_ARCH_X86:
        if root == "call":
            return "call"
        if root.startswith("j"):
            return "branch" if root == "jmp" else "cond-branch"
        if root in ("cmp", "test"):
            return "compare"
        if root == "mov":
            src = ops.split(",")[-1].strip()
            if "[" in src:
                return "load"
            return "mov-imm" if src.lstrip("-").startswith(("0x", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9")) else "move"
        return "other"
    if root in ("bl", "blx") or (emu.spec.name == "arm64" and root in ("bl", "blr")):
        return "call"
    if root in ("cbz", "cbnz", "tbz", "tbnz") or mn.lower().startswith("b.") \
            or (root.startswith("b") and root[1:] in _COND_SUFFIXES):
        return "cond-branch"
    if root in ("b", "bx", "br", "ret"):
        return "branch"
    if root in ("cmp", "cmn", "tst", "teq"):
        return "compare"
    if root in ("mov", "movs", "movw", "mvn", "mvns"):
        return "mov-imm" if "#" in ops else "move"
    if root.startswith(("ldr", "ldm")) or root == "pop":
        return "load"
    return "other"


def value_role(emu: "SecureBootEmulator", address: int, horizon: int = 64) -> str:
    """What the value written by the instruction at `address` is used for,
    following the unfaulted execution forward to its first reader:
      compare-operand  the first reader is a compare/test
      status           the first reader propagates it (copy, narrow, return)
      none             nothing reads it within the horizon, or no register
    """
    gprs, _ = emu._dest_regs(address)          # also creates emu._cs_detail
    if not gprs or emu._golden is None:
        return "none"
    trace = [a for a, _ in emu._golden.trace]
    try:
        i = trace.index(address)
    except ValueError:
        return "none"
    live = set(gprs)
    for a in trace[i + 1:i + 1 + horizon]:
        off = a - emu.cfg.load_addr
        insn = next(iter(emu._cs_detail.disasm(emu.fw[off:off + 16], a)), None)
        if insn is None:
            break
        try:
            r, wr = insn.regs_access()
        except Exception:
            break
        reads = {insn.reg_name(x) for x in r}
        writes = {insn.reg_name(x) for x in wr}
        if reads & live:
            return ("compare-operand" if classify_instruction(emu, a) == "compare"
                    else "status")
        live -= writes
        if not live:
            break
    return "none"


class _MechView:
    """skip / bit-flip / zero / ones flags for one instruction, from either
    its robust mechanisms or all of its (robust + context-dependent) ones."""
    def __init__(self, skip=False, bits=0, nbits=0, zero=False, ones=False):
        self.skip, self.bitflip_hits, self.bitflip_bits = skip, bits, nbits
        self.zero, self.ones = zero, ones

    def any(self) -> bool:
        return bool(self.skip or self.bitflip_hits or self.zero or self.ones)


def _mechanisms(emu: "SecureBootEmulator", source) -> Dict[int, dict]:
    """{address: {"robust": _MechView, "all": _MechView, "rates": str}} from a
    RobustnessReport (value-dependent dropped) or a Characterization."""
    acc: Dict[int, dict] = {}
    if isinstance(source, RobustnessReport):
        rows = [(f.model, f.address, f.bit, f.status,
                 f"{f.contexts_hit}/{f.contexts_valid}" if f.status == CONTEXT_DEP else None)
                for f in source.findings if f.status != VALUE_DEP]
    else:
        rows = [(f.model, f.address, f.bit, ROBUST, None) for f in source.findings]
    for model, addr, bit, status, rate in rows:
        e = acc.setdefault(addr, {"r": {"skip": False, "bits": set(), "zero": False, "ones": False},
                                  "a": {"skip": False, "bits": set(), "zero": False, "ones": False},
                                  "rates": set()})
        for k in (("r", "a") if status == ROBUST else ("a",)):
            d = e[k]
            if model == FaultModel.SKIP.value:
                d["skip"] = True
            elif model == FaultModel.BITFLIP.value:
                d["bits"].add(bit)
            elif model == FaultModel.RESULT_ZERO.value:
                d["zero"] = True
            elif model == FaultModel.RESULT_ONES.value:
                d["ones"] = True
        if rate:
            e["rates"].add(rate)
    out = {}
    for addr, e in acc.items():
        nb = emu._insn_size(addr) * 8
        mk = lambda d: _MechView(d["skip"], len(d["bits"]), nb, d["zero"], d["ones"])
        out[addr] = {"robust": mk(e["r"]), "all": mk(e["a"]),
                     "rates": ", ".join(sorted(e["rates"]))}
    return out


def _mech(t) -> str:
    parts = []
    if t.skip:
        parts.append("skip")
    if t.bitflip_hits:
        parts.append(f"bit-flip {t.bitflip_hits}/{t.bitflip_bits}")
    if t.zero:
        parts.append("result=0")
    if t.ones:
        parts.append("result=~0")
    return ", ".join(parts) or "-"


def _mech_diff(m: dict) -> str:
    """Robust mechanisms, then the ones that only work in some contexts."""
    r, a = m["robust"], m["all"]
    extra = _MechView(a.skip and not r.skip, a.bitflip_hits - r.bitflip_hits,
                      a.bitflip_bits, a.zero and not r.zero, a.ones and not r.ones)
    txt = _mech(r) if r.any() else ""
    if extra.any():
        txt += ("; " if txt else "") + f"context-dependent: {_mech(extra)}" + (
            f" ({m['rates']} contexts)" if m["rates"] else "")
    return txt or "-"


# Rules: (key, title, predicate(view, class, role), why, remediation)
WEAKNESS_RULES = [
    ("unchecked-call",
     "A skipped call leaves a stale result that is accepted",
     lambda v, c, r: c == "call" and v.skip,
     "Skipping the call means the check never runs, and the caller acts on "
     "whatever its result register already held.",
     ["Initialise the result to a FAILURE constant before the call, so a "
      "skipped call reads as failure.",
      "Make the callee prove it ran: have it return a multi-bit SUCCESS "
      "constant it alone writes, or advance a flow-integrity counter that is "
      "checked before boot."]),
    ("single-branch",
     "One conditional branch decides the outcome",
     lambda v, c, r: c == "cond-branch" and (v.skip or v.bitflip_hits > 0),
     "Skipping or corrupting a single branch instruction redirects execution "
     "into the success path.",
     ["Repeat the decision with an independent, complementary check and fail "
      "closed if the two disagree.",
      "Place the failure handler so that corrupted branch targets cannot land "
      "in or before the success path; add random delays around the check."]),
    ("single-compare",
     "The compare result is trusted once",
     lambda v, c, r: c == "compare" and (v.skip or v.zero or v.ones),
     "Skipping the compare, or corrupting the flags it produces, makes a "
     "mismatch look like a match.",
     ["Compare twice with independently reloaded operands, and compare "
      "complementary encodings of the expected value.",
      "Use a multi-word comparison whose result is a multi-bit value rather "
      "than a single flag."]),
    ("compare-operand",
     "A value feeding the comparison can be skipped or corrupted",
     lambda v, c, r: r == "compare-operand" and c not in ("call", "cond-branch",
                                                          "branch", "compare")
     and v.any(),
     "The comparison checks the wrong value: skipping or corrupting how one "
     "operand is produced makes it equal the other (for example both left "
     "at 0).",
     ["Produce each operand twice from independent sources and check that "
      "the copies agree.",
      "Never let an unloaded or zeroed register equal the expected value: "
      "avoid 0 or all-ones encodings for 'valid' and for computed results."]),
    ("fail-open",
     "Fail-open status handling: corrupted values are accepted",
     lambda v, c, r: r == "status" and v.zero and v.ones,
     "Forcing this status value to all zeros AND to all ones both boot the "
     "image, so the code accepts anything other than a few specific failure "
     "codes.",
     ["Fail closed: boot only when the status equals a specific multi-bit "
      "SUCCESS constant (high Hamming distance from 0 and from all ones); "
      "treat every other value as failure.",
      "Do not encode success as 0 or derive the decision from a narrowed "
      "(uxtb/uxth) copy of the status."]),
    ("status-assignment",
     "A failure status assignment can be removed or corrupted",
     lambda v, c, r: c == "mov-imm" and r == "status" and (v.skip or v.zero or v.ones),
     "The instruction that records the failure can be skipped or its value "
     "corrupted, leaving the status at an accepting value.",
     ["Initialise the status to FAILURE and set SUCCESS only at the end of a "
      "fully completed check.",
      "Use multi-bit constants for both states so a skipped or corrupted "
      "assignment cannot produce SUCCESS."]),
]


def detect_weaknesses(emu: "SecureBootEmulator", mech: Dict[int, dict]) -> List[dict]:
    """Evaluate every rule on robust mechanisms; a rule matched only by
    context-dependent mechanisms is reported with that qualifier."""
    if emu._golden is None:
        emu.golden_run()
    idx: Dict[int, int] = {}
    for i, (a, _) in enumerate(emu._golden.trace):
        idx.setdefault(a, i)
    found = []
    for key, title, rule, why, fix in WEAKNESS_RULES:
        robust_ev, ctx_ev = [], []
        for addr, m in mech.items():
            c, r = classify_instruction(emu, addr), value_role(emu, addr)
            if rule(m["robust"], c, r):
                robust_ev.append(addr)
            elif rule(m["all"], c, r):
                ctx_ev.append(addr)
        if robust_ev or ctx_ev:
            found.append({"key": key, "title": title, "why": why, "remediation": fix,
                          "robust": sorted(robust_ev, key=lambda a: idx.get(a, 0)),
                          "context": sorted(ctx_ev, key=lambda a: idx.get(a, 0))})
    return found


def write_report(path: str, *, emu: "SecureBootEmulator", fw_path: str,
                 command: str, golden: RunResult, models: Sequence[FaultModel],
                 ranking: BenchRanking, source, rep: Optional[RobustnessReport],
                 dres: Optional[DoubleFaultResult], calibration: Optional[dict],
                 stub_variants: List[Dict[int, int]],
                 retest: Optional[dict] = None) -> None:
    """Write the Markdown assessment report. `source` is the RobustnessReport
    (validated) or the Characterization (unvalidated) the findings come from."""
    import datetime
    import hashlib
    cfg, fw = emu.cfg, emu.fw
    h = lambda x: f"`0x{x:08x}`"
    validated = isinstance(source, RobustnessReport)
    mech = _mechanisms(emu, source)
    weak = detect_weaknesses(emu, mech)
    idx: Dict[int, int] = {}
    for i, (a, _) in enumerate(emu._golden.trace):
        idx.setdefault(a, i)
    score = {t.address: t.score for t in ranking.targets}
    robust_addrs = [a for a, m in mech.items() if m["robust"].any()]
    ctx_only = [a for a, m in mech.items() if not m["robust"].any()]
    st_ok = run_selftest(verbose=False)
    try:
        tool_sha = hashlib.sha256(open(__file__, "rb").read()).hexdigest()
    except OSError:
        tool_sha = "?"
    dis = lambda a: f"#{idx.get(a, '?')} {h(a)} `{emu._insn_text(a)[0]}`"
    L: List[str] = []
    w = L.append

    w("# Secure-boot fault-injection assessment\n")
    w(f"Generated {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC "
      f"by `secureboot_fi_emulator.py`. Emulation-based analysis: a finding shows "
      f"a fault is logically sufficient to bypass verification, not that a given "
      f"glitch produces it on silicon.\n")

    w("## Summary\n")
    if robust_addrs:
        ran = {m.value for m in models}
        per = {k: sum(1 for a in robust_addrs if f(mech[a]["robust"])) for k, f, need in (
            ("skip", lambda v: v.skip, FaultModel.SKIP.value),
            ("bit-flip", lambda v: v.bitflip_hits, FaultModel.BITFLIP.value),
            ("data", lambda v: v.zero or v.ones, FaultModel.RESULT_ZERO.value))
            if need in ran}
        w(f"- **A single fault bypasses verification.** {len(robust_addrs)} "
          f"instruction(s) have {'robust ' if validated else ''}single-fault bypasses ("
          + ", ".join(f"{k}: {v}" for k, v in per.items()) + ")"
          + (f"; {len(ctx_only)} more bypass only in some register contexts."
             if ctx_only else "."))
    elif ctx_only:
        w(f"- **Single-fault bypasses depend on register state:** {len(ctx_only)} "
          f"instruction(s) bypass only in some register contexts.")
    else:
        w("- **No single fault bypassed verification** under the models run "
          f"({', '.join(m.value for m in models)}).")
    if dres is not None:
        fm = ", ".join(dres.models)
        w(f"- **Fault-resistance order (models: {fm}):** " + {
            "1": "1, a single fault suffices.",
            "2": f"2, no single fault works but {len(dres.pairs)} pair(s) do.",
            ">2": "greater than 2, no single fault and no pair works."}[dres.order]
          + (" Search truncated: order not established." if dres.truncated else ""))
    stubs_txt = (f"{len(stub_variants)} stub value combination(s)" if cfg.stubs
                 else "no stubbed functions")
    if validated:
        w(f"- **Validation:** {stubs_txt}, "
          f"{source.contexts_valid} random register context(s); "
          f"{len(source.by_status(VALUE_DEP))} value-dependent artifact(s) dropped.")
    else:
        w("- **Validation: NONE.** No robustness check was run; re-run with "
          "several --stub values and/or --vary-regs before relying on these "
          "findings.")
    if weak:
        w("- **Weakness patterns:** " + "; ".join(
            x["title"] + ("" if x["robust"] else " (context-dependent evidence only)")
            for x in weak) + ".")
    w("")

    w("## Target and harness\n")
    w("| Item | Value |\n|---|---|")
    w(f"| Firmware | `{fw_path}` ({len(fw)} bytes) |")
    w(f"| SHA-256 | `{hashlib.sha256(fw).hexdigest()}` |")
    w(f"| Architecture | {emu.spec.name} |")
    w(f"| Load base / entry | {h(cfg.load_addr)} / {h(cfg.entry)} |")
    if cfg.initial_sp is not None:
        w(f"| Initial SP | {h(cfg.initial_sp)} |")
    if cfg.initial_regs:
        w("| Preset registers | " + ", ".join(f"{k}=0x{v:x}" for k, v in cfg.initial_regs.items()) + " |")
    w("| Success marker(s) | " + ", ".join(h(a) for a in cfg.success_addrs) + " |")
    w("| Fail marker(s) | " + ", ".join(h(a) for a in cfg.fail_addrs) + " |")
    for a in cfg.stubs:
        vals = sorted({v[a] for v in stub_variants if a in v}) or [cfg.stubs[a]]
        fl = (f"exit flags NZCV=0b{cfg.stub_exit_flags[a]:04b}"
              + (" (calibrated)" if calibration and a in calibration else "")
              if a in cfg.stub_exit_flags else "exit flags not modelled")
        w(f"| Stub {h(a)} | returns " + ", ".join(f"0x{x:x}" for x in vals) + f"; {fl} |")
    if cfg.mmio_reads:
        w("| Peripheral model | " + ", ".join(f"0x{a:08x}=0x{v:x}" for a, v in cfg.mmio_reads.items()) + " |")
    w(f"| Fault models | {', '.join(m.value for m in models)} |")
    w(f"| Instruction budget | {cfg.max_instr} per run |")
    _oracle = getattr(emu, "_oracle", None)
    if _oracle is not None:
        if _oracle.sound and _oracle.one_way:
            ov = "sound (one-way: tamper rejected; SUCCESS side unverified)"
        elif _oracle.sound:
            ov = "sound (tamper rejected, genuine accepted, unfaulted)"
        else:
            ov = "UNSOUND - findings below are suspect"
        w(f"| Oracle | {ov} |")
    w("")

    w("## Baseline\n")
    w(f"- Unfaulted run: **{golden.outcome.value}** after {golden.instr_count} "
      f"instructions (must be FAIL for a tampered image).")
    if validated and source.excluded_variants:
        w("- Stub values excluded because the image verifies with them: " + "; ".join(
            ", ".join(f"0x{a:08x}=0x{x:x}" for a, x in v.items()) for v in source.excluded_variants) + ".")
    uv, cv = getattr(unicorn, "__version__", "?"), getattr(capstone, "__version__", "?")
    w(f"- Environment: unicorn {uv}, capstone {cv}; self-test "
      f"{'PASSED' if st_ok else '**FAILED**'}; engine: "
      f"{'fast reset' if cfg.fast_reset else 'fresh instance per run'}.")
    w(f"- Tool SHA-256: `{tool_sha}`\n")

    w("## Single-fault findings\n")
    if mech:
        w(("Findings that bypass for every stub value tested. Mechanisms marked "
           "context-dependent bypass only for some random entry-register states; "
           "check what real callers leave in those registers. "
           if validated else "UNVALIDATED findings. ")
          + "Score: share of modelled fault mechanisms at the instruction that "
          "bypass (used for bench ranking).\n")
        w("| # | Address | Instruction | Class | Role | Mechanisms that bypass | Score |")
        w("|---|---|---|---|---|---|---|")
        for a in sorted(mech, key=lambda a: idx.get(a, 0)):
            w(f"| {idx.get(a, '?')} | {h(a)} | `{emu._insn_text(a)[0]}` | "
              f"{classify_instruction(emu, a)} | {value_role(emu, a)} | "
              f"{_mech_diff(mech[a])} | {score.get(a, 0):.2f} |")
    else:
        w("None.")
    w("")

    w("## Weakness patterns and remediation\n")
    w("Each pattern is a rule over the findings above (instruction class, the "
      "role of the value it produces, and which fault mechanisms bypass). "
      "Review against the source before reporting.\n")
    if not weak:
        w("No rule matched.\n")
    for x in weak:
        w(f"### {x['title']}\n")
        w(x["why"] + "\n")
        if x["robust"]:
            w("Evidence: " + "; ".join(f"{dis(a)} ({_mech(mech[a]['robust'])})"
                                       for a in x["robust"]) + ".\n")
        if x["context"]:
            w("Context-dependent evidence: " + "; ".join(
                f"{dis(a)} ({_mech(mech[a]['all'])}; {mech[a]['rates'] or '-'} contexts)"
                for a in x["context"]) + ".\n")
        w("Remediation:\n")
        for r in x["remediation"]:
            w(f"- {r}")
        w("")

    w("## Bench plan\n")
    if ranking.targets:
        w("Highest-scoring targets (instruction index = executed instructions "
          "after the harness entry; calibrate absolute timing on the bench):\n")
        for t in ranking.targets[:5]:
            w(f"- {dis(t.address)}: score {t.score:.2f} ({_mech_diff(mech[t.address]) if t.address in mech else _mech(t)})")
        w("\nHot zones (a glitch anywhere inside bypasses):\n")
        for z in ranking.zones[:3]:
            span = (f"#{z.start_index} ({h(z.start_addr)})" if z.width == 1 else
                    f"#{z.start_index}-#{z.end_index} ({h(z.start_addr)}-{h(z.end_addr)})")
            w(f"- {span}: {z.width} instruction(s), cumulative score {z.score_sum:.2f}")
        w("\nAlso weigh trigger observability: a target just after a visible "
          "event is easier to time.")
    else:
        w("No single-fault target.")
    w("")

    if dres is not None:
        w("## Multi-fault resistance\n")
        w(f"Exhaustive pair search (models: {', '.join(dres.models)}): "
          f"{dres.firsts_tested} first fault(s), "
          f"{dres.pair_runs} pair run(s)"
          + (f", glitches at most {dres.window} instructions apart" if dres.window else "")
          + f"; {len(dres.pairs)} pair(s) bypass where neither fault does alone.\n")
        if dres.pairs:
            by: Dict[int, int] = {}
            for pr in dres.pairs:
                by[pr.second] = by.get(pr.second, 0) + 1
            w("Second-glitch targets (hardening these closes every pair):\n")
            for a, n in sorted(by.items(), key=lambda kv: -kv[1]):
                w(f"- {h(a)} `{emu._insn_text(a)[0]}`: {n} pair(s)")
        w("")

    if retest is not None:
        w("## Retest against previous build\n")
        o_sha, n_sha = retest["firmware_sha256"]
        w(f"**Verdict: {retest['verdict']}.**\n")
        w(f"- Before: `{o_sha}`; after: `{n_sha}`.")
        w(f"- Aligned {retest['aligned_instructions']} of "
          f"{retest['sequence_lengths'][0]} / {retest['sequence_lengths'][1]} "
          f"executed instructions (matching is by instruction, not address).")
        w(f"- Instructions with robust single-fault bypasses: "
          f"{retest['robust_targets'][0]} before, {retest['robust_targets'][1]} after.")
        fo = retest["fault_order"]
        if fo[0] or fo[1]:
            w(f"- Fault-resistance order: {fo[0] or 'not run'} before, "
              f"{fo[1] or 'not run'} after.")
        for nt in retest["notes"]:
            w(f"- Note: {nt}.")
        w("\n| Status | Before | After | Instruction | Mechanisms before | Mechanisms after |")
        w("|---|---|---|---|---|---|")
        for r in retest["rows"]:
            b = h(r["old"]) if r["old"] is not None else "-"
            a = h(r["new"]) if r["new"] is not None else "-"
            w(f"| {r['status']} | {b} | {a} | `{r['text']}` | {r['before']} | {r['after']} |")
        w("")

    w("## Reproduction\n")
    w("```\n" + command + "\n```\n")
    w("## Limitations\n")
    for l in (
        "Emulation, not silicon: a finding shows a fault is sufficient, not that "
        "a specific glitch produces it on a specific chip.",
        "Stubbed functions are not fault-tested internally (e.g. a CRC loop); a "
        "stub models the return value and, if calibrated, the exit flags only.",
        "Fault models: " + ", ".join(m.value for m in models) + "; the "
        "double-fault search covers skips only.",
        "Weakness patterns are rule-based; the role of a value is inferred from "
        "the first instruction that reads it on the unfaulted path.",
    ):
        w(f"- {l}")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")


# --------------------------------------------------------------------------- #
# Retest comparison
#
# Verifying a fix means comparing two builds whose addresses differ.
# Findings are matched through their instructions: the two unfaulted
# execution sequences are aligned (difflib) after normalising build-specific
# details (branch targets and other addresses, PC-relative literal offsets),
# so each old instruction maps to its counterpart in the new build, or to
# nothing if that code changed.
# --------------------------------------------------------------------------- #
import difflib as _difflib
import re as _re

_ADDR_LIT = _re.compile(r"#?-?0x[0-9a-f]{4,}")
_PC_REL = _re.compile(r"\[(pc|rip)[^\]]*\]")


def normalize_instruction(text: str) -> str:
    t = _PC_REL.sub(r"[\1, LIT]", text.lower())
    return _ADDR_LIT.sub("ADDR", t)


def retest_snapshot(emu: "SecureBootEmulator", mech: Dict[int, dict],
                    models: Sequence[FaultModel], validated: bool,
                    dres: Optional["DoubleFaultResult"]) -> dict:
    import hashlib
    seen, seq = set(), []
    for a, _ in emu._golden.trace:
        if a not in seen:
            seen.add(a)
            seq.append([a, emu._insn_text(a)[0]])
    return {
        "firmware_sha256": hashlib.sha256(emu.fw).hexdigest(),
        "arch": emu.spec.name,
        "entry": emu.cfg.entry,
        "models": [m.value for m in models],
        "validated": validated,
        "fault_order": dres.order if dres is not None else None,
        "fault_order_models": dres.models if dres is not None else None,
        "fault_order_truncated": dres.truncated if dres is not None else None,
        "sequence": seq,
        "findings": {str(a): {"text": emu._insn_text(a)[0],
                              "robust": _mech(m["robust"]),
                              "all": _mech(m["all"]),
                              "robust_any": m["robust"].any()}
                     for a, m in mech.items()},
    }


RETEST_ORDER = ("still exploitable", "regression", "new", "reduced",
                "still context-dependent", "code changed", "closed")


def compare_snapshots(old: dict, new: dict) -> dict:
    """Classify every old finding (closed / reduced / still exploitable /
    code changed) and every new one (regression on unchanged code, new in
    changed code) after aligning the two execution sequences."""
    o_seq, n_seq = old["sequence"], new["sequence"]
    sm = _difflib.SequenceMatcher(
        a=[normalize_instruction(t) for _, t in o_seq],
        b=[normalize_instruction(t) for _, t in n_seq], autojunk=False)
    amap: Dict[int, int] = {}
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                amap[o_seq[i1 + k][0]] = n_seq[j1 + k][0]
    of = {int(k): v for k, v in old["findings"].items()}
    nf = {int(k): v for k, v in new["findings"].items()}
    rows = []
    for a, f in sorted(of.items()):
        if a not in amap:
            rows.append({"status": "code changed", "old": a, "new": None,
                         "text": f["text"], "before": f["all"], "after": "-"})
            continue
        b = amap[a]
        g = nf.get(b)
        if g is None:
            st, after = "closed", "-"
        elif g["robust_any"]:
            st, after = "still exploitable", g["all"]
        elif f["robust_any"]:
            st, after = "reduced", g["all"] + " (context-dependent only)"
        else:
            st, after = "still context-dependent", g["all"] + " (context-dependent only)"
        rows.append({"status": st, "old": a, "new": b, "text": f["text"],
                     "before": f["all"], "after": after})
    mapped_new = {b: a for a, b in amap.items()}
    for b, g in sorted(nf.items()):
        a = mapped_new.get(b)
        if a is not None and a in of:
            continue
        rows.append({"status": "regression" if a is not None else "new",
                     "old": a, "new": b, "text": g["text"], "before": "-",
                     "after": g["all"] + ("" if g["robust_any"] else
                                          " (context-dependent only)")})
    rows.sort(key=lambda r: (RETEST_ORDER.index(r["status"]),
                             r["new"] if r["new"] is not None else r["old"]))
    count = lambda st: sum(1 for r in rows if r["status"] == st)
    old_robust = sum(1 for f in of.values() if f["robust_any"])
    new_robust = sum(1 for g in nf.values() if g["robust_any"])
    notes = []
    if old["models"] != new["models"]:
        notes.append(f"fault models differ (before: {', '.join(old['models'])}; "
                     f"after: {', '.join(new['models'])}); results are not "
                     f"directly comparable")
    if (old.get("fault_order") and new.get("fault_order")
            and old.get("fault_order_models", ["skip"]) != new.get("fault_order_models", ["skip"])):
        notes.append("fault order established under different models (before: "
                     + ", ".join(old.get("fault_order_models") or ["skip"]) + "; after: "
                     + ", ".join(new.get("fault_order_models") or ["skip"]) + ")")
    if old["validated"] != new["validated"]:
        notes.append("only one of the two runs was robustness-validated")
    if old["firmware_sha256"] == new["firmware_sha256"]:
        notes.append("both runs analysed the same firmware image")
    unresolved = [r for r in rows if r["status"] in ("still exploitable", "regression")
                  or (r["status"] == "new" and "context-dependent" not in r["after"])]
    residual = [r for r in rows if "context-dependent only" in r["after"]]
    if unresolved or new_robust:
        verdict = "FIX INCOMPLETE"
    else:
        parts = []
        if count("code changed"):
            parts.append(f"{count('code changed')} old finding(s) were in changed "
                         f"code and are not counted as closed by matching")
        if residual:
            parts.append(f"{len(residual)} finding(s) remain context-dependent; "
                         f"check the register state real callers leave")
        verdict = ("NO ROBUST SINGLE-FAULT BYPASS REMAINS" if parts
                   else "ALL SINGLE-FAULT FINDINGS CLOSED") + \
                  ("; " + "; ".join(parts) if parts else "")
    return {"verdict": verdict, "rows": rows, "notes": notes,
            "aligned_instructions": len(amap),
            "sequence_lengths": [len(o_seq), len(n_seq)],
            "robust_targets": [old_robust, new_robust],
            "fault_order": [old["fault_order"], new["fault_order"]],
            "firmware_sha256": [old["firmware_sha256"], new["firmware_sha256"]],
            "counts": {st: count(st) for st in RETEST_ORDER}}


def print_retest(cmp: dict) -> None:
    line = "=" * 70
    print(f"\n{line}")
    print("RETEST AGAINST PREVIOUS BUILD")
    print(line)
    o, n = cmp["firmware_sha256"]
    print(f"  before {o[:16]}..  after {n[:16]}..  aligned "
          f"{cmp['aligned_instructions']} of {cmp['sequence_lengths'][0]} / "
          f"{cmp['sequence_lengths'][1]} instructions")
    print(f"  instructions with robust single-fault bypasses: "
          f"{cmp['robust_targets'][0]} -> {cmp['robust_targets'][1]}")
    fo = cmp["fault_order"]
    if fo[0] or fo[1]:
        print(f"  fault-resistance order: {fo[0] or 'not run'} -> "
              f"{fo[1] or 'not run'}")
    print("  " + ", ".join(f"{k}: {v}" for k, v in cmp["counts"].items() if v))
    for st in RETEST_ORDER:
        rs = [r for r in cmp["rows"] if r["status"] == st]
        if not rs:
            continue
        print(f"\n  {st}:")
        for r in rs:
            ad = (f"0x{r['old']:08x}" if r["old"] is not None else " " * 10) + " -> " + \
                 (f"0x{r['new']:08x}" if r["new"] is not None else "(gone)    ")
            print(f"    {ad}  {r['text']:<24} {r['before']}  =>  {r['after']}")
    for nt in cmp["notes"]:
        print(f"  note: {nt}")
    print(f"\n  VERDICT: {cmp['verdict']}")


# --------------------------------------------------------------------------- #
# Self-test
#
# Results rest on emulator behaviours that are undocumented and were found
# empirically on unicorn 2.1.4 / capstone 5.0.7: Thumb needs the entry LSB,
# PC redirects must keep the T-bit, the FPU must be enabled through CP15,
# write-protect hooks do not retry the access, translated code must be
# evicted after patching, a read hook over flash derails execution. Another
# library version can change any of them and silently produce wrong
# findings. --selftest checks each behaviour, and the end-to-end answers that
# depend on them, on the machine it runs on.
# --------------------------------------------------------------------------- #
TESTED_WITH = {"unicorn": "2.1.4", "capstone": "5.0.7"}

_SELFTEST_BLOBS = {
    "DEMO": bytes.fromhex("00210122914201d1a52000e0de2000bf"),
    # DEMO with movs r2,#1 -> movs r2,#0 so r1==r2: a genuine image that
    # reaches SUCCESS unfaulted (the accepted side of the oracle).
    "DEMO_GENUINE": bytes.fromhex("00210022914201d1a52000e0de2000bf"),
    # movs r1,#1 / movs r2,#2 / cmp / two consecutive "bne FAIL" guards.
    # Golden (r1!=r2) takes the first bne to FAIL and no single skip bypasses
    # (skipping either setup leaves the values unequal; skipping one guard
    # still hits the other). Only a width-2 wide glitch skips both guards and
    # falls through to SUCCESS. The second guard (B+8) is off the golden path,
    # so the single-skip sweep cannot even target it. SUCCESS=B+0xA, FAIL=B+0xE.
    "SKIPWIN": bytes.fromhex("01210222914202d101d1a52000e0de2000bf"),
    # A loop whose guard (beq at B+6) rejects the image on the SECOND pass
    # (r0==2). Skipping that guard on the first visit does nothing (not taken
    # when r0==1); only glitching visit#1 bypasses. SUCCESS=B+0x12, FAIL=B+0xE.
    "LOOPITER": bytes.fromhex("0020401c022802d00328fad101e0de2100e0a52100bf"),
    "HARDENED": bytes.fromhex("0021054a914204d1044b994201d1a520fde7de20fde700bf3cc3a55a3cc3a55a"),
    "HWBOOT": bytes.fromhex("40f20403c5f20603186810f0010ffbd000f006f8012801d1a52000e0de20fee740f20801c5f2060108687047"),
    "DATAFAULT": bytes.fromhex("0868002801d0de22fde7a522fde700000000000000000000000000000000000034120000"),
    "STUB": bytes.fromhex("00f00bf8072801d0de22fde7a522fde7012100f002f8f9d0f6e701207047"),
    "FPU": bytes.fromhex("0020e1ee100a00ee100a01e0de22fde7a522fde7"),
    "WILD": bytes.fromhex("40f20100c6f200000047de22fee7a522fee7"),
    "LAZYEXEC": bytes.fromhex("40f20000c6f20000016801300047de22fee7a522fee7"),
    "LEAK": bytes.fromhex("0c49086800280fd10b4a106800280bd10a4b1868002807d1ab200860106018600868ab2804d101e00124fde70224fde70324fde7000800080000006000010020"),
}


def _st_build_elf(cls64: bool, machine: int, entry: int) -> bytes:
    """Minimal ELF header (no program headers) for detection tests."""
    h = bytearray(64 if cls64 else 52)
    h[0:4] = b"\x7fELF"; h[4] = 2 if cls64 else 1; h[5] = 1; h[6] = 1
    struct.pack_into("<HHI", h, 16, 2, machine, 1)
    if cls64:
        struct.pack_into("<Q", h, 24, entry)
    else:
        struct.pack_into("<I", h, 24, entry)
    return bytes(h) + b"\x00" * 0x200


def run_selftest(verbose: bool = True) -> bool:
    """Known-answer tests for every emulator behaviour the analysis relies
    on. Returns True when all pass."""
    B = 0x08000000
    blobs = _SELFTEST_BLOBS

    def emu(name, entry=B, success=(), fail=(), **kw):
        kw.setdefault("max_instr", 500)
        return SecureBootEmulator(blobs[name], EmulatorConfig(
            arch="arm-thumb", load_addr=B, entry=entry, success_addrs=success,
            fail_addrs=fail, **kw))

    def path(r):
        return [a - B for a, _ in r.trace]

    checks = []

    def check(name):
        def deco(fn):
            checks.append((name, fn))
            return fn
        return deco

    @check("Thumb decoding from a T-bit entry")
    def _():
        g = emu("DEMO", success=(B + 8,), fail=(B + 0xC,)).golden_run()
        assert g.outcome is Outcome.FAIL and path(g) == [0, 2, 4, 6, 0xC], \
            f"{g.outcome.value} path {path(g)}"

    @check("skip keeps Thumb state (PC redirect with T-bit)")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        r = e.run(faults=[Fault(B + 2)], record_trace=True)
        assert r.outcome is Outcome.SUCCESS and path(r) == [0, 2, 4, 6, 8], \
            f"{r.outcome.value} path {path(r)}"

    @check("single-skip sweep known answer")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        got = sorted(r.faults[0].address - B for r in e.sweep_single_skip())
        assert got == [2, 6], f"targets {[hex(x) for x in got]}"

    @check("bit-flip known answer (corrupted-encoding semantics)")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        e.golden_run()
        want = {0: [0], 2: [0, 8, 9, 10, 11, 13, 14], 4: [3, 4, 5, 7, 8, 9],
                6: [8, 10, 12, 14, 15]}
        got = {o: [b for b in range(16)
                   if e.run(faults=[Fault(B + o, FaultModel.BITFLIP, bit=b)]).outcome
                   is Outcome.SUCCESS] for o in want}
        assert got == want, f"got {got}"

    @check("two-way oracle validation (tamper FAIL, genuine SUCCESS)")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        r = e.validate_oracle(genuine_firmware=blobs["DEMO_GENUINE"])
        assert r.sound and not r.one_way, r.messages
        assert (r.tamper_outcome is Outcome.FAIL
                and r.genuine_outcome is Outcome.SUCCESS), r
        # genuine-stub path: same image, a stub-style matching measurement is
        # not available for DEMO, so exercise one-way (no reference given).
        r1 = emu("DEMO", success=(B + 8,), fail=(B + 0xC,)).validate_oracle()
        assert r1.sound and r1.one_way and r1.genuine_outcome is None, r1
        # unsound: the genuine image does not reach SUCCESS (markers swapped)
        r2 = emu("DEMO", success=(B + 0xC,), fail=(B + 8,)).validate_oracle(
            genuine_firmware=blobs["DEMO_GENUINE"])
        assert not r2.sound, r2
        # unsound: the image under analysis already passes with no fault
        r3 = emu("DEMO_GENUINE", success=(B + 8,), fail=(B + 0xC,)) \
            .validate_oracle(genuine_firmware=blobs["DEMO_GENUINE"])
        assert not r3.sound and r3.tamper_outcome is Outcome.SUCCESS, r3

    @check("iteration-aware sweep finds a loop-pass-specific bypass")
    def _():
        e = emu("LOOPITER", success=(B + 0x12,), fail=(B + 0xE,))
        g = e.golden_run()
        assert g.outcome is Outcome.FAIL, g.outcome.value
        # the guard's first visit is not the one that rejects the image
        assert e.run(faults=[Fault(B + 6, FaultModel.SKIP, nth=0)]).outcome \
            is Outcome.FAIL
        assert e.run(faults=[Fault(B + 6, FaultModel.SKIP, nth=1)]).outcome \
            is Outcome.SUCCESS
        # the ordinary first-visit sweep never tries visit#1 of the guard
        assert not any(r.faults[0].address == B + 6
                       for r in e.sweep_single_skip())
        # the iteration-aware sweep finds the visit#1 bypass
        wins = e.sweep_iterations(max_iters=8)
        hit = [r for r in wins
               if r.faults[0].address == B + 6 and r.faults[0].nth == 1]
        assert hit, [(hex(r.faults[0].address - B), r.faults[0].nth)
                     for r in wins]

    @check("divergence: find the branch a bypass subverts")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        e.golden_run()
        # skipping the guard: the bne at B+6 sends execution to B+8 (SUCCESS)
        # instead of the golden B+0xC (FAIL).
        d = e.explain([Fault(B + 6, FaultModel.SKIP)])
        assert d.faulted_outcome is Outcome.SUCCESS, d
        assert d.split_addr == B + 6, hex(d.split_addr or 0)
        assert d.golden_next == B + 0xC and d.faulted_next == B + 8, d
        assert "SUCCESS" in d.note
        # glitching the compared value (skip movs r2) subverts the SAME branch:
        # the mechanism of action is the bne going the other way.
        d2 = e.explain([Fault(B + 2, FaultModel.SKIP)])
        assert d2.faulted_outcome is Outcome.SUCCESS and d2.split_addr == B + 6, d2
        # a fault that does not change control flow is reported as such
        d3 = e.explain([Fault(B + 4, FaultModel.SKIP)])
        assert d3.golden_next is None and d3.faulted_next is None, d3

    @check("wide-glitch skip window (single glitch skips consecutive insns)")
    def _():
        e = emu("SKIPWIN", success=(B + 0xA,), fail=(B + 0xE,))
        g = e.golden_run()
        assert g.outcome is Outcome.FAIL, g.outcome.value
        # no single skip on the golden path bypasses
        assert e.sweep_single_skip() == [], \
            [hex(r.faults[0].address - B) for r in e.sweep_single_skip()]
        # the second guard is off the golden path, so single-sweep can't reach it
        assert (B + 8) not in {a for a, _ in g.trace}
        # one wide glitch of width 2 at the first guard bypasses; width 1 does not
        assert e.run(faults=[Fault(B + 6, FaultModel.SKIP, width=1)]).outcome \
            is Outcome.FAIL
        assert e.run(faults=[Fault(B + 6, FaultModel.SKIP, width=2)]).outcome \
            is Outcome.SUCCESS
        ww = e.sweep_skip_window(max_width=4)
        hit = [r for r in ww if r.faults[0].address == B + 6]
        assert hit and hit[0].faults[0].width == 2, \
            [(hex(r.faults[0].address - B), r.faults[0].width) for r in ww]

    @check("data faults land after write-back")
    def _():
        e = emu("DATAFAULT", success=(B + 0xA,), fail=(B + 6,),
                initial_regs={"r1": B + 0x20})
        assert e.golden_run().outcome is Outcome.FAIL
        z = e.run(faults=[Fault(B, FaultModel.RESULT_ZERO)]).outcome
        o = e.run(faults=[Fault(B + 2, FaultModel.RESULT_ONES)]).outcome
        n = e.run(faults=[Fault(B + 2, FaultModel.RESULT_ZERO)]).outcome
        assert (z, o, n) == (Outcome.SUCCESS, Outcome.SUCCESS, Outcome.FAIL), \
            f"ldr->0 {z.value}, cmp->ones {o.value}, cmp->zero {n.value}"

    @check("stub returns into a Thumb caller with its value")
    def _():
        g = emu("STUB", success=(B + 0xC,), fail=(B + 8,)).golden_run().outcome
        s = emu("STUB", success=(B + 0xC,), fail=(B + 8,),
                stubs={B + 0x1A: 7}).golden_run().outcome
        assert (g, s) == (Outcome.FAIL, Outcome.SUCCESS), f"real {g.value}, stubbed {s.value}"

    @check("stub exit flags and calibration")
    def _():
        kw = dict(entry=B + 0x10, success=(B + 0xC,), fail=(B + 8,))
        plain = emu("STUB", stubs={B + 0x1A: 0}, **kw).golden_run().outcome
        flagged = emu("STUB", stubs={B + 0x1A: 0}, stub_exit_flags={B + 0x1A: 0x4},
                      **kw).golden_run().outcome
        cal = emu("STUB", stubs={B + 0x1A: 0}, **kw).calibrate_stubs(10_000)[B + 0x1A]
        assert (plain, flagged) == (Outcome.FAIL, Outcome.SUCCESS), \
            f"caller flags {plain.value}, Z set {flagged.value}"
        assert cal["completed"] == 1 and cal["exit_flags"] == [0], f"calibration {cal}"

    @check("FPU enabled for hard-float code")
    def _():
        g = emu("FPU", success=(B + 0x10,), fail=(B + 0xC,)).golden_run()
        assert g.outcome is Outcome.SUCCESS, f"{g.outcome.value}: {g.error}"

    @check("unmapped fetch crashes (not lazily mapped)")
    def _():
        e = emu("WILD", success=(B + 0xE,), fail=(B + 0xA,))
        _, acc = e.discover_mmio()
        g = e.golden_run()
        hints = " ".join(e.diagnose(g, acc))
        assert g.outcome is Outcome.CRASH and "0x60000000" in hints, \
            f"{g.outcome.value}; diagnosis: {hints[:80]}"

    @check("lazily mapped data page is not executable")
    def _():
        # Read from an unmapped page (maps it as data), then jump into it:
        # must crash immediately, not execute the zero-filled page.
        e = emu("LAZYEXEC", success=(B + 0x12,), fail=(B + 0xE,))
        r = e.run(record_trace=True)
        assert r.outcome is Outcome.CRASH and r.last_pc == B + 0xC, \
            f"{r.outcome.value}, last executed 0x{(r.last_pc or 0):x}"

    @check("peripheral poll diagnosis, then modelled baseline")
    def _():
        e = emu("HWBOOT", success=(B + 0x18,), fail=(B + 0x1C,), max_instr=3000)
        _, acc = e.discover_mmio()
        g = e.golden_run()
        polls = [a["address"] for a in acc if a["poll"]]
        assert g.outcome is Outcome.HANG and polls == [0x50060004], \
            f"{g.outcome.value}, polls {[hex(x) for x in polls]}"
        assert "0x50060004" in " ".join(e.diagnose(g, acc))
        m = emu("HWBOOT", success=(B + 0x18,), fail=(B + 0x1C,), max_instr=3000,
                mmio_reads={0x50060004: 1}).golden_run().outcome
        assert m is Outcome.FAIL, f"modelled baseline {m.value}"

    @check("discovery hooks never cover flash/RAM (read-hook derail guard)")
    def _():
        # A memory-read hook over executing flash derails Unicorn 2.x on real
        # Cortex-M startup code (an IT block with a conditional load inside
        # the C runtime's decompressor). Small programs do not trigger it, so
        # check the invariant that avoids it: discovery may only hook the
        # gaps between known memory regions.
        e = emu("HWBOOT", success=(B + 0x18,), fail=(B + 0x1C,), max_instr=300)
        recorded = []
        orig = Uc.hook_add

        def spy(self_, htype, cb, user_data=None, begin=1, end=0, *a, **k):
            recorded.append((htype, begin, end))
            return orig(self_, htype, cb, user_data, begin, end, *a, **k)

        Uc.hook_add = spy
        try:
            e.discover_mmio()
        finally:
            Uc.hook_add = orig
        access = UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE
        flash = (B, B + e._page_align(max(e.cfg.load_size, len(e.fw))))
        ram = (e.cfg.stack_addr, e.cfg.stack_addr + e._page_align(e.cfg.stack_size))
        bad = []
        for htype, b, en in recorded:
            if not htype & access or htype & UC_HOOK_CODE:
                continue
            lo, hi = (0, 1 << 64) if b > en else (b, en + 1)   # begin>end = all memory
            for rb, re_ in (flash, ram):
                if lo < re_ and rb < hi:
                    bad.append(f"hook 0x{b:x}-0x{en:x} overlaps 0x{rb:x}-0x{re_:x}")
        assert not bad, "; ".join(bad[:2])

    @check("fast reset: no state leaks (flash, lazy page, RAM)")
    def _():
        e = emu("LEAK", success=(B + 0x28,), fail=(B + 0x2C,), max_instr=200)
        outs = [e.run().outcome for _ in range(4)]
        e.run(faults=[Fault(B, FaultModel.RESULT_ONES)])
        outs += [e.run().outcome for _ in range(3)]
        assert all(o is Outcome.FAIL for o in outs), \
            f"runs {[o.value for o in outs]} (SUCCESS = leak, HANG = write lost)"

    @check("fast reset: code cache evicted after a bit-flip")
    def _():
        e = emu("DEMO", success=(B + 8,), fail=(B + 0xC,))
        assert e.run(faults=[Fault(B + 6, FaultModel.BITFLIP, bit=8)]).outcome \
            is Outcome.SUCCESS
        g = e.run(record_trace=True)
        assert g.outcome is Outcome.FAIL and path(g) == [0, 2, 4, 6, 0xC], \
            f"after patch: {g.outcome.value} path {path(g)}"

    @check("fast reset equals fresh instances (random faults)")
    def _():
        for name, s_, f_ in (("DEMO", 8, 0xC), ("HARDENED", 0xE, 0x12)):
            mm = emu(name, success=(B + s_,), fail=(B + f_,)).verify_fast_reset(150, seed=1)
            assert not mm, f"{name}: {mm[0]}"

    @check("fast reset: instance recycling is invisible to results")
    def _():
        e = emu("HARDENED", success=(B + 0xE,), fail=(B + 0x12,), fast_recycle=5)
        builds = [0]
        orig = e._fast_build

        def counting_build():
            builds[0] += 1
            return orig()
        e._fast_build = counting_build
        mm = e.verify_fast_reset(60, seed=2)
        assert not mm, mm[0]
        assert builds[0] >= 10, f"instance built {builds[0]} time(s), expected >= 10"

    @check("double-fault known answer (hardened stub: order 2, 8 pairs)")
    def _():
        r = emu("HARDENED", success=(B + 0xE,), fail=(B + 0x12,)).double_fault_sweep()
        assert r.order == "2" and len(r.pairs) == 8, f"order {r.order}, {len(r.pairs)} pairs"

    @check("architecture detection: Cortex-M vector table")
    def _():
        img = bytearray(b"\xff" * 0x400)
        struct.pack_into("<I", img, 0, 0x20004000)
        for i in range(1, 12):
            struct.pack_into("<I", img, 4 * i, (B + 0x101 + 0x10 * i) | 1)
        d = detect_architecture(bytes(img))
        assert (d.arch, d.base_addr, d.entry, d.initial_sp) == \
            ("arm-thumb", B, B + 0x110, 0x20004000), \
            f"{d.arch} base {d.base_addr} entry {d.entry} sp {d.initial_sp}"

    @check("architecture detection: ELF headers")
    def _():
        a = detect_architecture(_st_build_elf(True, 0x3E, 0x401000))
        b = detect_architecture(_st_build_elf(False, 0x28, 0x8001))
        assert (a.arch, a.method, b.arch, b.entry) == ("x86-64", "elf", "arm-thumb", 0x8000), \
            f"{a.arch}/{a.method}, {b.arch} entry {b.entry}"

    import time as _time
    t0 = _time.perf_counter()
    results = []
    for name, fn in checks:
        try:
            fn()
            results.append((name, True, ""))
        except Exception as exc:          # a failed check, not a crash
            results.append((name, False, f"{type(exc).__name__}: {exc}"))
    ok = all(r[1] for r in results)
    if verbose:
        line = "=" * 70
        print(line)
        print("SELF-TEST")
        print(line)
        uv = getattr(unicorn, "__version__", "?")
        cv = getattr(capstone, "__version__", "?")
        print(f"  unicorn {uv} (tested with {TESTED_WITH['unicorn']}), "
              f"capstone {cv} (tested with {TESTED_WITH['capstone']})\n")
        for name, passed, detail in results:
            print(f"  [{'PASS' if passed else 'FAIL'}] {name}")
            if not passed:
                print(f"         {detail}")
        n_ok = sum(r[1] for r in results)
        print(f"\n  {n_ok}/{len(results)} passed in {_time.perf_counter() - t0:.1f}s")
        if not ok:
            print("  Results from this installation are NOT trustworthy. Use the "
                  "tested library versions, or investigate the failing checks.")
    return ok


def _auto_int(s: str) -> int:
    return int(s, 0)


def _addr_val(s: str) -> Tuple[int, int]:
    """Parse ADDR=VALUE (both int literals, e.g. 0x50060004=0x1)."""
    if "=" not in s:
        raise argparse.ArgumentTypeError(f"expected ADDR=VALUE, got '{s}'")
    a, v = s.split("=", 1)
    return int(a, 0), int(v, 0)


def _addr_vals(s: str) -> Tuple[int, object]:
    """Parse ADDR=V1[,V2,...] or ADDR=rand:N (N random 32-bit values)."""
    if "=" not in s:
        raise argparse.ArgumentTypeError(f"expected ADDR=VALUE, got '{s}'")
    a, v = s.split("=", 1)
    try:
        if v.startswith("rand:"):
            n = int(v[5:], 0)
            if n < 1:
                raise ValueError
            return int(a, 0), ("rand", n)
        return int(a, 0), [int(x, 0) for x in v.split(",") if x.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected ADDR=V1[,V2,...] or ADDR=rand:N, got '{s}'")


MAX_STUB_VARIANTS = 32


def _addr_size(s: str) -> Tuple[int, int]:
    """Parse ADDR:SIZE (e.g. 0x50060000:0x400)."""
    if ":" not in s:
        raise argparse.ArgumentTypeError(f"expected ADDR:SIZE, got '{s}'")
    a, n = s.split(":", 1)
    return int(a, 0), int(n, 0)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="Emulate firmware and statically confirm whether an "
                    "instruction-skip fault can bypass secure boot.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("firmware", nargs="?", help="raw firmware image (binary)")
    p.add_argument("--demo", action="store_true",
                   help="run the built-in synthetic vulnerable example")
    p.add_argument("--selftest", action="store_true",
                   help="check, on this machine, every emulator behaviour the "
                        "analysis relies on (known-answer tests) and exit; "
                        "runs automatically when the installed unicorn or "
                        "capstone version differs from the tested one")
    p.add_argument("--arch", default="auto",
                   help="auto|arm-thumb|arm|arm64|x86|x86-64 "
                        "(default auto-detect)")
    p.add_argument("--base", type=_auto_int, default=None,
                   help="load/base address (default: detected, else 0x08000000)")
    p.add_argument("--entry", type=_auto_int, default=None,
                   help="entry point (default: detected, else = base)")
    p.add_argument("--stack", type=_auto_int, default=None,
                   help="stack/RAM base (default 0x20000000)")
    p.add_argument("--success", type=_auto_int, action="append", default=[],
                   help="address meaning 'verification passed' (repeatable)")
    p.add_argument("--fail", type=_auto_int, action="append", default=[],
                   help="address meaning 'verification failed' (repeatable)")
    p.add_argument("--max-instr", type=int, default=20000,
                   help="per-run instruction budget (default 20000)")
    p.add_argument("--campaign", type=int, default=0,
                   help="randomized multi-glitch iterations (0 = skip)")
    p.add_argument("--max-glitches", type=int, default=2,
                   help="max simultaneous skips in the campaign (default 2)")
    p.add_argument("--list-branches", action="store_true",
                   help="only print static decision points and exit")
    p.add_argument("--detect", action="store_true",
                   help="only run architecture detection and exit")
    p.add_argument("--characterize", action="store_true",
                   help="map bypasses onto the execution timeline as glitch "
                        "windows (bench targeting)")
    p.add_argument("--bitflip", action="store_true",
                   help="also sweep single-bit instruction-encoding flips "
                        "(broader coverage; implies --characterize)")
    p.add_argument("--data-faults", action="store_true",
                   help="also sweep data faults: each instruction executes, "
                        "then its result register is forced to all zeros / "
                        "all ones (compares: flags cleared / set), as when a "
                        "glitch corrupts a load or write-back; implies "
                        "--characterize")
    p.add_argument("--compare", metavar="OLD_JSON", default=None,
                   help="retest: compare with a previous run's --json output "
                        "(e.g. the build before a fix). Findings are "
                        "matched by aligning the two execution sequences, so "
                        "shifted addresses are handled; each old finding is "
                        "classified closed / reduced / still exploitable / "
                        "code changed, and regressions are flagged")
    p.add_argument("--report", metavar="PATH", default=None,
                   help="write a Markdown assessment report: summary, harness "
                        "and evidence trail, robust findings, rule-based "
                        "weakness patterns with remediation, bench plan, "
                        "multi-fault resistance and the reproduction command "
                        "(implies --characterize; use with several --stub "
                        "values / --vary-regs for validated findings)")
    p.add_argument("--json", metavar="PATH", default=None,
                   help="write the characterization result to a JSON file")
    hw = p.add_argument_group("hardware environment")
    hw.add_argument("--mmio", type=_addr_val, action="append", default=[],
                    metavar="ADDR=VAL",
                    help="value the firmware reads from a peripheral register, "
                         "e.g. a status/ready bit (repeatable)")
    hw.add_argument("--mmio-region", type=_addr_size, action="append",
                    default=[], metavar="ADDR:SIZE",
                    help="pre-map a peripheral region (repeatable)")
    hw.add_argument("--stub", type=_addr_vals, action="append", default=[],
                    metavar="ADDR=RET[,RET2..]|ADDR=rand:N",
                    help="skip the function at ADDR and return RET, e.g. a "
                         "HAL hash/verify routine (repeatable). Several "
                         "values, or rand:N random ones, enable the "
                         "robustness check: every finding is re-tested "
                         "under each value and stub-value artifacts are "
                         "dropped. The first value drives the main report.")
    hw.add_argument("--stub-flags", type=_addr_val, action="append", default=[],
                    metavar="ADDR=NZCV",
                    help="condition flags the stub at ADDR leaves on return, "
                         "as an NZCV nibble (e.g. 0x6 = Z and C set)")
    hw.add_argument("--calibrate-stubs", action="store_true",
                    help="measure each stubbed function's real exit flags by "
                         "letting short calls run (long calls are cut) and "
                         "apply them to every later run")
    hw.add_argument("--calibrate-budget", type=int, default=500_000, metavar="N",
                    help="per-call instruction budget for --calibrate-stubs "
                         "(default 500000)")
    hw.add_argument("--no-automap", action="store_true",
                    help="crash on unmapped data accesses instead of "
                         "lazily mapping a zero page")
    hw.add_argument("--discover", action="store_true",
                    help="only map peripheral accesses of the unfaulted run, "
                         "diagnose the baseline, and exit")
    hw.add_argument("--sp", type=_auto_int, default=None,
                    help="initial stack pointer (default: the vector table's "
                         "SP on Cortex-M, else top of the stack region)")
    hw.add_argument("--reg", type=str, action="append", default=[],
                    metavar="NAME=VAL",
                    help="preset a register, e.g. lr=0 when harnessing a "
                         "function directly (repeatable)")
    rb = p.add_argument_group("finding robustness")
    rb.add_argument("--vary-regs", type=int, default=0, metavar="N",
                    help="re-test findings under N random entry-register "
                         "contexts (registers not pinned with --reg) and flag "
                         "those that depend on the harness's register state")
    rb.add_argument("--skip-window", type=int, default=0, metavar="N",
                    help="search for a single wide glitch that skips up to N "
                         "consecutive instructions (N>=2). Finds bypasses that "
                         "need a burst, not the two precise faults of --double")
    rb.add_argument("--iterations", type=int, default=0, metavar="N",
                    help="iteration-aware sweep: for instructions run more than "
                         "once, fault visits 0..N-1, finding bypasses that need "
                         "glitching a specific loop pass (e.g. a byte-compare "
                         "hash check) that the first-visit sweep misses")
    rb.add_argument("--double", action="store_true",
                    help="exhaustive double-fault (two-skip) search; reports "
                         "the fault-resistance order (1, 2 or >2)")
    rb.add_argument("--double-models", default=None, metavar="LIST",
                    help="fault models for the double-fault search, comma "
                         "separated from skip,bitflip,data (default skip). "
                         "Each glitch of a pair may be any of them; implies "
                         "--double. Much more expensive than skip-only")
    rb.add_argument("--double-max-runs", type=int, default=200_000, metavar="N",
                    help="cap on pair runs (default 200000); a truncated search "
                         "does not establish the order")
    rb.add_argument("--double-window", type=int, default=None, metavar="N",
                    help="limit the double-fault search to glitch pairs at "
                         "most N executed instructions apart")
    en = p.add_argument_group("engine")
    en.add_argument("--no-fast-reset", action="store_true",
                    help="build a fresh Unicorn instance for every run instead "
                         "of restoring one (slower; the reference behaviour)")
    en.add_argument("--fast-recycle", type=int, default=20_000, metavar="N",
                    help="rebuild the persistent fast-reset instance every N "
                         "runs to bound Unicorn's native state (default "
                         "20000, 0 = never)")
    rb.add_argument("--rank", action="store_true",
                    help="rank instructions as bench glitch targets by the "
                         "share of fault mechanisms that bypass, and list hot "
                         "zones; uses robustness-validated findings when "
                         "several --stub values or --vary-regs are given")
    rb.add_argument("--explain", action="store_true",
                    help="for each single-fault bypass, diff its trace against "
                         "the golden run and report where control flow "
                         "diverged: the branch or guard the glitch subverted "
                         "and where execution went instead")
    en.add_argument("--verify-fast", type=int, default=0, metavar="N",
                    help="self-check: run N random faults on the fast-reset "
                         "engine and on fresh instances and require identical "
                         "results before analysing")
    rb.add_argument("--seed", type=int, default=0,
                    help="seed for rand:N stub values and --vary-regs")
    hw.add_argument("--genuine", metavar="PATH", default=None,
                    help="path to a genuine (accepted) firmware image. It is "
                         "run unfaulted under this same harness and must reach "
                         "SUCCESS, proving the harness can tell an accepted "
                         "image from the rejected one and that the sweep "
                         "measures a real FAIL->SUCCESS bypass")
    hw.add_argument("--genuine-stub", type=_addr_val, action="append",
                    default=[], metavar="ADDR=VAL",
                    help="instead of a separate image, model a genuine "
                         "measurement on the current image: stub return "
                         "value(s) that make it verify (e.g. the real hash). "
                         "Repeatable; validates the SUCCESS side of the oracle")
    hw.add_argument("--force", action="store_true",
                    help="sweep even when the baseline does not reach FAIL or "
                         "the oracle is unsound")
    args = p.parse_args(argv)

    if args.selftest:
        return 0 if run_selftest() else 5

    if args.demo:
        return run_demo()

    if not args.firmware:
        p.error("provide a firmware image, or use --demo / --selftest")

    # Untested library versions: verify the emulator behaviours first.
    versions = {"unicorn": getattr(unicorn, "__version__", "?"),
                "capstone": getattr(capstone, "__version__", "?")}
    if versions != TESTED_WITH:
        print("note: " + ", ".join(f"{k} {v}" for k, v in versions.items())
              + " differ from the tested " + ", ".join(
                  f"{k} {v}" for k, v in TESTED_WITH.items())
              + "; running the self-test first.", file=sys.stderr)
        with contextlib.redirect_stdout(sys.stderr):
            ok = run_selftest()
        if not ok and not args.force:
            print("error: self-test failed on this installation; results would "
                  "not be trustworthy. Fix the environment or pass --force.",
                  file=sys.stderr)
            return 5

    with open(args.firmware, "rb") as fh:
        fw = fh.read()

    # --detect: report detection and stop.
    if args.detect:
        print(detect_architecture(fw).summary())
        return 0

    # Resolve architecture (and, when auto, a base/entry hint).
    arch = args.arch
    det_base = det_entry = det_sp = None
    if arch == "auto":
        detection = detect_architecture(fw)
        print(detection.summary(), file=sys.stderr)
        print(file=sys.stderr)
        if detection.arch not in arch_registry():
            print("error: could not confidently detect architecture; pass "
                  "--arch explicitly.", file=sys.stderr)
            return 2
        arch = detection.arch
        det_base, det_entry = detection.base_addr, detection.entry
        det_sp = detection.initial_sp

    base = (args.base if args.base is not None
            else det_base if det_base is not None else 0x08000000)
    entry = (args.entry if args.entry is not None
             else det_entry if det_entry is not None else base)
    stack = args.stack if args.stack is not None else 0x20000000

    # Stubs: each may carry several values (or rand:N). The first value of
    # each drives the main run; the full cartesian product feeds the
    # robustness check.
    val_rng = random.Random(args.seed)
    stub_lists: List[Tuple[int, List[int]]] = []
    for addr, vals in args.stub:
        if isinstance(vals, tuple):
            vals = [val_rng.getrandbits(32) for _ in range(vals[1])]
        if not vals:
            p.error(f"--stub 0x{addr:x} has no values")
        stub_lists.append((addr, vals))
    primary_stubs = {a: v[0] for a, v in stub_lists}
    n_combos = 1
    for _, v in stub_lists:
        n_combos *= len(v)
    stub_variants = [dict(zip([a for a, _ in stub_lists], combo)) for combo in
                     itertools.islice(itertools.product(*[v for _, v in stub_lists]),
                                      MAX_STUB_VARIANTS)]
    if n_combos > MAX_STUB_VARIANTS:
        print(f"note: {n_combos} stub-value combinations; the robustness check "
              f"uses the first {MAX_STUB_VARIANTS}.", file=sys.stderr)
    init_regs = {}
    for item in args.reg:
        name, val = (item.split("=", 1) + [""])[:2]
        if not val:
            p.error(f"--reg expects NAME=VALUE, got '{item}'")
        init_regs[name.strip().lower()] = int(val, 0)

    cfg = EmulatorConfig(
        arch=arch,
        load_addr=base,
        entry=entry,
        stack_addr=stack,
        initial_sp=args.sp if args.sp is not None else det_sp,
        initial_regs=init_regs,
        success_addrs=tuple(args.success),
        fail_addrs=tuple(args.fail),
        max_instr=args.max_instr,
        auto_map_unmapped=not args.no_automap,
        mmio_reads=dict(args.mmio),
        mmio_regions=list(args.mmio_region),
        stubs=primary_stubs,
        fast_reset=not args.no_fast_reset,
        fast_recycle=args.fast_recycle,
    )
    emu = SecureBootEmulator(fw, cfg)

    # Stub exit flags: explicit values win, then calibration.
    cfg.stub_exit_flags.update({a: v & 0xF for a, v in args.stub_flags})
    calibration: Optional[dict] = None
    if args.calibrate_stubs and cfg.stubs:
        cal = emu.calibrate_stubs(per_call_budget=args.calibrate_budget)
        calibration = {a: c for a, c in cal.items()
                       if a in cfg.stub_exit_flags and a not in dict(args.stub_flags)}
        print("STUB CALIBRATION  (real exit flags, NZCV)")
        for a, c in cal.items():
            flags = c["exit_flags"]
            if a in dict(args.stub_flags):
                verdict = "explicit --stub-flags kept"
            elif len(flags) == 1:
                cfg.stub_exit_flags[a] = flags[0]
                verdict = f"applied 0b{flags[0]:04b}"
            elif flags:
                verdict = "calls disagree; not applied, pass --stub-flags"
            else:
                verdict = ("no call finished within budget; raise "
                           "--calibrate-budget or pass --stub-flags")
            fl = ", ".join(f"0b{x:04b}" for x in flags) or "-"
            print(f"  0x{a:08x}: {c['calls']} call(s), {c['completed']} measured, "
                  f"{c['cut']} cut; exit flags {fl} -> {verdict}")
        print()

    if args.list_branches:
        for addr, m, ops in emu.detect_decision_points():
            print(f"0x{addr:08x}: {m} {ops}".rstrip())
        return 0

    if not cfg.success_addrs and not cfg.success_fn and not args.discover:
        print("error: no success marker. Pass --success <addr> (and usually "
              "--fail <addr>), which you recover from Ghidra/IDA or from "
              "--list-branches.", file=sys.stderr)
        return 2

    # Hardware environment: map peripheral accesses and diagnose the baseline
    # before trusting any sweep.
    _, accesses = emu.discover_mmio()
    golden = emu.golden_run()
    hints = emu.diagnose(golden, accesses)
    if accesses or hints or cfg.stubs or args.discover:
        print_hardware(accesses, hints, cfg)
    if args.discover:
        return 0
    if args.verify_fast and not args.no_fast_reset:
        mm = emu.verify_fast_reset(n=args.verify_fast, seed=args.seed)
        if mm:
            print(f"FAST-RESET SELF-CHECK FAILED: {len(mm)} of {args.verify_fast} "
                  f"runs differ from fresh instances. Re-run with "
                  f"--no-fast-reset and please report this:")
            for m in mm[:5]:
                print("  " + m)
            return 4
        print(f"fast-reset self-check: {args.verify_fast} random fault runs "
              f"identical to fresh instances.\n")
    if args.genuine or args.genuine_stub:
        genuine_fw = None
        genuine_stubs = None
        if args.genuine:
            with open(args.genuine, "rb") as gh:
                genuine_fw = gh.read()
        if args.genuine_stub:
            genuine_stubs = {a: v for a, v in args.genuine_stub}
        oracle = emu.validate_oracle(genuine_firmware=genuine_fw,
                                     genuine_stubs=genuine_stubs)
        print_oracle(oracle)
        if not oracle.sound and not args.force:
            print("refusing to sweep: the oracle is unsound (see above), so "
                  "any bypass found would be an artefact. Fix the harness or "
                  "pass --force.")
            return 3

    if golden.outcome is not Outcome.FAIL and not args.force:
        print(f"[golden run] outcome {golden.outcome.value}: baseline does not "
              f"reach FAIL, so a sweep would not measure a real bypass. Fix the "
              f"model per the diagnosis above, or pass --force.")
        return 3

    single_wins = emu.sweep_single_skip()
    campaign_wins = None
    if args.campaign > 0:
        campaign_wins = emu.random_campaign(
            iterations=args.campaign, max_glitches=args.max_glitches,
            seed=args.seed,
        )
    print_report(emu, golden, single_wins, campaign_wins, hints)

    if args.explain and single_wins:
        print("=" * 70)
        print("DIVERGENCE  (where each single-fault bypass leaves the golden path)")
        print("=" * 70)
        for r in single_wins:
            d = emu.explain(r.faults)
            print(f"  {r.faults[0]!r}")
            print(f"      {d.note}")
        print()

    if args.iterations >= 2:
        iter_wins = emu.sweep_iterations(max_iters=args.iterations)
        first_visit = {(r.faults[0].address, 0) for r in single_wins}
        extra = [r for r in iter_wins if r.faults[0].nth > 0]
        print("=" * 70)
        print(f"ITERATION-AWARE SWEEP  (loop passes 0..{args.iterations - 1})")
        print("=" * 70)
        if not iter_wins:
            print("  no loop-iteration bypass found.\n")
        else:
            for r in iter_wins:
                f = r.faults[0]
                tag = "  (needs this specific loop pass)" if f.nth > 0 else ""
                print(f"  {emu.disasm_at(f.address)}  visit#{f.nth}{tag}")
            print(f"\n  {len(iter_wins)} iteration bypass(es), {len(extra)} "
                  f"requiring a non-first loop pass.\n")

    if args.skip_window >= 2:
        window_wins = emu.sweep_skip_window(max_width=args.skip_window)
        print("=" * 70)
        print(f"WIDE-GLITCH SKIP WINDOW  (single glitch, up to "
              f"{args.skip_window} consecutive instructions)")
        print("=" * 70)
        if not window_wins:
            print("  no wide-glitch bypass up to this width.\n")
        else:
            single_addrs = {r.faults[0].address for r in single_wins}
            for r in window_wins:
                f = r.faults[0]
                extra = "" if f.address in single_addrs else \
                    "  (no single skip here bypasses)"
                print(f"  start {emu.disasm_at(f.address)}  "
                      f"width {f.width}{extra}")
            print(f"\n  {len(window_wins)} wide-glitch start point(s).\n")

    models = [FaultModel.SKIP]
    if args.bitflip:
        models.append(FaultModel.BITFLIP)
    if args.data_faults:
        models.extend(DATA_FAULT_MODELS)
    out: dict = {}
    ch = rep = dres = ranking = None
    if (args.characterize or args.bitflip or args.data_faults or args.json
            or args.rank or args.report or args.compare):
        ch = emu.characterize(models=tuple(models))
        print_characterization(ch)
        out = ch.to_dict()

    if n_combos > 1 or args.vary_regs > 0:
        rep = emu.assess_robustness(stub_variants=stub_variants,
                                    models=tuple(models),
                                    n_contexts=args.vary_regs, seed=args.seed)
        print_robustness(rep)
        out["robustness"] = rep.to_dict()

    if args.rank:
        ranking = rank_bench_targets(emu, models, rep if rep is not None else ch)
        print_bench_ranking(ranking)
        out["bench_ranking"] = ranking.to_dict()

    if args.double or args.double_window is not None or args.double_models:
        dmodels = [FaultModel.SKIP]
        if args.double_models:
            names = {"skip": [FaultModel.SKIP], "bitflip": [FaultModel.BITFLIP],
                     "data": list(DATA_FAULT_MODELS)}
            toks = [t.strip().lower() for t in args.double_models.split(",") if t.strip()]
            bad = [t for t in toks if t not in names]
            if bad or not toks:
                p.error(f"--double-models: unknown model(s) {bad}; use skip,bitflip,data")
            dmodels = [m for t in ("skip", "bitflip", "data") if t in toks
                       for m in names[t]]
        dres = emu.double_fault_sweep(
            window=args.double_window,
            stub_variants=stub_variants if n_combos > 1 else None,
            models=dmodels, progress=True, max_pair_runs=args.double_max_runs)
        print_double_fault(dres)
        out["double_fault"] = dres.to_dict()

    retest = None
    if args.json or args.report or args.compare:
        source = rep if rep is not None else ch
        snapshot = retest_snapshot(emu, _mechanisms(emu, source), models,
                                   isinstance(source, RobustnessReport), dres)
        out["retest_baseline"] = snapshot
        if args.compare:
            with open(args.compare) as fh:
                old = json.load(fh)
            old = old.get("retest_baseline", old)
            if "sequence" not in old or "findings" not in old:
                print(f"error: {args.compare} has no retest baseline; produce it "
                      f"with --json from this version of the tool.", file=sys.stderr)
                return 2
            retest = compare_snapshots(old, snapshot)
            print_retest(retest)
            out["retest"] = retest

    if args.report:
        if ranking is None:
            ranking = rank_bench_targets(emu, models, rep if rep is not None else ch)
        import shlex
        cmd = "python3 " + " ".join(shlex.quote(x) for x in
                                    ([os.path.basename(__file__)] +
                                     list(argv if argv is not None else sys.argv[1:])))
        write_report(args.report, emu=emu, fw_path=args.firmware, command=cmd,
                     golden=golden, models=models, ranking=ranking,
                     source=rep if rep is not None else ch, rep=rep,
                     dres=dres, calibration=calibration,
                     stub_variants=stub_variants, retest=retest)
        print(f"\n  wrote report to {args.report}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"\n  wrote results to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
