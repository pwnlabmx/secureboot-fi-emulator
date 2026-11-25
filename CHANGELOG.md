# Changelog

All notable changes to this project are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Two-way oracle validation (`--genuine` / `--genuine-stub`): refuses to sweep a
  harness that cannot tell an accepted image from a rejected one.
- Wide-glitch skip-window model (`--skip-window N`): one glitch removing several
  consecutive instructions.
- Iteration-aware sweep (`--iterations N`): fault a specific pass of a
  compare/verify loop.
- Control-flow divergence analysis (`--explain`): the branch each bypass
  subverts and where execution went instead.

### Core
- Architecture auto-detection (ARM Thumb / A32 / AArch64 / x86 / x86-64).
- Peripheral discovery and baseline diagnosis.
- Fault models: skip, single-bit encoding flips, data faults (zeros/ones).
- Single-fault sweep with glitch-window characterization.
- Robustness validation across stub values and entry-register contexts.
- Double-fault search with fault-resistance order (1 / 2 / >2) and mixed models.
- Bench-target ranking with hot zones.
- Markdown assessment report with weakness patterns and remediation.
- Retest / regression comparison by execution-sequence alignment.
- Deterministic fast-reset engine with self-verification.
- 23 known-answer self-tests, run automatically on version mismatch.
