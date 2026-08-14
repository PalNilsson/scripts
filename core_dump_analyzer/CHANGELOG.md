# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial standalone prototype `analyze_core_dump.py`: drives gdb in batch mode
  over a core dump and asks an Anthropic model to explain the failure in plain
  language.
- Two-layer split between evidence extraction (`collect_evidence`) and LLM
  synthesis (`analyze_with_llm`), so the evidence layer can be lifted into a
  Bamboo MCP tool unchanged. `--no-llm` prints the evidence bundle alone.
- Hang vs. crash analysis modes with separate prompts, auto-detected from the
  terminating signal. Looping jobs produce a deliberate core with no fault to
  explain, so they need different gdb emphasis than a segfault post-mortem.
- Executable resolution from `AT_EXECFN` (auxiliary vector), the `NT_FILE` note,
  and the recorded command line, with `--exe` override.
- Thread-stack de-duplication with idle-wait detection, keeping evidence for
  100+ thread Athena jobs within a token budget.
- Explicit gdb `echo` section markers so per-command output is split exactly.
- Credential scrubbing (X509 proxies, JWTs, bearer tokens, PEM blocks,
  `*_TOKEN`/`*_PASSWORD`/`*_SECRET` assignments), disableable with `--no-redact`.
- Evidence-quality warnings for truncated cores, core/executable mismatch,
  missing symbols and unreadable memory, with prompt instructions to lead with
  limitations rather than guess.
- Structured JSON output (`--json`) alongside the human-readable report, plus
  raw gdb capture (`--raw-gdb`).
- Test suite of 74 tests, runnable without a core file or API key, and
  `tests/generate_test_cores.sh` to produce crash and hang fixtures locally.

### Fixed

- `_existing_path` no longer substitutes a same-named binary from `PATH` when an
  **absolute** recorded executable path is missing. Falling back to the system
  interpreter for an unmounted CVMFS path handed gdb a different build and
  produced confidently wrong symbols. Only bare names and relative paths are
  searched, and any search is flagged.
- Primary-thread sections are split on gdb `echo` markers rather than boundary
  regexes, which silently mislabelled `info args` output as `locals`.
- `py-bt` availability is detected from positive Python traceback markers and
  from **stderr**, where gdb writes `Undefined command`. The previous stdout-only
  negative check reported Python frames as available for a pure C program.
- Thread counting handles gdb's unsymbolised `LWP N` table format, not just
  `Thread 0x...`.
- gdb load banners (`[New LWP ...]`, `[Current thread is ...]`) no longer leak
  into extracted sections.
