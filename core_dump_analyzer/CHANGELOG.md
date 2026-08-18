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
- Test suite, runnable without a core file or API key, and
  `tests/generate_test_cores.sh` to produce crash and hang fixtures locally
  (74 tests at initial prototype, 92 after the progress/budget work below).
- Default-on progress logging to stderr (core size, gdb version, executable
  resolution, per-phase start/finish with duration) so a multi-minute gdb
  phase on a large core reads as "working," not "frozen." `-q`/`--quiet`
  suppresses it for scripted use.
- `-v`/`--verbose` heartbeat: a background thread prints a periodic
  `still running (Ns elapsed)` line during any gdb phase, since
  `subprocess.run(capture_output=True)` otherwise produces zero output for
  the full duration of a phase, however long it takes.
- One-time warning when the core exceeds `--large-core-warning-mib` (default
  1024), noting up front that gdb reloads the whole core once per phase and
  wall-clock time scales with core size.
- Multi-stage evidence-budget cascade in `enforce_global_budget`: once thread
  groups are down to one, further stages now shrink
  `shared_libraries.without_symbols`, `python.source`, `primary_thread.locals`
  /`registers`/`args`, `python.backtrace` and finally `primary_thread.backtrace`
  before giving up and recording a warning. Closes the gap where a large
  `primary_thread`/`python` bundle alone could exceed `--max-evidence-chars`
  with nothing left to trim.
- Hard failsafe cost cap in `analyze_with_llm` (`--max-evidence-chars` x2):
  truncates the actual outgoing prompt independently of
  `enforce_global_budget`, so a future evidence field or a call site that
  skips the budget pass can never send an unbounded prompt.
- `-v` now also logs the outgoing evidence size and a rough
  characters/4 token estimate before the API call, and the response's
  reported input/output token usage after it.

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
- `enforce_global_budget`'s new per-field shrink stage no longer loops forever
  once a field reaches its floor: `truncate()` always adds its marker text, so
  a field can never actually reach a raw character floor, only
  `floor + len(marker)`. The stopping check now compares against that true
  minimum. Caught before this ever shipped, via a dedicated termination test
  (`test_shrink_text_field_terminates_at_floor`) rather than a live run.