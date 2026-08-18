# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A standalone prototype (single script) that runs `gdb` over a core dump, extracts
structured evidence, and asks an Anthropic model to explain what went wrong in
plain language. Built as a precursor to a Bamboo MCP tool
(`atlas.core_dump_analysis`) for diagnosing looping and crashing ATLAS/PanDA jobs
— see the "Bamboo MCP integration" section of README.md for the intended path.
Everything lives in `analyze_core_dump.py`; there is no package structure.

## Commands

**Run the analyzer:**
```bash
export ANTHROPIC_API_KEY=sk-ant-...
python analyze_core_dump.py core.123456

# Evidence only, no API call, no tokens spent (fastest way to iterate on gdb extraction)
python analyze_core_dump.py core.123456 --no-llm
```

**Run tests** (pytest, not unittest; test file is at repo root, not in a `tests/` dir):
```bash
python -m pytest test_analyze_core_dump.py -q
```

**Lint:**
```bash
flake8 --max-line-length=120 --max-complexity=15 --ignore=W503 analyze_core_dump.py test_analyze_core_dump.py
```

**Generate synthetic core dumps for manual/local validation** (no real core file needed):
```bash
bash generate_test_cores.sh /tmp/cores
python analyze_core_dump.py /tmp/cores/core.crash.1234 --no-llm   # crash mode
python analyze_core_dump.py /tmp/cores/core.hang.5678  --no-llm   # hang mode + py-bt
```

Note: README.md refers to a `tests/` subdirectory (`tests/generate_test_cores.sh`,
`pytest tests/`) and a `requirements-dev.txt`. Neither exists — the test file and
the fixture generator both live at repo root, and `pytest` is the only extra dev
dependency (not pinned in any requirements file).

## Architecture

The script is deliberately split into two layers, because only one is meant to
survive into the future Bamboo MCP tool:

- **Evidence layer** (`collect_evidence()`): drives gdb, normalises output,
  de-duplicates thread stacks, redacts credentials, enforces size budgets. No LLM
  awareness. This is the half meant to be lifted into an MCP tool unchanged — the
  MCP tool would wrap `collect_evidence()` only and must not call an LLM itself
  (synthesis prompts belong in the MCP host, per README's integration sketch).
- **Synthesis layer** (`analyze_with_llm()`): sends the evidence bundle
  (`CoreEvidence`, a dataclass) to Anthropic and parses a structured JSON verdict
  (`extract_json_object()`), falling back to raw prose under `explanation` if the
  model doesn't return JSON.

`--no-llm` prints the evidence bundle alone — exactly the payload an MCP tool
would return.

### Hang vs. crash modes

`detect_mode()` infers framing from the terminating signal (`--mode auto` is the
default): a fault signal (SIGSEGV/SIGBUS/SIGFPE/SIGILL) means **crash** mode,
focused on the faulting thread/frame; no fault signal (or SIGQUIT/SIGABRT, or a
`gcore` snapshot) means **hang** mode, focused on which thread is doing work and
why it never finishes. Each mode gets a distinct gdb phase plan
(`_build_phase_plan()`) and a distinct system prompt (`build_system_prompt()`).
Conflating the two is called out in README as the main way this kind of tool
produces nonsense — preserve the distinction when touching prompt or phase logic.

### Executable resolution

gdb needs the ELF executable that was running, not a script — `resolve_executable()`
tries, in order: `--exe` (rejecting `.py` paths), `AT_EXECFN` from the auxiliary
vector (`executable_from_auxv()`), the core's `NT_FILE` note
(`executable_from_nt_file()`), then the recorded command line
(`parse_generated_by()`/`_argv0_from_command_line()`). `_existing_path()`
deliberately does **not** substitute a same-named binary from `PATH` when an
**absolute** recorded path is missing (e.g. an unmounted CVMFS path) — falling
back silently would hand gdb a different build and produce confidently wrong
symbols. Only bare names/relative paths are searched via `PATH`, and any such
search is flagged in warnings.

### Evidence budgeting

Athena-style jobs can have 100+ near-identical threads. `group_thread_stacks()`
normalises and collapses identical backtraces into `ThreadGroup`s with counts;
`_is_idle_stack()` flags stacks parked on condition variables/futexes/etc. so the
model is told not to report them as findings. `enforce_global_budget()` is a
multi-stage shrink cascade (drop thread groups → shrink shared-library lists →
shrink primary-thread locals/registers/args → shrink python backtrace/source →
shrink primary backtrace) that runs when the serialized evidence exceeds
`--max-evidence-chars`; anything shortened is recorded in `truncated_sections`.
`_cap_user_prompt()` is a hard failsafe (2x the evidence-char budget) applied to
the actual outgoing prompt independently of the budget pass, so a future field
addition can never send an unbounded prompt.

### gdb output parsing

Each gdb phase (`run_gdb_phase()`) runs as a separate subprocess with its own
timeout, so one hanging command can't take down the whole run. Per-command output
is split via explicit `echo`-emitted section markers (`split_sections()`), not
boundary regexes — an earlier heuristic version silently mislabelled `info args`
as `locals`, which is why this matters when editing phase/section logic.
`py-bt` availability is detected from positive Python-traceback markers **and**
stderr (gdb writes `Undefined command` there, not stdout) — a stdout-only check
previously reported Python frames as available for a pure C program.

### Redaction

`redact()` strips X509 proxy paths, `x509up_u*` filenames, JWT-shaped strings,
Bearer tokens, PEM blocks, and `*_TOKEN`/`*_PASSWORD`/`*_SECRET` assignments from
any gdb text before it can reach the evidence bundle or the LLM. Only gdb text is
ever transmitted, never raw memory. Disable with `--no-redact`; do not weaken this
without a clear reason since it's the only thing standing between `info locals`
output and the API call.

## Known constraints worth preserving

- Not yet validated against a real ATLAS/Athena core — only synthetic C/Python
  fixtures from `generate_test_cores.sh`. Thread-group counts and frame budgets
  are expected to need tuning once real cores are available.
- Symbol quality dominates output quality; against a stripped/no-debuginfo binary
  the correct behavior is an "insufficient evidence" verdict, not a guess — this
  is deliberate prompt design, not a gap to fix.
- Idle-thread detection (`_is_idle_stack()`) is a heuristic top-frame marker list
  and won't recognise every framework's wait primitive.
