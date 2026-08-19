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

The test file and fixture generator both live at repository root; `pytest` is
the only extra development dependency and is not pinned in a separate
requirements file.

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
normalises and collapses identical backtraces into `ThreadGroup`s with counts and
`active` / `blocked` / `idle` state. A futex/condition-variable top frame is not
sufficient to call a thread idle: deeper lock/shutdown/timeout frames can make it
diagnostically blocked. `enforce_global_budget()` is a
multi-stage shrink cascade (drop thread groups → shrink shared-library lists →
shrink primary-thread locals/registers/args → shrink python backtrace/source →
shrink primary backtrace) that runs when the serialized evidence exceeds
`--max-evidence-chars`; anything shortened is recorded in `truncated_sections`.
`_cap_user_prompt()` is a hard failsafe (2x the evidence-char budget) applied to
the actual outgoing prompt independently of the budget pass, so a future field
addition can never send an unbounded prompt.

### ATLAS container execution

`collect_evidence()` dispatches between local execution and the explicit
`--execution atlas-container` backend. Container mode stages a temporary copy of
the analyzer and an analyzer-owned runner under the PanDA job directory, then
uses `atlasLocalSetup.sh -c <platform> -s /srv/my_release_setup.sh -r /srv/<runner>`.
It never executes `container_script.sh`. The worker runs evidence-only inside the
container and returns JSON/raw GDB evidence to the host, where optional LLM
synthesis still occurs.

AnalysisBase `PYTHONHOME`/`PYTHONPATH` must never be inherited by GDB: EL9 GDB
embeds Python 3.9 while AnalysisBase 25.2.103 uses Python 3.13.
`gdb_subprocess_env()` removes those two variables and `run_gdb_phase()` also
uses `-eiex 'set python ignore-environment on'`. Preserve both defenses.


### Targeted thread inspection

After `thread apply all bt`, `select_targeted_threads()` chooses a bounded number
of representative non-idle thread groups and `_build_targeted_phase()` executes
all selected `thread` / `frame` / `info frame` / `info args` / `info locals`
commands in one additional GDB process. This is deliberately stack-based rather
than thread-number-based. On the reference XRootD core it selects T3/F3, T2/F3,
and T1/F2. Keep the dynamic section-marker support for digits because targeted
sections are named `target_1_args`, etc.

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

- The matching-container workflow and automated backend have been validated
  against real PanDA core `core.53289` from job `7262157016` / AnalysisBase
  25.2.103. The 0.2.2 targeted-frame phase was live-validated: it selects the intended T3/F3, T2/F3, and T1/F2 frames, but those optimized XRootD frames expose no `info args`/`info locals` data. Version 0.2.3 therefore treats that as a per-frame debug-detail limitation. Live 0.2.3 correlation showed that looping-job analysis must be payload-centric, leading to the 0.2.4 behavior below.
- The first container backend requires the core and release setup to live under
  the same `--job-dir` that ATLASLocalRootBase mounts at `/srv`.
- Symbol quality dominates output quality; against a stripped/no-debuginfo binary
  the correct behavior is an "insufficient evidence" verdict, not a guess — this
  is deliberate prompt design, not a gap to fix.
- Thread-state and context-frame selection are heuristic and won't recognise every
  framework's wait/lock primitive. Preserve conservative wording and avoid turning
  one stack snapshot into an unproven causal/deadlock claim.


## Payload-log correlation (0.2.6+)

When `--job-dir` is supplied, `collect_evidence()` augments the core evidence on
the host with `evidence.job_logs`. In `--mode hang`, automatic discovery is
payload-centric: `payload.stdout`, `payload.stderr`, and log-like files under
`workDir` are scanned; `pilotlog.txt` is excluded unless explicitly supplied.
This is intentional for looping jobs: pilot kill/timeout records are downstream
reaction, while payload output and user logs describe the pre-core payload state.

The collector stores payload-file mtime deltas from the core and a compact
`payload_activity` summary, including the last retained progress line. Matchers
are conservative: generic `root://`/`lsetup xrootd` text is not runtime XRootD
evidence and identifiers like `EventErrorState` are not errors. Lower-case descriptive text such as `error state` must not be interpreted as an `ERROR` severity. Automatic `workDir` discovery must not accept arbitrary `.txt` files solely by suffix; prefer strong log-like names/suffixes and explicit `--job-log` for unusual text logs. Preserve the actual line-numbered payload tail because output after the last periodic progress counter can be the most diagnostic evidence. Keep this layer
deterministic and do not infer causality beyond supported chronology.


## Structured deterministic diagnosis (0.2.9)

`CoreEvidence.diagnosis` is a downstream-integration contract, not an LLM verdict.
Keep its rules conservative. A classification may identify the captured phase and
component with high confidence while `root_cause_established` remains false.
For the validated signature, successful payload completion plus
`Py_Exit(sts=0)`/XRootD finalization yields
`post-event-processing-shutdown-hang`; the same core signature without payload
completion yields `shutdown-finalization-hang` at medium confidence. Unsupported
states must remain `unclassified`. Preserve explicit `signals`,
`supporting_evidence`, and `limitations` because Bamboo MCP should not have to
reparse prose to recover these facts.

## Latest validated state (0.2.9)

- 135 tests pass.
- Successful EventLoop completion is established before the XRootD shutdown hang for job 7262157016.
- Live 0.2.6 validation retained all three XRootD thread groups with no evidence warnings and only current payload/runtime logs.
- Hang-mode log discovery excludes stale workDir logs more than two hours older than the latest payload stream.
- `--max-evidence-chars` reduces only a deep-copied LLM input; deterministic report/JSON evidence stays complete.


## v0.2.8 notes

Keep captured-process identity separate from symbol trust. Use the core-recorded command line to distinguish payload vs prmon; a GDB executable-match warning alone must never imply prmon. Zero checked Build IDs means unverified, not zero mismatches. Supported shutdown patterns include both XrdCl poller finalization and ROOT/TNetXNGFile remote-file close.


## v0.2.9 family/subtype contract

Both validated post-success XRootD shutdown signatures use family `post-event-processing-xrootd-shutdown-hang`. Subtype `poller-finalization` identifies the `DefaultEnv::Finalize/Poller::Stop` path; subtype `remote-file-close` identifies the `TROOT::CloseFiles/TNetXNGFile::Close` path. Preserve the detailed classification strings for compatibility.
