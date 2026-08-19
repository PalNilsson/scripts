# Changelog

## 0.2.9

- Add stable diagnosis grouping fields: `family` and `subtype`.
- Group both validated looping-job signatures under `post-event-processing-xrootd-shutdown-hang`.
- Use subtype `poller-finalization` for the `DefaultEnv::Finalize -> Poller::Stop` signature.
- Use subtype `remote-file-close` for the `TROOT::CloseFiles -> TNetXNGFile::Close -> XrdCl::File::Close` signature.
- Preserve the existing detailed `classification` strings for backward compatibility.
- Extend the deterministic human report with Family/Subtype fields.
- Replay both saved looping-job evidence bundles in regression tests to ensure they cluster into one family but retain distinct subtypes.
- 143 tests pass.

## 0.2.8

- Add `evidence.process_identity` to distinguish payload, prmon, and unknown core owners using core-recorded command metadata plus stack corroboration.
- Add `monitor-process-core` guardrail so payload logs are not attributed to a prmon core.
- Add a second deterministic looping-job signature for shutdown hangs in `TROOT::CloseFiles -> TNetXNGFile::Close -> XrdCl::File::Close -> StreamMutex::Lock`.
- Separate process identity from symbol/build trust; executable-mismatch warnings no longer imply the core belongs to prmon.
- Report zero checked Build IDs as `UNVERIFIED` and preserve a bounded `eu-unstrip` excerpt when module enumeration is unexpectedly sparse.
- Cap structured-diagnosis confidence when GDB executable identity is degraded and key Build IDs cannot be verified.
- Refuse stack classification when both captured-process identity and symbol/build identity are unreliable.
- 142 tests pass.

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.7] - 2026-08-18

### Added

- `evidence.diagnosis`, a conservative machine-readable deterministic diagnosis
  intended for downstream consumers such as Bamboo MCP. The object separates
  classification/phase/component from root-cause proof and includes stable
  signals, supporting evidence, limitations, confidence, and
  `root_cause_established`.
- A high-confidence `post-event-processing-shutdown-hang` rule for the validated
  PanDA signature: successful EventLoop completion and output post-processing
  followed by `Py_Exit(sts=0)` blocked in XRootD/XrdCl finalization.
- A medium-confidence `shutdown-finalization-hang` fallback when the core has the
  shutdown signature but payload-completion evidence is absent.

### Changed

- `--no-llm` reports now include a compact `DETERMINISTIC DIAGNOSIS` section when
  a supported rule matches.
- Unmatched crash or hang states remain explicitly `unclassified`; the
  deterministic classifier does not force a diagnosis.

### Validated

- Live 0.2.6 analysis of PanDA job `7262157016` produced no evidence-quality
  warnings, retained all three XRootD thread groups, excluded stale reference
  logs, and scanned only the current payload streams plus the active workDir
  stdout.
- Replaying the 0.2.6 JSON through the 0.2.7 classifier yields
  `post-event-processing-shutdown-hang`, phase `process-shutdown`, component
  `XRootD/XrdCl`, confidence `high`, and `root_cause_established: false`.
- Test suite now contains 135 passing tests; `py_compile` passes.

## [0.2.6] - 2026-08-18

### Changed

- `--max-evidence-chars` now applies only to a deep-copied LLM synthesis input.
  The canonical deterministic evidence used by the human report and `--json` is
  never reduced for token-cost control; `--no-llm` therefore cannot lose thread
  groups or receive an irrelevant LLM-budget warning.
- Hang-mode automatic `workDir` discovery now excludes log-like files whose
  modification time is more than two hours older than the latest non-empty
  payload stream. This suppresses stale/reference test logs copied into job
  tarballs while preserving explicit `--job-log` as an override.
- Normal payload completion is a first-class `completion` log category, separate
  from errors and periodic progress.

### Added

- Deterministic payload-completion observations. When the tail reports
  `worker finished successfully`, successful batch status, and output
  post-processing, the analyzer states that EventLoop completed before process
  exit; combined with `Py_Exit(0)`/XRootD finalization it identifies a
  post-event-processing shutdown hang without claiming the exact lock cycle.

### Validated

- Live 0.2.5 analysis of PanDA job `7262157016` showed `worker finished
  successfully`, `1 success, 0 failure`, EventLoop `done`, then output move/rename
  handling before 2h 06m 16s of silence. The core independently shows
  `Py_Exit(sts=0)` blocked in XRootD finalization. Together these place the loop
  after successful event processing, during shutdown/finalization.
- The same run exposed stale AnalysisBase 25.2.100/25.2.101 reference logs under
  `workDir` and an LLM-budget pass that trimmed deterministic `--no-llm` evidence;
  both are fixed here.
- Test suite now contains 131 passing tests; `py_compile` passes.

## [0.2.5] - 2026-08-18

### Changed

- Hang-mode `workDir` discovery no longer treats every `.txt` file as a runtime
  log. Static input lists and path/configuration text can otherwise consume the
  bounded file budget. Automatic discovery now requires a strong log-like suffix
  or name (`.log`, `.out`, `.err`, stdout/stderr/log/trace/debug/report tokens);
  arbitrary text logs remain available through explicit `--job-log`.
- Error severity matching now distinguishes uppercase log severities (`ERROR`,
  `FATAL`) from descriptive lower-case text such as "without any error state
  set". `Exception`/`Traceback` detection remains case-insensitive.
- Event-selection summaries such as `accepted N out of M events` count as
  progress evidence rather than errors.

### Added

- Bounded line-numbered tail excerpts for payload/runtime logs, controlled by
  `--job-log-tail-lines` (default 20). `payload_activity` now records the actual
  last non-empty payload line and a bounded payload tail independently of keyword
  matching. The evidence-only report shows the final eight non-empty lines from
  the latest payload stream.

### Validated

- Live 0.2.4 analysis of PanDA job `7262157016` confirmed pilot exclusion and the
  2h 06m 16s payload-output silence, but exposed two remaining issues: the line
  `accepted 2139187 out of 2141242 events ... EventErrorState` was still labeled
  as an error because the lower-case phrase `error state` matched case-insensitively,
  and static `workDir` text files (`in.txt`, `input*.txt`, `*_path.txt`) consumed
  discovery slots.
- The same live evidence showed that line 3629 in `payload.stdout` occurs after
  the periodic `Processed 2140000 events` line at 3593. This motivates preserving
  the actual payload tail instead of equating the last matched progress counter
  with the last payload activity.
- Test suite now contains 126 passing tests; `py_compile` passes.

## [0.2.4] - 2026-08-18

### Changed

- Hang/loop log correlation is now payload-centric. Automatic discovery scans
  `payload.stdout`, `payload.stderr`, and log-like user/payload files under
  `workDir`; `pilotlog.txt` is excluded by default for `--mode hang` because
  pilot termination records describe watchdog/pilot reaction rather than the
  payload state that produced the loop. It remains available through explicit
  `--job-log pilotlog.txt` and for non-hang modes.
- Root-level setup/catalog files are no longer swept into hang-mode correlation,
  and `workDir/usr` is excluded so unpacked release/build text files do not crowd
  runtime logs out of the bounded discovery set.
- Runtime XRootD matching now requires evidence such as `XrdCl::`/`XrdSys::`,
  read-timeout, forced-disconnect, or failure wording; generic `lsetup xrootd` and
  `root://` catalog entries are not treated as runtime failures.
- Error matching no longer misclassifies identifiers such as `EventErrorState`.
- `category_counts` now describes retained evidence consistently; full scan counts
  are preserved separately as `category_counts_found`.

### Added

- `evidence.job_logs.payload_activity` records the latest non-empty payload-stream
  modification time relative to the core plus the latest retained progress line.
  For looping jobs, long payload-output silence is surfaced as deterministic
  evidence and in `--no-llm` output.
- Discovered files and matches now carry stable roles/relative paths so multiple
  `workDir` logs with the same basename remain distinguishable.

### Validated

- Live 0.2.3 analysis of PanDA job `7262157016` showed `payload.stdout` last
  modified 7,576 seconds (2h 06m 16s) before the core after reporting about
  2.14 million processed events. The pilot termination lines retained by 0.2.3
  occurred after core capture and are therefore not causal evidence for the loop.
- The same run exposed false-positive `EventErrorState`, setup-menu XRootD, and
  PoolFileCatalog `root://` matches; 0.2.4 adds regression tests for all three.
- Test suite now contains 124 passing tests; `py_compile` passes.

## [0.2.3] - 2026-08-18

### Added

- Bounded host-side PanDA/payload log correlation whenever `--job-dir` is supplied.
  Automatic discovery prioritizes pilot/payload log files; repeatable `--job-log`
  can select exact files, and `--no-job-logs` disables the feature.
- Recent-tail scanning for large logs, balanced retained matches across files,
  termination/XRootD/error/progress categories, credential redaction, exact line
  numbers, and log mtimes relative to the core capture. Results are stored under
  `evidence.job_logs` and summarized in `--no-llm` output.
- CLI bounds `--max-job-log-files` and `--max-job-log-matches`.

### Changed

- Focused frame evidence now records `frame_details_available`. A library with
  symbols read by GDB can still contain optimized functions with no recoverable
  `info args`/`info locals`; this is reported as a per-frame limitation rather
  than a missing-library-symbol problem.
- Repeated `No symbol table info available.` lines for targeted XRootD frames are
  collapsed into one explanatory note in the human-readable report.

### Validated

- Live 0.2.2 analysis of PanDA job `7262157016` selected the intended T3/F3,
  T2/F3, and T1/F2 XRootD frames automatically. All three returned no frame-local
  args/locals, confirming that further generic GDB-local extraction is lower value
  than job/pilot-log correlation for this core.
- Test suite now contains 121 passing tests; `py_compile` passes.

## [0.2.2] - 2026-08-18

### Added

- Focused post-stack inspection: after grouping all threads, the collector selects
  up to three representative non-idle groups and runs one additional batched GDB
  phase with `thread`, `frame`, `info frame`, `info args`, and `info locals`.
- `evidence.targeted_threads` records the selected thread ID, frame number, stack
  context, and bounded frame/argument/local evidence; `--no-llm` renders it
  compactly.
- `--max-targeted-threads` controls the focused phase (`3` by default, `0` to
  disable). Section markers now support numbered dynamic section names.
- Regression coverage for target selection, exact XRootD T3/F3 + T2/F3 + T1/F2
  behavior, batched command generation, section parsing, summarization, and
  report rendering. Suite now contains 114 tests.

### Validated

- The second live 0.2.1 container run against PanDA job `7262157016` produced no
  evidence-quality warnings, classified all three XRootD threads as blocked, and
  emitted the intended deterministic `Py_Exit(0)` / XRootD-finalization
  observations. The 0.2.2 selector was replayed against that JSON and selects the
  same three frames that were chosen manually during the original investigation.

### Added

- ATLAS container execution backend (`--execution atlas-container`) that uses
  `atlasLocalSetup.sh`, the job's `my_release_setup.sh`, and an analyzer-owned
  evidence worker. The original PanDA `container_script.sh` is never executed.
- Host/container path staging under the standard `/srv` job-directory mount,
  with container timeout, extra Apptainer args, and optional retained worker
  artifacts for debugging.
- Build-ID evidence from `eu-unstrip -n --core`, including exact comparisons for
  the resolved executable and critical EL9 system libraries (`libc`, `libm`,
  `ld-linux`).
- Analysis-environment evidence (OS/glibc), `info files`,
  `show debug-file-directory`, `info auto-load python-scripts`, and summarized
  GDB warning lines.
- Regression coverage for the real EL9 `eu-unstrip` format and ATLAS-container
  launcher contract; suite now contains 107 tests.


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
  `generate_test_cores.sh` to produce crash and hang fixtures locally
  (74 tests at initial prototype, 101 after the progress/budget/container work below).
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

- Real PanDA validation exposed a false-idle classification: threads blocked in
  XRootD shutdown, timeout handling, or `StreamMutex::Lock` were previously
  labelled idle merely because their top frames were futex/condition-variable
  waits. Thread groups now carry `active` / `blocked` / `idle` state, and blocked
  stacks are ranked ahead of genuinely parked workers.
- `--no-llm` thread summaries now show the most informative deeper blocking
  frame instead of only frame `#0`, and deterministic observations identify the
  validated `Py_Exit(sts=0)` -> XRootD-finalization signature without claiming
  an unproven lock cycle.
- `No symbol table info available` from `info args` / `info locals` no longer
  triggers a misleading global "frames have no symbols" warning. Missing-symbol
  warnings are now based on actual `??` backtrace frames and `No` shared-library
  symbol states.
- The `py-bt` unavailable message now states explicitly that CPython GDB-helper
  availability is separate from native Python symbols and full DWARF information.
- Loading pre-0.2.1 JSON preserves the old `idle` boolean when deriving the new
  thread `state` field.

- GDB subprocesses now remove AnalysisBase `PYTHONHOME`/`PYTHONPATH` and issue
  `set python ignore-environment on` as an early initialization command,
  preventing EL9 GDB's embedded Python 3.9 from importing the AnalysisBase
  Python 3.13 standard library.
- `info sharedlibrary` now distinguishes `Yes`, `Yes (*)`, and `No`; libraries
  with `Yes (*)` are no longer incorrectly reported as having no symbols.
- Failed/truncated executable candidates are retained as structured attempts but
  no longer survive as stale warnings after a later candidate resolves.

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