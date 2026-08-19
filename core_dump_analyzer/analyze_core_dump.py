#!/usr/bin/env python3
"""Analyze a core dump with gdb and explain it in plain language using an LLM.

This is a standalone prototype intended to be folded into Bamboo MCP later as an
``atlas.core_dump_analysis`` tool. It is deliberately split into two layers:

1.  An *evidence layer* (:func:`collect_evidence`) that drives ``gdb`` in batch
    mode and normalises, de-duplicates, redacts and truncates the output into a
    JSON-serialisable dictionary. This layer has no LLM awareness at all.
2.  A *synthesis layer* (:func:`analyze_with_llm`) that hands that dictionary to
    the Anthropic API and asks for an operator-readable explanation.

When this becomes an MCP tool, only layer 1 moves into the tool; synthesis
belongs in ``bamboo_executor.py`` alongside every other tool's synthesis prompt.
Run with ``--no-llm`` to see exactly the payload such a tool would return.

Typical usage::

    export ANTHROPIC_API_KEY=sk-ant-...
    python analyze_core_dump.py core.123456
    python analyze_core_dump.py core.123456 --exe /cvmfs/.../bin/python --mode hang
    python analyze_core_dump.py core.123456 --no-llm --json evidence.json

Note on the executable: gdb needs the ELF binary that was running, not the
script. For an ``athena.py`` job that is the Python interpreter, and it must be
the same build the job used (normally from CVMFS). The script tries to recover
that path automatically from the core's NT_FILE note before falling back to
``--exe``.
"""

from __future__ import annotations

import argparse
import copy
from collections import deque
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

__version__ = "0.2.9"

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_FRAMES = 40
DEFAULT_MAX_THREAD_GROUPS = 25
DEFAULT_MAX_TARGETED_THREADS = 3
DEFAULT_MAX_JOB_LOG_FILES = 12
DEFAULT_MAX_JOB_LOG_MATCHES = 60
DEFAULT_MAX_JOB_LOG_BYTES = 20 * 1024 * 1024
DEFAULT_JOB_LOG_TAIL_LINES = 20
DEFAULT_HANG_WORKDIR_LOG_RECENCY_S = 2 * 60 * 60
DEFAULT_GDB_TIMEOUT = 120
DEFAULT_MAX_TOKENS = 4000
DEFAULT_MAX_EVIDENCE_CHARS = 50_000
DEFAULT_CONTAINER_TIMEOUT = 1800
DEFAULT_ATLAS_LOCAL_ROOT_BASE = "/cvmfs/atlas.cern.ch/repo/ATLASLocalRootBase"
DEFAULT_ATLAS_PLATFORM = "el9"

#: Seconds between "still running" heartbeat messages during a gdb phase.
#: Only printed with --verbose; a phase producing no output for this long is
#: exactly the "is it frozen?" situation the heartbeat exists to answer.
DEFAULT_HEARTBEAT_INTERVAL = 15

#: Core size, in MiB, above which a one-time slow-analysis warning is printed.
#: Set --large-core-warning-mib 0 to disable. gdb reloads the whole core once
#: per phase (see README on the deliberate per-phase-subprocess design), so
#: wall-clock time scales with both core size and phase count.
DEFAULT_LARGE_CORE_WARNING_MIB = 1024

#: Rough characters-per-token ratio used only for a human-readable size log
#: line before the API call. Not an accurate tokenizer; do not use for billing.
CHARS_PER_TOKEN_ESTIMATE = 4

#: Hard multiplier on --max-evidence-chars applied as a last-resort cap on the
#: full rendered prompt just before the API call. enforce_global_budget()
#: should always bring evidence under --max-evidence-chars first; this exists
#: as defense-in-depth so a future evidence field can never bypass the budget
#: and send an unbounded (and unboundedly expensive) prompt.
HARD_CAP_MULTIPLIER = 2

#: Per-section character budgets applied before the global budget.
SECTION_LIMITS: dict[str, int] = {
    "backtrace": 12_000,
    "registers": 3_000,
    "args": 4_000,
    "locals": 8_000,
    "frame": 2_000,
    "python_backtrace": 8_000,
    "python_source": 3_000,
    "thread_group": 6_000,
    "targeted_frame": 1_500,
    "targeted_args": 2_000,
    "targeted_locals": 3_000,
    "job_log_line": 800,
}

#: Emitted by gdb's ``echo`` between commands so sections can be split exactly
#: rather than guessed at with boundary regexes.
SECTION_MARKER = "@@BAMBOO_SECTION:{name}@@"
_MARKER_RE = re.compile(r"^@@BAMBOO_SECTION:([a-z0-9_]+)@@\s*$", re.M)

#: Signals that indicate a genuine fault rather than a deliberate core dump.
CRASH_SIGNALS = frozenset({"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGSYS", "SIGTRAP"})

#: Signals typically seen when a supervisor snapshots or kills a looping job.
HANG_SIGNALS = frozenset({"SIGQUIT", "SIGABRT", "SIGTERM", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGINT"})

#: Earliest possible gdb initialization. AnalysisBase exports PYTHONHOME/PYTHONPATH
#: for its Python 3.13 runtime, while EL9 gdb embeds Python 3.9. This setting,
#: together with sanitising those environment variables at process launch, keeps
#: gdb's embedded Python from trying to import the wrong standard library.
GDB_EARLY_INIT_COMMANDS: tuple[str, ...] = (
    "set python ignore-environment on",
)

#: gdb settings applied before the core is loaded. Errors here are harmless on
#: older gdb builds (the command is simply undefined) and are captured in stderr.
GDB_INIT_COMMANDS: tuple[str, ...] = (
    "set confirm off",
    "set pagination off",
    "set height 0",
    "set width 0",
    "set backtrace past-main on",
    "set print frame-arguments scalars",
    # Keep frame lines short for large C/C++ containers. Note that language
    # pretty-printers (notably libpython's) apply their own internal cap instead.
    "set print elements 40",
    "set print repeats 8",
    # debuginfod prompts block on stdin in EL9 gdb and would hang the batch run.
    "set debuginfod enabled off",
    # Required for libpython-gdb.py to auto-load from CVMFS/LCG paths (py-bt).
    "set auto-load safe-path /",
)

#: Patterns scrubbed from any gdb text before it leaves this process.
REDACTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_KEY]"),
    (re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S), "[REDACTED_CERT]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "[REDACTED_JWT]"),
    (re.compile(r"/tmp/x509up_u\d+\w*"), "/tmp/[REDACTED_PROXY]"),
    (re.compile(r"\b(\w*(?:TOKEN|PASSWORD|SECRET|APIKEY|API_KEY))\s*=\s*\S+", re.I), r"\1=[REDACTED]"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{8,}"), "[REDACTED_API_KEY]"),
)


# --------------------------------------------------------------------------- #
# Data containers
# --------------------------------------------------------------------------- #


@dataclass
class GdbPhaseResult:
    """Outcome of one batched gdb invocation.

    Attributes:
        name: Short identifier for the phase, e.g. ``"metadata"``.
        commands: The gdb commands that were executed, in order.
        stdout: Captured standard output.
        stderr: Captured standard error.
        sections: Per-command output, keyed by section name.
        returncode: Process exit code, or ``-1`` if the phase timed out.
        timed_out: Whether the phase exceeded its timeout.
        duration_s: Wall-clock duration in seconds, rounded to two decimals.
    """

    name: str
    commands: list[str]
    sections: dict[str, str] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    duration_s: float = 0.0


@dataclass
class ThreadGroup:
    """A set of threads sharing an identical (address-normalised) backtrace.

    Attributes:
        count: Number of threads with this backtrace.
        thread_ids: gdb thread numbers belonging to the group (may be truncated).
        names: Distinct thread names observed in the group.
        backtrace: One representative backtrace for the group.
        idle: Backwards-compatible flag indicating a genuinely benign idle wait.
        state: ``"active"``, ``"blocked"``, or ``"idle"``. A thread blocked on
            a synchronization primitive while executing meaningful shutdown, I/O,
            or lock-acquisition code is ``"blocked"`` rather than ``"idle"``.
    """

    count: int
    thread_ids: list[str]
    names: list[str]
    backtrace: str
    idle: bool = False
    state: str = "active"


@dataclass
class CoreEvidence:
    """Structured, LLM-ready evidence extracted from a core dump.

    Attributes:
        core_file: Path, size and modification time of the core file.
        executable: Resolved executable path plus how it was resolved.
        gdb: gdb executable path and reported version.
        signal: Terminating signal name, if gdb reported one.
        mode: Either ``"crash"`` or ``"hang"``, after auto-detection.
        mode_source: Whether the mode was supplied or inferred, and from what.
        generated_by: The ``Core was generated by`` command line, if present.
        thread_count: Total number of threads found in the core.
        warnings: Human-readable warnings about degraded evidence quality.
        primary_thread: Backtrace, args, locals, registers of the faulting thread.
        thread_groups: De-duplicated backtraces across all threads.
        targeted_threads: Focused frame/args/locals evidence for selected non-idle threads.
        python: Python-level backtrace from ``py-bt``, if available.
        job_logs: Bounded PanDA/payload log evidence correlated with the captured state.
        process_identity: Conservative identification of whether the captured process is the payload, prmon, or unknown.
        diagnosis: Conservative machine-readable deterministic diagnosis for downstream tools.
        shared_libraries: Summary of loaded libraries and missing symbols.
        phases: Raw metadata about each gdb invocation.
        truncated_sections: Names of sections shortened to fit the budget.
    """

    core_file: dict[str, Any] = field(default_factory=dict)
    executable: dict[str, Any] = field(default_factory=dict)
    gdb: dict[str, Any] = field(default_factory=dict)
    signal: str | None = None
    mode: str = "auto"
    mode_source: str = ""
    generated_by: str | None = None
    thread_count: int | None = None
    warnings: list[str] = field(default_factory=list)
    primary_thread: dict[str, str] = field(default_factory=dict)
    thread_groups: list[ThreadGroup] = field(default_factory=list)
    targeted_threads: list[dict[str, Any]] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    job_logs: dict[str, Any] = field(default_factory=dict)
    process_identity: dict[str, Any] = field(default_factory=dict)
    diagnosis: dict[str, Any] = field(default_factory=dict)
    python: dict[str, Any] = field(default_factory=dict)
    shared_libraries: dict[str, Any] = field(default_factory=dict)
    build_ids: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    gdb_metadata: dict[str, Any] = field(default_factory=dict)
    phases: list[dict[str, Any]] = field(default_factory=list)
    truncated_sections: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the evidence.

        Returns:
            A dictionary with dataclass members expanded recursively.
        """
        payload = asdict(self)
        payload["thread_groups"] = [asdict(group) for group in self.thread_groups]
        return payload


# --------------------------------------------------------------------------- #
# Text helpers
# --------------------------------------------------------------------------- #


def redact(text: str, enabled: bool = True) -> str:
    """Strip credentials and other secrets from gdb output.

    Args:
        text: Raw text to scrub.
        enabled: When ``False``, the text is returned unchanged.

    Returns:
        The scrubbed text.
    """
    if not enabled or not text:
        return text
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


#: Default separator inserted between the retained head and tail of truncated
#: text. Shared with _shrink_text_field() so it can compute the true minimum
#: length truncate() can produce for a given floor (limit + len(marker)),
#: rather than looping forever comparing against a length it can never reach.
TRUNCATION_MARKER = "\n... [truncated] ..."


def truncate(text: str, limit: int, marker: str = TRUNCATION_MARKER) -> tuple[str, bool]:
    """Shorten text to a character budget, keeping head and tail.

    The head is favoured because the top stack frames matter most, but the tail
    is retained so that ``main`` and thread entry points remain visible.

    Args:
        text: Text to shorten.
        limit: Maximum number of characters to keep, excluding the marker.
        marker: Separator inserted between the retained head and tail.

    Returns:
        A tuple of the possibly-shortened text and whether truncation occurred.
    """
    if len(text) <= limit:
        return text, False
    head = int(limit * 0.75)
    tail = limit - head
    return f"{text[:head]}{marker}{text[-tail:]}", True


def clean_gdb_noise(text: str) -> str:
    """Remove repetitive gdb boilerplate that carries no diagnostic value.

    Args:
        text: Raw gdb output.

    Returns:
        The output with download progress, licence banners and duplicate
        "Missing separate debuginfos" hints removed.
    """
    drop_prefixes = (
        "GNU gdb",
        "Copyright (C)",
        "License GPLv",
        "This is free software",
        "There is NO WARRANTY",
        "Type \"show copying\"",
        "Type \"show warranty\"",
        "This GDB was configured",
        "For bug reporting instructions",
        "Find the GDB manual",
        "For help, type \"help\"",
        "Type \"apropos word\"",
        "Reading symbols from",
        "[Thread debugging using",
        "Using host libthread_db",
        "Downloading",
        "[New LWP",
        "[New Thread",
        "[Current thread is",
        "warning: Memory read failed for corefile section",
    )
    lines = [ln for ln in text.splitlines() if not ln.strip().startswith(drop_prefixes)]
    collapsed: list[str] = []
    for line in lines:
        if collapsed and not line.strip() and not collapsed[-1].strip():
            continue
        collapsed.append(line)
    return "\n".join(collapsed).strip()


def normalise_frame_line(line: str) -> str:
    """Reduce a backtrace line to an address-independent signature.

    Args:
        line: A single ``#N  0x... in func (...) at file:line`` frame line.

    Returns:
        A normalised string suitable for grouping identical stacks.
    """
    line = re.sub(r"^#\d+\s+", "", line.strip())
    line = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", line)
    line = re.sub(r"\s+", " ", line)
    return line


# --------------------------------------------------------------------------- #
# gdb driving
# --------------------------------------------------------------------------- #


def split_sections(text: str) -> dict[str, str]:
    """Split gdb output on the section markers emitted between commands.

    Everything before the first marker is gdb's load banner and is discarded.

    Args:
        text: Raw gdb stdout containing section markers.

    Returns:
        A mapping of section name to that command's cleaned output.
    """
    matches = list(_MARKER_RE.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        sections[match.group(1)] = clean_gdb_noise(text[match.end():end])
    return sections


def find_gdb(explicit: str | None) -> str:
    """Locate the gdb executable.

    Args:
        explicit: A user-supplied path, or ``None`` to search ``PATH``.

    Returns:
        Path to a usable gdb executable.

    Raises:
        FileNotFoundError: If gdb cannot be found.
    """
    candidate = explicit or shutil.which("gdb")
    if not candidate or not Path(candidate).exists():
        raise FileNotFoundError(
            "gdb not found. Install it (dnf install gdb) or pass --gdb /path/to/gdb."
        )
    return candidate


def gdb_subprocess_env() -> dict[str, str]:
    """Return a copy of the environment safe for gdb's embedded Python.

    AnalysisBase commonly exports ``PYTHONHOME`` and ``PYTHONPATH`` for its
    Python runtime. EL9 gdb embeds a different Python version, so inheriting
    those variables can make gdb fail before it processes any commands. Other
    release variables, especially ``PATH`` and ``LD_LIBRARY_PATH``, are kept.
    """
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    return env


def gdb_version(gdb_path: str) -> str:
    """Return the first line of ``gdb --version`` using a sanitized environment.

    Args:
        gdb_path: Path to the gdb executable.

    Returns:
        The version banner, or ``"unknown"`` if it could not be read.
    """
    try:
        proc = subprocess.run(
            [gdb_path, "--version"], capture_output=True, text=True, timeout=30, check=False,
            env=gdb_subprocess_env(),
        )
        return proc.stdout.splitlines()[0].strip() if proc.stdout else "unknown"
    except (OSError, subprocess.SubprocessError, IndexError):
        return "unknown"


def _report_heartbeat(name: str, started: float, stop_event: threading.Event, interval: int) -> None:
    """Print periodic "still running" messages while a gdb phase is blocked.

    ``subprocess.run(capture_output=True)`` buffers all of a phase's output
    until the process exits, so nothing is printed while gdb is working no
    matter how long that takes. On a large core, a single phase reloading and
    walking the whole core can easily run past a minute; this background
    thread is the only thing that distinguishes "still working" from "frozen"
    during that window.

    Args:
        name: Short identifier for the phase being watched.
        started: ``time.monotonic()`` value captured when the phase started.
        stop_event: Set by the caller once the phase has finished, so this
            loop exits promptly instead of waiting out its final interval.
        interval: Seconds between heartbeat messages.
    """
    while not stop_event.wait(interval):
        elapsed = time.monotonic() - started
        print(f"[*] gdb phase '{name}' still running ({elapsed:.0f}s elapsed)...", file=sys.stderr)


def run_gdb_phase(
    gdb_path: str,
    core_path: Path,
    exe_path: str | None,
    name: str,
    commands: Sequence[tuple[str, str]],
    timeout: int,
    progress: bool = True,
    detail: bool = False,
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
) -> GdbPhaseResult:
    """Run one batch of gdb commands against the core file.

    Each phase is a separate process so that a single hanging command cannot
    take down the whole analysis.

    Args:
        gdb_path: Path to the gdb executable.
        core_path: Path to the core dump file.
        exe_path: Path to the matching ELF executable, or ``None``.
        name: Short identifier for this phase.
        commands: ``(section_name, gdb_command)`` pairs to execute in order.
        timeout: Per-phase timeout in seconds.
        progress: Whether to print a start/finish line for this phase.
        detail: Whether to also print periodic heartbeat messages while the
            phase is running. Has no effect if ``progress`` is ``False``.
        heartbeat_interval: Seconds between heartbeat messages when ``detail``
            is enabled.

    Returns:
        A :class:`GdbPhaseResult` describing the invocation.
    """
    argv: list[str] = [gdb_path, "-q", "-nx", "-batch"]
    for setting in GDB_EARLY_INIT_COMMANDS:
        argv += ["-eiex", setting]
    for setting in GDB_INIT_COMMANDS:
        argv += ["-iex", setting]
    if exe_path:
        argv.append(exe_path)
    argv += ["-c", str(core_path)]
    for section, command in commands:
        argv += ["-ex", f"echo \\n{SECTION_MARKER.format(name=section)}\\n", "-ex", command]

    if progress:
        print(f"[*] gdb phase '{name}' starting...", file=sys.stderr)

    started = time.monotonic()
    stop_event = threading.Event()
    heartbeat_thread: threading.Thread | None = None
    if progress and detail:
        heartbeat_thread = threading.Thread(
            target=_report_heartbeat, args=(name, started, stop_event, heartbeat_interval), daemon=True,
        )
        heartbeat_thread.start()

    timed_out = False
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False, env=gdb_subprocess_env()
        )
        stdout = proc.stdout or ""
        result = GdbPhaseResult(
            name=name,
            commands=[cmd for _, cmd in commands],
            sections=split_sections(stdout),
            stdout=stdout,
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            duration_s=round(time.monotonic() - started, 2),
        )
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        result = GdbPhaseResult(
            name=name,
            commands=[cmd for _, cmd in commands],
            stdout=exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            stderr=f"gdb phase '{name}' timed out after {timeout}s",
            returncode=-1,
            timed_out=True,
            duration_s=round(time.monotonic() - started, 2),
        )
    finally:
        stop_event.set()
        if heartbeat_thread is not None:
            heartbeat_thread.join(timeout=1.0)

    if progress:
        status = f"timed out after {result.duration_s:.1f}s" if timed_out else f"completed in {result.duration_s:.1f}s"
        print(f"[*] gdb phase '{name}' {status}", file=sys.stderr)
    return result


# --------------------------------------------------------------------------- #
# Executable resolution
# --------------------------------------------------------------------------- #


def executable_from_auxv(
    gdb_path: str,
    core_path: Path,
    timeout: int,
    progress: bool = True,
    detail: bool = False,
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL,
) -> str | None:
    """Recover the executable path from the core's ``AT_EXECFN`` auxiliary vector entry.

    This is the most portable source: gdb can read it from a bare core with no
    executable loaded, and it does not depend on ``readelf`` being able to decode
    64-bit notes. It records the path exactly as passed to ``execve``.

    Args:
        gdb_path: Path to the gdb executable.
        core_path: Path to the core dump file.
        timeout: gdb timeout in seconds.
        progress: Whether to print a start/finish line for the gdb probe.
        detail: Whether to also print heartbeat messages during the probe.
        heartbeat_interval: Seconds between heartbeat messages when ``detail``
            is enabled.

    Returns:
        The recorded executable path, or ``None`` if it could not be read.
    """
    result = run_gdb_phase(
        gdb_path, core_path, None, "auxv", [("auxv", "info auxv")], timeout,
        progress=progress, detail=detail, heartbeat_interval=heartbeat_interval,
    )
    match = re.search(r"AT_EXECFN\s+File name of executable\s+0x[0-9a-fA-F]+\s+\"(.+?)\"", result.stdout)
    return match.group(1) if match else None


def executable_from_nt_file(core_path: Path) -> str | None:
    """Recover the executable path from the core file's NT_FILE note.

    This is the most reliable source: the kernel records absolute paths for all
    file-backed mappings, and the first mapping at page offset zero is the main
    executable. It survives cases where ``argv[0]`` was relative or truncated,
    which matters for CVMFS-hosted Python interpreters running ``athena.py``.

    Args:
        core_path: Path to the core dump file.

    Returns:
        The absolute executable path, or ``None`` if it could not be recovered.
    """
    readelf = shutil.which("eu-readelf") or shutil.which("readelf")
    if not readelf:
        return None
    try:
        proc = subprocess.run(
            [readelf, "-n", str(core_path)], capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None

    lines = proc.stdout.splitlines()
    in_nt_file = False
    triple = re.compile(r"^\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(?:0x)?([0-9a-fA-F]+)\s*$")
    for index, line in enumerate(lines):
        if "NT_FILE" in line:
            in_nt_file = True
            continue
        if not in_nt_file:
            continue
        if line.strip().startswith("Owner") or "NT_" in line:
            break
        match = triple.match(line)
        if match and int(match.group(1), 16) == 0 and index + 1 < len(lines):
            candidate = lines[index + 1].strip()
            if candidate.startswith("/"):
                return candidate
    return None


def parse_generated_by(text: str) -> str | None:
    """Extract the ``Core was generated by`` command line from gdb output.

    Args:
        text: gdb output to search.

    Returns:
        The recorded command line, or ``None`` if absent.
    """
    match = re.search(r"Core was generated by [`'\"](.*?)['\"]\.", text, re.S)
    return match.group(1).strip() if match else None


def _argv0_from_command_line(command_line: str | None) -> str | None:
    """Extract argv[0] from a recorded command line.

    Args:
        command_line: The ``Core was generated by`` string, if any.

    Returns:
        The first token, or ``None`` if there is none.
    """
    parts = (command_line or "").split()
    return parts[0] if parts else None


def _existing_path(candidate: str | None) -> tuple[str | None, bool]:
    """Resolve a recorded executable path to something present on this host.

    An absolute recorded path is treated as a build identity and must exist
    exactly. Searching ``PATH`` for its basename is deliberately *not* attempted:
    if a core references ``/cvmfs/.../bin/python`` and CVMFS is not mounted,
    silently substituting the system interpreter would give gdb a different build
    and yield plausible but wrong symbols. Only bare names and relative paths,
    which the OS would itself have resolved via ``PATH``, are searched for.

    Args:
        candidate: A path recorded in the core, possibly relative or stale.

    Returns:
        A tuple of the resolved path (or ``None``) and whether resolution
        involved a search that the caller should warn about.
    """
    if not candidate:
        return None, False
    path = Path(candidate)
    if path.is_file():
        return str(path.resolve()), False
    if path.is_absolute():
        return None, False
    local = Path.cwd() / path.name
    if local.is_file():
        return str(local.resolve()), True
    found = shutil.which(path.name)
    return (found, True) if found else (None, False)


def resolve_executable(gdb_path: str, core_path: Path, explicit: str | None,
                       probe_output: str, timeout: int, progress: bool = True,
                       detail: bool = False,
                       heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL) -> dict[str, Any]:
    """Determine which ELF binary gdb should load alongside the core.

    Resolution order is ``--exe``, then ``AT_EXECFN`` from the auxiliary vector,
    then the core's NT_FILE note, then the recorded command line. Failed automatic
    candidates are recorded as attempts but do not become user-facing warnings if
    a later candidate resolves successfully. This avoids stale warnings such as a
    truncated ``AT_EXECFN`` path surviving after command-line resolution succeeds.
    """
    persistent_notes: list[str] = []
    failed_notes: list[str] = []
    attempts: list[dict[str, Any]] = []

    if explicit:
        explicit_path = Path(explicit)
        if explicit_path.suffix == ".py":
            persistent_notes.append(
                f"--exe pointed at a Python script ({explicit}). gdb needs the interpreter ELF binary, "
                "not the script; ignoring it and attempting automatic resolution."
            )
            attempts.append({"source": "--exe", "recorded": explicit, "resolved": False, "reason": "python-script"})
        elif not explicit_path.is_file():
            persistent_notes.append(f"--exe path does not exist: {explicit}")
            attempts.append({"source": "--exe", "recorded": explicit, "resolved": False, "reason": "missing"})
        else:
            resolved = str(explicit_path.resolve())
            attempts.append({"source": "--exe", "recorded": explicit, "resolved": True, "path": resolved})
            return {"path": resolved, "resolved": True, "source": "--exe",
                    "recorded": None, "notes": persistent_notes, "attempts": attempts}

    candidates: list[tuple[str, str | None]] = [
        ("AT_EXECFN", executable_from_auxv(
            gdb_path, core_path, timeout, progress=progress, detail=detail, heartbeat_interval=heartbeat_interval)),
        ("NT_FILE", executable_from_nt_file(core_path)),
        ("command-line", _argv0_from_command_line(parse_generated_by(probe_output))),
    ]
    for source, recorded in candidates:
        if not recorded:
            attempts.append({"source": source, "recorded": None, "resolved": False, "reason": "not-found-in-core"})
            continue
        resolved, searched = _existing_path(recorded)
        if resolved:
            attempts.append({"source": source, "recorded": recorded, "resolved": True,
                             "path": resolved, "searched": searched})
            notes = list(persistent_notes)
            if searched:
                notes.append(
                    f"Executable recorded as '{recorded}' was not found directly and was matched to "
                    f"'{resolved}' by search. Verify it is the same build; a mismatched binary yields "
                    "plausible but wrong symbols."
                )
            return {"path": resolved, "resolved": True, "source": source,
                    "recorded": recorded, "notes": notes, "attempts": attempts}
        attempts.append({"source": source, "recorded": recorded, "resolved": False, "reason": "missing"})
        failed_notes.append(
            f"The core references executable '{recorded}' ({source}), which is not present on this host. "
            "No substitute was used, because a different build would produce misleading symbols. "
            "Re-run where that path is available (for ATLAS jobs, with the matching CVMFS release mounted), "
            "or pass the correct binary with --exe."
        )

    notes = persistent_notes + failed_notes
    notes.append("No executable could be resolved. Backtraces will be unsymbolised and largely uninterpretable.")
    return {"path": None, "resolved": False, "source": "none", "recorded": None,
            "notes": notes, "attempts": attempts}


CRITICAL_BUILD_ID_BASENAMES = frozenset({"libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2"})


def collect_runtime_environment() -> dict[str, Any]:
    """Collect a small deterministic description of the current analysis OS."""
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            os_release[key] = value.strip().strip('"')
    except OSError:
        pass

    glibc = "unknown"
    ldd = shutil.which("ldd")
    if ldd:
        try:
            proc = subprocess.run([ldd, "--version"], capture_output=True, text=True, timeout=15, check=False)
            first = (proc.stdout or proc.stderr or "").splitlines()
            if first:
                glibc = first[0].strip()
        except (OSError, subprocess.SubprocessError):
            pass
    return {
        "execution_backend": "local",
        "os": os_release.get("PRETTY_NAME") or os_release.get("NAME") or "unknown",
        "os_id": os_release.get("ID"),
        "os_version": os_release.get("VERSION_ID"),
        "glibc": glibc,
    }


def parse_eu_unstrip_modules(text: str) -> list[dict[str, str]]:
    """Parse ``eu-unstrip -n --core`` module lines into compact records."""
    modules: list[dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or "+0x" not in parts[0] or "@0x" not in parts[1]:
            continue
        build_id = parts[1].split("@", 1)[0]
        path = next((part for part in parts[2:] if part.startswith("/")), "")
        name = Path(path).name if path else parts[-1]
        modules.append({"build_id": build_id, "path": path, "name": name, "mapping": parts[0]})
    return modules


def file_build_id(path: str) -> str | None:
    """Read an ELF Build ID from a file using an available readelf implementation."""
    if not path or not Path(path).is_file():
        return None
    tool = shutil.which("eu-readelf") or shutil.which("readelf")
    if not tool:
        return None
    try:
        proc = subprocess.run([tool, "-n", path], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", (proc.stdout or "") + "\n" + (proc.stderr or ""))
    return match.group(1).lower() if match else None


def collect_build_id_evidence(core_path: Path, exe_path: str | None) -> tuple[dict[str, Any], str]:
    """Collect core module Build IDs and compare key files on the analysis host."""
    tool = shutil.which("eu-unstrip")
    if not tool:
        return {"available": False, "reason": "eu-unstrip not found"}, ""
    try:
        proc = subprocess.run(
            [tool, "-n", "--core", str(core_path)], capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": f"eu-unstrip failed: {exc}"}, ""
    raw = (proc.stdout or "") + (proc.stderr or "")
    modules = parse_eu_unstrip_modules(proc.stdout or "")
    selected: list[dict[str, Any]] = []
    exe_resolved = str(Path(exe_path).resolve()) if exe_path and Path(exe_path).is_file() else exe_path
    for module in modules:
        path = module.get("path", "")
        name = module.get("name", "")
        is_executable = bool(
            exe_path and path
            and (path == exe_path or (exe_resolved and str(Path(path).resolve()) == exe_resolved))
        )
        if name not in CRITICAL_BUILD_ID_BASENAMES and not is_executable:
            continue
        disk_id = file_build_id(path)
        core_id = module["build_id"].lower()
        selected.append({
            "name": name,
            "path": path,
            "role": "executable" if is_executable else "system-library",
            "core_build_id": core_id,
            "file_build_id": disk_id,
            "file_present": bool(path and Path(path).is_file()),
            "match": (disk_id == core_id) if disk_id else None,
        })
    mismatches = [item for item in selected if item.get("match") is False]
    unavailable = [item for item in selected if item.get("match") is None]
    return {
        "available": proc.returncode == 0 or bool(modules),
        "tool": tool,
        "module_count": len(modules),
        "checked": selected,
        "mismatch_count": len(mismatches),
        "unverified_count": len(unavailable),
        "coverage": "verified" if selected and not mismatches and not unavailable else ("partial" if selected else "unverified"),
        "raw_excerpt": raw[:2000] if len(modules) < 4 else "",
    }, raw


# --------------------------------------------------------------------------- #
# Output parsing
# --------------------------------------------------------------------------- #


def parse_signal(text: str) -> str | None:
    """Find the terminating signal reported by gdb.

    Args:
        text: gdb output to search.

    Returns:
        The signal name such as ``"SIGSEGV"``, or ``None``.
    """
    match = re.search(r"(?:Program terminated with signal|It stopped with signal)\s+(SIG[A-Z0-9]+)", text)
    return match.group(1) if match else None


def parse_thread_count(text: str) -> int | None:
    """Count threads from ``info threads`` output.

    Args:
        text: gdb output containing an ``info threads`` table.

    Returns:
        The number of threads, or ``None`` if the table was not found.
    """
    count = len(re.findall(r"^[\s*]+\d+\s+(?:Thread|LWP|process|Process)\b", text, re.M))
    return count or None


def collect_warnings(text: str) -> list[str]:
    """Detect conditions that degrade the quality of the evidence.

    Args:
        text: Combined gdb stdout and stderr.

    Returns:
        A list of human-readable warnings.
    """
    warnings: list[str] = []
    checks = (
        ("is truncated", "The core file is truncated (likely a `ulimit -c` cap). Deep frames may be missing or wrong."),
        ("core file may not match", "gdb reports the core may not match the executable. Symbols may be misleading."),
        ("no debugging symbols found", "The executable was built or shipped without debug symbols."),
        ("Missing separate debuginfo", "Separate debuginfo packages are missing for one or more libraries."),
        ("Cannot access memory", "Parts of the process memory are unreadable in this core."),
    )
    for needle, message in checks:
        if needle in text and message not in warnings:
            warnings.append(message)
    return warnings


def _classify_thread_stack(backtrace: str) -> str:
    """Classify a thread stack as active, blocked, or genuinely idle.

    A top-level futex/condition-variable wait does *not* by itself mean a thread
    is uninteresting. In hang cores, the thread we care about is often blocked
    in exactly such a primitive while a deeper frame shows a shutdown handshake,
    mutex acquisition, timeout handler, or other meaningful operation.

    Returns:
        ``"active"`` when the top frames are not a known wait, ``"blocked"``
        when they are waiting in a meaningful blocking context, otherwise
        ``"idle"`` for a benign parked worker.
    """
    wait_markers = (
        "pthread_cond_wait", "pthread_cond_timedwait", "__futex_abstimed_wait",
        "epoll_wait", "poll (", "ppoll", "select (", "nanosleep", "sem_wait",
        "sigwait", "accept (", "read (", "recvmsg", "XrdSysCondVar::Wait",
    )
    frames = [line for line in backtrace.splitlines() if line.lstrip().startswith("#")]
    head = "\n".join(frames[:3])
    if not any(marker in head for marker in wait_markers):
        return "active"

    # These contexts make a blocking primitive diagnostically meaningful rather
    # than a benign worker wait. The list intentionally mixes generic lock/exit
    # patterns with XRootD shutdown/timeout operations seen in ATLAS jobs.
    blocking_context_markers = (
        "pthread_mutex_lock", "__lll_lock_wait", "std::mutex::lock",
        "::Lock(", "::SendCmd(", "::Stop(", "::Finalize(",
        "::ShutdownEvents(", "::ForceDisconnect(", "::ForceError(",
        "::OnReadTimeout(", "Py_Exit (", "__run_exit_handlers",
    )
    if any(marker in backtrace for marker in blocking_context_markers):
        return "blocked"
    return "idle"


def _is_idle_stack(backtrace: str) -> bool:
    """Return whether a stack is a genuinely benign parked-worker wait.

    Kept as a small compatibility wrapper for callers/tests that used the
    original boolean classifier.
    """
    return _classify_thread_stack(backtrace) == "idle"


def _thread_context_frame(backtrace: str) -> str:
    """Return the most useful single frame for a compact thread summary."""
    frames = [line.strip() for line in backtrace.splitlines() if line.lstrip().startswith("#")]
    if not frames:
        return "?"
    preferred = (
        "::OnReadTimeout(", "::ForceDisconnect(", "::ShutdownEvents(",
        "::StreamMutex::Lock(", "::SendCmd(", "::Stop(", "::Finalize(",
        "Py_Exit (", "pthread_mutex_lock", "__lll_lock_wait",
    )
    for line in frames:
        if any(marker in line for marker in preferred):
            return line
    generic = (
        "__futex_abstimed_wait", "pthread_cond_wait", "XrdSysCondVar::Wait",
        "start_thread", "clone3",
    )
    for line in frames[1:]:
        if not any(marker in line for marker in generic):
            return line
    return frames[0]


def _frame_number(frame_line: str) -> int | None:
    """Extract a numeric gdb frame index from a rendered ``#N`` frame line."""
    match = re.match(r"^#(\d+)\b", frame_line.strip())
    return int(match.group(1)) if match else None


def select_targeted_threads(thread_groups: list[ThreadGroup], max_targets: int) -> list[dict[str, Any]]:
    """Select representative non-idle threads for focused frame inspection.

    One representative is chosen from each interesting thread group.  The
    context-frame heuristic is the same one used by the compact report, so the
    detailed evidence explains exactly the frame the operator sees highlighted.
    """
    if max_targets <= 0:
        return []
    targets: list[dict[str, Any]] = []
    for group in thread_groups:
        if group.state == "idle" or not group.thread_ids:
            continue
        context = _thread_context_frame(group.backtrace)
        frame_no = _frame_number(context)
        if frame_no is None:
            continue
        targets.append({
            "thread_id": group.thread_ids[0],
            "state": group.state,
            "frame": frame_no,
            "context": context,
        })
        if len(targets) >= max_targets:
            break
    return targets


def _build_targeted_phase(targets: list[dict[str, Any]], include_locals: bool) -> list[tuple[str, str]]:
    """Build one batched gdb phase for the selected thread/frame pairs."""
    commands: list[tuple[str, str]] = []
    for index, target in enumerate(targets, start=1):
        prefix = f"target_{index}"
        commands.extend([
            (f"{prefix}_thread", f"thread {target['thread_id']}"),
            (f"{prefix}_frame_select", f"frame {target['frame']}"),
            (f"{prefix}_frame", "info frame"),
            (f"{prefix}_args", "info args"),
        ])
        if include_locals:
            commands.append((f"{prefix}_locals", "info locals"))
    return commands


def summarise_targeted_threads(targets: list[dict[str, Any]], sections: dict[str, str],
                               redact_enabled: bool) -> list[dict[str, Any]]:
    """Attach bounded ``info frame/args/locals`` output to targeted thread metadata.

    ``info sharedlibrary`` saying ``Yes`` only means that GDB read symbols for
    the DSO; an optimized function can still lack usable argument/local DWARF.
    Record that distinction explicitly so the report does not imply that the
    whole library is unsymbolized when only frame-local detail is unavailable.
    """
    summaries: list[dict[str, Any]] = []
    unavailable_marker = "No symbol table info available."
    for index, target in enumerate(targets, start=1):
        prefix = f"target_{index}"
        item = dict(target)
        detail_available = False
        for key, limit_name in (("frame_info", "targeted_frame"),
                                ("args", "targeted_args"),
                                ("locals", "targeted_locals")):
            section_key = f"{prefix}_{'frame' if key == 'frame_info' else key}"
            body = sections.get(section_key, "").strip()
            if body:
                item[key], _ = truncate(redact(body, redact_enabled), SECTION_LIMITS[limit_name])
                if key in {"args", "locals"} and unavailable_marker not in body:
                    detail_available = True
        item["frame_details_available"] = detail_available
        summaries.append(item)
    return summaries



JOB_LOG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("termination", re.compile(
        r"\b(SystemExit|SIGTERM|SIGQUIT|SIGKILL|killed|kill signal|payload.*(?:exit|finished)|exit code|walltime|looping job)\b",
        re.I,
    )),
    # Runtime I/O evidence only.  Generic mentions such as `lsetup xrootd` or
    # `root://` entries in a catalog describe configuration/input locations,
    # not an observed XRootD failure in the payload.
    ("xrootd", re.compile(
        r"(?:\bXrd(?:Cl|Sys)::|\bread timeout\b|\boperation expired\b|\bforce(?:d)? disconnect\b|"
        r"\bXRootD\b.*\b(?:error|timeout|fail(?:ed|ure)?)\b)",
        re.I,
    )),
    # Severity words are intentionally case-sensitive here.  Payload text can
    # legitimately contain phrases such as "without any error state set";
    # treating every lower-case word "error" as a log severity creates false
    # positives.  Exception/traceback markers remain case-insensitive.
    ("error", re.compile(
        r"(?:^|[\s|])(?:FATAL|ERROR)(?=[\s:|]|$)|(?:^|[\s|])(?:Fatal|Error):|(?i:\b(?:exception|traceback)\b)",
    )),
    ("completion", re.compile(
        r"\bworker finished successfully\b|\bcurrent job status:\s*\d+\s+success,\s*0\s+failure|"
        r"\bMoving the analysis root file\b|\brenaming .*output\.root\b",
        re.I,
    )),
    ("progress", re.compile(
        r"\b(events? processed|processed .*events?|accepted \d+ out of \d+ events|"
        r"finali[sz](?:e|ing|ation)|closing .*file|output .*file|write .*output)\b",
        re.I,
    )),
)


def _log_role(path: Path, job_dir: Path) -> str:
    """Return a stable evidence role for a discovered payload/job log."""
    try:
        rel = path.relative_to(job_dir)
    except ValueError:
        rel = path
    name = path.name.lower()
    if len(rel.parts) == 1 and name == "payload.stdout":
        return "payload-stdout"
    if len(rel.parts) == 1 and name == "payload.stderr":
        return "payload-stderr"
    if len(rel.parts) == 1 and name == "pilotlog.txt":
        return "pilot"
    if rel.parts and rel.parts[0] == "workDir":
        return "workdir-log"
    if "payload" in name:
        return "payload-log"
    return "other"


def _job_log_rank(path: Path, job_dir: Path, core_mtime: float | None = None) -> tuple[int, float, str]:
    """Rank payload streams and recent workDir logs ahead of incidental files."""
    role = _log_role(path, job_dir)
    role_rank = {
        "payload-stdout": 0,
        "payload-stderr": 0,
        "payload-log": 1,
        "workdir-log": 2,
        "pilot": 3,
        "other": 9,
    }.get(role, 9)
    recency = float("inf")
    if core_mtime is not None:
        try:
            recency = abs(path.stat().st_mtime - core_mtime)
        except OSError:
            pass
    return (role_rank, recency, str(path))


def _looks_like_log_file(path: Path) -> bool:
    """Conservatively identify runtime log artifacts by name/suffix.

    A bare ``.txt`` suffix is not enough: PanDA work directories commonly
    contain input lists, path/configuration files, and other static text.
    Arbitrarily named text logs can still be supplied explicitly with
    ``--job-log``.
    """
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in {".log", ".out", ".err", ".stdout", ".stderr"}:
        return True
    return any(token in name for token in ("log", "stdout", "stderr", "trace", "debug", "report"))


def discover_job_logs(job_dir: Path, explicit: Sequence[str] | None = None,
                      max_files: int = DEFAULT_MAX_JOB_LOG_FILES,
                      failure_mode: str = "auto",
                      core_mtime: float | None = None) -> list[Path]:
    """Discover bounded payload-centric logs for a core-analysis failure mode.

    For looping/hang jobs the pilot's own log is deliberately excluded from
    automatic discovery: pilot termination records describe what the pilot did
    *after* deciding the payload was looping, not what the payload was doing
    before the core was captured.  The primary automatic sources are the
    payload stdout/stderr streams plus user/payload-generated log-like files
    below ``workDir``.  ``--job-log`` remains an explicit escape hatch for any
    other file, including ``pilotlog.txt``.
    """
    candidates: list[Path] = []
    if explicit:
        for raw in explicit:
            path = Path(raw).expanduser()
            if not path.is_absolute():
                path = job_dir / path
            if path.is_file():
                candidates.append(path.resolve())
    else:
        generated_prefixes = ("core-analysis", ".core_dump_analyzer_")

        # Canonical payload streams live at the job root.
        for name in ("payload.stdout", "payload.stderr"):
            path = job_dir / name
            if path.is_file():
                candidates.append(path.resolve())
        for path in job_dir.glob("payload*"):
            if path.is_file() and _looks_like_log_file(path):
                candidates.append(path.resolve())

        # User/payload-created logs are expected below workDir.  Search them
        # recursively but only retain log-like text artifacts; build products
        # and payload data files are intentionally ignored.  For hang analysis
        # we additionally prefer files active near the end of the payload: a
        # job tarball can contain old reference/test logs copied into workDir,
        # and their ERROR lines are not evidence about this execution.
        payload_mtimes: list[float] = []
        for payload_name in ("payload.stdout", "payload.stderr"):
            payload_path = job_dir / payload_name
            try:
                if payload_path.is_file() and payload_path.stat().st_size > 0:
                    payload_mtimes.append(payload_path.stat().st_mtime)
            except OSError:
                pass
        latest_payload_mtime = max(payload_mtimes, default=None)

        work_dir = job_dir / "workDir"
        if work_dir.is_dir():
            for path in work_dir.rglob("*"):
                if not path.is_file() or not _looks_like_log_file(path):
                    continue
                try:
                    rel_work = path.relative_to(work_dir)
                except ValueError:
                    continue
                # The unpacked user release can live below workDir/usr and may
                # contain thousands of build/configuration .txt files.  Those
                # are not runtime logs and must not crowd payload-created files
                # out of the bounded discovery set.
                if rel_work.parts and rel_work.parts[0] == "usr":
                    continue
                name = path.name.lower()
                if name.startswith(generated_prefixes):
                    continue
                if failure_mode == "hang" and latest_payload_mtime is not None:
                    try:
                        if path.stat().st_mtime < latest_payload_mtime - DEFAULT_HANG_WORKDIR_LOG_RECENCY_S:
                            continue
                    except OSError:
                        continue
                candidates.append(path.resolve())

        # Pilot evidence can still be useful for non-looping failures, but not
        # for an explicitly diagnosed hang/loop.
        if failure_mode != "hang":
            pilot = job_dir / "pilotlog.txt"
            if pilot.is_file():
                candidates.append(pilot.resolve())

    unique = list(dict.fromkeys(candidates))
    unique.sort(key=lambda path: _job_log_rank(path, job_dir, core_mtime))
    return unique[:max(0, max_files)]


def _format_duration(seconds: float) -> str:
    """Format a non-negative duration compactly for evidence-only reports."""
    total = max(0, int(round(seconds)))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours}h")
    if hours or minutes:
        parts.append(f"{minutes:02d}m" if hours else f"{minutes}m")
    parts.append(f"{secs:02d}s" if hours or minutes else f"{secs}s")
    return " ".join(parts)


def collect_job_log_evidence(job_dir: Path, explicit: Sequence[str] | None = None,
                             max_files: int = DEFAULT_MAX_JOB_LOG_FILES,
                             max_matches: int = DEFAULT_MAX_JOB_LOG_MATCHES,
                             max_bytes: int = DEFAULT_MAX_JOB_LOG_BYTES,
                             tail_lines: int = DEFAULT_JOB_LOG_TAIL_LINES,
                             redact_enabled: bool = True,
                             core_mtime: float | None = None,
                             failure_mode: str = "auto") -> dict[str, Any]:
    """Extract bounded payload/runtime evidence near the captured core state.

    Hang-mode collection is payload-centric: canonical payload stdout/stderr
    and log-like files under ``workDir`` are scanned automatically, while the
    pilot log is excluded unless supplied explicitly.  Large logs are searched
    in a tail window because the last payload activity before a loop is usually
    the most useful.  Matches are bounded per file so one noisy log cannot
    evict evidence from all other payload-generated logs.
    """
    files = discover_job_logs(
        job_dir, explicit=explicit, max_files=max_files,
        failure_mode=failure_mode, core_mtime=core_mtime,
    )
    result: dict[str, Any] = {
        "available": bool(files),
        "job_dir": str(job_dir),
        "profile": "payload-centric" if failure_mode == "hang" else "general",
        "pilotlog_default_excluded": failure_mode == "hang" and not explicit,
        "files": [],
        "matches": [],
        "category_counts": {},
        "category_counts_found": {},
        "tail_lines_per_file": max(0, tail_lines),
    }
    if failure_mode == "hang" and not explicit:
        result["workdir_recency_window_s"] = DEFAULT_HANG_WORKDIR_LOG_RECENCY_S
    if not files or max_matches <= 0:
        result["match_limit_reached"] = False
        return result

    per_file_limit = max(4, (max_matches + len(files) - 1) // len(files))
    all_matches: list[dict[str, Any]] = []
    found_counts: dict[str, int] = {}
    total_found = 0

    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        window_start = max(0, stat.st_size - max_bytes)
        line_base = 0
        try:
            with path.open("rb") as handle:
                remaining = window_start
                while remaining > 0:
                    chunk = handle.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    line_base += chunk.count(b"\n")
                    remaining -= len(chunk)
                if window_start:
                    partial = handle.readline()
                    line_base += 1
                    scanned = handle.read(max(0, max_bytes - len(partial)))
                else:
                    scanned = handle.read(max_bytes)
        except OSError:
            continue

        try:
            rel = str(path.relative_to(job_dir))
        except ValueError:
            rel = path.name
        role = _log_role(path, job_dir)
        meta = {
            "path": str(path),
            "relative_path": rel,
            "role": role,
            "size_bytes": stat.st_size,
            "scanned_bytes": len(scanned),
            "window": "tail" if window_start else "full",
            "truncated": bool(window_start),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
        }
        if core_mtime is not None:
            meta["mtime_delta_from_core_s"] = round(stat.st_mtime - core_mtime, 3)
        result["files"].append(meta)

        text = scanned.decode("utf-8", errors="replace")

        # Preserve the actual end of runtime output independently of keyword
        # matching.  For looping jobs this is often more diagnostic than the
        # latest periodic "Processed N events" line because shutdown/finalize
        # messages can follow the last progress counter.
        if tail_lines > 0 and role in {"payload-stdout", "payload-stderr", "payload-log", "workdir-log"}:
            tail: deque[dict[str, Any]] = deque(maxlen=tail_lines)
            for relative_line, line in enumerate(text.splitlines(), start=1):
                clean = line.strip()
                if not clean:
                    continue
                bounded, _ = truncate(redact(clean, redact_enabled), SECTION_LIMITS["job_log_line"])
                tail.append({"line": line_base + relative_line, "text": bounded})
            if tail:
                meta["tail"] = list(tail)

        recent: deque[dict[str, Any]] = deque(maxlen=per_file_limit)
        for relative_line, line in enumerate(text.splitlines(), start=1):
            clean = line.strip()
            if not clean:
                continue
            for category, pattern in JOB_LOG_PATTERNS:
                if not pattern.search(clean):
                    continue
                bounded, _ = truncate(redact(clean, redact_enabled), SECTION_LIMITS["job_log_line"])
                recent.append({
                    "file": str(path),
                    "relative_file": rel,
                    "role": role,
                    "line": line_base + relative_line,
                    "category": category,
                    "text": bounded,
                })
                found_counts[category] = found_counts.get(category, 0) + 1
                total_found += 1
                break
        all_matches.extend(recent)

    retained = all_matches[:max_matches]
    retained_counts: dict[str, int] = {}
    for item in retained:
        category = str(item.get("category", "other"))
        retained_counts[category] = retained_counts.get(category, 0) + 1
    result["matches"] = retained
    result["category_counts"] = retained_counts
    result["category_counts_found"] = found_counts
    result["matched_lines_found"] = total_found
    result["match_limit_reached"] = total_found > len(retained)

    # Filesystem modification time is valuable deterministic evidence for a
    # looping job even when the payload log itself has no timestamps.  Record
    # the latest observed payload-stream write before the core and the most
    # recent retained progress line from that stream.
    payload_files = [
        meta for meta in result["files"]
        if meta.get("role") in {"payload-stdout", "payload-stderr", "payload-log"}
        and meta.get("size_bytes", 0) > 0
        and isinstance(meta.get("mtime_delta_from_core_s"), (int, float))
        and meta["mtime_delta_from_core_s"] <= 0
    ]
    if payload_files:
        latest = max(payload_files, key=lambda meta: meta["mtime_delta_from_core_s"])
        silence_s = abs(float(latest["mtime_delta_from_core_s"]))
        progress_matches = [
            item for item in retained
            if item.get("category") == "progress"
            and item.get("role") in {"payload-stdout", "payload-stderr", "payload-log"}
        ]
        latest_progress = max(progress_matches, key=lambda item: int(item.get("line", 0)), default=None)
        activity: dict[str, Any] = {
            "latest_payload_file": latest.get("relative_path", Path(str(latest.get("path", ""))).name),
            "last_write_before_core_s": round(silence_s, 3),
            "last_write_before_core_human": _format_duration(silence_s),
        }
        latest_tail = latest.get("tail")
        if isinstance(latest_tail, list) and latest_tail:
            activity["last_nonempty_line"] = latest_tail[-1]
            activity["tail"] = latest_tail
        if latest_progress:
            activity["latest_progress"] = latest_progress
        result["payload_activity"] = activity

    return result


def derive_payload_log_observations(job_logs: dict[str, Any], primary_backtrace: str) -> list[str]:
    """Derive conservative completion/shutdown observations from payload tails.

    The payload tail is more reliable than filename heuristics for deciding
    whether a looping job was still in event processing.  These observations
    intentionally describe ordering/state only; they do not claim which XRootD
    lock or timeout caused the shutdown hang.
    """
    activity = job_logs.get("payload_activity", {}) if isinstance(job_logs, dict) else {}
    tail = activity.get("tail", []) if isinstance(activity, dict) else []
    tail_text = "\n".join(str(item.get("text", "")) for item in tail if isinstance(item, dict))
    observations: list[str] = []

    worker_success = "worker finished successfully" in tail_text
    job_success = bool(re.search(r"current job status:\s*\d+\s+success,\s*0\s+failure", tail_text, re.I))
    output_postprocessing = bool(re.search(
        r"Moving the analysis root file|Moving .*hist-output|renaming .*output\.root", tail_text, re.I
    ))
    clean_python_exit = "Py_Exit (sts=0)" in primary_backtrace
    xrootd_finalize = "XrdCl::DefaultEnv::Finalize" in primary_backtrace

    if worker_success and job_success:
        observations.append(
            "Payload EventLoop reported that the worker finished successfully and the batch job status was successful before process exit."
        )
    if output_postprocessing:
        last_line = activity.get("last_nonempty_line")
        suffix = ""
        if isinstance(last_line, dict) and last_line.get("text"):
            suffix = f"; the last payload line was: {last_line['text']}"
        observations.append(
            "Payload output continued into post-processing/output-file handling after EventLoop completion" + suffix + "."
        )
    if worker_success and clean_python_exit and xrootd_finalize:
        observations.append(
            "Combined payload and core evidence places the captured hang after successful event processing, during process shutdown/XRootD finalization rather than inside the EventLoop."
        )
    return observations




def derive_process_identity(evidence: CoreEvidence) -> dict[str, Any]:
    """Identify the process captured by the core without trusting gdb symbols alone.

    The ``Core was generated by`` command line is core metadata and therefore
    remains useful even when gdb warns that a supplied executable may not match.
    Stack-shape signals are used as corroboration, not as the sole identity source.
    """
    command = evidence.generated_by or ""
    primary = evidence.primary_thread.get("backtrace", "")
    all_stacks = "\n".join(group.backtrace for group in evidence.thread_groups)
    stack_text = primary + "\n" + all_stacks

    signals = {
        "generated_by": command or None,
        "command_mentions_prmon": bool(re.search(r"(?:^|[/\s])prmon(?:\s|$)", command, re.I)),
        "command_looks_like_payload": bool(re.search(
            r"EWRun\.py|eventloop|/srv/workDir/usr/|/InstallArea/.*/bin/.*Run\.py", command, re.I
        )),
        "python_runtime_stack": "Py_Exit" in stack_text or "Py_RunMain" in stack_text,
        "root_runtime_stack": "TROOT::" in stack_text or "TNetXNGFile::" in stack_text,
        "xrootd_runtime_stack": "XrdCl::" in stack_text or "XrdSys::" in stack_text,
        "stack_mentions_prmon": bool(re.search(r"\bprmon\b", stack_text, re.I)),
    }

    if signals["command_mentions_prmon"]:
        return {
            "kind": "prmon",
            "confidence": "high",
            "signals": signals,
            "reason": "The core-recorded command line identifies prmon.",
        }
    if signals["command_looks_like_payload"]:
        corroborated = signals["python_runtime_stack"] and (
            signals["root_runtime_stack"] or signals["xrootd_runtime_stack"]
        )
        return {
            "kind": "payload",
            "confidence": "high" if corroborated else "medium",
            "signals": signals,
            "reason": (
                "The core-recorded command line identifies the payload and the captured runtime stack is consistent with it."
                if corroborated else
                "The core-recorded command line identifies the payload, but stack corroboration is limited."
            ),
        }
    if signals["stack_mentions_prmon"]:
        return {
            "kind": "prmon",
            "confidence": "medium",
            "signals": signals,
            "reason": "The captured stack mentions prmon, but the core-recorded command line is inconclusive.",
        }
    return {
        "kind": "unknown",
        "confidence": "low",
        "signals": signals,
        "reason": "The available core metadata does not identify the captured process reliably.",
    }


def derive_symbol_evidence_quality(evidence: CoreEvidence) -> dict[str, Any]:
    """Summarise whether symbol/build identity is verified strongly enough for diagnosis."""
    checked = evidence.build_ids.get("checked", []) if isinstance(evidence.build_ids, dict) else []
    mismatch_count = int(evidence.build_ids.get("mismatch_count", 0) or 0) if isinstance(evidence.build_ids, dict) else 0
    module_count = int(evidence.build_ids.get("module_count", 0) or 0) if isinstance(evidence.build_ids, dict) else 0
    match_warning = any("core may not match the executable" in warning.lower() for warning in evidence.warnings)
    verified = len(checked) > 0 and mismatch_count == 0 and not match_warning
    if mismatch_count:
        level = "low"
    elif match_warning and not checked:
        level = "degraded"
    elif verified:
        level = "verified"
    else:
        level = "partial"
    return {
        "level": level,
        "gdb_executable_match_warning": match_warning,
        "key_build_ids_checked": len(checked),
        "build_id_mismatch_count": mismatch_count,
        "eu_unstrip_module_count": module_count,
        "verified": verified,
    }

def derive_structured_diagnosis(evidence: CoreEvidence) -> dict[str, Any]:
    """Build a conservative machine-readable diagnosis from deterministic evidence.

    Classification describes the captured phase/component, not an initiating
    root cause. Evidence-quality limitations can lower confidence without
    discarding a strongly supported process-phase classification.
    """
    primary = evidence.primary_thread.get("backtrace", "")
    all_stacks = "\n".join(group.backtrace for group in evidence.thread_groups)
    activity = evidence.job_logs.get("payload_activity", {}) if isinstance(evidence.job_logs, dict) else {}
    tail = activity.get("tail", []) if isinstance(activity, dict) else []
    tail_text = "\n".join(str(item.get("text", "")) for item in tail if isinstance(item, dict))
    process_identity = evidence.process_identity or derive_process_identity(evidence)
    symbol_quality = derive_symbol_evidence_quality(evidence)

    signals: dict[str, Any] = {
        "clean_python_exit": "Py_Exit (sts=0)" in primary,
        "xrootd_finalization": "XrdCl::DefaultEnv::Finalize" in primary,
        "xrootd_poller_stop_wait": (
            "XrdSys::IOEvents::Poller::SendCmd" in primary
            and "XrdSys::IOEvents::Poller::Stop" in primary
        ),
        "root_close_files": "TROOT::CloseFiles" in primary,
        "xrootd_remote_file_close": (
            "TNetXNGFile::Close" in primary
            and "XrdCl::File::Close" in primary
            and "XrdCl::FileStateHandler::Close" in primary
        ),
        "xrootd_close_stream_mutex_wait": (
            "XrdCl::StreamMutex::Lock" in primary
            and "XrdCl::Stream::Send" in primary
        ),
        "xrootd_shutdown_events": "XrdCl::PollerBuiltIn::ShutdownEvents" in all_stacks,
        "xrootd_socket_fault": (
            "XrdCl::AsyncSocketHandler::OnFault" in all_stacks
            or "XrdCl::Stream::OnError" in all_stacks
        ),
        "xrootd_read_timeout_force_disconnect": (
            "XrdCl::Stream::OnReadTimeout" in all_stacks
            and "ForceDisconnect" in all_stacks
        ),
        "xrootd_stream_mutex_wait": (
            "XrdCl::StreamMutex::Lock" in all_stacks
            and "XrdCl::Stream::Tick" in all_stacks
        ),
        "eventloop_worker_success": "worker finished successfully" in tail_text,
        "batch_status_success": bool(re.search(
            r"current job status:\s*\d+\s+success,\s*0\s+failure", tail_text, re.I
        )),
        "output_postprocessing": bool(re.search(
            r"Moving the analysis root file|Moving .*hist-output|renaming .*output\.root", tail_text, re.I
        )),
        "captured_process": process_identity.get("kind", "unknown"),
    }
    silence = activity.get("last_write_before_core_s") if isinstance(activity, dict) else None
    if isinstance(silence, (int, float)):
        signals["payload_silence_before_core_s"] = round(float(silence), 3)

    if process_identity.get("kind") == "prmon":
        return {
            "available": True,
            "classification": "monitor-process-core",
            "phase": "monitoring-process",
            "component": "prmon",
            "confidence": process_identity.get("confidence", "medium"),
            "root_cause_established": False,
            "payload_diagnosis_applicable": False,
            "summary": "The core metadata identifies the captured process as prmon rather than the payload; payload-loop diagnosis is not applicable to this core.",
            "process_identity": process_identity,
            "symbol_evidence_quality": symbol_quality,
            "signals": signals,
            "supporting_evidence": [process_identity.get("reason", "The captured process is prmon.")],
            "limitations": [
                "Payload logs in the job directory describe the payload and must not be attributed to the prmon core."
            ],
        }

    if (process_identity.get("kind") == "unknown"
            and symbol_quality.get("level") in {"degraded", "low"}):
        return {
            "available": False,
            "classification": "unclassified",
            "confidence": "low",
            "root_cause_established": False,
            "process_identity": process_identity,
            "symbol_evidence_quality": symbol_quality,
            "signals": signals,
            "reason": "Process identity is unknown and symbol/build identity is degraded; refusing to classify the stack signature.",
        }

    completed_payload = (
        signals["eventloop_worker_success"]
        and signals["batch_status_success"]
        and signals["output_postprocessing"]
    )
    poller_shutdown_signature = (
        evidence.mode == "hang"
        and signals["clean_python_exit"]
        and signals["xrootd_finalization"]
        and signals["xrootd_poller_stop_wait"]
    )
    remote_close_signature = (
        evidence.mode == "hang"
        and signals["clean_python_exit"]
        and signals["root_close_files"]
        and signals["xrootd_remote_file_close"]
        and signals["xrootd_close_stream_mutex_wait"]
    )

    if remote_close_signature:
        classification = (
            "post-event-processing-remote-file-close-hang"
            if completed_payload else "remote-file-close-hang"
        )
        family = "post-event-processing-xrootd-shutdown-hang" if completed_payload else "xrootd-shutdown-hang"
        subtype = "remote-file-close"
        phase = "process-shutdown"
        component = "ROOT/XRootD"
        confidence = "high" if completed_payload else "medium"
        summary = (
            "Event processing completed successfully and the process later hung while ROOT/XRootD was closing a remote file during process shutdown."
            if completed_payload else
            "The process was captured in a clean Python exit path while ROOT/XRootD was closing a remote file."
        )
        supporting = []
        if completed_payload:
            supporting.extend([
                "Payload reports that the EventLoop worker finished successfully.",
                "Payload reports a successful batch status with zero failures.",
                "Payload reached output-file post-processing before becoming silent.",
            ])
        supporting.append(
            "Primary thread is in Py_Exit(sts=0) -> TROOT::CloseFiles -> TNetXNGFile::Close -> XrdCl::File::Close -> StreamMutex::Lock."
        )
        if signals["xrootd_shutdown_events"]:
            supporting.append("A concurrent XRootD poller thread is in ShutdownEvents during socket close/error handling.")
        if signals["xrootd_stream_mutex_wait"]:
            supporting.append("A concurrent XRootD task thread waits in StreamMutex::Lock while running Stream::Tick.")
    elif poller_shutdown_signature:
        classification = "post-event-processing-shutdown-hang" if completed_payload else "shutdown-finalization-hang"
        family = "post-event-processing-xrootd-shutdown-hang" if completed_payload else "xrootd-shutdown-hang"
        subtype = "poller-finalization"
        phase = "process-shutdown"
        component = "XRootD/XrdCl"
        confidence = "high" if completed_payload else "medium"
        summary = (
            "Event processing completed successfully and the process later hung during XRootD/XrdCl shutdown finalization."
            if completed_payload else
            "The process was captured in a clean Python exit path while blocked during XRootD/XrdCl shutdown finalization."
        )
        supporting = []
        if signals["eventloop_worker_success"]:
            supporting.append("Payload reports that the EventLoop worker finished successfully.")
        if signals["batch_status_success"]:
            supporting.append("Payload reports a successful batch status with zero failures.")
        if signals["output_postprocessing"]:
            supporting.append("Payload reached output-file post-processing before becoming silent.")
        supporting.append("Primary thread is in Py_Exit(sts=0) -> XrdCl::DefaultEnv::Finalize -> Poller::Stop/SendCmd.")
        if signals["xrootd_stream_mutex_wait"]:
            supporting.append("A concurrent XRootD thread waits in StreamMutex::Lock while running Stream::Tick.")
        if signals["xrootd_read_timeout_force_disconnect"]:
            supporting.append("A concurrent XRootD thread handles OnReadTimeout with forced disconnect activity.")
    else:
        return {
            "available": False,
            "classification": "unclassified",
            "confidence": "low",
            "root_cause_established": False,
            "process_identity": process_identity,
            "symbol_evidence_quality": symbol_quality,
            "signals": signals,
            "reason": "No supported deterministic diagnosis rule matched the captured state.",
        }

    limitations = ["A single core snapshot does not prove the exact lock cycle."]
    if signals["xrootd_read_timeout_force_disconnect"]:
        limitations.append(
            "The concurrent XRootD read timeout/forced-disconnect path is observed, but causality is not established."
        )
    if signals["xrootd_socket_fault"]:
        limitations.append(
            "Concurrent XRootD socket fault/error handling is observed, but causality is not established."
        )
    if symbol_quality["gdb_executable_match_warning"]:
        limitations.append(
            "GDB warns that the core may not match the supplied executable; key Build IDs could not verify the executable/system-library identity."
        )
        if confidence == "high":
            confidence = "medium"
    if evidence.targeted_threads and all(
        not item.get("frame_details_available", True) for item in evidence.targeted_threads
    ):
        limitations.append("Selected XRootD frames lack usable argument/local DWARF in this optimized build.")

    return {
        "available": True,
        "classification": classification,
        "family": family,
        "subtype": subtype,
        "phase": phase,
        "component": component,
        "confidence": confidence,
        "root_cause_established": False,
        "summary": summary,
        "process_identity": process_identity,
        "symbol_evidence_quality": symbol_quality,
        "signals": signals,
        "supporting_evidence": supporting,
        "limitations": limitations,
    }

def split_thread_stacks(text: str) -> list[tuple[str, str, str]]:
    """Split ``thread apply all bt`` output into per-thread backtraces.

    Args:
        text: Output of ``thread apply all bt``.

    Returns:
        A list of ``(thread_id, thread_name, backtrace)`` tuples.
    """
    header = re.compile(r"^Thread\s+(\d+)\s+\(.*?(?:\"([^\"]*)\")?\s*\):\s*$", re.M)
    matches = list(header.finditer(text))
    stacks: list[tuple[str, str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end():end].strip()
        stacks.append((match.group(1), match.group(2) or "", body))
    return stacks


def group_thread_stacks(text: str, max_groups: int, redact_enabled: bool) -> list[ThreadGroup]:
    """Collapse identical thread backtraces into groups.

    An ATLAS/Gaudi job routinely has 100+ threads parked on the same condition
    variable. Grouping them keeps the evidence within a sane token budget and
    makes the one genuinely interesting thread stand out.

    Args:
        text: Output of ``thread apply all bt``.
        max_groups: Maximum number of groups to retain.
        redact_enabled: Whether to scrub secrets from the representative stacks.

    Returns:
        Thread groups sorted so that busy stacks appear before idle ones.
    """
    buckets: dict[str, ThreadGroup] = {}
    for thread_id, thread_name, backtrace in split_thread_stacks(text):
        signature = "\n".join(normalise_frame_line(ln) for ln in backtrace.splitlines() if ln.strip().startswith("#"))
        if not signature:
            continue
        group = buckets.get(signature)
        if group is None:
            trimmed, was_cut = truncate(redact(backtrace, redact_enabled), SECTION_LIMITS["thread_group"])
            state = _classify_thread_stack(backtrace)
            buckets[signature] = ThreadGroup(
                count=1,
                thread_ids=[thread_id],
                names=[thread_name] if thread_name else [],
                backtrace=trimmed + ("" if not was_cut else ""),
                idle=(state == "idle"),
                state=state,
            )
            continue
        group.count += 1
        if len(group.thread_ids) < 10:
            group.thread_ids.append(thread_id)
        if thread_name and thread_name not in group.names:
            group.names.append(thread_name)

    state_rank = {"blocked": 0, "active": 1, "idle": 2}
    groups = sorted(buckets.values(), key=lambda grp: (state_rank.get(grp.state, 1), -grp.count))
    return groups[:max_groups]



def derive_deterministic_observations(primary_backtrace: str,
                                      thread_groups: list[ThreadGroup]) -> list[str]:
    """Derive conservative, pattern-based observations without an LLM.

    These are intentionally factual stack-state statements, not root-cause
    claims. They make ``--no-llm`` useful while preserving the distinction
    between evidence and synthesis.
    """
    observations: list[str] = []
    all_stacks = "\n".join(group.backtrace for group in thread_groups)

    clean_python_exit = "Py_Exit (sts=0)" in primary_backtrace
    xrootd_finalize = (
        "XrdCl::DefaultEnv::Finalize" in primary_backtrace
        and "XrdCl::PostMaster::Stop" in primary_backtrace
        and "XrdSys::IOEvents::Poller::Stop" in primary_backtrace
    )
    if clean_python_exit and xrootd_finalize:
        observations.append(
            "Process is already in Py_Exit(sts=0) and is blocked while XRootD/XrdCl finalization stops the poller."
        )
    elif xrootd_finalize:
        observations.append(
            "Primary thread is blocked while XRootD/XrdCl finalization stops the poller."
        )

    remote_file_close = (
        "TROOT::CloseFiles" in primary_backtrace
        and "TNetXNGFile::Close" in primary_backtrace
        and "XrdCl::File::Close" in primary_backtrace
        and "XrdCl::StreamMutex::Lock" in primary_backtrace
    )
    if clean_python_exit and remote_file_close:
        observations.append(
            "Process is already in Py_Exit(sts=0) and is blocked while ROOT/XRootD closes a remote file."
        )

    if "XrdCl::Stream::OnReadTimeout" in all_stacks and "ForceDisconnect" in all_stacks:
        observations.append(
            "A concurrent XRootD thread is handling a read timeout and forced disconnect during the captured state."
        )
    if "XrdCl::StreamMutex::Lock" in all_stacks and "XrdCl::Stream::Tick" in all_stacks:
        observations.append(
            "Another XRootD thread is waiting in StreamMutex::Lock while processing Stream::Tick."
        )
    return observations


def _backtrace_has_unknown_frames(text: str) -> bool:
    """Return whether actual backtrace frames, rather than args/locals, lack symbols."""
    return bool(re.search(r"^#\d+\s+.*(?:\bin \?\?|\s\?\?\s*$)", text, re.M))


def summarise_shared_libraries(text: str) -> dict[str, Any]:
    """Summarise ``info sharedlibrary`` without conflating symbol states.

    GDB reports three materially different states: ``Yes`` means symbols were
    read, ``Yes (*)`` means symbols were read but full/separate debugging
    information is absent, and ``No`` means symbols were not read. Only ``No``
    belongs in ``without_symbols``. A plain ``Yes`` is not a guarantee that
    every optimized function in that DSO has recoverable arguments or locals.
    """
    total = 0
    without_symbols: list[str] = []
    without_full_debug: list[str] = []
    with_symbols_count = 0
    pattern = re.compile(
        r"^\s*0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+\s+(Yes(?:\s+\(\*\))?|No)\s+(.+?)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        status, path = match.groups()
        if not path.startswith("/"):
            continue
        total += 1
        if status == "No":
            if len(without_symbols) < 40:
                without_symbols.append(path)
        elif "(*)" in status:
            with_symbols_count += 1
            if len(without_full_debug) < 40:
                without_full_debug.append(path)
        else:
            with_symbols_count += 1
    return {
        "total_loaded": total,
        "with_symbols_count": with_symbols_count,
        "without_symbols": without_symbols,
        "without_symbols_count": len(without_symbols),
        "without_full_debug_info": without_full_debug,
        "without_full_debug_info_count": len(without_full_debug),
    }


def detect_mode(requested: str, signal: str | None, generated_by: str | None) -> tuple[str, str]:
    """Classify the dump as a crash or a hang snapshot.

    Args:
        requested: The user's ``--mode`` value.
        signal: The terminating signal, if known.
        generated_by: The recorded command line, if known.

    Returns:
        A tuple of the resolved mode and a short explanation of how it was set.
    """
    if requested in ("crash", "hang"):
        return requested, "explicitly supplied via --mode"
    if signal in CRASH_SIGNALS:
        return "crash", f"inferred from fault signal {signal}"
    if signal in HANG_SIGNALS:
        return "hang", f"inferred from signal {signal}, which is normally externally delivered"
    if generated_by and "gcore" in generated_by:
        return "hang", "inferred from a gcore-generated snapshot"
    return "hang", "no fault signal found; defaulting to hang analysis"


# --------------------------------------------------------------------------- #
# Evidence assembly
# --------------------------------------------------------------------------- #


def _build_phase_plan(args: argparse.Namespace) -> list[tuple[str, list[tuple[str, str]]]]:
    """Build the ordered list of gdb phases to execute.

    Args:
        args: Parsed command-line arguments.

    Returns:
        A list of ``(phase_name, [(section_name, gdb_command), ...])`` tuples.
    """
    primary: list[tuple[str, str]] = [
        ("backtrace", f"bt {args.max_frames}"),
        ("frame", "info frame"),
        ("args", "info args"),
    ]
    if args.locals:
        primary.append(("locals", "info locals"))
    primary.append(("registers", "info registers"))
    return [
        ("metadata", [
            ("program", "info program"),
            ("threads", "info threads"),
            ("files", "info files"),
            ("debug_file_directory", "show debug-file-directory"),
            ("auto_load_python_scripts", "info auto-load python-scripts"),
        ]),
        ("primary_thread", primary),
        ("all_threads", [("all_threads", f"thread apply all bt {args.max_frames}")]),
        ("python", [("py_bt", "py-bt"), ("py_list", "py-list")]),
        ("libraries", [("libraries", "info sharedlibrary")]),
    ]


def _trim_primary_sections(sections: dict[str, str], redact_enabled: bool) -> tuple[dict[str, str], list[str]]:
    """Redact and size-limit the primary-thread sections.

    Args:
        sections: Raw per-command output keyed by section name.
        redact_enabled: Whether to scrub secrets.

    Returns:
        A tuple of the trimmed sections and the names of any that were truncated.
    """
    trimmed: dict[str, str] = {}
    truncated: list[str] = []
    for name in ("backtrace", "frame", "args", "locals", "registers"):
        body = sections.get(name, "").strip()
        if not body:
            continue
        body, was_cut = truncate(redact(body, redact_enabled), SECTION_LIMITS.get(name, 6_000))
        trimmed[name] = body
        if was_cut:
            truncated.append(f"primary_thread.{name}")
    return trimmed, truncated


def _collect_evidence_local(
    args: argparse.Namespace, progress: bool = True, detail: bool = False,
) -> tuple[CoreEvidence, str]:
    """Drive gdb and assemble the structured evidence bundle.

    Args:
        args: Parsed command-line arguments.
        progress: Whether to print basic phase-level progress to stderr. gdb
            buffers all output of a phase until it exits, so without this a
            large core can appear to hang with no indication anything is
            happening.
        detail: Whether to also print periodic heartbeat messages while a
            phase is running, and note when a phase's evidence gets trimmed
            to fit the budget. Has no effect if ``progress`` is ``False``.

    Returns:
        A tuple of the :class:`CoreEvidence` and the concatenated raw gdb output.

    Raises:
        FileNotFoundError: If the core file or gdb cannot be found.
    """
    core_path = Path(args.core_file).expanduser().resolve()
    if not core_path.is_file():
        raise FileNotFoundError(f"Core file not found: {core_path}")

    gdb_path = find_gdb(args.gdb)
    evidence = CoreEvidence()
    evidence.environment = collect_runtime_environment()
    stat = core_path.stat()
    size_mib = stat.st_size / (1024 ** 2)
    evidence.core_file = {
        "path": str(core_path),
        "size_bytes": stat.st_size,
        "size_human": f"{size_mib:.1f} MiB",
        "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stat.st_mtime)),
    }
    evidence.gdb = {"path": gdb_path, "version": gdb_version(gdb_path)}

    warning_threshold = getattr(args, "large_core_warning_mib", DEFAULT_LARGE_CORE_WARNING_MIB)
    if progress:
        print(f"[*] Core file: {core_path.name} ({size_mib:.1f} MiB), gdb {evidence.gdb['version']}",
              file=sys.stderr)
        if warning_threshold and size_mib >= warning_threshold:
            print(
                f"[*] This core is above {warning_threshold} MiB. gdb reloads the whole core once per "
                "analysis phase, so each of the phases below can take from several seconds to a few "
                "minutes on a core this size -- that is expected, not a hang. Pass -v for a periodic "
                "'still running' heartbeat during long phases.",
                file=sys.stderr,
            )
        print("[*] Resolving executable...", file=sys.stderr)

    heartbeat_interval = getattr(args, "heartbeat_interval", DEFAULT_HEARTBEAT_INTERVAL)
    probe = run_gdb_phase(
        gdb_path, core_path, None, "probe", [("program", "info program")], args.gdb_timeout,
        progress=progress, detail=detail, heartbeat_interval=heartbeat_interval,
    )
    evidence.executable = resolve_executable(
        gdb_path, core_path, args.exe, probe.stdout + probe.stderr, args.gdb_timeout,
        progress=progress, detail=detail, heartbeat_interval=heartbeat_interval,
    )
    exe_path = evidence.executable.get("path")
    if progress:
        print(f"[*] Executable: {exe_path or 'UNRESOLVED'} (via {evidence.executable['source']})", file=sys.stderr)

    evidence.build_ids, unstrip_raw = collect_build_id_evidence(core_path, exe_path)
    if not evidence.build_ids.get("available"):
        evidence.warnings.append(
            "Build-ID comparison was not available; executable/system-library identity was not verified."
        )
    elif not evidence.build_ids.get("checked"):
        evidence.warnings.append(
            f"Build-ID coverage is insufficient: eu-unstrip enumerated {evidence.build_ids.get('module_count', 0)} module(s), "
            "but no executable or critical system-library Build IDs could be verified."
        )
    for item in evidence.build_ids.get("checked", []):
        if item.get("match") is False:
            evidence.warnings.append(
                f"Build-ID mismatch for {item.get('name')}: core {item.get('core_build_id')} vs "
                f"analysis file {item.get('file_build_id')}. Stack unwinding/symbols may be misleading."
            )

    raw_chunks: list[str] = [f"$ gdb -c {core_path.name} -ex 'info program'\n{probe.stdout}\n{probe.stderr}"]
    if unstrip_raw:
        raw_chunks.append(f"\n{'=' * 70}\n# eu-unstrip -n --core {core_path.name}\n{'=' * 70}\n{unstrip_raw}")
    sections: dict[str, str] = {}
    errors: dict[str, str] = {}
    for name, commands in _build_phase_plan(args):
        result = run_gdb_phase(
            gdb_path, core_path, exe_path, name, commands, args.gdb_timeout,
            progress=progress, detail=detail, heartbeat_interval=heartbeat_interval,
        )
        sections.update(result.sections)
        errors[name] = result.stderr
        banner = "=" * 70
        rendered = "; ".join(cmd for _, cmd in commands)
        raw_chunks.append(
            f"\n{banner}\n# phase: {name} ({rendered})\n{banner}\n{result.stdout}\n{result.stderr}"
        )
        evidence.phases.append({
            "name": result.name,
            "commands": result.commands,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_s": result.duration_s,
            "stderr_excerpt": redact(result.stderr[:500], not args.no_redact),
        })
        if result.timed_out:
            evidence.warnings.append(
                f"gdb phase '{name}' timed out after {args.gdb_timeout}s; its evidence is missing."
            )

    # Select interesting thread/frame pairs only after the all-thread phase has
    # established the shape of the hang.  All focused inspections run in one
    # additional gdb process so large cores are reloaded only once more.
    evidence.thread_groups = group_thread_stacks(
        sections.get("all_threads", ""), args.max_thread_groups, not args.no_redact
    )
    targets = select_targeted_threads(
        evidence.thread_groups, getattr(args, "max_targeted_threads", DEFAULT_MAX_TARGETED_THREADS)
    )
    if targets:
        commands = _build_targeted_phase(targets, args.locals)
        result = run_gdb_phase(
            gdb_path, core_path, exe_path, "targeted_threads", commands, args.gdb_timeout,
            progress=progress, detail=detail, heartbeat_interval=heartbeat_interval,
        )
        sections.update(result.sections)
        errors["targeted_threads"] = result.stderr
        banner = "=" * 70
        rendered = "; ".join(cmd for _, cmd in commands)
        raw_chunks.append(
            f"\n{banner}\n# phase: targeted_threads ({rendered})\n{banner}\n{result.stdout}\n{result.stderr}"
        )
        evidence.phases.append({
            "name": result.name,
            "commands": result.commands,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "duration_s": result.duration_s,
            "stderr_excerpt": redact(result.stderr[:500], not args.no_redact),
        })
        if result.timed_out:
            evidence.warnings.append(
                f"gdb phase 'targeted_threads' timed out after {args.gdb_timeout}s; focused frame evidence is missing."
            )
        else:
            evidence.targeted_threads = summarise_targeted_threads(
                targets, result.sections, not args.no_redact
            )

    combined = "\n".join(raw_chunks)
    evidence.signal = parse_signal(combined)
    evidence.generated_by = redact(parse_generated_by(combined) or "", not args.no_redact) or None
    evidence.thread_count = parse_thread_count(sections.get("threads", ""))
    evidence.warnings.extend(w for w in collect_warnings(combined) if w not in evidence.warnings)
    evidence.warnings.extend(evidence.executable.get("notes", []))
    evidence.mode, evidence.mode_source = detect_mode(args.mode, evidence.signal, evidence.generated_by)

    primary, truncated = _trim_primary_sections(sections, not args.no_redact)
    evidence.primary_thread = primary
    evidence.truncated_sections.extend(truncated)
    evidence.observations = derive_deterministic_observations(
        primary.get("backtrace", ""), evidence.thread_groups
    )
    if _backtrace_has_unknown_frames(
        sections.get("backtrace", "") + "\n" + sections.get("all_threads", "")
    ):
        evidence.warnings.append("Some backtrace frames have no symbol information.")
    evidence.python = _summarise_python(
        sections.get("py_bt", ""), sections.get("py_list", ""), errors.get("python", ""), not args.no_redact
    )
    evidence.shared_libraries = summarise_shared_libraries(sections.get("libraries", ""))
    missing_library_symbols = evidence.shared_libraries.get("without_symbols_count", 0)
    if missing_library_symbols:
        evidence.warnings.append(
            f"GDB could not read symbols for {missing_library_symbols} loaded shared librar"
            f"{'y' if missing_library_symbols == 1 else 'ies'}."
        )
    files_excerpt, files_cut = truncate(
        redact(sections.get("files", ""), not args.no_redact), 4_000
    )
    evidence.gdb_metadata = {
        "debug_file_directory": redact(sections.get("debug_file_directory", ""), not args.no_redact),
        "auto_load_python_scripts": redact(sections.get("auto_load_python_scripts", ""), not args.no_redact),
        "info_files_excerpt": files_excerpt,
        "info_files_truncated": files_cut,
        "startup_warnings": list(dict.fromkeys(
            redact(line.strip(), not args.no_redact)
            for line in combined.splitlines()
            if "warning:" in line.lower()
        ))[:20],
    }
    return evidence, combined


def core_evidence_from_dict(payload: dict[str, Any]) -> CoreEvidence:
    """Reconstruct :class:`CoreEvidence` from a JSON-serialised dictionary.

    Older evidence bundles only carried the boolean ``idle`` field. Preserve
    their meaning when loading them after the additive ``state`` field was
    introduced in 0.2.1.
    """
    data = dict(payload)
    groups: list[ThreadGroup] = []
    for raw_group in data.get("thread_groups", []):
        group = dict(raw_group)
        if "state" not in group:
            group["state"] = "idle" if group.get("idle") else "active"
        groups.append(ThreadGroup(**group))
    data["thread_groups"] = groups
    allowed = set(CoreEvidence.__dataclass_fields__)
    return CoreEvidence(**{key: value for key, value in data.items() if key in allowed})


def _container_path(host_path: Path, job_dir: Path) -> str:
    """Translate a path under the job directory to its standard ``/srv`` mount."""
    try:
        rel = host_path.resolve().relative_to(job_dir.resolve())
    except ValueError as exc:
        raise RuntimeError(
            f"Path {host_path} is outside --job-dir {job_dir}. The ATLAS container backend currently "
            "requires the core and release setup to live under the job directory mounted at /srv."
        ) from exc
    return "/srv" if str(rel) == "." else f"/srv/{rel.as_posix()}"


def _container_worker_args(args: argparse.Namespace, core_in_container: str,
                           worker_in_container: str, json_in_container: str,
                           raw_in_container: str, job_dir: Path) -> list[str]:
    """Build the evidence-only analyzer command executed inside the container."""
    argv = [
        "python3", worker_in_container, core_in_container,
        "--execution", "local",
        "--mode", args.mode,
        "--max-frames", str(args.max_frames),
        "--max-thread-groups", str(args.max_thread_groups),
        "--max-targeted-threads", str(getattr(args, "max_targeted_threads", DEFAULT_MAX_TARGETED_THREADS)),
        "--max-evidence-chars", str(args.max_evidence_chars),
        "--gdb-timeout", str(args.gdb_timeout),
        "--heartbeat-interval", str(getattr(args, "heartbeat_interval", DEFAULT_HEARTBEAT_INTERVAL)),
        "--large-core-warning-mib", "0",
        "--no-llm",
        "--json", json_in_container,
        "--raw-gdb", raw_in_container,
        "--quiet",
    ]
    if not args.locals:
        argv.append("--no-locals")
    if args.no_redact:
        argv.append("--no-redact")
    if args.exe:
        exe = Path(args.exe).expanduser()
        if exe.is_absolute() and exe.exists():
            try:
                exe_arg = _container_path(exe, job_dir)
            except RuntimeError:
                exe_arg = str(exe)
        else:
            exe_arg = args.exe
        argv += ["--exe", exe_arg]
    if args.gdb:
        argv += ["--gdb", args.gdb]
    return argv


def _collect_evidence_atlas_container(
    args: argparse.Namespace, progress: bool = True, detail: bool = False,
) -> tuple[CoreEvidence, str]:
    """Run the deterministic collector once inside an ATLAS AlmaLinux container.

    The original PanDA ``container_script.sh`` is intentionally not executed.
    Instead, ``atlasLocalSetup.sh`` sets up the requested container and release,
    then runs an analyzer-owned worker that invokes this script in evidence-only
    local mode. LLM synthesis remains in the host process.
    """
    core_path = Path(args.core_file).expanduser().resolve()
    if not core_path.is_file():
        raise FileNotFoundError(f"Core file not found: {core_path}")
    job_dir = Path(getattr(args, "job_dir", None) or core_path.parent).expanduser().resolve()
    if not job_dir.is_dir():
        raise FileNotFoundError(f"Job directory not found: {job_dir}")
    core_in_container = _container_path(core_path, job_dir)

    release_value = getattr(args, "release_setup", None)
    release_setup = Path(release_value).expanduser().resolve() if release_value else job_dir / "my_release_setup.sh"
    if not release_setup.is_file():
        raise FileNotFoundError(
            f"Release setup not found: {release_setup}. Pass --release-setup or place my_release_setup.sh in --job-dir."
        )
    release_in_container = _container_path(release_setup, job_dir)

    alrb = Path(getattr(args, "atlas_local_root_base", DEFAULT_ATLAS_LOCAL_ROOT_BASE)).expanduser().resolve()
    atlas_setup = alrb / "user" / "atlasLocalSetup.sh"
    if not atlas_setup.is_file():
        raise FileNotFoundError(f"ATLAS Local Root Base setup not found: {atlas_setup}")

    created: list[Path] = []
    try:
        worker_fd, worker_name = tempfile.mkstemp(prefix=".core_dump_analyzer_worker_", suffix=".py", dir=job_dir)
        os.close(worker_fd)
        worker_path = Path(worker_name)
        shutil.copy2(Path(__file__).resolve(), worker_path)
        created.append(worker_path)

        json_fd, json_name = tempfile.mkstemp(prefix=".core_dump_analyzer_evidence_", suffix=".json", dir=job_dir)
        os.close(json_fd)
        json_path = Path(json_name)
        created.append(json_path)

        raw_fd, raw_name = tempfile.mkstemp(prefix=".core_dump_analyzer_gdb_", suffix=".txt", dir=job_dir)
        os.close(raw_fd)
        raw_path = Path(raw_name)
        created.append(raw_path)

        runner_fd, runner_name = tempfile.mkstemp(prefix=".core_dump_analyzer_runner_", suffix=".sh", dir=job_dir)
        os.close(runner_fd)
        runner_path = Path(runner_name)
        created.append(runner_path)

        worker_in_container = _container_path(worker_path, job_dir)
        json_in_container = _container_path(json_path, job_dir)
        raw_in_container = _container_path(raw_path, job_dir)
        runner_in_container = _container_path(runner_path, job_dir)
        worker_argv = _container_worker_args(
            args, core_in_container, worker_in_container, json_in_container, raw_in_container, job_dir
        )
        runner_path.write_text(
            "#!/bin/bash\nset -euo pipefail\nexec " + shlex.join(worker_argv) + "\n",
            encoding="utf-8",
        )
        runner_path.chmod(0o700)

        platform = getattr(args, "atlas_platform", DEFAULT_ATLAS_PLATFORM)
        extra_args = getattr(args, "container_extra_args", "-c -i")
        source_cmd = (
            f"export ATLAS_LOCAL_ROOT_BASE={shlex.quote(str(alrb))}; "
            f"source {shlex.quote(str(atlas_setup))} "
            f"-c {shlex.quote(platform)} "
            f"-s {shlex.quote(release_in_container)} "
            f"-r {shlex.quote(runner_in_container)} "
            f"-e {shlex.quote(extra_args)}"
        )
        if progress:
            print(f"[*] ATLAS container analysis starting ({platform}, job dir {job_dir})...", file=sys.stderr)
        started = time.monotonic()
        stop_event = threading.Event()
        heartbeat_thread: threading.Thread | None = None
        if progress and detail:
            heartbeat_thread = threading.Thread(
                target=_report_heartbeat,
                args=("atlas-container", started, stop_event,
                      getattr(args, "heartbeat_interval", DEFAULT_HEARTBEAT_INTERVAL)),
                daemon=True,
            )
            heartbeat_thread.start()
        try:
            proc = subprocess.run(
                ["bash", "-lc", source_cmd], cwd=job_dir, capture_output=True, text=True, check=False,
                timeout=getattr(args, "container_timeout", DEFAULT_CONTAINER_TIMEOUT),
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"ATLAS container analysis timed out after "
                f"{getattr(args, 'container_timeout', DEFAULT_CONTAINER_TIMEOUT)}s"
            ) from exc
        finally:
            stop_event.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=1.0)
        if progress:
            print(f"[*] ATLAS container analysis completed in {time.monotonic() - started:.1f}s", file=sys.stderr)

        if proc.returncode != 0 or not json_path.stat().st_size:
            diagnostics = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            diagnostics = diagnostics[-6000:]
            raise RuntimeError(
                f"ATLAS container evidence collector failed with exit code {proc.returncode}.\n{diagnostics}"
            )

        payload = json.loads(json_path.read_text(encoding="utf-8"))
        evidence = core_evidence_from_dict(payload["evidence"])
        evidence.environment["execution_backend"] = "atlas-container"
        evidence.environment["atlas_platform"] = platform
        evidence.environment["release_setup"] = str(release_setup)
        evidence.environment["job_dir"] = str(job_dir)
        evidence.core_file["container_path"] = core_in_container
        evidence.core_file["path"] = str(core_path)
        raw = raw_path.read_text(encoding="utf-8", errors="replace") if raw_path.exists() else ""
        return evidence, raw
    finally:
        if not getattr(args, "keep_container_artifacts", False):
            for path in created:
                try:
                    path.unlink()
                except OSError:
                    pass


def collect_evidence(
    args: argparse.Namespace, progress: bool = True, detail: bool = False,
) -> tuple[CoreEvidence, str]:
    """Collect core evidence, then optionally correlate bounded payload/job logs on the host."""
    execution = getattr(args, "execution", "local")
    if execution == "atlas-container":
        evidence, raw = _collect_evidence_atlas_container(args, progress=progress, detail=detail)
    else:
        evidence, raw = _collect_evidence_local(args, progress=progress, detail=detail)

    job_dir_value = getattr(args, "job_dir", None)
    collect_logs = getattr(args, "collect_job_logs", True)
    # The in-container worker is a local backend with no --job-dir, so it never
    # recursively scans logs. Correlation happens once, on the host, after the
    # matching-environment core evidence has been returned.
    if collect_logs and job_dir_value:
        job_dir = Path(job_dir_value).expanduser().resolve()
        if job_dir.is_dir():
            evidence.job_logs = collect_job_log_evidence(
                job_dir,
                explicit=getattr(args, "job_log", None),
                max_files=getattr(args, "max_job_log_files", DEFAULT_MAX_JOB_LOG_FILES),
                max_matches=getattr(args, "max_job_log_matches", DEFAULT_MAX_JOB_LOG_MATCHES),
                tail_lines=getattr(args, "job_log_tail_lines", DEFAULT_JOB_LOG_TAIL_LINES),
                redact_enabled=not args.no_redact,
                core_mtime=Path(args.core_file).expanduser().resolve().stat().st_mtime
                if Path(args.core_file).expanduser().resolve().is_file() else None,
                failure_mode=evidence.mode,
            )
            activity = evidence.job_logs.get("payload_activity", {})
            silence = activity.get("last_write_before_core_s")
            if isinstance(silence, (int, float)) and silence >= 300:
                observation = (
                    f"{activity.get('latest_payload_file', 'Payload log')} was last modified "
                    f"{activity.get('last_write_before_core_human', _format_duration(float(silence)))} before the core capture"
                )
                last_line = activity.get("last_nonempty_line")
                if isinstance(last_line, dict) and last_line.get("text"):
                    observation += f"; its last non-empty line was: {last_line['text']}"
                latest_progress = activity.get("latest_progress")
                if (isinstance(latest_progress, dict) and latest_progress.get("text")
                        and (not isinstance(last_line, dict) or latest_progress.get("line") != last_line.get("line"))):
                    observation += f"; latest retained progress: {latest_progress['text']}"
                evidence.observations.append(observation + ".")
            for item in derive_payload_log_observations(
                evidence.job_logs, evidence.primary_thread.get("backtrace", "")
            ):
                if item not in evidence.observations:
                    evidence.observations.append(item)
            if progress and evidence.job_logs.get("available"):
                print(
                    f"[*] Payload/job-log correlation: {len(evidence.job_logs.get('files', []))} file(s), "
                    f"{len(evidence.job_logs.get('matches', []))} relevant line(s)",
                    file=sys.stderr,
                )
    evidence.process_identity = derive_process_identity(evidence)
    evidence.diagnosis = derive_structured_diagnosis(evidence)
    return evidence, raw


def _summarise_python(text: str, source: str, stderr: str, redact_enabled: bool) -> dict[str, Any]:
    """Interpret the output of the ``py-bt`` / ``py-list`` phase.

    Detection is positive rather than negative: real ``py-bt`` output always
    contains a Python traceback header or a ``File "..."`` frame. gdb reports an
    unavailable command on stderr, so that stream must be inspected too.

    Args:
        text: Output of ``py-bt``.
        source: Output of ``py-list``.
        stderr: Standard error of the Python phase.
        redact_enabled: Whether to scrub secrets.

    Returns:
        A dictionary describing whether Python frames were available and, if so,
        the Python-level backtrace and surrounding source.
    """
    if "Undefined command" in stderr or "Undefined command" in text:
        return {
            "available": False,
            "reason": ("py-bt is not available because the libpython/CPython GDB helper (python-gdb.py) is not loaded. "
                       "This is separate from native Python symbol availability or full DWARF debug information."),
        }
    has_frames = bool(
        re.search(r"Traceback \(most recent call first\)", text)
        or re.search(r'^\s*File "[^"]+", line \d+, in ', text, re.M)
    )
    if not has_frames:
        return {"available": False, "reason": "py-bt produced no Python frames; this is likely not a Python process."}

    backtrace, _ = truncate(redact(text.strip(), redact_enabled), SECTION_LIMITS["python_backtrace"])
    context, _ = truncate(redact(source.strip(), redact_enabled), SECTION_LIMITS["python_source"])
    return {"available": True, "backtrace": backtrace, "source_context": context}


def _serialized_size(evidence: CoreEvidence) -> int:
    """Return the character length of the evidence exactly as sent to the LLM.

    Uses the same ``indent=2`` formatting as :func:`build_user_prompt` so this
    is a faithful stand-in for the size of the real prompt, not just a proxy.

    Args:
        evidence: The assembled evidence.

    Returns:
        Length in characters of the JSON-serialised evidence.
    """
    return len(json.dumps(evidence.to_dict(), indent=2, default=str))


def _shrink_shared_libraries(evidence: CoreEvidence) -> bool:
    """Halve the list of symbol-less shared libraries, if any remain.

    Args:
        evidence: The assembled evidence, mutated in place.

    Returns:
        ``True`` if the list was shrunk, ``False`` if it was already empty.
    """
    libraries = evidence.shared_libraries.get("without_symbols") or []
    if not libraries:
        return False
    evidence.shared_libraries["without_symbols"] = libraries[: len(libraries) // 2]
    if "shared_libraries.without_symbols" not in evidence.truncated_sections:
        evidence.truncated_sections.append("shared_libraries.without_symbols")
    return True


def _pop_thread_group(evidence: CoreEvidence) -> bool:
    """Drop the least interesting remaining thread group.

    Groups are already sorted busy-before-idle (see :func:`group_thread_stacks`),
    so this always removes an idle group before a busy one, and always leaves
    at least one group so the model has *some* thread evidence.

    Args:
        evidence: The assembled evidence, mutated in place.

    Returns:
        ``True`` if a group was dropped, ``False`` if only one group remains.
    """
    if len(evidence.thread_groups) <= 1:
        return False
    evidence.thread_groups.pop()
    if "thread_groups" not in evidence.truncated_sections:
        evidence.truncated_sections.append("thread_groups")
    return True


def _drop_python_source(evidence: CoreEvidence) -> bool:
    """Remove the ``py-list`` source context, keeping the ``py-bt`` traceback.

    Args:
        evidence: The assembled evidence, mutated in place.

    Returns:
        ``True`` if source context was present and dropped, ``False`` otherwise.
    """
    if not evidence.python.get("source"):
        return False
    evidence.python["source"] = ""
    if "python.source" not in evidence.truncated_sections:
        evidence.truncated_sections.append("python.source")
    return True


def _shrink_text_field(
    container: dict[str, str], key: str, label: str, evidence: CoreEvidence, floor: int = 500,
) -> bool:
    """Halve a text field toward a floor, keeping head and tail.

    ``truncate()`` can never produce text shorter than ``limit + len(marker)``,
    since the marker itself is always inserted. The stopping condition compares
    against that true minimum rather than the bare floor, so this reliably
    terminates instead of "succeeding" forever at a length it can never reduce
    further -- which would hang :func:`enforce_global_budget` in an infinite
    loop on any evidence still over budget once a field reaches its floor.

    Args:
        container: The dict holding the field, e.g. ``evidence.primary_thread``.
        key: The key within ``container`` to shrink.
        label: Name recorded in ``evidence.truncated_sections`` when shrunk.
        evidence: The evidence bundle, for recording that truncation happened.
        floor: Minimum length to shrink toward; returns ``False`` once reached.

    Returns:
        ``True`` if the field was shrunk, ``False`` if absent or already at
        the floor.
    """
    body = container.get(key, "")
    min_len = floor + len(TRUNCATION_MARKER)
    if len(body) <= min_len:
        return False
    trimmed, _ = truncate(body, max(floor, len(body) // 2))
    container[key] = trimmed
    if label not in evidence.truncated_sections:
        evidence.truncated_sections.append(label)
    return True


def enforce_global_budget(evidence: CoreEvidence, limit: int, detail: bool = False) -> CoreEvidence:
    """Shrink the evidence bundle to fit a character budget for the LLM prompt.

    Applies a cascade of reduction stages, cheapest evidence first, moving to
    the next stage only once the current one stops helping (e.g. thread groups
    are down to one, or a text field has hit its floor). This exists because
    per-section limits (:data:`SECTION_LIMITS`) cap each field individually,
    but do not cap the bundle as a whole -- a job with both a huge ``locals``
    dump and many distinct thread stacks could previously exceed ``limit`` even
    after every thread group but one had been dropped.

    Stage order (least to most valuable evidence):
        1. ``shared_libraries.without_symbols``
        2. ``thread_groups`` (idle groups first, per their existing sort)
        3. ``python.source``
        4. ``primary_thread.locals``
        5. ``primary_thread.registers``
        6. ``primary_thread.args``
        7. ``python.backtrace``
        8. ``primary_thread.backtrace`` (last resort)

    Args:
        evidence: The assembled evidence.
        limit: Maximum total serialised size in characters.
        detail: Whether to log which sections were trimmed to stderr.

    Returns:
        The supplied evidence object, mutated to fit within ``limit`` wherever the
        cascade was able to. Callers should pass a disposable/deep-copied LLM input,
        never the canonical evidence artifact. See ``evidence.warnings`` for whether it fully
        succeeded.
    """
    stages: list[tuple[str, Callable[[], bool]]] = [
        ("shared_libraries.without_symbols", lambda: _shrink_shared_libraries(evidence)),
        ("thread_groups", lambda: _pop_thread_group(evidence)),
        ("python.source", lambda: _drop_python_source(evidence)),
        ("primary_thread.locals",
         lambda: _shrink_text_field(evidence.primary_thread, "locals", "primary_thread.locals", evidence)),
        ("primary_thread.registers",
         lambda: _shrink_text_field(evidence.primary_thread, "registers", "primary_thread.registers", evidence)),
        ("primary_thread.args",
         lambda: _shrink_text_field(evidence.primary_thread, "args", "primary_thread.args", evidence)),
        ("python.backtrace",
         lambda: _shrink_text_field(evidence.python, "backtrace", "python.backtrace", evidence)),
        ("primary_thread.backtrace",
         lambda: _shrink_text_field(
             evidence.primary_thread, "backtrace", "primary_thread.backtrace", evidence, floor=1000)),
    ]

    stage_index = 0
    while _serialized_size(evidence) > limit and stage_index < len(stages):
        _, shrink = stages[stage_index]
        if not shrink():
            stage_index += 1

    if _serialized_size(evidence) > limit:
        evidence.warnings.append(
            f"Evidence remains above the {limit}-character budget even after all reduction stages; "
            "sending it as-is. Consider raising --max-evidence-chars or lowering --max-thread-groups."
        )
    if detail and evidence.truncated_sections:
        print(
            f"[*] Evidence trimmed to fit the {limit}-character budget: {', '.join(evidence.truncated_sections)}",
            file=sys.stderr,
        )
    return evidence


# --------------------------------------------------------------------------- #
# LLM synthesis
# --------------------------------------------------------------------------- #

SYSTEM_PROMPT_BASE = """You are an expert in post-mortem debugging of large C++ and Python \
scientific applications, specifically ATLAS/Athena jobs running on distributed grid computing \
infrastructure.

You will be given structured evidence extracted from a core dump using gdb. Your audience is a \
computing operations shifter or a physicist who submitted the job. They do not read gdb output and \
do not care about frame numbers, register values or mangled symbol names. Translate, do not transcribe.

Hard rules:
- Never invent stack frames, function names, file names or line numbers. Use only what appears in the evidence.
- If symbols are missing, the core is truncated, or the executable did not resolve, say so FIRST and \
lower your confidence accordingly. A confident wrong answer is worse than an honest "insufficient evidence".
- Distinguish clearly between application code (Athena algorithms, physics code, user Python) and \
framework or system noise (TBB, GaudiHive, libc, pthread, the Python interpreter loop). The interesting \
frame is almost always the deepest one belonging to application code.
- A top frame in pthread_cond_wait, futex or epoll does not by itself make a thread irrelevant. Inspect deeper \
frames: a thread blocked while stopping a subsystem, acquiring a lock, handling a timeout, or finalizing can be \
central to a hang. Treat only genuinely parked worker-loop stacks as idle.
"""

SYSTEM_PROMPT_CRASH = """
This dump is being analysed as a CRASH. Focus on: the faulting thread, the signal, the faulting frame, \
the likely memory error (null dereference, use-after-free, buffer overrun, bad cast, stack exhaustion, \
uncaught C++ exception leading to abort), and which component owns the bug.
"""

SYSTEM_PROMPT_HANG = """
This dump is being analysed as a HANG or LOOPING JOB. The core was most likely produced deliberately by \
the pilot or a watchdog after the job exceeded its wall-clock or looping-job time limit, so there is no \
"crash" to explain.

Focus instead on: which thread is actually doing work, what that work is, and why it is not finishing. \
Look specifically for infinite or very slow loops, unbounded I/O waits, deadlocks (two threads each \
blocked on a lock the other holds), lock convoys, pathological allocation or garbage-collection behaviour, \
and a single-threaded bottleneck while the rest of the pool is idle. If a Python backtrace is present it is \
usually the most informative evidence available; lead with it.
"""

RESPONSE_SCHEMA = """
Return ONLY a JSON object, with no preamble, commentary or Markdown fences. Use exactly these keys:

{
  "verdict": "one sentence, plain language, what happened",
  "classification": "crash" | "hang" | "deadlock" | "resource_exhaustion" | "undetermined",
  "confidence": "high" | "medium" | "low",
  "confidence_reason": "one sentence on what limits or supports your confidence",
  "likely_cause": "2-4 sentences explaining the most probable cause in plain language",
  "supporting_evidence": ["specific frames or observations from the evidence that support the verdict"],
  "culprit_component": "the software component or package most likely responsible, or 'unknown'",
  "busy_threads": "short description of what the non-idle threads were doing",
  "limitations": ["anything that weakened this analysis, e.g. missing symbols, truncated core"],
  "next_steps": ["concrete, ordered actions the operator or job owner should take"],
  "explanation": "a longer plain-language narrative, 1-3 short paragraphs, safe to show a non-expert"
}
"""


def build_system_prompt(mode: str) -> str:
    """Assemble the system prompt for the requested analysis mode.

    Args:
        mode: Either ``"crash"`` or ``"hang"``.

    Returns:
        The full system prompt text.
    """
    specific = SYSTEM_PROMPT_CRASH if mode == "crash" else SYSTEM_PROMPT_HANG
    return SYSTEM_PROMPT_BASE + specific + RESPONSE_SCHEMA


def build_user_prompt(evidence: CoreEvidence) -> str:
    """Render the evidence bundle into the user message.

    Args:
        evidence: The assembled evidence.

    Returns:
        The user message text.
    """
    return (
        "Here is the gdb evidence extracted from the core dump. Analyse it and respond with the "
        "JSON object described in your instructions.\n\n"
        f"```json\n{json.dumps(evidence.to_dict(), indent=2, default=str)}\n```"
    )


def extract_json_object(text: str) -> dict[str, Any] | None:
    """Parse a JSON object out of a model response.

    Args:
        text: The raw model response, possibly wrapped in Markdown fences.

    Returns:
        The parsed object, or ``None`` if no valid JSON object was found.
    """
    cleaned = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(cleaned[start:end + 1])
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _cap_user_prompt(prompt: str, max_evidence_chars: int, evidence: CoreEvidence) -> str:
    """Apply a hard, last-resort ceiling to the rendered user prompt.

    :func:`enforce_global_budget` should already have brought the evidence
    under ``max_evidence_chars`` before this is ever called. This is a second,
    independent check applied to the actual prompt text right before it goes
    over the wire: defense-in-depth so that a future evidence field, or a call
    site that forgets to run the budget pass, can never send an unbounded (and
    unboundedly expensive) prompt to the API.

    Args:
        prompt: The fully rendered user message.
        max_evidence_chars: The evidence budget the caller intended to enforce.
        evidence: The evidence bundle, so a warning can be recorded if this
            cap actually had to do something.

    Returns:
        ``prompt``, unchanged if already within the hard cap, otherwise
        truncated to it.
    """
    hard_cap = max_evidence_chars * HARD_CAP_MULTIPLIER
    if len(prompt) <= hard_cap:
        return prompt
    evidence.warnings.append(
        f"The rendered LLM prompt ({len(prompt):,} chars) exceeded the hard {hard_cap:,}-char cost cap "
        f"({HARD_CAP_MULTIPLIER}x --max-evidence-chars) even after evidence reduction, and was truncated "
        "before being sent. This should not normally happen; if it does routinely, lower "
        "--max-thread-groups or investigate what is making the evidence so large."
    )
    capped, _ = truncate(prompt, hard_cap, marker="\n... [TRUNCATED FOR COST PROTECTION] ...")
    return capped


def analyze_with_llm(
    evidence: CoreEvidence,
    model: str,
    max_tokens: int,
    max_evidence_chars: int = DEFAULT_MAX_EVIDENCE_CHARS,
    progress: bool = True,
    detail: bool = False,
) -> dict[str, Any]:
    """Send the evidence to the Anthropic API and parse the structured verdict.

    Args:
        evidence: The assembled evidence.
        model: Anthropic model identifier.
        max_tokens: Maximum tokens for the response.
        max_evidence_chars: The evidence budget already applied by
            :func:`enforce_global_budget`, reused here to derive a hard cost
            ceiling on the actual outgoing prompt (see :func:`_cap_user_prompt`).
            Defaults to :data:`DEFAULT_MAX_EVIDENCE_CHARS` so this function
            remains usable on its own, without requiring every caller to
            thread the CLI's budget value through explicitly.
        progress: Whether to print a line before and after the API call.
        detail: Whether to also log the outgoing prompt size and a rough
            estimated token count before the call. The estimate is a simple
            ``chars / 4`` heuristic, not a real tokenizer -- good enough to
            catch an unexpectedly huge payload, not for billing.

    Returns:
        A dictionary with the parsed analysis plus ``_meta`` describing the call.

    Raises:
        RuntimeError: If the SDK is missing, the key is unset, or the call fails.
    """
    try:
        from anthropic import Anthropic
    except ImportError as exc:
        raise RuntimeError("The anthropic package is not installed. Run: pip install -r requirements.txt") from exc

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set. Export it, or run with --no-llm.")

    user_prompt = _cap_user_prompt(build_user_prompt(evidence), max_evidence_chars, evidence)

    if detail:
        estimated_tokens = len(user_prompt) // CHARS_PER_TOKEN_ESTIMATE
        print(
            f"[*] Evidence prompt: {len(user_prompt):,} chars (~{estimated_tokens:,} est. input tokens; "
            "rough chars/4 heuristic, not exact)",
            file=sys.stderr,
        )
    if progress:
        print(f"[*] Querying {model} ({evidence.mode} mode)...", file=sys.stderr)

    client = Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=build_system_prompt(evidence.mode),
            messages=[{"role": "user", "content": user_prompt}],
        )
    except Exception as exc:  # noqa: BLE001 - surface any SDK/transport failure uniformly
        raise RuntimeError(f"Anthropic API call failed: {exc}") from exc

    text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
    parsed = extract_json_object(text)
    meta = {
        "model": model,
        "mode": evidence.mode,
        "input_tokens": getattr(response.usage, "input_tokens", None),
        "output_tokens": getattr(response.usage, "output_tokens", None),
        "stop_reason": getattr(response, "stop_reason", None),
    }
    if progress:
        print(f"[*] Response received (in: {meta['input_tokens']} tok, out: {meta['output_tokens']} tok)",
              file=sys.stderr)
    if parsed is None:
        return {"verdict": "The model did not return parsable JSON.", "explanation": text, "_meta": meta}
    parsed["_meta"] = meta
    return parsed


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _bullets(values: Any, indent: str = "  ") -> str:
    """Render a value as an indented bullet list.

    Args:
        values: A list of strings, a single string, or ``None``.
        indent: Leading whitespace for each bullet.

    Returns:
        The formatted bullet list, or an empty string.
    """
    if not values:
        return ""
    items = values if isinstance(values, list) else [values]
    return "\n".join(f"{indent}- {item}" for item in items)


def render_report(evidence: CoreEvidence, analysis: dict[str, Any] | None) -> str:
    """Build the human-readable report printed to stdout.

    Args:
        evidence: The assembled evidence.
        analysis: The parsed LLM analysis, or ``None`` when ``--no-llm`` is used.

    Returns:
        The formatted report text.
    """
    rule = "=" * 78
    lines = [rule, "CORE DUMP ANALYSIS", rule, ""]
    lines.append(f"Core file    : {evidence.core_file.get('path')} ({evidence.core_file.get('size_human')})")
    lines.append(f"Executable   : {evidence.executable.get('path') or 'UNRESOLVED'} "
                 f"(via {evidence.executable.get('source')})")
    lines.append(f"Signal       : {evidence.signal or 'none recorded'}")
    lines.append(f"Threads      : {evidence.thread_count if evidence.thread_count is not None else 'unknown'}")
    lines.append(f"Analysis mode: {evidence.mode} ({evidence.mode_source})")
    if evidence.environment:
        backend = evidence.environment.get("execution_backend", "local")
        os_name = evidence.environment.get("os", "unknown")
        lines.append(f"Environment  : {os_name} ({backend})")
    if evidence.build_ids.get("available"):
        checked = len(evidence.build_ids.get("checked", []))
        mismatches = evidence.build_ids.get("mismatch_count", 0)
        if checked:
            lines.append(f"Build IDs    : {checked} key module(s) checked, {mismatches} mismatch(es)")
        else:
            lines.append(
                f"Build IDs    : UNVERIFIED (eu-unstrip enumerated {evidence.build_ids.get('module_count', 0)} module(s); 0 key modules checked)"
            )
    if evidence.process_identity:
        lines.append(
            f"Core process : {evidence.process_identity.get('kind', 'unknown')} "
            f"({evidence.process_identity.get('confidence', 'low')} confidence)"
        )
    if evidence.generated_by:
        lines.append(f"Generated by : {evidence.generated_by}")
    if evidence.python.get("available"):
        lines.append("Python frames: available (py-bt)")
    lines.append("")

    if evidence.warnings:
        lines += ["EVIDENCE QUALITY WARNINGS", "-" * 78, _bullets(evidence.warnings), ""]

    if analysis is None:
        lines += ["(--no-llm: showing extracted evidence only)", ""]
        if evidence.diagnosis.get("available"):
            diagnosis = evidence.diagnosis
            lines += ["DETERMINISTIC DIAGNOSIS", "-" * 78]
            lines.append(f"  Classification: {diagnosis.get('classification', 'unclassified')}")
            if diagnosis.get("family"):
                lines.append(f"  Family        : {diagnosis.get('family')}")
            if diagnosis.get("subtype"):
                lines.append(f"  Subtype       : {diagnosis.get('subtype')}")
            lines.append(f"  Phase         : {diagnosis.get('phase', 'unknown')}")
            lines.append(f"  Component     : {diagnosis.get('component', 'unknown')}")
            lines.append(f"  Confidence    : {diagnosis.get('confidence', 'unknown')}")
            lines.append(f"  Root cause    : {'established' if diagnosis.get('root_cause_established') else 'not established'}")
            if diagnosis.get("summary"):
                lines.append(f"  Summary       : {diagnosis.get('summary')}")
            if diagnosis.get("limitations"):
                lines.append("  Limitations:")
                lines.extend(f"    - {item}" for item in diagnosis.get("limitations", []))
            lines.append("")
        if evidence.observations:
            lines += ["DETERMINISTIC OBSERVATIONS", "-" * 78, _bullets(evidence.observations), ""]
        lines += ["THREAD SUMMARY", "-" * 78]
        for group in evidence.thread_groups[:10]:
            state = "BUSY" if group.state == "active" else ("BLOCKED" if group.state == "blocked" else "idle")
            tids = ",".join(group.thread_ids[:3])
            context = _thread_context_frame(group.backtrace)
            lines.append(f"  [{state}] {group.count:>4} thread(s) T{tids}: {context[:115]}")
        lines.append("")
        if evidence.targeted_threads:
            lines += ["TARGETED FRAME EVIDENCE", "-" * 78]
            unavailable = 0
            for target in evidence.targeted_threads:
                lines.append(
                    f"  T{target.get('thread_id')} frame {target.get('frame')} [{str(target.get('state', '')).upper()}]: "
                    f"{str(target.get('context', '?'))[:105]}"
                )
                if target.get("frame_details_available", True):
                    for label in ("args", "locals"):
                        value = str(target.get(label, "")).strip()
                        if value:
                            compact = " | ".join(line.strip() for line in value.splitlines() if line.strip())
                            lines.append(f"    {label}: {compact[:220]}")
                else:
                    unavailable += 1
            if unavailable:
                lines.append(
                    f"  Note: arguments/locals were unavailable for {unavailable} selected frame(s); "
                    "this can occur in optimized functions even when GDB reports symbols read for the library."
                )
            lines.append("")
        if evidence.job_logs.get("available"):
            profile = evidence.job_logs.get("profile", "general")
            title = "PAYLOAD LOG CORRELATION" if profile == "payload-centric" else "JOB LOG CORRELATION"
            lines += [title, "-" * 78]
            counts = evidence.job_logs.get("category_counts", {})
            lines.append(
                "  Scanned: " + str(len(evidence.job_logs.get("files", []))) + " file(s); retained relevant lines: " +
                str(len(evidence.job_logs.get("matches", []))) +
                (f" ({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))})" if counts else "")
            )
            if evidence.job_logs.get("pilotlog_default_excluded"):
                lines.append("  Scope: payload stdout/stderr plus log-like files under workDir; pilotlog.txt excluded for hang mode.")
            activity = evidence.job_logs.get("payload_activity", {})
            if activity:
                line = (
                    f"  Payload activity: {activity.get('latest_payload_file', '?')} last modified "
                    f"{activity.get('last_write_before_core_human', '?')} before core capture"
                )
                last_line = activity.get("last_nonempty_line")
                if isinstance(last_line, dict) and last_line.get("text"):
                    line += f"; last non-empty line {last_line.get('line', '?')}: {str(last_line.get('text'))[:120]}"
                latest_progress = activity.get("latest_progress")
                if (isinstance(latest_progress, dict) and latest_progress.get("text")
                        and (not isinstance(last_line, dict) or latest_progress.get("line") != last_line.get("line"))):
                    line += f"; latest retained progress: {str(latest_progress.get('text'))[:120]}"
                lines.append(line)
                tail = activity.get("tail")
                if isinstance(tail, list) and tail:
                    lines.append("  Payload tail (last non-empty lines):")
                    for item in tail[-8:]:
                        if isinstance(item, dict):
                            lines.append(f"    {activity.get('latest_payload_file', '?')}:{item.get('line', '?')}: {str(item.get('text', ''))[:170]}")
            for match in evidence.job_logs.get("matches", [])[:12]:
                display_file = match.get("relative_file") or Path(str(match.get("file", "?"))).name
                lines.append(
                    f"  [{str(match.get('category', '?')).upper()}] {display_file}:"
                    f"{match.get('line', '?')}: {str(match.get('text', ''))[:180]}"
                )
            if len(evidence.job_logs.get("matches", [])) > 12:
                lines.append("  ... additional matched lines are retained in JSON.")
            lines.append("")
        return "\n".join(lines)

    sections: list[tuple[str, Any]] = [
        ("VERDICT", analysis.get("verdict")),
        ("CLASSIFICATION", f"{analysis.get('classification', '?')} "
                           f"(confidence: {analysis.get('confidence', '?')}"
                           f" - {analysis.get('confidence_reason', '')})"),
        ("LIKELY CAUSE", analysis.get("likely_cause")),
        ("CULPRIT COMPONENT", analysis.get("culprit_component")),
        ("BUSY THREADS", analysis.get("busy_threads")),
    ]
    for title, body in sections:
        if body:
            lines += [title, "-" * 78, str(body), ""]

    for title, key in (("SUPPORTING EVIDENCE", "supporting_evidence"),
                       ("LIMITATIONS", "limitations"),
                       ("NEXT STEPS", "next_steps")):
        rendered = _bullets(analysis.get(key))
        if rendered:
            lines += [title, "-" * 78, rendered, ""]

    if analysis.get("explanation"):
        lines += ["EXPLANATION", "-" * 78, str(analysis["explanation"]), ""]

    meta = analysis.get("_meta", {})
    lines.append(f"[model: {meta.get('model')} | in: {meta.get('input_tokens')} tok | "
                 f"out: {meta.get('output_tokens')} tok]")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Argument vector to parse, or ``None`` to use ``sys.argv``.

    Returns:
        The parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="analyze_core_dump.py",
        description="Analyze a core dump with gdb and explain it in plain language using an LLM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment:\n"
            "  ANTHROPIC_API_KEY     required unless --no-llm\n"
            "  CORE_ANALYSIS_MODEL   model override (falls back to LLM_DEFAULT_MODEL, then "
            f"{DEFAULT_MODEL})\n"
        ),
    )
    parser.add_argument("core_file", help="Path to the core dump file, e.g. core.123456")
    parser.add_argument(
        "--execution", choices=["local", "atlas-container"], default="local",
        help="Where to collect deterministic evidence. 'local' uses the current OS; "
             "'atlas-container' recreates the ATLAS release/container environment.",
    )
    parser.add_argument("--job-dir", default=None,
                        help="PanDA job directory mounted as /srv in atlas-container mode "
                             "(default: directory containing the core).")
    parser.add_argument("--release-setup", default=None,
                        help="Release setup script for atlas-container mode "
                             "(default: <job-dir>/my_release_setup.sh).")
    parser.add_argument("--atlas-platform", default=DEFAULT_ATLAS_PLATFORM,
                        help=f"ATLAS container platform (default: {DEFAULT_ATLAS_PLATFORM}).")
    parser.add_argument("--atlas-local-root-base", default=DEFAULT_ATLAS_LOCAL_ROOT_BASE,
                        help="ATLASLocalRootBase path on the host.")
    parser.add_argument("--container-extra-args", default="-c -i",
                        help="Raw Apptainer arguments passed through atlasLocalSetup.sh -e "
                             "(default: '-c -i').")
    parser.add_argument("--container-timeout", type=int, default=DEFAULT_CONTAINER_TIMEOUT,
                        help=f"Whole container evidence-run timeout in seconds "
                             f"(default: {DEFAULT_CONTAINER_TIMEOUT}).")
    parser.add_argument("--keep-container-artifacts", action="store_true",
                        help="Keep generated worker/runner/evidence files in --job-dir for debugging.")
    parser.add_argument("--job-log", action="append", default=None,
                        help="Specific payload/job log to correlate (repeatable; relative paths use --job-dir). "
                             "If omitted, hang mode discovers payload stdout/stderr and log-like files under workDir.")
    parser.add_argument("--no-job-logs", dest="collect_job_logs", action="store_false", default=True,
                        help="Disable bounded host-side payload/job log correlation.")
    parser.add_argument("--max-job-log-files", type=int, default=DEFAULT_MAX_JOB_LOG_FILES,
                        help=f"Maximum discovered payload/job log files to scan (default: {DEFAULT_MAX_JOB_LOG_FILES}).")
    parser.add_argument("--max-job-log-matches", type=int, default=DEFAULT_MAX_JOB_LOG_MATCHES,
                        help=f"Maximum matched payload/job-log lines retained (default: {DEFAULT_MAX_JOB_LOG_MATCHES}).")
    parser.add_argument("--job-log-tail-lines", type=int, default=DEFAULT_JOB_LOG_TAIL_LINES,
                        help=f"Non-empty tail lines retained per payload/runtime log (default: {DEFAULT_JOB_LOG_TAIL_LINES}; 0 disables).")
    parser.add_argument("--exe", default=None,
                        help="Path to the ELF executable. For athena.py jobs this is the Python "
                             "interpreter binary, NOT the .py script. Usually auto-detected.")
    parser.add_argument("--mode", choices=["auto", "hang", "crash"], default="auto",
                        help="Analysis framing. 'auto' infers it from the terminating signal.")
    parser.add_argument("--model", default=None, help="Anthropic model to use (overrides the environment).")
    parser.add_argument("--max-frames", type=int, default=DEFAULT_MAX_FRAMES,
                        help=f"Stack frames per thread (default: {DEFAULT_MAX_FRAMES}).")
    parser.add_argument("--max-thread-groups", type=int, default=DEFAULT_MAX_THREAD_GROUPS,
                        help=f"Distinct thread backtraces to keep (default: {DEFAULT_MAX_THREAD_GROUPS}).")
    parser.add_argument("--max-targeted-threads", type=int, default=DEFAULT_MAX_TARGETED_THREADS,
                        help=f"Non-idle thread groups to inspect with focused frame/args/locals commands; "
                             f"0 disables this extra phase (default: {DEFAULT_MAX_TARGETED_THREADS}).")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS,
                        help=f"Maximum response tokens (default: {DEFAULT_MAX_TOKENS}).")
    parser.add_argument("--max-evidence-chars", type=int, default=DEFAULT_MAX_EVIDENCE_CHARS,
                        help=f"Evidence size budget (default: {DEFAULT_MAX_EVIDENCE_CHARS}).")
    parser.add_argument("--no-locals", dest="locals", action="store_false", default=True,
                        help="Skip 'info locals'. Locals are collected by default because loop "
                             "counters are often the payoff for a looping job.")
    parser.add_argument("--no-redact", action="store_true",
                        help="Disable scrubbing of tokens, proxies and keys from gdb output.")
    parser.add_argument("--gdb", default=None, help="Path to the gdb executable (default: search PATH).")
    parser.add_argument("--gdb-timeout", type=int, default=DEFAULT_GDB_TIMEOUT,
                        help=f"Per-phase gdb timeout in seconds (default: {DEFAULT_GDB_TIMEOUT}).")
    parser.add_argument("--no-llm", action="store_true", help="Extract evidence only; skip the LLM call.")
    parser.add_argument("--json", dest="json_out", default=None,
                        help="Write the full evidence and analysis to this JSON file.")
    parser.add_argument("--raw-gdb", default=None, help="Write the unprocessed gdb output to this file.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Also log a heartbeat during long gdb phases and the outgoing evidence "
                             "size/token estimate. Basic phase progress is logged by default; see -q.")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress all progress logging to stderr, including -v output.")
    parser.add_argument("--heartbeat-interval", type=int, default=DEFAULT_HEARTBEAT_INTERVAL,
                        help="Seconds between -v heartbeat messages during a gdb phase "
                             f"(default: {DEFAULT_HEARTBEAT_INTERVAL}).")
    parser.add_argument("--large-core-warning-mib", type=int, default=DEFAULT_LARGE_CORE_WARNING_MIB,
                        help="Core size in MiB above which a one-time slow-analysis note is printed. "
                             f"0 disables it (default: {DEFAULT_LARGE_CORE_WARNING_MIB}).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def resolve_logging_flags(args: argparse.Namespace) -> tuple[bool, bool]:
    """Resolve effective progress/heartbeat verbosity from the CLI flags.

    ``--quiet`` always wins: it suppresses both the default progress lines and
    anything ``-v``/``--verbose`` would otherwise add.

    Args:
        args: Parsed command-line arguments.

    Returns:
        A tuple of ``(progress, detail)``: whether to print basic phase-level
        progress at all, and whether to additionally print heartbeats and
        size/token estimates.
    """
    quiet = getattr(args, "quiet", False)
    return not quiet, bool(getattr(args, "verbose", False)) and not quiet


def resolve_model(explicit: str | None) -> str:
    """Determine which model to use.

    Args:
        explicit: A ``--model`` value, or ``None``.

    Returns:
        The model identifier, preferring ``--model``, then ``CORE_ANALYSIS_MODEL``,
        then ``LLM_DEFAULT_MODEL``, then the built-in default.
    """
    return explicit or os.environ.get("CORE_ANALYSIS_MODEL") or os.environ.get("LLM_DEFAULT_MODEL") or DEFAULT_MODEL


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.

    Args:
        argv: Argument vector, or ``None`` to use ``sys.argv``.

    Returns:
        ``0`` on success, ``1`` on a handled error, ``130`` on interrupt.
    """
    args = parse_args(argv)
    progress, detail = resolve_logging_flags(args)
    started = time.monotonic()
    try:
        evidence, raw = collect_evidence(args, progress=progress, detail=detail)
    except (FileNotFoundError, OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    if args.raw_gdb:
        Path(args.raw_gdb).write_text(redact(raw, not args.no_redact), encoding="utf-8")
        if detail:
            print(f"[*] Raw gdb output written to {args.raw_gdb}", file=sys.stderr)

    analysis: dict[str, Any] | None = None
    if not args.no_llm:
        # Cost control belongs to the LLM input, not to the deterministic
        # evidence artifact.  Keep the report/JSON complete and reduce only a
        # deep copy that is about to be sent to the model.
        llm_evidence = enforce_global_budget(
            copy.deepcopy(evidence), args.max_evidence_chars, detail=detail
        )
        try:
            analysis = analyze_with_llm(
                llm_evidence, resolve_model(args.model), args.max_tokens, args.max_evidence_chars,
                progress=progress, detail=detail,
            )
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    print(render_report(evidence, analysis))

    if args.json_out:
        payload = {
            "schema_version": 1,
            "tool_version": __version__,
            "evidence": evidence.to_dict(),
            "analysis": analysis,
        }
        Path(args.json_out).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        if detail:
            print(f"[*] JSON written to {args.json_out}", file=sys.stderr)

    if progress:
        print(f"[*] Done in {time.monotonic() - started:.1f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
