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
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

__version__ = "0.1.0"

# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_FRAMES = 40
DEFAULT_MAX_THREAD_GROUPS = 25
DEFAULT_GDB_TIMEOUT = 120
DEFAULT_MAX_TOKENS = 4000
DEFAULT_MAX_EVIDENCE_CHARS = 50_000

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
}

#: Emitted by gdb's ``echo`` between commands so sections can be split exactly
#: rather than guessed at with boundary regexes.
SECTION_MARKER = "@@BAMBOO_SECTION:{name}@@"
_MARKER_RE = re.compile(r"^@@BAMBOO_SECTION:([a-z_]+)@@\s*$", re.M)

#: Signals that indicate a genuine fault rather than a deliberate core dump.
CRASH_SIGNALS = frozenset({"SIGSEGV", "SIGBUS", "SIGFPE", "SIGILL", "SIGSYS", "SIGTRAP"})

#: Signals typically seen when a supervisor snapshots or kills a looping job.
HANG_SIGNALS = frozenset({"SIGQUIT", "SIGABRT", "SIGTERM", "SIGKILL", "SIGUSR1", "SIGUSR2", "SIGINT"})

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
        idle: Whether the top frame looks like a benign wait rather than work.
    """

    count: int
    thread_ids: list[str]
    names: list[str]
    backtrace: str
    idle: bool = False


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
        python: Python-level backtrace from ``py-bt``, if available.
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
    python: dict[str, Any] = field(default_factory=dict)
    shared_libraries: dict[str, Any] = field(default_factory=dict)
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


def gdb_version(gdb_path: str) -> str:
    """Return the first line of ``gdb --version``.

    Args:
        gdb_path: Path to the gdb executable.

    Returns:
        The version banner, or ``"unknown"`` if it could not be read.
    """
    try:
        proc = subprocess.run(
            [gdb_path, "--version"], capture_output=True, text=True, timeout=30, check=False
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
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
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
    then the core's NT_FILE note, then the recorded command line. A ``.py`` path
    passed via ``--exe`` is rejected, because gdb needs the interpreter binary
    rather than the script.

    Args:
        gdb_path: Path to the gdb executable.
        core_path: Path to the core dump file.
        explicit: User-supplied executable path, or ``None``.
        probe_output: Output of a bare ``gdb -c core`` probe run.
        timeout: gdb timeout in seconds.
        progress: Whether to print progress for any gdb probe this triggers.
        detail: Whether to also print heartbeat messages during those probes.
        heartbeat_interval: Seconds between heartbeat messages when ``detail``
            is enabled.

    Returns:
        A dictionary with keys ``path``, ``resolved``, ``source``, ``recorded``
        and ``notes``.
    """
    notes: list[str] = []

    if explicit:
        explicit_path = Path(explicit)
        if explicit_path.suffix == ".py":
            notes.append(
                f"--exe pointed at a Python script ({explicit}). gdb needs the interpreter ELF binary, "
                "not the script; ignoring it and attempting automatic resolution."
            )
        elif not explicit_path.is_file():
            notes.append(f"--exe path does not exist: {explicit}")
        else:
            return {"path": str(explicit_path.resolve()), "resolved": True,
                    "source": "--exe", "recorded": None, "notes": notes}

    candidates: list[tuple[str, str | None]] = [
        ("AT_EXECFN", executable_from_auxv(
            gdb_path, core_path, timeout, progress=progress, detail=detail, heartbeat_interval=heartbeat_interval)),
        ("NT_FILE", executable_from_nt_file(core_path)),
        ("command-line", _argv0_from_command_line(parse_generated_by(probe_output))),
    ]
    for source, recorded in candidates:
        if not recorded:
            continue
        resolved, searched = _existing_path(recorded)
        if resolved:
            if searched:
                notes.append(
                    f"Executable recorded as '{recorded}' was not found directly and was matched to "
                    f"'{resolved}' by search. Verify it is the same build; a mismatched binary yields "
                    "plausible but wrong symbols."
                )
            return {"path": resolved, "resolved": True, "source": source,
                    "recorded": recorded, "notes": notes}
        notes.append(
            f"The core references executable '{recorded}' ({source}), which is not present on this host. "
            "No substitute was used, because a different build would produce misleading symbols. "
            "Re-run where that path is available (for ATLAS jobs, with the matching CVMFS release mounted), "
            "or pass the correct binary with --exe."
        )

    notes.append("No executable could be resolved. Backtraces will be unsymbolised and largely uninterpretable.")
    return {"path": None, "resolved": False, "source": "none", "recorded": None, "notes": notes}


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
        ("No symbol table info available", "Some frames have no symbol information."),
        ("no debugging symbols found", "The executable was built or shipped without debug symbols."),
        ("Missing separate debuginfo", "Separate debuginfo packages are missing for one or more libraries."),
        ("Cannot access memory", "Parts of the process memory are unreadable in this core."),
    )
    for needle, message in checks:
        if needle in text and message not in warnings:
            warnings.append(message)
    return warnings


def _is_idle_stack(backtrace: str) -> bool:
    """Heuristically decide whether a stack is waiting rather than working.

    Args:
        backtrace: The backtrace text for one thread.

    Returns:
        ``True`` if the top frames look like a benign blocking wait.
    """
    idle_markers = (
        "pthread_cond_wait", "pthread_cond_timedwait", "__futex_abstimed_wait",
        "epoll_wait", "poll (", "ppoll", "select (", "nanosleep", "sem_wait",
        "sigwait", "accept (", "read (", "recvmsg",
    )
    head = "\n".join(backtrace.splitlines()[:3])
    return any(marker in head for marker in idle_markers)


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
            buckets[signature] = ThreadGroup(
                count=1,
                thread_ids=[thread_id],
                names=[thread_name] if thread_name else [],
                backtrace=trimmed + ("" if not was_cut else ""),
                idle=_is_idle_stack(backtrace),
            )
            continue
        group.count += 1
        if len(group.thread_ids) < 10:
            group.thread_ids.append(thread_id)
        if thread_name and thread_name not in group.names:
            group.names.append(thread_name)

    groups = sorted(buckets.values(), key=lambda grp: (grp.idle, -grp.count))
    return groups[:max_groups]


def summarise_shared_libraries(text: str) -> dict[str, Any]:
    """Summarise ``info sharedlibrary`` output.

    Only the libraries *without* symbols are kept verbatim, since a full list of
    300 loaded ATLAS libraries adds tokens without adding signal.

    Args:
        text: Output of ``info sharedlibrary``.

    Returns:
        A dictionary with the total count and the unsymbolised subset.
    """
    total = 0
    missing: list[str] = []
    for line in text.splitlines():
        if "/" not in line:
            continue
        total += 1
        if "No" in line.split()[:3] or "(*)" in line:
            path = line.split()[-1]
            if path.startswith("/") and len(missing) < 40:
                missing.append(path)
    return {"total_loaded": total, "without_symbols": missing, "without_symbols_count": len(missing)}


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
        ("metadata", [("program", "info program"), ("threads", "info threads")]),
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


def collect_evidence(
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

    raw_chunks: list[str] = [f"$ gdb -c {core_path.name} -ex 'info program'\n{probe.stdout}\n{probe.stderr}"]
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
    evidence.thread_groups = group_thread_stacks(
        sections.get("all_threads", ""), args.max_thread_groups, not args.no_redact
    )
    evidence.python = _summarise_python(
        sections.get("py_bt", ""), sections.get("py_list", ""), errors.get("python", ""), not args.no_redact
    )
    evidence.shared_libraries = summarise_shared_libraries(sections.get("libraries", ""))
    return evidence, combined


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
            "reason": ("py-bt is not available: the libpython gdb helper is not loaded. Ensure the "
                       "interpreter's python-gdb.py is on the auto-load path and debug symbols are present."),
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
        The same evidence object, mutated to fit within ``limit`` wherever the
        cascade was able to. See ``evidence.warnings`` for whether it fully
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
- Threads parked on pthread_cond_wait, futex or epoll are idle workers, not the problem. Do not report them \
as findings.
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
    if evidence.generated_by:
        lines.append(f"Generated by : {evidence.generated_by}")
    if evidence.python.get("available"):
        lines.append("Python frames: available (py-bt)")
    lines.append("")

    if evidence.warnings:
        lines += ["EVIDENCE QUALITY WARNINGS", "-" * 78, _bullets(evidence.warnings), ""]

    if analysis is None:
        lines += ["(--no-llm: showing extracted evidence only)", "", "THREAD SUMMARY", "-" * 78]
        for group in evidence.thread_groups[:10]:
            top = next((ln for ln in group.backtrace.splitlines() if ln.strip().startswith("#0")), "?")
            state = "idle" if group.idle else "BUSY"
            lines.append(f"  [{state}] {group.count:>4} thread(s): {top.strip()[:100]}")
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
        evidence = enforce_global_budget(evidence, args.max_evidence_chars, detail=detail)
    except (FileNotFoundError, OSError) as exc:
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
        try:
            analysis = analyze_with_llm(
                evidence, resolve_model(args.model), args.max_tokens, args.max_evidence_chars,
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
