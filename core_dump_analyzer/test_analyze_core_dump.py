"""Tests for :mod:`analyze_core_dump`.

The gdb-driving code is exercised against captured gdb output rather than a live
core file, so the suite runs anywhere. The Anthropic call is exercised with a
stubbed SDK module.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import analyze_core_dump as acd  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

ALL_THREADS_OUTPUT = """
Thread 4 (Thread 0x7f0a2b3fc6c0 (LWP 903) "AthenaHiveEvent"):
#0  0x00007f0a2c8ecbdf in pthread_cond_wait () from /lib64/libc.so.6
#1  0x00007f0a2d112a41 in tbb::detail::r1::market::process () from /lib/libtbb.so.12
#2  0x00007f0a2c8e81ca in start_thread () from /lib64/libc.so.6

Thread 3 (Thread 0x7f0a2bbfd6c0 (LWP 902) "AthenaHiveEvent"):
#0  0x00007f0a2c8ecbdf in pthread_cond_wait () from /lib64/libc.so.6
#1  0x00007f0a2d112a41 in tbb::detail::r1::market::process () from /lib/libtbb.so.12
#2  0x00007f0a2c8e81ca in start_thread () from /lib64/libc.so.6

Thread 1 (Thread 0x7f0a2d728740 (LWP 900) "athena.py"):
#0  0x00000000005d8eb9 in _PyEval_EvalFrameDefault ()
#1  0x00000000005a1234 in InDetTrackFinder::findTracks (this=0x123, evt=40771) at TrackFinder.cxx:412
#2  0x00000000004f0000 in main ()
"""

PRIMARY_SECTIONS = {
    "backtrace": "#0  0x5d8eb9 in InDetTrackFinder::findTracks (this=0x1) at TrackFinder.cxx:412",
    "frame": "Stack level 0, frame at 0x7ffd0000:",
    "args": "this = 0x1\nevt = 40771",
    "locals": "iteration = 998877\ncandidate = 0x0",
    "registers": "rax            0x0                 0",
}


def make_args(**overrides: Any) -> argparse.Namespace:
    """Build a Namespace mirroring parsed CLI arguments.

    Args:
        **overrides: Fields to override on the default namespace.

    Returns:
        A namespace suitable for passing to production helpers.
    """
    defaults: dict[str, Any] = {
        "core_file": "core.1", "exe": None, "mode": "auto", "model": None,
        "max_frames": 40, "max_thread_groups": 25, "max_targeted_threads": 3, "max_tokens": 4000,
        "max_evidence_chars": 50_000, "locals": True, "no_redact": False,
        "gdb": None, "gdb_timeout": 120, "no_llm": False, "json_out": None,
        "raw_gdb": None, "verbose": False, "quiet": False,
        "heartbeat_interval": acd.DEFAULT_HEARTBEAT_INTERVAL,
        "large_core_warning_mib": acd.DEFAULT_LARGE_CORE_WARNING_MIB,
        "execution": "local", "job_dir": None, "release_setup": None,
        "atlas_platform": acd.DEFAULT_ATLAS_PLATFORM,
        "atlas_local_root_base": acd.DEFAULT_ATLAS_LOCAL_ROOT_BASE,
        "container_extra_args": "-c -i",
        "container_timeout": acd.DEFAULT_CONTAINER_TIMEOUT,
        "keep_container_artifacts": False,
        "job_log": None, "collect_job_logs": True,
        "max_job_log_files": acd.DEFAULT_MAX_JOB_LOG_FILES,
        "max_job_log_matches": acd.DEFAULT_MAX_JOB_LOG_MATCHES,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# --------------------------------------------------------------------------- #
# Redaction and text helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw, must_not_contain", [
    ("token=abcdef1234567890abcdef", "abcdef1234567890abcdef"),
    ("Bearer aaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaa"),
    ("proxy at /tmp/x509up_u25123", "x509up_u25123"),
    ("PANDA_PASSWORD=hunter2secret", "hunter2secret"),
    ("key sk-ant-api03-DEADBEEFCAFE", "sk-ant-api03-DEADBEEFCAFE"),
    ("eyJhbGciOiJIUzI1NiI.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF2QT4", "SflKxwRJSMeKKF2QT4"),
])
def test_redact_removes_secrets(raw: str, must_not_contain: str) -> None:
    """Secrets are scrubbed from gdb text."""
    assert must_not_contain not in acd.redact(raw)


def test_redact_can_be_disabled() -> None:
    """Redaction is a no-op when disabled."""
    assert acd.redact("token=supersecretvalue1234", enabled=False) == "token=supersecretvalue1234"


def test_redact_preserves_ordinary_text() -> None:
    """Non-sensitive gdb output is left intact."""
    text = "#0  0x1234 in findTracks (evt=40771) at TrackFinder.cxx:412"
    assert acd.redact(text) == text


def test_truncate_keeps_head_and_tail() -> None:
    """Truncation retains both ends and reports that it happened."""
    result, was_cut = acd.truncate("A" * 100 + "B" * 100, 60)
    assert was_cut and result.startswith("A") and result.endswith("B") and "truncated" in result


def test_truncate_noop_when_short() -> None:
    """Short text is returned unchanged."""
    assert acd.truncate("short", 100) == ("short", False)


def test_normalise_frame_line_strips_addresses_and_numbers() -> None:
    """Two frames differing only by address normalise identically."""
    a = acd.normalise_frame_line("#0  0x00007f0a2c8ecbdf in pthread_cond_wait ()")
    b = acd.normalise_frame_line("#7  0x00007fbe11112222 in pthread_cond_wait ()")
    assert a == b == "0xADDR in pthread_cond_wait ()"


def test_clean_gdb_noise_drops_banners() -> None:
    """Load-time banners and licence text are removed."""
    noisy = "GNU gdb (Ubuntu 15.1)\n[New LWP 902]\n[Current thread is 1 (LWP 900)]\nreal content"
    assert acd.clean_gdb_noise(noisy) == "real content"


# --------------------------------------------------------------------------- #
# Section splitting
# --------------------------------------------------------------------------- #


def test_split_sections_discards_preamble_and_splits_exactly() -> None:
    """Output before the first marker is dropped and sections split cleanly."""
    text = (
        "Core was generated by `athena.py'.\n"
        "@@BAMBOO_SECTION:args@@\nthis = 0x1\n"
        "@@BAMBOO_SECTION:locals@@\niteration = 5\n"
    )
    sections = acd.split_sections(text)
    assert sections == {"args": "this = 0x1", "locals": "iteration = 5"}


def test_split_sections_empty_without_markers() -> None:
    """Text with no markers yields no sections."""
    assert acd.split_sections("no markers here") == {}


def test_split_sections_accepts_numbered_target_markers() -> None:
    """Dynamic targeted-thread section names may contain digits."""
    text = "@@BAMBOO_SECTION:target_1_args@@\nthis = 0x123\n"
    assert acd.split_sections(text) == {"target_1_args": "this = 0x123"}


def test_trim_primary_sections_preserves_labels() -> None:
    """Args and locals stay distinct, which regression-tests a real mislabelling bug."""
    trimmed, truncated = acd._trim_primary_sections(PRIMARY_SECTIONS, redact_enabled=True)
    assert trimmed["args"] == "this = 0x1\nevt = 40771"
    assert "iteration = 998877" in trimmed["locals"]
    assert truncated == []


def test_trim_primary_sections_skips_missing() -> None:
    """Absent sections are omitted rather than emitted empty."""
    trimmed, _ = acd._trim_primary_sections({"backtrace": "#0 foo"}, redact_enabled=True)
    assert list(trimmed) == ["backtrace"]


# --------------------------------------------------------------------------- #
# gdb output parsing
# --------------------------------------------------------------------------- #


def test_parse_signal_from_termination_line() -> None:
    """The terminating signal is recovered."""
    assert acd.parse_signal("Program terminated with signal SIGSEGV, Segmentation fault.") == "SIGSEGV"


def test_parse_signal_absent() -> None:
    """A gcore snapshot has no signal."""
    assert acd.parse_signal("Core was generated by `python athena.py'.") is None


@pytest.mark.parametrize("table, expected", [
    ("* 1    Thread 0x7f0a (LWP 900) main ()\n  2    Thread 0x7f0b (LWP 901) foo ()", 2),
    ("* 1    LWP 900   0x5d8eb9 in ?? ()", 1),
    ("no table at all", None),
])
def test_parse_thread_count(table: str, expected: int | None) -> None:
    """Thread counting works with and without symbols."""
    assert acd.parse_thread_count(table) == expected


def test_parse_generated_by() -> None:
    """The recorded command line is extracted."""
    text = "Core was generated by `python athena.py --evtMax 100'."
    assert acd.parse_generated_by(text) == "python athena.py --evtMax 100"


def test_collect_warnings_detects_degraded_evidence() -> None:
    """Truncated cores and missing symbols are flagged."""
    warnings = acd.collect_warnings("BFD: warning: core file is truncated\nno debugging symbols found")
    assert len(warnings) == 2
    assert any("truncated" in w for w in warnings)


def test_collect_warnings_deduplicates() -> None:
    """A repeated condition is reported once."""
    assert len(acd.collect_warnings("is truncated\nis truncated")) == 1


@pytest.mark.parametrize("backtrace, idle", [
    ("#0  0x1 in pthread_cond_wait ()", True),
    ("#0  0x1 in epoll_wait ()", True),
    ("#0  0x1 in InDetTrackFinder::findTracks ()", False),
])
def test_is_idle_stack(backtrace: str, idle: bool) -> None:
    """Blocking waits are classified as idle; real work is not."""
    assert acd._is_idle_stack(backtrace) is idle


def test_blocking_wait_with_shutdown_context_is_not_idle() -> None:
    """A futex wait inside subsystem shutdown is diagnostically blocked, not idle."""
    bt = (
        "#0  0x1 in __futex_abstimed_wait_common ()\n"
        "#1  0x2 in __new_sem_wait_slow64 ()\n"
        "#2  0x3 in XrdSys::IOEvents::Poller::SendCmd(...) ()\n"
        "#3  0x4 in XrdSys::IOEvents::Poller::Stop() ()\n"
        "#4  0x5 in XrdCl::PostMaster::Stop() ()\n"
    )
    assert acd._classify_thread_stack(bt) == "blocked"
    assert acd._is_idle_stack(bt) is False


def test_xrootd_stream_mutex_wait_is_blocked() -> None:
    """The live PanDA signature must not collapse a StreamMutex wait into idle."""
    bt = (
        "#0  0x1 in __futex_abstimed_wait_common ()\n"
        "#1  0x2 in pthread_cond_wait ()\n"
        "#2  0x3 in XrdSysCondVar::Wait() ()\n"
        "#3  0x4 in XrdCl::StreamMutex::Lock() ()\n"
        "#4  0x5 in XrdCl::Stream::Tick(long) ()\n"
    )
    assert acd._classify_thread_stack(bt) == "blocked"


def test_collect_warnings_ignores_missing_args_locals_symbols() -> None:
    """Missing DWARF for info args/locals alone must not imply unsymbolized frames."""
    assert "Some frames have no symbol information." not in acd.collect_warnings(
        "No symbol table info available."
    )


def test_unknown_backtrace_frame_is_detected_separately() -> None:
    """Actual ?? frames still degrade stack evidence."""
    assert acd._backtrace_has_unknown_frames("#0  0x1234 in ?? ()") is True
    assert acd._backtrace_has_unknown_frames("#0  0x1234 in named_function ()") is False


def test_deterministic_xrootd_shutdown_observations() -> None:
    """The known PanDA signature produces conservative no-LLM observations."""
    primary = (
        "#2 XrdSys::IOEvents::Poller::SendCmd(...)\n"
        "#3 XrdSys::IOEvents::Poller::Stop()\n"
        "#5 XrdCl::PostMaster::Stop()\n"
        "#6 XrdCl::DefaultEnv::Finalize()\n"
        "#10 Py_Exit (sts=0)\n"
    )
    groups = [
        acd.ThreadGroup(1, ["2"], [],
                        "#3 XrdCl::StreamMutex::Lock()\n#4 XrdCl::Stream::Tick(long)",
                        idle=False, state="blocked"),
        acd.ThreadGroup(1, ["3"], [],
                        "#7 XrdCl::PostMaster::ForceDisconnect(...)\n#9 XrdCl::Stream::OnReadTimeout(unsigned short)",
                        idle=False, state="blocked"),
    ]
    observations = acd.derive_deterministic_observations(primary, groups)
    assert any("Py_Exit(sts=0)" in item for item in observations)
    assert any("read timeout" in item for item in observations)
    assert any("StreamMutex::Lock" in item for item in observations)


def test_split_thread_stacks_finds_all_threads() -> None:
    """Each thread header starts a new stack."""
    stacks = acd.split_thread_stacks(ALL_THREADS_OUTPUT)
    assert [tid for tid, _, _ in stacks] == ["4", "3", "1"]
    assert stacks[0][1] == "AthenaHiveEvent"


def test_group_thread_stacks_collapses_duplicates_and_ranks_busy_first() -> None:
    """Identical idle stacks collapse, and the working thread is ranked first."""
    groups = acd.group_thread_stacks(ALL_THREADS_OUTPUT, max_groups=25, redact_enabled=True)
    assert len(groups) == 2
    assert groups[0].idle is False and groups[0].count == 1
    assert groups[1].idle is True and groups[1].count == 2
    assert sorted(groups[1].thread_ids) == ["3", "4"]


def test_group_thread_stacks_respects_max_groups() -> None:
    """The group cap is honoured."""
    assert len(acd.group_thread_stacks(ALL_THREADS_OUTPUT, max_groups=1, redact_enabled=True)) == 1


def test_summarise_shared_libraries_distinguishes_symbol_states() -> None:
    """Yes (*): symbols loaded but full debug info absent; only No means no symbols."""
    text = (
        "0x00007f0a  0x00007f0b  Yes         /lib64/libpython.so\n"
        "0x00007f0c  0x00007f0d  Yes (*)     /lib64/libc.so.6\n"
        "0x00007f0e  0x00007f0f  No          /lib/libFoo.so\n"
    )
    summary = acd.summarise_shared_libraries(text)
    assert summary["total_loaded"] == 3
    assert summary["with_symbols_count"] == 2
    assert summary["without_symbols"] == ["/lib/libFoo.so"]
    assert summary["without_full_debug_info"] == ["/lib64/libc.so.6"]


# --------------------------------------------------------------------------- #
# Mode detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("requested, signal, generated, expected", [
    ("crash", None, None, "crash"),
    ("hang", "SIGSEGV", None, "hang"),
    ("auto", "SIGSEGV", None, "crash"),
    ("auto", "SIGBUS", None, "crash"),
    ("auto", "SIGQUIT", None, "hang"),
    ("auto", None, "gcore 1234", "hang"),
    ("auto", None, None, "hang"),
])
def test_detect_mode(requested: str, signal: str | None, generated: str | None, expected: str) -> None:
    """Mode detection honours explicit requests and infers sensibly otherwise."""
    mode, reason = acd.detect_mode(requested, signal, generated)
    assert mode == expected and reason


# --------------------------------------------------------------------------- #
# Python frame summary
# --------------------------------------------------------------------------- #


def test_summarise_python_detects_unavailable_from_stderr() -> None:
    """gdb reports an unavailable command on stderr, which must be honoured."""
    result = acd._summarise_python("#0 0x1 in ?? ()", "", 'Undefined command: "py-bt".', True)
    assert result["available"] is False and "libpython" in result["reason"]


def test_summarise_python_rejects_non_python_output() -> None:
    """C-only output must not be reported as Python frames."""
    result = acd._summarise_python("#0  0x1 in reconstruct_cluster ()", "", "", True)
    assert result["available"] is False


def test_summarise_python_extracts_traceback() -> None:
    """A real py-bt traceback is captured together with the source context."""
    py_bt = (
        "Traceback (most recent call first):\n"
        '  File "/cvmfs/atlas/Reco.py", line 88, in merge_hits\n    hits.append(x)\n'
    )
    result = acd._summarise_python(py_bt, " >88\t    hits.append(x)", "", True)
    assert result["available"] is True
    assert "merge_hits" in result["backtrace"]
    assert "hits.append" in result["source_context"]


# --------------------------------------------------------------------------- #
# Executable resolution
# --------------------------------------------------------------------------- #


def test_existing_path_resolves_absolute(tmp_path: Path) -> None:
    """An existing absolute path is returned resolved without a search flag."""
    binary = tmp_path / "athena"
    binary.write_text("#!/bin/sh\n")
    assert acd._existing_path(str(binary)) == (str(binary.resolve()), False)


def test_existing_path_never_substitutes_for_missing_absolute_path() -> None:
    """A stale CVMFS path must not be silently replaced by a same-named system binary.

    Regression test: falling back to ``shutil.which("python")`` here would hand
    gdb an unrelated interpreter build and produce confidently wrong symbols.
    """
    assert acd._existing_path("/cvmfs/atlas.cern.ch/nonexistent/bin/python") == (None, False)
    assert acd._existing_path("/cvmfs/atlas.cern.ch/nonexistent/bin/sh") == (None, False)


def test_existing_path_searches_only_relative_names() -> None:
    """A bare name may be PATH-resolved, and the search is flagged."""
    resolved, searched = acd._existing_path("sh")
    assert resolved and resolved.endswith("sh") and searched is True


def test_existing_path_handles_none() -> None:
    """A missing recorded path is tolerated."""
    assert acd._existing_path(None) == (None, False)


def test_executable_from_auxv_parses_at_execfn(monkeypatch: pytest.MonkeyPatch) -> None:
    """AT_EXECFN is parsed out of ``info auxv`` output."""
    output = '31   AT_EXECFN   File name of executable   0x7ffd2caf4fee "/usr/bin/python3"'
    monkeypatch.setattr(
        acd, "run_gdb_phase",
        lambda *a, **k: acd.GdbPhaseResult(name="auxv", commands=[], stdout=output),
    )
    assert acd.executable_from_auxv("gdb", Path("core.1"), 10) == "/usr/bin/python3"


def test_resolve_executable_rejects_python_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Passing athena.py to --exe is refused with an explanatory note."""
    script = tmp_path / "athena.py"
    script.write_text("print('hi')\n")
    monkeypatch.setattr(acd, "executable_from_auxv", lambda *a, **k: None)
    monkeypatch.setattr(acd, "executable_from_nt_file", lambda *a, **k: None)
    result = acd.resolve_executable("gdb", Path("core.1"), str(script), "", 10)
    assert result["resolved"] is False
    assert any("interpreter ELF binary" in note for note in result["notes"])


def test_resolve_executable_prefers_explicit_binary(tmp_path: Path) -> None:
    """A valid --exe short-circuits automatic resolution."""
    binary = tmp_path / "python3"
    binary.write_text("\x7fELF")
    result = acd.resolve_executable("gdb", Path("core.1"), str(binary), "", 10)
    assert result["resolved"] is True and result["source"] == "--exe"


def test_resolve_executable_warns_on_absent_recorded_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unavailable CVMFS path produces an actionable warning."""
    monkeypatch.setattr(acd, "executable_from_auxv", lambda *a, **k: "/cvmfs/atlas/nope/python")
    monkeypatch.setattr(acd, "executable_from_nt_file", lambda *a, **k: None)
    result = acd.resolve_executable("gdb", Path("core.1"), None, "", 10)
    assert result["resolved"] is False
    assert any("CVMFS" in note for note in result["notes"])


def test_resolve_executable_drops_stale_failed_candidate_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bad AT_EXECFN candidate is an attempt, not a warning after later success."""
    binary = tmp_path / "python3.13"
    binary.write_text("\x7fELF")
    monkeypatch.setattr(acd, "executable_from_auxv", lambda *a, **k: "/truncated/cvmfs/python")
    monkeypatch.setattr(acd, "executable_from_nt_file", lambda *a, **k: None)
    probe = f"Core was generated by `{binary} EWRun.py'."
    result = acd.resolve_executable("gdb", Path("core.1"), None, probe, 10)
    assert result["resolved"] is True and result["source"] == "command-line"
    assert not any("/truncated/cvmfs/python" in note for note in result["notes"])
    assert any(attempt.get("recorded") == "/truncated/cvmfs/python" for attempt in result["attempts"])


# --------------------------------------------------------------------------- #
# Targeted thread inspection
# --------------------------------------------------------------------------- #


def _xrootd_groups() -> list[acd.ThreadGroup]:
    return [
        acd.ThreadGroup(
            count=1, thread_ids=["3"], names=[], state="blocked", idle=False,
            backtrace="""#0  in __futex_abstimed_wait_common ()
#1  in pthread_cond_wait ()
#2  in XrdSysCondVar::Wait ()
#3  in XrdCl::PollerBuiltIn::ShutdownEvents(XrdCl::Socket*) ()
#9  in XrdCl::Stream::OnReadTimeout(unsigned short) ()""",
        ),
        acd.ThreadGroup(
            count=1, thread_ids=["2"], names=[], state="blocked", idle=False,
            backtrace="""#0  in __futex_abstimed_wait_common ()
#1  in pthread_cond_wait ()
#2  in XrdSysCondVar::Wait ()
#3  in XrdCl::StreamMutex::Lock() ()
#4  in XrdCl::Stream::Tick(long) ()""",
        ),
        acd.ThreadGroup(
            count=1, thread_ids=["1"], names=[], state="blocked", idle=False,
            backtrace="""#0  in __futex_abstimed_wait_common ()
#1  in __new_sem_wait_slow64 ()
#2  in XrdSys::IOEvents::Poller::SendCmd(XrdSys::IOEvents::Poller::PipeData&) ()
#3  in XrdSys::IOEvents::Poller::Stop() ()
#10 in Py_Exit (sts=0)""",
        ),
        acd.ThreadGroup(
            count=8, thread_ids=["8"], names=[], state="idle", idle=True,
            backtrace="#0 in pthread_cond_wait ()\n#1 in worker_wait ()",
        ),
    ]


def test_select_targeted_threads_recovers_expected_xrootd_frames() -> None:
    """The real hang shape naturally selects T3/F3, T2/F3 and T1/F2."""
    targets = acd.select_targeted_threads(_xrootd_groups(), 3)
    assert [(item["thread_id"], item["frame"]) for item in targets] == [
        ("3", 3), ("2", 3), ("1", 2),
    ]
    assert all(item["state"] == "blocked" for item in targets)


def test_select_targeted_threads_skips_idle_and_respects_limit() -> None:
    """Focused GDB work is bounded and never spent on benign parked groups."""
    targets = acd.select_targeted_threads(_xrootd_groups(), 2)
    assert len(targets) == 2
    assert all(item["thread_id"] != "8" for item in targets)
    assert acd.select_targeted_threads(_xrootd_groups(), 0) == []


def test_build_targeted_phase_batches_all_threads_in_one_phase() -> None:
    """Each selected thread gets select/frame/args/locals commands with unique markers."""
    targets = acd.select_targeted_threads(_xrootd_groups(), 2)
    commands = acd._build_targeted_phase(targets, include_locals=True)
    assert ("target_1_thread", "thread 3") in commands
    assert ("target_1_frame_select", "frame 3") in commands
    assert ("target_1_args", "info args") in commands
    assert ("target_1_locals", "info locals") in commands
    assert ("target_2_thread", "thread 2") in commands


def test_summarise_targeted_threads_attaches_bounded_frame_details() -> None:
    """Focused GDB output is associated with the correct selected thread/frame."""
    targets = acd.select_targeted_threads(_xrootd_groups(), 1)
    sections = {
        "target_1_frame": "Stack level 3, frame at 0xabc",
        "target_1_args": "this = 0x123\nsocket = 0x456",
        "target_1_locals": "status = 7",
    }
    result = acd.summarise_targeted_threads(targets, sections, redact_enabled=True)
    assert result[0]["thread_id"] == "3" and result[0]["frame"] == 3
    assert "this = 0x123" in result[0]["args"]
    assert result[0]["locals"] == "status = 7"




def test_summarise_targeted_threads_marks_missing_frame_details() -> None:
    """Library symbols may load even when optimized frame args/locals are unavailable."""
    targets = acd.select_targeted_threads(_xrootd_groups(), 1)
    sections = {
        "target_1_frame": "Stack level 3, frame at 0xabc",
        "target_1_args": "No symbol table info available.",
        "target_1_locals": "No symbol table info available.",
    }
    result = acd.summarise_targeted_threads(targets, sections, redact_enabled=True)
    assert result[0]["frame_details_available"] is False


def test_render_report_compacts_unavailable_targeted_details() -> None:
    """Repeated GDB no-symbol-table lines become one explanatory note."""
    evidence = acd.CoreEvidence(mode="hang", mode_source="explicit")
    evidence.targeted_threads = [{
        "thread_id": "2", "frame": 3, "state": "blocked",
        "context": "#3 in XrdCl::StreamMutex::Lock() ()",
        "args": "No symbol table info available.",
        "locals": "No symbol table info available.",
        "frame_details_available": False,
    }]
    report = acd.render_report(evidence, None)
    assert "arguments/locals were unavailable" in report
    assert "No symbol table info available" not in report


def test_discover_job_logs_is_payload_centric_for_hang_mode(tmp_path: Path) -> None:
    """Looping jobs use payload streams/workDir logs and exclude pilot/root setup logs."""
    (tmp_path / "payload.stdout").write_text("payload")
    (tmp_path / "payload.stderr").write_text("")
    (tmp_path / "pilotlog.txt").write_text("pilot SIGTERM")
    (tmp_path / "other.log").write_text("root-level setup log")
    (tmp_path / "core-analysis-gdb.txt").write_text("generated")
    work = tmp_path / "workDir"
    work.mkdir()
    (work / "analysis.log").write_text("user log")
    (work / "custom.txt").write_text("static arbitrary text")
    (work / "tmp.stdout.abc").write_text("payload child stdout")
    (work / "input.txt").write_text("input list")
    (work / "SUSY_path.txt").write_text("configuration path")
    (work / "usr").mkdir()
    (work / "usr" / "CMakeLists.txt").write_text("not a runtime log")
    found = acd.discover_job_logs(tmp_path, failure_mode="hang")
    rel = [str(path.relative_to(tmp_path)) for path in found]
    assert rel[:2] == ["payload.stderr", "payload.stdout"] or rel[:2] == ["payload.stdout", "payload.stderr"]
    assert "workDir/analysis.log" in rel and "workDir/tmp.stdout.abc" in rel
    assert "workDir/custom.txt" not in rel and "workDir/input.txt" not in rel
    assert "workDir/SUSY_path.txt" not in rel
    assert "pilotlog.txt" not in rel and "other.log" not in rel
    assert "workDir/usr/CMakeLists.txt" not in rel
    assert "core-analysis-gdb.txt" not in rel


def test_discover_job_logs_includes_pilot_for_non_hang_and_explicit_hang(tmp_path: Path) -> None:
    """Pilot logs remain available for crash/general analysis or explicit requests."""
    (tmp_path / "payload.stdout").write_text("payload")
    (tmp_path / "pilotlog.txt").write_text("pilot")
    auto = acd.discover_job_logs(tmp_path, failure_mode="crash")
    assert [path.name for path in auto][:2] == ["payload.stdout", "pilotlog.txt"]
    explicit = acd.discover_job_logs(tmp_path, explicit=["pilotlog.txt"], failure_mode="hang")
    assert [path.name for path in explicit] == ["pilotlog.txt"]


def test_collect_job_log_evidence_uses_recent_tail_and_balances_files(tmp_path: Path) -> None:
    """Large-log tail evidence keeps recent timeout/termination lines from multiple files."""
    pilot = tmp_path / "pilotlog.txt"
    payload = tmp_path / "payload.stdout"
    pilot.write_text("old error\n" + ("filler\n" * 40) + "pilot SIGTERM payload exit code 0\n")
    payload.write_text("XRootD old\n" + ("noise\n" * 40) + "XrdCl read timeout forced disconnect\n")
    evidence = acd.collect_job_log_evidence(
        tmp_path, max_files=2, max_matches=8, max_bytes=100, core_mtime=pilot.stat().st_mtime
    )
    texts = [item["text"] for item in evidence["matches"]]
    assert any("SIGTERM" in text for text in texts)
    assert any("read timeout" in text for text in texts)
    assert all(meta["window"] == "tail" for meta in evidence["files"])
    assert all("mtime_delta_from_core_s" in meta for meta in evidence["files"])


def test_collect_job_log_evidence_redacts_matches(tmp_path: Path) -> None:
    """Log correlation obeys the same credential redaction contract as GDB evidence."""
    log = tmp_path / "pilotlog.txt"
    log.write_text("ERROR TOKEN=supersecretvalue123456789 payload exit code 1\n")
    evidence = acd.collect_job_log_evidence(tmp_path, max_files=1, max_matches=4)
    assert evidence["matches"]
    assert "supersecretvalue" not in evidence["matches"][0]["text"]


def test_render_report_shows_payload_log_correlation() -> None:
    """Hang-mode evidence clearly presents payload-centric scope and silence."""
    evidence = acd.CoreEvidence(mode="hang", mode_source="explicit")
    evidence.job_logs = {
        "available": True,
        "profile": "payload-centric",
        "pilotlog_default_excluded": True,
        "files": [{"path": "/job/payload.stdout"}],
        "category_counts": {"progress": 1},
        "payload_activity": {
            "latest_payload_file": "payload.stdout",
            "last_write_before_core_human": "2h 06m 16s",
            "last_nonempty_line": {"line": 3629, "text": "Final event selection summary"},
            "tail": [
                {"line": 3628, "text": "Finalizing output"},
                {"line": 3629, "text": "Final event selection summary"},
            ],
            "latest_progress": {"line": 3593, "text": "Processed 2140000 events"},
        },
        "matches": [{"file": "/job/payload.stdout", "relative_file": "payload.stdout",
                     "line": 3593, "category": "progress", "text": "Processed 2140000 events"}],
    }
    report = acd.render_report(evidence, None)
    assert "PAYLOAD LOG CORRELATION" in report
    assert "pilotlog.txt excluded for hang mode" in report
    assert "2h 06m 16s before core capture" in report
    assert "payload.stdout:3593" in report and "Processed 2140000 events" in report
    assert "Payload tail (last non-empty lines)" in report
    assert "payload.stdout:3629: Final event selection summary" in report

def test_job_log_patterns_avoid_identifier_and_configuration_false_positives(tmp_path: Path) -> None:
    """EventErrorState, lsetup xrootd and root:// catalog entries are not runtime failures."""
    (tmp_path / "payload.stdout").write_text(
        "INFO accepted 42 events for filter EventErrorState\n"
        "lsetup xrootd XRootD data access\n"
        "root://host.example/path/file.root\n"
        "XrdCl::Stream::OnReadTimeout read timeout forced disconnect\n"
    )
    ev = acd.collect_job_log_evidence(tmp_path, failure_mode="hang", max_matches=20)
    assert [(m["category"], m["text"]) for m in ev["matches"]] == [
        ("xrootd", "XrdCl::Stream::OnReadTimeout read timeout forced disconnect")
    ]


def test_job_log_error_matching_requires_real_severity_or_exception(tmp_path: Path) -> None:
    """Lower-case descriptive 'error' text is not a severity, while ERROR/Traceback are."""
    (tmp_path / "payload.stdout").write_text(
        "INFO selecting events without any error state set\n"
        "ERROR failed to write output\n"
        "Traceback (most recent call last):\n"
    )
    ev = acd.collect_job_log_evidence(tmp_path, failure_mode="hang", max_matches=20)
    assert [(m["category"], m["text"]) for m in ev["matches"]] == [
        ("error", "ERROR failed to write output"),
        ("error", "Traceback (most recent call last):"),
    ]


def test_payload_tail_preserves_actual_last_output_independent_of_progress(tmp_path: Path) -> None:
    """Loop evidence keeps actual tail lines after the final periodic progress counter."""
    import os
    core_time = 2_000_000_000.0
    payload = tmp_path / "payload.stdout"
    payload.write_text(
        "Processed 2140000 events\n"
        "Finalizing output file\n"
        "accepted 2139187 out of 2141242 events for filter EventErrorState\n"
    )
    os.utime(payload, (core_time - 7576, core_time - 7576))
    ev = acd.collect_job_log_evidence(
        tmp_path, failure_mode="hang", core_mtime=core_time, max_matches=10, tail_lines=10
    )
    activity = ev["payload_activity"]
    assert activity["last_nonempty_line"]["line"] == 3
    assert "EventErrorState" in activity["last_nonempty_line"]["text"]
    assert [item["line"] for item in activity["tail"]] == [1, 2, 3]
    assert ev["category_counts"].get("error", 0) == 0
    assert ev["category_counts"].get("progress", 0) == 3


def test_collect_job_log_evidence_reports_payload_silence_and_retained_counts(tmp_path: Path) -> None:
    """Payload mtime gap and last progress become first-class looping-job evidence."""
    import os
    core_time = 2_000_000_000.0
    payload = tmp_path / "payload.stdout"
    payload.write_text("Processed 2130000 events\nProcessed 2140000 events\n")
    os.utime(payload, (core_time - 7576, core_time - 7576))
    ev = acd.collect_job_log_evidence(
        tmp_path, failure_mode="hang", core_mtime=core_time, max_files=4, max_matches=4
    )
    assert ev["profile"] == "payload-centric" and ev["pilotlog_default_excluded"] is True
    assert ev["payload_activity"]["last_write_before_core_s"] == 7576.0
    assert ev["payload_activity"]["last_write_before_core_human"] == "2h 06m 16s"
    assert ev["payload_activity"]["latest_progress"]["text"] == "Processed 2140000 events"
    assert ev["category_counts"] == {"progress": 2}
    assert ev["category_counts_found"] == {"progress": 2}


def test_render_report_shows_targeted_frame_evidence() -> None:
    """--no-llm output exposes the focused evidence rather than hiding it in JSON."""
    evidence = acd.CoreEvidence(mode="hang", mode_source="explicit")
    evidence.targeted_threads = [{
        "thread_id": "2", "frame": 3, "state": "blocked",
        "context": "#3 in XrdCl::StreamMutex::Lock() ()",
        "args": "this = 0x123", "locals": "owner = 3",
    }]
    report = acd.render_report(evidence, None)
    assert "TARGETED FRAME EVIDENCE" in report
    assert "T2 frame 3 [BLOCKED]" in report
    assert "this = 0x123" in report and "owner = 3" in report


# --------------------------------------------------------------------------- #
# Prompts, JSON extraction and rendering
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("mode, marker", [("crash", "CRASH"), ("hang", "HANG")])
def test_build_system_prompt_is_mode_specific(mode: str, marker: str) -> None:
    """Each mode gets its own framing plus the shared schema."""
    prompt = acd.build_system_prompt(mode)
    assert marker in prompt and "Never invent stack frames" in prompt and '"verdict"' in prompt


def test_build_user_prompt_embeds_evidence() -> None:
    """The evidence bundle is serialised into the user message."""
    evidence = acd.CoreEvidence(signal="SIGSEGV")
    assert '"signal": "SIGSEGV"' in acd.build_user_prompt(evidence)


@pytest.mark.parametrize("raw", [
    '{"verdict": "ok"}',
    '```json\n{"verdict": "ok"}\n```',
    'Here you go:\n{"verdict": "ok"}\nHope that helps.',
])
def test_extract_json_object_variants(raw: str) -> None:
    """Fenced, bare and prose-wrapped JSON all parse."""
    assert acd.extract_json_object(raw) == {"verdict": "ok"}


@pytest.mark.parametrize("raw", ["not json at all", "[1, 2, 3]", ""])
def test_extract_json_object_rejects_non_objects(raw: str) -> None:
    """Non-object responses are rejected rather than half-parsed."""
    assert acd.extract_json_object(raw) is None


def test_old_json_idle_flag_maps_to_idle_state() -> None:
    """Evidence written before 0.2.1 keeps its idle/busy meaning when reloaded."""
    evidence = acd.core_evidence_from_dict({
        "thread_groups": [{
            "count": 1, "thread_ids": ["7"], "names": [],
            "backtrace": "#0 in pthread_cond_wait ()", "idle": True,
        }]
    })
    assert evidence.thread_groups[0].state == "idle"


def test_render_report_no_llm_lists_threads() -> None:
    """The evidence-only report summarises thread groups."""
    evidence = acd.CoreEvidence(signal="SIGSEGV", thread_count=3)
    evidence.core_file = {"path": "/tmp/core.1", "size_human": "1.0 MiB"}
    evidence.executable = {"path": "/usr/bin/python3", "source": "AT_EXECFN"}
    evidence.thread_groups = [acd.ThreadGroup(count=2, thread_ids=["1"], names=[],
                                              backtrace="#0  0x1 in findTracks ()", idle=False)]
    report = acd.render_report(evidence, None)
    assert "no-llm" in report and "findTracks" in report and "[BUSY]" in report


def test_render_report_includes_all_analysis_fields() -> None:
    """Every populated analysis field reaches the report."""
    evidence = acd.CoreEvidence(signal="SIGQUIT", mode="hang")
    analysis = {
        "verdict": "Stuck in an unbounded loop.",
        "classification": "hang", "confidence": "high", "confidence_reason": "Python frames present.",
        "likely_cause": "merge_hits never terminates.", "culprit_component": "Reco.py",
        "busy_threads": "One thread in merge_hits.",
        "supporting_evidence": ["py-bt shows merge_hits"], "limitations": ["No debug symbols for libFoo"],
        "next_steps": ["Fix the loop bound"], "explanation": "The job never finished.",
        "_meta": {"model": "claude-sonnet-4-6", "input_tokens": 10, "output_tokens": 20},
    }
    report = acd.render_report(evidence, analysis)
    for expected in ("Stuck in an unbounded loop.", "merge_hits never terminates.", "Reco.py",
                     "py-bt shows merge_hits", "No debug symbols for libFoo", "Fix the loop bound",
                     "claude-sonnet-4-6"):
        assert expected in report


def test_render_report_surfaces_warnings() -> None:
    """Evidence-quality warnings are shown prominently."""
    evidence = acd.CoreEvidence(warnings=["The core file is truncated."])
    assert "truncated" in acd.render_report(evidence, None)


# --------------------------------------------------------------------------- #
# Budget, model selection and the LLM call
# --------------------------------------------------------------------------- #


def test_enforce_global_budget_drops_thread_groups() -> None:
    """Groups are shed until the payload fits, keeping at least one."""
    evidence = acd.CoreEvidence()
    evidence.thread_groups = [
        acd.ThreadGroup(count=1, thread_ids=[str(i)], names=[], backtrace="X" * 2000)
        for i in range(10)
    ]
    acd.enforce_global_budget(evidence, 5_000)
    assert 1 <= len(evidence.thread_groups) < 10
    assert "thread_groups" in evidence.truncated_sections


def test_enforce_global_budget_noop_when_small() -> None:
    """A small payload is untouched."""
    evidence = acd.CoreEvidence()
    evidence.thread_groups = [acd.ThreadGroup(count=1, thread_ids=["1"], names=[], backtrace="short")]
    acd.enforce_global_budget(evidence, 50_000)
    assert evidence.truncated_sections == []


def test_shrink_text_field_terminates_at_floor() -> None:
    """Must stop once truncate() can no longer shorten the field further.

    Regression test: the field must not report a successful shrink forever
    once it reaches a length truncate() can never actually get below.
    """
    evidence = acd.CoreEvidence()
    container = {"locals": "X" * 5000}
    iterations = 0
    while acd._shrink_text_field(container, "locals", "primary_thread.locals", evidence, floor=500):
        iterations += 1
        assert iterations < 100, "did not converge -- infinite loop regression"
    assert len(container["locals"]) <= 500 + len(acd.TRUNCATION_MARKER)


def test_enforce_global_budget_shrinks_primary_thread_when_groups_insufficient() -> None:
    """Once thread_groups bottoms out at one, the cascade keeps going.

    Regression for the gap where primary_thread/python sections alone could
    exceed the budget and nothing past "one thread group" would trim them.
    """
    evidence = acd.CoreEvidence()
    evidence.thread_groups = [acd.ThreadGroup(count=1, thread_ids=["1"], names=[], backtrace="Y" * 500)]
    evidence.primary_thread = {"locals": "L" * 20_000, "backtrace": "B" * 2_000}
    acd.enforce_global_budget(evidence, 3_000)
    assert len(evidence.thread_groups) == 1
    assert "primary_thread.locals" in evidence.truncated_sections
    assert acd._serialized_size(evidence) < 10_000


def test_enforce_global_budget_warns_when_unreachable() -> None:
    """An impossibly small budget still terminates, with a warning recorded."""
    evidence = acd.CoreEvidence()
    evidence.thread_groups = [acd.ThreadGroup(count=1, thread_ids=["1"], names=[], backtrace="Z" * 3_000)]
    evidence.primary_thread = {"backtrace": "B" * 3_000}
    acd.enforce_global_budget(evidence, 10)
    assert any("budget" in warning for warning in evidence.warnings)


def test_cap_user_prompt_noop_when_within_limit() -> None:
    """A prompt already under the hard cap is returned unchanged."""
    evidence = acd.CoreEvidence()
    assert acd._cap_user_prompt("short prompt", 1_000, evidence) == "short prompt"
    assert evidence.warnings == []


def test_cap_user_prompt_enforces_hard_ceiling() -> None:
    """An oversized prompt is truncated to max_evidence_chars * HARD_CAP_MULTIPLIER."""
    evidence = acd.CoreEvidence()
    capped = acd._cap_user_prompt("P" * 10_000, 1_000, evidence)
    assert len(capped) <= 2_000 + len("\n... [TRUNCATED FOR COST PROTECTION] ...")
    assert any("cost cap" in warning.lower() for warning in evidence.warnings)


def test_resolve_model_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """--model beats CORE_ANALYSIS_MODEL, which beats LLM_DEFAULT_MODEL."""
    monkeypatch.setenv("CORE_ANALYSIS_MODEL", "from-core-var")
    monkeypatch.setenv("LLM_DEFAULT_MODEL", "from-bamboo-var")
    assert acd.resolve_model("explicit") == "explicit"
    assert acd.resolve_model(None) == "from-core-var"
    monkeypatch.delenv("CORE_ANALYSIS_MODEL")
    assert acd.resolve_model(None) == "from-bamboo-var"
    monkeypatch.delenv("LLM_DEFAULT_MODEL")
    assert acd.resolve_model(None) == acd.DEFAULT_MODEL


def _install_stub_sdk(monkeypatch: pytest.MonkeyPatch, reply: str, captured: dict[str, Any]) -> None:
    """Install a stub ``anthropic`` module that records the request.

    Args:
        monkeypatch: Pytest monkeypatch fixture.
        reply: Text the stub model should return.
        captured: Dictionary populated with the request keyword arguments.
    """
    class _Block:
        type = "text"

        def __init__(self, text: str) -> None:
            self.text = text

    class _Messages:
        def create(self, **kwargs: Any) -> Any:
            captured.update(kwargs)
            usage = types.SimpleNamespace(input_tokens=123, output_tokens=45)
            return types.SimpleNamespace(content=[_Block(reply)], usage=usage, stop_reason="end_turn")

    class _Client:
        def __init__(self, api_key: str) -> None:
            self.api_key = api_key
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=_Client))


def test_analyze_with_llm_parses_structured_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    """A well-formed JSON reply is parsed and annotated with call metadata."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured: dict[str, Any] = {}
    _install_stub_sdk(monkeypatch, json.dumps({"verdict": "Unbounded loop", "confidence": "high"}), captured)
    result = acd.analyze_with_llm(acd.CoreEvidence(mode="hang"), "claude-sonnet-4-6", 4000)
    assert result["verdict"] == "Unbounded loop"
    assert result["_meta"]["input_tokens"] == 123
    assert captured["model"] == "claude-sonnet-4-6"
    assert "HANG" in captured["system"]


def test_analyze_with_llm_tolerates_unparsable_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prose instead of JSON degrades gracefully rather than raising."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _install_stub_sdk(monkeypatch, "I could not determine the cause.", {})
    result = acd.analyze_with_llm(acd.CoreEvidence(), "claude-sonnet-4-6", 4000)
    assert "did not return parsable JSON" in result["verdict"]
    assert "could not determine" in result["explanation"]


def test_analyze_with_llm_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing key produces an actionable error."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    _install_stub_sdk(monkeypatch, "{}", {})
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
        acd.analyze_with_llm(acd.CoreEvidence(), "claude-sonnet-4-6", 4000)


def test_analyze_with_llm_wraps_transport_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """SDK failures are surfaced as RuntimeError, not raw exceptions."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    class _Failing:
        def __init__(self, api_key: str) -> None:
            self.messages = self

        def create(self, **kwargs: Any) -> Any:
            raise ConnectionError("overloaded")

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(Anthropic=_Failing))
    with pytest.raises(RuntimeError, match="Anthropic API call failed"):
        acd.analyze_with_llm(acd.CoreEvidence(), "claude-sonnet-4-6", 4000)


def test_analyze_with_llm_applies_hard_cap_even_without_budget_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """The hard cap protects the API call even if enforce_global_budget was skipped."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    captured: dict[str, Any] = {}
    _install_stub_sdk(monkeypatch, json.dumps({"verdict": "x"}), captured)
    evidence = acd.CoreEvidence(mode="hang")
    evidence.primary_thread = {"backtrace": "A" * 200_000}
    acd.analyze_with_llm(evidence, "claude-sonnet-4-6", 4000, max_evidence_chars=1_000)
    sent = captured["messages"][0]["content"]
    assert len(sent) <= 1_000 * acd.HARD_CAP_MULTIPLIER + len("\n... [TRUNCATED FOR COST PROTECTION] ...")
    assert any("cost cap" in warning.lower() for warning in evidence.warnings)


def test_analyze_with_llm_progress_logs_query_and_response(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Default progress reports both the outgoing call and the token usage."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _install_stub_sdk(monkeypatch, json.dumps({"verdict": "x"}), {})
    acd.analyze_with_llm(acd.CoreEvidence(), "claude-sonnet-4-6", 4000)
    stderr = capsys.readouterr().err
    assert "Querying" in stderr
    assert "Response received" in stderr


def test_analyze_with_llm_detail_logs_size_estimate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """-v adds a rough evidence-size/token-estimate line before the call."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    _install_stub_sdk(monkeypatch, json.dumps({"verdict": "x"}), {})
    acd.analyze_with_llm(acd.CoreEvidence(), "claude-sonnet-4-6", 4000, progress=False, detail=True)
    stderr = capsys.readouterr().err
    assert "est. input tokens" in stderr
    assert "Querying" not in stderr


# --------------------------------------------------------------------------- #
# GDB environment and Build-ID evidence
# --------------------------------------------------------------------------- #


def test_gdb_subprocess_env_removes_python_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """GDB keeps release paths but never inherits AnalysisBase Python variables."""
    monkeypatch.setenv("PYTHONHOME", "/analysisbase/python")
    monkeypatch.setenv("PYTHONPATH", "/analysisbase/site-packages")
    monkeypatch.setenv("LD_LIBRARY_PATH", "/cvmfs/lib")
    env = acd.gdb_subprocess_env()
    assert "PYTHONHOME" not in env and "PYTHONPATH" not in env
    assert env["LD_LIBRARY_PATH"] == "/cvmfs/lib"


def test_run_gdb_phase_uses_early_python_protection_and_sanitized_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The known-good -eiex setting and sanitized environment are both applied."""
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> types.SimpleNamespace:
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return types.SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setenv("PYTHONHOME", "/bad")
    monkeypatch.setenv("PYTHONPATH", "/bad/path")
    monkeypatch.setattr(acd.subprocess, "run", fake_run)
    acd.run_gdb_phase("gdb", Path("core.1"), None, "demo", [("x", "info x")], 10, progress=False)
    argv = captured["argv"]
    idx = argv.index("-eiex")
    assert argv[idx + 1] == "set python ignore-environment on"
    assert "PYTHONHOME" not in captured["env"] and "PYTHONPATH" not in captured["env"]


def test_parse_eu_unstrip_modules_realistic_lines() -> None:
    """eu-unstrip module paths and Build IDs are recovered from the real EL9 format."""
    text = (
        "0x400000+0x5000 8f6bd1573d10501aec0c3dd50446da7c9524fb86@0x400368 . . /cvmfs/python3.13\n"
        "0x146a7fd1c000+0x208fd0 e650335ac8463e9e58c04e07c6f36c5f826ed953@0x123 /lib64/libc.so.6 - libc.so.6\n"
    )
    modules = acd.parse_eu_unstrip_modules(text)
    assert modules[0]["path"] == "/cvmfs/python3.13"
    assert modules[1]["name"] == "libc.so.6"
    assert modules[1]["build_id"].startswith("e650335")

# --------------------------------------------------------------------------- #
# Progress, heartbeat and quiet/verbose logging flags
# --------------------------------------------------------------------------- #


def test_resolve_logging_flags_default_is_basic_progress_only() -> None:
    """Progress is on by default; heartbeat/detail needs -v."""
    assert acd.resolve_logging_flags(make_args()) == (True, False)


def test_resolve_logging_flags_verbose_enables_detail() -> None:
    """-v enables detail on top of the default progress."""
    assert acd.resolve_logging_flags(make_args(verbose=True)) == (True, True)


def test_resolve_logging_flags_quiet_wins_over_verbose() -> None:
    """-q suppresses everything, even if -v is also passed."""
    assert acd.resolve_logging_flags(make_args(quiet=True, verbose=True)) == (False, False)


def test_run_gdb_phase_progress_prints_start_and_finish(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """Basic phase progress prints by default, with no heartbeat needed."""
    monkeypatch.setattr(
        acd.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="ok", stderr="", returncode=0),
    )
    acd.run_gdb_phase("gdb", Path("core.1"), None, "demo", [("x", "info x")], 10)
    stderr = capsys.readouterr().err
    assert "gdb phase 'demo' starting" in stderr
    assert "gdb phase 'demo' completed" in stderr


def test_run_gdb_phase_quiet_suppresses_progress(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """progress=False silences both the start/finish lines and the heartbeat."""
    monkeypatch.setattr(
        acd.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="ok", stderr="", returncode=0),
    )
    acd.run_gdb_phase("gdb", Path("core.1"), None, "demo", [("x", "info x")], 10, progress=False, detail=True)
    assert capsys.readouterr().err == ""


def test_run_gdb_phase_detail_emits_heartbeat(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """detail=True surfaces a heartbeat while the (simulated) phase runs.

    This is the actual fix for the reported "freezes with no output" issue:
    a slow phase now prints liveness while it is still blocked in gdb.
    """
    def slow_run(*_args: Any, **_kwargs: Any) -> types.SimpleNamespace:
        time.sleep(0.05)
        return types.SimpleNamespace(stdout="ok", stderr="", returncode=0)

    monkeypatch.setattr(acd.subprocess, "run", slow_run)
    acd.run_gdb_phase(
        "gdb", Path("core.1"), None, "demo", [("x", "info x")], 10,
        progress=True, detail=True, heartbeat_interval=0.01,
    )
    assert "still running" in capsys.readouterr().err


def test_collect_evidence_warns_on_large_core(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """A core above --large-core-warning-mib gets an upfront slow-analysis note."""
    core_path = tmp_path / "core.1"
    core_path.touch()
    os.truncate(core_path, 2 * 1024 * 1024)  # 2 MiB sparse file; no real disk write
    monkeypatch.setattr(acd, "find_gdb", lambda explicit: "gdb")
    monkeypatch.setattr(acd, "gdb_version", lambda path: "GNU gdb 15.1")
    monkeypatch.setattr(
        acd, "run_gdb_phase",
        lambda *a, **k: acd.GdbPhaseResult(name="x", commands=[], stdout="", stderr=""),
    )
    monkeypatch.setattr(
        acd, "resolve_executable",
        lambda *a, **k: {"path": None, "resolved": False, "source": "none", "recorded": None, "notes": []},
    )
    args = make_args(core_file=str(core_path), large_core_warning_mib=1)
    acd.collect_evidence(args, progress=True, detail=False)
    assert "above 1 MiB" in capsys.readouterr().err


def test_collect_evidence_quiet_suppresses_all_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    """progress=False leaves stderr completely silent, for scripted use."""
    core_path = tmp_path / "core.1"
    core_path.write_bytes(b"x" * 10)
    monkeypatch.setattr(acd, "find_gdb", lambda explicit: "gdb")
    monkeypatch.setattr(acd, "gdb_version", lambda path: "GNU gdb 15.1")
    monkeypatch.setattr(
        acd, "run_gdb_phase",
        lambda *a, **k: acd.GdbPhaseResult(name="x", commands=[], stdout="", stderr=""),
    )
    monkeypatch.setattr(
        acd, "resolve_executable",
        lambda *a, **k: {"path": None, "resolved": False, "source": "none", "recorded": None, "notes": []},
    )
    args = make_args(core_file=str(core_path))
    acd.collect_evidence(args, progress=False, detail=False)
    assert capsys.readouterr().err == ""


# --------------------------------------------------------------------------- #
# Phase plan and CLI
# --------------------------------------------------------------------------- #


def test_build_phase_plan_includes_locals_by_default() -> None:
    """Locals are collected unless explicitly disabled."""
    sections = [sec for _, cmds in acd._build_phase_plan(make_args()) for sec, _ in cmds]
    assert "locals" in sections


def test_build_phase_plan_omits_locals_when_disabled() -> None:
    """--no-locals removes the locals command."""
    sections = [sec for _, cmds in acd._build_phase_plan(make_args(locals=False)) for sec, _ in cmds]
    assert "locals" not in sections and "args" in sections


def test_build_phase_plan_uses_paired_commands() -> None:
    """Every command is paired with a section name for marker emission."""
    for _, commands in acd._build_phase_plan(make_args()):
        for entry in commands:
            assert isinstance(entry, tuple) and len(entry) == 2


def test_build_phase_plan_collects_debugger_metadata() -> None:
    """Metadata includes the commands needed to explain symbol/helper quality."""
    sections = {sec for _, commands in acd._build_phase_plan(make_args()) for sec, _ in commands}
    assert {"files", "debug_file_directory", "auto_load_python_scripts"} <= sections


def test_parse_args_defaults() -> None:
    """The CLI exposes the documented defaults."""
    args = acd.parse_args(["core.123456"])
    assert args.core_file == "core.123456"
    assert args.mode == "auto" and args.locals is True and args.no_llm is False


def test_parse_args_flags() -> None:
    """Flags are wired to the expected fields."""
    args = acd.parse_args(["core.1", "--no-llm", "--no-locals", "--mode", "hang", "--max-frames", "10"])
    assert args.no_llm is True and args.locals is False and args.mode == "hang" and args.max_frames == 10


def test_parse_args_quiet_and_logging_defaults() -> None:
    """-q defaults off; heartbeat/large-core defaults match the module constants."""
    args = acd.parse_args(["core.1"])
    assert args.quiet is False
    assert args.heartbeat_interval == acd.DEFAULT_HEARTBEAT_INTERVAL
    assert args.large_core_warning_mib == acd.DEFAULT_LARGE_CORE_WARNING_MIB


def test_parse_args_quiet_flag() -> None:
    """-q/--quiet is parsed."""
    assert acd.parse_args(["core.1", "-q"]).quiet is True
    assert acd.parse_args(["core.1", "--quiet"]).quiet is True


def test_parse_args_atlas_container_options() -> None:
    """Container execution options are explicit and local remains the default."""
    assert acd.parse_args(["core.1"]).execution == "local"
    args = acd.parse_args([
        "core.1", "--execution", "atlas-container", "--job-dir", "/job",
        "--release-setup", "/job/my_release_setup.sh", "--atlas-platform", "el9",
    ])
    assert args.execution == "atlas-container" and args.job_dir == "/job"
    assert args.max_targeted_threads == acd.DEFAULT_MAX_TARGETED_THREADS



def test_parse_args_job_log_options() -> None:
    """Job-log correlation is on by default and can be bounded or disabled."""
    args = acd.parse_args(["core.1", "--job-dir", "/job", "--job-log", "pilotlog.txt",
                           "--max-job-log-files", "4", "--max-job-log-matches", "9"])
    assert args.collect_job_logs is True and args.job_log == ["pilotlog.txt"]
    assert args.max_job_log_files == 4 and args.max_job_log_matches == 9
    assert acd.parse_args(["core.1", "--no-job-logs"]).collect_job_logs is False

def test_parse_args_max_targeted_threads_can_disable_phase() -> None:
    """The focused phase can be bounded or disabled from the CLI."""
    assert acd.parse_args(["core.1", "--max-targeted-threads", "0"]).max_targeted_threads == 0


def test_container_path_maps_only_job_directory(tmp_path: Path) -> None:
    """The standard ALRB /srv bind is used and outside paths are rejected."""
    nested = tmp_path / "sub" / "core.1"
    nested.parent.mkdir()
    nested.touch()
    assert acd._container_path(nested, tmp_path) == "/srv/sub/core.1"
    with pytest.raises(RuntimeError):
        acd._container_path(Path("/elsewhere/core.1"), tmp_path)


def test_container_worker_never_references_payload_script(tmp_path: Path) -> None:
    """The generated worker invokes our analyzer, never PanDA container_script.sh."""
    args = make_args(execution="atlas-container")
    argv = acd._container_worker_args(
        args, "/srv/core.1", "/srv/worker.py", "/srv/evidence.json", "/srv/raw.txt", tmp_path
    )
    rendered = " ".join(argv)
    assert "container_script.sh" not in rendered
    assert "--execution local" in rendered and "--no-llm" in rendered
    assert "--max-targeted-threads 3" in rendered


def test_main_reports_missing_core_file(capsys: pytest.CaptureFixture[str]) -> None:
    """A missing core file exits non-zero with a clear message."""
    assert acd.main(["/nonexistent/core.1", "--no-llm"]) == 1
    assert "not found" in capsys.readouterr().err


def test_atlas_container_backend_runs_one_launcher_and_returns_host_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Container mode stages a worker, launches ALRB once, and restores the host core path."""
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    core = job_dir / "core.1"
    core.write_bytes(b"core")
    release = job_dir / "my_release_setup.sh"
    release.write_text("#!/bin/bash\n")
    alrb = tmp_path / "alrb"
    setup = alrb / "user" / "atlasLocalSetup.sh"
    setup.parent.mkdir(parents=True)
    setup.write_text("#!/bin/bash\n")
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> types.SimpleNamespace:
        calls.append((argv, kwargs))
        json_path = next(job_dir.glob(".core_dump_analyzer_evidence_*.json"))
        raw_path = next(job_dir.glob(".core_dump_analyzer_gdb_*.txt"))
        evidence = acd.CoreEvidence(
            core_file={"path": "/srv/core.1", "size_human": "0.0 MiB"},
            environment={"execution_backend": "local", "os": "AlmaLinux 9.7"},
        )
        json_path.write_text(json.dumps({"evidence": evidence.to_dict(), "analysis": None}))
        raw_path.write_text("gdb raw")
        return types.SimpleNamespace(stdout="container ok", stderr="", returncode=0)

    monkeypatch.setattr(acd.subprocess, "run", fake_run)
    args = make_args(
        core_file=str(core), execution="atlas-container", job_dir=str(job_dir),
        release_setup=str(release), atlas_local_root_base=str(alrb),
    )
    evidence, raw = acd.collect_evidence(args, progress=False)
    assert len(calls) == 1
    assert calls[0][0][:2] == ["bash", "-lc"]
    assert "container_script.sh" not in calls[0][0][2]
    assert evidence.core_file["path"] == str(core.resolve())
    assert evidence.core_file["container_path"] == "/srv/core.1"
    assert evidence.environment["execution_backend"] == "atlas-container"
    assert raw == "gdb raw"
    assert not list(job_dir.glob(".core_dump_analyzer_*"))


def test_hang_log_discovery_excludes_stale_workdir_reference_logs(tmp_path: Path) -> None:
    """Old/reference logs copied into workDir must not contaminate a looping-job diagnosis."""
    core_time = 2_000_000_000.0
    payload = tmp_path / "payload.stdout"
    payload.write_text("worker finished successfully\n")
    work = tmp_path / "workDir"
    work.mkdir()
    current = work / "tmp.stdout.current"
    current.write_text("Processed 10 events\n")
    stale = work / "log_AB_old.txt"
    stale.write_text("Package.EventLoop ERROR old test failure\n")
    os.utime(payload, (core_time - 100, core_time - 100))
    os.utime(current, (core_time - 200, core_time - 200))
    os.utime(stale, (core_time - 20_000, core_time - 20_000))

    found = acd.discover_job_logs(tmp_path, failure_mode="hang", core_mtime=core_time)
    rel = [str(path.relative_to(tmp_path)) for path in found]
    assert "payload.stdout" in rel and "workDir/tmp.stdout.current" in rel
    assert "workDir/log_AB_old.txt" not in rel


def test_payload_completion_observations_place_hang_after_eventloop() -> None:
    """Successful payload tail plus Py_Exit/XRootD stack yields a post-EventLoop observation."""
    logs = {
        "payload_activity": {
            "tail": [
                {"line": 1, "text": "Package.EventLoop INFO worker finished successfully"},
                {"line": 2, "text": "Package.EventLoop INFO current job status: 1 success, 0 failure, 0 running/unknown"},
                {"line": 3, "text": "Py:CPBaseRunner INFO Moving the analysis root file and the hist file to the top level."},
                {"line": 4, "text": "Py:CPBaseRunner INFO renaming the hist-output.root to output.root"},
            ],
            "last_nonempty_line": {"line": 4, "text": "Py:CPBaseRunner INFO renaming the hist-output.root to output.root"},
        }
    }
    primary = "Py_Exit (sts=0)\nXrdCl::DefaultEnv::Finalize()"
    obs = acd.derive_payload_log_observations(logs, primary)
    assert any("worker finished successfully" in item for item in obs)
    assert any("post-processing/output-file handling" in item for item in obs)
    assert any("after successful event processing" in item and "XRootD finalization" in item for item in obs)


def test_completion_log_category_is_distinct_from_errors(tmp_path: Path) -> None:
    """Normal EventLoop/output completion is retained as completion evidence, not an error."""
    (tmp_path / "payload.stdout").write_text(
        "Package.EventLoop INFO worker finished successfully\n"
        "Package.EventLoop INFO current job status: 1 success, 0 failure, 0 running/unknown\n"
        "Py:CPBaseRunner INFO renaming the hist-output.root to output.root\n"
    )
    ev = acd.collect_job_log_evidence(tmp_path, failure_mode="hang", max_matches=20)
    assert ev["category_counts"].get("completion") == 3
    assert ev["category_counts"].get("error", 0) == 0


def test_main_no_llm_preserves_full_evidence_despite_small_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--max-evidence-chars is an LLM cost control and must not trim --no-llm JSON/report evidence."""
    evidence = acd.CoreEvidence()
    evidence.thread_groups = [
        acd.ThreadGroup(count=1, thread_ids=[str(i)], names=[], backtrace="X" * 3000)
        for i in range(3)
    ]
    monkeypatch.setattr(acd, "collect_evidence", lambda *args, **kwargs: (evidence, ""))
    monkeypatch.setattr(acd, "render_report", lambda ev, analysis: "report")
    rc = acd.main(["core.1", "--no-llm", "--max-evidence-chars", "100", "-q"])
    assert rc == 0
    assert len(evidence.thread_groups) == 3
    assert evidence.truncated_sections == []
    assert not any("budget" in warning for warning in evidence.warnings)


def test_main_llm_budget_reduces_copy_not_canonical_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LLM input may be reduced, while the canonical evidence remains complete for JSON/reporting."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.thread_groups = [
        acd.ThreadGroup(count=1, thread_ids=[str(i)], names=[], backtrace="Y" * 3000)
        for i in range(3)
    ]
    seen: dict[str, Any] = {}
    monkeypatch.setattr(acd, "collect_evidence", lambda *args, **kwargs: (evidence, ""))
    monkeypatch.setattr(acd, "render_report", lambda ev, analysis: "report")

    def fake_analyze(ev: acd.CoreEvidence, *args: Any, **kwargs: Any) -> dict[str, Any]:
        seen["evidence"] = ev
        return {"verdict": "ok"}

    monkeypatch.setattr(acd, "analyze_with_llm", fake_analyze)
    rc = acd.main(["core.1", "--max-evidence-chars", "100", "-q"])
    assert rc == 0
    assert len(evidence.thread_groups) == 3 and evidence.truncated_sections == []
    assert seen["evidence"] is not evidence
    assert seen["evidence"].truncated_sections


def test_structured_diagnosis_high_confidence_post_eventloop_shutdown_hang() -> None:
    """Successful payload completion plus the XRootD shutdown signature yields a high-confidence classification."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.primary_thread = {
        "backtrace": (
            "#2 XrdSys::IOEvents::Poller::SendCmd(...)\n"
            "#3 XrdSys::IOEvents::Poller::Stop()\n"
            "#6 XrdCl::DefaultEnv::Finalize()\n"
            "#10 Py_Exit (sts=0)\n"
        )
    }
    evidence.thread_groups = [
        acd.ThreadGroup(
            1, ["2"], [],
            "#3 XrdCl::StreamMutex::Lock()\n#4 XrdCl::Stream::Tick(long)",
            idle=False, state="blocked",
        ),
        acd.ThreadGroup(
            1, ["3"], [],
            "#7 XrdCl::PostMaster::ForceDisconnect(...)\n#9 XrdCl::Stream::OnReadTimeout(unsigned short)",
            idle=False, state="blocked",
        ),
    ]
    evidence.job_logs = {
        "payload_activity": {
            "last_write_before_core_s": 7576.0,
            "tail": [
                {"line": 1, "text": "Package.EventLoop INFO worker finished successfully"},
                {"line": 2, "text": "Package.EventLoop INFO current job status: 1 success, 0 failure, 0 running/unknown"},
                {"line": 3, "text": "Py:CPBaseRunner INFO Moving the analysis root file and the hist file to the top level."},
                {"line": 4, "text": "Py:CPBaseRunner INFO renaming the hist-output.root to output.root"},
            ],
        }
    }

    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["available"] is True
    assert diagnosis["classification"] == "post-event-processing-shutdown-hang"
    assert diagnosis["family"] == "post-event-processing-xrootd-shutdown-hang"
    assert diagnosis["subtype"] == "poller-finalization"
    assert diagnosis["phase"] == "process-shutdown"
    assert diagnosis["component"] == "XRootD/XrdCl"
    assert diagnosis["confidence"] == "high"
    assert diagnosis["root_cause_established"] is False
    assert diagnosis["signals"]["eventloop_worker_success"] is True
    assert diagnosis["signals"]["xrootd_read_timeout_force_disconnect"] is True
    assert diagnosis["signals"]["payload_silence_before_core_s"] == 7576.0


def test_structured_diagnosis_core_only_shutdown_signature_is_medium_confidence() -> None:
    """Core-only evidence may identify the shutdown phase without claiming successful event completion."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.primary_thread = {
        "backtrace": (
            "#2 XrdSys::IOEvents::Poller::SendCmd(...)\n"
            "#3 XrdSys::IOEvents::Poller::Stop()\n"
            "#6 XrdCl::DefaultEnv::Finalize()\n"
            "#10 Py_Exit (sts=0)\n"
        )
    }
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["available"] is True
    assert diagnosis["classification"] == "shutdown-finalization-hang"
    assert diagnosis["family"] == "xrootd-shutdown-hang"
    assert diagnosis["subtype"] == "poller-finalization"
    assert diagnosis["confidence"] == "medium"
    assert diagnosis["root_cause_established"] is False


def test_structured_diagnosis_does_not_force_unmatched_cases() -> None:
    """Unmatched crash/other states stay explicitly unclassified."""
    evidence = acd.CoreEvidence(mode="crash", signal="SIGSEGV")
    evidence.primary_thread = {"backtrace": "#0 crash_here()"}
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["available"] is False
    assert diagnosis["classification"] == "unclassified"
    assert diagnosis["confidence"] == "low"


def test_no_llm_report_renders_structured_diagnosis() -> None:
    """The machine-readable diagnosis is also visible in the deterministic human report."""
    evidence = acd.CoreEvidence(mode="hang", mode_source="explicit")
    evidence.core_file = {"path": "core.1", "size_human": "1 MiB"}
    evidence.executable = {"path": "/bin/python", "source": "command-line"}
    evidence.diagnosis = {
        "available": True,
        "classification": "post-event-processing-shutdown-hang",
        "family": "post-event-processing-xrootd-shutdown-hang",
        "subtype": "poller-finalization",
        "phase": "process-shutdown",
        "component": "XRootD/XrdCl",
        "confidence": "high",
        "root_cause_established": False,
        "summary": "Event processing completed successfully and shutdown hung.",
        "limitations": ["Exact lock cycle is not proven."],
    }
    report = acd.render_report(evidence, None)
    assert "DETERMINISTIC DIAGNOSIS" in report
    assert "post-event-processing-shutdown-hang" in report
    assert "Family        : post-event-processing-xrootd-shutdown-hang" in report
    assert "Subtype       : poller-finalization" in report
    assert "Root cause    : not established" in report
    assert "Exact lock cycle is not proven." in report


def test_process_identity_payload_despite_gdb_executable_warning() -> None:
    """Core-recorded EWRun command plus Python/ROOT/XRootD stack identifies the payload independently of symbol warning."""
    evidence = acd.CoreEvidence(
        generated_by=(
            "/cvmfs/atlas/.../bin/python /srv/workDir/usr/UserAnalysis/1.0.0/"
            "InstallArea/x86_64-el9-gcc15-opt/bin/EWRun.py --analysis SUSYSS3L"
        ),
        warnings=["gdb reports the core may not match the executable. Symbols may be misleading."],
    )
    evidence.primary_thread = {
        "backtrace": "Py_Exit (sts=0)\nTROOT::CloseFiles()\nTNetXNGFile::Close()\nXrdCl::File::Close()"
    }
    identity = acd.derive_process_identity(evidence)
    assert identity["kind"] == "payload"
    assert identity["confidence"] == "high"
    assert identity["signals"]["command_looks_like_payload"] is True


def test_process_identity_prmon_from_core_command_line() -> None:
    """A prmon core should be identified from core metadata before payload-oriented interpretation."""
    evidence = acd.CoreEvidence(generated_by="/usr/bin/prmon --pid 12345 --json-summary prmon.json")
    identity = acd.derive_process_identity(evidence)
    assert identity["kind"] == "prmon"
    assert identity["confidence"] == "high"


def test_remote_file_close_shutdown_signature_classifies_second_looping_pattern() -> None:
    """Successful payload completion plus ROOT/XRootD remote-file close wait is a distinct shutdown-hang signature."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.generated_by = "/cvmfs/.../bin/python /srv/workDir/usr/UserAnalysis/1.0.0/InstallArea/x86_64-el9-gcc15-opt/bin/EWRun.py"
    evidence.primary_thread = {
        "backtrace": (
            "#3 XrdCl::StreamMutex::Lock()\n"
            "#4 XrdCl::Stream::Send(...)\n"
            "#9 XrdCl::FileStateHandler::Close(...)\n"
            "#10 XrdCl::File::Close(...)\n"
            "#12 TNetXNGFile::Close(char const*)\n"
            "#13 TROOT::CloseFiles()\n"
            "#16 Py_Exit (sts=0)\n"
        )
    }
    evidence.thread_groups = [
        acd.ThreadGroup(1, ["2"], [], "#3 XrdCl::PollerBuiltIn::ShutdownEvents(...)\n#7 XrdCl::AsyncSocketHandler::OnFault(...)", state="blocked"),
        acd.ThreadGroup(1, ["12"], [], "#3 XrdCl::StreamMutex::Lock()\n#4 XrdCl::Stream::Tick(long)", state="blocked"),
    ]
    evidence.job_logs = {
        "payload_activity": {
            "last_write_before_core_s": 7398.0,
            "tail": [
                {"line": 1, "text": "Package.EventLoop INFO worker finished successfully"},
                {"line": 2, "text": "Package.EventLoop INFO current job status: 1 success, 0 failure, 0 running/unknown"},
                {"line": 3, "text": "Py:CPBaseRunner INFO Moving the analysis root file and the hist file to the top level."},
                {"line": 4, "text": "Py:CPBaseRunner INFO renaming the hist-output.root to output.root"},
            ],
        }
    }
    evidence.process_identity = acd.derive_process_identity(evidence)
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["available"] is True
    assert diagnosis["classification"] == "post-event-processing-remote-file-close-hang"
    assert diagnosis["family"] == "post-event-processing-xrootd-shutdown-hang"
    assert diagnosis["subtype"] == "remote-file-close"
    assert diagnosis["component"] == "ROOT/XRootD"
    assert diagnosis["confidence"] == "high"
    assert diagnosis["signals"]["root_close_files"] is True
    assert diagnosis["signals"]["xrootd_remote_file_close"] is True
    assert diagnosis["root_cause_established"] is False


def test_executable_match_warning_and_no_build_ids_downgrades_diagnosis_confidence() -> None:
    """A strong shutdown classification remains available but confidence is capped when build identity is unverified."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.generated_by = "/cvmfs/.../bin/python /srv/workDir/usr/UserAnalysis/1.0.0/InstallArea/x86_64-el9-gcc15-opt/bin/EWRun.py"
    evidence.warnings = ["gdb reports the core may not match the executable. Symbols may be misleading."]
    evidence.build_ids = {"available": True, "module_count": 1, "checked": [], "mismatch_count": 0}
    evidence.primary_thread = {
        "backtrace": (
            "XrdCl::StreamMutex::Lock()\nXrdCl::Stream::Send(...)\n"
            "XrdCl::FileStateHandler::Close(...)\nXrdCl::File::Close(...)\n"
            "TNetXNGFile::Close()\nTROOT::CloseFiles()\nPy_Exit (sts=0)"
        )
    }
    evidence.job_logs = {"payload_activity": {"tail": [
        {"text": "worker finished successfully"},
        {"text": "current job status: 1 success, 0 failure, 0 running/unknown"},
        {"text": "renaming the hist-output.root to output.root"},
    ]}}
    evidence.process_identity = acd.derive_process_identity(evidence)
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["classification"] == "post-event-processing-remote-file-close-hang"
    assert diagnosis["confidence"] == "medium"
    assert diagnosis["symbol_evidence_quality"]["level"] == "degraded"
    assert any("may not match" in item for item in diagnosis["limitations"])


def test_report_does_not_present_zero_checked_build_ids_as_zero_mismatches() -> None:
    """Zero checked Build IDs is an unverified state, not a reassuring zero-mismatch result."""
    evidence = acd.CoreEvidence(mode="hang", mode_source="explicit")
    evidence.core_file = {"path": "core.1", "size_human": "1 MiB"}
    evidence.executable = {"path": "/bin/python", "source": "command-line"}
    evidence.build_ids = {"available": True, "module_count": 1, "checked": [], "mismatch_count": 0}
    evidence.process_identity = {"kind": "payload", "confidence": "high"}
    report = acd.render_report(evidence, None)
    assert "Build IDs    : UNVERIFIED" in report
    assert "0 key module(s) checked, 0 mismatch(es)" not in report
    assert "Core process : payload (high confidence)" in report


def test_prmon_identity_short_circuits_payload_diagnosis_even_with_payload_logs() -> None:
    """Payload logs in the same job directory must not turn a prmon core into a payload diagnosis."""
    evidence = acd.CoreEvidence(mode="hang", generated_by="/usr/bin/prmon --pid 1234")
    evidence.primary_thread = {"backtrace": "some monitor stack"}
    evidence.job_logs = {"payload_activity": {"tail": [
        {"text": "Package.EventLoop INFO worker finished successfully"},
        {"text": "Package.EventLoop INFO current job status: 1 success, 0 failure, 0 running/unknown"},
        {"text": "Py:CPBaseRunner INFO renaming the hist-output.root to output.root"},
    ]}}
    evidence.process_identity = acd.derive_process_identity(evidence)
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert diagnosis["available"] is True
    assert diagnosis["classification"] == "monitor-process-core"
    assert diagnosis["component"] == "prmon"
    assert diagnosis["payload_diagnosis_applicable"] is False


def test_unknown_process_plus_degraded_symbols_refuses_stack_classification() -> None:
    """Do not classify plausible-looking stacks when neither process nor symbol identity is trustworthy."""
    evidence = acd.CoreEvidence(mode="hang")
    evidence.warnings = ["gdb reports the core may not match the executable. Symbols may be misleading."]
    evidence.build_ids = {"available": True, "module_count": 1, "checked": [], "mismatch_count": 0}
    evidence.primary_thread = {
        "backtrace": "XrdCl::StreamMutex::Lock()\nXrdCl::Stream::Send()\nXrdCl::FileStateHandler::Close()\nXrdCl::File::Close()\nTNetXNGFile::Close()\nTROOT::CloseFiles()\nPy_Exit (sts=0)"
    }
    evidence.process_identity = acd.derive_process_identity(evidence)
    diagnosis = acd.derive_structured_diagnosis(evidence)
    assert evidence.process_identity["kind"] == "unknown"
    assert diagnosis["available"] is False
    assert diagnosis["classification"] == "unclassified"
    assert "refusing to classify" in diagnosis["reason"]


def test_saved_looping_cases_share_family_but_have_distinct_subtypes() -> None:
    """The two validated looping jobs should cluster into one family without losing subtype detail."""
    import json
    from pathlib import Path

    fixtures = [
        (Path("/mnt/data/core-analysis7.json"), "poller-finalization"),
        (Path("/mnt/data/core-analysis9.json"), "remote-file-close"),
    ]
    for path, expected_subtype in fixtures:
        data = json.loads(path.read_text())["evidence"]
        evidence = acd.CoreEvidence(mode=data.get("mode", "hang"))
        evidence.generated_by = data.get("generated_by")
        evidence.primary_thread = data.get("primary_thread", {})
        evidence.thread_groups = [
            acd.ThreadGroup(
                item.get("count", 1),
                item.get("thread_ids", []),
                item.get("names", []),
                item.get("backtrace", ""),
                idle=item.get("idle", False),
                state=item.get("state", "active"),
            )
            for item in data.get("thread_groups", [])
        ]
        evidence.targeted_threads = data.get("targeted_threads", [])
        evidence.job_logs = data.get("job_logs", {})
        evidence.warnings = data.get("warnings", [])
        evidence.build_ids = data.get("build_ids", {})
        evidence.process_identity = data.get("process_identity", {}) or acd.derive_process_identity(evidence)
        diagnosis = acd.derive_structured_diagnosis(evidence)
        assert diagnosis["family"] == "post-event-processing-xrootd-shutdown-hang"
        assert diagnosis["subtype"] == expected_subtype
        assert diagnosis["root_cause_established"] is False
