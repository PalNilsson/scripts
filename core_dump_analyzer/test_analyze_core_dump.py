"""Tests for :mod:`analyze_core_dump`.

The gdb-driving code is exercised against captured gdb output rather than a live
core file, so the suite runs anywhere. The Anthropic call is exercised with a
stubbed SDK module.
"""

from __future__ import annotations

import argparse
import json
import sys
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
        "max_frames": 40, "max_thread_groups": 25, "max_tokens": 4000,
        "max_evidence_chars": 50_000, "locals": True, "no_redact": False,
        "gdb": None, "gdb_timeout": 120, "no_llm": False, "json_out": None,
        "raw_gdb": None, "verbose": False,
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


def test_summarise_shared_libraries_keeps_only_unsymbolised() -> None:
    """Only libraries without symbols are retained verbatim."""
    text = (
        "0x00007f0a  0x00007f0b  Yes         /lib64/libc.so.6\n"
        "0x00007f0c  0x00007f0d  No          /lib/libFoo.so\n"
    )
    summary = acd.summarise_shared_libraries(text)
    assert summary["total_loaded"] == 2
    assert summary["without_symbols"] == ["/lib/libFoo.so"]


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


def test_parse_args_defaults() -> None:
    """The CLI exposes the documented defaults."""
    args = acd.parse_args(["core.123456"])
    assert args.core_file == "core.123456"
    assert args.mode == "auto" and args.locals is True and args.no_llm is False


def test_parse_args_flags() -> None:
    """Flags are wired to the expected fields."""
    args = acd.parse_args(["core.1", "--no-llm", "--no-locals", "--mode", "hang", "--max-frames", "10"])
    assert args.no_llm is True and args.locals is False and args.mode == "hang" and args.max_frames == 10


def test_main_reports_missing_core_file(capsys: pytest.CaptureFixture[str]) -> None:
    """A missing core file exits non-zero with a clear message."""
    assert acd.main(["/nonexistent/core.1", "--no-llm"]) == 1
    assert "not found" in capsys.readouterr().err
