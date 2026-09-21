#!/usr/bin/env python3
"""Report file and source-code statistics for a Python source tree."""

from __future__ import annotations

import argparse
import ast
import fnmatch
import os
import subprocess
import sys
import tokenize
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Iterable, Sequence


DEFAULT_EXTENSIONS = (".py", ".pyi", ".pyw")
DEFAULT_EXCLUDE_PATTERNS = (
    ".git",
    ".git/**",
    ".hg",
    ".hg/**",
    ".svn",
    ".svn/**",
    ".mypy_cache",
    ".mypy_cache/**",
    ".pytest_cache",
    ".pytest_cache/**",
    ".ruff_cache",
    ".ruff_cache/**",
    ".tox",
    ".tox/**",
    ".venv",
    ".venv/**",
    "__pycache__",
    "__pycache__/**",
    "build",
    "build/**",
    "dist",
    "dist/**",
    "site-packages",
    "site-packages/**",
    "venv",
    "venv/**",
)


@dataclass(frozen=True)
class FileStats:
    path: Path
    relative_path: Path
    extension: str
    size: int
    total_lines: int
    blank_lines: int
    comment_lines: int
    code_lines: int
    functions: int | None
    classes: int | None
    complexity: int | None
    modified: datetime
    warning: str | None = None


@dataclass(frozen=True)
class ScanResult:
    files: list[FileStats]
    directories: int
    errors: list[str]


class PythonAstMetrics(ast.NodeVisitor):
    """Collect simple structural metrics and an aggregate complexity estimate."""

    def __init__(self) -> None:
        self.functions = 0
        self.classes = 0
        self.decision_points = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions += 1
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes += 1
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.decision_points += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.decision_points += len(node.handlers)
        self.generic_visit(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self.decision_points += len(node.handlers)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.decision_points += 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.decision_points += 1 + len(node.ifs)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        for case in node.cases:
            is_default = (
                isinstance(case.pattern, ast.MatchAs)
                and case.pattern.name is None
                and case.pattern.pattern is None
            )
            if not is_default:
                self.decision_points += 1
            if case.guard is not None:
                self.decision_points += 1
        self.generic_visit(node)


def normalize_extensions(values: Sequence[str]) -> tuple[str, ...]:
    extensions: list[str] = []
    for value in values:
        extension = value.lower()
        if not extension.startswith("."):
            extension = f".{extension}"
        extensions.append(extension)
    return tuple(dict.fromkeys(extensions))


def matches_any(path: Path, patterns: Iterable[str]) -> bool:
    relative = path.as_posix()
    candidates = (relative, path.name)
    return any(
        fnmatch.fnmatchcase(candidate, pattern.replace(os.sep, "/"))
        for pattern in patterns
        for candidate in candidates
    )


def is_selected(
    relative_path: Path,
    extensions: tuple[str, ...],
    include_patterns: Sequence[str],
    exclude_patterns: Sequence[str],
) -> bool:
    if relative_path.suffix.lower() not in extensions:
        return False
    if include_patterns and not matches_any(relative_path, include_patterns):
        return False
    return not matches_any(relative_path, exclude_patterns)


def parse_datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "expected an ISO date or timestamp, for example 2026-01-31 "
            "or 2026-01-31T14:30:00"
        ) from error


def git_tracked_files(root: Path) -> list[Path]:
    try:
        git_root_text = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.PIPE,
        ).strip()
        raw_paths = subprocess.check_output(
            ["git", "-C", git_root_text, "ls-files", "-z", "--cached"],
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Git is not installed or is not on PATH") from error
    except subprocess.CalledProcessError as error:
        if isinstance(error.stderr, bytes):
            detail = error.stderr.decode(errors="replace").strip()
        else:
            detail = (error.stderr or "").strip()
        raise RuntimeError(detail or f"{root} is not inside a Git repository") from error

    git_root = Path(git_root_text).resolve()
    paths: list[Path] = []
    for raw_path in raw_paths.split(b"\0"):
        if not raw_path:
            continue
        path = (git_root / os.fsdecode(raw_path)).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            continue
        if path.is_file():
            paths.append(path)
    return paths


def walk_files(
    root: Path, exclude_patterns: Sequence[str]
) -> tuple[list[Path], int, list[str]]:
    paths: list[Path] = []
    directories = 0
    errors: list[str] = []

    def record_error(error: OSError) -> None:
        errors.append(str(error))

    for current_dir, directory_names, filenames in os.walk(
        root, followlinks=False, onerror=record_error
    ):
        directories += 1
        current_path = Path(current_dir)

        retained_directories = []
        for name in directory_names:
            candidate = current_path / name
            relative = candidate.relative_to(root)
            if candidate.is_symlink() or matches_any(relative, exclude_patterns):
                continue
            retained_directories.append(name)
        directory_names[:] = retained_directories

        paths.extend(current_path / name for name in filenames)

    return paths, directories, errors


def analyze_python_text(
    text: str, path: Path, calculate_complexity: bool
) -> tuple[int, int, int, int | None, int | None, int | None, str | None]:
    lines = text.splitlines()
    blank_lines = sum(not line.strip() for line in lines)
    comment_only_lines: set[int] = set()
    warning: str | None = None

    try:
        tokens = tokenize.generate_tokens(StringIO(text).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            row, column = token.start
            if 0 < row <= len(lines) and not lines[row - 1][:column].strip():
                comment_only_lines.add(row)
    except (IndentationError, SyntaxError, tokenize.TokenError) as error:
        warning = f"tokenization warning: {error}"

    total_lines = len(lines)
    comment_lines = len(comment_only_lines)
    code_lines = total_lines - blank_lines - comment_lines

    if not calculate_complexity:
        return (
            total_lines,
            blank_lines,
            comment_lines,
            None,
            None,
            None,
            warning,
        )

    try:
        tree = ast.parse(text, filename=str(path))
    except (SyntaxError, ValueError) as error:
        ast_warning = f"AST warning: {error}"
        warning = f"{warning}; {ast_warning}" if warning else ast_warning
        return (
            total_lines,
            blank_lines,
            comment_lines,
            None,
            None,
            None,
            warning,
        )

    metrics = PythonAstMetrics()
    metrics.visit(tree)
    complexity = (
        0
        if not tree.body
        else 1 + metrics.functions + metrics.decision_points
    )
    return (
        total_lines,
        blank_lines,
        comment_lines,
        metrics.functions,
        metrics.classes,
        complexity,
        warning,
    )


def inspect_file(path: Path, root: Path, calculate_complexity: bool) -> FileStats:
    file_stat = path.stat()
    with tokenize.open(path) as source_file:
        text = source_file.read()

    (
        total_lines,
        blank_lines,
        comment_lines,
        functions,
        classes,
        complexity,
        warning,
    ) = analyze_python_text(text, path, calculate_complexity)

    return FileStats(
        path=path.resolve(),
        relative_path=path.resolve().relative_to(root),
        extension=path.suffix.lower(),
        size=file_stat.st_size,
        total_lines=total_lines,
        blank_lines=blank_lines,
        comment_lines=comment_lines,
        code_lines=total_lines - blank_lines - comment_lines,
        functions=functions,
        classes=classes,
        complexity=complexity,
        modified=datetime.fromtimestamp(file_stat.st_mtime),
        warning=warning,
    )


def scan(args: argparse.Namespace) -> ScanResult:
    root: Path = args.input_dir
    exclude_patterns = list(args.exclude_pattern)
    if not args.no_default_excludes:
        exclude_patterns = [*DEFAULT_EXCLUDE_PATTERNS, *exclude_patterns]

    if args.git_tracked_only:
        candidates = git_tracked_files(root)
        represented_directories = {root}
        for path in candidates:
            parent = path.parent
            while parent != root and root in parent.parents:
                represented_directories.add(parent)
                parent = parent.parent
        directories = len(represented_directories)
        errors: list[str] = []
    else:
        candidates, directories, errors = walk_files(root, exclude_patterns)

    extensions = normalize_extensions(args.extensions)
    selected_paths = []
    for path in candidates:
        try:
            relative_path = path.resolve().relative_to(root)
        except (OSError, ValueError) as error:
            errors.append(f"{path}: {error}")
            continue
        if is_selected(
            relative_path,
            extensions,
            args.include_pattern,
            exclude_patterns,
        ):
            selected_paths.append(path)

    files: list[FileStats] = []
    for path in selected_paths:
        try:
            item = inspect_file(path, root, not args.skip_complexity)
        except (OSError, UnicodeError, SyntaxError) as error:
            errors.append(f"{path}: {error}")
            continue

        if args.modified_after and item.modified < args.modified_after:
            continue
        if args.modified_before and item.modified > args.modified_before:
            continue
        files.append(item)

    return ScanResult(files=files, directories=directories, errors=errors)


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def optional_number(value: int | None) -> str:
    return "-" if value is None else f"{value:,}"


def sort_files(
    files: list[FileStats], sort_by: str, descending: bool
) -> list[FileStats]:
    sort_keys = {
        "path": lambda item: item.path.as_posix().lower(),
        "size": lambda item: item.size,
        "lines": lambda item: item.total_lines,
        "code-lines": lambda item: item.code_lines,
        "complexity": lambda item: item.complexity if item.complexity is not None else -1,
        "modified": lambda item: item.modified,
    }
    return sorted(files, key=sort_keys[sort_by], reverse=descending)


def print_files(files: list[FileStats], args: argparse.Namespace) -> None:
    headings = [
        f"{'Bytes':>10}",
        f"{'Lines':>8}",
        f"{'Blank':>8}",
        f"{'Comment':>8}",
        f"{'Code':>8}",
        f"{'Funcs':>7}",
        f"{'Classes':>7}",
        f"{'Complex':>8}",
    ]
    if args.show_modified:
        headings.append(f"{'Modified':>19}")
    if args.show_age:
        headings.append(f"{'Age days':>9}")
    headings.append("Path")
    print("  ".join(headings))
    print("  ".join("-" * len(heading) for heading in headings[:-1]) + "  " + "-" * 40)

    now = datetime.now()
    for item in files:
        fields = [
            f"{item.size:10,d}",
            f"{item.total_lines:8,d}",
            f"{item.blank_lines:8,d}",
            f"{item.comment_lines:8,d}",
            f"{item.code_lines:8,d}",
            f"{optional_number(item.functions):>7}",
            f"{optional_number(item.classes):>7}",
            f"{optional_number(item.complexity):>8}",
        ]
        if args.show_modified:
            fields.append(item.modified.isoformat(sep=" ", timespec="seconds"))
        if args.show_age:
            age_days = max(0.0, (now - item.modified).total_seconds() / 86400)
            fields.append(f"{age_days:9.1f}")
        fields.append(str(item.path))
        print("  ".join(fields))


def print_extension_breakdown(
    files: list[FileStats], calculate_complexity: bool
) -> None:
    groups: dict[str, list[FileStats]] = defaultdict(list)
    for item in files:
        groups[item.extension or "[none]"].append(item)

    print("\nBreakdown by extension")
    print(
        f"{'Extension':<12} {'Files':>8} {'Bytes':>12} {'Lines':>10} "
        f"{'Code':>10} {'Comments':>10} {'Functions':>10} {'Complexity':>11}"
    )
    for extension, items in sorted(groups.items()):
        functions = sum(item.functions or 0 for item in items)
        complexity = sum(item.complexity or 0 for item in items)
        functions_display = f"{functions:10,d}" if calculate_complexity else f"{'-':>10}"
        complexity_display = (
            f"{complexity:11,d}" if calculate_complexity else f"{'-':>11}"
        )
        print(
            f"{extension:<12} {len(items):8,d} "
            f"{sum(item.size for item in items):12,d} "
            f"{sum(item.total_lines for item in items):10,d} "
            f"{sum(item.code_lines for item in items):10,d} "
            f"{sum(item.comment_lines for item in items):10,d} "
            f"{functions_display} {complexity_display}"
        )


def print_ranked_files(
    title: str,
    files: list[FileStats],
    count: int,
    metric_name: str,
    metric,
) -> None:
    if count <= 0 or not files:
        return
    print(f"\n{title}")
    for item in sorted(files, key=metric, reverse=True)[:count]:
        print(f"  {metric(item):12,d} {metric_name:<6}  {item.path}")


def print_summary(result: ScanResult, args: argparse.Namespace) -> None:
    files = result.files
    total_size = sum(item.size for item in files)
    total_lines = sum(item.total_lines for item in files)
    total_blank = sum(item.blank_lines for item in files)
    total_comments = sum(item.comment_lines for item in files)
    total_code = sum(item.code_lines for item in files)
    total_functions = sum(item.functions or 0 for item in files)
    total_classes = sum(item.classes or 0 for item in files)
    total_complexity = sum(item.complexity or 0 for item in files)
    warnings = [item for item in files if item.warning]

    print("\nSummary")
    print(f"  Input directory:  {args.input_dir}")
    print(f"  Python files:     {len(files):,}")
    print(f"  Directories:      {result.directories:,}")
    print(f"  Total size:       {total_size:,} bytes ({format_size(total_size)})")
    print(f"  Total lines:      {total_lines:,}")
    print(f"  Blank lines:      {total_blank:,}")
    print(f"  Comment lines:    {total_comments:,}")
    print(f"  Source lines:     {total_code:,}")
    if not args.skip_complexity:
        print(f"  Functions:        {total_functions:,}")
        print(f"  Classes:          {total_classes:,}")
        print(f"  Complexity:       {total_complexity:,}")
    print(f"  Analysis warnings:{len(warnings):>6,d}")
    print(f"  Read errors:      {len(result.errors):>6,d}")

    if files:
        oldest = min(files, key=lambda item: item.modified)
        newest = max(files, key=lambda item: item.modified)
        print(
            f"  Oldest modified:  {oldest.modified.isoformat(sep=' ', timespec='seconds')} "
            f"({oldest.path})"
        )
        print(
            f"  Newest modified:  {newest.modified.isoformat(sep=' ', timespec='seconds')} "
            f"({newest.path})"
        )

    print_extension_breakdown(files, not args.skip_complexity)
    print_ranked_files(
        "Largest files",
        files,
        args.top_largest,
        "bytes",
        lambda item: item.size,
    )
    print_ranked_files(
        "Files with the most lines",
        files,
        args.top_longest,
        "lines",
        lambda item: item.total_lines,
    )

    if warnings:
        print("\nAnalysis warnings", file=sys.stderr)
        for item in warnings:
            print(f"  {item.path}: {item.warning}", file=sys.stderr)
    if result.errors:
        print("\nRead errors", file=sys.stderr)
        for error in result.errors:
            print(f"  {error}", file=sys.stderr)


def non_negative_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("expected zero or a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recursively report sizes, line counts, structure, complexity, and "
            "modification data for a Python source tree."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="root directory to scan",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        default=list(DEFAULT_EXTENSIONS),
        metavar="EXT",
        help="Python filename extensions to include",
    )
    parser.add_argument(
        "--include-pattern",
        action="append",
        default=[],
        metavar="GLOB",
        help="include only matching relative paths; repeat for multiple patterns",
    )
    parser.add_argument(
        "--exclude-pattern",
        action="append",
        default=[],
        metavar="GLOB",
        help="exclude matching files or directories; repeat for multiple patterns",
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="scan normally excluded cache, environment, build, and VCS directories",
    )
    parser.add_argument(
        "--git-tracked-only",
        action="store_true",
        help="analyze only files tracked by the containing Git repository",
    )
    parser.add_argument(
        "--modified-after",
        type=parse_datetime,
        metavar="DATE",
        help="include files modified at or after this ISO date or timestamp",
    )
    parser.add_argument(
        "--modified-before",
        type=parse_datetime,
        metavar="DATE",
        help="include files modified at or before this ISO date or timestamp",
    )
    parser.add_argument(
        "--show-modified",
        action="store_true",
        help="show each file's modification timestamp",
    )
    parser.add_argument(
        "--show-age",
        action="store_true",
        help="show each file's age in days",
    )
    parser.add_argument(
        "--skip-complexity",
        action="store_true",
        help="skip AST-based function, class, and complexity analysis",
    )
    parser.add_argument(
        "--sort-by",
        choices=("path", "size", "lines", "code-lines", "complexity", "modified"),
        default="path",
        help="field used to sort the main file list",
    )
    parser.add_argument(
        "--descending",
        action="store_true",
        help="reverse the main file-list sort order",
    )
    parser.add_argument(
        "--top-largest",
        type=non_negative_integer,
        default=10,
        metavar="N",
        help="show the N largest files; use 0 to hide the section",
    )
    parser.add_argument(
        "--top-longest",
        type=non_negative_integer,
        default=10,
        metavar="N",
        help="show the N files with the most lines; use 0 to hide the section",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.input_dir = args.input_dir.expanduser().resolve()

    if not args.input_dir.is_dir():
        parser.error(f"not a directory: {args.input_dir}")
    if (
        args.modified_after
        and args.modified_before
        and args.modified_after > args.modified_before
    ):
        parser.error("--modified-after must not be later than --modified-before")

    try:
        result = scan(args)
    except RuntimeError as error:
        parser.error(str(error))

    ordered_files = sort_files(result.files, args.sort_by, args.descending)
    print_files(ordered_files, args)
    print_summary(result, args)
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
