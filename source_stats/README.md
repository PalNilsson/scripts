# Python Source Statistics

`python_source_stats.py` recursively analyzes a Python source tree and prints
per-file statistics followed by project totals and rankings. It uses only the
Python standard library and runs on Python 3.10 or newer.

The report includes:

- full file paths and sizes;
- total, blank, comment-only, and source-code line counts;
- function and class counts;
- an aggregate cyclomatic-complexity estimate;
- total file and directory counts;
- a breakdown by Python file extension;
- the largest files and the files with the most lines;
- the oldest and newest modification timestamps; and
- optional per-file modification timestamps and file ages.

## Quick start

No installation or third-party packages are required.

```bash
python3 python_source_stats.py --input-dir /path/to/project
```

To make the script directly executable on macOS or Linux:

```bash
chmod +x python_source_stats.py
./python_source_stats.py --input-dir /path/to/project
```

By default, the tool analyzes `.py`, `.pyi`, and `.pyw` files. It skips common
version-control, virtual-environment, cache, build, and installed-package
directories.

## Examples

Analyze only files tracked by Git:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --git-tracked-only
```

Include only test modules while excluding integration tests:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --include-pattern "tests/test_*.py" \
  --exclude-pattern "tests/integration/**"
```

Show modification timestamps and ages, then sort newest first:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --show-modified \
  --show-age \
  --sort-by modified \
  --descending
```

Analyze files modified during a date range:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --modified-after 2026-01-01 \
  --modified-before 2026-06-30T23:59:59
```

Show only the five largest and five longest files:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --top-largest 5 \
  --top-longest 5
```

Scan every directory, including environments, caches, and build output:

```bash
python3 python_source_stats.py \
  --input-dir /path/to/project \
  --no-default-excludes
```

## Command-line arguments

| Argument | Meaning |
| --- | --- |
| `--input-dir DIRECTORY` | Root directory to scan. This argument is required. |
| `--extensions EXT [EXT ...]` | Extensions to include. Defaults to `.py .pyi .pyw`; leading dots are optional. |
| `--include-pattern GLOB` | Include only paths matching this pattern. Repeat the argument to add patterns. |
| `--exclude-pattern GLOB` | Exclude files or directories matching this pattern. Repeat the argument to add patterns. |
| `--no-default-excludes` | Disable the built-in exclusions for VCS, cache, environment, build, and package directories. |
| `--git-tracked-only` | Analyze only files returned by `git ls-files`. The input directory must be inside a Git repository. |
| `--modified-after DATE` | Include files modified at or after an ISO date or timestamp. |
| `--modified-before DATE` | Include files modified at or before an ISO date or timestamp. |
| `--show-modified` | Add each file's local modification timestamp to the main table. |
| `--show-age` | Add each file's age in days to the main table. |
| `--skip-complexity` | Skip parsing the Python AST and omit function, class, and complexity values. |
| `--sort-by FIELD` | Sort by `path`, `size`, `lines`, `code-lines`, `complexity`, or `modified`. |
| `--descending` | Reverse the selected sort order. |
| `--top-largest N` | List the N largest files. The default is 10; use 0 to hide the ranking. |
| `--top-longest N` | List the N files with the most lines. The default is 10; use 0 to hide the ranking. |
| `-h`, `--help` | Show the complete command help. |

Shells expand unquoted wildcard characters before starting a program. Quote glob
patterns such as `"tests/**"` so the tool receives them unchanged.

## Default exclusions

The default exclusion set covers:

- `.git`, `.hg`, and `.svn`;
- `.venv`, `venv`, `.tox`, and `site-packages`;
- `__pycache__`, `.mypy_cache`, `.pytest_cache`, and `.ruff_cache`; and
- `build` and `dist`.

Additional `--exclude-pattern` values are combined with these defaults. Use
`--no-default-excludes` when these directories are intentionally part of the
analysis.

Symbolic links to directories are not followed, preventing cycles and avoiding
accidental traversal outside the input tree.

## Metric definitions

### Lines

- **Lines** is the number of physical lines recognized by Python's text reader.
- **Blank** is a line containing only whitespace.
- **Comment** is a comment-only line identified with Python's tokenizer. Inline
  comments are counted as part of a source line, not as a separate comment line.
- **Code** is `Lines - Blank - Comment`.

Docstrings are Python expressions, so they count as source lines rather than
comments. Files are opened with `tokenize.open`, which honors Python encoding
declarations as defined by PEP 263.

### Functions, classes, and complexity

The script parses each file with Python's abstract syntax tree module. Function
counts include synchronous functions, asynchronous functions, methods, and
nested functions. Class counts include nested classes.

Complexity is a lightweight aggregate estimate:

```text
1 per non-empty module
+ 1 per function or method
+ decision points from branches, loops, exception handlers, Boolean chains,
  comprehensions, assertions, conditional expressions, and match cases
```

This is useful for comparing files and noticing trends, but it is not intended
to reproduce a particular third-party complexity package exactly. A file with a
syntax error still contributes size and line metrics; its AST-derived metrics
are shown as `-`, and a warning is printed.

### Directories and modification dates

During a normal scan, the directory total is the number of directories actually
traversed after exclusions. With `--git-tracked-only`, it is the number of input
directories represented by tracked files. Modification timestamps use the
computer's local time, and age is calculated at report time.

## Exit status and errors

Unreadable files and inaccessible directories are reported on standard error.
The program continues processing other files and exits with status `1` if a read
error occurred. Parser or tokenizer warnings do not stop the scan. Successful
runs exit with status `0`.

## License

Add the license of your choice before publishing the repository.
