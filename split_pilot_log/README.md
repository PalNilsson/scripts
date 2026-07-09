# PanDA Pilot Log Splitter

A small utility for splitting a large intermingled PanDA Pilot log into one output file per pilot.

This was written for logs produced by running many PanDA Pilots in parallel, where all pilots write to a single combined stdout/stderr log and each physical line is tagged at the beginning with the pilot number, for example:

```text
  8: [07-08-26 04:05:42 UTC] create new working directory (if needed) - /path/to/workdir/8
268: [07-08-26 04:05:42 UTC] create new working directory (if needed) - /path/to/workdir/268
 36: [07-08-26 04:05:42 UTC] create new working directory (if needed) - /path/to/workdir/36
```

The splitter reads the combined log line-by-line and writes each pilot's output to a separate file:

```text
pilot-output-0.txt
pilot-output-1.txt
...
pilot-output-599.txt
```

It is designed for very large logs, including multi-GB files, and does not load the whole log into memory.

## Use case

A typical PanDA Pilot run on a large system such as Perlmutter may launch hundreds of pilots in parallel. The wrapper script may combine stdout/stderr into one large log, tagging each line with a pilot number such as `  8:`, `268:`, or `599:`.

For debugging, this combined file can be very difficult to inspect directly, especially when it is several GB in size. This tool reconstructs per-pilot logs so that each pilot can be inspected independently.

## Requirements

- Python 3.8 or newer recommended
- No external Python packages required

The script only uses the Python standard library.

## Installation

Clone the repository or copy the script into a working directory:

```bash
git clone <repository-url>
cd <repository-name>
```

Make the script executable:

```bash
chmod +x split-pilot-log.py
```

## Basic usage

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs
```

This creates an output directory named `split-pilot-logs` containing:

```text
split-pilot-logs/pilot-output-0.txt
split-pilot-logs/pilot-output-1.txt
...
split-pilot-logs/pilot-output-599.txt
split-pilot-logs/unparsed-lines.txt
split-pilot-logs/split-summary.tsv
```

By default, the leading pilot tag is removed from each per-pilot output file. For example:

```text
  8: [07-08-26 04:05:42 UTC] create new working directory ...
```

becomes:

```text
[07-08-26 04:05:42 UTC] create new working directory ...
```

in:

```text
split-pilot-logs/pilot-output-8.txt
```

## Input format

The expected line format is:

```text
<spaces><pilot number>: <message>
```

Accepted examples include:

```text
  0: message
  8: message
 36: message
268: message
599: message
```

The parser accepts any number of leading spaces before the pilot number.

## Output files

### Per-pilot logs

For each pilot ID, the script writes:

```text
pilot-output-<pilot_id>.txt
```

With the default configuration of 600 pilots, this means pilot IDs `0` through `599`.

### `split-summary.tsv`

The summary file contains one row per pilot:

```text
pilot_id    lines    bytes
0           ...      ...
1           ...      ...
...
599         ...      ...
```

This is useful for quickly identifying pilots with unusually small, unusually large, or empty logs.

Example inspection commands:

```bash
column -t split-pilot-logs/split-summary.tsv | less
sort -n -k2 split-pilot-logs/split-summary.tsv | head
sort -n -k2 split-pilot-logs/split-summary.tsv | tail
```

### `unparsed-lines.txt`

Lines that do not match the expected format are written to:

```text
unparsed-lines.txt
```

Each unparsed line is prefixed with the original line number and a reason, for example:

```text
12345    NO_TAG    original line contents
12346    BAD_PILOT_ID_900    original line contents
```

Ideally, this file should be empty. If it is not empty, inspect it with:

```bash
wc -l split-pilot-logs/unparsed-lines.txt
head -50 split-pilot-logs/unparsed-lines.txt
```

A non-empty `unparsed-lines.txt` may indicate that the wrapper sometimes emits lines without a pilot prefix, such as traceback continuation lines.

## Useful options

### Specify the number of pilots

The default is 600 pilots, corresponding to pilot IDs `0` through `599`.

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --num-pilots 600
```

For a different number of pilots:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --num-pilots 1024
```

### Keep the original pilot prefix

By default, the script removes the leading prefix such as `  8:` from each per-pilot file.

To preserve the original prefix:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --keep-prefix
```

### Reuse an existing output directory

The script refuses to write into a non-empty output directory by default, to avoid accidentally mixing old and new split logs.

To remove previous splitter outputs and rerun:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --force
```

The `--force` option removes files matching:

```text
pilot-output-*.txt
unparsed-lines.txt
split-summary.tsv
```

from the selected output directory before starting.

### Limit the number of open files

On shared login systems such as CERN lxplus, the maximum number of simultaneously open files may be limited.

The script automatically chooses a conservative value based on the current open-file limit. To explicitly limit the number of pilot output files kept open at once:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --max-open 64
```

This still creates all per-pilot output files. It simply closes and reopens files as needed.

To check the current shell limit:

```bash
ulimit -n
```

### Adjust progress reporting

By default, the script prints progress every 512 MiB processed:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --progress-mb 512
```

To report less frequently:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --progress-mb 2048
```

To disable progress messages:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --progress-mb 0
```

## Recommended workflow

Run the splitter:

```bash
./split-pilot-log.py big-combined-pilot.log -o split-pilot-logs --max-open 64
```

Check whether any lines failed to parse:

```bash
wc -l split-pilot-logs/unparsed-lines.txt
head -50 split-pilot-logs/unparsed-lines.txt
```

Inspect the summary:

```bash
column -t split-pilot-logs/split-summary.tsv | less
```

Find pilots with very small logs:

```bash
awk 'NR > 1 {print $0}' split-pilot-logs/split-summary.tsv | sort -n -k2 | head
```

Find pilots with very large logs:

```bash
awk 'NR > 1 {print $0}' split-pilot-logs/split-summary.tsv | sort -n -k2 | tail
```

Search for errors in the split logs:

```bash
grep -R "ERROR\|FATAL\|Traceback\|Exception" split-pilot-logs/pilot-output-*.txt
```

Open a specific pilot log:

```bash
less split-pilot-logs/pilot-output-268.txt
```

## Design notes

The splitter is intentionally conservative:

- It streams the input log line-by-line.
- It does not load the full log into memory.
- It writes malformed or unexpected lines to `unparsed-lines.txt` rather than guessing where they belong.
- It validates pilot IDs against the configured pilot count.
- It uses a small file-handle cache, so it can run on systems where keeping hundreds of files open is undesirable.

By default, untagged lines are not attached to the previous pilot. This is deliberate: in an intermingled parallel log, the previous physical line may belong to a different pilot.

## Limitations

This tool assumes that each physical line belonging to a pilot starts with a pilot tag, for example:

```text
123: message
```

If the combined log contains multi-line messages where only the first line has a pilot tag, continuation lines will be written to `unparsed-lines.txt`. That behavior is safer than assigning them to the wrong pilot.

## Example

Input:

```text
  8: [07-08-26 04:05:42 UTC] create new working directory - /workdir/8
268: [07-08-26 04:05:42 UTC] create new working directory - /workdir/268
  8: [07-08-26 04:05:43 UTC] starting pilot
268: [07-08-26 04:05:43 UTC] starting pilot
```

Output in `pilot-output-8.txt`:

```text
[07-08-26 04:05:42 UTC] create new working directory - /workdir/8
[07-08-26 04:05:43 UTC] starting pilot
```

Output in `pilot-output-268.txt`:

```text
[07-08-26 04:05:42 UTC] create new working directory - /workdir/268
[07-08-26 04:05:43 UTC] starting pilot
```

## Repository layout

Suggested initial repository layout:

```text
.
├── README.md
├── split-pilot-log.py
└── .gitignore
```

Suggested `.gitignore`:

```text
split-pilot-logs/
*.log
*.out
*.err
__pycache__/
```

## License

Choose the license appropriate for your project or collaboration. For internal debugging utilities, common choices include MIT, BSD-3-Clause, or Apache-2.0.
