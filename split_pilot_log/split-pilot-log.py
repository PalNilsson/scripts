#!/usr/bin/env python3

import argparse
import os
import re
import sys
from pathlib import Path
from collections import OrderedDict

try:
    import resource
except ImportError:
    resource = None


TAG_RE = re.compile(rb"^ *([0-9]+): ?")


def choose_default_max_open(num_pilots: int) -> int:
    """
    Pick a conservative open-file cache size.

    We leave room for stdin/stdout/stderr, the input log, unparsed log,
    Python internals, shared libraries, etc.
    """
    fallback = 64

    if resource is None:
        return min(num_pilots, fallback)

    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)

    if soft == resource.RLIM_INFINITY:
        return min(num_pilots, 512)

    # Leave a safety margin.
    safe = max(1, soft - 64)

    return min(num_pilots, max(1, safe))


def prepare_output_dir(outdir: Path, force: bool) -> None:
    if outdir.exists():
        if not outdir.is_dir():
            raise RuntimeError(f"Output path exists but is not a directory: {outdir}")

        existing = list(outdir.iterdir())
        if existing and not force:
            raise RuntimeError(
                f"Output directory is not empty: {outdir}\n"
                f"Use --force to remove old split-pilot-log outputs first."
            )

        if force:
            for path in outdir.glob("pilot-output-*.txt"):
                path.unlink()
            for name in ("unparsed-lines.txt", "split-summary.tsv"):
                path = outdir / name
                if path.exists():
                    path.unlink()
    else:
        outdir.mkdir(parents=True)


class FileCache:
    def __init__(self, outdir: Path, max_open: int):
        self.outdir = outdir
        self.max_open = max(1, max_open)
        self.handles = OrderedDict()

    def get(self, pilot_id: int):
        if pilot_id in self.handles:
            handle = self.handles.pop(pilot_id)
            self.handles[pilot_id] = handle
            return handle

        if len(self.handles) >= self.max_open:
            _old_pilot_id, old_handle = self.handles.popitem(last=False)
            old_handle.close()

        path = self.outdir / f"pilot-output-{pilot_id}.txt"

        # Use append mode because this file may have been closed earlier
        # and later reopened by the LRU cache.
        handle = open(path, "ab", buffering=1024 * 1024)
        self.handles[pilot_id] = handle
        return handle

    def close_all(self):
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()


def split_log(
    input_path: Path,
    outdir: Path,
    num_pilots: int,
    max_open: int,
    keep_prefix: bool,
    progress_mb: int,
):
    line_counts = [0] * num_pilots
    byte_counts = [0] * num_pilots
    unparsed_count = 0
    total_lines = 0
    total_bytes = 0

    cache = FileCache(outdir, max_open)
    unparsed_path = outdir / "unparsed-lines.txt"

    progress_step = progress_mb * 1024 * 1024
    next_progress = progress_step

    try:
        with open(input_path, "rb", buffering=16 * 1024 * 1024) as infile, \
             open(unparsed_path, "wb", buffering=1024 * 1024) as unparsed:

            for line in infile:
                total_lines += 1
                total_bytes += len(line)

                match = TAG_RE.match(line)

                if not match:
                    unparsed.write(f"{total_lines}\tNO_TAG\t".encode("ascii") + line)
                    unparsed_count += 1
                    continue

                pilot_id = int(match.group(1))

                if pilot_id < 0 or pilot_id >= num_pilots:
                    unparsed.write(
                        f"{total_lines}\tBAD_PILOT_ID_{pilot_id}\t".encode("ascii") + line
                    )
                    unparsed_count += 1
                    continue

                payload = line if keep_prefix else line[match.end():]

                handle = cache.get(pilot_id)
                handle.write(payload)

                line_counts[pilot_id] += 1
                byte_counts[pilot_id] += len(payload)

                if progress_step > 0 and total_bytes >= next_progress:
                    gb = total_bytes / (1024 ** 3)
                    print(
                        f"processed {gb:.2f} GiB, {total_lines} lines",
                        file=sys.stderr,
                        flush=True,
                    )
                    while total_bytes >= next_progress:
                        next_progress += progress_step

    finally:
        cache.close_all()

    # Ensure all expected pilot files exist, even for pilots with zero lines.
    for pilot_id in range(num_pilots):
        path = outdir / f"pilot-output-{pilot_id}.txt"
        path.touch(exist_ok=True)

    summary_path = outdir / "split-summary.tsv"
    with open(summary_path, "w", encoding="utf-8") as summary:
        summary.write("pilot_id\tlines\tbytes\n")
        for pilot_id in range(num_pilots):
            summary.write(f"{pilot_id}\t{line_counts[pilot_id]}\t{byte_counts[pilot_id]}\n")

    return total_lines, total_bytes, unparsed_count, summary_path, unparsed_path


def main():
    parser = argparse.ArgumentParser(
        description="Split an intermingled PanDA Pilot log into one file per pilot."
    )
    parser.add_argument(
        "input_log",
        type=Path,
        help="Large combined pilot log file",
    )
    parser.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=Path("split-pilot-logs"),
        help="Output directory. Default: split-pilot-logs",
    )
    parser.add_argument(
        "-n",
        "--num-pilots",
        type=int,
        default=600,
        help="Number of expected pilots. Default: 600",
    )
    parser.add_argument(
        "--max-open",
        type=int,
        default=None,
        help="Maximum number of pilot output files to keep open at once. "
             "Default: auto-detect from ulimit.",
    )
    parser.add_argument(
        "--keep-prefix",
        action="store_true",
        help="Keep the leading 'NNN: ' tag in each per-pilot output file.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite previous split output files in the output directory.",
    )
    parser.add_argument(
        "--progress-mb",
        type=int,
        default=512,
        help="Print progress every N MiB. Use 0 to disable. Default: 512",
    )

    args = parser.parse_args()

    if args.num_pilots <= 0:
        parser.error("--num-pilots must be positive")

    if not args.input_log.exists():
        parser.error(f"Input log does not exist: {args.input_log}")

    max_open = args.max_open
    if max_open is None:
        max_open = choose_default_max_open(args.num_pilots)

    max_open = max(1, min(max_open, args.num_pilots))

    prepare_output_dir(args.outdir, args.force)

    print(f"input log: {args.input_log}", file=sys.stderr)
    print(f"output dir: {args.outdir}", file=sys.stderr)
    print(f"num pilots: {args.num_pilots}", file=sys.stderr)
    print(f"max open pilot files: {max_open}", file=sys.stderr)

    total_lines, total_bytes, unparsed_count, summary_path, unparsed_path = split_log(
        input_path=args.input_log,
        outdir=args.outdir,
        num_pilots=args.num_pilots,
        max_open=max_open,
        keep_prefix=args.keep_prefix,
        progress_mb=args.progress_mb,
    )

    print("", file=sys.stderr)
    print(f"done", file=sys.stderr)
    print(f"processed lines: {total_lines}", file=sys.stderr)
    print(f"processed bytes: {total_bytes}", file=sys.stderr)
    print(f"unparsed lines: {unparsed_count}", file=sys.stderr)
    print(f"summary: {summary_path}", file=sys.stderr)
    print(f"unparsed: {unparsed_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
