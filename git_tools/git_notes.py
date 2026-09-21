#!/usr/bin/env python3

import argparse
import subprocess
import sys
from pathlib import Path

""" Show the latest GitHub repository commit notes. """

def main():
    parser = argparse.ArgumentParser(
        description="Show the latest GitHub repository commit notes."
    )
    parser.add_argument(
        "--target-directory",
        "-d",
        type=Path,
        default=Path.cwd(),
        help="Git repository directory (default: current directory)",
    )

    args = parser.parse_args()
    target = args.target_directory.resolve()

    if not target.is_dir():
        print(f"Error: directory does not exist: {target}", file=sys.stderr)
        sys.exit(1)

    try:
        result = subprocess.run(
            ["git", "log", "-1", "--pretty=format:%h %s%n%b"],
            cwd=target,
            capture_output=True,
            text=True,
            check=True,
        )

        print(result.stdout)

    except subprocess.CalledProcessError:
        print(
            f"Error: '{target}' does not appear to be a Git repository.",
            file=sys.stderr,
        )
        sys.exit(1)

    except FileNotFoundError:
        print("Error: Git is not installed or is not in PATH.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
