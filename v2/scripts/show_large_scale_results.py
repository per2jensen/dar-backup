#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Parse large-scale-results.jsonl and display a human-readable summary table.

Usage:
    python3 show_large_scale_results.py [path/to/large-scale-results.jsonl]

Defaults to v2/doc/test-report/large-scale-results.jsonl relative to this script.
"""

import json
import sys
from pathlib import Path


def format_mem(v: float | None) -> str:
    """Format a memory peak value.

    Args:
        v: Peak RSS in MB, or None if unavailable.

    Returns:
        Human-readable string such as "33.1 MB" or "N/A".
    """
    if v is None:
        return "N/A"
    return f"{v:.1f} MB"


def format_gb(v: float | None) -> str:
    """Format a size value in GB.

    Args:
        v: Size in GB, or None if unavailable.

    Returns:
        Human-readable string such as "116.23" or "?".
    """
    if v is None:
        return "?"
    return f"{v:.2f}"


def load_records(path: Path) -> list[dict]:
    """Load and parse all JSONL records from a file.

    Args:
        path: Path to a newline-delimited JSON file.

    Returns:
        List of parsed record dicts (invalid lines are skipped with a warning).
    """
    records = []
    with open(path) as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"WARNING: line {i} skipped — {exc}", file=sys.stderr)
    return records


def build_rows(records: list[dict]) -> tuple[list[str], list[list[str]]]:
    """Convert records to a header list and a list of string rows.

    Args:
        records: Parsed JSONL records (any order).

    Returns:
        Tuple of (headers, rows) where every row has the same length as headers.
    """
    headers = [
        "Date", "Commit", "Result",
        "FULL(s)", "FULL(GB)", "DIFF(s)", "DIFF(GB)",
        "dar-backup", "dar", "par2", "manager", "Fail",
    ]
    rows = []
    for r in sorted(records, key=lambda x: x.get("datestamp", ""), reverse=True):
        mem = r.get("memory_mb") or {}
        rows.append([
            r.get("date", "?"),
            r.get("git_commit", "?"),
            "PASS" if r.get("passed") else "FAIL",
            str(r.get("full_elapsed_s", "?")),
            format_gb(r.get("full_size_gb")),
            str(r.get("diff_elapsed_s", "?")),
            format_gb(r.get("diff_size_gb")),
            format_mem(mem.get("dar_backup")),
            format_mem(mem.get("dar")),
            format_mem(mem.get("par2")),
            format_mem(mem.get("manager")),
            str(r.get("failures", "?")),
        ])
    return headers, rows


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a fixed-width ASCII table to stdout.

    Args:
        headers: Column header labels.
        rows: Data rows; each row must have the same number of cells as headers.
    """
    col_widths = [
        max(len(headers[i]), *(len(row[i]) for row in rows))
        for i in range(len(headers))
    ]
    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    row_fmt = "| " + " | ".join(f"{{:<{w}}}" for w in col_widths) + " |"

    print(sep)
    print(row_fmt.format(*headers))
    print(sep)
    for row in rows:
        print(row_fmt.format(*row))
    print(sep)
    print(f"\n{len(rows)} run(s) — newest first")


def main() -> None:
    """Entry point: parse args, load records, and print the table."""
    if len(sys.argv) > 1:
        path = Path(sys.argv[1])
    else:
        path = Path(__file__).parent.parent / "doc" / "test-report" / "large-scale-results.jsonl"

    if not path.exists():
        print(f"ERROR: {path} not found", file=sys.stderr)
        print(f"Usage: {sys.argv[0]} [large-scale-results.jsonl]", file=sys.stderr)
        sys.exit(1)

    records = load_records(path)
    if not records:
        print("No records found.")
        return

    headers, rows = build_rows(records)
    print_table(headers, rows)


if __name__ == "__main__":
    main()
