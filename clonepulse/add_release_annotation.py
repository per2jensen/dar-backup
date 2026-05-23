#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Append a release annotation to clonepulse/fetch_clones.json.

Usage:
    python clonepulse/add_release_annotation.py 0.7.10
Produces an annotation like:
    {"date": "2025-12-03", "label": "Rel. 0.7.10"}
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path


def main(version: str) -> None:
    json_path = Path(__file__).with_name("fetch_clones.json")

    if not json_path.exists():
        raise SystemExit(f"fetch_clones.json not found at {json_path}")

    data = json.loads(json_path.read_text(encoding="utf-8"))

    annotations = data.setdefault("annotations", [])

    today = date.today().isoformat()
    label = f"Rel. {version}"

    # Avoid duplicate annotations with same label and date
    for ann in annotations:
        if ann.get("date") == today and ann.get("label") == label:
            print(f"Annotation already present for {today}: {label}")
            break
    else:
        annotations.append({"date": today, "label": label})
        data["annotations"] = annotations
        json_path.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Added release annotation: {today} → {label}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: add_release_annotation.py <version>")
    main(sys.argv[1])


