"""
PyPI Total Downloads Tracker (Block Marker Edition)

Fetches total downloads without mirrors from PyPIStats
and replaces a block in README.md marked by custom START/END markers.

LICENSE: MIT
"""

import json
import subprocess
from datetime import datetime, UTC
from pathlib import Path

# --- CONFIGURATION ---
PACKAGE_NAME = "dar-backup"
JSON_FILE = Path("downloads.json")
README_FILE = Path("README.md")
START_MARKER = "<!--PYPI_TOTAL_START-->"
END_MARKER = "<!--PYPI_TOTAL_END-->"


def fetch_total_downloads_without_mirrors(package: str) -> int:
    try:
        result = subprocess.run(
            ["pypistats", "overall", package, "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        for entry in data["data"]:
            if entry["category"] == "without_mirrors":
                return entry["downloads"]
    except Exception as e:
        print(f"Error fetching download data: {e}")
    return 0


def save_download_data(total: int):
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    data = {"total": total, "fetched": today}
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved total: {total} (as of {today})")


def update_readme(total: int):
    if not README_FILE.exists():
        print("README.md not found.")
        return

    content = README_FILE.read_text()
    start = content.find(START_MARKER)
    end = content.find(END_MARKER)

    if start == -1 or end == -1 or start >= end:
        print("Start or end marker not found or malformed.")
        return

    before = content[:start + len(START_MARKER)]
    after = content[end:]

    insert_block = f"\n📦 Total PyPI downloads: {total}\n"

    updated_content = before + insert_block + after
    README_FILE.write_text(updated_content)
    print("README.md updated between markers.")


def main():
    total = fetch_total_downloads_without_mirrors(PACKAGE_NAME)
    print(f"Fetched total downloads (without mirrors): {total}")
    if total > 0:
        save_download_data(total)
        update_readme(total)
    else:
        print("No valid download count received. Skipping update.")


if __name__ == "__main__":
    main()