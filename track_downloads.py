"""
PyPI Total Downloads Tracker (Simplified)

Fetches total downloads without mirrors from PyPIStats
and updates downloads.json and README.md accordingly.

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
MARKER = "<!--TOTAL_DOWNLOADS-->"


def fetch_total_downloads_without_mirrors(package: str) -> int:
    """Fetch total downloads without mirrors using pypistats overall --json."""
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
    """Save total download count with the fetch date."""
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    data = {"total": total, "fetched": today}
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Saved total: {total} (as of {today})")


def update_readme(total: int):
    """Replace marker in README with total download count."""
    if not README_FILE.exists():
        print("README.md not found.")
        return

    lines = README_FILE.read_text().splitlines()
    updated = False

    for i, line in enumerate(lines):
        if MARKER in line:
            lines[i] = line.replace(
                MARKER,
                f"{MARKER} 📦 Total PyPI downloads: {total}"
            )
            updated = True
            break

    if updated:
        README_FILE.write_text("\n".join(lines) + "\n")
        print("README.md updated.")
    else:
        print("Marker not found in README.md.")


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
