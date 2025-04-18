"""
source code is here: https://github.com/per2jensen/dar-backup/blob/main/track_downloads.py


LICENSE:  MIT License
"""

import json
import subprocess
from datetime import datetime, timedelta, UTC
from pathlib import Path


# --- CONFIGURATION ---
PACKAGE_NAME = "pypi-package"
SEED_TOTAL = 1234  # 👈 Change this to your known historical total
JSON_FILE = Path("downloads.json")
README_FILE = Path("README.md")
MARKER = "<!--TOTAL_DOWNLOADS-->"


def get_yesterday_date() -> str:
    """Return yesterday's date in ISO format (UTC)."""
    return (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%d")


def fetch_downloads_last_day(package: str) -> int:
    """Run `pypistats recent <package> --json` and return last_day count."""
    try:
        result = subprocess.run(
            ["pypistats", "recent", package, "--json"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        return data["data"]["last_day"]
    except Exception as e:
        print(f"Error fetching download data: {e}")
        return 0


def load_download_data() -> dict:
    """Load or initialize the download JSON with a seed value."""
    if JSON_FILE.exists():
        with open(JSON_FILE, "r") as f:
            return json.load(f)
    print(f"{JSON_FILE} not found. Starting with seed total: {SEED_TOTAL}")
    return {"total": SEED_TOTAL, "history": []}


def save_download_data(data: dict):
    """Save the updated download data to disk."""
    with open(JSON_FILE, "w") as f:
        json.dump(data, f, indent=2)


def update_readme(total: int, flagged: bool = False):
    """
    Update the README with the total downloads.
    
    Arguments:
      total -- Total download count to be inserted.
      flagged -- Boolean indicating if the count is repeated.
    """
    if not README_FILE.exists():
        print("README.md not found.")
        return

    lines = README_FILE.read_text().splitlines()
    updated = False

    for i, line in enumerate(lines):
        if MARKER in line:
            lines[i] = line.replace(
                MARKER,
                f"{MARKER} 📦 Total PyPI downloads: {total}" + (" ⚠️ Repeated count" if flagged else "")
            )
            updated = True
            break

    if updated:
        README_FILE.write_text("\n".join(lines) + "\n")
        print("README.md updated.")
    else:
        print("Marker not found in README.md.")


def main():
    yesterday = get_yesterday_date()
    count = fetch_downloads_last_day(PACKAGE_NAME)
    print(f"Fetched {count} downloads for {yesterday}.")

    data = load_download_data()

    # Avoid duplicate entries
    if any(entry["date"] == yesterday for entry in data["history"]):
        print(f"Already recorded downloads for {yesterday}. Skipping.")
        return

    flagged = False
    entry = {"date": yesterday, "count": count}
    if len(data["history"]) >= 1 and data["history"][-1]["count"] == count:
        flagged = True
        entry["flagged"] = True
        print(f"⚠️ Warning: Download count repeated ({count}) on {yesterday}")
    data["total"] += count
    data["history"].append(entry)
    save_download_data(data)
    update_readme(data["total"], flagged=flagged)
    print(f"Recorded {count} downloads for {yesterday}. Total: {data['total']}")


if __name__ == "__main__":
    main()