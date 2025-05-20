#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

""" 
Fetch clone data from GitHub API and update local JSON file,
triggered by Action `fetch_clones.json`.
The script retrieves clone statistics for the dar-backup repository
A badge on the repo README.md file will show the total number of clones.
"""
import os
import json
import requests
from collections import OrderedDict

# Constants
API_URL = "https://api.github.com/repos/per2jensen/dar-backup/traffic/clones"
CLONES_FILE = "v2/doc/clones.json"

# Load token from environment
TOKEN = os.getenv("TOKEN")
if not TOKEN:
    raise RuntimeError("TOKEN environment variable is not set.")

HEADERS = {
    "Accept": "application/json",
    "Authorization": f"Bearer {TOKEN}",
    "X-GitHub-Api-Version": "2022-11-28"
}

# Fetch clone data from GitHub API
response = requests.get(API_URL, headers=HEADERS)
response.raise_for_status()
data = response.json()

# Load existing clone data if available
if os.path.exists(CLONES_FILE):
    with open(CLONES_FILE, "r") as f:
        clones_data = json.load(f)
else:
    clones_data = {
        "annotations": [],
        "total_clones": 0,
        "unique_clones": 0,
        "daily": []
    }


# Build existing entries as a dict (timestamp → entry)
existing_entries = {entry["timestamp"]: entry for entry in clones_data.get("daily", [])}
new_entries = []

# Process and optionally update/skip each day's data
for day in data.get("clones", []):
    timestamp = day.get("timestamp")
    if not timestamp:
        continue  # skip invalid entries

    # Only add if it's new
    if timestamp not in existing_entries:
        new_entries.append({
            "timestamp": timestamp,
            "count": day["count"],
            "uniques": day["uniques"]
        })
    # Optional: detect and warn about mismatches (for debug/logging)
    elif (existing_entries[timestamp]["count"], existing_entries[timestamp]["uniques"]) != (day["count"], day["uniques"]):
        print(f"⚠️  Data mismatch at {timestamp}, skipping duplicate with different values.")


# Only update and write the file if there are new entries
if new_entries:
    print(f"Adding {len(new_entries)} new clone entries.")
    clones_data["daily"].extend(new_entries)
    clones_data["daily"].sort(key=lambda x: x["timestamp"])

    # Recalculate totals
    clones_data["total_clones"] = sum(entry["count"] for entry in clones_data["daily"])
    clones_data["unique_clones"] = sum(entry["uniques"] for entry in clones_data["daily"])

    # Reorder keys to keep annotations at the top
    ordered = OrderedDict()
    if "annotations" in clones_data:
        ordered["annotations"] = clones_data["annotations"]
    ordered["total_clones"] = clones_data["total_clones"]
    ordered["unique_clones"] = clones_data["unique_clones"]
    ordered["daily"] = clones_data["daily"]

    # Save the updated file
    with open(CLONES_FILE + ".tmp", "w") as f:
        json.dump(ordered, f, indent=2)
    os.replace(CLONES_FILE + ".tmp", CLONES_FILE)
