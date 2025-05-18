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

# Collect existing timestamps to ensure idempotency
existing_dates = {entry["timestamp"] for entry in clones_data.get("daily", [])}
new_entries = []

# Process each day's data
for day in data.get("clones", []):
    timestamp = day["timestamp"]
    if timestamp not in existing_dates:
        new_entries.append({
            "timestamp": timestamp,
            "count": day["count"],
            "uniques": day["uniques"]
        })

# Only update and write the file if there are new entries
if new_entries:
    clones_data["daily"].extend(new_entries)
    clones_data["daily"].sort(key=lambda x: x["timestamp"], reverse=True)

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
    with open(CLONES_FILE, "w") as f:
        json.dump(ordered, f, indent=2)
