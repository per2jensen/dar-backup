#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

""" 
Fetch clone data from GitHub API and update local JSON file,
triggered by Action `fetch_clones.json`.
The script retrieves clone statistics for the dar-backup repository
A badge on the repo README.md file will show the total number of clones.
Also, it will create a badge for each milestone reached (500, 1000, 2000 clones).
"""
import datetime
import os
import json
import requests
from collections import OrderedDict

# Constants
API_URL = "https://api.github.com/repos/per2jensen/dar-backup/traffic/clones"
CLONES_FILE = "v2/doc/clones.json"
MILESTONES = [500, 1000, 2000, 5000, 10000, 20000, 50000]
BADGE_DIR = "v2/doc/badges"
BADGE_CLONES = "badge_clones.json"


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
if not data.get("clones"):
    print("⚠️ No clone data returned from GitHub API.")
    exit(0)



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

# Process and optionally update/skip each day's data
for day in data.get("clones", []):
    timestamp = day["timestamp"]
    new_entry = {
        "timestamp": timestamp,
        "count": day["count"],
        "uniques": day["uniques"]
    }

    # Log if updated
    if timestamp in existing_entries:
        prev = existing_entries[timestamp]
        if prev != new_entry:
            print(f"🔄 Updated {timestamp}: {prev} → {new_entry}")

    existing_entries[timestamp] = new_entry

clones_data["daily"] = sorted(existing_entries.values(), key=lambda x: x["timestamp"])

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


# --- Auto-annotate max clone day ---
# Find previous max
max_prev = max(clones_data["daily"], key=lambda d: d["count"])
today = datetime.date.today().isoformat()

# Get today's entry (assumes sorted and up to date)
today_entry = next((d for d in clones_data["daily"] if d["timestamp"].startswith(today)), None)

if today_entry and today_entry["count"] > max_prev["count"]:
    # Avoid duplicate annotations
    if not any(a["date"] == today and "max" in a["label"].lower() for a in clones_data.get("annotations", [])):
        clones_data.setdefault("annotations", []).append({
            "date": today,
            "label": f"🔥 New max: {today_entry['count']} clones"
        })
        print(f"📌 Annotated new max clone day: {today_entry['count']}")


# Save the updated file
with open(CLONES_FILE + ".tmp", "w") as f:
    json.dump(ordered, f, indent=2)
os.replace(CLONES_FILE + ".tmp", CLONES_FILE)


# --- Milestone Watcher ---
milestones_hit = []

for milestone in MILESTONES:
    milestone_file = os.path.join(BADGE_DIR, f"milestone_{milestone}.txt")
    if clones_data["total_clones"] >= milestone and not os.path.exists(milestone_file):
        with open(milestone_file, "w") as f:
            f.write(f"Reached {milestone} clones on {datetime.utcnow().isoformat()}Z\n")
        milestones_hit.append(milestone)

# Determine the highest milestone reached (if any)
total_clones = clones_data["total_clones"]
milestones_hit = [m for m in MILESTONES if total_clones >= m]


# Optional: write a badge for the highest milestone just reached
if milestones_hit:
    last = milestones_hit[-1]

    # Determine number of 🎉 to show
    index = MILESTONES.index(last) + 1
    celebration = "🎉" * index


    if last >= 2000:
        color = "red"
    elif last >= 1000:
        color = "orange"
    else:
        color = "yellow"

    badge = {
        "schemaVersion": 1,
        "label": "Milestone",
        "message": f"{last} clones {celebration}",
        "color": color
    }
else:
    badge = {
        "schemaVersion": 1,
        "label": "Milestone",
        "message": "Coming soon...",
        "color": "lightgray"
    }

with open(os.path.join(BADGE_DIR, "milestone_badge.json"), "w") as f:
    json.dump(badge, f, indent=2)


# --- Generate total clones badge.json ---
badge = {
    "schemaVersion": 1,
    "label": "# clones",
    "message": str(clones_data["total_clones"]),
    "color": "deeppink"
}
with open(os.path.join(BADGE_DIR, BADGE_CLONES), "w") as f:
    json.dump(badge, f, indent=2)
