#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

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
import argparse
import re
import sys
from urllib.parse import quote


from collections import OrderedDict
from datetime import datetime as dt
from datetime import timezone
from clonepulse.util import show_scriptname, show_version
import clonepulse.__about__ as about

# Constants
CLONES_FILE = "clonepulse/fetch_clones.json"
MILESTONES = [500, 1000, 2000, 5000, 10000, 20000, 50000]
BADGE_DIR = "clonepulse"
BADGE_CLONES = "badge_clones.json"
# Days whose clone/unique ratio exceeds this threshold are discarded.
# Discarded days are excluded from totals, badges, milestones and the dashboard.
# Recomputed on every run — adjust this constant to change what gets filtered.
RATIO_THRESHOLD = 25



def validate_github_name(name: str, kind: str) -> str:
    if not name:
        raise argparse.ArgumentTypeError(f"{kind} name cannot be empty.")
    if len(name) > 100:
        raise argparse.ArgumentTypeError(f"{kind} name is too long.")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise argparse.ArgumentTypeError(
            f"{kind} name '{name}' contains invalid characters. "
            "Only letters, numbers, hyphens (-), underscores (_), and dots (.) are allowed."
        )
    return name



def parse_args():
    env_user = os.getenv("GITHUB_USER")
    env_repo = os.getenv("GITHUB_REPO")

    parser = argparse.ArgumentParser(
        description="Fetch GitHub clone stats for a given user and repo."
    )
    parser.add_argument(
        "--user",
        type=lambda x: validate_github_name(x, "GitHub user"),
        default=env_user,
        help="GitHub username/org (or set GITHUB_USER env var)"
    )
    parser.add_argument(
        "--repo",
        type=lambda x: validate_github_name(x, "GitHub repo"),
        default=env_repo,
        help="GitHub repository name (or set GITHUB_REPO env var)"
    )
    args = parser.parse_args()

    if not args.user:
        parser.error("GitHub user must be provided via --user or GITHUB_USER")
    if not args.repo:
        parser.error("GitHub repo must be provided via --repo or GITHUB_REPO")

    return args


def main():

    args = parse_args()
    print(f"{show_scriptname()} {about.__version__} running")
    print(f"Fetching data for repo: https://github.com/{args.user}/{args.repo}")


    # Load token from environment
    TOKEN = os.getenv("TOKEN")
    if not TOKEN:
        raise RuntimeError("TOKEN environment variable is not set. Please export your GitHub PAT as `TOKEN`.")
        
    HEADERS = {
        "Accept": "application/json",
        "Authorization": f"Bearer {TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }


    # Fetch clone data from GitHub API
    API_URL = f"https://api.github.com/repos/{quote(args.user)}/{quote(args.repo)}/traffic/clones"
    response = requests.get(API_URL, headers=HEADERS)
    response.raise_for_status()
    data = response.json()
    if not data.get("clones"):
        print("⚠️ No clone data returned from GitHub API.")
        exit(0)


    # --- Show raw API data debug info to stay in the CI log ---
    print("Raw clone data from GitHub API:")
    for day in data.get("clones", []):
        print(json.dumps(day, indent=2))


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
        try:
            timestamp = day["timestamp"]
            count = int(day["count"])
            uniques = int(day["uniques"])

            if count < 0 or uniques < 0:
                raise ValueError("Negative clone count")

            new_entry = {
                "timestamp": timestamp,
                "count": count,
                "uniques": uniques
            }
        except Exception as e:
            print(f"⚠️ Skipping invalid entry: {day} ({e})")
            continue

        # Log if updated
        if timestamp in existing_entries:
            prev = existing_entries[timestamp]
            if prev != new_entry:
                print(f"🔄 Updated {timestamp}: {prev} → {new_entry}")

        existing_entries[timestamp] = new_entry

    clones_data["daily"] = sorted(existing_entries.values(), key=lambda x: x["timestamp"])

    # --- Ratio-based discard ---
    # Compute which dates exceed RATIO_THRESHOLD (clone count / unique cloners).
    # A day with uniques == 0 and count > 0 is treated as infinite ratio and discarded.
    discarded_dates: set[str] = set()
    for entry in clones_data["daily"]:
        date = entry["timestamp"][:10]
        if entry["uniques"] > 0:
            if entry["count"] / entry["uniques"] > RATIO_THRESHOLD:
                discarded_dates.add(date)
        elif entry["count"] > 0:
            discarded_dates.add(date)

    # Mark discarded flag on each daily entry; remove stale flags when threshold changes.
    discard_list = []
    for entry in clones_data["daily"]:
        date = entry["timestamp"][:10]
        if date in discarded_dates:
            entry["discarded"] = True
            ratio = round(entry["count"] / entry["uniques"], 1) if entry["uniques"] > 0 else None
            ratio_str = f"{ratio}x" if ratio is not None else "N/A (zero uniques)"
            discard_list.append({
                "date": date,
                "count": entry["count"],
                "uniques": entry["uniques"],
                "ratio": ratio,
                "discard_reason": f"Clone/unique ratio {ratio_str} exceeds threshold {RATIO_THRESHOLD}x"
            })
            print(f"🚫 Discarding {date}: {entry['count']} clones, {entry['uniques']} uniques, ratio {ratio_str}")
        else:
            entry.pop("discarded", None)  # remove stale flag if threshold was raised

    clones_data["discard"] = discard_list

    if discarded_dates:
        print(f"⚠️  {len(discarded_dates)} day(s) discarded (ratio > {RATIO_THRESHOLD}x)")
    else:
        print(f"✅ No days discarded (ratio threshold: {RATIO_THRESHOLD}x)")

    # Recalculate totals — discarded days excluded
    clones_data["total_clones_raw"] = sum(entry["count"] for entry in clones_data["daily"])
    clones_data["total_clones"] = sum(
        entry["count"] for entry in clones_data["daily"]
        if entry["timestamp"][:10] not in discarded_dates
    )
    clones_data["unique_clones"] = sum(
        entry["uniques"] for entry in clones_data["daily"]
        if entry["timestamp"][:10] not in discarded_dates
    )

    # --- Auto-annotate the true max clone day (non-discarded entries only) ---
    valid_entries = [d for d in clones_data["daily"] if d["timestamp"][:10] not in discarded_dates]
    if valid_entries:
        # Step 1: Determine true max across all non-discarded days
        max_entry = max(valid_entries, key=lambda d: d["count"])
        max_date = max_entry["timestamp"][:10]
        max_count = max_entry["count"]

        # Step 2: Remove all previous "max" annotations
        annotations = clones_data.setdefault("annotations", [])
        before = len(annotations)
        annotations[:] = [a for a in annotations if "max" not in a["label"].lower()]

        # Step 3: Add one correct max annotation
        annotations.append({
            "date": max_date,
            "label": f"Daily max: {max_count}"
        })
        print(f"📌 Set max annotation for {max_date}: {max_count} clones (replaced {before - len(annotations) + 1} old)")
    else:
        print("ℹ️ No valid (non-discarded) clone entries — skipping max annotation.")



    # Reorder keys: annotations → totals → discard summary → daily
    ordered = OrderedDict()
    if "annotations" in clones_data:
        ordered["annotations"] = clones_data["annotations"]
    ordered["total_clones"] = clones_data["total_clones"]
    ordered["total_clones_raw"] = clones_data["total_clones_raw"]
    ordered["unique_clones"] = clones_data["unique_clones"]
    ordered["discard"] = clones_data["discard"]
    ordered["daily"] = clones_data["daily"]


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
                f.write(f"Reached {milestone} clones on {dt.now(timezone.utc).isoformat()}Z\n")
            milestones_hit.append(milestone)

    # Determine the highest milestone reached (if any)
    total_clones = clones_data["total_clones"]
    milestones_hit = [m for m in MILESTONES if total_clones >= m]


    # Optional: write a badge for the highest milestone reached
    if milestones_hit:
        last = milestones_hit[-1]

        # Convert milestone number into a compact label (1k+, 2k+, 5k+ ...)
        if last >= 1000:
            label = f"{last // 1000}k+ clones"
        else:
            # For 500 milestone
            label = f"{last}+ clones"
 
        print(f"🎯 Milestone reached: {label}")

        if last >= 2000:
            color = "red"
        elif last >= 1000:
            color = "orange"
        else:
            color = "goldenrod"

        badge = {
            "schemaVersion": 1,
            "label": "Milestone",
            "message": label,
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



# Example use:
if __name__ == "__main__":
    main()
