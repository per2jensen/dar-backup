#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
GitHub clone dashboard that aligns weekly totals to the following Monday.

Each data point on the chart represents the total clone activity from the
previous full week (Monday–Sunday), and is plotted on the following Monday.

This ensures that weekly metrics are only reported after a full week's data
has been collected. If the program is run mid-week, the current week's data
is excluded to avoid partial reporting.

If annotations are provided, they are displayed as vertical lines on the chart.
Annotations with "bad" dates (in the future or invalid) are skipped with a warning.

The script `fetch_clones.py` imports GitHub statistics into a JSON file, which
serves as input for this dashboard.

JSON Input Format:
------------------
{
  "total_clones": 845,               // Optional: overall summary (not used in chart)
  "unique_clones": 418,              // Optional: overall summary (not used in chart)
  "daily": [                         // Required: list of daily clone stats
    {
      "timestamp": "YYYY-MM-DDTHH:MM:SSZ",  // Required: UTC ISO date (e.g., 00:00:00Z)
      "count": 30,                          // Required: total clones on that day
      "uniques": 15                         // Required: number of unique cloners
    },
    ...
  ],
  "annotations": [                   // Optional: markers to be displayed on the plot
    {
      "date": "YYYY-MM-DD",          // Required: date to place the annotation
      "label": "Your label here"     // Required: short label for the event
    },
    ...
  ]
}

Validation Requirements:
------------------------

`daily` (Required):
  Each entry must include:
    - "timestamp": A valid ISO 8601 datetime string
        • Must be parseable
        • Must not be in the future
    - "count": Integer ≥ 0
    - "uniques": Integer ≥ 0

  Entries are grouped into calendar weeks (Monday–Sunday).
  The aggregated weekly total is plotted on the Monday that follows.

`annotations` (Optional):
  A list of annotation objects:
    - "date": A valid date string in ISO 8601 format (YYYY-MM-DD) and not in the future
    - "label": A short, descriptive text label, longer labels are truncated

  These are drawn as vertical lines with labels for visual context.

`total_clones` and `unique_clones` (Optional):
  Present for summary display (e.g., badges), but not used in the chart.

"""

import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

CLONES_FILE = "v2/doc/clones.json"
OUTPUT_PNG =  "v2/doc/weekly_clones.png"

# --- Load and validate JSON ---
try:
    with open(CLONES_FILE, "r") as f:
        clones_data = json.load(f)
except Exception as e:
    raise RuntimeError(f"Failed to load or parse JSON file: {e}")

# --- Schema validation ---
# Validate and sanitize 'daily' data
raw_rows = clones_data["daily"]
validated_rows = []
now = pd.Timestamp.utcnow()

for i, row in enumerate(raw_rows):
    try:
        ts = pd.to_datetime(row["timestamp"], utc=True)
    except Exception:
        raise ValueError(f"Row {i} has invalid timestamp: {row.get('timestamp')}")

    if ts > now:
        raise ValueError(f"Row {i} timestamp is in the future: {ts}")

    count = row.get("count")
    uniques = row.get("uniques")

    if not isinstance(count, int) or count < 0:
        raise ValueError(f"Row {i} has invalid count: {count}")
    if not isinstance(uniques, int) or uniques < 0:
        raise ValueError(f"Row {i} has invalid uniques: {uniques}")

    validated_rows.append({"timestamp": ts, "count": count, "uniques": uniques})

# Safe to build DataFrame
df = pd.DataFrame(validated_rows)


# --- Create DataFrame ---
df = pd.DataFrame(clones_data["daily"])
df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
df.dropna(subset=['timestamp'], inplace=True)

# Optional: Drop future-dated entries (clock skew, etc.)
now = pd.Timestamp.utcnow().normalize()
df = df[df['timestamp'] <= now]

# Group by ISO week starting Mondays
df['week_start'] = df['timestamp'] - pd.to_timedelta(df['timestamp'].dt.weekday, unit='D')
df['week_start'] = df['week_start'].dt.normalize()

if df.empty:
    print("No valid clone data available.")
    exit(0)

# --- Aggregate weekly ---
weekly_data = df.groupby('week_start')[['count', 'uniques']].sum().reset_index()

# Remove the current (possibly incomplete) week
yesterday = pd.Timestamp.utcnow().normalize() - pd.Timedelta(days=1)
last_complete_monday = yesterday - pd.Timedelta(days=yesterday.weekday())

# Include only weeks that ended by yesterday (i.e., their Sunday ≤ yesterday)
today = pd.Timestamp.utcnow().normalize()
weekly_data = weekly_data[weekly_data['week_start'] + pd.Timedelta(days=6) < today]

# Compute rolling averages
weekly_data['count_avg'] = weekly_data['count'].rolling(window=3, min_periods=1).mean()
weekly_data['uniques_avg'] = weekly_data['uniques'].rolling(window=3, min_periods=1).mean()

# Shift week_start to the *reporting date* (following Monday)
weekly_data['report_date'] = weekly_data['week_start'] + pd.Timedelta(days=7)
weekly_data = weekly_data.sort_values('report_date').tail(12)

# --- Validate and parse annotations ---
annotations = clones_data.get("annotations", [])
valid_annotations = []
now = pd.Timestamp.utcnow().normalize()

if not isinstance(annotations, list):
    print("⚠️  'annotations' field is not a list — skipping all annotations.")
else:
    for i, ann in enumerate(annotations):
        if not isinstance(ann, dict):
            print(f"⚠️  Annotation {i} is not a dict — skipping.")
            continue
        if not {"date", "label"}.issubset(ann):
            print(f"⚠️  Annotation {i} missing 'date' or 'label' — skipping.")
            continue
        try:
            ann_date = pd.to_datetime(ann["date"], utc=True)
            if ann_date > now:
                print(f"⚠️  Annotation {i} has future date ({ann['date']}) — skipping.")
                continue
        except Exception:
            print(f"⚠️  Annotation {i} has invalid date format — skipping.")
            continue
        if not isinstance(ann["label"], str):
            print(f"⚠️  Annotation {i} label is not a string — skipping.")
            continue

        valid_annotations.append({
            "date": ann_date,
            "label": ann["label"]
        })

annotation_df = pd.DataFrame(valid_annotations).sort_values("date")

# --- Plotting ---
fig, ax = plt.subplots(figsize=(10, 5))

ax.plot(weekly_data['report_date'], weekly_data['count'], label='Total Clones', marker='o')
ax.plot(weekly_data['report_date'], weekly_data['count_avg'], label='Total Clones (3w Avg)', linestyle='--')

ax.plot(weekly_data['report_date'], weekly_data['uniques'], label='Unique Clones', marker='s')
ax.plot(weekly_data['report_date'], weekly_data['uniques_avg'], label='Unique Clones (3w Avg)', linestyle=':')

# --- Calculate max safe label length ---
fig_height_px = fig.get_size_inches()[1] * fig.dpi
max_vertical_pixels = fig_height_px / 3
pixels_per_char = 8  # estimate
max_chars = int(max_vertical_pixels // pixels_per_char)
print(f"Max annotation label characters allowed: {max_chars}")

# --- Calculate vertical placement inside plot box ---
ymin, ymax = ax.get_ylim()
label_y = ymin + 0.97 * (ymax - ymin)

for _, row in annotation_df.iterrows():
    ann_date = row['date']
    label = row['label']

    if len(label) > max_chars:
        label = label[:max_chars - 3] + "..."

    ax.axvline(x=ann_date, color='gray', linestyle=':', linewidth=1)
    ax.annotate(
        label,
        xy=(ann_date, label_y),     # anchor point
        xytext=(0, -5),             # move slightly downward
        textcoords='offset points',
        rotation=90,
        fontsize=10,
        ha='center',
        va='top',                   # anchor top, so text flows down
        color='dimgray',
        clip_on=True
    )


# --- Final plot polish ---
ax.set_title("Weekly Clone Metrics (Reported on Following Monday)")
ax.set_xlabel("Reporting Date (Monday after week ends)")
ax.set_ylabel("Clones")
ax.grid(True)
ax.set_xticks(weekly_data['report_date'])
ax.set_xticklabels([d.strftime('%Y-%m-%d') for d in weekly_data['report_date']], rotation=45)
ax.legend(loc="lower left", fontsize=9)
plt.tight_layout()


# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_PNG), exist_ok=True)
plt.savefig(OUTPUT_PNG)

# --- CI-friendly log output ---
print(f"✅ Dashboard rendered with {len(weekly_data)} weeks.")

last_week = weekly_data.iloc[-1]
start_date = last_week['week_start'].date()
end_date = (last_week['week_start'] + pd.Timedelta(days=6)).date()
report_date = last_week['report_date'].date()

print(f"📊 Latest week: {start_date} → {end_date} (reported on {report_date})")
print(f"🖼️  Output saved to: {OUTPUT_PNG}")
