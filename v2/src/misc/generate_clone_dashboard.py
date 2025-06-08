#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
GitHub clone dashboard that aligns weekly totals to the following Monday.

Each data point on the chart corresponds to the total clone activity from the
previous full week (Monday–Sunday), and is plotted on the following Monday.

This ensures that weekly metrics are only reported after a full week's data
is available. If the program is run mid-week, the current week's data is excluded.
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

CLONES_FILE = "v2/doc/clones.json"
OUTPUT_PNG = "v2/doc/weekly_clones_final.png"

# Load clones.json
with open(CLONES_FILE, "r") as f:
    clones_data = json.load(f)

# Create DataFrame
try:
    df = pd.DataFrame(clones_data["daily"])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['week_start'] = df['timestamp'] - pd.to_timedelta(df['timestamp'].dt.weekday, unit='D')
    df['week_start'] = df['week_start'].dt.normalize()
except Exception as e:
    print(f"DataFrame: failed to process clone data: {e}")
    exit(1)
if df.empty:
    print("No clone data available.")
    exit(0)

# Aggregate by week
weekly_data = df.groupby('week_start')[['count', 'uniques']].sum().reset_index()

# Remove the incomplete final week (if current week isn't done)
latest_day = df['timestamp'].max().normalize()
last_complete_week = latest_day - pd.to_timedelta(latest_day.weekday(), unit='D')
weekly_data = weekly_data[weekly_data['week_start'] < last_complete_week]

# Rolling averages
weekly_data['count_avg'] = weekly_data['count'].rolling(window=3, min_periods=1).mean()
weekly_data['uniques_avg'] = weekly_data['uniques'].rolling(window=3, min_periods=1).mean()

# Plot reporting date: Monday after the week ends
weekly_data['report_date'] = weekly_data['week_start'] + pd.Timedelta(days=7)
weekly_data = weekly_data.sort_values('report_date').tail(12)

# Extract annotations
annotations = clones_data.get("annotations", [])
annotation_df = pd.DataFrame(annotations)
if not annotation_df.empty:
    annotation_df['date'] = pd.to_datetime(annotation_df['date'])
    annotation_df = annotation_df.sort_values('date')

# Plotting
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(weekly_data['report_date'], weekly_data['count'], label='Total Clones', marker='o')
ax.plot(weekly_data['report_date'], weekly_data['count_avg'], label='Total Clones (3w Avg)', linestyle='--')

ax.plot(weekly_data['report_date'], weekly_data['uniques'], label='Unique Clones', marker='s')
ax.plot(weekly_data['report_date'], weekly_data['uniques_avg'], label='Unique Clones (3w Avg)', linestyle=':')

# Add annotations
for _, row in annotation_df.iterrows():
    annotation_date = row['date']
    label = row['label']
    ax.axvline(x=annotation_date, color='gray', linestyle=':', linewidth=1)
    ax.annotate(
        label,
        xy=(annotation_date, ax.get_ylim()[1] * 0.85),
        xytext=(0, 5),
        textcoords='offset points',
        rotation=90,
        fontsize=10,
        ha='center',
        va='center',
        color='dimgray'
    )

# Final touches
ax.set_title("Weekly Clone Metrics (Reported on Following Monday)")
ax.set_xlabel("Reporting Date (Monday after week ends)")
ax.set_ylabel("Clones")
ax.grid(True)
ax.set_xticks(weekly_data['report_date'])
ax.set_xticklabels([d.strftime('%Y-%m-%d') for d in weekly_data['report_date']], rotation=45)
ax.legend(loc="lower left", fontsize=9)
plt.tight_layout()

# Save
plt.savefig(OUTPUT_PNG)
print(f"Clone dashboard saved to {OUTPUT_PNG}")