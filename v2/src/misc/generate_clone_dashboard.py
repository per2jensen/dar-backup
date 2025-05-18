"""
Script to generate a clone dashboard from the clones.json file.

It aggregates daily clone data into weekly metrics and mark the annotations stored in the clones.json.
"""


import os
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

CLONES_FILE = "v2/doc/clones.json"
OUTPUT_PNG = "v2/doc/weekly_clones.png"

# Load clones.json
with open(CLONES_FILE, "r") as f:
    clones_data = json.load(f)

# Create DataFrame
df = pd.DataFrame(clones_data["daily"])
df['timestamp'] = pd.to_datetime(df['timestamp'])
df['week'] = df['timestamp'].dt.strftime('%Y-W%U')

# Aggregate by week
weekly_data = df.groupby('week')[['count', 'uniques']].sum().reset_index()
weekly_data = weekly_data.sort_values('week').tail(12)

# Rolling averages (3-week)
weekly_data['count_avg'] = weekly_data['count'].rolling(window=3, min_periods=1).mean()
weekly_data['uniques_avg'] = weekly_data['uniques'].rolling(window=3, min_periods=1).mean()

# Prepare week positions
weeks = weekly_data['week'].tolist()
week_dates = pd.to_datetime(weekly_data['week'] + '-1', format='%Y-W%U-%w')  # week starts (Monday)

# Extract annotation dates
annotations = clones_data.get("annotations", [])
annotation_df = pd.DataFrame(annotations)
if not annotation_df.empty:
    annotation_df['date'] = pd.to_datetime(annotation_df['date'])
    annotation_df = annotation_df.sort_values('date')

# Plot
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(weeks, weekly_data['count'], label='Total Clones', marker='o')
ax.plot(weeks, weekly_data['count_avg'], label='Total Clones (3w Avg)', linestyle='--')

ax.plot(weeks, weekly_data['uniques'], label='Unique Clones', marker='s')
ax.plot(weeks, weekly_data['uniques_avg'], label='Unique Clones (3w Avg)', linestyle=':')

# Add interpolated annotation markers
for _, row in annotation_df.iterrows():
    annotation_date = row['date']
    label = row['label']
    x_pos = 0  # default if out of range

    for i in range(len(week_dates) - 1):
        if week_dates[i] <= annotation_date < week_dates[i + 1]:
            delta = (annotation_date - week_dates[i]) / (week_dates[i + 1] - week_dates[i])
            x_pos = i + delta
            break
    else:
        if annotation_date >= week_dates.iloc[-1]:
            x_pos = len(week_dates) - 1
        elif annotation_date < week_dates.iloc[0]:
            x_pos = 0

    ax.axvline(x=x_pos, color='gray', linestyle=':', linewidth=1)
    ax.annotate(
        label,
        xy=(x_pos, ax.get_ylim()[1] * 0.85),
        xytext=(0, 5),
        textcoords='offset points',
        rotation=90,
        fontsize=10,
        ha='center',
        va='center',
        color='dimgray'
    )

# Final polish
ax.set_title("Weekly Clone Metrics (Last 12 Weeks)")
ax.set_xlabel("Week")
ax.set_ylabel("Clones")
ax.grid(True)
ax.set_xticks(range(len(weeks)))
ax.set_xticklabels(weeks, rotation=45)
ax.legend(loc="lower left", fontsize=9)
plt.tight_layout()

# Save chart
plt.savefig(OUTPUT_PNG)