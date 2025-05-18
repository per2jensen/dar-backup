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

# Plot
plt.figure(figsize=(10, 5))
plt.plot(weekly_data['week'], weekly_data['count'], label='Total Clones', marker='o')
plt.plot(weekly_data['week'], weekly_data['count_avg'], label='Total Clones (3w Avg)', linestyle='--')

plt.plot(weekly_data['week'], weekly_data['uniques'], label='Unique Clones', marker='s')
plt.plot(weekly_data['week'], weekly_data['uniques_avg'], label='Unique Clones (3w Avg)', linestyle=':')

plt.title("Weekly Clone Metrics (Last 12 Weeks)")
plt.xlabel("Week")
plt.ylabel("Clones")
plt.grid(True)
plt.xticks(rotation=45)
plt.legend()
plt.tight_layout()

# Save chart
plt.savefig(OUTPUT_PNG)

