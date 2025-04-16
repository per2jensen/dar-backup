import json
import subprocess
from datetime import datetime

PACKAGE_NAME = "dar-backup"
DATA_FILE = "downloads.json"
README_FILE = "README.md"
MARKER = "<!--TOTAL_DOWNLOADS-->"

# Initial total downloads up to today (manual seed from pepy or Shields)
INITIAL_TOTAL = 12500  # change this to your actual known number

def get_today_downloads(package: str) -> int:
    try:
        result = subprocess.run(
            ["pypistats", "python_minor", package, "--last-day", "--json"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        return sum(row["downloads"] for row in data["data"])
    except Exception as e:
        print("Error fetching download data:", e)
        return 0

def load_data() -> dict:
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"total": INITIAL_TOTAL, "history": []}

def save_data(data: dict):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

def update_readme(total_downloads: int):
    try:
        with open(README_FILE, "r") as f:
            lines = f.readlines()

        with open(README_FILE, "w") as f:
            for line in lines:
                if line.strip().startswith(MARKER):
                    f.write(f"{MARKER} 📦 Total PyPI downloads: {total_downloads}\n")
                else:
                    f.write(line)
    except Exception as e:
        print("Could not update README:", e)

def main():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    downloads_today = get_today_downloads(PACKAGE_NAME)

    data = load_data()
    if data["history"] and data["history"][-1]["date"] == today:
        print("Already updated for today.")
        return

    data["total"] += downloads_today
    data["history"].append({"date": today, "downloads": downloads_today})
    save_data(data)
    update_readme(data["total"])
    print(f"Recorded {downloads_today} downloads for {today}. Total: {data['total']}")

if __name__ == "__main__":
    main()
