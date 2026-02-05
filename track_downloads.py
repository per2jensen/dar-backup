"""
PyPI Daily Downloads Tracker

Fetches daily download counts from the PyPI Stats API and stores a
time series in downloads.json. On each run, it re-fetches the last
N days to pick up PyPI Stats corrections.
"""

import argparse
import json
import math
import urllib.request
from datetime import datetime, timedelta, UTC
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# --- CONFIGURATION ---
PACKAGE_NAME = "dar-backup"
JSON_FILE = Path("downloads.json")
PYPI_STATS_BASE = "https://pypistats.org/api"
MIRRORS = False  # False => exclude known mirrors
DEFAULT_DAYS_BACK = 31


def _read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False))


def _fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} for {url}")
        return json.loads(resp.read().decode("utf-8"))


def _fetch_overall_daily(package: str, mirrors: bool = False) -> Dict[str, int]:
    url = f"{PYPI_STATS_BASE}/packages/{package}/overall?mirrors={'true' if mirrors else 'false'}"
    payload = _fetch_json(url)
    data = payload.get("data", [])
    if not isinstance(data, Iterable):
        raise RuntimeError("Unexpected overall payload format (missing data list)")

    # When mirrors=... is supplied, API may still include the category field;
    # filter defensively to the requested series.
    category = "with_mirrors" if mirrors else "without_mirrors"
    filtered = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if "category" in item and item.get("category") != category:
            continue
        filtered.append(item)

    daily: Dict[str, int] = {}
    for item in filtered:
        date_str = item.get("date")
        downloads = item.get("downloads")
        if not date_str or downloads is None:
            continue
        daily[date_str] = int(downloads)
    return daily


def _fetch_recent(package: str) -> dict:
    url = f"{PYPI_STATS_BASE}/packages/{package}/recent"
    payload = _fetch_json(url)
    data = payload.get("data", {})
    return data if isinstance(data, dict) else {}


def _daily_list_to_map(daily_list: Iterable[dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in daily_list:
        if not isinstance(item, dict):
            continue
        ts = item.get("timestamp")
        count = item.get("count")
        if not ts or count is None:
            continue
        date_str = ts.split("T", 1)[0]
        out[date_str] = int(count)
    return out


def _merge_daily(existing: Dict[str, int], incoming: Dict[str, int], cutoff_date: datetime.date) -> Dict[str, int]:
    if not existing:
        return dict(incoming)

    for date_str, count in incoming.items():
        try:
            date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
        except ValueError:
            continue
        if date_obj >= cutoff_date or date_str not in existing:
            existing[date_str] = count
    return existing


def _build_output(
    package: str,
    daily_map: Dict[str, int],
    recent: dict,
    mirrors: bool,
    annotations: Iterable[dict],
    rollups: dict,
) -> dict:
    daily = _build_daily_list(daily_map)
    total_downloads = sum(daily_map.values())
    return {
        "package": package,
        "source": f"{PYPI_STATS_BASE}/packages/{package}/overall?mirrors={'true' if mirrors else 'false'}",
        "updated": datetime.now(UTC).strftime("%Y-%m-%d"),
        "recent": recent,
        "total_downloads": total_downloads,
        "rollups": rollups,
        "daily": daily,
        "annotations": list(annotations),
    }


def _build_daily_list(daily_map: Dict[str, int]) -> List[dict]:
    return [
        {"timestamp": f"{date_str}T00:00:00Z", "count": daily_map[date_str]}
        for date_str in sorted(daily_map.keys())
    ]


def _compute_rollups(daily: List[dict]) -> dict:
    counts = [item.get("count", 0) for item in daily]
    if not counts:
        return {"last_7_days": 0, "last_30_days": 0, "avg_7_days": 0, "avg_30_days": 0}

    def _sum_last(n: int) -> int:
        return sum(counts[-n:]) if len(counts) >= n else sum(counts)

    def _avg_last(n: int) -> float:
        window = counts[-n:] if len(counts) >= n else counts
        return round(sum(window) / len(window), 2) if window else 0.0

    return {
        "last_7_days": _sum_last(7),
        "last_30_days": _sum_last(30),
        "avg_7_days": _avg_last(7),
        "avg_30_days": _avg_last(30),
    }


def _compute_spike_annotations(
    daily: List[dict],
    window: int = 30,
    threshold_mad: float = 5.0,
    min_count: int = 50,
) -> List[dict]:
    counts = [item.get("count", 0) for item in daily]
    if len(counts) < 3:
        return []

    spikes = []
    for idx, item in enumerate(daily):
        if idx < window:
            continue
        window_counts = counts[idx - window:idx]
        if not window_counts:
            continue
        med = _median(window_counts)
        mad = _median([abs(x - med) for x in window_counts])
        scaled_mad = 1.4826 * mad
        if scaled_mad == 0:
            continue
        threshold = med + (threshold_mad * scaled_mad)
        count = item.get("count", 0)
        if count >= min_count and count > threshold:
            date_str = str(item.get("timestamp", "")).split("T", 1)[0]
            if date_str:
                spikes.append({"date": date_str, "label": f"Spike: {count} (>5*MAD)"})

    return spikes


def _median(values: List[float]) -> float:
    if not values:
        return 0.0
    values_sorted = sorted(values)
    mid = len(values_sorted) // 2
    if len(values_sorted) % 2 == 1:
        return float(values_sorted[mid])
    return (values_sorted[mid - 1] + values_sorted[mid]) / 2.0


def _merge_annotations(existing: Iterable[dict], spike_annotations: Iterable[dict]) -> List[dict]:
    manual = []
    for entry in existing or []:
        if not isinstance(entry, dict):
            continue
        label = str(entry.get("label", ""))
        if label.startswith("Spike:"):
            continue
        manual.append(entry)

    merged = manual + list(spike_annotations)
    merged.sort(key=lambda item: str(item.get("date", "")))
    return merged


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update PyPI download stats JSON.")
    parser.add_argument("--package", default=PACKAGE_NAME, help="PyPI package name.")
    parser.add_argument(
        "--days-back",
        type=int,
        default=DEFAULT_DAYS_BACK,
        help="Re-fetch this many days to capture PyPI stats corrections.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.days_back < 0:
        print("--days-back must be >= 0")
        return 2

    existing_payload = _read_json(JSON_FILE) or {}
    existing_daily_map = _daily_list_to_map(existing_payload.get("daily", []))
    existing_annotations = existing_payload.get("annotations", [])
    if not isinstance(existing_annotations, list):
        existing_annotations = []

    overall_daily = _fetch_overall_daily(args.package, mirrors=MIRRORS)
    recent = _fetch_recent(args.package)

    today = datetime.now(UTC).date()
    cutoff = today - timedelta(days=args.days_back)

    merged = _merge_daily(existing_daily_map, overall_daily, cutoff)
    daily_list = _build_daily_list(merged)
    rollups = _compute_rollups(daily_list)
    spike_annotations = _compute_spike_annotations(daily_list)
    annotations = _merge_annotations(existing_annotations, spike_annotations)

    output = _build_output(
        args.package,
        merged,
        recent,
        mirrors=MIRRORS,
        annotations=annotations,
        rollups=rollups,
    )
    if output["daily"]:
        summed = sum(item.get("count", 0) for item in output["daily"])
        if summed != output["total_downloads"]:
            print(
                f"Warning: daily sum ({summed}) does not match total_downloads "
                f"({output['total_downloads']})."
            )
    _write_json(JSON_FILE, output)

    print(
        f"Saved {len(output['daily'])} daily entries "
        f"(updated last {args.days_back} days) to {JSON_FILE}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
