#!/usr/bin/env bash
# scripts/pytest_report.sh
#
# Unified pytest runner that produces:
# - human-readable console log (.txt)
# - machine-readable structured report (.json)
# - test collection inventory (__collect.txt)
#
# Usage:
#   ./scripts/pytest_report.sh fast
#   ./scripts/pytest_report.sh integration
#   ./scripts/pytest_report.sh full

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
: "${COVERAGE_PROCESS_START:=$PWD/pyproject.toml}"

MODE="${1:-fast}"
OUTDIR="${2:-doc/test-report}"

case "$MODE" in
  fast)
    MARKS='unit or component'
    ;;
  integration)
    MARKS='integration and not slow and not live_discord'
    ;;
  full)
    MARKS='not live_discord'
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Valid modes: fast | integration | full"
    exit 2
    ;;
esac

# Resolve version from source of truth
VERSION_FILE="src/dar_backup/__about__.py"

if [[ ! -f "$VERSION_FILE" ]]; then
  echo "ERROR: version file not found: $VERSION_FILE"
  exit 3
fi

VER="$(python - <<'PY'
from pathlib import Path

ns = {}
exec(Path("src/dar_backup/__about__.py").read_text(), ns)
print(ns["__version__"])
PY
)"

TS="$(date -u +%Y-%m-%dT%H-%M-%SZ)"

mkdir -p "$OUTDIR"

BASE="${OUTDIR}/dar-backup-${VER}__pytest-${MODE}__${TS}"

TXT="${BASE}.txt"
JSON="${BASE}.json"
COLLECT="${BASE}__collect.txt"

# Ensure pytest-json-report is available
python - <<'PY'
try:
    import pytest_jsonreport  # noqa: F401
except Exception:
    raise SystemExit(
        "ERROR: pytest-json-report is required\n"
        "Install with: pip install pytest-json-report"
    )
PY

echo "=== pytest report ==="
echo "Mode:        $MODE"
echo "Markers:     $MARKS"
echo "Version:     $VER"
echo "UTC time:    $TS"
echo

# Define coverage output next to the other artifacts
COV_XML="${OUTDIR}/coverage.xml"

# 1) Collection inventory (skip coverage to avoid noisy reports)
pytest -q --collect-only --no-cov -m "$MARKS" | tee "$COLLECT"

# 2) Execution (TXT + JSON)
pytest -q -m "$MARKS" \
  --json-report \
  --json-report-file="$JSON" \
  | tee "$TXT"

# 3) Coverage XML (only if coverage data exists)
if [[ ! -f "$COV_XML" ]]; then
get_cov_data_file() {
  if [[ -n "${COVERAGE_FILE:-}" ]]; then
    echo "${COVERAGE_FILE}"
    return
  fi
  if [[ -f ".coveragerc" ]]; then
    python - <<'PY'
import configparser
cfg = configparser.ConfigParser()
cfg.read(".coveragerc")
print(cfg.get("run", "data_file", fallback=".coverage"))
PY
    return
  fi
  if [[ -f "pyproject.toml" ]]; then
    python - <<'PY'
import tomllib
from pathlib import Path

data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
tool = data.get("tool", {})
coverage = tool.get("coverage", {})
run = coverage.get("run", {})
print(run.get("data_file", ".coverage"))
PY
    return
  fi
  echo ".coverage"
}

COV_DATA_FILE="$(get_cov_data_file)"

if ls "${COV_DATA_FILE}" "${COV_DATA_FILE}".* >/dev/null 2>&1; then
  coverage combine || true
  coverage xml -i -o "$COV_XML"
  echo "Coverage XML written to file $COV_XML"

  # Cleanup intermediate coverage data
  rm -f "${COV_DATA_FILE}" "${COV_DATA_FILE}".*
else
  echo "Coverage data not found (${COV_DATA_FILE}*); skipping coverage xml generation"
fi
fi

echo
echo "Reports written:"
echo "  $TXT"
echo "  $JSON"
echo "  $COLLECT"
if [[ -f "$COV_XML" ]]; then
  echo "  $COV_XML"
fi
