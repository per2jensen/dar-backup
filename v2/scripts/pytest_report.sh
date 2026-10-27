#!/usr/bin/env bash
# scripts/pytest_report.sh
#
# Unified pytest runner that produces:
# - structured mypy report (.json)
# - human-readable console log (.txt)
# - machine-readable structured report (.json)
# - standard CI test report (.xml)
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

validate_pytest_basetemp_root() {
  if [[ "$#" -ne 1 ]]; then
    >&2 echo "ERROR: validate_pytest_basetemp_root requires one path"
    return 1
  fi
  local basetemp_root="$1"
  local canonical_root first_entry

  if [[ -z "${basetemp_root}" || "${basetemp_root}" != /* || "${basetemp_root}" == "/" ]]; then
    >&2 echo "ERROR: pytest base temporary root must be an absolute non-root path"
    return 1
  fi
  if [[ ! -d "${basetemp_root}" || -L "${basetemp_root}" || ! -r "${basetemp_root}" || ! -w "${basetemp_root}" || ! -x "${basetemp_root}" ]]; then
    >&2 echo "ERROR: pytest base temporary root is missing or unsafe: ${basetemp_root}"
    return 1
  fi
  if ! first_entry="$(find "${basetemp_root}" -mindepth 1 -maxdepth 1 -print -quit)"; then
    >&2 echo "ERROR: cannot inspect pytest base temporary root: ${basetemp_root}"
    return 1
  fi
  if [[ -n "${first_entry}" ]]; then
    >&2 echo "ERROR: pytest base temporary root must be empty: ${basetemp_root}"
    return 1
  fi

  canonical_root="$(realpath -e -- "${basetemp_root}")"
  printf '%s\n' "${canonical_root}"
}

validate_pytest_stream_output() {
  if [[ "$#" -ne 1 ]]; then
    >&2 echo "ERROR: validate_pytest_stream_output requires one value"
    return 1
  fi
  case "$1" in
    yes|no)
      printf '%s\n' "$1"
      ;;
    *)
      >&2 echo "ERROR: DAR_BACKUP_PYTEST_STREAM_OUTPUT must be 'yes' or 'no'"
      return 1
      ;;
  esac
}

run_report_command() {
  if [[ "$#" -lt 3 ]]; then
    >&2 echo "ERROR: run_report_command requires OUTPUT_PATH, STREAM_OUTPUT, and COMMAND"
    return 1
  fi
  local output_path="$1"
  local stream_output="$2"
  shift 2

  if [[ -z "${output_path}" || -d "${output_path}" || -L "${output_path}" || ! -d "$(dirname "${output_path}")" ]]; then
    >&2 echo "ERROR: report output path is missing or unsafe: ${output_path:-<empty>}"
    return 1
  fi
  case "${stream_output}" in
    yes|no)
      ;;
    *)
      >&2 echo "ERROR: STREAM_OUTPUT must be 'yes' or 'no'"
      return 1
      ;;
  esac

  if [[ "${stream_output}" == "yes" ]]; then
    "$@" 2>&1 | tee "${output_path}"
    return
  fi
  "$@" > "${output_path}" 2>&1
}

PYTEST_BASETEMP_ROOT=""
COLLECT_BASETEMP_ARGS=()
EXECUTION_BASETEMP_ARGS=()
if [[ -n "${DAR_BACKUP_PYTEST_BASETEMP_ROOT:-}" ]]; then
  PYTEST_BASETEMP_ROOT="$(validate_pytest_basetemp_root "${DAR_BACKUP_PYTEST_BASETEMP_ROOT}")"
  COLLECT_BASETEMP_ARGS=("--basetemp=${PYTEST_BASETEMP_ROOT}/collect")
  EXECUTION_BASETEMP_ARGS=("--basetemp=${PYTEST_BASETEMP_ROOT}/execution")
fi
PYTEST_STREAM_OUTPUT="$(validate_pytest_stream_output "${DAR_BACKUP_PYTEST_STREAM_OUTPUT:-yes}")"

case "$MODE" in
  fast)
    MARKS='unit or component'
    ;;
  smoke)
    MARKS='unit or component or smoke'
    ;;
  integration)
    MARKS='integration and not slow and not live_discord'
    ;;
  full)
    MARKS='not live_discord'
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Valid modes: fast | smoke | integration | full"
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
JUNIT="${BASE}.xml"
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
echo "Stream logs: $PYTEST_STREAM_OUTPUT"
if [[ -n "${PYTEST_BASETEMP_ROOT}" ]]; then
  echo "Pytest temp: ${PYTEST_BASETEMP_ROOT}"
fi
echo

# 0) Static type check (fails the run on error, same as ruff in release.sh)
echo "=== mypy ==="
MYPY_JSON="${OUTDIR}/mypy.json"
python scripts/run_mypy_report.py --output "${MYPY_JSON}" src/
echo

# Define coverage output next to the other artifacts
COV_XML="${OUTDIR}/coverage.xml"

# 1) Collection inventory (skip coverage to avoid noisy reports)
run_report_command \
  "$COLLECT" \
  "$PYTEST_STREAM_OUTPUT" \
  pytest "${COLLECT_BASETEMP_ARGS[@]}" -q --collect-only --no-cov -m "$MARKS"

# 2) Execution (TXT + JSON)
run_report_command \
  "$TXT" \
  "$PYTEST_STREAM_OUTPUT" \
  pytest "${EXECUTION_BASETEMP_ARGS[@]}" -q -m "$MARKS" \
  --json-report \
  --json-report-file="$JSON" \
  --junitxml="$JUNIT" \
  --cov-report="xml:$COV_XML"

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
echo "  $JUNIT"
echo "  $COLLECT"
echo "  $MYPY_JSON"
if [[ -f "$COV_XML" ]]; then
  echo "  $COV_XML"
fi
