#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# large_scale_test.sh — pre-release torture test for dar-backup

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
DATESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
DATE_OF_RUN=$(date '+%Y-%m-%d')  # Pinned once at initialization
BASE_DIR="/data/tmp/large-scale-test"
DEFINITION_NAME="large-scale-test"
DEFINITION_CONTENT=""
SLICE_SIZE="10G"
PAR2_RATIO=5
DO_BITROT=0
KEEP=0
TIMEOUT=86400
SCRIPT_VERSION="4"
DIFF_PRIMER_DIR=""
PRIMER_NON_LINK_COUNT=0
DAR_BACKUP_VERSION=""
GIT_COMMIT=""
REPO_DIR=""
DAR_VERSION=""
PAR2_VERSION=""
PYTHON_VERSION=""
OS_DESC=""
KERNEL=""

# ── colours ─────────────────────────────────────────────────────────────────
RED='\033[31m'; GREEN='\033[32m'
CYAN='\033[36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()   { echo -e "${GREEN}  PASS${RESET}  $*"; }
fail()   { echo -e "${RED}  FAIL${RESET}  $*"; FAILURES=$((FAILURES+1)); }
info()   { echo -e "${CYAN}  INFO${RESET}  $*"; }
banner() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
           echo -e "${BOLD}${CYAN}  $*${RESET}"
           echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

FAILURES=0

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --definition) DEFINITION_CONTENT="$2"; shift 2 ;;
        --base)       BASE_DIR="$2";           shift 2 ;;
        --slice)      SLICE_SIZE="$2";         shift 2 ;;
        --par2-ratio) PAR2_RATIO="$2";         shift 2 ;;
        --bitrot)     DO_BITROT=1;             shift   ;;
        --keep)       KEEP=1;                  shift   ;;
        --timeout)    TIMEOUT="$2";            shift 2 ;;
        --help|-h)    usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

[[ -z "$DEFINITION_CONTENT" ]] && { echo "ERROR: --definition is required"; exit 1; }

# ── preflight checks ──────────────────────────────────────────────────────────
preflight() {
    local errors=0
    if [[ ! -f "pyproject.toml" || ! -d "src/dar_backup" ]]; then
        echo "ERROR: must be run from the v2/ directory (pyproject.toml and src/dar_backup not found)"
        errors=$((errors+1))
    fi
    if [[ -z "${VIRTUAL_ENV:-}" || "${VIRTUAL_ENV}" != "$(realpath ./venv 2>/dev/null)" ]]; then
        echo "ERROR: project venv not active — run: source ./venv/bin/activate"
        errors=$((errors+1))
    fi
    local editable_loc; editable_loc=$(pip show dar-backup 2>/dev/null | grep "Editable project location" | awk '{print $NF}')
    if [[ -z "$editable_loc" ]]; then
        echo "ERROR: dar-backup is not installed in editable mode"; errors=$((errors+1))
    else
        REPO_DIR="$editable_loc"
    fi
    [[ $errors -gt 0 ]] && exit 1

    DAR_BACKUP_VERSION=$(dar-backup --version 2>/dev/null | head -1 || echo "unknown")
    GIT_COMMIT=$(git -C "${REPO_DIR:-.}" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    DAR_VERSION=$(dar --version 2>&1 | grep "dar version" | head -1 | sed 's/^ *//' || echo "unknown")
    PAR2_VERSION=$(par2 --version 2>/dev/null | head -1 || echo "unknown")
    PYTHON_VERSION=$(python3 --version 2>/dev/null || echo "unknown")
    OS_DESC=$(lsb_release -d 2>/dev/null | awk -F':	' '{print $2}' || echo "unknown")
    KERNEL=$(uname -r)
}
preflight

# ── directory layout ─────────────────────────────────────────────────────────
RUN_DIR="${BASE_DIR}/runs/${DATESTAMP}"
BACKUP_DIR="${RUN_DIR}/backups"
PAR2_DIR="${RUN_DIR}/par2"
RESTORE_DIR="${RUN_DIR}/restore"
BACKUP_D_DIR="${RUN_DIR}/backup.d"
RESULTS_DIR="${BASE_DIR}/results"
METRICS_DB="${RESULTS_DIR}/dar-backup-metrics.db"
LOGFILE="${RESULTS_DIR}/large-scale-test-${DATESTAMP}.dar-backup.log"
SUMMARY="${RESULTS_DIR}/summary-${DATESTAMP}.txt"
CONFIG_FILE="${RUN_DIR}/dar-backup.conf"
DARRC="${RUN_DIR}/.darrc"
RSS_LOGFILE="${RUN_DIR}/rss.log"
DIFF_PRIMER_DIR="${BASE_DIR}/diff-primer"

mkdir -p "$BACKUP_DIR" "$PAR2_DIR" "$RESTORE_DIR" "$BACKUP_D_DIR" "$RESULTS_DIR" "$DIFF_PRIMER_DIR"

# Tee all output to the summary file from this point forward so every run
# leaves a self-contained record alongside the structured dar/par2 log.
exec > >(tee "$SUMMARY") 2>&1


# ── RSS monitor ──────────────────────────────────────────────────────────────
RSS_MONITOR_PID=""
stop_rss_monitor() {
    if [[ -n "${RSS_MONITOR_PID:-}" ]]; then
        kill "$RSS_MONITOR_PID" 2>/dev/null || true
        wait "$RSS_MONITOR_PID" 2>/dev/null || true
        RSS_MONITOR_PID=""
    fi
}
start_rss_monitor() {
    (
        local main_script_pid=$PPID
        while true; do
            local child_pids; child_pids=$(pgrep -P "$main_script_pid" 2>/dev/null || true)
            if [[ -n "$child_pids" ]]; then
                local nested_pids; nested_pids=$(pgrep -P "$(echo "$child_pids" | tr '\n' ',' | sed 's/,$//')" 2>/dev/null || true)
                child_pids="${child_pids}"$'\n'"${nested_pids}"
            fi

            for pid in $child_pids; do
                [[ -z "$pid" || ! -d "/proc/$pid" ]] && continue
                local cmd; cmd=$(ps -p "$pid" -o comm= 2>/dev/null || true)
                
                if [[ "$cmd" =~ ^(dar|dar-backup|par2|manager)$ ]]; then
                    local rss; rss=$(awk '/VmRSS/{print $2}' /proc/"$pid"/status 2>/dev/null || echo 0)
                    local vsz; vsz=$(awk '/VmPeak/{print $2}' /proc/"$pid"/status 2>/dev/null || echo 0)
                    
                    [[ "$rss" -gt 0 ]] && printf '%s pid=%-6s rss=%-8s kB peak=%-8s kB cmd=%s\n' \
                        "$(date '+%H:%M:%S')" "$pid" "$rss" "$vsz" "$cmd"
                fi
            done
            sleep 0.5
        done
    ) >> "${RSS_LOGFILE:-/dev/null}" 2>/dev/null &
    RSS_MONITOR_PID=$!
}

write_config() {
    cat > "$CONFIG_FILE" << EOF
[MISC]
LOGFILE_LOCATION = ${LOGFILE}
MAX_SIZE_VERIFICATION_MB = 200
MIN_SIZE_VERIFICATION_MB = 1
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = ${TIMEOUT}
COMMAND_CAPTURE_MAX_BYTES = 102400
METRICS_DB_PATH = ${METRICS_DB}
RESTORETEST_EXCLUDE_PREFIXES = .cache/, .local/share/Trash/
RESTORETEST_EXCLUDE_SUFFIXES = .log, .tmp, .lock
[DIRECTORIES]
BACKUP_DIR = ${BACKUP_DIR}
BACKUP.D_DIR = ${BACKUP_D_DIR}
TEST_RESTORE_DIR = ${RESTORE_DIR}
[AGE]
DIFF_AGE = 50
INCR_AGE = 30
[PAR2]
ERROR_CORRECTION_PERCENT = ${PAR2_RATIO}
ENABLED = True
PAR2_DIR = ${PAR2_DIR}
EOF
}

write_backup_def() {
    local content="$DEFINITION_CONTENT"
    [[ ! "$content" =~ -s\  ]] && content="-s ${SLICE_SIZE}"$'\n'"$content"
    content="${content}"$'\n'"-g ${DIFF_PRIMER_DIR#/}"
    printf '%s\n' "$content" > "${BACKUP_D_DIR}/${DEFINITION_NAME}"
}

create_diff_primer() {
    info "Creating diff-primer data..."
    rm -rf "${DIFF_PRIMER_DIR:?}"/*
    for i in $(seq 1 100); do dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/small_${i}.bin" bs=4096 count=1 2>/dev/null; done
    for i in $(seq 1 10); do dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/medium_${i}.bin" bs=1M count=2 2>/dev/null; done
    for i in $(seq 1 5); do dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/large_${i}.NEF" bs=1M count=55 2>/dev/null; done
    echo "Original static content stream for hard link verification tracking." > "${DIFF_PRIMER_DIR}/link_original.txt"
    ln "${DIFF_PRIMER_DIR}/link_original.txt" "${DIFF_PRIMER_DIR}/link_target1.txt"
    # Count non-link files; used as the expected-modified threshold in verify_diff_contents.
    PRIMER_NON_LINK_COUNT=$(find "${DIFF_PRIMER_DIR}" -type f ! -name "link_*" | wc -l)
}

update_diff_primer() {
    info "Updating diff-primer data..."
    find "$DIFF_PRIMER_DIR" -type f | grep -v "link_" | while read -r f; do
        dd if=/dev/urandom of="$f" bs=$(stat -c%s "$f") count=1 2>/dev/null
    done || true
    rm "${DIFF_PRIMER_DIR}/link_original.txt"
    echo "Appended text block mutating target1 inode before execution of DIFF backup." >> "${DIFF_PRIMER_DIR}/link_target1.txt"
    ln "${DIFF_PRIMER_DIR}/link_target1.txt" "${DIFF_PRIMER_DIR}/link_target2.txt"
    dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/diff_new_$(date +%s).bin" bs=1M count=2 2>/dev/null
}

verify_diff_contents() {
    local full_base="$1" diff_base="$2" primer_rel="${DIFF_PRIMER_DIR#/}"
    banner "Phase 2b — DIFF contents verification"
    local diff_saved; diff_saved=$(dar -l "${BACKUP_DIR}/${diff_base}" --noconf -am -as -Q 2>/dev/null | grep "\[Saved\]" | grep "${primer_rel}" || true)
    local modified_count; modified_count=$(echo "$diff_saved" | grep -v "diff_new_" | grep -c "${primer_rel}" 2>/dev/null || echo 0)
    local new_count; new_count=$(echo "$diff_saved" | grep -c "diff_new_" 2>/dev/null || echo 0)
    [[ "${modified_count}" -ge "${PRIMER_NON_LINK_COUNT}" ]] && pass "Modified file count OK (${modified_count})" || fail "Modified file count LOW (${modified_count}, expected >=${PRIMER_NON_LINK_COUNT})"
    [[ "${new_count}" -ge 1 ]] && pass "New file count OK" || fail "New file missing from DIFF"
}

write_darrc() {
    local installed; installed=$(python3 -c "import dar_backup, os; print(os.path.join(os.path.dirname(dar_backup.__file__), '.darrc'))" 2>/dev/null || true)
    if [[ -f "$installed" ]]; then cp "$installed" "$DARRC"; else
        cat > "$DARRC" << 'EOF'
verbose:
 -vd
 -vf
compress-exclusion:
-an
-ag
-Z "*.gz" -Z "*.bz2" -Z "*.xz" -Z "*.zip" -Z "*.jpg" -Z "*.jpeg" -Z "*.png" -Z "*.NEF" -Z "*.mp4" -Z "*.mkv" -Z "*.dar"
-acase
EOF
    fi
}

check_par2_per_slice() {
    local archive_base="$1" slice_count="$2" ok=1
    for i in $(seq 1 "$slice_count"); do
        [[ ! -f "${PAR2_DIR}/${archive_base}.${i}.dar.par2" ]] && { fail "Missing par2 slice ${i}"; ok=0; }
    done
    [[ -f "${PAR2_DIR}/${archive_base}.par2" ]] && { fail "Archive-level par2 found (regression)"; ok=0; }
    [[ -f "${PAR2_DIR}/${archive_base}.par2.manifest.ini" ]] && pass "Manifest present" || { fail "Manifest missing"; ok=0; }
    return $((1 - ok))
}

check_dar_integrity() {
    info "Running dar -t on $2..."
    dar -t "${BACKUP_DIR}/${1}" -N -Q >> "$LOGFILE" 2>&1 && pass "dar -t passed: $2" || fail "dar -t failed: $2"
}

check_par2_verify() {
    local archive_base="$1" label="$2" all_ok=1
    
    # Enable safe globbing transitions
    shopt -s nullglob
    local par2_files=("${PAR2_DIR}/${archive_base}".*.dar.par2)
    shopt -u nullglob

    for par2_file in "${par2_files[@]}"; do
        par2 verify -B "$BACKUP_DIR" -q "$par2_file" >> "$LOGFILE" 2>&1 || { fail "par2 verify FAILED: $(basename "$par2_file")"; all_ok=0; }
    done
    [[ $all_ok -eq 1 ]] && pass "par2 verify passed all slices: ${label}"
}



do_bitrot_test() {
    local archive_base="$1"
    local slice="${BACKUP_DIR}/${archive_base}.1.dar"
    local par2="${PAR2_DIR}/${archive_base}.1.dar.par2"
    banner "Bitrot test on ${archive_base}"
    local size; size=$(stat -c%s "$slice")
    local corrupt_bytes=$(( size * 2 / 100 )) offset=$(( size / 4 ))
    info "Injecting bitrot..."
    dd if=/dev/urandom of="$slice" bs=1 seek="$offset" count="$corrupt_bytes" conv=notrunc >> "$LOGFILE" 2>&1
    dar -t "${BACKUP_DIR}/${archive_base}" -N -Q >> "$LOGFILE" 2>&1 && { fail "dar-t missed corruption"; return; } || pass "dar -t correctly detected corruption"
    info "Repairing with par2..."
    par2 repair -B "$BACKUP_DIR" -q "$par2" >> "$LOGFILE" 2>&1 && pass "par2 repair succeeded" || { fail "par2 repair failed"; return; }
    dar -t "${BACKUP_DIR}/${archive_base}" -N -Q >> "$LOGFILE" 2>&1 && pass "dar -t passed after repair" || fail "dar -t still fails after repair"
}

count_slices() { ls "${BACKUP_DIR}/${1}".*.dar 2>/dev/null | wc -l; }
init_manager_db() { manager --create-db --config-file "$CONFIG_FILE" --log-stdout >> "$LOGFILE" 2>&1 && pass "manager --create-db succeeded" || fail "manager --create-db failed"; }

# ── find archive base for a backup type ───────────────────────────────────────
find_archive_base() {
    local type="$1"
    
    # Explicitly construct the exact expected filename structure
    local expected_base="${DEFINITION_NAME}_${type}_${DATE_OF_RUN}"
    local expected_file="${BACKUP_DIR}/${expected_base}.1.dar"

    # Verify the file is actually present on disk before claiming success
    if [[ -f "$expected_file" ]]; then
        echo "$expected_base"
    else
        # If it doesn't exist, log why directly to stderr so it bypasses command substitutions
        echo "  FAIL  Expected slice file not found at: ${expected_file}" >&2
        echo ""
    fi
}

cleanup() { stop_rss_monitor; [[ $KEEP -eq 0 ]] && rm -rf "$RUN_DIR" || info "Keeping run directory: $RUN_DIR"; }

trap cleanup EXIT

# ════════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════════
banner "dar-backup large-scale test  ${DATESTAMP}"

full_elapsed=0; diff_elapsed=0; FULL_BASE=""; DIFF_BASE=""; FULL_SLICES=0

write_config; create_diff_primer; write_backup_def; write_darrc; init_manager_db; start_rss_monitor

# ── PHASE 1 ──
banner "Phase 1 — FULL backup"
t0=$(date +%s)
if dar-backup -F -d "$DEFINITION_NAME" --config-file "$CONFIG_FILE" --darrc "$DARRC" --log-level debug; then
    full_elapsed=$(( $(date +%s) - t0 )); pass "FULL backup completed in ${full_elapsed}s"
else
    exit 1
fi

FULL_BASE=$(find_archive_base "FULL")
[[ -z "${FULL_BASE}" ]] && { fail "No FULL base found"; exit 1; }
FULL_SLICES=$(count_slices "$FULL_BASE")

check_dar_integrity  "$FULL_BASE" "FULL"
check_par2_per_slice "$FULL_BASE" "$FULL_SLICES"
check_par2_verify    "$FULL_BASE" "FULL"
[[ $DO_BITROT -eq 1 ]] && do_bitrot_test "$FULL_BASE"

# ── PHASE 2 ──
banner "Phase 2 — DIFF backup"
update_diff_primer
t0=$(date +%s)
if dar-backup -D -d "$DEFINITION_NAME" --config-file "$CONFIG_FILE" --darrc "$DARRC" --log-level debug; then
    diff_elapsed=$(( $(date +%s) - t0 )); pass "DIFF backup completed in ${diff_elapsed}s"
else
    exit 1
fi

DIFF_BASE=$(find_archive_base "DIFF")
[[ -z "${DIFF_BASE}" ]] && { fail "No DIFF base found"; exit 1; }
DIFF_SLICES=$(count_slices "$DIFF_BASE")
check_dar_integrity  "$DIFF_BASE" "DIFF"
check_par2_per_slice "$DIFF_BASE" "$DIFF_SLICES"
check_par2_verify    "$DIFF_BASE" "DIFF"
verify_diff_contents "$FULL_BASE" "$DIFF_BASE"

# ── PHASE 3 ──
banner "Phase 3a — Point-In-Time Restore Validation (latest state)"

info "Cleaning restore target directory to satisfy manager safety checks..."
rm -rf "$RESTORE_DIR"
mkdir -p "$RESTORE_DIR"

info "Invoking manager to process PITR extraction for diff-primer data..."

# Using the exact CLI arguments from restoring.md to restore our relative primer directory
if manager --config-file "$CONFIG_FILE" \
           -d "$DEFINITION_NAME" \
           --restore-path "${DIFF_PRIMER_DIR#/}/" \
           --when "now" \
           --target "$RESTORE_DIR" \
           --log-stdout --verbose >> "$LOGFILE" 2>&1; then
    pass "Restore sequence completed execution via manager"
else
    fail "manager PITR restore dropped an error exit code"
fi

RESTORE_PRIMER_PATH="${RESTORE_DIR}/${DIFF_PRIMER_DIR#/}"

if [[ -f "${RESTORE_PRIMER_PATH}/link_original.txt" ]]; then
    fail "link_original.txt present in latest-state restore (should have been deleted by DIFF)"
else
    pass "link_original.txt correctly absent from latest-state restore"
fi
if [[ -f "${RESTORE_PRIMER_PATH}/link_target1.txt" && -f "${RESTORE_PRIMER_PATH}/link_target2.txt" ]]; then
    inode1=$(stat -c %i "${RESTORE_PRIMER_PATH}/link_target1.txt")
    inode2=$(stat -c %i "${RESTORE_PRIMER_PATH}/link_target2.txt")
    [[ "$inode1" -eq "$inode2" ]] && pass "Hard Link Inodes match (${inode1})" || fail "Inodes mismatched (Cloned data!)"
else
    fail "Hard-link targets missing"
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
banner "Summary"

stop_rss_monitor

calc_max_rss() {
    local target_cmd="$1"
    local log_path="${RSS_LOGFILE:-}"
    
    if [[ -n "$log_path" && -f "$log_path" ]]; then
        awk -v target="cmd=$target_cmd" '
            $7 == target {
                split($3, rss_val, "=");
                if (rss_val[2] > max) max = rss_val[2] 
            } 
            END { if (max > 0) printf "%.1f MB", max / 1024; else print "N/A" }
        ' "$log_path"
    else
        echo "N/A"
    fi
}

# Use the precise binary names matching the output of cmd= in rss.log
MAX_DAR_BACKUP=$(calc_max_rss "dar-backup")
MAX_DAR=$(calc_max_rss "dar")
MAX_PAR2=$(calc_max_rss "par2")
MAX_MANAGER=$(calc_max_rss "manager")

# Fixed disk analyzer helper: avoids pipe failures if globs don't match files
calc_slice_size() {
    local prefix="$1"
    local target_dir="${BACKUP_DIR:-}"
    local def_name="${DEFINITION_NAME:-}"
    
    if [[ -n "$target_dir" && -d "$target_dir" && -n "$def_name" ]]; then
        # Ensure the glob resolves without throwing errors to du
        local bytes; bytes=$(du -cb "${target_dir}/${def_name}_${prefix}_"* 2>/dev/null | awk 'END{print $1}' || echo 0)
        if [[ "$bytes" -gt 0 ]]; then
            awk -v b="$bytes" 'BEGIN { printf "%.2f GB", b / 1024 / 1024 / 1024 }'
        else
            echo "0.00 GB"
        fi
    else
        echo "0.00 GB"
    fi
}

FULL_SIZE=$(calc_slice_size "FULL")
DIFF_SIZE=$(calc_slice_size "DIFF")

# Compile final analytics screen layout using matched variable casing
echo -e "dar-backup test pass: ${DATESTAMP:-}"
echo -e "FULL elapsed: ${full_elapsed:-0}s (~${FULL_SIZE})"
echo -e "DIFF elapsed: ${diff_elapsed:-0}s (~${DIFF_SIZE})"
echo -e "Peak Engine Memory Consumption:"
echo -e "  ├── dar-backup : ${MAX_DAR_BACKUP}"
echo -e "  ├── dar backend: ${MAX_DAR}"
echo -e "  ├── par2 engine: ${MAX_PAR2}"
echo -e "  └── db manager : ${MAX_MANAGER}"
echo -e "Failures:      ${FAILURES:-0}"

# Final status validation routing
if [ "${FAILURES:-0}" -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✓ ALL TESTS PASSED SUCCESSFULLY${RESET}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}✗ TEST SUITE FAILED WITH ${FAILURES} ERRORS${RESET}\n"
    exit 1
fi
