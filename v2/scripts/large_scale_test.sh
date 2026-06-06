#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# large_scale_test.sh — pre-release torture test for dar-backup
#
# Runs a FULL backup followed by a DIFF backup against a real source tree,
# verifies par2 files are per-slice, checks dar integrity, optionally injects
# bitrot and repairs it, and writes a summary report.  Nothing touches the
# production environment.
#
# The backup definition is supplied by the caller as a string (use a heredoc
# to keep personal paths out of this script and out of version control).
#
# Usage:
#   ./large_scale_test.sh --definition DEF_STRING [OPTIONS]
#
# Options:
#   --definition STR   dar backup definition content (required, see example)
#   --base       DIR   Base directory for test output (default: /data/tmp/large-scale-test)
#   --slice      SIZE  dar slice size written into the definition (default: 10G)
#   --par2-ratio INT   PAR2 redundancy percent (default: 5)
#   --bitrot           Inject bitrot into FULL slice 1, repair, verify
#   --keep             Do not delete backup/par2/run dirs on exit (metrics DB always kept)
#   --timeout    SECS  Command timeout in seconds (default: 86400)
#   --help             Show this help
#
# The metrics DB and summary report are always kept under --base/results/.
# The metrics DB accumulates across runs so you can compare releases over time.
#
# Example — single source tree:
#   ./large_scale_test.sh \
#       --base /data/tmp/large-scale-test \
#       --bitrot \
#       --definition "$(cat << 'EOF'
# -R /
# -s 10G
# -z6
# -am
# --cache-directory-tagging
# -g mnt/photos/2023
# EOF
# )"
#
# Example — multiple source trees:
#   ./large_scale_test.sh \
#       --base /data/tmp/large-scale-test \
#       --bitrot \
#       --definition "$(cat << 'EOF'
# -R /
# -s 10G
# -z6
# -am
# --cache-directory-tagging
# -g mnt/photos/2023
# -g mnt/photos/2024
# -g home/pj/documents
# EOF
# )"
#
# Note: dar does not accept a leading '/' in -g paths; write 'mnt/foo' not '/mnt/foo'.
# The -s (slice size) in the definition overrides --slice if both are present;
# omit -s from the definition to let --slice control it.
#
# A synthetic diff-primer directory is automatically appended to the definition
# and managed by the script:
#   - Before FULL:  100 small files, 10 × 2 MB files, 5 × 55 MB files are created.
#   - Before DIFF:  all files are overwritten with new random data and one new
#                   file is added, guaranteeing a non-trivial DIFF without
#                   touching any personal source files.
# The primer directory lives at --base/diff-primer/ and is NOT deleted on exit
# (even without --keep) so it can serve as a stable DIFF source across runs.

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
DEFINITION_CONTENT=""
BASE_DIR="/data/tmp/large-scale-test"
SLICE_SIZE="10G"
PAR2_RATIO=5
DO_BITROT=0
KEEP=0
TIMEOUT=86400
DATESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')
DEFINITION_NAME="large-scale-test"
SCRIPT_VERSION="2"          # increment when the script changes
# diff-primer lives outside the run dir so it persists across runs
DIFF_PRIMER_DIR=""   # set after BASE_DIR is finalised
DAR_BACKUP_VERSION=""
GIT_COMMIT=""
REPO_DIR=""
DAR_VERSION=""
PAR2_VERSION=""
PYTHON_VERSION=""
OS_DESC=""
KERNEL=""

# ── colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pass()   { echo -e "${GREEN}  PASS${RESET}  $*"; }
fail()   { echo -e "${RED}  FAIL${RESET}  $*"; FAILURES=$((FAILURES+1)); }
info()   { echo -e "${CYAN}  INFO${RESET}  $*"; }
banner() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
           echo -e "${BOLD}${CYAN}  $*${RESET}"
           echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"; }

FAILURES=0

# ── argument parsing ─────────────────────────────────────────────────────────
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

[[ -z "$DEFINITION_CONTENT" ]] && {
    echo "ERROR: --definition is required"
    echo "See --help for an example using a heredoc."
    exit 1
}

# ── preflight checks ──────────────────────────────────────────────────────────
preflight() {
    local errors=0

    # 1. Must be run from the v2/ directory
    if [[ ! -f "pyproject.toml" || ! -d "src/dar_backup" ]]; then
        echo "ERROR: must be run from the v2/ directory (pyproject.toml and src/dar_backup not found)"
        errors=$((errors+1))
    fi

    # 2. Must be run inside the project venv
    if [[ -z "${VIRTUAL_ENV:-}" || "${VIRTUAL_ENV}" != "$(realpath ./venv 2>/dev/null)" ]]; then
        echo "ERROR: project venv not active — run: source ./venv/bin/activate"
        errors=$((errors+1))
    fi

    # 3. dar-backup must be installed in editable mode (pip install -e .)
    local editable_loc
    editable_loc=$(pip show dar-backup 2>/dev/null \
        | grep "Editable project location" | awk '{print $NF}')
    if [[ -z "$editable_loc" ]]; then
        echo "ERROR: dar-backup is not installed in editable mode"
        echo "       Run: pip install -e .[dev]  (see build.sh)"
        errors=$((errors+1))
    else
        echo "  INFO  Editable install: $editable_loc"
        REPO_DIR="$editable_loc"
    fi

    # 4. Git repo must be clean — no uncommitted changes
    if [[ -d "${REPO_DIR:-}/.git" ]] || git -C "${REPO_DIR:-.}" rev-parse --git-dir &>/dev/null; then
        local dirty
        dirty=$(git -C "${REPO_DIR:-.}" status --porcelain 2>/dev/null)
        if [[ -n "$dirty" ]]; then
            echo "ERROR: git repo has uncommitted changes — commit or stash before running:"
            echo "$dirty" | sed "s/^/         /"
            errors=$((errors+1))
        fi
    else
        echo "WARNING: could not find git repo — skipping clean-commit check"
    fi

    [[ $errors -gt 0 ]] && { echo "Aborting: fix the errors above before running the test."; exit 1; }

    # Capture version and commit for the summary
    DAR_BACKUP_VERSION=$(dar-backup --version 2>/dev/null | head -1 || echo "unknown")
    GIT_COMMIT=$(git -C "${REPO_DIR:-.}" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    DAR_VERSION=$(dar --version 2>&1 | grep "dar version" | head -1 || echo "unknown")
    PAR2_VERSION=$(par2 --version 2>/dev/null | head -1 || echo "unknown")
    PYTHON_VERSION=$(python3 --version 2>/dev/null || echo "unknown")
    OS_DESC=$(lsb_release -d 2>/dev/null | awk -F':	' '{print $2}' || echo "unknown")
    KERNEL=$(uname -r)
    echo "  INFO  dar-backup version: ${DAR_BACKUP_VERSION}"
    echo "  INFO  git commit:         ${GIT_COMMIT}"
    echo "  INFO  dar version:        ${DAR_VERSION}"
    echo "  INFO  par2 version:       ${PAR2_VERSION}"
    echo "  INFO  python version:     ${PYTHON_VERSION}"
    echo "  INFO  OS:                 ${OS_DESC}"
    echo "  INFO  kernel:             ${KERNEL}"
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
LOGFILE="${RESULTS_DIR}/large-scale-test-${DATESTAMP}.log"
SUMMARY="${RESULTS_DIR}/summary-${DATESTAMP}.txt"
CONFIG_FILE="${RUN_DIR}/dar-backup.conf"
DARRC="${RUN_DIR}/.darrc"
RSS_LOG="${RUN_DIR}/rss.log"

DIFF_PRIMER_DIR="${BASE_DIR}/diff-primer"
mkdir -p "$BACKUP_DIR" "$PAR2_DIR" "$RESTORE_DIR" "$BACKUP_D_DIR" "$RESULTS_DIR" "$DIFF_PRIMER_DIR"

# ── RSS monitor ──────────────────────────────────────────────────────────────
RSS_MONITOR_PID=""

start_rss_monitor() {
    (
        while true; do
            for name in dar-backup dar par2; do
                pids=$(pgrep -x "$name" 2>/dev/null || true)
                for pid in $pids; do
                    rss=$(awk '/VmRSS/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
                    vsz=$(awk '/VmPeak/{print $2}' /proc/$pid/status 2>/dev/null || echo 0)
                    cmd=$(ps -p $pid -o comm= 2>/dev/null || echo "$name")
                    [[ "$rss" -gt 0 ]] && \
                        printf '%s pid=%-6s rss=%-8s kB peak=%-8s kB cmd=%s\n' \
                            "$(date '+%H:%M:%S')" "$pid" "$rss" "$vsz" "$cmd"
                done
            done
            sleep 5
        done
    ) >> "$RSS_LOG" 2>/dev/null &
    RSS_MONITOR_PID=$!
}

stop_rss_monitor() {
    [[ -n "$RSS_MONITOR_PID" ]] && kill "$RSS_MONITOR_PID" 2>/dev/null || true
}

peak_rss_kb() {
    local name="$1"
    grep "cmd=${name}" "$RSS_LOG" 2>/dev/null \
        | awk '{for(i=1;i<=NF;i++) if($i~/^rss=/) {sub("rss=",""); print $i+0}}' \
        | sort -n | tail -1
}

# ── write config file ─────────────────────────────────────────────────────────
write_config() {
    cat > "$CONFIG_FILE" << EOF
# large_scale_test.sh — generated config ${DATESTAMP}

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
DIFF_AGE = 100
INCR_AGE = 40

[PAR2]
ERROR_CORRECTION_PERCENT = ${PAR2_RATIO}
ENABLED = True
PAR2_DIR = ${PAR2_DIR}
EOF
}

# ── write backup definition ───────────────────────────────────────────────────
write_backup_def() {
    # If the definition does not already contain a -s (slice size) line,
    # prepend one using --slice.  This lets the caller override slice size
    # via --slice without having to embed it in the heredoc.
    local content="$DEFINITION_CONTENT"
    if ! echo "$content" | grep -q '^\s*-s '; then
        content="-s ${SLICE_SIZE}"$'\n'"${content}"
    fi
    # Automatically append the diff-primer directory so the DIFF has
    # real changed data without touching any personal source files.
    # dar requires paths without a leading '/'
    local primer_g="${DIFF_PRIMER_DIR#/}"
    content="${content}"$'\n'"-g ${primer_g}"
    printf '%s\n' "$content" > "${BACKUP_D_DIR}/${DEFINITION_NAME}"
    info "Backup definition written to ${BACKUP_D_DIR}/${DEFINITION_NAME}"
    info "Diff-primer appended: -g ${primer_g}"
}

# ── diff-primer data generation ──────────────────────────────────────────────
create_diff_primer() {
    info "Creating diff-primer data in ${DIFF_PRIMER_DIR}..."
    # 100 small files (4 kB each — metadata-heavy workload)
    for i in $(seq 1 100); do
        dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/small_${i}.bin" bs=4096 count=1 2>/dev/null
    done
    # 10 medium files (2 MB each)
    for i in $(seq 1 10); do
        dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/medium_${i}.bin" bs=1M count=2 2>/dev/null
    done
    # 5 large files (55 MB each — simulates Nikon D850 NEF files)
    for i in $(seq 1 5); do
        dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/large_${i}.NEF" bs=1M count=55 2>/dev/null
    done
    local total; total=$(du -sh "$DIFF_PRIMER_DIR" | cut -f1)
    pass "Diff-primer created: 100 × 4kB + 10 × 2MB + 5 × 55MB  (total ~${total})"
}

update_diff_primer() {
    info "Updating diff-primer data to produce a non-trivial DIFF..."
    # Overwrite all existing files with new random content
    find "$DIFF_PRIMER_DIR" -type f | while read -r f; do
        local sz; sz=$(stat -c%s "$f")
        dd if=/dev/urandom of="$f" bs="$sz" count=1 2>/dev/null
    done
    # Add one new file so the DIFF contains at least one genuinely new entry
    dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/diff_new_$(date +%s).bin" bs=1M count=2 2>/dev/null
    pass "Diff-primer updated: all files refreshed, one new file added"
}

# ── verify DIFF contents against primer expectations ─────────────────────────
verify_diff_contents() {
    local full_base="$1"
    local diff_base="$2"
    local primer_rel="${DIFF_PRIMER_DIR#/}"   # path as dar sees it (no leading /)

    banner "Phase 2b — DIFF contents verification"

    # Extract saved filenames from FULL archive that belong to the primer dir
    info "Listing saved primer files in FULL archive..."
    local full_primer_files
    full_primer_files=$(dar -l "${BACKUP_DIR}/${full_base}" --noconf -am -as -Q 2>/dev/null \
        | grep "\[Saved\]" \
        | grep "${primer_rel}" \
        | grep -oP '(?<=\] ).*' \
        | sort) || true

    local full_count
    full_count=$(echo "$full_primer_files" | grep -c . || echo 0)
    info "FULL archive contains ${full_count} primer file(s)"

    # Extract saved filenames from DIFF archive that belong to the primer dir
    info "Listing saved primer files in DIFF archive..."
    local diff_primer_files
    diff_primer_files=$(dar -l "${BACKUP_DIR}/${diff_base}" --noconf -am -as -Q 2>/dev/null \
        | grep "\[Saved\]" \
        | grep "${primer_rel}" \
        | grep -oP '(?<=\] ).*' \
        | sort) || true

    local diff_count
    diff_count=$(echo "$diff_primer_files" | grep -c . || echo 0)
    info "DIFF archive contains ${diff_count} primer file(s)"

    # Modified files: present in both FULL and DIFF
    local modified_count
    modified_count=$(comm -12 \
        <(echo "$full_primer_files") \
        <(echo "$diff_primer_files") \
        | grep -c . || echo 0)

    # New files: present in DIFF but not in FULL
    local new_count
    new_count=$(comm -23 \
        <(echo "$diff_primer_files") \
        <(echo "$full_primer_files") \
        | grep -c . || echo 0)

    info "Modified primer files (in FULL + DIFF):  ${modified_count}"
    info "New primer files     (in DIFF only):     ${new_count}"

    # Expected: 115 modified (100 small + 10 medium + 5 large), 1 new (diff_new_*)
    local expected_modified=115
    local expected_new=1

    if [[ "$modified_count" -ge "$expected_modified" ]]; then
        pass "Modified file count OK: ${modified_count} >= ${expected_modified}"
    else
        fail "Modified file count LOW: ${modified_count} < ${expected_modified} — some primer files may be missing from DIFF"
    fi

    if [[ "$new_count" -ge "$expected_new" ]]; then
        pass "New file count OK: ${new_count} >= ${expected_new}"
    else
        fail "New file count LOW: ${new_count} < ${expected_new} — diff_new_* file missing from DIFF"
    fi
}

# ── write .darrc ──────────────────────────────────────────────────────────────
write_darrc() {
    local installed
    installed=$(python3 -c \
        "import dar_backup, os; print(os.path.join(os.path.dirname(dar_backup.__file__), '.darrc'))" \
        2>/dev/null || true)
    if [[ -f "$installed" ]]; then
        cp "$installed" "$DARRC"
        info "Using installed .darrc: $installed"
    else
        cat > "$DARRC" << 'EOF'
verbose:
 -vd
 -vf

restore-options:

compress-exclusion:
-an
-ag
-Z "*.gz"
-Z "*.bz2"
-Z "*.xz"
-Z "*.zip"
-Z "*.jpg"
-Z "*.jpeg"
-Z "*.png"
-Z "*.NEF"
-Z "*.mp4"
-Z "*.mkv"
-Z "*.dar"
-acase
EOF
        info "Using built-in fallback .darrc"
    fi
}

# ── par2 slice check ──────────────────────────────────────────────────────────
check_par2_per_slice() {
    local archive_base="$1"
    local slice_count="$2"
    local ok=1
    for i in $(seq 1 "$slice_count"); do
        local p="${PAR2_DIR}/${archive_base}.${i}.dar.par2"
        if [[ -f "$p" ]]; then
            local sz; sz=$(du -sh "$p" | cut -f1)
            info "par2 slice ${i}: $(basename "$p")  (${sz})"
        else
            fail "Missing per-slice par2: $p"
            ok=0
        fi
    done
    # Archive-level par2 (old behaviour) must not exist
    local archive_par2="${PAR2_DIR}/${archive_base}.par2"
    if [[ -f "$archive_par2" ]]; then
        fail "Archive-level par2 found (regression — should be per-slice): $archive_par2"
        ok=0
    fi
    # Manifest
    local manifest="${PAR2_DIR}/${archive_base}.par2.manifest.ini"
    if [[ -f "$manifest" ]]; then
        pass "Manifest present: $(basename "$manifest")"
    else
        fail "Manifest missing: $manifest"
        ok=0
    fi
    return $((1 - ok))
}

# ── dar integrity check ───────────────────────────────────────────────────────
check_dar_integrity() {
    local archive_base="$1"
    local label="$2"
    info "Running dar -t on ${label}..."
    if dar -t "${BACKUP_DIR}/${archive_base}" -N -Q >> "$LOGFILE" 2>&1; then
        pass "dar -t passed: ${label}"
    else
        fail "dar -t failed: ${label}"
    fi
}

# ── par2 verify ───────────────────────────────────────────────────────────────
check_par2_verify() {
    local archive_base="$1"
    local label="$2"
    local all_ok=1
    # Sort by slice number numerically to get 1,2,...,10,11 not 1,10,11,2,...
    local slice_count
    slice_count=$(count_slices "$archive_base")
    for i in $(seq 1 "$slice_count"); do
        local par2_file="${PAR2_DIR}/${archive_base}.${i}.dar.par2"
        [[ -f "$par2_file" ]] || continue
        if par2 verify -B "$BACKUP_DIR" -q "$par2_file" >> "$LOGFILE" 2>&1; then
            info "par2 verify OK: $(basename "$par2_file")"
        else
            fail "par2 verify FAILED: $(basename "$par2_file")"
            all_ok=0
        fi
    done
    [[ $all_ok -eq 1 ]] && pass "par2 verify passed all slices: ${label}"
}

# ── bitrot inject + repair ────────────────────────────────────────────────────
do_bitrot_test() {
    local archive_base="$1"
    local slice="${BACKUP_DIR}/${archive_base}.1.dar"
    local par2="${PAR2_DIR}/${archive_base}.1.dar.par2"

    banner "Bitrot test on ${archive_base}"

    [[ -f "$slice" ]] || { fail "Slice not found for bitrot test: $slice"; return; }
    [[ -f "$par2"  ]] || { fail "par2 not found for bitrot test: $par2";   return; }

    local size; size=$(stat -c%s "$slice")
    local corrupt_bytes=$(( size * 2 / 100 ))
    local offset=$(( size / 4 ))
    info "Injecting ${corrupt_bytes} bytes of bitrot at offset ${offset} in $(basename "$slice")"
    dd if=/dev/urandom of="$slice" bs=1 seek="$offset" count="$corrupt_bytes" conv=notrunc \
        >> "$LOGFILE" 2>&1

    if ! dar -t "${BACKUP_DIR}/${archive_base}" -N -Q >> "$LOGFILE" 2>&1; then
        pass "dar -t correctly detected corruption"
    else
        fail "dar -t did NOT detect corruption — bitrot test inconclusive"
        return
    fi

    info "Repairing with par2..."
    if par2 repair -B "$BACKUP_DIR" -q "$par2" >> "$LOGFILE" 2>&1; then
        pass "par2 repair succeeded"
    else
        fail "par2 repair failed"
        return
    fi

    if dar -t "${BACKUP_DIR}/${archive_base}" -N -Q >> "$LOGFILE" 2>&1; then
        pass "dar -t passed after repair"
    else
        fail "dar -t still fails after repair"
    fi
}

# ── count dar slices ──────────────────────────────────────────────────────────
count_slices() {
    local archive_base="$1"
    ls "${BACKUP_DIR}/${archive_base}".*.dar 2>/dev/null | wc -l
}

# ── run dar-backup ────────────────────────────────────────────────────────────
run_backup() {
    local flag="$1"
    local label="$2"
    local t0; t0=$(date +%s)
    info "Starting ${label} backup..."
    if dar-backup "$flag" -d "$DEFINITION_NAME" \
            --config-file "$CONFIG_FILE" \
            --darrc "$DARRC" \
            --log-level debug \
            >> "$LOGFILE" 2>&1; then
        local secs=$(( $(date +%s) - t0 ))
        pass "${label} backup completed in ${secs}s"
        echo "$secs"
    else
        local secs=$(( $(date +%s) - t0 ))
        fail "${label} backup failed after ${secs}s"
        echo "$secs"
    fi
}

# ── initialise manager DB ─────────────────────────────────────────────────────
init_manager_db() {
    if manager --create-db --config-file "$CONFIG_FILE" --log-stdout >> "$LOGFILE" 2>&1; then
        pass "manager --create-db succeeded"
    else
        fail "manager --create-db failed"
    fi
}

# ── find archive base for a backup type ───────────────────────────────────────
find_archive_base() {
    local type="$1"
    local date; date=$(date '+%Y-%m-%d')
    local match
    match=$(ls "${BACKUP_DIR}/${DEFINITION_NAME}_${type}_${date}.1.dar" 2>/dev/null | head -1 || true)
    [[ -n "$match" ]] || { echo ""; return; }
    basename "$match" | sed 's/\.1\.dar$//'
}

# ── cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    stop_rss_monitor
    if [[ $KEEP -eq 0 ]]; then
        info "Cleaning up run directory: $RUN_DIR"
        rm -rf "$RUN_DIR"
    else
        info "Keeping run directory: $RUN_DIR  (--keep)"
    fi
    # diff-primer is always kept — it serves as a stable DIFF source across runs
    info "Diff-primer kept at: $DIFF_PRIMER_DIR"
}
trap cleanup EXIT

# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════

banner "dar-backup large-scale test  ${DATESTAMP}"
info "Script version: ${SCRIPT_VERSION}"
info "Base dir:   ${BASE_DIR}"
info "Slice size: ${SLICE_SIZE}  (used only if -s absent from definition)"
info "PAR2 ratio: ${PAR2_RATIO}%"
info "Metrics DB: ${METRICS_DB}"
info "Log:        ${LOGFILE}"
echo ""

# Setup
write_config
create_diff_primer
write_backup_def
write_darrc
init_manager_db
start_rss_monitor

# ── FULL backup ───────────────────────────────────────────────────────────────
banner "Phase 1 — FULL backup"
full_elapsed=$(run_backup "-F" "FULL")
FULL_BASE=$(find_archive_base "FULL")

if [[ -z "$FULL_BASE" ]]; then
    fail "Could not find FULL archive base — aborting"
    exit 1
fi

FULL_SLICES=$(count_slices "$FULL_BASE")
FULL_SIZE_HUMAN=$(du -sb "${BACKUP_DIR}/${FULL_BASE}".*.dar 2>/dev/null \
    | awk '{s+=$1} END{printf "%.1f GB", s/1024/1024/1024}' || echo "?")

info "Archive:    ${FULL_BASE}"
info "Slices:     ${FULL_SLICES}"
info "Total size: ~${FULL_SIZE_HUMAN}"

check_dar_integrity  "$FULL_BASE" "FULL"
check_par2_per_slice "$FULL_BASE" "$FULL_SLICES"
check_par2_verify    "$FULL_BASE" "FULL"

[[ $DO_BITROT -eq 1 ]] && do_bitrot_test "$FULL_BASE"

# ── DIFF backup ───────────────────────────────────────────────────────────────
banner "Phase 2 — DIFF backup"
update_diff_primer

diff_elapsed=$(run_backup "-D" "DIFF")
DIFF_BASE=$(find_archive_base "DIFF")

DIFF_SLICES=0
if [[ -z "$DIFF_BASE" ]]; then
    fail "Could not find DIFF archive base"
else
    DIFF_SLICES=$(count_slices "$DIFF_BASE")
    info "Archive: ${DIFF_BASE}"
    info "Slices:  ${DIFF_SLICES}"
    check_dar_integrity  "$DIFF_BASE" "DIFF"
    check_par2_per_slice "$DIFF_BASE" "$DIFF_SLICES"
    check_par2_verify    "$DIFF_BASE" "DIFF"
    verify_diff_contents "$FULL_BASE" "$DIFF_BASE"
fi

# ── RSS summary ───────────────────────────────────────────────────────────────
banner "Memory usage summary"
stop_rss_monitor
RSS_MONITOR_PID=""

for proc in dar-backup dar par2; do
    peak=$(peak_rss_kb "$proc")
    if [[ -n "$peak" && "$peak" -gt 0 ]]; then
        peak_mb=$(( peak / 1024 ))
        info "Peak RSS  ${proc}: ${peak_mb} MB  (${peak} kB)"
    fi
done

# ── write summary ─────────────────────────────────────────────────────────────
banner "Summary"
{
    echo "dar-backup large-scale test"
    echo "Script version: ${SCRIPT_VERSION}"
    echo "Run:           ${DATESTAMP}"
    echo "dar-backup:    ${DAR_BACKUP_VERSION:-unknown}"
    echo "git commit:    ${GIT_COMMIT:-unknown}"
    echo "dar:           ${DAR_VERSION:-unknown}"
    echo "par2:          ${PAR2_VERSION:-unknown}"
    echo "python:        ${PYTHON_VERSION:-unknown}"
    echo "OS:            ${OS_DESC:-unknown}"
    echo "kernel:        ${KERNEL:-unknown}"
    echo "Slice size:    ${SLICE_SIZE}"
    echo "PAR2 ratio:    ${PAR2_RATIO}%"
    echo ""
    echo "FULL archive:  ${FULL_BASE:-unknown}"
    echo "FULL slices:   ${FULL_SLICES:-?}"
    echo "FULL size:     ${FULL_SIZE_HUMAN:-?}"
    echo "FULL elapsed:  ${full_elapsed}s"
    echo ""
    echo "DIFF archive:  ${DIFF_BASE:-unknown}"
    echo "DIFF slices:   ${DIFF_SLICES:-?}"
    echo "DIFF elapsed:  ${diff_elapsed}s"
    echo ""
    for proc in dar-backup dar par2; do
        peak=$(peak_rss_kb "$proc")
        [[ -n "$peak" && "$peak" -gt 0 ]] && \
            echo "Peak RSS ${proc}: $(( peak / 1024 )) MB"
    done
    echo ""
    echo "Failures:      ${FAILURES}"
    echo "Metrics DB:    $(basename "${METRICS_DB}")  (kept at --base/results/)"
    echo "Log:           $(basename "${LOGFILE}")  (kept at --base/results/)"
} | tee "$SUMMARY"

if [[ $FAILURES -eq 0 ]]; then
    echo -e "\n${GREEN}${BOLD}All checks passed.${RESET}"
    exit 0
else
    echo -e "\n${RED}${BOLD}${FAILURES} check(s) failed — see log: ${LOGFILE}${RESET}"
    exit 1
fi
