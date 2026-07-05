#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# large_scale_test.sh — pre-release torture test for dar-backup

set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
# All of these are dumped by print_run_variables() near the start of MAIN
# ORCHESTRATION, into the tee'd $SUMMARY file — so a run's exact configuration
# and derived paths are always on record, even if --keep wasn't used and the
# run directory itself is gone afterward. If you add a new top-level variable,
# add its name to RUN_VARIABLES (below the directory-layout block) too.

DATESTAMP=$(date '+%Y-%m-%d_%H-%M-%S')             # Run identifier: used in RUN_DIR, LOGFILE, SUMMARY filenames, and the JSONL record
DATE_OF_RUN=$(date '+%Y-%m-%d')                    # Calendar date only (pinned once at startup); matches the date dar-backup encodes in archive filenames
BASE_DIR="/data/tmp/large-scale-test"               # --base: root directory for runs/, results/, and the diff-primer directory. Must have MIN_FREE_MULTIPLIER x source-size free space
DEFINITION_NAME="large-scale-test"                  # Backup definition name (also the archive filename prefix); fixed, not currently a CLI option
DEFINITION_CONTENT=""                               # --definition (required): the backup definition body (-R/-g/etc. lines) supplied by the caller
SLICE_SIZE="10G"                                    # --slice: dar -s slice size; only injected into DEFINITION_CONTENT if it doesn't already set one
PAR2_RATIO=5                                        # --par2-ratio: PAR2 ERROR_CORRECTION_PERCENT written into the generated config
DO_BITROT=0                                         # --bitrot: when 1, runs do_bitrot_test (corrupt + par2 repair) on FULL, DIFF, and INCR
KEEP=0                                              # --keep: when 1, RUN_DIR is left on disk after the run instead of being deleted by cleanup()
SMOKETEST=0                                         # --smoketest: when 1, skips mirroring this run's JSONL record into the tracked repo history file
TIMEOUT=86400                                       # --timeout: COMMAND_TIMEOUT_SECS written into the generated config (dar/par2/manager command timeout, seconds)
SCRIPT_VERSION="7"                                  # Bumped whenever this script's behavior changes in a way worth tracking alongside JSONL history
MIN_FREE_MULTIPLIER=2                               # --min-free-multiplier: required free space under BASE_DIR, as a multiple of the estimated source data size
DIFF_PRIMER_DIR=""                                  # Set below to "${BASE_DIR}/diff-primer"; synthetic data mutated at each phase to exercise DIFF/INCR/restore logic
PRIMER_NON_LINK_COUNT=0                             # Set by create_diff_primer(); expected-modified-file-count threshold used by verify_diff_contents/verify_incr_contents
DAR_BACKUP_VERSION=""                               # Set by preflight() from `dar-backup --version`
GIT_COMMIT=""                                       # Set by preflight() from `git rev-parse --short HEAD` in REPO_DIR
REPO_DIR=""                                         # Set by preflight() from `pip show dar-backup`'s editable project location; also the JSONL-mirror target (unless SMOKETEST=1)
DAR_VERSION=""                                      # Set by preflight() from `dar --version`
PAR2_VERSION=""                                     # Set by preflight() from `par2 --version`
PYTHON_VERSION=""                                   # Set by preflight() from `python3 --version`
OS_DESC=""                                          # Set by preflight() from `lsb_release -d`
KERNEL=""                                           # Set by preflight() from `uname -r`

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
        --smoketest)  SMOKETEST=1;             shift   ;;
        --timeout)    TIMEOUT="$2";            shift 2 ;;
        --min-free-multiplier) MIN_FREE_MULTIPLIER="$2"; shift 2 ;;
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

# ── disk-space preflight ──────────────────────────────────────────────────────
# Estimates the real source data size from the backup definition's -R/-g paths and
# fails fast if BASE_DIR's filesystem doesn't have MIN_FREE_MULTIPLIER times that much
# free — a multi-hour run has no business discovering "disk full" three phases in.
check_disk_space() {
    local def_file="${BACKUP_D_DIR}/${DEFINITION_NAME}"
    local root_path; root_path=$(grep -m1 '^-R ' "$def_file" | awk '{print $2}')
    if [[ -z "$root_path" ]]; then
        info "No -R root path found in backup definition; skipping disk-space preflight."
        return
    fi

    local total_bytes=0
    local glob_paths; glob_paths=$(grep '^-g ' "$def_file" | awk '{print $2}')
    if [[ -z "$glob_paths" ]]; then
        total_bytes=$(du -sb "$root_path" 2>/dev/null | awk '{print $1}')
    else
        while IFS= read -r g; do
            [[ -z "$g" ]] && continue
            local full_path="${root_path%/}/${g}"
            if [[ -e "$full_path" ]]; then
                local sz; sz=$(du -sb "$full_path" 2>/dev/null | awk '{print $1}')
                total_bytes=$(( total_bytes + ${sz:-0} ))
            fi
        done <<< "$glob_paths"
    fi

    if [[ "${total_bytes:-0}" -le 0 ]]; then
        info "Could not estimate source data size; skipping disk-space preflight."
        return
    fi

    local required_bytes=$(( total_bytes * MIN_FREE_MULTIPLIER ))
    local available_bytes; available_bytes=$(df --output=avail -B1 "$BASE_DIR" 2>/dev/null | tail -1 | tr -d ' ')
    if [[ -z "$available_bytes" ]]; then
        info "Could not determine available disk space for '${BASE_DIR}'; skipping preflight check."
        return
    fi

    local total_gb required_gb available_gb
    total_gb=$(awk -v b="$total_bytes" 'BEGIN{printf "%.2f", b/1024/1024/1024}')
    required_gb=$(awk -v b="$required_bytes" 'BEGIN{printf "%.2f", b/1024/1024/1024}')
    available_gb=$(awk -v b="$available_bytes" 'BEGIN{printf "%.2f", b/1024/1024/1024}')

    if [[ "$available_bytes" -lt "$required_bytes" ]]; then
        echo "ERROR: insufficient disk space under '${BASE_DIR}'."
        echo "  Source data size: ~${total_gb} GB"
        echo "  Required (${MIN_FREE_MULTIPLIER}x source, for archive+PAR2+restore copy): ~${required_gb} GB"
        echo "  Available:        ~${available_gb} GB"
        exit 1
    fi
    info "Disk-space preflight OK: source ~${total_gb} GB, need ~${required_gb} GB (${MIN_FREE_MULTIPLIER}x), have ~${available_gb} GB free under '${BASE_DIR}'."
}

# ── directory layout ─────────────────────────────────────────────────────────
# Note the split: RUN_DIR (backups/par2/restore/backup.d) is deleted by cleanup()
# unless --keep is given. RESULTS_DIR (and everything under it — LOGFILE, SUMMARY,
# METRICS_DB, the JSONL history) is NOT under RUN_DIR and always survives — so a
# run's transcript/log outlives the run, but the actual archives do not unless
# --keep was used. This is exactly why print_run_variables() below matters: even
# without --keep, you at least always know what RUN_DIR *was*.
RUN_DIR="${BASE_DIR}/runs/${DATESTAMP}"             # This run's private working directory; wiped by cleanup() unless --keep
BACKUP_DIR="${RUN_DIR}/backups"                     # Where the FULL/DIFF/INCR .dar slices are written — gone after the run unless --keep
PAR2_DIR="${RUN_DIR}/par2"                          # Where PAR2 redundancy files + manifest are written — gone after the run unless --keep
RESTORE_DIR="${RUN_DIR}/restore"                    # Phase 3a restore target directory — gone after the run unless --keep
BACKUP_D_DIR="${RUN_DIR}/backup.d"                  # Holds the generated backup definition file (DEFINITION_NAME) — gone after the run unless --keep
RESULTS_DIR="${BASE_DIR}/results"                   # NOT under RUN_DIR — persists across every run regardless of --keep
METRICS_DB="${RESULTS_DIR}/dar-backup-metrics.db"   # dar-backup's own METRICS_DB_PATH for this run (persists)
LOGFILE="${RESULTS_DIR}/large-scale-test-${DATESTAMP}.dar-backup.log"  # dar-backup's own LOGFILE_LOCATION for this run (persists)
SUMMARY="${RESULTS_DIR}/summary-${DATESTAMP}.txt"   # Full tee'd transcript of this script's own output, including this variable dump (persists)
CONFIG_FILE="${RUN_DIR}/dar-backup.conf"            # Generated dar-backup.conf for this run — gone after the run unless --keep
DARRC="${RUN_DIR}/.darrc"                           # Copied/generated .darrc for this run — gone after the run unless --keep
RSS_LOGFILE="${RUN_DIR}/rss.log"                    # Raw per-process RSS samples written by start_rss_monitor — gone after the run unless --keep
DIFF_PRIMER_DIR="${BASE_DIR}/diff-primer"           # NOT under RUN_DIR — reused/reset by create_diff_primer() at the start of every run

mkdir -p "$BACKUP_DIR" "$PAR2_DIR" "$RESTORE_DIR" "$BACKUP_D_DIR" "$RESULTS_DIR" "$DIFF_PRIMER_DIR"

# ── variable dump ──────────────────────────────────────────────────────────
# Explicit list rather than a blanket `set`/`env` dump, so this stays a readable
# summary of *this script's* configuration and derived paths, not shell noise.
# Add new top-level variables here when you add them above.
RUN_VARIABLES=(
    DATESTAMP DATE_OF_RUN SCRIPT_VERSION
    BASE_DIR DEFINITION_NAME DEFINITION_CONTENT SLICE_SIZE PAR2_RATIO
    DO_BITROT KEEP SMOKETEST TIMEOUT MIN_FREE_MULTIPLIER
    DAR_BACKUP_VERSION GIT_COMMIT REPO_DIR DAR_VERSION PAR2_VERSION
    PYTHON_VERSION OS_DESC KERNEL
    RUN_DIR BACKUP_DIR PAR2_DIR RESTORE_DIR BACKUP_D_DIR
    RESULTS_DIR METRICS_DB LOGFILE SUMMARY CONFIG_FILE DARRC RSS_LOGFILE
    DIFF_PRIMER_DIR
)

print_run_variables() {
    banner "Run configuration"
    for name in "${RUN_VARIABLES[@]}"; do
        printf '  %-22s = %s\n' "$name" "${!name}"
    done
}

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
    # System-wide scan by command name rather than walking the process tree a fixed
    # two levels deep — simpler, and not blind to a descendant one level deeper than
    # that (e.g. if dar or par2 ever forks an extra level). On a dedicated test run
    # there's no realistic risk of an unrelated same-named process polluting the sample.
    (
        while true; do
            while read -r pid cmd rss vsz; do
                [[ -z "$pid" ]] && continue
                if [[ "$cmd" =~ ^(dar|dar-backup|par2|manager)$ ]]; then
                    [[ "$rss" -gt 0 ]] && printf '%s pid=%-6s rss=%-8s kB peak=%-8s kB cmd=%s\n' \
                        "$(date '+%H:%M:%S')" "$pid" "$rss" "$vsz" "$cmd"
                fi
            done < <(ps -eo pid=,comm=,rss=,vsize= 2>/dev/null)
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
    # grep -c already prints "0" (with exit 1) on no match; the `|| true` below only
    # guards against set -e aborting the script, it must not print a second fallback
    # value the way `|| echo 0` used to (which silently corrupted the count to "0\n0").
    local modified_count; modified_count=$(echo "$diff_saved" | grep -v "diff_new_" | { grep -c "${primer_rel}" || true; } 2>/dev/null)
    local new_count; new_count=$(echo "$diff_saved" | { grep -c "diff_new_" || true; } 2>/dev/null)
    [[ "${modified_count}" -ge "${PRIMER_NON_LINK_COUNT}" ]] && pass "Modified file count OK (${modified_count})" || fail "Modified file count LOW (${modified_count}, expected >=${PRIMER_NON_LINK_COUNT})"
    [[ "${new_count}" -ge 1 ]] && pass "New file count OK" || fail "New file missing from DIFF"
}

update_incr_primer() {
    info "Updating diff-primer data for INCR..."
    find "$DIFF_PRIMER_DIR" -type f | grep -v "link_" | while read -r f; do
        dd if=/dev/urandom of="$f" bs=$(stat -c%s "$f") count=1 2>/dev/null
    done || true
    # Remove one of the two current hardlink names; the underlying inode/content
    # survives via link_target2.txt, extending the hardlink-tracking chain one tier.
    rm "${DIFF_PRIMER_DIR}/link_target1.txt"
    ln "${DIFF_PRIMER_DIR}/link_target2.txt" "${DIFF_PRIMER_DIR}/link_target3.txt"
    dd if=/dev/urandom of="${DIFF_PRIMER_DIR}/incr_new_$(date +%s).bin" bs=1M count=2 2>/dev/null
}

verify_incr_contents() {
    local diff_base="$1" incr_base="$2" primer_rel="${DIFF_PRIMER_DIR#/}"
    banner "Phase 2c — INCR contents verification"
    local incr_saved; incr_saved=$(dar -l "${BACKUP_DIR}/${incr_base}" --noconf -am -as -Q 2>/dev/null | grep "\[Saved\]" | grep "${primer_rel}" || true)
    local modified_count; modified_count=$(echo "$incr_saved" | grep -v "incr_new_" | { grep -c "${primer_rel}" || true; } 2>/dev/null)
    local new_count; new_count=$(echo "$incr_saved" | { grep -c "incr_new_" || true; } 2>/dev/null)
    [[ "${modified_count}" -ge "${PRIMER_NON_LINK_COUNT}" ]] && pass "Modified file count OK (${modified_count})" || fail "Modified file count LOW (${modified_count}, expected >=${PRIMER_NON_LINK_COUNT})"
    [[ "${new_count}" -ge 1 ]] && pass "New file count OK" || fail "New file missing from INCR"
}

# ── content checksum tracking ─────────────────────────────────────────────────
# Captures the final source state right before the Phase 3a restore, so the restore
# can be proven byte-for-byte correct rather than just "produced a file of that name".
declare -A PRIMER_SHA256
capture_primer_checksums() {
    info "Capturing sha256 checksums of current primer files for restore verification..."
    PRIMER_SHA256=()
    while IFS= read -r -d '' f; do
        local rel="${f#"$DIFF_PRIMER_DIR"/}"
        PRIMER_SHA256["$rel"]=$(sha256sum "$f" | awk '{print $1}')
    done < <(find "$DIFF_PRIMER_DIR" -type f -print0)
}

verify_primer_checksums() {
    banner "Phase 3a — Content checksum verification"
    local ok=1 checked=0
    for rel in "${!PRIMER_SHA256[@]}"; do
        local restored="${RESTORE_PRIMER_PATH}/${rel}"
        if [[ ! -f "$restored" ]]; then
            fail "Checksum verification: restored file missing: ${rel}"
            ok=0
            continue
        fi
        local actual; actual=$(sha256sum "$restored" | awk '{print $1}')
        if [[ "$actual" == "${PRIMER_SHA256[$rel]}" ]]; then
            checked=$((checked+1))
        else
            fail "Checksum mismatch for ${rel} (expected ${PRIMER_SHA256[$rel]}, got ${actual})"
            ok=0
        fi
    done
    [[ $ok -eq 1 ]] && pass "All ${checked} restored file(s) match source sha256 checksums"
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

print_run_variables

full_elapsed=0; diff_elapsed=0; incr_elapsed=0
FULL_BASE=""; DIFF_BASE=""; INCR_BASE=""; FULL_SLICES=0

write_config; create_diff_primer; write_backup_def; check_disk_space; write_darrc; init_manager_db; start_rss_monitor

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
[[ $DO_BITROT -eq 1 ]] && do_bitrot_test "$DIFF_BASE"
verify_diff_contents "$FULL_BASE" "$DIFF_BASE"

# ── PHASE 2c ──
banner "Phase 2c — INCR backup"
info "Waiting ~2-3 minutes before mutating data for INCR (keeps primer mtimes cleanly separated in the log)..."
sleep 150
update_incr_primer
t0=$(date +%s)
if dar-backup -I -d "$DEFINITION_NAME" --config-file "$CONFIG_FILE" --darrc "$DARRC" --log-level debug; then
    incr_elapsed=$(( $(date +%s) - t0 )); pass "INCR backup completed in ${incr_elapsed}s"
else
    exit 1
fi

INCR_BASE=$(find_archive_base "INCR")
[[ -z "${INCR_BASE}" ]] && { fail "No INCR base found"; exit 1; }
INCR_SLICES=$(count_slices "$INCR_BASE")
check_dar_integrity  "$INCR_BASE" "INCR"
check_par2_per_slice "$INCR_BASE" "$INCR_SLICES"
check_par2_verify    "$INCR_BASE" "INCR"
[[ $DO_BITROT -eq 1 ]] && do_bitrot_test "$INCR_BASE"
verify_incr_contents "$DIFF_BASE" "$INCR_BASE"

capture_primer_checksums

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
if [[ -f "${RESTORE_PRIMER_PATH}/link_target1.txt" ]]; then
    fail "link_target1.txt present in latest-state restore (should have been deleted by INCR)"
else
    pass "link_target1.txt correctly absent from latest-state restore"
fi
if [[ -f "${RESTORE_PRIMER_PATH}/link_target2.txt" && -f "${RESTORE_PRIMER_PATH}/link_target3.txt" ]]; then
    inode2=$(stat -c %i "${RESTORE_PRIMER_PATH}/link_target2.txt")
    inode3=$(stat -c %i "${RESTORE_PRIMER_PATH}/link_target3.txt")
    [[ "$inode2" -eq "$inode3" ]] && pass "Hard Link Inodes match (${inode2})" || fail "Inodes mismatched (Cloned data!)"
else
    fail "Hard-link targets missing"
fi
if compgen -G "${RESTORE_PRIMER_PATH}/incr_new_*.bin" > /dev/null; then
    pass "INCR-tier new file present in latest-state restore"
else
    fail "INCR-tier new file missing from latest-state restore"
fi

verify_primer_checksums

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
INCR_SIZE=$(calc_slice_size "INCR")

# Compile final analytics screen layout using matched variable casing
echo -e "dar-backup test pass: ${DATESTAMP:-}"
echo -e "FULL elapsed: ${full_elapsed:-0}s (~${FULL_SIZE})"
echo -e "DIFF elapsed: ${diff_elapsed:-0}s (~${DIFF_SIZE})"
echo -e "INCR elapsed: ${incr_elapsed:-0}s (~${INCR_SIZE})"
echo -e "Peak Engine Memory Consumption:"
echo -e "  ├── dar-backup : ${MAX_DAR_BACKUP}"
echo -e "  ├── dar backend: ${MAX_DAR}"
echo -e "  ├── par2 engine: ${MAX_PAR2}"
echo -e "  └── db manager : ${MAX_MANAGER}"
echo -e "Failures:      ${FAILURES:-0}"

# ── Structured JSON record ────────────────────────────────────────────────────
# Appends one JSONL line to RESULTS_DIR and mirrors it to the repo doc directory.
# Python handles all JSON serialisation so version strings with special characters
# are encoded safely without manual escaping.
write_json_record() {
    local full_gb diff_gb incr_gb db_mb dar_mb_val p2_mb mgr_mb
    full_gb=$(awk '{print $1}' <<< "${FULL_SIZE:-0}")
    diff_gb=$(awk '{print $1}' <<< "${DIFF_SIZE:-0}")
    incr_gb=$(awk '{print $1}' <<< "${INCR_SIZE:-0}")
    db_mb=$(awk  '{print $1}' <<< "${MAX_DAR_BACKUP:-N/A}")
    dar_mb_val=$(awk '{print $1}' <<< "${MAX_DAR:-N/A}")
    p2_mb=$(awk  '{print $1}' <<< "${MAX_PAR2:-N/A}")
    mgr_mb=$(awk '{print $1}' <<< "${MAX_MANAGER:-N/A}")

    # --smoketest never mirrors into the tracked repo history file: a fast, tiny
    # synthetic run would otherwise sit alongside real multi-hour/116GB runs and
    # corrupt the regression-detection trend and show_large_scale_results.py output.
    local effective_repo_dir="${REPO_DIR:-}"
    if [[ $SMOKETEST -eq 1 ]]; then
        effective_repo_dir=""
        info "Smoketest mode: not mirroring this run into the tracked repo history file."
    fi

    LST_DATESTAMP="${DATESTAMP:-}" \
    LST_DATE="${DATE_OF_RUN:-}" \
    LST_GIT_COMMIT="${GIT_COMMIT:-unknown}" \
    LST_DAR_BACKUP_VER="${DAR_BACKUP_VERSION:-unknown}" \
    LST_DAR_VER="${DAR_VERSION:-unknown}" \
    LST_PAR2_VER="${PAR2_VERSION:-unknown}" \
    LST_PYTHON_VER="${PYTHON_VERSION:-unknown}" \
    LST_OS_DESC="${OS_DESC:-unknown}" \
    LST_KERNEL="${KERNEL:-unknown}" \
    LST_FULL_ELAPSED="${full_elapsed:-0}" \
    LST_FULL_GB="${full_gb:-0}" \
    LST_DIFF_ELAPSED="${diff_elapsed:-0}" \
    LST_DIFF_GB="${diff_gb:-0}" \
    LST_INCR_ELAPSED="${incr_elapsed:-0}" \
    LST_INCR_GB="${incr_gb:-0}" \
    LST_DB_MB="${db_mb}" \
    LST_DAR_MB="${dar_mb_val}" \
    LST_PAR2_MB="${p2_mb}" \
    LST_MGR_MB="${mgr_mb}" \
    LST_FAILURES="${FAILURES:-0}" \
    LST_RESULTS_DIR="${RESULTS_DIR}" \
    LST_REPO_DIR="${effective_repo_dir}" \
    python3 - << 'PYEOF'
import json, os
from pathlib import Path

def to_float(s: str) -> float | None:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None

e = os.environ
record = {
    "schema_version": 2,
    "datestamp":          e["LST_DATESTAMP"],
    "date":               e["LST_DATE"],
    "git_commit":         e["LST_GIT_COMMIT"],
    "dar_backup_version": e["LST_DAR_BACKUP_VER"],
    "dar_version":        e["LST_DAR_VER"],
    "par2_version":       e["LST_PAR2_VER"],
    "python_version":     e["LST_PYTHON_VER"],
    "os_desc":            e["LST_OS_DESC"],
    "kernel":             e["LST_KERNEL"],
    "full_elapsed_s":     int(e["LST_FULL_ELAPSED"]),
    "full_size_gb":       to_float(e["LST_FULL_GB"]),
    "diff_elapsed_s":     int(e["LST_DIFF_ELAPSED"]),
    "diff_size_gb":       to_float(e["LST_DIFF_GB"]),
    "incr_elapsed_s":     int(e["LST_INCR_ELAPSED"]),
    "incr_size_gb":       to_float(e["LST_INCR_GB"]),
    "memory_mb": {
        "dar_backup": to_float(e["LST_DB_MB"]),
        "dar":        to_float(e["LST_DAR_MB"]),
        "par2":       to_float(e["LST_PAR2_MB"]),
        "manager":    to_float(e["LST_MGR_MB"]),
    },
    "failures": int(e["LST_FAILURES"]),
    "passed":   int(e["LST_FAILURES"]) == 0,
}

results_path = Path(e["LST_RESULTS_DIR"]) / "large-scale-results.jsonl"

# ── Regression check against trailing history (read BEFORE appending this run) ──
# Warns only — real hardware/environment variance makes a hard fail too noisy here.
# This is a "look at this before tagging a release" signal, not a pass/fail gate.
def load_history(path: Path) -> list[dict]:
    if not path.exists():
        return []
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records

TREND_WINDOW = 5
REGRESSION_FACTOR = 1.5

history = [r for r in load_history(results_path) if r.get("passed")]
recent = history[-TREND_WINDOW:]

def trailing_avg(records: list[dict], key: str, mem_key: str | None = None) -> float | None:
    values = []
    for r in records:
        v = r.get("memory_mb", {}).get(mem_key) if mem_key else r.get(key)
        if isinstance(v, (int, float)):
            values.append(v)
    return sum(values) / len(values) if values else None

def check_regression(label: str, current: float | None, baseline: float | None) -> None:
    if current is None or baseline is None or baseline <= 0:
        return
    if current > baseline * REGRESSION_FACTOR:
        print(
            f"WARN  {label} ({current:.1f}) is {current / baseline:.1f}x the "
            f"trailing {len(recent)}-run average ({baseline:.1f}) — worth a look "
            f"before tagging a release.",
            flush=True,
        )

if recent:
    check_regression("FULL elapsed (s)", record["full_elapsed_s"], trailing_avg(recent, "full_elapsed_s"))
    for tool in ("dar_backup", "dar", "par2", "manager"):
        check_regression(
            f"Peak {tool} memory (MB)",
            record["memory_mb"][tool],
            trailing_avg(recent, "", mem_key=tool),
        )

with open(results_path, "a") as fh:
    fh.write(json.dumps(record, separators=(",", ":")) + "\n")

repo_dir = e.get("LST_REPO_DIR", "")
if repo_dir:
    repo_path = Path(repo_dir) / "doc" / "test-report" / "large-scale-results.jsonl"
    if repo_path.parent.is_dir():
        with open(repo_path, "a") as fh:
            fh.write(json.dumps(record, separators=(",", ":")) + "\n")
PYEOF
    info "Structured result written to: ${RESULTS_DIR}/large-scale-results.jsonl"
    if [[ -n "${effective_repo_dir}" ]]; then
        info "Structured result mirrored to: ${effective_repo_dir}/doc/test-report/large-scale-results.jsonl"
    fi
    return 0
}
write_json_record || echo "WARNING: failed to write structured JSON record" >&2

# Final status validation routing
if [ "${FAILURES:-0}" -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}✓ ALL TESTS PASSED SUCCESSFULLY${RESET}\n"
    exit 0
else
    echo -e "\n${RED}${BOLD}✗ TEST SUITE FAILED WITH ${FAILURES} ERRORS${RESET}\n"
    exit 1
fi
