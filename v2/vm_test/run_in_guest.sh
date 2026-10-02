#!/usr/bin/env bash

# Provision a fresh Ubuntu guest and return structured pytest diagnostics.

set -euo pipefail

if [[ "$#" -ne 5 ]]; then
    >&2 echo "ERROR: usage: $0 SOURCE_ARCHIVE MODE RESULT_DIR APPLICATION_COMMIT ORCHESTRATION_COMMIT"
    exit 2
fi

SOURCE_ARCHIVE="$1"
MODE="$2"
RESULT_DIR="$3"
APPLICATION_COMMIT="$4"
ORCHESTRATION_COMMIT="$5"

case "${MODE}" in
    fast|smoke|integration|full)
        ;;
    *)
        >&2 echo "ERROR: invalid test mode: ${MODE}"
        exit 2
        ;;
esac

if [[ ! -f "${SOURCE_ARCHIVE}" ]]; then
    >&2 echo "ERROR: source archive does not exist: ${SOURCE_ARCHIVE}"
    exit 2
fi

if [[ -z "${APPLICATION_COMMIT}" || -z "${ORCHESTRATION_COMMIT}" ]]; then
    >&2 echo "ERROR: commit identifiers must not be empty"
    exit 2
fi

mkdir -p "${RESULT_DIR}"
CONSOLE_LOG="${RESULT_DIR}/guest-console.log"
exec > >(tee -a "${CONSOLE_LOG}") 2>&1

STARTED_AT="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
STATUS="SETUP_FAILED"
DETAIL="Guest setup did not complete"
FINAL_EXIT_CODE=2
WORK_DIR=""
DPKG_MANIFEST=""

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
write_result() {
    local finished_at os_release kernel_version python_version pytest_version
    local dar_version dar_manager_version par2_version

    finished_at="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
    os_release="$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    kernel_version="$(uname -r 2>/dev/null || printf 'unknown')"
    python_version="$(python3 --version 2>&1 || printf 'unknown')"
    pytest_version="$(pytest --version 2>&1 | head -n 1 || printf 'unavailable')"
    # DAR prints a non-TTY warning before its version, so select the version
    # line explicitly instead of recording the first output line.
    dar_version="$(dar -V 2>&1 | sed -n '/^[[:space:]]*dar version /{s/^[[:space:]]*//;p;q;}')"
    dar_manager_version="$(dar_manager -V 2>&1 | sed -n '/^[[:space:]]*dar_manager version /{s/^[[:space:]]*//;p;q;}')"
    [[ -n "${dar_version}" ]] || dar_version="unavailable"
    [[ -n "${dar_manager_version}" ]] || dar_manager_version="unavailable"
    par2_version="$(par2 -V 2>&1 | head -n 1 || printf 'unavailable')"

    /usr/bin/python3 - \
        "${RESULT_DIR}/result.json" \
        "${STATUS}" \
        "${DETAIL}" \
        "${FINAL_EXIT_CODE}" \
        "${MODE}" \
        "${APPLICATION_COMMIT}" \
        "${ORCHESTRATION_COMMIT}" \
        "${STARTED_AT}" \
        "${finished_at}" \
        "${os_release}" \
        "${kernel_version}" \
        "${python_version}" \
        "${pytest_version}" \
        "${dar_version}" \
        "${dar_manager_version}" \
        "${par2_version}" \
        "${DPKG_MANIFEST}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    result_path,
    status,
    detail,
    exit_code,
    mode,
    application_commit,
    orchestration_commit,
    started_at,
    finished_at,
    os_release,
    kernel_version,
    python_version,
    pytest_version,
    dar_version,
    dar_manager_version,
    par2_version,
    dpkg_manifest_path,
) = sys.argv[1:]

package_manifest = None
package_manifest_sha256 = None
if dpkg_manifest_path:
    package_manifest = {}
    manifest_lines = Path(dpkg_manifest_path).read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(manifest_lines, start=1):
        fields = line.split("\t")
        if len(fields) != 4:
            raise SystemExit(
                f"ERROR: malformed dpkg manifest line {line_number}: expected four fields"
            )
        package, version, architecture, status = fields
        if status.strip() != "ii":
            continue
        package_key = f"{package}:{architecture}"
        if package_key in package_manifest:
            raise SystemExit(f"ERROR: duplicate package in dpkg manifest: {package_key}")
        package_manifest[package_key] = version
    if not package_manifest:
        raise SystemExit("ERROR: dpkg manifest contains no installed packages")
    package_manifest = dict(sorted(package_manifest.items()))
    canonical_manifest = json.dumps(
        package_manifest,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    package_manifest_sha256 = hashlib.sha256(canonical_manifest).hexdigest()

payload = {
    "status": status,
    "detail": detail,
    "exit_code": int(exit_code),
    "mode": mode,
    "application_commit": application_commit,
    "orchestration_commit": orchestration_commit,
    "started_at": started_at,
    "finished_at": finished_at,
    "os_release": os_release,
    "kernel": kernel_version,
    "python": python_version,
    "pytest": pytest_version,
    "dar": dar_version,
    "dar_manager": dar_manager_version,
    "par2": par2_version,
    "package_manifest": package_manifest,
    "package_manifest_sha256": package_manifest_sha256,
}
Path(result_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
finalize() {
    set +e
    write_result
    if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
        case "${WORK_DIR}" in
            /home/ubuntu/dar-backup-vm-test.*)
                rm -rf "${WORK_DIR}"
                ;;
            *)
                >&2 echo "ERROR: refusing to remove unexpected work directory: ${WORK_DIR}"
                ;;
        esac
    fi
    trap - EXIT
    exit "${FINAL_EXIT_CODE}"
}

trap finalize EXIT

echo "=== dar-backup fresh-VM test ==="
echo "Mode: ${MODE}"
echo "Application commit: ${APPLICATION_COMMIT}"
echo "Orchestration commit: ${ORCHESTRATION_COMMIT}"

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo -E apt-get install -y \
    acl \
    dar \
    dar-static \
    git \
    libguestfs-tools \
    locales \
    par2 \
    python3 \
    python3-venv

sudo locale-gen en_US.UTF-8

# libguestfs needs to read the running kernel when it builds its appliance.
KERNEL_IMAGE="/boot/vmlinuz-$(uname -r)"
if [[ -f "${KERNEL_IMAGE}" ]]; then
    sudo chmod 0644 "${KERNEL_IMAGE}"
fi

WORK_DIR="$(mktemp -d --tmpdir=/home/ubuntu dar-backup-vm-test.XXXXXXXX)"
tar -xf "${SOURCE_ARCHIVE}" -C "${WORK_DIR}"
CHECKOUT_ROOT="${WORK_DIR}/dar-backup"
PROJECT_DIR="${CHECKOUT_ROOT}/v2"
PREPARE_CHECKOUT="${PROJECT_DIR}/vm_test/prepare_checkout.sh"
if [[ ! -f "${PREPARE_CHECKOUT}" ]]; then
    >&2 echo "ERROR: source archive does not contain the checkout preparation script"
    exit 2
fi
bash "${PREPARE_CHECKOUT}" "${CHECKOUT_ROOT}"

cd "${PROJECT_DIR}"
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip
venv/bin/python -m pip install -e '.[dev]'
# shellcheck disable=SC1091
source venv/bin/activate

DPKG_MANIFEST="${RESULT_DIR}/dpkg-manifest.tsv"
LC_ALL=C dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
    | LC_ALL=C sort > "${DPKG_MANIFEST}"

mkdir -p "${RESULT_DIR}/pytest"
set +e
./scripts/pytest_report.sh "${MODE}" "${RESULT_DIR}/pytest"
PYTEST_EXIT_CODE="$?"
set -e

if [[ "${PYTEST_EXIT_CODE}" -eq 0 ]]; then
    STATUS="PASS"
    DETAIL="pytest and mypy passed"
    FINAL_EXIT_CODE=0
else
    STATUS="TEST_FAILED"
    DETAIL="pytest or mypy failed with status ${PYTEST_EXIT_CODE}"
    FINAL_EXIT_CODE=1
fi

exit "${FINAL_EXIT_CODE}"
