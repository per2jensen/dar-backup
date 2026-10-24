#!/usr/bin/env bash

# Provision a fresh Linux guest and return structured pytest diagnostics.

set -euo pipefail

if [[ "$#" -ne 6 ]]; then
    >&2 echo "ERROR: usage: $0 SOURCE_ARCHIVE MODE RESULT_DIR APPLICATION_COMMIT ORCHESTRATION_COMMIT PROVISIONER"
    exit 2
fi

SOURCE_ARCHIVE="$1"
MODE="$2"
RESULT_DIR="$3"
APPLICATION_COMMIT="$4"
ORCHESTRATION_COMMIT="$5"
PROVISIONER="$6"

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

case "${PROVISIONER}" in
    debian)
        PACKAGE_MANAGER="apt"
        PACKAGE_MANIFEST_FORMAT="dpkg-query-v1"
        ;;
    fedora)
        PACKAGE_MANAGER="dnf"
        PACKAGE_MANIFEST_FORMAT="rpm-nevra-v1"
        ;;
    *)
        >&2 echo "ERROR: unsupported provisioner: ${PROVISIONER}"
        exit 2
        ;;
esac

mkdir -p "${RESULT_DIR}"
CONSOLE_LOG="${RESULT_DIR}/guest-console.log"
exec > >(tee -a "${CONSOLE_LOG}") 2>&1

STARTED_AT="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
STATUS="SETUP_FAILED"
DETAIL="Guest setup did not complete"
FINAL_EXIT_CODE=2
WORK_DIR=""
GUEST_HOME=""
PACKAGE_MANIFEST_PATH=""
ENVIRONMENT_ADJUSTMENTS_JSON="[]"

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
write_result() {
    local finished_at os_release os_id os_version_id kernel_version python_version pytest_version
    local dar_version dar_manager_version par2_version
    local selinux_availability selinux_mode selinux_policy

    finished_at="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
    os_release="$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    os_id="$(grep '^ID=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    os_version_id="$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
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
    selinux_availability="unavailable"
    selinux_mode="unavailable"
    selinux_policy=""
    if command -v getenforce >/dev/null 2>&1; then
        selinux_availability="available"
        selinux_mode="$(getenforce 2>/dev/null | tr '[:upper:]' '[:lower:]' || printf 'unknown')"
        if command -v sestatus >/dev/null 2>&1; then
            selinux_policy="$(
                sestatus 2>/dev/null \
                    | sed -n 's/^[[:space:]]*Loaded policy name:[[:space:]]*//p' \
                    | head -n 1
            )"
        fi
    fi

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
        "${os_id}" \
        "${os_version_id}" \
        "${kernel_version}" \
        "${python_version}" \
        "${pytest_version}" \
        "${dar_version}" \
        "${dar_manager_version}" \
        "${par2_version}" \
        "${PACKAGE_MANAGER}" \
        "${PACKAGE_MANIFEST_FORMAT}" \
        "${ENVIRONMENT_ADJUSTMENTS_JSON}" \
        "${selinux_availability}" \
        "${selinux_mode}" \
        "${selinux_policy}" \
        "${PACKAGE_MANIFEST_PATH}" <<'PY'
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
    os_id,
    os_version_id,
    kernel_version,
    python_version,
    pytest_version,
    dar_version,
    dar_manager_version,
    par2_version,
    package_manager,
    package_manifest_format,
    environment_adjustments_json,
    selinux_availability,
    selinux_mode,
    selinux_policy,
    package_manifest_path,
) = sys.argv[1:]

try:
    environment_adjustments = json.loads(environment_adjustments_json)
except json.JSONDecodeError as exc:
    raise SystemExit(f"ERROR: invalid environment adjustment evidence: {exc.msg}") from exc
if not isinstance(environment_adjustments, list) or any(
    not isinstance(value, str) or not value for value in environment_adjustments
):
    raise SystemExit("ERROR: environment adjustments must be a list of non-empty strings")

if selinux_availability not in {"available", "unavailable"}:
    raise SystemExit(f"ERROR: invalid SELinux availability: {selinux_availability!r}")
if selinux_mode not in {"disabled", "enforcing", "permissive", "unavailable"}:
    raise SystemExit(f"ERROR: invalid SELinux mode: {selinux_mode!r}")
if selinux_availability == "unavailable" and selinux_mode != "unavailable":
    raise SystemExit("ERROR: unavailable SELinux must use unavailable mode")
if selinux_availability == "available" and selinux_mode == "unavailable":
    raise SystemExit("ERROR: available SELinux cannot use unavailable mode")
if selinux_policy and not all(character.isalnum() or character in "._-" for character in selinux_policy):
    raise SystemExit(f"ERROR: invalid SELinux policy name: {selinux_policy!r}")

package_manifest = None
package_manifest_sha256 = None
if package_manifest_path:
    manifest_lines = Path(package_manifest_path).read_text(encoding="utf-8").splitlines()
    if package_manifest_format == "dpkg-query-v1":
        package_manifest = {}
        for line_number, line in enumerate(manifest_lines, start=1):
            fields = line.split("\t")
            if len(fields) != 4:
                raise SystemExit(
                    f"ERROR: malformed dpkg manifest line {line_number}: expected four fields"
                )
            package, version, architecture, package_status = fields
            if package_status.strip() != "ii":
                continue
            package_key = f"{package}:{architecture}"
            if package_key in package_manifest:
                raise SystemExit(f"ERROR: duplicate package in dpkg manifest: {package_key}")
            package_manifest[package_key] = version
        package_manifest = dict(sorted(package_manifest.items()))
    elif package_manifest_format == "rpm-nevra-v1":
        package_manifest = []
        identities = set()
        for line_number, line in enumerate(manifest_lines, start=1):
            fields = line.split("\t")
            if len(fields) != 5:
                raise SystemExit(
                    f"ERROR: malformed RPM manifest line {line_number}: expected five fields"
                )
            name, epoch, version, release, architecture = fields
            epoch = "0" if epoch in {"", "(none)"} else epoch
            values = (name, epoch, version, release, architecture)
            if any(not value or any(character in value for character in "\r\n\t") for value in values):
                raise SystemExit(f"ERROR: invalid RPM manifest line {line_number}")
            if values in identities:
                raise SystemExit(f"ERROR: duplicate RPM package in manifest: {name}.{architecture}")
            identities.add(values)
            package_manifest.append(
                {
                    "name": name,
                    "epoch": epoch,
                    "version": version,
                    "release": release,
                    "architecture": architecture,
                }
            )
        package_manifest.sort(
            key=lambda entry: (
                entry["name"],
                entry["epoch"],
                entry["version"],
                entry["release"],
                entry["architecture"],
            )
        )
    else:
        raise SystemExit(f"ERROR: unsupported package manifest format: {package_manifest_format}")
    if not package_manifest:
        raise SystemExit("ERROR: package manifest contains no installed packages")
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
    "os_id": os_id,
    "os_version_id": os_version_id,
    "kernel": kernel_version,
    "python": python_version,
    "pytest": pytest_version,
    "dar": dar_version,
    "dar_manager": dar_manager_version,
    "par2": par2_version,
    "package_manager": package_manager,
    "package_manifest_format": package_manifest_format,
    "environment_adjustments": environment_adjustments,
    "mandatory_access_control": {
        "selinux": {
            "availability": selinux_availability,
            "mode": selinux_mode,
            "policy": selinux_policy or None,
        }
    },
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
            "${GUEST_HOME}"/dar-backup-vm-test.*)
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
echo "Provisioner: ${PROVISIONER}"

GUEST_HOME="${HOME:-}"
if [[ -z "${GUEST_HOME}" || "${GUEST_HOME}" != /* || "${GUEST_HOME}" == "/" || ! -d "${GUEST_HOME}" || ! -w "${GUEST_HOME}" ]]; then
    >&2 echo "ERROR: guest home directory is missing or unsafe: ${GUEST_HOME:-<empty>}"
    exit 2
fi

provision_debian() {
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

    # Ubuntu's libguestfs appliance builder must be able to read this kernel.
    local kernel_image
    kernel_image="/boot/vmlinuz-$(uname -r)"
    if [[ -f "${kernel_image}" ]]; then
        sudo chmod 0644 "${kernel_image}"
    fi
}

provision_fedora() {
    sudo dnf -y install \
        acl \
        dar \
        git \
        glibc-langpack-en \
        guestfs-tools \
        par2cmdline \
        python3 \
        python3-devel \
        python3-pip

}

collect_package_manifest() {
    if [[ "${PACKAGE_MANIFEST_FORMAT}" == "dpkg-query-v1" ]]; then
        PACKAGE_MANIFEST_PATH="${RESULT_DIR}/dpkg-manifest.tsv"
        LC_ALL=C dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n' \
            | LC_ALL=C sort > "${PACKAGE_MANIFEST_PATH}"
        return
    fi
    if [[ "${PACKAGE_MANIFEST_FORMAT}" == "rpm-nevra-v1" ]]; then
        PACKAGE_MANIFEST_PATH="${RESULT_DIR}/rpm-manifest.tsv"
        LC_ALL=C rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' \
            | LC_ALL=C sort > "${PACKAGE_MANIFEST_PATH}"
        return
    fi
    >&2 echo "ERROR: unsupported package manifest format: ${PACKAGE_MANIFEST_FORMAT}"
    exit 2
}

case "${PROVISIONER}" in
    debian)
        provision_debian
        ;;
    fedora)
        provision_fedora
        ;;
esac

export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

WORK_DIR="$(mktemp -d --tmpdir="${GUEST_HOME}" dar-backup-vm-test.XXXXXXXX)"
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

collect_package_manifest

mkdir -p "${RESULT_DIR}/pytest"
mkdir -p "${RESULT_DIR}/restoretest-catalog"
export DAR_BACKUP_VM_ARTIFACT_DIR="${RESULT_DIR}/restoretest-catalog"
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
