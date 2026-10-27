#!/usr/bin/env bash

# Provision a fresh Linux guest and return structured pytest diagnostics.

set -euo pipefail

if [[ "$#" -ne 8 ]]; then
    >&2 echo "ERROR: usage: $0 SOURCE_ARCHIVE MODE RESULT_DIR APPLICATION_COMMIT ORCHESTRATION_COMMIT PROVISIONER DATASET_ARCHIVE DATASET_SHA256"
    exit 2
fi

SOURCE_ARCHIVE="$1"
MODE="$2"
RESULT_DIR="$3"
APPLICATION_COMMIT="$4"
ORCHESTRATION_COMMIT="$5"
PROVISIONER="$6"
DATASET_ARCHIVE="$7"
DATASET_SHA256="$8"

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

if [[ "${MODE}" == "full" ]]; then
    if [[ ! -f "${DATASET_ARCHIVE}" ]]; then
        >&2 echo "ERROR: restore-test dataset archive does not exist: ${DATASET_ARCHIVE}"
        exit 2
    fi
    if [[ ! "${DATASET_SHA256}" =~ ^[0-9a-f]{64}$ ]]; then
        >&2 echo "ERROR: restore-test dataset SHA-256 is invalid"
        exit 2
    fi
elif [[ "${DATASET_ARCHIVE}" != "-" || "${DATASET_SHA256}" != "-" ]]; then
    >&2 echo "ERROR: restore-test dataset is only valid in full mode"
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
    local dar_backup_version dar_version dar_manager_version par2_version
    local selinux_availability selinux_mode selinux_policy
    local apparmor_availability apparmor_mode apparmor_status_tool apparmor_current_label
    local apparmor_profiles_loaded apparmor_profiles_enforcing apparmor_profiles_complain
    local security_dir apparmor_status_command apparmor_status_output

    finished_at="$(date --utc +%Y-%m-%dT%H:%M:%SZ)"
    os_release="$(grep '^PRETTY_NAME=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    os_id="$(grep '^ID=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    os_version_id="$(grep '^VERSION_ID=' /etc/os-release | cut -d= -f2- | tr -d '\"')"
    kernel_version="$(uname -r 2>/dev/null || printf 'unknown')"
    python_version="$(python3 --version 2>&1 || printf 'unknown')"
    pytest_version="$(pytest --version 2>&1 | head -n 1 || printf 'unavailable')"
    dar_backup_version="unavailable"
    if command -v dar-backup >/dev/null 2>&1; then
        dar_backup_version="$(dar-backup --version 2>&1 | sed -n '1p' || printf 'unavailable')"
        [[ -n "${dar_backup_version}" ]] || dar_backup_version="unavailable"
    fi
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
    security_dir="${RESULT_DIR}/security"
    mkdir -p "${security_dir}"
    if [[ "${selinux_availability}" == "available" ]]; then
        if command -v sestatus >/dev/null 2>&1; then
            sestatus > "${security_dir}/selinux-status.txt" 2>&1 || true
        else
            printf 'sestatus unavailable; getenforce=%s\n' "${selinux_mode}" \
                > "${security_dir}/selinux-status.txt"
        fi
    else
        printf 'SELinux unavailable\n' > "${security_dir}/selinux-status.txt"
    fi

    apparmor_availability="unavailable"
    apparmor_mode="unavailable"
    apparmor_status_tool="unavailable"
    apparmor_current_label=""
    apparmor_profiles_loaded=""
    apparmor_profiles_enforcing=""
    apparmor_profiles_complain=""
    if [[ "${selinux_mode}" != "enforcing" && "${selinux_mode}" != "permissive" ]]; then
        if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
            apparmor_availability="available"
            if grep -qx 'Y' /sys/module/apparmor/parameters/enabled; then
                apparmor_mode="enabled"
                # AppArmor is the effective host MAC. Keep the schema mutually
                # exclusive even if inactive SELinux utilities are installed.
                selinux_availability="unavailable"
                selinux_mode="unavailable"
                selinux_policy=""
            else
                apparmor_mode="disabled"
            fi
        fi
    fi
    if [[ "${apparmor_availability}" == "available" ]]; then
        if [[ -r /proc/self/attr/current ]]; then
            apparmor_current_label="$(tr -d '\r\n' < /proc/self/attr/current)"
        fi
        apparmor_status_command=""
        if command -v aa-status >/dev/null 2>&1; then
            apparmor_status_command="$(command -v aa-status)"
        elif command -v apparmor_status >/dev/null 2>&1; then
            apparmor_status_command="$(command -v apparmor_status)"
        fi
        if [[ -n "${apparmor_status_command}" ]]; then
            apparmor_status_tool="available"
            apparmor_status_output="$("${apparmor_status_command}" 2>&1 || true)"
            printf '%s\n' "${apparmor_status_output}" > "${security_dir}/apparmor-status.txt"
            apparmor_profiles_loaded="$(
                printf '%s\n' "${apparmor_status_output}" \
                    | sed -n 's/^[[:space:]]*\([0-9][0-9]*\) profiles are loaded\..*/\1/p' \
                    | head -n 1
            )"
            apparmor_profiles_enforcing="$(
                printf '%s\n' "${apparmor_status_output}" \
                    | sed -n 's/^[[:space:]]*\([0-9][0-9]*\) profiles are in enforce mode\..*/\1/p' \
                    | head -n 1
            )"
            apparmor_profiles_complain="$(
                printf '%s\n' "${apparmor_status_output}" \
                    | sed -n 's/^[[:space:]]*\([0-9][0-9]*\) profiles are in complain mode\..*/\1/p' \
                    | head -n 1
            )"
        else
            printf 'AppArmor status tool unavailable\n' > "${security_dir}/apparmor-status.txt"
        fi
        printf '%s\n' "${apparmor_current_label}" \
            > "${security_dir}/apparmor-current-label.txt"
    else
        printf 'AppArmor unavailable; SELinux mode=%s\n' "${selinux_mode}" \
            > "${security_dir}/apparmor-status.txt"
        printf 'unavailable\n' > "${security_dir}/apparmor-current-label.txt"
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
        "${dar_backup_version}" \
        "${dar_version}" \
        "${dar_manager_version}" \
        "${par2_version}" \
        "${PACKAGE_MANAGER}" \
        "${PACKAGE_MANIFEST_FORMAT}" \
        "${ENVIRONMENT_ADJUSTMENTS_JSON}" \
        "${selinux_availability}" \
        "${selinux_mode}" \
        "${selinux_policy}" \
        "${apparmor_availability}" \
        "${apparmor_mode}" \
        "${apparmor_status_tool}" \
        "${apparmor_current_label}" \
        "${apparmor_profiles_loaded}" \
        "${apparmor_profiles_enforcing}" \
        "${apparmor_profiles_complain}" \
        "${PACKAGE_MANIFEST_PATH}" <<'PY'
import hashlib
import json
import re
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
    dar_backup_version,
    dar_version,
    dar_manager_version,
    par2_version,
    package_manager,
    package_manifest_format,
    environment_adjustments_json,
    selinux_availability,
    selinux_mode,
    selinux_policy,
    apparmor_availability,
    apparmor_mode,
    apparmor_status_tool,
    apparmor_current_label,
    apparmor_profiles_loaded,
    apparmor_profiles_enforcing,
    apparmor_profiles_complain,
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

valid_dar_backup_version = (
    re.fullmatch(r"dar-backup [0-9][A-Za-z0-9.+-]{0,79}", dar_backup_version)
    is not None
)
if status in {"PASS", "TEST_FAILED"} and not valid_dar_backup_version:
    raise SystemExit(f"ERROR: invalid dar-backup version: {dar_backup_version!r}")
if status not in {"PASS", "TEST_FAILED"} and (
    dar_backup_version != "unavailable" and not valid_dar_backup_version
):
    raise SystemExit(f"ERROR: invalid dar-backup version: {dar_backup_version!r}")

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

if apparmor_availability not in {"available", "unavailable"}:
    raise SystemExit(f"ERROR: invalid AppArmor availability: {apparmor_availability!r}")
if apparmor_mode not in {"disabled", "enabled", "unavailable"}:
    raise SystemExit(f"ERROR: invalid AppArmor mode: {apparmor_mode!r}")
if apparmor_status_tool not in {"available", "unavailable"}:
    raise SystemExit(f"ERROR: invalid AppArmor status-tool state: {apparmor_status_tool!r}")
if apparmor_availability == "unavailable" and (
    apparmor_mode != "unavailable"
    or apparmor_status_tool != "unavailable"
    or apparmor_current_label
):
    raise SystemExit("ERROR: unavailable AppArmor section contains active state")
if apparmor_availability == "available" and apparmor_mode == "unavailable":
    raise SystemExit("ERROR: available AppArmor cannot use unavailable mode")
if any(character in apparmor_current_label for character in "\r\n\t") or len(apparmor_current_label) > 256:
    raise SystemExit("ERROR: invalid AppArmor current label")
if selinux_mode in {"enforcing", "permissive"} and apparmor_availability != "unavailable":
    raise SystemExit("ERROR: active SELinux requires AppArmor to be unavailable")
if apparmor_mode == "enabled" and selinux_availability != "unavailable":
    raise SystemExit("ERROR: enabled AppArmor requires SELinux to be unavailable")

def optional_count(value: str, field: str) -> int | None:
    """Parse one optional non-negative AppArmor counter.

    Args:
        value: Decimal counter text, or an empty string when unavailable.
        field: Human-readable field name used in errors.

    Returns:
        Parsed counter, or ``None`` when the source did not report it.

    Raises:
        SystemExit: If the value is not a non-negative decimal integer.
    """
    if not value:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise SystemExit(f"ERROR: invalid {field} count: {value!r}") from exc
    if parsed < 0:
        raise SystemExit(f"ERROR: invalid {field} count: {value!r}")
    return parsed

profiles_loaded = optional_count(apparmor_profiles_loaded, "AppArmor loaded-profile")
profiles_enforcing = optional_count(apparmor_profiles_enforcing, "AppArmor enforcing-profile")
profiles_complain = optional_count(apparmor_profiles_complain, "AppArmor complain-profile")
profile_counts = (profiles_loaded, profiles_enforcing, profiles_complain)
if any(value is not None for value in profile_counts) and any(
    value is None for value in profile_counts
):
    raise SystemExit("ERROR: incomplete AppArmor profile counts")
if apparmor_status_tool == "unavailable" and any(
    value is not None for value in profile_counts
):
    raise SystemExit("ERROR: AppArmor profile counts require an available status tool")
if profiles_loaded is not None and profiles_enforcing + profiles_complain > profiles_loaded:
    raise SystemExit("ERROR: AppArmor profile counts exceed loaded profiles")
apparmor_profiles = None
if profiles_loaded is not None:
    apparmor_profiles = {
        "loaded": profiles_loaded,
        "enforcing": profiles_enforcing,
        "complain": profiles_complain,
    }

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
    "dar_backup": dar_backup_version,
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
        },
        "apparmor": {
            "availability": apparmor_availability,
            "mode": apparmor_mode,
            "status_tool": apparmor_status_tool,
            "current_label": apparmor_current_label or None,
            "profiles": apparmor_profiles,
        },
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
if [[ "${MODE}" == "full" ]]; then
    actual_dataset_sha256="$(sha256sum "${DATASET_ARCHIVE}" | awk '{print $1}')"
    if [[ "${actual_dataset_sha256}" != "${DATASET_SHA256}" ]]; then
        >&2 echo "ERROR: restore-test dataset digest mismatch: expected ${DATASET_SHA256}, got ${actual_dataset_sha256}"
        exit 2
    fi
    DATASET_ROOT="${WORK_DIR}/restoretest-input"
    mkdir -p "${DATASET_ROOT}"
    /usr/bin/python3 - "${DATASET_ARCHIVE}" "${DATASET_ROOT}" <<'PY'
import sys
import tarfile
from pathlib import Path, PurePosixPath

archive_path = Path(sys.argv[1])
destination = Path(sys.argv[2])
with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise SystemExit(f"ERROR: unsafe restore-test dataset member: {member.name!r}")
        if not member.isfile():
            raise SystemExit(f"ERROR: unsupported restore-test dataset member: {member.name!r}")
    archive.extractall(destination, members=members, filter="data")
PY
    export DAR_BACKUP_VM_DATASET_DIR="${DATASET_ROOT}/restoretest-dataset"
    export DAR_BACKUP_VM_DATASET_MANIFEST="${DATASET_ROOT}/restoretest-dataset-manifest.json"
    export DAR_BACKUP_VM_DATASET_SHA256="${DATASET_SHA256}"
    chmod -R a-w "${DATASET_ROOT}"
fi
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
