#!/usr/bin/env bash

# Materialize generated build inputs in an extracted immutable checkout.

set -euo pipefail

fail() {
    >&2 echo "ERROR: $1"
    exit 2
}

if [[ "$#" -ne 1 ]]; then
    fail "usage: $0 CHECKOUT_ROOT"
fi

CHECKOUT_ROOT="$1"
if [[ "${CHECKOUT_ROOT}" != /* ]]; then
    fail "checkout root must be absolute: ${CHECKOUT_ROOT}"
fi
if [[ ! -d "${CHECKOUT_ROOT}" ]]; then
    fail "checkout root does not exist: ${CHECKOUT_ROOT}"
fi

PROJECT_DIR="${CHECKOUT_ROOT}/v2"
SOURCE_README="${CHECKOUT_ROOT}/README.md"
PROJECT_README="${PROJECT_DIR}/README.md"

if [[ ! -s "${SOURCE_README}" ]]; then
    fail "committed root README is missing or empty: ${SOURCE_README}"
fi
if [[ ! -f "${PROJECT_DIR}/pyproject.toml" || ! -d "${PROJECT_DIR}/tests" ]]; then
    fail "checkout does not contain matching v2 application source and tests"
fi
if [[ -L "${PROJECT_README}" || ( -e "${PROJECT_README}" && ! -f "${PROJECT_README}" ) ]]; then
    fail "refusing unsafe generated README target: ${PROJECT_README}"
fi

if ! cp -- "${SOURCE_README}" "${PROJECT_README}"; then
    fail "cannot copy root README into v2 build directory"
fi
