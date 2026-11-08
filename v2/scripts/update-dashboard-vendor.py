#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Update pinned, locally served dashboard JavaScript and licence metadata."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path
from typing import Any


CHART_VERSION = "4.6.1"
COLOR_VERSION = "0.3.2"
CHART_URL = f"https://registry.npmjs.org/chart.js/-/chart.js-{CHART_VERSION}.tgz"
COLOR_URL = f"https://registry.npmjs.org/@kurkle/color/-/color-{COLOR_VERSION}.tgz"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_ROOT = PROJECT_ROOT / "src" / "dar_backup" / "data"


def _download(url: str) -> bytes:
    """Download one pinned upstream package.

    Args:
        url: HTTPS URL of the exact package tarball.

    Returns:
        Downloaded package bytes.

    Raises:
        ValueError: If the URL is not HTTPS.
        OSError: If the download fails.
    """
    if not url.startswith("https://"):
        raise ValueError(f"Vendor source URL must use HTTPS: {url}")
    with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310 — exact HTTPS package URLs are constants above
        return response.read()


def _read_member(package_bytes: bytes, member_name: str) -> bytes:
    """Read an exact regular-file member without extracting the tarball.

    Args:
        package_bytes: Complete npm tarball bytes.
        member_name: Exact member path expected inside the tarball.

    Returns:
        Member contents.

    Raises:
        ValueError: If the member is absent, not regular, or unreadable.
    """
    with tarfile.open(fileobj=io.BytesIO(package_bytes), mode="r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise ValueError(f"Package member is missing: {member_name}") from exc
        if not member.isfile():
            raise ValueError(f"Package member is not a regular file: {member_name}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise ValueError(f"Package member could not be read: {member_name}")
        return extracted.read()


def _sha256(contents: bytes) -> str:
    """Return a lowercase SHA-256 digest.

    Args:
        contents: Bytes to hash.

    Returns:
        Hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(contents).hexdigest()


def _validate_package(
    package_bytes: bytes,
    expected_name: str,
    expected_version: str,
) -> dict[str, Any]:
    """Validate an npm package's identity and MIT licence declaration.

    Args:
        package_bytes: Complete npm tarball bytes.
        expected_name: Required package name.
        expected_version: Required exact package version.

    Returns:
        Parsed package metadata.

    Raises:
        ValueError: If package identity or licence differs from expectations.
    """
    metadata = json.loads(_read_member(package_bytes, "package/package.json"))
    if metadata.get("name") != expected_name:
        raise ValueError(f"Expected package {expected_name!r}, got {metadata.get('name')!r}")
    if metadata.get("version") != expected_version:
        raise ValueError(
            f"Expected {expected_name} {expected_version}, got {metadata.get('version')!r}"
        )
    if metadata.get("license") != "MIT":
        raise ValueError(f"Expected {expected_name} licence MIT, got {metadata.get('license')!r}")
    return metadata


def _artifact_manifest(path: str, contents: bytes, chart_digest: str) -> dict[str, Any]:
    """Build one manifest entry for a Chart.js distribution artifact.

    Args:
        path: Package-relative output path.
        contents: Artifact bytes.
        chart_digest: SHA-256 digest of the source Chart.js tarball.

    Returns:
        Serializable manifest entry.
    """
    return {
        "path": path,
        "sha256": _sha256(contents),
        "source_package": "chart.js",
        "version": CHART_VERSION,
        "source_url": CHART_URL,
        "source_tarball_sha256": chart_digest,
        "license": "MIT",
        "license_files": [
            "third_party_licenses/Chart.js-LICENSE.md",
            "third_party_licenses/kurkle-color-LICENSE.md",
        ],
        "embedded_components": [
            {
                "name": "@kurkle/color",
                "version": COLOR_VERSION,
                "license": "MIT",
                "source_url": COLOR_URL,
                "source_tarball_sha256": "",
            }
        ],
    }


def main() -> int:
    """Download, validate, and replace the pinned dashboard vendor assets.

    Returns:
        Zero after every file and manifest is written successfully.

    Raises:
        ValueError: If upstream identity, licence, dependency, or bundle data differs.
        OSError: If downloading or writing fails.
    """
    chart_package = _download(CHART_URL)
    color_package = _download(COLOR_URL)
    chart_metadata = _validate_package(chart_package, "chart.js", CHART_VERSION)
    _validate_package(color_package, "@kurkle/color", COLOR_VERSION)
    if chart_metadata.get("dependencies", {}).get("@kurkle/color") != "^0.3.0":
        raise ValueError("Chart.js @kurkle/color dependency changed; perform a fresh licence audit")

    chart_source = _read_member(chart_package, "package/dist/chart.umd.js")
    chart_runtime = _read_member(chart_package, "package/dist/chart.umd.min.js")
    dependency_marker = f"@kurkle/color v{COLOR_VERSION}".encode()
    if dependency_marker not in chart_source or dependency_marker not in chart_runtime:
        raise ValueError("Pinned @kurkle/color marker was not found in both Chart.js bundles")

    chart_license = _read_member(chart_package, "package/LICENSE.md")
    color_license = _read_member(color_package, "package/LICENSE.md")
    chart_digest = _sha256(chart_package)
    color_digest = _sha256(color_package)

    vendor_dir = DATA_ROOT / "vendor"
    licence_dir = DATA_ROOT / "third_party_licenses"
    vendor_dir.mkdir(parents=True, exist_ok=True)
    licence_dir.mkdir(parents=True, exist_ok=True)
    (vendor_dir / "chart.umd.js").write_bytes(chart_source)
    (vendor_dir / "chart.umd.min.js").write_bytes(chart_runtime)
    (licence_dir / "Chart.js-LICENSE.md").write_bytes(chart_license)
    (licence_dir / "kurkle-color-LICENSE.md").write_bytes(color_license)

    artifacts = [
        _artifact_manifest("vendor/chart.umd.js", chart_source, chart_digest),
        _artifact_manifest("vendor/chart.umd.min.js", chart_runtime, chart_digest),
    ]
    for artifact in artifacts:
        artifact["embedded_components"][0]["source_tarball_sha256"] = color_digest
    manifest = {"schema_version": 1, "artifacts": artifacts}
    (vendor_dir / "vendor-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
