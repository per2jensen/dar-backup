"""
Security tests for XXE (XML External Entity) protection.

These tests verify that the application's XML parsing code does not expand
external entities, protecting against CVE-2022-23437 and related XXE attacks.

Three layers are tested:
  - DoctypeStripper: DOCTYPE declaration is stripped before ET sees the XML.
  - iter_files_with_paths_from_xml: file-based XML listing is safe.
  - find_files_with_paths: string-based XML listing is safe.

Safe outcome in all cases: ET.ParseError because the entity reference (&xxe;)
is left undefined after DOCTYPE removal — the entity is never expanded.
"""

import sys
import xml.etree.ElementTree as ET

import pytest

from dar_backup.dar_backup import (
    DoctypeStripper,
    find_files_with_paths,
    iter_files_with_paths_from_xml,
)

pytestmark = pytest.mark.unit

# DAR-format XML with an embedded XXE payload.
# After DOCTYPE removal &xxe; becomes an undefined entity → ParseError.
_XXE_PAYLOAD = (
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<Archive>'
    '<Directory name="home">'
    '<File name="&xxe;" size="0"/>'
    '</Directory>'
    '</Archive>'
)


def test_python_version_is_safe_against_xxe():
    """
    Python < 3.11 has CVE-2022-23437 — xml.etree.ElementTree vulnerable to XXE.
    Enforce that the runtime is 3.11 or newer.
    """
    assert sys.version_info >= (3, 11), (
        f"Python {sys.version_info.major}.{sys.version_info.minor} is vulnerable to XXE "
        f"(CVE-2022-23437). Upgrade to Python 3.11+."
    )


def test_doctype_stripper_removes_xxe_doctype(tmp_path):
    """
    DoctypeStripper must strip the DOCTYPE declaration so ET never sees the
    external entity definition.
    """
    xml_path = tmp_path / "xxe.xml"
    xml_path.write_text(_XXE_PAYLOAD, encoding="utf-8")

    content = DoctypeStripper(str(xml_path)).read()

    assert "<!DOCTYPE" not in content
    assert "file:///etc/passwd" not in content


def test_iter_files_with_paths_from_xml_is_safe_against_xxe(tmp_path):
    """
    iter_files_with_paths_from_xml must not expand external entities.

    After DOCTYPE stripping &xxe; is undefined. ET.ParseError is the correct
    safe outcome: the entity was rejected, not silently read from disk.
    """
    xml_path = tmp_path / "xxe.xml"
    xml_path.write_text(_XXE_PAYLOAD, encoding="utf-8")

    with pytest.raises(ET.ParseError):
        list(iter_files_with_paths_from_xml(str(xml_path)))


def test_find_files_with_paths_is_safe_against_xxe():
    """
    find_files_with_paths must not expand external entities.

    The regex strips the DOCTYPE declaration; the remaining undefined entity
    reference causes ET.ParseError — the safe, non-leaking outcome.
    """
    with pytest.raises(ET.ParseError):
        find_files_with_paths(_XXE_PAYLOAD)
