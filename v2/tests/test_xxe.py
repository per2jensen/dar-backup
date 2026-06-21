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


# ---------------------------------------------------------------------------
# DoctypeStripper context-manager / file-handle tests
# ---------------------------------------------------------------------------

def test_doctype_stripper_closes_file_on_normal_exit(tmp_path):
    """The underlying file handle must be closed after the with block exits normally."""
    xml_path = tmp_path / "test.xml"
    xml_path.write_text("<root/>", encoding="utf-8")

    with DoctypeStripper(str(xml_path)) as s:
        assert not s.f.closed, "file should be open inside the with block"
    assert s.f.closed, "file must be closed after the with block"


def test_doctype_stripper_closes_file_on_exception(tmp_path):
    """The underlying file handle must be closed even when an exception escapes the with block."""
    xml_path = tmp_path / "test.xml"
    xml_path.write_text("<root/>", encoding="utf-8")

    try:
        with DoctypeStripper(str(xml_path)) as s:
            raise RuntimeError("simulated mid-parse error")
    except RuntimeError:
        pass

    assert s.f.closed, "file must be closed after an exception exits the with block"


def test_iter_files_with_paths_from_xml_closes_handle_on_parse_error(tmp_path):
    """When ET.iterparse raises ParseError, the DoctypeStripper file handle must be closed.

    This guards against the pre-fix behaviour where the handle was left open for
    the GC to collect, which could exhaust OS file-descriptor limits over many runs.
    """
    xml_path = tmp_path / "bad.xml"
    xml_path.write_text(_XXE_PAYLOAD, encoding="utf-8")

    captured: list[DoctypeStripper] = []
    original_enter = DoctypeStripper.__enter__

    def capturing_enter(self: DoctypeStripper) -> DoctypeStripper:
        captured.append(self)
        return original_enter(self)

    DoctypeStripper.__enter__ = capturing_enter  # type: ignore[method-assign]
    try:
        with pytest.raises(ET.ParseError):
            list(iter_files_with_paths_from_xml(str(xml_path)))
    finally:
        DoctypeStripper.__enter__ = original_enter  # type: ignore[method-assign]

    assert captured, "DoctypeStripper must have been instantiated"
    assert captured[0].f.closed, (
        "DoctypeStripper file handle must be closed after ParseError during iterparse"
    )
