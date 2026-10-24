"""Tests for disk-backed DAR XML and slicing reconciliation."""

import logging
from pathlib import Path

import pytest

from dar_backup.restoretest_catalog import DarCatalogueError
from dar_backup.restoretest_catalog import RestoreTestCatalogIndex
from dar_backup.restoretest_catalog import parse_slicing_listing_line


pytestmark = pytest.mark.unit

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "dar"


def _write_catalogue(path: Path) -> None:
    """Write a representative full/differential XML catalogue.

    Args:
        path: Destination file path.

    Returns:
        None.
    """
    path.write_text(
        """<?xml version="1.0" ?>
<!DOCTYPE Catalog SYSTEM "dar-catalog.dtd">
<Catalog format="1.3">
  <Directory name="data">
    <Attributes data="saved" metadata="saved" user="u" group="g" permissions="drwxr-xr-x" atime="1" mtime="1" ctime="1" />
    <File name="saved.bin" size="2 kio" stored="2 kio">
      <Attributes data="saved" metadata="absent" user="u" group="g" permissions="-rw-r--r--" atime="1" mtime="1" ctime="1" />
    </File>
    <File name="reference.bin" size="1 kio" stored="0">
      <Attributes data="referenced" metadata="referenced" user="u" group="g" permissions="-rw-r--r--" atime="1" mtime="1" ctime="1" />
    </File>
    <File name="deleted.bin" size="0" stored="0">
      <Attributes data="deleted" metadata="absent" user="u" group="g" permissions="-rw-r--r--" atime="1" mtime="1" ctime="1" />
    </File>
  </Directory>
</Catalog>
""",
        encoding="utf-8",
    )


def _write_slicing(path: Path, *, include_saved_file: bool = True) -> None:
    """Write representative raw DAR slicing output.

    Args:
        path: Destination file path.
        include_saved_file: Include the saved regular-file mapping when true.

    Returns:
        None.
    """
    rows = ["Slice(s) [Data ][D][ EA ][Compr][S] Permission  File"]
    if include_saved_file:
        rows.append("1-2 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin")
    rows.append("    [-----][ ] [-L-][     ][ ] -rw-r--r-- data/reference.bin")
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")


def test_catalog_index_reconciles_saved_payload_and_ignores_nonpayload_states(
    tmp_path: Path,
) -> None:
    """Require mappings only for XML entries whose payload is saved.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    xml_path = tmp_path / "catalog.xml"
    slicing_path = tmp_path / "slicing.txt"
    _write_catalogue(xml_path)
    _write_slicing(slicing_path)

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        assert index.load_xml_file(xml_path) == 4
        assert index.load_slicing_file(slicing_path) == 1
        report = index.reconcile(frozenset({1, 2, 3}))
        saved_files = list(index.iter_saved_files())

    assert saved_files == [("data/saved.bin", "2 kio")]
    assert report.expected_saved_files == 1
    assert report.mapped_saved_files == 1
    assert report.data_slices == frozenset({1, 2})
    assert report.non_data_slices == frozenset({3})


def test_catalog_index_missing_saved_payload_mapping_raises(tmp_path: Path) -> None:
    """Reject partial slicing parses that omit a saved XML file.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    xml_path = tmp_path / "catalog.xml"
    slicing_path = tmp_path / "slicing.txt"
    _write_catalogue(xml_path)
    _write_slicing(slicing_path, include_saved_file=False)

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        index.load_xml_file(xml_path)
        index.load_slicing_file(slicing_path)
        with pytest.raises(DarCatalogueError, match="missing mappings=.*saved.bin"):
            index.reconcile(frozenset({1, 2, 3}))


def test_catalog_index_conflicting_duplicate_slicing_mapping_raises(tmp_path: Path) -> None:
    """Reject two different slicing ranges for the same archive path.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    slicing_path = tmp_path / "slicing.txt"
    slicing_path.write_text(
        "1 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin\n"
        "2 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin\n",
        encoding="utf-8",
    )

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        with pytest.raises(DarCatalogueError, match="Conflicting DAR slice mappings"):
            index.load_slicing_file(slicing_path)


def test_catalog_index_mapping_to_nonphysical_slice_raises(tmp_path: Path) -> None:
    """Reject a syntactically valid mapping outside the archive inventory.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    xml_path = tmp_path / "catalog.xml"
    slicing_path = tmp_path / "slicing.txt"
    _write_catalogue(xml_path)
    slicing_path.write_text(
        "4 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin\n",
        encoding="utf-8",
    )

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        index.load_xml_file(xml_path)
        index.load_slicing_file(slicing_path)
        with pytest.raises(DarCatalogueError, match=r"non-physical slices=\[4\]"):
            index.reconcile(frozenset({1, 2, 3}))


def test_slicing_parser_accepts_whitespace_and_added_column_mutations() -> None:
    """Parse saved rows despite harmless spacing and pre-permission columns.

    Returns:
        None.
    """
    parsed = parse_slicing_listing_line(
        "  1-2,4   [Saved] [ ] [-L-] [     ] [ ] [future]   "
        "-rw-r--r--   data/file with spaces.bin  "
    )

    assert parsed == (
        "data/file with spaces.bin",
        frozenset({1, 2, 4}),
    )


def test_slicing_parser_rejects_descending_slice_range() -> None:
    """Reject a saved row whose inclusive slice range runs backwards.

    Returns:
        None.
    """
    with pytest.raises(ValueError, match="Invalid DAR slice range"):
        parse_slicing_listing_line(
            "3-1 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin"
        )


def test_catalog_index_unexpected_saved_mapping_raises(tmp_path: Path) -> None:
    """Reject a slicing path absent from the saved-file XML set.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    xml_path = tmp_path / "catalog.xml"
    slicing_path = tmp_path / "slicing.txt"
    _write_catalogue(xml_path)
    slicing_path.write_text(
        "1-2 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/saved.bin\n"
        "3 [Saved][ ] [-L-][     ][ ] -rw-r--r-- data/unexpected.bin\n",
        encoding="utf-8",
    )

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        index.load_xml_file(xml_path)
        index.load_slicing_file(slicing_path)
        with pytest.raises(
            DarCatalogueError,
            match="unexpected mappings=.*unexpected.bin",
        ):
            index.reconcile(frozenset({1, 2, 3}))


def test_catalog_index_unrecognized_saved_row_fails_parsing(
    tmp_path: Path,
) -> None:
    """Fail immediately when a changed saved row cannot be parsed.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.

    Returns:
        None.
    """
    xml_path = tmp_path / "catalog.xml"
    slicing_path = tmp_path / "slicing.txt"
    _write_catalogue(xml_path)
    slicing_path.write_text(
        "1-2 [Saved][ ] [-L-][     ][ ] no-permission-column data/saved.bin\n",
        encoding="utf-8",
    )

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        index.load_xml_file(xml_path)
        with pytest.raises(DarCatalogueError, match="Unrecognized saved DAR slicing row"):
            index.load_slicing_file(slicing_path)


def test_catalog_index_removes_temporary_database_after_context() -> None:
    """Remove the per-operation database even after normal completion."""
    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        database_path = index.database_path
        assert database_path.exists()

    assert database_path.exists() is False


@pytest.mark.parametrize("fixture_version", ["2.7.21", "2.8.6"])
def test_captured_dar_version_fixture_reconciles(fixture_version: str) -> None:
    """Keep the parser compatible with captured DAR 2.7 and 2.8 interfaces.

    Args:
        fixture_version: Captured DAR release fixture to reconcile.

    Returns:
        None.
    """
    fixture_dir = _FIXTURE_ROOT / fixture_version

    with RestoreTestCatalogIndex(logging.getLogger(__name__)) as index:
        index.load_xml_file(fixture_dir / "catalog.xml")
        index.load_slicing_file(fixture_dir / "slicing.txt")
        report = index.reconcile(frozenset({1, 2, 3, 4}))

    assert report.expected_saved_files == 2
    assert report.mapped_saved_files == 2
    assert report.data_slices == frozenset({1, 2, 3, 4})
