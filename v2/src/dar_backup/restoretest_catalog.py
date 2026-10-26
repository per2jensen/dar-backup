"""DAR CLI catalogue compatibility helpers for restore-test verification."""

from __future__ import annotations

import logging
import os
import random
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Callable, Iterator, Mapping, Optional, cast

from dar_backup.command_runner import CommandRunner
from dar_backup.util import get_binary_info


_SLICING_PERMISSION_RE = re.compile(
    r"(?P<permission>[bcdlps-][rwxStTs-]{9})(?:[+.])?\s+(?P<path>.+)$"
)
_SLICING_RANGE_RE = re.compile(r"^\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*$")
_SLICING_DATA_STATES = frozenset({"-----", "InRef", "Saved"})
_RAW_EXCERPT_LINE_LIMIT = 20


class DarCatalogueError(RuntimeError):
    """Report an unusable or inconsistent DAR catalogue representation."""


@dataclass(frozen=True)
class DarSlicingListing:
    """Describe a validated invocation of DAR's slicing-list format.

    Args:
        slice_map: Saved regular-file paths mapped to payload slice numbers.
        dar_version: Diagnostic DAR version reported by the installed binary.
        raw_excerpt: Bounded raw listing excerpt for failure diagnostics.
        raw_line_count: Total number of stdout lines emitted by DAR.
    """

    slice_map: Mapping[str, frozenset[int]]
    dar_version: str
    raw_excerpt: str
    raw_line_count: int


@dataclass(frozen=True)
class DarSlicingRowEvidence:
    """Describe the positional states of one file-shaped slicing row.

    Args:
        path: Normalized archive-relative path.
        data_state: First DAR slicing state, which alone describes file payload.
        ea_state: Extended-attribute state when the standard-width field is present.
        fsa_state: Filesystem-specific-attribute state when identifiable.
        permission: DAR permission field used to classify the inode type.
        slice_spec: Raw leading slice specification, or None when absent.
        later_saved_markers: Saved markers after the data column, for diagnostics.
    """

    path: str
    data_state: str
    ea_state: Optional[str]
    fsa_state: Optional[str]
    permission: str
    slice_spec: Optional[str]
    later_saved_markers: int


@dataclass(frozen=True)
class CatalogRecord:
    """Describe one entry from DAR's XML catalogue.

    Args:
        path: Normalized archive-relative path.
        entry_type: DAR XML element type in lower case.
        data_state: DAR payload state: saved, referenced, or deleted.
        metadata_state: DAR metadata state from the Attributes element.
        size_text: DAR-formatted file size, or None for non-files/omissions.
    """

    path: str
    entry_type: str
    data_state: str
    metadata_state: str
    size_text: Optional[str]


@dataclass(frozen=True)
class CatalogReconciliation:
    """Summarize agreement between XML, slicing, and physical slices.

    Args:
        expected_saved_files: Saved regular files found in XML.
        mapped_saved_files: Saved regular files found in slicing output.
        data_slices: Physical slices containing mapped regular-file payload.
        non_data_slices: Physical slices with no mapped regular-file payload.
    """

    expected_saved_files: int
    mapped_saved_files: int
    data_slices: frozenset[int]
    non_data_slices: frozenset[int]


@dataclass(frozen=True)
class IndexedSliceSelection:
    """Describe disk-backed additions needed for data-slice coverage.

    Args:
        additional_files: Eligible paths added beyond the random sample.
        data_slices: Slices containing saved regular-file payload.
        covered_slices: Data slices predicted to be covered by selections.
        unavailable_slices: Data slices with no eligible selectable file.
    """

    additional_files: tuple[str, ...]
    data_slices: frozenset[int]
    covered_slices: frozenset[int]
    unavailable_slices: frozenset[int]


class RestoreTestCatalogIndex:
    """Own a fresh disk-backed catalogue index for one verification operation.

    Args:
        operation_logger: Logger receiving cleanup and parse diagnostics.

    Raises:
        ValueError: If ``operation_logger`` is not a Logger.
    """

    def __init__(self, operation_logger: logging.Logger) -> None:
        """Initialize an unopened per-operation index.

        Args:
            operation_logger: Logger receiving cleanup and parse diagnostics.

        Returns:
            None.

        Raises:
            ValueError: If ``operation_logger`` is not a Logger.
        """
        if not isinstance(operation_logger, logging.Logger):
            raise ValueError("operation_logger must be a Logger")  # noqa: TRY004 -- project input-validation convention
        self._logger = operation_logger
        self._connection: Optional[sqlite3.Connection] = None
        self._database_path: Optional[Path] = None
        self._dar_version = "unknown"
        self._xml_excerpt = ""
        self._slicing_excerpt = ""

    @property
    def database_path(self) -> Path:
        """Return the temporary database path while the index is open.

        Returns:
            Path to the live SQLite database.

        Raises:
            RuntimeError: If the context has not been entered or is closed.
        """
        if self._database_path is None:
            raise RuntimeError("Restore-test catalogue index is not open")
        return self._database_path

    @property
    def dar_version(self) -> str:
        """Return the diagnostic DAR version recorded during CLI capture.

        Returns:
            DAR version text, or ``unknown`` before capture.
        """
        return self._dar_version

    @property
    def xml_excerpt(self) -> str:
        """Return the bounded raw XML excerpt recorded during CLI capture.

        Returns:
            Raw XML excerpt, or an empty string before capture.
        """
        return self._xml_excerpt

    @property
    def slicing_excerpt(self) -> str:
        """Return the bounded raw slicing excerpt recorded during CLI capture.

        Returns:
            Raw slicing excerpt, or an empty string before capture.
        """
        return self._slicing_excerpt

    def __enter__(self) -> RestoreTestCatalogIndex:
        """Create the temporary database and schema.

        Returns:
            This open catalogue index.

        Raises:
            RuntimeError: If the same index instance is entered twice.
            OSError: If the temporary database cannot be created.
            sqlite3.Error: If SQLite initialization fails.
        """
        if self._connection is not None or self._database_path is not None:
            raise RuntimeError("Restore-test catalogue index is already open")
        file_descriptor, database_name = tempfile.mkstemp(
            prefix="dar-backup-catalog-", suffix=".sqlite3"
        )
        os.close(file_descriptor)
        self._database_path = Path(database_name)
        try:
            self._connection = sqlite3.connect(database_name)
            self._connection.executescript(
                """
                PRAGMA journal_mode=DELETE;
                PRAGMA synchronous=FULL;
                CREATE TABLE catalog_entries (
                    path TEXT PRIMARY KEY,
                    entry_type TEXT NOT NULL,
                    data_state TEXT NOT NULL,
                    metadata_state TEXT NOT NULL,
                    size_text TEXT
                );
                CREATE TABLE slicing_paths (
                    path TEXT PRIMARY KEY,
                    slice_spec TEXT NOT NULL
                );
                CREATE TABLE slicing_entries (
                    path TEXT NOT NULL,
                    slice_number INTEGER NOT NULL CHECK (slice_number > 0),
                    PRIMARY KEY (path, slice_number),
                    FOREIGN KEY (path) REFERENCES slicing_paths(path)
                );
                CREATE INDEX slicing_entries_slice_number
                    ON slicing_entries(slice_number);
                CREATE TABLE eligible_files (
                    path TEXT PRIMARY KEY,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
                    FOREIGN KEY (path) REFERENCES catalog_entries(path)
                );
                """
            )
        except (OSError, sqlite3.Error):
            self.close()
            raise
        return self

    def __exit__(
        self,
        exception_type: Optional[type[BaseException]],
        exception: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Close and unconditionally remove the temporary database.

        Args:
            exception_type: Exception type leaving the context, if any.
            exception: Exception leaving the context, if any.
            traceback: Traceback leaving the context, if any.

        Returns:
            None.
        """
        self.close()

    def close(self) -> None:
        """Close the database and remove all SQLite sidecar files.

        Returns:
            None.
        """
        database_path = self._database_path
        connection = self._connection
        self._connection = None
        self._database_path = None
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                self._logger.warning(
                    "Could not close temporary restore-test catalogue database",
                    exc_info=True,
                )
        if database_path is None:
            return
        for suffix in ("", "-journal", "-wal", "-shm"):
            sidecar_path = Path(f"{database_path}{suffix}")
            try:
                sidecar_path.unlink(missing_ok=True)
            except OSError:
                self._logger.warning(
                    "Could not delete temporary restore-test catalogue file: %s",
                    sidecar_path,
                    exc_info=True,
                )

    def _database(self) -> sqlite3.Connection:
        """Return the live SQLite connection.

        Returns:
            Open SQLite connection.

        Raises:
            RuntimeError: If the index is not open.
        """
        if self._connection is None:
            raise RuntimeError("Restore-test catalogue index is not open")
        return self._connection

    def add_catalog_record(self, record: CatalogRecord) -> None:
        """Insert one authoritative XML catalogue record.

        Args:
            record: Validated catalogue record to insert.

        Returns:
            None.

        Raises:
            ValueError: If the record contains an unsupported or empty value.
            DarCatalogueError: If the path appears more than once.
        """
        if not isinstance(record, CatalogRecord):
            raise ValueError("record must be a CatalogRecord")  # noqa: TRY004 -- project input-validation convention
        if not record.path:
            raise ValueError("Catalogue record path must not be empty")
        if record.entry_type not in {"file", "directory", "symlink", "device", "pipe", "socket"}:
            raise ValueError(f"Unsupported DAR XML entry type: {record.entry_type!r}")
        if record.data_state not in {"saved", "referenced", "deleted"}:
            raise ValueError(f"Unsupported DAR data state: {record.data_state!r}")
        if not record.metadata_state:
            raise ValueError("DAR metadata state must not be empty")
        try:
            self._database().execute(
                """
                INSERT INTO catalog_entries (
                    path, entry_type, data_state, metadata_state, size_text
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.path,
                    record.entry_type,
                    record.data_state,
                    record.metadata_state,
                    record.size_text,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise DarCatalogueError(
                f"Duplicate path in DAR XML catalogue: {record.path!r}"
            ) from exc

    def add_slicing_record(self, path: str, slices: frozenset[int]) -> None:
        """Insert one saved regular-file slicing mapping.

        Args:
            path: Normalized archive-relative path.
            slices: Positive slice numbers containing the file payload.

        Returns:
            None.

        Raises:
            ValueError: If the path or slice set is invalid.
            DarCatalogueError: If the path has a conflicting prior mapping.
        """
        if not isinstance(path, str) or not path:
            raise ValueError("Slicing path must not be empty")
        if not isinstance(slices, frozenset) or not slices:
            raise ValueError("Slicing record must contain at least one slice")
        if any(not isinstance(number, int) or number < 1 for number in slices):
            raise ValueError("Slicing record contains an invalid slice number")
        database = self._database()
        slice_spec = ",".join(str(number) for number in sorted(slices))
        existing_row = database.execute(
            "SELECT slice_spec FROM slicing_paths WHERE path = ?", (path,)
        ).fetchone()
        if existing_row is not None:
            if existing_row[0] != slice_spec:
                raise DarCatalogueError(
                    f"Conflicting DAR slice mappings for {path!r}: "
                    f"{existing_row[0]!r} and {slice_spec!r}"
                )
            return
        database.execute(
            "INSERT INTO slicing_paths (path, slice_spec) VALUES (?, ?)",
            (path, slice_spec),
        )
        database.executemany(
            "INSERT INTO slicing_entries (path, slice_number) VALUES (?, ?)",
            ((path, number) for number in sorted(slices)),
        )

    def load_xml_file(self, xml_path: Path) -> int:
        """Stream a raw DAR XML catalogue into the SQLite index.

        Args:
            xml_path: Path to a DAR XML catalogue capture.

        Returns:
            Number of catalogue entries inserted.

        Raises:
            ValueError: If ``xml_path`` is invalid.
            DarCatalogueError: If XML is malformed or lacks required fields.
            OSError: If the file cannot be read.
        """
        if not isinstance(xml_path, Path):
            raise ValueError("xml_path must be a Path")  # noqa: TRY004 -- project input-validation convention
        if not xml_path.is_file():
            raise ValueError(f"DAR XML catalogue does not exist: {xml_path}")

        parser: ET.XMLPullParser[ET.Element] = ET.XMLPullParser(events=("start", "end"))
        directory_stack: list[str] = []
        inserted = 0
        try:
            with xml_path.open("r", encoding="utf-8", errors="strict") as xml_file:
                for line in xml_file:
                    if "<!DOCTYPE" in line:
                        continue
                    parser.feed(line)
                    inserted += self._consume_xml_events(parser, directory_stack)
            parser.close()
            inserted += self._consume_xml_events(parser, directory_stack)
        except (ET.ParseError, UnicodeError, ValueError) as exc:
            raise DarCatalogueError(
                f"Could not parse DAR XML catalogue {str(xml_path)!r}: {exc}"
            ) from exc
        if directory_stack:
            raise DarCatalogueError(
                f"DAR XML catalogue ended with unclosed directories: {directory_stack!r}"
            )
        self._database().commit()
        return inserted

    def _consume_xml_events(
        self,
        parser: ET.XMLPullParser[ET.Element],
        directory_stack: list[str],
    ) -> int:
        """Convert available XML pull events into indexed records.

        Args:
            parser: XML pull parser already fed with catalogue content.
            directory_stack: Mutable stack local to the current parse operation.

        Returns:
            Number of catalogue entries inserted.

        Raises:
            ValueError: If a required DAR XML attribute is absent or invalid.
            DarCatalogueError: If a duplicate catalogue path is found.
        """
        inserted = 0
        supported_tags = {"File", "Directory", "Symlink", "Device", "Pipe", "Socket"}
        for queued_event in parser.read_events():
            event, element = cast(tuple[str, ET.Element], queued_event)
            if event == "start" and element.tag == "Directory":
                directory_name = element.get("name")
                if not directory_name:
                    raise ValueError("DAR Directory entry has no name")
                directory_stack.append(directory_name)
                continue
            if event != "end" or element.tag not in supported_tags:
                continue

            entry_name = element.get("name")
            if not entry_name:
                raise ValueError(f"DAR {element.tag} entry has no name")
            if element.tag == "Directory":
                path_parts = list(directory_stack)
            else:
                path_parts = [*directory_stack, entry_name]
            normalized_parts = [part for part in path_parts if part not in {"", "."}]
            path = "/".join(normalized_parts).lstrip("/")
            attributes = element.find("Attributes")
            if attributes is None:
                raise ValueError(f"DAR {element.tag} entry {path!r} has no Attributes")
            data_state = attributes.get("data")
            metadata_state = attributes.get("metadata")
            if data_state is None or metadata_state is None:
                raise ValueError(
                    f"DAR {element.tag} entry {path!r} has incomplete Attributes"
                )
            self.add_catalog_record(
                CatalogRecord(
                    path=path,
                    entry_type=element.tag.lower(),
                    data_state=data_state,
                    metadata_state=metadata_state,
                    size_text=element.get("size"),
                )
            )
            inserted += 1
            if element.tag == "Directory":
                directory_stack.pop()
            element.clear()
        return inserted

    def load_slicing_file(self, slicing_path: Path) -> int:
        """Stream captured DAR slicing output into the SQLite index.

        Args:
            slicing_path: Path to raw ``-Tslicing`` output.

        Returns:
            Number of saved regular-file rows parsed.

        Raises:
            ValueError: If ``slicing_path`` is invalid.
            DarCatalogueError: If a row is malformed or conflicts.
            OSError: If the file cannot be read.
        """
        if not isinstance(slicing_path, Path):
            raise ValueError("slicing_path must be a Path")  # noqa: TRY004 -- project input-validation convention
        if not slicing_path.is_file():
            raise ValueError(f"DAR slicing listing does not exist: {slicing_path}")
        inserted = 0
        line_number = 0
        try:
            with slicing_path.open("r", encoding="utf-8", errors="strict") as slicing_file:
                for line_number, raw_line in enumerate(slicing_file, start=1):
                    try:
                        parsed = parse_slicing_listing_line(raw_line.rstrip("\r\n"))
                    except ValueError as exc:
                        raise DarCatalogueError(
                            f"Could not parse DAR slicing listing {str(slicing_path)!r} "
                            f"at line {line_number}: {exc}"
                        ) from exc
                    if parsed is None:
                        continue
                    path, slices = parsed
                    self.add_slicing_record(path, slices)
                    inserted += 1
        except UnicodeError as exc:
            raise DarCatalogueError(
                f"Could not parse DAR slicing listing {str(slicing_path)!r} "
                f"near line {line_number}: {exc}"
            ) from exc
        self._database().commit()
        return inserted

    def load_archive(
        self,
        archive_path: str,
        command_runner: CommandRunner,
        physical_slices: frozenset[int],
        timeout: Optional[int] = None,
    ) -> CatalogReconciliation:
        """Capture, index, and reconcile both DAR catalogue representations.

        Args:
            archive_path: Archive path without a DAR slice suffix.
            command_runner: Runner used to invoke the DAR CLI.
            physical_slices: Positive slice numbers found on disk.
            timeout: Command timeout in seconds, or None for runner default.

        Returns:
            Strict XML/slicing/physical reconciliation summary.

        Raises:
            ValueError: If an input is invalid.
            DarCatalogueError: If a DAR command or reconciliation fails.
            OSError: If a temporary capture cannot be created or written.
        """
        if not isinstance(archive_path, str) or not archive_path.strip():
            raise ValueError("archive_path must not be empty")
        if not isinstance(command_runner, CommandRunner):
            raise ValueError("command_runner must be a CommandRunner")  # noqa: TRY004 -- project input-validation convention
        if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
            raise ValueError("timeout must be a positive integer or None")
        if not isinstance(physical_slices, frozenset) or not physical_slices:
            raise ValueError("physical_slices must be a non-empty frozenset")
        if any(not isinstance(number, int) or number < 1 for number in physical_slices):
            raise ValueError("physical_slices must contain only positive integers")
        self.load_xml_archive(archive_path, command_runner, timeout=timeout)
        slicing_path = self._new_capture_path(".slicing.txt")
        try:
            self._capture_listing(
                [
                    "dar",
                    "-l",
                    archive_path,
                    "--noconf",
                    "-am",
                    "-as",
                    "-Tslicing",
                    "-Q",
                ],
                slicing_path,
                command_runner,
                timeout,
                "slicing",
            )
            self._slicing_excerpt = _read_bounded_excerpt(slicing_path)
            self.load_slicing_file(slicing_path)
            return self.reconcile(physical_slices)
        except DarCatalogueError as exc:
            raise DarCatalogueError(
                f"{exc}; DAR version={self._dar_version}; "
                f"XML excerpt:\n{self._xml_excerpt}\n"
                f"slicing excerpt:\n{self._slicing_excerpt}"
            ) from exc
        finally:
            self._remove_capture(slicing_path)

    def load_xml_archive(
        self,
        archive_path: str,
        command_runner: CommandRunner,
        timeout: Optional[int] = None,
    ) -> int:
        """Capture and index DAR's unfiltered XML catalogue representation.

        Args:
            archive_path: Archive path without a DAR slice suffix.
            command_runner: Runner used to invoke the DAR CLI.
            timeout: Command timeout in seconds, or None for runner default.

        Returns:
            Number of XML catalogue entries indexed.

        Raises:
            ValueError: If an input is invalid.
            RuntimeError: If XML records were already loaded.
            DarCatalogueError: If DAR fails or the XML is malformed.
            OSError: If a temporary capture cannot be created or written.
        """
        if not isinstance(archive_path, str) or not archive_path.strip():
            raise ValueError("archive_path must not be empty")
        if not isinstance(command_runner, CommandRunner):
            raise ValueError("command_runner must be a CommandRunner")  # noqa: TRY004 -- project input-validation convention
        if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
            raise ValueError("timeout must be a positive integer or None")
        database = self._database()
        existing_count = cast(
            int,
            database.execute("SELECT COUNT(*) FROM catalog_entries").fetchone()[0],
        )
        if existing_count != 0:
            raise RuntimeError("Restore-test catalogue index already contains XML records")
        self._dar_version = _dar_version()
        xml_path = self._new_capture_path(".xml")
        try:
            self._capture_listing(
                ["dar", "-l", archive_path, "--noconf", "-am", "-Txml", "-Q"],
                xml_path,
                command_runner,
                timeout,
                "XML",
            )
            self._xml_excerpt = _read_bounded_excerpt(xml_path)
            return self.load_xml_file(xml_path)
        except DarCatalogueError as exc:
            raise DarCatalogueError(
                f"{exc}; DAR version={self._dar_version}; "
                f"XML excerpt:\n{self._xml_excerpt}"
            ) from exc
        finally:
            self._remove_capture(xml_path)

    def _new_capture_path(self, suffix: str) -> Path:
        """Create a fresh empty temporary capture file.

        Args:
            suffix: Diagnostic filename suffix.

        Returns:
            Path to the new capture file.

        Raises:
            ValueError: If ``suffix`` is empty.
            OSError: If the temporary file cannot be created.
        """
        if not isinstance(suffix, str) or not suffix:
            raise ValueError("Temporary capture suffix must not be empty")
        file_descriptor, capture_name = tempfile.mkstemp(
            prefix="dar-backup-catalog-", suffix=suffix
        )
        os.close(file_descriptor)
        return Path(capture_name)

    def _capture_listing(
        self,
        command: list[str],
        destination: Path,
        command_runner: CommandRunner,
        timeout: Optional[int],
        representation: str,
    ) -> None:
        """Stream one DAR listing command to a temporary capture file.

        Args:
            command: Complete DAR command and arguments.
            destination: Fresh temporary destination path.
            command_runner: Runner used to invoke DAR.
            timeout: Command timeout or None for runner default.
            representation: Human-readable representation name for errors.

        Returns:
            None.

        Raises:
            ValueError: If command, destination, or representation is invalid.
            DarCatalogueError: If DAR exits unsuccessfully.
            OSError: If the capture cannot be written.
        """
        if not command or any(not isinstance(argument, str) or not argument for argument in command):
            raise ValueError("DAR listing command must contain non-empty strings")
        if not isinstance(destination, Path):
            raise ValueError("destination must be a Path")  # noqa: TRY004 -- project input-validation convention
        if not representation:
            raise ValueError("representation must not be empty")
        with destination.open("w", encoding="utf-8") as capture_file:

            def on_line(line: str) -> None:
                """Write one decoded DAR line to the operation-local capture.

                Args:
                    line: Decoded output line without a trailing newline.

                Returns:
                    None.
                """
                capture_file.write(line)
                capture_file.write("\n")

            result = command_runner.stream_command(command, on_line, timeout=timeout)
            capture_file.flush()
        if result.returncode == 0:
            return
        excerpt = _read_bounded_excerpt(destination)
        stderr = cast(str, result.stderr) or ""
        raise DarCatalogueError(
            f"DAR {self._dar_version} {representation} listing failed with exit "
            f"code {result.returncode}: {stderr}; raw excerpt:\n{excerpt}"
        )

    def _remove_capture(self, capture_path: Path) -> None:
        """Remove one operation-local raw listing capture.

        Args:
            capture_path: Temporary capture to remove.

        Returns:
            None.
        """
        try:
            capture_path.unlink(missing_ok=True)
        except OSError:
            self._logger.warning(
                "Could not delete temporary DAR catalogue capture: %s",
                capture_path,
                exc_info=True,
            )

    def iter_saved_files(self) -> Iterator[tuple[str, Optional[str]]]:
        """Yield saved regular-file paths and sizes in deterministic order.

        Returns:
            Iterator of archive paths and optional DAR-formatted sizes.
        """
        rows = self._database().execute(
            """
            SELECT path, size_text
            FROM catalog_entries
            WHERE entry_type = 'file' AND data_state = 'saved'
            ORDER BY path
            """
        )
        for path, size_text in rows:
            yield cast(str, path), cast(Optional[str], size_text)

    def get_slice_map(self) -> dict[str, frozenset[int]]:
        """Return indexed saved-file mappings for coverage selection.

        Returns:
            Mapping from normalized archive paths to payload slice numbers.
        """
        mutable_map: dict[str, set[int]] = {}
        rows = self._database().execute(
            """
            SELECT path, slice_number
            FROM slicing_entries
            ORDER BY path, slice_number
            """
        )
        for path, slice_number in rows:
            normalized_path = cast(str, path)
            mutable_map.setdefault(normalized_path, set()).add(cast(int, slice_number))
        return {
            path: frozenset(slice_numbers)
            for path, slice_numbers in mutable_map.items()
        }

    def index_eligible_files(
        self,
        eligibility: Callable[[str, Optional[str]], Optional[int]],
    ) -> int:
        """Evaluate saved files and persist only eligible candidates.

        Args:
            eligibility: Callback returning a non-negative byte size for an
                eligible path, or None when the file is excluded.

        Returns:
            Number of eligible saved regular files.

        Raises:
            ValueError: If ``eligibility`` is not callable or returns bad data.
            RuntimeError: If eligibility was already indexed.
        """
        if not callable(eligibility):
            raise ValueError("eligibility must be callable")  # noqa: TRY004 -- project input-validation convention
        database = self._database()
        existing_count = cast(
            int,
            database.execute("SELECT COUNT(*) FROM eligible_files").fetchone()[0],
        )
        if existing_count != 0:
            raise RuntimeError("Restore-test eligibility has already been indexed")
        eligible_count = 0
        for path, size_text in self.iter_saved_files():
            size_bytes = eligibility(path, size_text)
            if size_bytes is None:
                continue
            if not isinstance(size_bytes, int) or size_bytes < 0:
                raise ValueError(
                    f"Eligibility callback returned an invalid size for {path!r}: "
                    f"{size_bytes!r}"
                )
            database.execute(
                "INSERT INTO eligible_files (path, size_bytes) VALUES (?, ?)",
                (path, size_bytes),
            )
            eligible_count += 1
        database.commit()
        return eligible_count

    def sample_eligible_files(self, sample_size: int) -> list[str]:
        """Reservoir-sample eligible paths without materializing all candidates.

        Args:
            sample_size: Maximum number of paths to return.

        Returns:
            Random eligible paths, bounded by ``sample_size``.

        Raises:
            ValueError: If ``sample_size`` is negative or not an integer.
        """
        if not isinstance(sample_size, int) or sample_size < 0:
            raise ValueError("sample_size must be a non-negative integer")
        if sample_size == 0:
            return []
        reservoir: list[str] = []
        candidates_seen = 0
        rows = self._database().execute("SELECT path FROM eligible_files ORDER BY path")
        for row in rows:
            path = cast(str, row[0])
            candidates_seen += 1
            if candidates_seen <= sample_size:
                reservoir.append(path)
                continue
            index = random.randint(1, candidates_seen)  # noqa: S311 -- non-security sampling
            if index <= sample_size:
                reservoir[index - 1] = path
        return reservoir

    def select_slice_coverage_files(
        self,
        initially_selected: list[str],
    ) -> IndexedSliceSelection:
        """Greedily cover data slices using disk-backed eligible mappings.

        Args:
            initially_selected: Paths already selected by random sampling.

        Returns:
            Additional paths and predicted coverage details.

        Raises:
            ValueError: If a selected path is empty or duplicated.
        """
        if any(not isinstance(path, str) or not path for path in initially_selected):
            raise ValueError("initially_selected must contain non-empty paths")
        normalized_selected = [path.lstrip("/") for path in initially_selected]
        if len(set(normalized_selected)) != len(normalized_selected):
            raise ValueError("initially_selected contains duplicate paths")

        database = self._database()
        database.execute("DROP TABLE IF EXISTS temp.selected_restoretest_paths")
        database.execute("DROP TABLE IF EXISTS temp.uncovered_restoretest_slices")
        database.execute(
            "CREATE TEMP TABLE selected_restoretest_paths (path TEXT PRIMARY KEY)"
        )
        database.execute(
            "CREATE TEMP TABLE uncovered_restoretest_slices (slice_number INTEGER PRIMARY KEY)"
        )
        database.executemany(
            "INSERT INTO selected_restoretest_paths (path) VALUES (?)",
            ((path,) for path in normalized_selected),
        )
        database.execute(
            """
            INSERT INTO uncovered_restoretest_slices (slice_number)
            SELECT DISTINCT slice_number FROM slicing_entries
            """
        )
        database.execute(
            """
            DELETE FROM uncovered_restoretest_slices
            WHERE slice_number IN (
                SELECT slice_number FROM slicing_entries
                WHERE path IN (SELECT path FROM selected_restoretest_paths)
            )
            """
        )
        additions: list[str] = []
        while True:
            uncovered_count = cast(
                int,
                database.execute(
                    "SELECT COUNT(*) FROM uncovered_restoretest_slices"
                ).fetchone()[0],
            )
            if uncovered_count == 0:
                break
            best_row = database.execute(
                """
                SELECT slicing_entries.path, COUNT(*) AS new_slice_count,
                       eligible_files.size_bytes
                FROM slicing_entries
                JOIN uncovered_restoretest_slices USING (slice_number)
                JOIN eligible_files USING (path)
                WHERE slicing_entries.path NOT IN (
                    SELECT path FROM selected_restoretest_paths
                )
                GROUP BY slicing_entries.path, eligible_files.size_bytes
                ORDER BY new_slice_count DESC, eligible_files.size_bytes ASC,
                         slicing_entries.path ASC
                LIMIT 1
                """
            ).fetchone()
            if best_row is None:
                break
            best_path = cast(str, best_row[0])
            additions.append(best_path)
            database.execute(
                "INSERT INTO selected_restoretest_paths (path) VALUES (?)",
                (best_path,),
            )
            database.execute(
                """
                DELETE FROM uncovered_restoretest_slices
                WHERE slice_number IN (
                    SELECT slice_number FROM slicing_entries WHERE path = ?
                )
                """,
                (best_path,),
            )

        data_slices = frozenset(
            cast(int, row[0])
            for row in database.execute(
                "SELECT DISTINCT slice_number FROM slicing_entries ORDER BY slice_number"
            )
        )
        unavailable_slices = frozenset(
            cast(int, row[0])
            for row in database.execute(
                "SELECT slice_number FROM uncovered_restoretest_slices ORDER BY slice_number"
            )
        )
        return IndexedSliceSelection(
            additional_files=tuple(additions),
            data_slices=data_slices,
            covered_slices=data_slices - unavailable_slices,
            unavailable_slices=unavailable_slices,
        )

    def get_selected_size_texts(self, selected_paths: list[str]) -> dict[str, str]:
        """Return DAR size text only for selected restore-test files.

        Args:
            selected_paths: Archive paths selected for extraction.

        Returns:
            Mapping from each selected path to its available DAR size text.

        Raises:
            ValueError: If a selected path is empty.
        """
        if any(not isinstance(path, str) or not path for path in selected_paths):
            raise ValueError("selected_paths must contain non-empty paths")
        database = self._database()
        sizes: dict[str, str] = {}
        for path in selected_paths:
            row = database.execute(
                "SELECT size_text FROM catalog_entries WHERE path = ?",
                (path.lstrip("/"),),
            ).fetchone()
            if row is not None and isinstance(row[0], str):
                sizes[path] = row[0]
        return sizes

    def get_selected_slice_map(
        self,
        selected_paths: list[str],
    ) -> dict[str, frozenset[int]]:
        """Return slicing mappings only for selected restore-test files.

        Args:
            selected_paths: Archive paths selected for extraction.

        Returns:
            Mapping from selected normalized paths to payload slice numbers.

        Raises:
            ValueError: If a selected path is empty.
        """
        if any(not isinstance(path, str) or not path for path in selected_paths):
            raise ValueError("selected_paths must contain non-empty paths")
        database = self._database()
        selected_map: dict[str, frozenset[int]] = {}
        for selected_path in selected_paths:
            normalized_path = selected_path.lstrip("/")
            slices = frozenset(
                cast(int, row[0])
                for row in database.execute(
                    """
                    SELECT slice_number FROM slicing_entries
                    WHERE path = ? ORDER BY slice_number
                    """,
                    (normalized_path,),
                )
            )
            if slices:
                selected_map[normalized_path] = slices
        return selected_map

    def reconcile(self, physical_slices: frozenset[int]) -> CatalogReconciliation:
        """Require exact agreement between saved XML files and slicing rows.

        Referenced and deleted XML entries intentionally do not require a
        slicing mapping because they have no saved payload in this archive.

        Args:
            physical_slices: Positive slice numbers found on disk.

        Returns:
            Counts and data/non-data physical slice classifications.

        Raises:
            ValueError: If ``physical_slices`` is empty or invalid.
            DarCatalogueError: If paths disagree or mappings reference missing
                physical slices.
        """
        if not isinstance(physical_slices, frozenset) or not physical_slices:
            raise ValueError("physical_slices must be a non-empty frozenset")
        if any(not isinstance(number, int) or number < 1 for number in physical_slices):
            raise ValueError("physical_slices must contain only positive integers")
        database = self._database()
        missing_rows = database.execute(
            """
            SELECT path FROM catalog_entries
            WHERE entry_type = 'file' AND data_state = 'saved'
              AND path NOT IN (SELECT path FROM slicing_paths)
            ORDER BY path LIMIT 10
            """
        ).fetchall()
        unexpected_rows = database.execute(
            """
            SELECT path FROM slicing_paths
            WHERE path NOT IN (
                SELECT path FROM catalog_entries
                WHERE entry_type = 'file' AND data_state = 'saved'
            )
            ORDER BY path LIMIT 10
            """
        ).fetchall()
        mapped_slices = frozenset(
            cast(int, row[0])
            for row in database.execute(
                "SELECT DISTINCT slice_number FROM slicing_entries ORDER BY slice_number"
            )
        )
        out_of_range = sorted(mapped_slices - physical_slices)
        if missing_rows or unexpected_rows or out_of_range:
            missing = [cast(str, row[0]) for row in missing_rows]
            unexpected = [cast(str, row[0]) for row in unexpected_rows]
            raise DarCatalogueError(
                "DAR XML/slicing reconciliation failed: "
                f"missing mappings={missing!r}; unexpected mappings={unexpected!r}; "
                f"non-physical slices={out_of_range!r}"
            )
        expected_count = cast(
            int,
            database.execute(
                """
                SELECT COUNT(*) FROM catalog_entries
                WHERE entry_type = 'file' AND data_state = 'saved'
                """
            ).fetchone()[0],
        )
        mapped_count = cast(
            int,
            database.execute("SELECT COUNT(*) FROM slicing_paths").fetchone()[0],
        )
        return CatalogReconciliation(
            expected_saved_files=expected_count,
            mapped_saved_files=mapped_count,
            data_slices=mapped_slices,
            non_data_slices=physical_slices - mapped_slices,
        )


def _parse_slice_numbers(slice_spec: str) -> frozenset[int]:
    """Expand DAR's comma-separated slice numbers and inclusive ranges.

    Args:
        slice_spec: DAR slicing field such as ``1`` or ``1-3,5``.

    Returns:
        Positive slice numbers represented by the field.

    Raises:
        ValueError: If the field is malformed, descending, or includes zero.
    """
    if not slice_spec or not _SLICING_RANGE_RE.fullmatch(slice_spec):
        raise ValueError(f"Invalid DAR slice range: {slice_spec!r}")

    slices: set[int] = set()
    for part in slice_spec.split(","):
        bounds = part.split("-", maxsplit=1)
        first = int(bounds[0])
        last = int(bounds[-1])
        if first < 1 or last < first:
            raise ValueError(f"Invalid DAR slice range: {slice_spec!r}")
        slices.update(range(first, last + 1))
    return frozenset(slices)


def _optional_slicing_state(raw_field: str) -> Optional[str]:
    """Normalize one optional fixed-width DAR slicing state field.

    Args:
        raw_field: Fixed-width field text, possibly blank or bracketed.

    Returns:
        State text without brackets, or None for a blank field.
    """
    stripped = raw_field.strip()
    if not stripped:
        return None
    if stripped.startswith("[") and stripped.endswith("]"):
        return stripped[1:-1].strip() or None
    return stripped


def parse_slicing_listing_evidence(line: str) -> Optional[DarSlicingRowEvidence]:
    """Parse positional states from one file-shaped DAR slicing row.

    Args:
        line: A single text line emitted by DAR.

    Returns:
        Positional row evidence, or None for headers and summaries.

    Raises:
        ValueError: If a file-shaped row has an unknown data state or a saved
            row cannot be interpreted safely.
    """
    if not isinstance(line, str):
        raise ValueError("DAR slicing line must be text")  # noqa: TRY004 -- project input-validation convention
    data_open = line.find("[")
    if data_open < 0:
        return None
    data_close = line.find("]", data_open + 1)
    if data_close < 0:
        if _SLICING_PERMISSION_RE.search(line) is not None:
            raise ValueError(f"Unterminated DAR slicing data state: {line!r}")
        return None

    data_state = line[data_open + 1:data_close].strip()
    permission_match = _SLICING_PERMISSION_RE.search(line)
    if permission_match is None:
        if data_state == "Saved":
            raise ValueError(f"Unrecognized saved DAR slicing row: {line!r}")
        return None
    permission = permission_match.group("permission")
    # DAR 2.7.21 leaves Data blank for directories, which have no file payload.
    if not permission.startswith("-") and not data_state:
        return None
    if data_state not in _SLICING_DATA_STATES:
        raise ValueError(
            f"Unknown DAR slicing data state {data_state!r}: {line!r}"
        )
    prefix = line[:data_open].strip()
    path = permission_match.group("path").strip().lstrip("/")
    if not path:
        raise ValueError(f"Missing file path in DAR slicing row: {line!r}")
    state_tail = line[data_close + 1:permission_match.start()]
    optional_states = re.match(
        r"^\[[^\]]*\](?P<ea>.{7})(?P<fsa>.{5})",
        state_tail,
    )
    ea_state = None
    fsa_state = None
    if optional_states is not None:
        ea_state = _optional_slicing_state(optional_states.group("ea"))
        fsa_state = _optional_slicing_state(optional_states.group("fsa"))
    return DarSlicingRowEvidence(
        path=path,
        data_state=data_state,
        ea_state=ea_state,
        fsa_state=fsa_state,
        permission=permission,
        slice_spec=prefix.split(maxsplit=1)[0] if prefix else None,
        later_saved_markers=state_tail.count("[Saved]"),
    )


def parse_slicing_listing_line(line: str) -> Optional[tuple[str, frozenset[int]]]:
    """Parse one saved regular-file payload mapping from DAR slicing output.

    Args:
        line: A single text line emitted by DAR.

    Returns:
        A normalized archive path and its payload slice numbers, or None for
        headers, summaries, non-regular files, and non-saved data states.

    Raises:
        ValueError: If a saved regular-file row has malformed slice data.
    """
    evidence = parse_slicing_listing_evidence(line)
    if evidence is None or evidence.data_state != "Saved":
        return None
    if not evidence.permission.startswith("-"):
        return None
    if evidence.slice_spec is None:
        raise ValueError(f"Missing slice range in DAR slicing row: {line!r}")
    return evidence.path, _parse_slice_numbers(evidence.slice_spec)


def _dar_version() -> str:
    """Return the installed DAR version for diagnostics only.

    Returns:
        Version text, or ``unknown`` when it cannot be determined.
    """
    binary_info = get_binary_info("dar")
    version = binary_info.get("version", "unknown")
    if not isinstance(version, str) or not version:
        return "unknown"
    return version


def _read_bounded_excerpt(raw_path: Path, line_limit: int = _RAW_EXCERPT_LINE_LIMIT) -> str:
    """Read a bounded head-and-tail excerpt from a raw DAR listing.

    Args:
        raw_path: Temporary file containing the complete raw listing.
        line_limit: Maximum combined number of lines to return.

    Returns:
        Raw text containing at most ``line_limit`` lines.

    Raises:
        ValueError: If ``line_limit`` is less than two.
        OSError: If the raw listing cannot be read.
    """
    if line_limit < 2:
        raise ValueError("line_limit must be at least 2")
    lines = raw_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if len(lines) <= line_limit:
        return "\n".join(lines)
    head_count = line_limit // 2
    tail_count = line_limit - head_count
    omitted = len(lines) - line_limit
    return "\n".join(
        [*lines[:head_count], f"... {omitted} line(s) omitted ...", *lines[-tail_count:]]
    )


def read_slicing_listing(
    archive_path: str,
    command_runner: CommandRunner,
    operation_logger: logging.Logger,
    timeout: Optional[int] = None,
) -> DarSlicingListing:
    """Capture and parse the saved-file slicing view of a DAR archive.

    The full raw output is held in a fresh temporary file for the duration of
    this operation.  A bounded excerpt is retained in the result, while the
    temporary file is removed unconditionally.

    Args:
        archive_path: Archive path without a DAR slice suffix.
        command_runner: Runner used to invoke the DAR CLI.
        operation_logger: Logger receiving cleanup and failure context.
        timeout: Command timeout in seconds, or None for the runner default.

    Returns:
        Parsed mappings and bounded diagnostic evidence.

    Raises:
        ValueError: If an input is invalid.
        DarCatalogueError: If DAR fails, emits a malformed row, or reports
            conflicting mappings for one path.
    """
    if not isinstance(archive_path, str) or not archive_path.strip():
        raise ValueError("archive_path must not be empty")
    if not isinstance(command_runner, CommandRunner):
        raise ValueError("command_runner must be a CommandRunner")  # noqa: TRY004 -- project input-validation convention
    if not isinstance(operation_logger, logging.Logger):
        raise ValueError("operation_logger must be a Logger")  # noqa: TRY004 -- project input-validation convention
    if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
        raise ValueError("timeout must be a positive integer or None")

    file_descriptor, raw_name = tempfile.mkstemp(prefix="dar-backup-slicing-", suffix=".txt")
    os.close(file_descriptor)
    raw_path = Path(raw_name)
    slice_map: dict[str, frozenset[int]] = {}
    line_count = 0
    raw_excerpt = ""
    dar_version = _dar_version()

    try:
        with raw_path.open("w", encoding="utf-8") as raw_file:

            def on_line(line: str) -> None:
                """Persist and parse one decoded DAR output line.

                Args:
                    line: A decoded stdout line without its newline.

                Returns:
                    None.

                Raises:
                    ValueError: If a saved-file row is malformed or conflicts
                        with an earlier row for the same path.
                """
                nonlocal line_count
                line_count += 1
                raw_file.write(line)
                raw_file.write("\n")
                parsed = parse_slicing_listing_line(line)
                if parsed is None:
                    return
                path, slices = parsed
                existing = slice_map.get(path)
                if existing is not None and existing != slices:
                    raise ValueError(
                        f"Conflicting DAR slice mappings for {path!r}: "
                        f"{sorted(existing)} and {sorted(slices)}"
                    )
                slice_map[path] = slices

            command = [
                "dar",
                "-l",
                archive_path,
                "--noconf",
                "-am",
                "-as",
                "-Tslicing",
                "-Q",
            ]
            result = command_runner.stream_command(command, on_line, timeout=timeout)
            raw_file.flush()

        raw_excerpt = _read_bounded_excerpt(raw_path)
        if result.returncode != 0:
            stderr = cast(str, result.stderr) or ""
            raise DarCatalogueError(
                f"DAR {dar_version} slicing listing failed with exit code "
                f"{result.returncode}: {stderr}; raw excerpt:\n{raw_excerpt}"
            )
        return DarSlicingListing(
            slice_map=dict(slice_map),
            dar_version=dar_version,
            raw_excerpt=raw_excerpt,
            raw_line_count=line_count,
        )
    except DarCatalogueError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        try:
            raw_excerpt = _read_bounded_excerpt(raw_path)
        except OSError:
            operation_logger.exception(
                "Could not read temporary DAR slicing output for '%s'", archive_path
            )
        raise DarCatalogueError(
            f"Could not parse DAR {dar_version} slicing listing for "
            f"{archive_path!r}: {exc}; raw excerpt:\n{raw_excerpt}"
        ) from exc
    finally:
        try:
            raw_path.unlink(missing_ok=True)
        except OSError:
            operation_logger.warning(
                "Could not delete temporary DAR slicing output: %s", raw_path,
                exc_info=True,
            )
