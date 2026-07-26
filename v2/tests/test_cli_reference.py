"""Tests that keep the CLI reference synchronized with every command parser."""

# Ruff's S101 rule is inappropriate for pytest, where assertions are the test API.
# ruff: noqa: S101

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.component

V2_DIR = Path(__file__).parent.parent
CLI_REFERENCE = V2_DIR / "doc" / "cli-reference.md"
SOURCE_DIR = V2_DIR / "src" / "dar_backup"

CLI_SECTIONS = (
    pytest.param("dar_backup.py", "Dar-backup options", "Dar-backup option details", id="dar-backup"),
    pytest.param("manager.py", "Manager Options", "Manager option details", id="manager"),
    pytest.param("cleanup.py", "Cleanup options", "Cleanup option details", id="cleanup"),
    pytest.param("clean_log.py", "Clean-log options", "Clean-log option details", id="clean-log"),
    pytest.param(
        "dar_backup_systemd.py",
        "Dar-backup-systemd options",
        "Dar-backup-systemd option details",
        id="dar-backup-systemd",
    ),
    pytest.param("installer.py", "Installer options", "Installer option details", id="installer"),
    pytest.param("demo.py", "Demo options", "Demo option details", id="demo"),
    pytest.param(
        "dashboard.py",
        "Dar-backup-dashboard options",
        "Dar-backup-dashboard option details",
        id="dar-backup-dashboard",
    ),
)


def _declared_parser_options(source_path: Path) -> set[str]:
    """Extract explicit and automatic help options from an argparse parser.

    Args:
        source_path: Python module containing one command-line parser.

    Returns:
        Every short and long option declared through ``add_argument``, plus
        argparse's automatic ``-h`` and ``--help`` options.

    Raises:
        ValueError: If the source contains no ``ArgumentParser`` construction
            or no optional arguments.
        SyntaxError: If the source module cannot be parsed.
    """
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    has_argument_parser = False
    options: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute) and node.func.attr == "ArgumentParser":
            has_argument_parser = True
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "add_argument":
            continue
        for argument in node.args:
            if not isinstance(argument, ast.Constant) or not isinstance(argument.value, str):
                continue
            if argument.value.startswith("-"):
                options.add(argument.value)

    if not has_argument_parser:
        raise ValueError(f"No ArgumentParser construction found in {source_path}")
    if not options:
        raise ValueError(f"No optional arguments found in {source_path}")

    options.update({"-h", "--help"})
    return options


def _command_section(document: str, heading: str) -> str:
    """Return one command's level-two section from the reference document.

    Args:
        document: Complete CLI reference Markdown.
        heading: Level-two heading text without the ``##`` prefix.

    Returns:
        Section content, including its level-two heading.

    Raises:
        ValueError: If the requested heading is absent.
    """
    marker = f"## {heading}\n"
    start = document.find(marker)
    if start < 0:
        raise ValueError(f"CLI reference section not found: {heading}")

    end = document.find("\n## ", start + len(marker))
    if end < 0:
        return document[start:]
    return document[start:end]


def _split_summary_and_details(section: str, details_heading: str) -> tuple[str, str]:
    """Split a command section into its short list and detailed entries.

    Args:
        section: Complete level-two command section.
        details_heading: Level-three option-details heading without ``###``.

    Returns:
        A tuple containing the short-list portion and detailed portion.

    Raises:
        ValueError: If the details heading is absent.
    """
    marker = f"### {details_heading}\n"
    split_at = section.find(marker)
    if split_at < 0:
        raise ValueError(f"CLI option-details section not found: {details_heading}")
    return section[:split_at], section[split_at:]


def _option_is_present(text: str, option: str) -> bool:
    """Return whether an exact CLI option token occurs in text.

    Args:
        text: Markdown content to inspect.
        option: Short or long command-line option, including leading hyphens.

    Returns:
        True when the exact option occurs outside a longer option name.
    """
    pattern = rf"(?<![A-Za-z0-9-]){re.escape(option)}(?![A-Za-z0-9-])"
    return re.search(pattern, text) is not None


def _detail_heading_options(details: str) -> set[str]:
    """Extract option tokens from level-four detail headings.

    Args:
        details: Detailed portion of one command's reference section.

    Returns:
        Options named in headings such as ``#### `-c`, `--config-file <path>```.
    """
    options: set[str] = set()
    for line in details.splitlines():
        if not line.startswith("#### "):
            continue
        options.update(re.findall(r"`(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*)", line))
    return options


@pytest.mark.parametrize("source_name,section_heading,details_heading", CLI_SECTIONS)
def test_cli_reference_short_list_contains_every_parser_option(
    source_name: str,
    section_heading: str,
    details_heading: str,
) -> None:
    """Every parser option must occur in its own command's short list.

    Args:
        source_name: Parser module filename.
        section_heading: Command section heading in the CLI reference.
        details_heading: Detailed option subsection heading.

    Returns:
        None.

    Raises:
        AssertionError: If a parser option is absent from the command's short
            option list.
    """
    document = CLI_REFERENCE.read_text(encoding="utf-8")
    section = _command_section(document, section_heading)
    summary, _details = _split_summary_and_details(section, details_heading)
    expected = _declared_parser_options(SOURCE_DIR / source_name)
    missing = sorted(option for option in expected if not _option_is_present(summary, option))

    assert not missing, (
        f"{section_heading} short list is missing parser options from {source_name}: "
        f"{', '.join(missing)}"
    )


@pytest.mark.parametrize("source_name,section_heading,details_heading", CLI_SECTIONS)
def test_cli_reference_has_details_for_every_parser_option(
    source_name: str,
    section_heading: str,
    details_heading: str,
) -> None:
    """Every parser option must have a paragraph under an option heading.

    Args:
        source_name: Parser module filename.
        section_heading: Command section heading in the CLI reference.
        details_heading: Detailed option subsection heading.

    Returns:
        None.

    Raises:
        AssertionError: If a parser option has no detailed option heading.
    """
    document = CLI_REFERENCE.read_text(encoding="utf-8")
    section = _command_section(document, section_heading)
    _summary, details = _split_summary_and_details(section, details_heading)
    expected = _declared_parser_options(SOURCE_DIR / source_name)
    documented = _detail_heading_options(details)

    assert expected <= documented, (
        f"{section_heading} has no detail heading for parser options from {source_name}: "
        f"{', '.join(sorted(expected - documented))}"
    )


def test_option_in_another_command_does_not_satisfy_section_coverage() -> None:
    """An option mentioned only under another command must remain missing.

    Returns:
        None.

    Raises:
        AssertionError: If section extraction leaks content from another
            command.
    """
    document = (
        "## First options\n"
        "```text\n--first\n```\n"
        "### First option details\n"
        "#### `--first`\n\nFirst option.\n"
        "## Second options\n"
        "```text\n--second\n```\n"
    )
    first_section = _command_section(document, "First options")

    assert not _option_is_present(first_section, "--second")


def test_option_body_mention_does_not_replace_detail_heading() -> None:
    """A prose mention without its own heading must not count as option details.

    Returns:
        None.

    Raises:
        AssertionError: If a body-only option mention is treated as a detail
            heading.
    """
    details = (
        "### Example option details\n"
        "#### `--documented`\n\n"
        "Mentions --missing in the body only.\n"
    )

    assert _detail_heading_options(details) == {"--documented"}
