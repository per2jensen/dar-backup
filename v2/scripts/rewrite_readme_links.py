#!/usr/bin/env python3
"""
rewrite_readme_links.py

Rewrite repo-root-relative markdown links/images in a copy of README.md into
absolute GitHub URLs.

Why: PyPI embeds README.md verbatim as the package's long description. PyPI
has no notion of "relative to this GitHub repo" — relative links/images
(e.g. v2/doc/quick-guide.md, CHANGELOG.md) 404 on the project page. GitHub
itself resolves those same relative paths fine when it renders the file in
its repo context, so the *original* README.md must stay untouched; this
script only transforms a copy meant for packaging.

Targets already absolute (http://, https://, mailto:) or a same-document
anchor (#section) are left unchanged. Everything else is treated as a
repo-root-relative path and rewritten:
    image target  ->  https://raw.githubusercontent.com/<repo>/<ref>/<path>
    link target   ->  https://github.com/<repo>/blob/<ref>/<path>[#fragment]

Linked images (badges of the form `[![alt](img)](link)`) are handled as a
single unit so the image target becomes a raw URL and the link target
becomes a blob URL, without corrupting the nested brackets.

Usage
-----
    python rewrite_readme_links.py --input v2/README.md --output v2/README.md \\
        --ref v2-1.1.10
"""

import argparse
import logging
import re
from pathlib import Path

DEFAULT_REPO = "per2jensen/dar-backup"

# Three mutually-exclusive alternatives, tried in this order at every position:
#   1. linked image   [![alt](img_target)](link_target)
#   2. plain image     ![alt](target)
#   3. plain link       [text](target)
# Alternative 1 must come first so a badge's nested "![...](...)" is consumed
# as one unit instead of being torn apart by alternative 3.
_LINK_RE = re.compile(
    r"\[!\[([^\]]*)\]\(([^)]+)\)\]\(([^)]+)\)"
    r"|!\[([^\]]*)\]\(([^)]+)\)"
    r"|\[([^\]]*)\]\(([^)]+)\)"
)


def _setup_logging(verbose: bool) -> logging.Logger:
    """Configure logging to stderr and return the module logger.

    Args:
        verbose: If True, set DEBUG level; otherwise INFO.

    Returns:
        A configured logger instance.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return logging.getLogger(__name__)


def _rewrite_target(is_image: bool, target: str, repo: str, ref: str) -> str:
    """Rewrite a single link/image target to an absolute GitHub URL.

    Repo-root-relative paths become GitHub URLs (raw.githubusercontent.com
    for images, blob URLs for links). Already-absolute targets (http/https/
    mailto) and same-document anchors (#section) are returned unchanged.

    Args:
        is_image: True if this target came from an image (``![]()``) reference.
        target: The raw link target as written in the markdown source.
        repo: GitHub "owner/repo" slug.
        ref: Git ref (tag, branch, or commit) to pin the URL to.

    Returns:
        The (possibly rewritten) link target.
    """
    if target.startswith(("http://", "https://", "mailto:", "#")):
        return target

    path, _, fragment = target.partition("#")
    path = path.lstrip("/")
    if not path:
        return target

    if is_image:
        return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"

    url = f"https://github.com/{repo}/blob/{ref}/{path}"
    return f"{url}#{fragment}" if fragment else url


def rewrite_links(markdown_text: str, ref: str, repo: str = DEFAULT_REPO) -> str:
    """Rewrite all repo-relative markdown links/images to absolute GitHub URLs.

    Args:
        markdown_text: The README content to transform.
        ref: Git tag, branch, or commit to pin rewritten URLs to.
        repo: GitHub "owner/repo" slug.

    Returns:
        The transformed markdown text.

    Raises:
        ValueError: If ref or repo is empty.
    """
    if not ref:
        raise ValueError("ref must be a non-empty git tag, branch, or commit")
    if not repo:
        raise ValueError("repo must be a non-empty 'owner/repo' slug")

    def _replace(match: re.Match) -> str:
        if match.group(1) is not None:  # linked image: [![alt](img)](link)
            alt, img_target, link_target = match.group(1), match.group(2), match.group(3)
            new_img = _rewrite_target(is_image=True, target=img_target, repo=repo, ref=ref)
            new_link = _rewrite_target(is_image=False, target=link_target, repo=repo, ref=ref)
            return f"[![{alt}]({new_img})]({new_link})"
        if match.group(4) is not None:  # plain image: ![alt](target)
            alt, target = match.group(4), match.group(5)
            new_target = _rewrite_target(is_image=True, target=target, repo=repo, ref=ref)
            return f"![{alt}]({new_target})"
        # plain link: [text](target)
        text, target = match.group(6), match.group(7)
        new_target = _rewrite_target(is_image=False, target=target, repo=repo, ref=ref)
        return f"[{text}]({new_target})"

    return _LINK_RE.sub(_replace, markdown_text)


def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Rewrite relative README.md links to absolute GitHub URLs for PyPI."
    )
    parser.add_argument("--input", required=True, type=Path, help="Path to the source README.md")
    parser.add_argument("--output", required=True, type=Path, help="Path to write the rewritten README.md")
    parser.add_argument("--ref", required=True, help="Git tag, branch, or commit to pin links to (e.g. v2-1.1.10)")
    parser.add_argument("--repo", default=DEFAULT_REPO, help=f"GitHub 'owner/repo' slug (default: {DEFAULT_REPO})")
    parser.add_argument("--verbose", action="store_true", help="Enable DEBUG logging.")
    return parser.parse_args()


def main() -> int:
    """Entry point: read --input, rewrite links, write --output.

    Returns:
        Process exit code (0 on success).

    Raises:
        ValueError: If --input does not exist.
    """
    args = _parse_args()
    logger = _setup_logging(args.verbose)

    if not args.input.is_file():
        logger.error("Input file not found: %s", args.input)
        raise ValueError(f"Input file not found: {args.input}")

    original = args.input.read_text(encoding="utf-8")
    rewritten = rewrite_links(original, ref=args.ref, repo=args.repo)
    args.output.write_text(rewritten, encoding="utf-8")

    num_targets = len(_LINK_RE.findall(original))
    logger.info(
        "Rewrote relative links in %s -> %s (ref=%s, repo=%s, %d markdown link/image targets scanned)",
        args.input, args.output, args.ref, args.repo, num_targets,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
