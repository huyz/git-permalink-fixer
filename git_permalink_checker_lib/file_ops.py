from __future__ import annotations

from pathlib import Path
from typing import List, Tuple
import re
import logging
from .permalink import PermalinkInfo
from .constants import (
    COMMON_EXTENSIONLESS_REPO_FILES,
    COMMON_TEXT_FILE_EXTENSIONS,
    GITHUB_PERMALINK_RE,
)

logger = logging.getLogger(__name__)


def should_skip_file_search(file_path: Path) -> bool:
    """Helper to determine if a file should be skipped during permalink search.

    Note that calling `file` would be too slow, so we use a heuristic.
    """
    if (
        file_path.is_dir()
        or ".git" in file_path.parts
        or ".idea" in file_path.parts
        or ".vscode" in file_path.parts
    ):
        return True

    # Only search in text files or in common git repo filenames with no extension
    if file_path.suffix == "":
        if file_path.name not in COMMON_EXTENSIONLESS_REPO_FILES:
            return True
    else:
        if file_path.suffix.lower() not in COMMON_TEXT_FILE_EXTENSIONS:
            return True
    return False


def extract_permalinks_from_file_lines(
    file_path: Path,
    lines: List[str],
    repo_root: Path,
    github_owner: str,
    github_repo: str,
    current_found_count: int,
    normalize_repo_name_func=None,
) -> Tuple[List[PermalinkInfo], int, bool]:
    """Helper to extract permalinks from the lines of a single file."""
    permalinks_in_file: List[PermalinkInfo] = []
    file_header_printed = False
    for line_num, line_content in enumerate(lines, 1):
        urls_in_line = re.findall(r"https://github\.com/[^][()<>\"'{}|\\^`\s]+", line_content)
        permalinks_found_on_this_line = []
        for url in urls_in_line:
            permalink_info = parse_github_permalink(
                url, github_owner, github_repo, normalize_repo_name_func
            )
            if permalink_info:
                permalink_info.found_in_file = file_path
                permalink_info.found_at_line = line_num
                permalinks_in_file.append(permalink_info)
                permalinks_found_on_this_line.append(permalink_info)

        if permalinks_found_on_this_line:
            if not file_header_printed:
                logger.debug(f"\n- In `{file_path.relative_to(repo_root)}`:")
                file_header_printed = True
            logger.debug(f"  - Line {line_num}: {line_content.strip()}")
            for p_info in permalinks_found_on_this_line:
                current_found_count += 1
                logger.debug(
                    f"    {current_found_count:2d}. 📍 Found permalink: {p_info.commit_hash[:8]}"
                )
    return permalinks_in_file, current_found_count, file_header_printed


def parse_github_permalink(
    url: str, github_owner: str, github_repo: str, normalize_repo_name_func=None
) -> PermalinkInfo | None:
    """Parse a GitHub permalink URL to extract commit hash, file path, and line numbers."""

    match = GITHUB_PERMALINK_RE.match(url)
    if not match:
        return None

    owner, repo, commit_hash, url_path, line_start, line_end = match.groups()

    # Validate commit hash length
    if len(commit_hash) < 7 or len(commit_hash) > 40:
        return None

    # Only process URLs from the current repository
    if owner.lower() != github_owner.lower() or (
        normalize_repo_name_func(repo) != normalize_repo_name_func(github_repo)
        if normalize_repo_name_func
        else repo.lower() != github_repo.lower()
    ):
        return None

    return PermalinkInfo(
        url=url,
        commit_hash=commit_hash,
        url_path=url_path,
        line_start=int(line_start) if line_start else None,
        line_end=int(line_end) if line_end else None,
        found_in_file=Path(),  # Will be set by caller
        found_at_line=0,  # Will be set by caller
    )
