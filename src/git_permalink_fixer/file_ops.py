from __future__ import annotations

from pathlib import Path
from typing import List, Tuple, Set, Optional, Callable
import re
import logging
from .permalink_info import PermalinkInfo
from .constants import (
    COMMON_EXTENSIONLESS_REPO_FILES,
    COMMON_TEXT_FILE_EXTENSIONS,
    GITHUB_URL_FIND_PATTERN,
)
from .url_utils import parse_github_permalink_for_this_repo

logger = logging.getLogger(__name__)


def should_skip_file_search(file_path: Path, repo_root: Path, ignored_paths: Optional[Set[Path]] = None) -> bool:
    """Helper to determine if a file should be skipped during permalink search.

    Note that calling `file` would be too slow, so we use a heuristic.
    Checks against a pre-computed set of git-ignored paths if provided.

    :param file_path: The absolute paths of files to ignore; e.g., git-ignored paths.
    """
    if file_path.is_dir() or ".git" in file_path.parts or ".idea" in file_path.parts or ".vscode" in file_path.parts:
        return True

    if ignored_paths:
        # Check if the file itself or any of its parent directories up to the repo root
        # are in the pre-computed set of ignored paths.
        # The ignored_paths_from_git set contains absolute paths.
        current_check_path = file_path
        while True:
            if current_check_path in ignored_paths:
                return True
            if current_check_path == repo_root:  # Stop if we've checked the repo root itself
                break
            parent = current_check_path.parent
            if parent == current_check_path:  # Reached filesystem root
                break
            current_check_path = parent

    # Only search in text files or in common git repo filenames with no extension
    if file_path.suffix == "":
        if file_path.name not in COMMON_EXTENSIONLESS_REPO_FILES:
            return True
    else:
        if file_path.suffix.lower() not in COMMON_TEXT_FILE_EXTENSIONS:
            return True
    return False


def extract_permalinks_from_file(
    file_path: Path,
    lines: List[str],
    repo_root: Path,
    git_owner: str,
    git_repo: str,
    current_global_found_count: int,
    normalize_repo_name_func: Optional[Callable] = None,
) -> Tuple[List[PermalinkInfo], int]:
    """Helper to extract permalinks from the lines of a single file.
    Returns (permalinks_in_file, new_global_found_count)
    """
    permalinks_in_file: List[PermalinkInfo] = []
    file_header_printed = False
    for line_num, line_content in enumerate(lines, 1):
        urls_in_line = re.findall(GITHUB_URL_FIND_PATTERN, line_content)
        permalinks_found_on_this_line = []
        for url in urls_in_line:
            permalink_info = parse_github_permalink_for_this_repo(url, git_owner, git_repo, normalize_repo_name_func)
            if permalink_info:
                permalink_info.found_in_file = file_path
                permalink_info.found_at_line = line_num
                permalinks_in_file.append(permalink_info)
                permalinks_found_on_this_line.append(permalink_info)

        if permalinks_found_on_this_line:
            if not file_header_printed:
                logger.debug("\n- In %s:", file_path.relative_to(repo_root))
                file_header_printed = True
            logger.debug("  - Line %d: %s", line_num, line_content.strip())
            for p_info in permalinks_found_on_this_line:
                current_global_found_count += 1
                logger.debug(f"    %2d. 📍 Found permalink: %s", current_global_found_count, p_info.commit_hash[:8])
    return permalinks_in_file, current_global_found_count
