from __future__ import annotations

import re
from pathlib import Path
from typing import Optional, Tuple, Callable

from git_permalink_fixer.constants import GITHUB_PERMALINK_RE, GITHUB_BLOB_PERMALINK_RE
from git_permalink_fixer.permalink_info import PermalinkInfo


def parse_any_github_url_for_raw_content(url: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Parses a GitHub blob URL to extract components needed for fetching raw content.
    Example: https://github.com/owner/repo/blob/ref/path/to/file.txt
    Returns: (owner, repo, ref, path) or None
    """
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)", url, re.IGNORECASE)
    if match:
        owner, repo, ref, path = match.groups()
        path = path.split('#')[0].split('?')[0]  # Clean path from fragments or query params
        return owner, repo, ref, path
    return None


def parse_github_blob_permalink(url: str) -> Optional[Tuple[str, str, str, str, Optional[int], Optional[int]]]:
    """
    Parses any GitHub file URL (blob view) to extract owner, repo, ref (commit/branch),
    path, and line numbers.
    Returns: (owner, repo, ref, path, line_start, line_end) or None
    """
    match = GITHUB_BLOB_PERMALINK_RE.match(url)
    if not match:
        return None
    owner, repo, ref, path_part, ls, le = match.groups()
    # Sanitize path_part further if necessary, though regex tries to capture up to # or ?
    # path_part might still contain query parameters if not starting with #
    path_part = path_part.split('?')[0]
    return owner, repo, ref, path_part, int(ls) if ls else None, int(le) if le else None


def parse_github_permalink(
    url: str,
    git_owner: str,
    git_repo: str,
    normalize_repo_name_func: Optional[Callable] = None,
) -> Optional[PermalinkInfo]:
    """Parse a GitHub permalink URL to extract commit hash, file path, and line numbers."""

    match = GITHUB_PERMALINK_RE.match(url)
    if not match:
        return None

    owner, repo, commit_hash, url_path, line_start, line_end = match.groups()

    # Validate commit hash length
    if len(commit_hash) < 7 or len(commit_hash) > 40:
        return None

    # Only process URLs from the current repository
    if owner.lower() != git_owner.lower() or (
        normalize_repo_name_func(repo) != normalize_repo_name_func(git_repo)
        if normalize_repo_name_func
        else repo.lower() != git_repo.lower()
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


def update_github_url_with_line_numbers(base_url: str, line_start: Optional[int], line_end: Optional[int]) -> str:
    """Updates a given URL with new line number fragments, removing old ones.
    """
    url_no_frag = base_url.split('#')[0]
    if line_start is not None:
        if line_end is not None and line_end != line_start:
            return f"{url_no_frag}#L{line_start}-L{line_end}"
        elif line_end is None and line_start > 0: # Single line
            return f"{url_no_frag}#L{line_start}"
        elif line_end is not None and line_end == line_start: # Single line specified as range
            return f"{url_no_frag}#L{line_start}"
        # If line_start is 0 or invalid, or line_end implies no range, don't add fragment.
        # This case should ideally be handled by the caller ensuring line_start is valid if provided.
    return url_no_frag # No valid line_start provided or it was meant to be cleared.


