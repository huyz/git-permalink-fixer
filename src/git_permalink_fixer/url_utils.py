from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, Callable

from .constants import GITHUB_PERMALINK_RE
from .permalink_info import PermalinkInfo


def parse_github_blob_permalink(url: str) -> Optional[Tuple[str, str, str, str, Optional[int], Optional[int]]]:
    """
    Parses any GitHub file URL (blob view) to extract owner, repo, ref (commit/branch),
    path, and line numbers.
    In this case, we accept any type of git ref; we don't accept tree URLs and empty paths.
    Returns: (owner, repo, ref, path, line_start, line_end) or None
    """
    match = GITHUB_PERMALINK_RE.match(url)
    if not match:
        return None
    owner, repo, url_type, ref, url_path, line_start, line_end = match.groups()

    if url_type != "blob" or not url_path:
        return None
    return owner, repo, ref, url_path, int(line_start) if line_start else None, int(line_end) if line_end else None


def parse_github_permalink_for_this_repo(
    url: str,
    git_owner: str,
    git_repo: str,
    normalize_repo_name_func: Optional[Callable] = None,
) -> Optional[PermalinkInfo]:
    """Parse a GitHub permalink URL to extract commit hash, file path, and line numbers.
    Note in this case that for the ref, we only accept commit hashes, not branches or tags.
    Returns None if the URL does not match the expected format or is not from the current repository.
    """

    match = GITHUB_PERMALINK_RE.match(url)
    if not match:
        return None

    owner, repo, _, commit_hash, url_path, line_start, line_end = match.groups()

    # Validate that the commit_hash is a hexadecimal hash and not a branch or tag
    if (
        not commit_hash
        or not all(c in "0123456789abcdefABCDEF" for c in commit_hash)
        or not 7 <= len(commit_hash) <= 40
    ):
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


def update_github_url_with_line_numbers(
    base_url: Optional[str], line_start: Optional[int], line_end: Optional[int]
) -> str:
    """Updates a given URL with new line number fragments, removing old ones."""
    if base_url is None:
        raise ValueError("Base URL cannot be None")

    url_no_frag = base_url.split("#")[0]
    if line_start is not None:
        if line_end is not None and line_end != line_start:
            return f"{url_no_frag}#L{line_start}-L{line_end}"
        if line_end is None and line_start > 0:  # Single line
            return f"{url_no_frag}#L{line_start}"
        if line_end is not None and line_end == line_start:  # Single line specified as range
            return f"{url_no_frag}#L{line_start}"
        # If line_start is 0 or invalid, or line_end implies no range, don't add fragment.
        # This case should ideally be handled by the caller ensuring line_start is valid if provided.
    return url_no_frag  # No valid line_start provided or it was meant to be cleared.
