import pytest
from typing import Optional, Tuple
from pathlib import Path

from git_permalink_fixer.url_utils import (
    parse_github_blob_permalink,
    parse_github_permalink_for_this_repo,
    update_github_url_with_line_numbers,
)
from git_permalink_fixer.permalink_info import PermalinkInfo


@pytest.mark.parametrize(
    "url, expected_output",
    [
        (
            "https://github.com/owner/repo/blob/16d21d1/path/to/file.txt",
            ("owner", "repo", "16d21d1", "path/to/file.txt", None, None),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/src/component.js#L10",  # Line number
            ("owner", "repo", "16d21d1", "src/component.js", 10, None),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/src/component.js#L10-L10",  # Single line number
            ("owner", "repo", "16d21d1", "src/component.js", 10, 10),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/README.md#L10-L20",  # Line numbers
            ("owner", "repo", "16d21d1", "README.md", 10, 20),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/only_query.txt?p=1",  # Query param, no fragment
            ("owner", "repo", "16d21d1", "only_query.txt", None, None),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/no_lines_but_fragment.txt#section-1",  # Fragment not line
            ("owner", "repo", "16d21d1", "no_lines_but_fragment.txt", None, None),
        ),
        (
            "https://github.com/test-user/test-project/blob/16d21d1/docs/api.rst?version=2#section-3",  # Query parameters and fragment
            ("test-user", "test-project", "16d21d1", "docs/api.rst", None, None),
        ),
        (
            "https://GITHUB.COM/Org/Project/blob/16d21d1/path/to/file.ext?raw=true#L5",  # Query parameters and line number
            ("Org", "Project", "16d21d1", "path/to/file.ext", 5, None),
        ),
        (
            "https://GITHUB.COM/Org/Project/blob/16d21d1/path/to/file.ext",  # Different casing
            ("Org", "Project", "16d21d1", "path/to/file.ext", None, None),
        ),
        (
            "https://github.com/owner/repo/blob/16d21d1/path/with%20spaces/file.txt#L123",  # URL encoded spaces
            ("owner", "repo", "16d21d1", "path/with%20spaces/file.txt", 123, None),
        ),
        # Negative cases
        ("https://github.com/owner/repo/tree/16d21d1/path/to/directory", None),  # Tree URL
        ("https://gitlab.com/owner/repo/blob/16d21d1/path/to/file.txt", None),  # Different domain
        ("http://github.com/org/project/blob/16d21d1/file.py", None),  # HTTP
        ("https://github.com/owner/repo/blob/16d21d1", None),  # Missing path
        ("https://github.com/owner/repo/blob", None),  # Malformed
        ("https://github.com/owner/repo/tree/16d21d1", None),  # Not a blob URL
        ("https://github.com/owner/repo", None),  # Repo
        ("https://github.com/owner", None),  # Owner
        ("https://github.com", None),  # Web site
        ("invalid-url", None),  # Completely invalid
        ("", None),  # Empty string
    ],
)
def test_parse_github_blob_permalink(
    url: str,
    expected_output: Optional[Tuple[str, str, str, str, Optional[int], Optional[int]]],
):
    """Tests parse_github_blob_permalink with various inputs."""
    assert parse_github_blob_permalink(url) == expected_output


def normalize_repo_name_dummy(repo_name: str) -> str:
    """Dummy normalizer for testing."""
    if repo_name == "alias-repo":
        return "actual-repo"
    return repo_name.lower()


@pytest.mark.parametrize(
    "url, git_owner, git_repo, normalize_func, expected_output",
    [
        (
            "https://github.com/test-owner/test-repo/blob/abcdef1234567890abcdef1234567890abcdef12/file.py#L10-L20",
            "test-owner",
            "test-repo",
            None,
            PermalinkInfo(
                "https://github.com/test-owner/test-repo/blob/abcdef1234567890abcdef1234567890abcdef12/file.py#L10-L20",
                "abcdef1234567890abcdef1234567890abcdef12",
                "file.py",
                10,
                20,
                Path(),
                0,
            ),
        ),
        (
            "https://github.com/test-owner/test-repo/blob/abcdef1/file.py",  # Short hash
            "test-owner",
            "test-repo",
            None,
            PermalinkInfo(
                "https://github.com/test-owner/test-repo/blob/abcdef1/file.py",
                "abcdef1",
                "file.py",
                None,
                None,
                Path(),
                0,
            ),
        ),
        (
            "https://github.com/test-owner/test-repo/tree/abcdef1234567890",  # Tree URL
            "test-owner",
            "test-repo",
            None,
            PermalinkInfo(
                "https://github.com/test-owner/test-repo/tree/abcdef1234567890",
                "abcdef1234567890",
                None,
                None,
                None,
                Path(),
                0,
            ),
        ),
        (  # Case mismatch for owner/repo, should still match
            "https://github.com/Test-Owner/Test-Repo/blob/abcdef1/file.py",
            "test-owner",
            "test-repo",
            None,
            PermalinkInfo(
                "https://github.com/Test-Owner/Test-Repo/blob/abcdef1/file.py",
                "abcdef1",
                "file.py",
                None,
                None,
                Path(),
                0,
            ),
        ),
        (  # Using normalize_repo_name_func with an alias
            "https://github.com/my-org/alias-repo/blob/abcdef1/path/to/code.js#L5",
            "my-org",
            "actual-repo",
            normalize_repo_name_dummy,
            PermalinkInfo(
                "https://github.com/my-org/alias-repo/blob/abcdef1/path/to/code.js#L5",
                "abcdef1",
                "path/to/code.js",
                5,
                None,
                Path(),
                0,
            ),
        ),
        # Negative cases
        (  # Different owner
            "https://github.com/other-owner/test-repo/blob/abcdef1/file.py",
            "test-owner",
            "test-repo",
            None,
            None,
        ),
        (  # Different repo
            "https://github.com/test-owner/other-repo/blob/abcdef1/file.py",
            "test-owner",
            "test-repo",
            None,
            None,
        ),
        (  # Different repo, even with normalizer if not an alias
            "https://github.com/my-org/another-repo/blob/abcdef1/code.js",
            "my-org",
            "actual-repo",
            normalize_repo_name_dummy,
            None,
        ),
        (
            "https://github.com/test-owner/test-repo/blob/main/file.py",
            "test-owner",
            "test-repo",
            None,
            None,
        ),  # Ref is not a commit hash
        (
            "https://github.com/test-owner/test-repo/blob/abc/file.py",
            "test-owner",
            "test-repo",
            None,
            None,
        ),  # Hash too short
        (
            "https://gitlab.com/test-owner/test-repo/blob/abcdef1/file.py",
            "test-owner",
            "test-repo",
            None,
            None,
        ),  # Wrong domain
        (
            "https://github.com/test-owner/test-repo/blob/main/path/to/directory",
            "test-owner",
            "test-repo",
            None,
            None,
        ),  # branch name
        (
            "https://github.com/test-owner/test-repo/blob/v1.2.3/path/to/directory",
            "test-owner",
            "test-repo",
            None,
            None,
        ),  # tag name
        ("invalid-url", "test-owner", "test-repo", None, None),
        ("", "test-owner", "test-repo", None, None),
    ],
)
def test_parse_github_permalink_for_this_repo(
    url: str, git_owner: str, git_repo: str, normalize_func, expected_output: Optional[PermalinkInfo]
):
    """Tests parse_github_permalink_for_this_repo with various inputs."""
    assert parse_github_permalink_for_this_repo(url, git_owner, git_repo, normalize_func) == expected_output


@pytest.mark.parametrize(
    "base_url, line_start, line_end, expected_url",
    [
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            10,
            20,
            "https://github.com/owner/repo/blob/ref/file.txt#L10-L20",
        ),
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            5,
            None,
            "https://github.com/owner/repo/blob/ref/file.txt#L5",
        ),
        ("https://github.com/owner/repo/blob/ref/file.txt", 7, 7, "https://github.com/owner/repo/blob/ref/file.txt#L7"),
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            None,
            None,
            "https://github.com/owner/repo/blob/ref/file.txt",
        ),
        (
            "https://github.com/owner/repo/blob/ref/file.txt#L1-L2",
            10,
            20,
            "https://github.com/owner/repo/blob/ref/file.txt#L10-L20",
        ),  # Existing fragment
        (
            "https://github.com/owner/repo/blob/ref/file.txt?raw=true",
            10,
            None,
            "https://github.com/owner/repo/blob/ref/file.txt?raw=true#L10",
        ),  # With query
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            0,
            None,
            "https://github.com/owner/repo/blob/ref/file.txt",
        ),  # line_start is 0
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            -5,
            None,
            "https://github.com/owner/repo/blob/ref/file.txt",
        ),  # line_start is negative
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            10,
            5,
            "https://github.com/owner/repo/blob/ref/file.txt#L10-L5",
        ),  # line_end < line_start
        (
            "https://github.com/owner/repo/blob/ref/file.txt",
            None,
            5,
            "https://github.com/owner/repo/blob/ref/file.txt",
        ),  # line_start is None, line_end has value
    ],
)
def test_update_github_url_with_line_numbers(
    base_url: str, line_start: Optional[int], line_end: Optional[int], expected_url: str
):
    """Tests update_github_url_with_line_numbers."""
    assert update_github_url_with_line_numbers(base_url, line_start, line_end) == expected_url


def test_update_github_url_with_line_numbers_none_base_url():
    """Tests update_github_url_with_line_numbers with None base_url."""
    with pytest.raises(ValueError, match="Base URL cannot be None"):
        update_github_url_with_line_numbers(None, 10, 20)
