import pytest
from pathlib import Path
from typing import List, Optional, Set, Callable, Tuple
from unittest.mock import patch, MagicMock, call
import re

from git_permalink_fixer.file_ops import (
    should_skip_file_search,
    extract_permalinks_from_file,
)
from git_permalink_fixer.permalink_info import PermalinkInfo
from git_permalink_fixer.constants import (
    COMMON_EXTENSIONLESS_REPO_FILES as DEFAULT_COMMON_EXTENSIONLESS,
    COMMON_TEXT_FILE_EXTENSIONS as DEFAULT_COMMON_TEXT_EXTENSIONS,
    GITHUB_URL_FIND_PATTERN,
)

REPO_ROOT_STR = "/test/repo"


@pytest.fixture
def test_repo_root(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    return repo_root


@pytest.fixture
def setup_test_constants(monkeypatch):
    """Allows modifying constants for specific tests if needed, returning them to original after."""
    test_extensions = {".jsx", ".uppercasetext", ".md", ".txt", ".py", ".json", ".xml"}
    modified_text_extensions = DEFAULT_COMMON_TEXT_EXTENSIONS | test_extensions
    monkeypatch.setattr("git_permalink_fixer.file_ops.COMMON_TEXT_FILE_EXTENSIONS", modified_text_extensions)

    test_extless = {"README", "Makefile", "LICENSE"}
    modified_extless_files = DEFAULT_COMMON_EXTENSIONLESS | test_extless
    monkeypatch.setattr("git_permalink_fixer.file_ops.COMMON_EXTENSIONLESS_REPO_FILES", modified_extless_files)


@pytest.mark.usefixtures("setup_test_constants")
@pytest.mark.parametrize(
    "file_rel_path_str, create_as_dir, ignored_rel_paths_str, expected_skip, description",
    [
        # 1. Directory checks
        ("some_dir", True, None, True, "Should skip a directory"),
        # 2. Special path component checks
        (".git/config", False, None, True, "Should skip if '.git' in path parts"),
        ("src/.git/hooks", False, None, True, "Should skip if '.git' in path parts (deeper)"),
        (".idea/workspace.xml", False, None, True, "Should skip if '.idea' in path parts"),
        ("src/.vscode/settings.json", False, None, True, "Should skip if '.vscode' in path parts"),
        # 3. Gitignore checks
        ("ignored_file.txt", False, {"ignored_file.txt"}, True, "Should skip if file is in ignored_paths_from_git"),
        (
            "not_ignored.txt",
            False,
            {"other_ignored.txt"},
            False,
            "Should not skip if file is not in ignored_paths_from_git",
        ),
        ("dir_ignored/file.py", False, {"dir_ignored"}, True, "Should skip if parent dir is in ignored_paths_from_git"),
        (
            "deep/path/to/ignored.py",
            False,
            {"deep/path/to"},
            True,
            "Should skip if an ancestor dir is in ignored_paths_from_git",
        ),
        ("file.txt", False, set(), False, "Should not skip if ignored_paths_from_git is empty"),
        # 4. Extension/Name checks
        ("unknown_extensionless", False, None, True, "Should skip unknown extensionless file"),
        ("README", False, None, False, "Should not skip common extensionless file 'README'"),
        ("Makefile", False, None, False, "Should not skip common extensionless file 'Makefile'"),
        ("src/main.py", False, None, False, "Should not skip '.py' file"),
        ("docs/index.html", False, None, False, "Should not skip '.html' file (if in constants)"),
        ("image.png", False, None, True, "Should skip '.png' file (not in text extensions)"),
        ("archive.tar.gz", False, None, True, "Should skip '.tar.gz' (not in text extensions)"),
        ("src/component.jsx", False, None, False, "Should not skip '.jsx' file (added to test constants)"),
        ("UPPERCASE.MD", False, None, False, "Should handle uppercase extension correctly (.md)"),
        ("file.UPPERCASETEXT", False, None, False, "Should handle uppercase extension correctly (.uppercasetext)"),
        ("LICENSE", False, None, False, "Should not skip 'LICENSE' at root"),
    ],
)
def test_should_skip_file_search(
    test_repo_root: Path,
    file_rel_path_str: str,
    create_as_dir: bool,
    ignored_rel_paths_str: Optional[Set[str]],
    expected_skip: bool,
    description: str,
):
    file_path = test_repo_root / file_rel_path_str

    # Create file/directory structure
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if create_as_dir:
        file_path.mkdir(exist_ok=True)
    else:
        file_path.touch(exist_ok=True)

    ignored_paths_absolute: Optional[Set[Path]] = None
    if ignored_rel_paths_str is not None:
        ignored_paths_absolute = {test_repo_root / p for p in ignored_rel_paths_str}
        # Ensure ignored directories exist if they are parents for the check
        for p_str in ignored_rel_paths_str:
            abs_p = test_repo_root / p_str
            if not abs_p.suffix:  # Assume it's a directory if no suffix for this test setup
                abs_p.mkdir(parents=True, exist_ok=True)

    result = should_skip_file_search(file_path, test_repo_root, ignored_paths_absolute)
    assert result == expected_skip, description


def dummy_normalize_repo_name_func(repo_name: str) -> str:
    return repo_name.lower()


@patch("git_permalink_fixer.file_ops.parse_github_permalink_for_this_repo")
@pytest.mark.parametrize(
    "lines, git_owner, git_repo, normalize_func_to_use, initial_found_count, mock_parse_side_effect, "
    "expected_permalinks_data, expected_found_count_after, description",
    [
        # 1. No permalinks
        (["Just some text", "Another line"], "owner", "repo", None, 0, [], [], 0, "No permalinks found"),
        # 2. One valid permalink
        (
            ["Link: https://github.com/owner/repo/blob/hash1/file1.py"],
            "owner",
            "repo",
            None,
            1,
            [
                PermalinkInfo(
                    "https://github.com/owner/repo/blob/hash1/file1.py",
                    "hash1",
                    "file1.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                )
            ],
            [("https://github.com/owner/repo/blob/hash1/file1.py", "hash1", "file1.py", 1)],
            2,
            "One valid permalink",
        ),
        # 3. Permalink not matching owner/repo (parse_github_permalink_for_this_repo should return None)
        (
            ["Link: https://github.com/other_owner/other_repo/blob/hash2/file2.py"],
            "owner",
            "repo",
            None,
            0,
            [None],
            [],
            0,
            "Permalink for different owner/repo",
        ),
        # 4. Multiple URLs in one line, one valid, one not a permalink type
        (
            ["URL1: https://github.com/owner/repo/issues/1 URL2: https://github.com/owner/repo/blob/hash3/file3.py"],
            "owner",
            "repo",
            None,
            10,
            [
                PermalinkInfo(
                    "https://github.com/owner/repo/blob/hash3/file3.py",
                    "hash3",
                    "file3.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                ),
                None,
            ],
            [("https://github.com/owner/repo/blob/hash3/file3.py", "hash3", "file3.py", 1)],
            11,
            "Multiple URLs, one valid permalink, one not permalink type",
        ),
        # 5. Using normalize_repo_name_func
        (
            ["Link: https://github.com/OWNER/REPO_ALIAS/blob/hash4/file4.py"],
            "owner",
            "repo",
            dummy_normalize_repo_name_func,
            0,
            [
                PermalinkInfo(
                    "https://github.com/OWNER/REPO_ALIAS/blob/hash4/file4.py",
                    "hash4",
                    "file4.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                )
            ],
            [("https://github.com/OWNER/REPO_ALIAS/blob/hash4/file4.py", "hash4", "file4.py", 1)],
            1,
            "Permalink with normalize_repo_name_func",
        ),
        # 6. Multiple valid permalinks on different lines
        (
            [
                "Line1: https://github.com/owner/repo/blob/hash5/file5.py",
                "Line2: https://github.com/owner/repo/blob/hash6/file6.py",
            ],
            "owner",
            "repo",
            None,
            0,
            [
                PermalinkInfo(
                    "https://github.com/owner/repo/blob/hash5/file5.py",
                    "hash5",
                    "file5.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                ),
                PermalinkInfo(
                    "https://github.com/owner/repo/blob/hash6/file6.py",
                    "hash6",
                    "file6.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                ),
            ],
            [
                ("https://github.com/owner/repo/blob/hash5/file5.py", "hash5", "file5.py", 1),
                ("https://github.com/owner/repo/blob/hash6/file6.py", "hash6", "file6.py", 2),
            ],
            2,
            "Multiple permalinks on different lines",
        ),
        # 7. URL that is not a GitHub URL (re.findall won't match)
        (
            ["Not a GitHub URL: http://example.com"],
            "owner",
            "repo",
            None,
            0,
            [],  # mock_parse_permalink won't be called
            [],
            0,
            "URL is not a GitHub URL",
        ),
        # 8. Empty lines
        ([], "owner", "repo", None, 0, [], [], 0, "Empty file content"),
        # 9. URL with special characters that should be handled by re.findall
        (
            ["Link: https://github.com/o-w_n.er/r_e-p.o/blob/h/f.py?query=1#frag"],
            "o-w_n.er",
            "r_e-p.o",
            None,
            0,
            [
                PermalinkInfo(
                    "https://github.com/o-w_n.er/r_e-p.o/blob/h/f.py?query=1#frag",
                    "h",
                    "f.py",
                    None,
                    None,
                    Path("dummy"),
                    0,
                )
            ],
            [("https://github.com/o-w_n.er/r_e-p.o/blob/h/f.py?query=1#frag", "h", "f.py", 1)],
            1,
            "URL with special chars, query, and fragment",
        ),
        # 10. Multiple permalinks on the same line
        (
            ["https://g.com/o/r/blob/h1/f1 https://github.com/owner/repo/blob/h2/f2.py"],
            "owner",
            "repo",
            None,
            0,
            [
                None,
                PermalinkInfo(
                    "https://github.com/owner/repo/blob/h2/f2.py", "h2", "f2.py", None, None, Path("dummy"), 0
                ),
            ],
            # Note: "g.com" is filtered by re.findall pattern. Corrected pattern in test.
            # The re.findall is `https://github\.com/[^][()<>\"'{}|\\^`\s]+`
            # So "https://g.com/..." will not be found by re.findall.
            # Let's adjust the test case for re.findall behavior.
            # If the first URL was https://github.com/invalid/... it would be found by re.findall then rejected by parse_github_permalink_for_this_repo.
            [("https://github.com/owner/repo/blob/h2/f2.py", "h2", "f2.py", 1)],  # Only the second one is valid
            1,
            "Multiple GitHub URLs on same line, one valid",
        ),
    ],
)
def test_extract_permalinks_from_file(
    mock_parse_github_permalink: MagicMock,
    test_repo_root: Path,  # Use the fixture
    lines: List[str],
    git_owner: str,
    git_repo: str,
    normalize_func_to_use: Optional[Callable],
    initial_found_count: int,
    mock_parse_side_effect: List[Optional[PermalinkInfo]],
    expected_permalinks_data: List[Tuple[str, str, str, int]],  # url, hash, path, line_num
    expected_found_count_after,
    description: str,
):
    # Adjusting test case 10 based on re.findall behavior
    if description == "Multiple GitHub URLs on same line, one valid":
        lines = ["https://github.com/other/invalid/blob/h1/f1 https://github.com/owner/repo/blob/h2/f2.py"]
        # mock_parse_side_effect should be [None, PermalinkInfo(...)]

    mock_parse_github_permalink.side_effect = mock_parse_side_effect
    file_path = test_repo_root / "test_file.txt"  # Use test_repo_root from fixture

    # The logger is used in the function, ensure it doesn't break tests
    # (We are not asserting logger calls)
    with patch("git_permalink_fixer.file_ops.logger"):
        actual_permalinks, actual_found_count = extract_permalinks_from_file(
            file_path, lines, test_repo_root, git_owner, git_repo, initial_found_count, normalize_func_to_use
        )

    assert actual_found_count == expected_found_count_after, f"{description} (found count)"
    assert len(actual_permalinks) == len(expected_permalinks_data), f"{description} (num permalinks)"

    for i, actual_pl_info in enumerate(actual_permalinks):
        expected_data = expected_permalinks_data[i]
        assert actual_pl_info.url == expected_data[0]
        assert actual_pl_info.commit_hash == expected_data[1]
        assert actual_pl_info.url_path == expected_data[2]
        assert actual_pl_info.found_in_file == file_path
        assert actual_pl_info.found_at_line == expected_data[3]  # Expected line number

    # Verify calls to mock_parse_github_permalink
    # This regex must match the one in extract_permalinks_from_file
    expected_parse_calls = []
    for line_content in lines:
        urls_in_line = re.findall(GITHUB_URL_FIND_PATTERN, line_content)
        for url in urls_in_line:
            expected_parse_calls.append(call(url, git_owner, git_repo, normalize_func_to_use))

    assert mock_parse_github_permalink.call_count == len(expected_parse_calls)
    if expected_parse_calls:  # assert_has_calls raises AssertionError if empty list is passed
        mock_parse_github_permalink.assert_has_calls(expected_parse_calls, any_order=False)


# Test case for when re.findall finds nothing
@patch("git_permalink_fixer.file_ops.parse_github_permalink_for_this_repo")
def test_extract_permalinks_from_file_no_github_urls(mock_parse_github_permalink, test_repo_root):
    lines = ["No github urls here http://example.com", "only plain text"]
    file_path = test_repo_root / "test_file.txt"

    actual_permalinks, actual_found_count = extract_permalinks_from_file(
        file_path, lines, test_repo_root, "owner", "repo", 0, None
    )

    assert actual_permalinks == []
    assert actual_found_count == 0
    mock_parse_github_permalink.assert_not_called()
