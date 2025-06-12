from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from git_permalink_fixer import GlobalPreferences, SessionPreferences, PermalinkFixerApp
from git_permalink_fixer.permalink_info import PermalinkInfo


# Helper to create a mock PermalinkInfo object (can be shared or defined in conftest.py)
def create_mock_permalink_info(
    url="https://github.com/owner/repo/blob/abcdef123456/path/to/file.py#L10",
    commit_hash="abcdef123456",
    url_path="path/to/file.py",
    line_start=10,
    line_end=None,
    found_in_file_rel_path="path/to/containing_file.md",
    found_at_line=50,
    repo_root_base="/fake/repo",
):
    return PermalinkInfo(
        url=url,
        commit_hash=commit_hash,
        url_path=url_path,
        line_start=line_start,
        line_end=line_end,
        found_in_file=Path(repo_root_base) / found_in_file_rel_path,
        found_at_line=found_at_line,
    )


@pytest.fixture
def mock_app_for_resolution():
    mock_global_prefs = MagicMock(spec=GlobalPreferences)
    mock_global_prefs.verbose = False
    mock_global_prefs.main_branch = "main"
    mock_global_prefs.tag_prefix = "permalinks/ref"
    mock_global_prefs.repo_aliases = []
    mock_global_prefs.line_shift_tolerance_str = "20"
    mock_global_prefs.tolerance_is_percentage = False
    mock_global_prefs.tolerance_value = 20

    mock_session_prefs = MagicMock(spec=SessionPreferences)
    # Set defaults for session prefs as needed by methods under test

    with (
        patch("git_permalink_fixer.app.get_repo_root", return_value=Path("/fake/repo")),
        patch("git_permalink_fixer.app.get_remote_url", return_value="https://github.com/owner/repo.git"),
        patch("git_permalink_fixer.app.get_github_info_from_url", return_value=("owner", "repo")),
    ):
        app = PermalinkFixerApp(mock_global_prefs, mock_session_prefs)

    app._vprint = MagicMock()
    # Mock other methods that might be called by the methods under test if they are complex
    # For example, if _verify_content_match calls get_file_content_at_commit, mock that at the app module level
    return app
