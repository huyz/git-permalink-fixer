from pathlib import PosixPath
from unittest.mock import patch

from git_permalink_fixer.app import ResolutionState
from .conftest import create_mock_permalink_info


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_external_needs_url(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info()
    state: ResolutionState = {
        "current_is_external": True,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": None,
        "current_ls": 1,
        "current_le": 1,
        "custom_tolerance_str": None,
    }
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, None, state)
    assert status == "needs_external_url"
    assert url is None


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_external_resolved_no_lines_original(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=None)  # No lines in original
    state: ResolutionState = {
        "current_is_external": True,
        "current_external_url_base": "https://ext.com/base",
        "current_url_path_for_ancestor": None,
        "current_ls": 10,
        "current_le": None,
        "custom_tolerance_str": None,
    }
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, None, state)
    assert status == "resolved"
    assert url == "https://ext.com/base#L10"
    mock_verify.assert_not_called()  # No verification if original has no lines


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_external_resolved_with_lines_match(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1)
    state: ResolutionState = {
        "current_is_external": True,
        "current_external_url_base": "https://ext.com/base",
        "current_url_path_for_ancestor": None,
        "current_ls": 5,
        "current_le": 5,
        "custom_tolerance_str": None,
    }
    mock_verify.return_value = (True, 5, 5)  # Match found
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, None, state)
    assert status == "resolved"
    assert url == "https://ext.com/base#L5"
    expected_verify_url = "https://ext.com/base#L5"
    mock_verify.assert_called_once_with(original, target_url=expected_verify_url, custom_tolerance_str=None)


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_ancestor_path_cleared(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(url_path="some/path.py")  # Original had a path
    state: ResolutionState = {
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": None,
        "current_ls": 1,
        "current_le": 1,
        "custom_tolerance_str": None,
    }
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, "anc_hash", state)
    assert status == "path_cleared"


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_ancestor_tree_link(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(url_path=None)  # Original was a tree link
    state: ResolutionState = {
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": None,
        "current_ls": None,
        "current_le": None,
        "custom_tolerance_str": None,
    }
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, "anc_hash", state)
    assert status == "resolved"
    assert (
        url
        == f"https://github.com/{mock_app_for_resolution.git_owner}/{mock_app_for_resolution.git_repo}/tree/anc_hash"
    )


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_ancestor_path_missing(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(url_path="path.py")
    state: ResolutionState = {
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "new/path.py",
        "current_ls": 1,
        "current_le": 1,
        "custom_tolerance_str": None,
    }
    mock_file_exists.return_value = False  # Path does not exist in ancestor
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, "anc_hash", state)
    assert status == "path_missing_ancestor"
    mock_file_exists.assert_called_once_with("anc_hash", "new/path.py", repo_path=PosixPath("/fake/repo"))


@patch("git_permalink_fixer.app.PermalinkFixerApp._verify_content_match")
@patch("git_permalink_fixer.app.file_exists_at_commit")
def test_evaluate_candidate_ancestor_lines_mismatch(mock_file_exists, mock_verify, mock_app_for_resolution):
    original = create_mock_permalink_info(url_path="path.py", line_start=1)
    state: ResolutionState = {
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "path.py",
        "current_ls": 1,
        "current_le": 1,
        "custom_tolerance_str": "5",
    }
    mock_file_exists.return_value = True
    mock_verify.return_value = (False, None, None)  # Content mismatch
    status, desc, url = mock_app_for_resolution._evaluate_current_resolution_candidate(original, "anc_hash", state)
    assert status == "lines_mismatch_ancestor"
    mock_verify.assert_called_once_with(
        original, target_commit_hash="anc_hash", target_url_path="path.py", custom_tolerance_str="5"
    )
