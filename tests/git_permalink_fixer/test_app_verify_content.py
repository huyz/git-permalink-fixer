from pathlib import PosixPath
from unittest.mock import patch

from .conftest import create_mock_permalink_info


@patch("git_permalink_fixer.app.get_file_content_at_commit")
@patch("git_permalink_fixer.app.fetch_raw_github_content_from_url")
@patch("git_permalink_fixer.app.parse_github_blob_permalink")
def test_verify_content_match_original_no_lines(
    mock_parse_gh_blob, mock_fetch_raw, mock_get_content, mock_app_for_resolution
):
    original = create_mock_permalink_info(line_start=None, url_path="file.py")
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is True
    assert ls is None
    assert le is None
    mock_get_content.assert_not_called()


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_original_content_not_available(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    mock_get_content.return_value = None  # Original content cannot be fetched
    match, _, _ = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is False
    mock_get_content.assert_called_once_with(original.commit_hash, original.url_path, repo_path=PosixPath("/fake/repo"))


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_target_content_not_available(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    mock_get_content.side_effect = [["line1"], None]  # Original content, then target content fails
    match, _, _ = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is False
    assert mock_get_content.call_count == 2


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_exact_match_no_shift(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    mock_get_content.side_effect = [["  line1  "], ["  line1  "]]
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is True
    assert ls == 1
    assert le is None


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_with_positive_shift(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    mock_app_for_resolution.global_prefs.tolerance_value = 1  # Allow 1 line shift
    mock_get_content.side_effect = [["line1"], ["padding", "line1"]]
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is True
    assert ls == 2  # Shifted by +1
    assert le is None


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_with_negative_shift(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=2, url_path="file.py")
    mock_app_for_resolution.global_prefs.tolerance_value = 1
    mock_get_content.side_effect = [["padding", "line_orig"], ["line_orig", "padding"]]  # Original content is on line 2
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is True
    assert ls == 1  # Shifted by -1 (original was line 2, found at line 1 in target)
    assert le is None


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_no_match_within_tolerance(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    mock_app_for_resolution.global_prefs.tolerance_value = 0  # No shift allowed
    mock_get_content.side_effect = [["line1"], ["line_different", "line1"]]
    match, _, _ = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py"
    )
    assert match is False


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_custom_percentage_tolerance(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    # Target file has 10 lines, 10% tolerance = 1 line shift
    mock_get_content.side_effect = [["line1"], ["pad"] * 1 + ["line1"] + ["pad"] * 8]
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py", custom_tolerance_str="10%"
    )
    assert match is True
    assert ls == 2  # Shifted by +1


@patch("git_permalink_fixer.app.get_file_content_at_commit")
def test_verify_content_match_custom_percentage_tolerance_not_found(mock_get_content, mock_app_for_resolution):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    # Target file has 10 lines, 10% tolerance = 1 line shift
    mock_get_content.side_effect = [["line1"], ["pad"] * 1 + ["line1"] + ["pad"] * 8]
    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_commit_hash="target_hash", target_url_path="file.py", custom_tolerance_str="9%"
    )
    assert match is False
    assert ls is None


@patch("git_permalink_fixer.app.fetch_raw_github_content_from_url")
@patch("git_permalink_fixer.app.parse_github_blob_permalink")
@patch("git_permalink_fixer.app.get_file_content_at_commit")  # For original content
def test_verify_content_match_target_url_matches(
    mock_get_orig_content, mock_parse_gh_blob, mock_fetch_raw, mock_app_for_resolution
):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    target_url = "https://github.com/owner/repo/blob/newhash/file.py#L5"
    mock_get_orig_content.return_value = ["line_content"]
    mock_parse_gh_blob.return_value = ("owner", "repo", "newhash", "file.py", 5, None)
    mock_fetch_raw.return_value = [""] * 4 + ["line_content"]  # Content at line 5

    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_url=target_url, custom_tolerance_str="0"
    )
    assert match is True
    assert ls == 5
    assert le is None
    mock_fetch_raw.assert_called_once_with(target_url)


@patch("git_permalink_fixer.app.fetch_raw_github_content_from_url")
@patch("git_permalink_fixer.app.parse_github_blob_permalink")
@patch("git_permalink_fixer.app.get_file_content_at_commit")  # For original content
def test_verify_content_match_target_url_no_match(
    mock_get_orig_content, mock_parse_gh_blob, mock_fetch_raw, mock_app_for_resolution
):
    original = create_mock_permalink_info(line_start=1, url_path="file.py")
    target_url = "https://github.com/owner/repo/blob/newhash/file.py#L5"
    mock_get_orig_content.return_value = ["line_content"]
    mock_parse_gh_blob.return_value = ("owner", "repo", "newhash", "file.py", 4, None)
    mock_fetch_raw.return_value = [""] * 4 + ["line_content"]  # Content at line 5

    match, ls, le = mock_app_for_resolution._verify_content_match(
        original, target_url=target_url, custom_tolerance_str="0"
    )
    assert match is False
    assert ls is None
    assert le is None
    mock_fetch_raw.assert_called_once_with(target_url)
