import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from git_permalink_fixer.app import PermalinkFixerApp
from git_permalink_fixer.global_prefs import GlobalPreferences
from git_permalink_fixer.session_prefs import SessionPreferences
from .conftest import create_mock_permalink_info


@pytest.fixture
def mock_app_for_process_commit_details():
    mock_global_prefs = MagicMock(spec=GlobalPreferences)
    mock_global_prefs.verbose = False
    # repo_root is needed for relative_to in print statements
    # It will be set during PermalinkFixerApp instantiation by mocked get_repo_root

    mock_session_prefs = MagicMock(spec=SessionPreferences)
    mock_session_prefs.remembered_action_with_repl = None
    mock_session_prefs.remembered_action_without_repl = None

    with (
        patch("git_permalink_fixer.app.get_repo_root", return_value=Path("/fake/repo")),
        patch("git_permalink_fixer.app.get_remote_url", return_value="https://github.com/owner/repo.git"),
        patch("git_permalink_fixer.app.get_github_info_from_url", return_value=("owner", "repo")),
    ):
        app = PermalinkFixerApp(mock_global_prefs, mock_session_prefs)

    app._vprint = MagicMock()
    app._process_permalink = MagicMock()
    # app.repo_root is set by __init__

    return app


def test_process_commit_details_single_permalink_replace(mock_app_for_process_commit_details: PermalinkFixerApp):
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    commit_permalinks = [pl1]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"
    repl_url1 = "https://new.url/for_pl1"

    mock_app_for_process_commit_details._process_permalink.return_value = ("replace", repl_url1)

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag is None
    assert len(pending_repls) == 1
    assert pending_repls[0] == (pl1, repl_url1)
    mock_app_for_process_commit_details._process_permalink.assert_called_once_with(
        pl1,
        ancestor_commit,
        index=0,
        total=1,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )


def test_process_commit_details_single_permalink_tag(mock_app_for_process_commit_details: PermalinkFixerApp):
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash)
    commit_permalinks = [pl1]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"

    mock_app_for_process_commit_details._process_permalink.return_value = ("tag", None)  # User chooses to tag

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag == (commit_hash, commit_info)
    assert len(pending_repls) == 0
    mock_app_for_process_commit_details._vprint.assert_any_call(
        f"  ℹ️ Commit {commit_hash[:8]} is now slated to be tagged based on choice for '{pl1.url[-50:]}'…"
    )


def test_process_commit_details_initially_slated_for_tagging(mock_app_for_process_commit_details: PermalinkFixerApp):
    mock_app_for_process_commit_details.session_prefs.remembered_action_with_repl = (
        "tag"  # Slated due to remembered choice
    )
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash)
    commit_permalinks = [pl1]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"  # Has ancestor, so remembered_action_with_repl applies

    mock_app_for_process_commit_details._process_permalink.return_value = ("skip", None)  # User skips this one

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag == (commit_hash, commit_info)  # Still tagged
    assert len(pending_repls) == 0
    mock_app_for_process_commit_details._vprint.assert_any_call(
        f"  ℹ️ Commit {commit_hash[:8]} is initially slated for tagging due to remembered choice."
    )
    mock_app_for_process_commit_details._process_permalink.assert_called_once_with(
        pl1,
        ancestor_commit,
        index=0,
        total=1,
        is_commit_slated_for_tagging=True,  # Should be True
        auto_action_directive_for_commit=None,
    )


def test_process_commit_details_untag_action(mock_app_for_process_commit_details: PermalinkFixerApp):
    mock_app_for_process_commit_details.session_prefs.remembered_action_with_repl = "tag"  # Initially slated
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash)
    commit_permalinks = [pl1]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"

    # First call to _process_permalink (for pl1) returns "untag"
    # Second call (reprocessing pl1) returns "skip"
    mock_app_for_process_commit_details._process_permalink.side_effect = [("untag", None), ("skip", None)]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag is None  # Should be untagged
    assert len(pending_repls) == 0
    assert mock_app_for_process_commit_details._process_permalink.call_count == 2
    # First call, slated is True
    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl1, ancestor_commit, index=0, total=1, is_commit_slated_for_tagging=True, auto_action_directive_for_commit=None
    )
    # Second call, slated is False
    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl1,
        ancestor_commit,
        index=0,
        total=1,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )
    mock_app_for_process_commit_details._vprint.assert_any_call(
        f"  ℹ️ Commit {commit_hash[:8]} is no longer slated for tagging. Re-evaluating current permalink."
    )


def test_process_commit_details_replace_commit_group(mock_app_for_process_commit_details: PermalinkFixerApp):
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    pl2 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=20)
    commit_permalinks = [pl1, pl2]  # Sorted by file, then line
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"
    repl_url1 = "https://new.url/for_pl1"
    repl_url2 = "https://new.url/for_pl2"

    mock_app_for_process_commit_details._process_permalink.side_effect = [
        ("replace_commit_group", repl_url1),  # For pl1
        ("replace", repl_url2),  # For pl2, should be auto-accepted due to directive
    ]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag is None
    assert len(pending_repls) == 2
    assert pending_repls[0] == (pl1, repl_url1)
    assert pending_repls[1] == (pl2, repl_url2)

    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl1,
        ancestor_commit,
        index=0,
        total=2,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )
    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl2,
        ancestor_commit,
        index=1,
        total=2,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit="replace",  # Directive passed
    )
    mock_app_for_process_commit_details._vprint.assert_any_call(
        f"    🤖 User chose 'replace commit'. Will auto-accept replace for rest of commit {commit_hash[:8]}."
    )


@patch("builtins.input")
def test_process_commit_details_tag_with_existing_replacements_discard(
    mock_input, mock_app_for_process_commit_details: PermalinkFixerApp
):
    mock_input.return_value = "1"  # Discard previous replacements
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    pl2 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=20)
    commit_permalinks = [pl1, pl2]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"
    repl_url1 = "https://new.url/for_pl1"

    mock_app_for_process_commit_details._process_permalink.side_effect = [
        ("replace", repl_url1),  # pl1 is replaced
        ("tag", None),  # pl2 triggers tagging
    ]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag == (commit_hash, commit_info)  # Tagged
    assert len(pending_repls) == 0  # Replacements discarded
    mock_input.assert_called_once()
    # _process_permalink for pl2 should have is_commit_slated_for_tagging=False initially
    # then it becomes True after "tag" action. The sub-prompt handles the rest.
    # The loop for pl2 will break due to stop_processing_permalinks_for_this_commit_entirely = True
    assert mock_app_for_process_commit_details._process_permalink.call_count == 2  # Called for pl1 and pl2
    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl1,
        ancestor_commit,
        index=0,
        total=2,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )
    mock_app_for_process_commit_details._process_permalink.assert_any_call(
        pl2,
        ancestor_commit,
        index=1,
        total=2,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )


@patch("builtins.input")
def test_process_commit_details_tag_with_existing_replacements_keep_and_stop(
    mock_input, mock_app_for_process_commit_details: PermalinkFixerApp
):
    mock_input.return_value = "2"  # Keep previous, stop prompting
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    pl2 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=20)
    pl3 = create_mock_permalink_info(
        commit_hash=commit_hash, found_in_file_rel_path="fileB.md", found_at_line=5
    )  # Different file
    commit_permalinks = [pl1, pl2, pl3]  # Ensure order by file then line
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"
    repl_url1 = "https://new.url/for_pl1"

    mock_app_for_process_commit_details._process_permalink.side_effect = [
        ("replace", repl_url1),  # pl1 is replaced
        ("tag", None),  # pl2 triggers tagging. pl3 should not be processed.
    ]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag == (commit_hash, commit_info)
    assert len(pending_repls) == 1  # pl1's replacement kept
    assert pending_repls[0] == (pl1, repl_url1)
    assert mock_app_for_process_commit_details._process_permalink.call_count == 2  # Only for pl1 and pl2
    mock_input.assert_called_once()


@patch("builtins.input")
def test_process_commit_details_tag_with_existing_replacements_keep_and_continue(
    mock_input, mock_app_for_process_commit_details: PermalinkFixerApp
):
    mock_input.return_value = "3"  # Keep previous, continue prompting
    commit_hash = "commit1"
    pl1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    pl2 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=20)
    pl3 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileB.md", found_at_line=5)
    commit_permalinks = [pl1, pl2, pl3]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"
    repl_url1 = "https://new.url/for_pl1"
    repl_url3 = "https://new.url/for_pl3"  # pl3 will be replaced

    mock_app_for_process_commit_details._process_permalink.side_effect = [
        ("replace", repl_url1),  # pl1
        ("tag", None),  # pl2 (triggers tag, sub-prompt)
        ("replace", repl_url3),  # pl3 (processed because sub-prompt was "3")
    ]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag == (commit_hash, commit_info)
    assert len(pending_repls) == 2
    assert (pl1, repl_url1) in pending_repls
    assert (pl3, repl_url3) in pending_repls
    assert mock_app_for_process_commit_details._process_permalink.call_count == 3
    mock_input.assert_called_once()
    # Check that pl3 was processed with is_commit_slated_for_tagging=True
    third_call_args = mock_app_for_process_commit_details._process_permalink.call_args_list[2]
    assert third_call_args[0][0] == pl3  # permalink object
    assert third_call_args[1]["is_commit_slated_for_tagging"] is True


def test_process_commit_details_multiple_files_sorted_correctly(mock_app_for_process_commit_details: PermalinkFixerApp):
    commit_hash = "commit1"
    # Create permalinks out of order to test sorting
    pl_b1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileB.md", found_at_line=10)
    pl_a2 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=20)
    pl_a1 = create_mock_permalink_info(commit_hash=commit_hash, found_in_file_rel_path="fileA.md", found_at_line=10)
    commit_permalinks = [pl_b1, pl_a2, pl_a1]
    commit_info = {"subject": "Commit 1 subject"}
    ancestor_commit = "ancestor1"

    # Define behavior for _process_permalink for each permalink in expected sorted order
    # Expected order: pl_a1, pl_a2, pl_b1
    repl_url_a1 = "url_a1"
    repl_url_a2 = "url_a2"
    # pl_b1 will be skipped
    mock_app_for_process_commit_details._process_permalink.side_effect = [
        ("replace", repl_url_a1),  # For pl_a1
        ("replace", repl_url_a2),  # For pl_a2
        ("skip", None),  # For pl_b1
    ]

    pending_tag, pending_repls = mock_app_for_process_commit_details._process_commit_with_details(
        commit_hash, commit_permalinks, commit_info, ancestor_commit
    )

    assert pending_tag is None
    assert len(pending_repls) == 2
    assert pending_repls[0] == (pl_a1, repl_url_a1)
    assert pending_repls[1] == (pl_a2, repl_url_a2)

    assert mock_app_for_process_commit_details._process_permalink.call_count == 3
    calls = mock_app_for_process_commit_details._process_permalink.call_args_list
    assert calls[0][0][0] == pl_a1  # First call is for pl_a1
    assert calls[1][0][0] == pl_a2  # Second call is for pl_a2
    assert calls[2][0][0] == pl_b1  # Third call is for pl_b1
