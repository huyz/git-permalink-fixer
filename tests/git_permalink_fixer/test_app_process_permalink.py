import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path, PosixPath

from git_permalink_fixer.app import PermalinkFixerApp
from git_permalink_fixer.global_prefs import GlobalPreferences
from git_permalink_fixer.session_prefs import SessionPreferences, FetchMode
from .conftest import create_mock_permalink_info


@pytest.fixture
def mock_app_for_process_permalink():
    mock_global_prefs = MagicMock(spec=GlobalPreferences)
    mock_global_prefs.verbose = False
    mock_global_prefs.main_branch = "main"
    mock_global_prefs.repo_aliases = []  # for _normalize_repo_name if it were called

    mock_session_prefs = MagicMock(spec=SessionPreferences)
    mock_session_prefs.fetch_mode = FetchMode.PROMPT
    mock_session_prefs.remembered_action_with_repl = None
    mock_session_prefs.remembered_action_without_repl = None

    # Patch dependencies of PermalinkFixerApp.__init__
    with (
        patch("git_permalink_fixer.app.get_repo_root", return_value=Path("/fake/repo")),
        patch("git_permalink_fixer.app.get_remote_url", return_value="https://github.com/owner/repo.git"),
        patch("git_permalink_fixer.app.get_github_info_from_url", return_value=("owner", "repo")),
    ):
        app = PermalinkFixerApp(mock_global_prefs, mock_session_prefs)

    # Mock methods directly called by _process_permalink or its callees
    app._vprint = MagicMock()
    app._resolve_replacement_interactively = MagicMock()
    app._construct_repl_permalink = MagicMock()
    app._prompt_user_for_action = MagicMock()
    # app.repo_root is set by __init__ via mocked get_repo_root

    return app


@patch("git_permalink_fixer.app.get_commit_info")  # Mocked at the app module level
def test_process_permalink_with_ancestor_and_path_resolves(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    expected_repl_url = "https://new.url/resolved"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (
        expected_repl_url,
        False,
    )  # url, aborted
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", None)  # action, remember_choice

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False
    )

    assert action == "replace"
    assert repl_url == expected_repl_url
    mock_app_for_process_permalink._resolve_replacement_interactively.assert_called_once_with(
        original_permalink, ancestor_commit
    )
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, expected_repl_url, False, auto_action_directive_for_commit=None
    )
    mock_get_commit_info.assert_called_once_with(ancestor_commit, repo_path=PosixPath("/fake/repo"))


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_with_ancestor_tree_link(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info(
        url_path=None, url="https://github.com/owner/repo/tree/abcdef123456"
    )  # Tree link
    ancestor_commit = "ancestorhash"
    expected_repl_url = "https://github.com/owner/repo/tree/ancestorhash"
    mock_app_for_process_permalink._construct_repl_permalink.return_value = expected_repl_url
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", None)

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False
    )

    assert action == "replace"
    assert repl_url == expected_repl_url
    mock_app_for_process_permalink._construct_repl_permalink.assert_called_once_with(
        original_permalink, ancestor_commit, None, None, None
    )
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, expected_repl_url, False, auto_action_directive_for_commit=None
    )
    mock_app_for_process_permalink._resolve_replacement_interactively.assert_not_called()


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_no_ancestor_resolves(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    original_permalink = create_mock_permalink_info()
    expected_repl_url = "https://new.url/user_provided"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (expected_repl_url, False)
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", None)

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink,
        None,
        0,
        1,
        False,  # No ancestor
    )

    assert action == "replace"
    assert repl_url == expected_repl_url
    mock_app_for_process_permalink._resolve_replacement_interactively.assert_called_once_with(original_permalink, None)
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, expected_repl_url, False, auto_action_directive_for_commit=None
    )
    mock_get_commit_info.assert_not_called()


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_resolution_aborted(mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (None, True)  # Aborted

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False
    )

    assert action == "skip"
    assert repl_url is None
    mock_app_for_process_permalink._resolve_replacement_interactively.assert_called_once_with(
        original_permalink, ancestor_commit
    )
    mock_app_for_process_permalink._prompt_user_for_action.assert_not_called()


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_action_tag(mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    # Resolution provides a URL, but user chooses to tag
    resolved_url = "https://resolved.url/for_ancestor"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (resolved_url, False)
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("tag", None)

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False
    )

    assert action == "tag"
    assert repl_url is None  # repl_url is None because action is not "replace"
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, resolved_url, False, auto_action_directive_for_commit=None
    )


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_action_replace_no_repl_url_fallback_to_skip(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (
        None,
        False,
    )  # No repl_url, not aborted
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", None)  # User chose replace

    action, repl_url = mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False
    )

    assert action == "skip"  # Should fallback to skip
    assert repl_url is None
    mock_app_for_process_permalink._vprint.assert_any_call(
        f"  ⚠️ Warning: Action 'replace' chosen but no replacement URL available for {original_permalink.url}. Falling back to skip."
    )


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_remember_choice_with_repl(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    expected_repl_url = "https://new.url/resolved"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (expected_repl_url, False)
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", "replace")  # remember "replace"

    mock_app_for_process_permalink._process_permalink(original_permalink, ancestor_commit, 0, 1, False)
    assert mock_app_for_process_permalink.session_prefs.remembered_action_with_repl == "replace"
    assert mock_app_for_process_permalink.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_remember_choice_without_repl(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (None, False)  # No repl_url
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("tag", "tag")  # remember "tag"

    mock_app_for_process_permalink._process_permalink(original_permalink, ancestor_commit, 0, 1, False)
    assert mock_app_for_process_permalink.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_process_permalink.session_prefs.remembered_action_without_repl == "tag"


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_is_commit_slated_for_tagging_passed_to_prompt(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    expected_repl_url = "https://new.url/resolved"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (expected_repl_url, False)
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("skip", None)

    mock_app_for_process_permalink._process_permalink(
        original_permalink,
        ancestor_commit,
        0,
        1,
        True,  # is_commit_slated_for_tagging = True
    )
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, expected_repl_url, True, auto_action_directive_for_commit=None
    )


@patch("git_permalink_fixer.app.get_commit_info")
def test_process_permalink_auto_action_directive_passed_to_prompt(
    mock_get_commit_info, mock_app_for_process_permalink: PermalinkFixerApp
):
    mock_get_commit_info.return_value = {"subject": "Ancestor commit subject", "author": "Auth", "date": "Date"}
    original_permalink = create_mock_permalink_info()
    ancestor_commit = "ancestorhash"
    expected_repl_url = "https://new.url/resolved"
    mock_app_for_process_permalink._resolve_replacement_interactively.return_value = (expected_repl_url, False)
    mock_app_for_process_permalink._prompt_user_for_action.return_value = ("replace", None)

    mock_app_for_process_permalink._process_permalink(
        original_permalink, ancestor_commit, 0, 1, False, auto_action_directive_for_commit="replace"
    )
    mock_app_for_process_permalink._prompt_user_for_action.assert_called_once_with(
        original_permalink, expected_repl_url, False, auto_action_directive_for_commit="replace"
    )
