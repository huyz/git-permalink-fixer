import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from git_permalink_fixer.app import PermalinkFixerApp
from git_permalink_fixer.global_prefs import GlobalPreferences
from git_permalink_fixer.session_prefs import SessionPreferences, FetchMode
from .conftest import create_mock_permalink_info


@pytest.fixture
def mock_app_for_prompt_user():
    # Mock GlobalPreferences and SessionPreferences
    mock_global_prefs = MagicMock(spec=GlobalPreferences)
    mock_global_prefs.verbose = False
    mock_global_prefs.dry_run = False
    mock_global_prefs.main_branch = "main"
    mock_global_prefs.tag_prefix = "permalinks/ref"
    mock_global_prefs.repo_aliases = []
    mock_global_prefs.line_shift_tolerance_str = "20"
    mock_global_prefs.tolerance_is_percentage = False
    mock_global_prefs.tolerance_value = 20
    mock_global_prefs.output_json_report_path = None

    mock_session_prefs = MagicMock(spec=SessionPreferences)
    mock_session_prefs.fetch_mode = FetchMode.PROMPT
    mock_session_prefs.auto_accept_replace = False
    mock_session_prefs.auto_fallback = None
    mock_session_prefs.remembered_action_with_repl = None
    mock_session_prefs.remembered_action_without_repl = None

    # Patch dependencies of PermalinkFixerApp.__init__ that call subprocess
    with (
        patch("git_permalink_fixer.app.get_repo_root", return_value=Path("/fake/repo")),
        patch("git_permalink_fixer.app.get_remote_url", return_value="https://github.com/owner/repo.git"),
    ):
        # Mock PermalinkFixerApp instance
        app = PermalinkFixerApp(mock_global_prefs, mock_session_prefs)

    # Mock other internal methods/attributes used by _prompt_user_for_action
    # app.repo_root, app.remote_url, app.git_owner, app.git_repo are set by the
    # constructor using the patched get_repo_root and get_remote_url.
    app._vprint = MagicMock()

    return app


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_replace(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["r"]  # Simulate user choosing 'r'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," in prompt_call_args
    assert ",rc," in prompt_call_args
    assert ",ra," in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_replace_no_repl_url(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["r", "s"]  # Simulate user choosing 'r' then 's'
    original_permalink = create_mock_permalink_info()
    repl_url = None

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_called()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," not in prompt_call_args
    assert ",rc," not in prompt_call_args
    assert ",ra," not in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_tag(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["t"]  # Simulate user choosing 't'
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL available

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "tag"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_skip(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["s"]  # Simulate user choosing 's'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_replace_all(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["ra"]  # Simulate user choosing 'ra'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace"
    assert remember_choice == "replace"
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    # Not yet set to "replace"; that's the parent caller's job
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_tag_all(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["ta"]  # Simulate user choosing 'ta'
    original_permalink = create_mock_permalink_info()
    repl_url = (
        "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"  # Repl URL exists, but user wants to tag all
    )

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "tag"
    assert remember_choice == "tag"
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    # Not yet set to "tag"; that's the parent caller's job
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_skip_all(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["sa"]  # Simulate user choosing 'sa'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice == "skip"
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    # Not yet set to "skip"; that's the parent caller's job
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_replace_commit_group(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["rc"]  # Simulate user choosing 'rc'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace_commit_group"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_skip_commit_group(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["sc"]  # Simulate user choosing 'sc'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip_commit_group"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_untag(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["-t"]  # Simulate user choosing '-t'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=True
    )

    assert action == "untag"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_open_urls(mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp):
    mock_input.side_effect = ["o", "s"]  # Simulate user choosing 'o' then 's'
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    assert mock_input.call_count == 2
    mock_open_urls.assert_called_once_with(
        [
            ("original URL", original_permalink.url),
            ("suggested replacement URL", repl_url),
        ]
    )
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_invalid_then_valid_input(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["invalid", "r"]  # Simulate invalid then valid input
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace"
    assert remember_choice is None
    assert mock_input.call_count == 2
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_auto_accept_replace(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.auto_accept_replace = True
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_auto_fallback_tag(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.auto_fallback = "tag"
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "tag"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_auto_fallback_skip(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.auto_fallback = "skip"
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_remembered_replace(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.remembered_action_with_repl = "replace"
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "replace"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_remembered_tag_fallback(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.remembered_action_without_repl = "tag"
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "tag"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_remembered_skip_fallback(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_app_for_prompt_user.session_prefs.remembered_action_without_repl = "skip"
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_commit_directive_replace(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit="replace",
    )

    assert action == "replace"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_commit_directive_skip(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit="skip",
    )

    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_not_called()  # Should not prompt
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_commit_directive_replace_no_repl_url(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    # auto_action_directive_for_commit is ineffective since repl_url is NOne
    mock_input.side_effect = ["s"]  # Simulate user choosing 's'

    # Test case where commit directive is 'replace' but no repl_url is available
    original_permalink = create_mock_permalink_info()
    repl_url = None

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit="replace",  # Directive is replace
    )

    # Should fall back to skip if repl_url is None
    assert action == "skip"
    assert remember_choice is None
    mock_input.assert_called_once()  # Should fall back to prompting
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_priority_commit_directive_over_auto_flags(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    # Commit directive should override global auto flags
    mock_app_for_prompt_user.session_prefs.auto_accept_replace = True  # Global says replace
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No repl URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit="skip",  # Commit directive says skip
    )

    assert action == "skip"  # Skip directive should win
    assert remember_choice is None
    mock_input.assert_not_called()
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_priority_auto_flags_over_remembered(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    # Global auto flags should override remembered choices
    mock_app_for_prompt_user.session_prefs.remembered_action_with_repl = "skip"  # Remembered says skip
    mock_app_for_prompt_user.session_prefs.auto_accept_replace = True  # Global says replace
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )

    assert action == "replace"  # Global auto-accept should win
    assert remember_choice is None
    mock_input.assert_not_called()
    mock_open_urls.assert_not_called()


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_remembered_choice_applies(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["r"]  # Simulate user choosing 'r'

    # Remembered choice should not matter because there's a viable replace URL
    mock_app_for_prompt_user.session_prefs.remembered_action_with_repl = "skip"
    mock_app_for_prompt_user.session_prefs.auto_accept_replace = False
    mock_app_for_prompt_user.session_prefs.auto_fallback = None
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,
        auto_action_directive_for_commit=None,
    )

    assert action == "replace"
    assert remember_choice is None
    mock_input.assert_called_once()
    mock_open_urls.assert_not_called()
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," in prompt_call_args
    assert ",rc," in prompt_call_args
    assert ",ra," in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_untag_option_shown_when_slated(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["-t"]  # User chooses untag
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=True,  # Commit is slated
    )

    assert action == "untag"
    assert remember_choice is None
    mock_input.assert_called_once()
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," in prompt_call_args
    assert ",rc," in prompt_call_args
    assert ",ra," in prompt_call_args
    # Check that '-t' was in the prompt options list
    assert ",-t," in prompt_call_args
    assert ",t," not in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_tag_option_shown_when_not_slated(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["t"]  # User chooses tag
    original_permalink = create_mock_permalink_info()
    repl_url = "https://github.com/owner/repo/blob/newhash/path/to/file.py#L12"

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink,
        repl_url,
        is_commit_slated_for_tagging=False,  # Commit is NOT slated
    )

    assert action == "tag"
    assert remember_choice is None
    mock_input.assert_called_once()
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," in prompt_call_args
    assert ",rc," in prompt_call_args
    assert ",ra," in prompt_call_args
    assert ",t," in prompt_call_args
    assert ",-t," not in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_replace_options_not_shown_if_no_repl_url(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["t"]  # User chooses tag
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "tag"
    assert remember_choice is None
    mock_input.assert_called_once()
    # Check that 'r', 'rc', 'ra' were NOT in the prompt options list
    prompt_call_args = mock_input.call_args[0][0]
    assert ",r," not in prompt_call_args
    assert ",rc," not in prompt_call_args
    assert ",ra," not in prompt_call_args


@patch("git_permalink_fixer.app.open_urls_in_browser")
@patch("builtins.input")
def test_prompt_user_for_action_open_urls_no_repl_url(
    mock_input, mock_open_urls, mock_app_for_prompt_user: PermalinkFixerApp
):
    mock_input.side_effect = ["o", "s"]  # Simulate user choosing 'o' then 's'
    original_permalink = create_mock_permalink_info()
    repl_url = None  # No replacement URL

    action, remember_choice = mock_app_for_prompt_user._prompt_user_for_action(
        original_permalink, repl_url, is_commit_slated_for_tagging=False
    )

    assert action == "skip"
    assert remember_choice is None
    assert mock_input.call_count == 2
    mock_open_urls.assert_called_once_with(
        [
            ("original URL", original_permalink.url),
        ]
    )
    assert mock_app_for_prompt_user.session_prefs.remembered_action_with_repl is None
    assert mock_app_for_prompt_user.session_prefs.remembered_action_without_repl is None
