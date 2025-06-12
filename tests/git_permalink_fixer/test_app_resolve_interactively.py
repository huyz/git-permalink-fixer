from unittest.mock import MagicMock, patch

from git_permalink_fixer.app import ResolutionState
from .conftest import create_mock_permalink_info


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("builtins.input")  # For the menu prompt
def test_resolve_interactively_cache_hit(mock_input, mock_process_choice, mock_evaluate, mock_app_for_resolution):
    original = create_mock_permalink_info(url="http://cached.url")
    cached_url = "http://resolved.cached.url"
    mock_app_for_resolution.resolved_repl_cache[original.url] = cached_url

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(original, "anc_hash")

    assert repl_url == cached_url
    assert aborted is False
    mock_evaluate.assert_not_called()
    mock_process_choice.assert_not_called()


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
def test_resolve_interactively_resolves_first_try(mock_evaluate, mock_app_for_resolution):
    original = create_mock_permalink_info()
    resolved_url_val = "http://resolved.first.try"
    mock_evaluate.return_value = ("resolved", "Success", resolved_url_val)

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(original, "anc_hash")

    assert repl_url == resolved_url_val
    assert aborted is False
    mock_evaluate.assert_called_once()


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("builtins.input")
def test_resolve_interactively_abort_choice(mock_input, mock_process_choice, mock_evaluate, mock_app_for_resolution):
    original = create_mock_permalink_info()
    mock_evaluate.return_value = ("path_missing_ancestor", "Path missing", None)  # First evaluation fails
    # User chooses to abort
    mock_process_choice.return_value = ("abort", MagicMock(spec=ResolutionState))

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(original, "anc_hash")

    assert repl_url is None
    assert aborted is True
    mock_evaluate.assert_called_once()
    mock_input.assert_called_once()  # For the menu
    mock_process_choice.assert_called_once()


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("git_permalink_fixer.app.PermalinkFixerApp._construct_url_from_current_state")
@patch("builtins.input")
def test_resolve_interactively_keep_choice_valid(
    mock_input, mock_construct_url, mock_process_choice, mock_evaluate, mock_app_for_resolution
):
    original = create_mock_permalink_info()
    kept_url_val = "http://kept.url"
    mock_evaluate.return_value = ("lines_mismatch_ancestor", "Lines mismatch", None)
    current_state_mock = MagicMock(spec=ResolutionState)
    mock_process_choice.return_value = ("resolve_with_current", current_state_mock)
    mock_construct_url.return_value = kept_url_val  # Successfully constructs URL from state

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(original, "anc_hash")

    assert repl_url == kept_url_val
    assert aborted is False
    mock_construct_url.assert_called_once_with(original, "anc_hash", current_state_mock)


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("git_permalink_fixer.app.PermalinkFixerApp._construct_url_from_current_state")
@patch("builtins.input")
def test_resolve_interactively_loop_then_resolve(
    mock_input, mock_construct_url, mock_process_choice, mock_evaluate, mock_app_for_resolution
):
    original = create_mock_permalink_info()
    final_resolved_url = "http://finally.resolved"

    # Simulate:
    # 1. Evaluate: fails (e.g., path_missing)
    # 2. Process choice: user inputs 'p' (set path), returns ("state_updated_continue", new_state_after_path_set)
    # 3. Evaluate (loop): succeeds with final_resolved_url

    state_after_path_set = MagicMock(spec=ResolutionState)
    mock_evaluate.side_effect = [
        ("path_missing_ancestor", "Path missing", None),  # First call
        ("resolved", "Success", final_resolved_url),  # Second call
    ]
    mock_process_choice.return_value = ("state_updated_continue", state_after_path_set)
    mock_input.return_value = "p"  # User chooses 'p'

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(original, "anc_hash")

    assert repl_url == final_resolved_url
    assert aborted is False
    assert mock_evaluate.call_count == 2
    assert mock_process_choice.call_count == 1  # Called after the first failed evaluation
    # Check that the second call to _evaluate_current_resolution_candidate used the state from _process_resolution_menu_choice
    assert mock_evaluate.call_args_list[1][0][2] == state_after_path_set


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("git_permalink_fixer.app.PermalinkFixerApp._construct_url_from_current_state")
@patch("builtins.input")
def test_resolve_interactively_no_ancestor_user_provides_url(
    mock_input, mock_construct_url, mock_process_choice, mock_evaluate, mock_app_for_resolution
):
    original = create_mock_permalink_info()
    user_provided_url = "https://user.provided/url#L1"

    # Initial state for no ancestor: current_is_external=True, current_external_url_base=None
    # 1. Evaluate: "needs_external_url"
    # 2. Process choice: user inputs 'u', state updates to reflect user_provided_url
    # 3. Evaluate: "resolved" with user_provided_url

    state_after_url_set = MagicMock(spec=ResolutionState)
    # Simulate _evaluate_current_resolution_candidate
    # First call: no external URL set
    eval_results = [("needs_external_url", "No external URL", None), ("resolved", "User URL OK", user_provided_url)]

    def evaluate_side_effect(orig, anc, state_param):
        # Check if state_param reflects the user having set the URL
        if state_param == state_after_url_set:  # This is a bit simplistic, real check would be on state content
            return eval_results[1]
        return eval_results[0]

    mock_evaluate.side_effect = evaluate_side_effect

    # Simulate _process_resolution_menu_choice for 'u'
    # It would internally call _resolution_menu_handle_set_url which updates the state
    mock_process_choice.return_value = ("state_updated_continue", state_after_url_set)

    mock_input.return_value = "u"  # User chooses 'u' to set URL

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(
        original,
        None,  # No ancestor
    )

    assert repl_url == user_provided_url
    assert aborted is False
    assert mock_evaluate.call_count == 2
    mock_process_choice.assert_called_once()

    # Check initial state passed to _evaluate_current_resolution_candidate
    initial_call_state = mock_evaluate.call_args_list[0][0][2]
    assert initial_call_state["current_is_external"] is True
    assert initial_call_state["current_external_url_base"] is None
    assert initial_call_state["current_url_path_for_ancestor"] is None  # No ancestor

    # Check state after user input 'u' passed to _evaluate_current_resolution_candidate
    second_call_state = mock_evaluate.call_args_list[1][0][2]
    assert second_call_state == state_after_url_set


@patch("git_permalink_fixer.app.PermalinkFixerApp._evaluate_current_resolution_candidate")
@patch("git_permalink_fixer.app.PermalinkFixerApp._process_resolution_menu_choice")
@patch("git_permalink_fixer.app.PermalinkFixerApp._construct_url_from_current_state")
@patch("builtins.input")
def test_resolve_interactively_keep_choice_invalid_then_abort(
    mock_input, mock_construct_url, mock_process_choice, mock_evaluate, mock_app_for_resolution
):
    original = create_mock_permalink_info()

    # 1. Evaluate: fails (e.g., "needs_external_url")
    # 2. Process choice: user inputs 'k' (keep)
    # 3. _construct_url_from_current_state returns None (invalid state to keep)
    # 4. Loop, Evaluate again: fails (still "needs_external_url")
    # 5. Process choice: user inputs 'a' (abort)

    initial_state_mock = MagicMock(spec=ResolutionState)
    initial_state_mock.current_is_external = True  # Example initial state
    initial_state_mock.current_external_url_base = None

    # Simulate _evaluate_current_resolution_candidate
    mock_evaluate.return_value = ("needs_external_url", "No external URL", None)

    # Simulate _process_resolution_menu_choice
    # First call for 'k', second for 'a'
    mock_process_choice.side_effect = [
        ("resolve_with_current", initial_state_mock),  # User chose 'k'
        ("abort", initial_state_mock),  # User chose 'a'
    ]

    # Simulate _construct_url_from_current_state
    # First call (after 'k') returns None because state is not yet valid for a URL
    mock_construct_url.return_value = None

    # User inputs 'k', then 'a'
    mock_input.side_effect = ["k", "a"]

    repl_url, aborted = mock_app_for_resolution._resolve_replacement_interactively(
        original,
        None,  # No ancestor
    )

    assert repl_url is None
    assert aborted is True
    assert mock_evaluate.call_count == 2  # Called twice due to loop
    assert mock_process_choice.call_count == 2
    mock_construct_url.assert_called_once_with(original, None, initial_state_mock)  # Called after 'k'

    # Verify initial state passed to _evaluate
    first_eval_call_args = mock_evaluate.call_args_list[0][0]
    assert first_eval_call_args[2]["current_is_external"] is True  # Initial state for no ancestor
    assert first_eval_call_args[2]["current_external_url_base"] is None

    # Verify state passed to _process_resolution_menu_choice (should be the one from the loop)
    first_process_choice_call_args = mock_process_choice.call_args_list[0][0]
    assert first_process_choice_call_args[3]["current_is_external"] is True

    # Verify state passed to _construct_url_from_current_state
    assert mock_construct_url.call_args[0][2] == initial_state_mock

    # Verify state for second loop
    second_eval_call_args = mock_evaluate.call_args_list[1][0]
    assert second_eval_call_args[2] == initial_state_mock  # State should persist from the 'k' choice attempt

    second_process_choice_call_args = mock_process_choice.call_args_list[1][0]
    assert second_process_choice_call_args[3] == initial_state_mock
