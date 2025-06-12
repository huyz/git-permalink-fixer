from unittest.mock import patch

from git_permalink_fixer.app import ResolutionState


@patch("builtins.input")
def test_resolution_menu_handle_set_line_numbers_valid_single(mock_input, mock_app_for_resolution):
    mock_input.return_value = "10"
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_line_numbers(state)
    assert status == "state_updated_continue"
    assert new_state["current_ls"] == 10
    assert new_state["current_le"] is None


@patch("builtins.input")
def test_resolution_menu_handle_set_line_numbers_valid_range(mock_input, mock_app_for_resolution):
    mock_input.return_value = "15-20"
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_line_numbers(state)
    assert status == "state_updated_continue"
    assert new_state["current_ls"] == 15
    assert new_state["current_le"] == 20


@patch("builtins.input")
def test_resolution_menu_handle_set_line_numbers_empty_clears(mock_input, mock_app_for_resolution):
    mock_input.return_value = ""
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_line_numbers(state)
    assert status == "state_updated_continue"
    assert new_state["current_ls"] is None
    assert new_state["current_le"] is None


@patch("builtins.input")
def test_resolution_menu_handle_set_line_numbers_invalid(mock_input, mock_app_for_resolution):
    mock_input.return_value = "abc"
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    original_state = state.copy()
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_line_numbers(state)
    assert status == "invalid_choice_continue"
    assert new_state == original_state  # State should not change


# Tests for _resolution_menu_handle_set_url
@patch("builtins.input")
@patch("git_permalink_fixer.app.parse_github_blob_permalink")
def test_resolution_menu_handle_set_url_valid_external(mock_parse_gh, mock_input, mock_app_for_resolution):
    mock_input.side_effect = ["https://new.com/file#L5", "y"]  # URL, then confirm 'y'
    mock_parse_gh.return_value = None  # Parsed as non-ancestor
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_url("anc_hash", state)
    assert status == "state_updated_continue"
    assert new_state["current_is_external"] is True
    assert new_state["current_external_url_base"] == "https://new.com/file"
    assert new_state["current_ls"] is None
    assert new_state["current_url_path_for_ancestor"] is None


@patch("builtins.input")
@patch("git_permalink_fixer.app.parse_github_blob_permalink")
def test_resolution_menu_handle_set_url_for_ancestor(mock_parse_gh, mock_input, mock_app_for_resolution):
    ancestor_commit = "anc_hash_long"
    new_url = f"https://github.com/{mock_app_for_resolution.git_owner}/{mock_app_for_resolution.git_repo}/blob/{ancestor_commit}/new/path.py#L10"
    mock_input.return_value = new_url
    # Mock parse_github_blob_permalink to return info matching the ancestor
    mock_parse_gh.return_value = (
        mock_app_for_resolution.git_owner,
        mock_app_for_resolution.git_repo,
        ancestor_commit,
        "new/path.py",
        10,
        None,
    )

    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": True,
        "current_external_url_base": "old_url",
        "current_url_path_for_ancestor": None,
        "custom_tolerance_str": None,
    }
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_url(ancestor_commit, state)

    assert status == "state_updated_continue"
    assert new_state["current_is_external"] is False
    assert new_state["current_url_path_for_ancestor"] == "new/path.py"
    assert new_state["current_ls"] == 10
    assert new_state["current_external_url_base"] is None  # Should be cleared


@patch("builtins.input")
def test_resolution_menu_handle_set_url_invalid_protocol(mock_input, mock_app_for_resolution):
    mock_input.return_value = "http://new.com/file"  # Not https
    state: ResolutionState = {
        "current_ls": 1,
        "current_le": 2,
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "p",
        "custom_tolerance_str": None,
    }
    original_state = state.copy()
    status, new_state = mock_app_for_resolution._resolution_menu_handle_set_url("anc_hash", state)
    assert status == "invalid_choice_continue"
    assert new_state == original_state
