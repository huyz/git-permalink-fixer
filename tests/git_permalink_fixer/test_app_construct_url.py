from git_permalink_fixer.app import ResolutionState
from .conftest import create_mock_permalink_info


def test_construct_repl_permalink_blob_with_lines(mock_app_for_resolution):
    original = create_mock_permalink_info(url="https://github.com/orig_owner/orig_repo/blob/oldhash/path/file.py#L1")
    repl_url = mock_app_for_resolution._construct_repl_permalink(original, "newhash", "path/file.py", 10, 12)
    assert repl_url == "https://github.com/orig_owner/orig_repo/blob/newhash/path/file.py#L10-L12"


def test_construct_repl_permalink_blob_no_lines(mock_app_for_resolution):
    original = create_mock_permalink_info(url="https://github.com/owner/repo/blob/oldhash/path/file.py")
    repl_url = mock_app_for_resolution._construct_repl_permalink(original, "newhash", "path/file.py", None, None)
    assert repl_url == "https://github.com/owner/repo/blob/newhash/path/file.py"


def test_construct_repl_permalink_tree_link(mock_app_for_resolution):
    original = create_mock_permalink_info(
        url="https://github.com/owner/repo/tree/oldhash/path"
    )  # Original might have path
    repl_url = mock_app_for_resolution._construct_repl_permalink(
        original, "newhash", None, None, None
    )  # For tree, path is None
    assert repl_url == "https://github.com/owner/repo/tree/newhash"


def test_construct_repl_permalink_blob_no_path_becomes_tree(mock_app_for_resolution):
    original = create_mock_permalink_info(url="https://github.com/owner/repo/blob/oldhash")  # No path in original
    # If repl_url_path is None, it should construct a tree link to the commit
    repl_url = mock_app_for_resolution._construct_repl_permalink(original, "newhash", None, None, None)
    assert repl_url == "https://github.com/owner/repo/tree/newhash"


def test_construct_url_from_current_state_external(mock_app_for_resolution):
    original = create_mock_permalink_info()
    state: ResolutionState = {
        "current_is_external": True,
        "current_external_url_base": "https://ext.com/file",
        "current_url_path_for_ancestor": None,
        "current_ls": 1,
        "current_le": 2,
        "custom_tolerance_str": None,
    }
    url = mock_app_for_resolution._construct_url_from_current_state(original, None, state)
    assert url == "https://ext.com/file#L1-L2"


def test_construct_url_from_current_state_ancestor(mock_app_for_resolution):
    original = create_mock_permalink_info()
    state: ResolutionState = {
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "anc/file.py",
        "current_ls": 5,
        "current_le": None,
        "custom_tolerance_str": None,
    }
    url = mock_app_for_resolution._construct_url_from_current_state(original, "ancestor_hash", state)
    assert (
        url
        == f"https://github.com/{mock_app_for_resolution.git_owner}/{mock_app_for_resolution.git_repo}/blob/ancestor_hash/anc/file.py#L5"
    )


def test_construct_url_from_current_state_none(mock_app_for_resolution):
    original = create_mock_permalink_info()
    state: ResolutionState = {  # Not external, but no ancestor provided to func
        "current_is_external": False,
        "current_external_url_base": None,
        "current_url_path_for_ancestor": "anc/file.py",
        "current_ls": 5,
        "current_le": None,
        "custom_tolerance_str": None,
    }
    url = mock_app_for_resolution._construct_url_from_current_state(original, None, state)
    assert url is None
