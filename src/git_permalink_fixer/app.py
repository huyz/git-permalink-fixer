import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, TypedDict

from .examination_set import ExaminationSet
from .file_ops import extract_permalinks_from_file, should_skip_file_search
from .git_utils import (
    create_git_tag,
    file_exists_at_commit,
    find_closest_ancestor_in_main,
    gen_git_tag_name,
    get_commit_info,
    get_file_content_at_commit,
    get_github_info_from_url,
    get_remote_url,
    get_repo_root,
    git_tag_exists,
    is_commit_in_main,
    load_ignored_paths,
)
from .global_prefs import GlobalPreferences
from .operation_set import OperationSet, PermalinkReplacementOperation, TagCreationOperation
from .permalink_info import PermalinkInfo
from .session_prefs import SessionPreferences
from .url_utils import parse_github_blob_permalink, update_github_url_with_line_numbers
from .web_utils import fetch_raw_github_content_from_url, open_urls_in_browser
from .text_utils import parse_tolerance_input


from .session_prefs import FetchMode
from .git_utils import is_commit_available_locally, fetch_commit_missing_locally


class ResolutionState(TypedDict):
    current_is_external: bool
    current_external_url_base: Optional[str]
    current_url_path_for_ancestor: Optional[str]
    current_ls: Optional[int]
    current_le: Optional[int]
    custom_tolerance_str: Optional[str]


class PermalinkFixerApp:
    repo_root: Path
    effective_scan_path: Path

    def __init__(
        self,
        global_prefs: GlobalPreferences,
        session_prefs: SessionPreferences,
    ):
        self.global_prefs = global_prefs
        self.session_prefs = session_prefs

        # Determine repo_root and effective_scan_path
        if self.global_prefs.scan_path:
            user_scan_path_input = self.global_prefs.scan_path
            # Resolve first to handle relative paths correctly
            scan_path = user_scan_path_input.resolve()

            if not scan_path.exists():
                raise RuntimeError(f"Provided scan path '{self.global_prefs.scan_path}' does not exist.")

            # Determine the directory from which to find the repo root
            # If scan_path is a file, start search from its parent. If a dir, start from itself.
            path_for_repo_discovery = scan_path.parent if scan_path.is_file() else scan_path

            # This will raise RuntimeError if not in a git repo (or path_for_repo_discovery isn't in one),
            # handled by main()
            self.repo_root = get_repo_root(start_dir=path_for_repo_discovery)

            # Sanity check: the scan_path must be within the discovered repo_root.
            # This should generally be true if get_repo_root works correctly from path_for_repo_discovery.
            try:
                scan_path.relative_to(self.repo_root)
            except ValueError as e:
                # This case implies that scan_path.resolve() is outside the repo found from its own context.
                raise RuntimeError(
                    f"Resolved scan path '{scan_path}' is not inside the git repository root '{self.repo_root}' discovered from '{path_for_repo_discovery}'."
                ) from e
            self.effective_scan_path = scan_path
        else:
            # No scan_path provided, determine repo_root from CWD
            self.repo_root = get_repo_root()  # Defaults to CWD
            self.effective_scan_path = self.repo_root

        self.remote_url = get_remote_url(repo_path=self.repo_root)
        self.git_owner, self.git_repo = get_github_info_from_url(self.remote_url)

        self.resolved_repl_cache: Dict[str, str] = {}

    def _print_initial_summary(self):
        self._vprint(f"Repository root: {self.repo_root}")
        self._vprint(f"Effective scan path: {self.effective_scan_path}")
        self._vprint(f"GitHub: {self.git_owner}/{self.git_repo}")
        self._vprint(f"Main branch: {self.global_prefs.main_branch}, Tag prefix: {self.global_prefs.tag_prefix}")
        self._vprint(f"Repo aliases: {self.global_prefs.repo_aliases if self.global_prefs.repo_aliases else 'None'}")
        self._vprint(
            f"Respect gitignore: {self.global_prefs.respect_gitignore}, "
            f"Dry run: {self.global_prefs.dry_run}, "
            f"Fetch mode: {self.session_prefs.fetch_mode.value}, Auto accept replace: {self.session_prefs.auto_accept_replace}, Auto fallback: {self.session_prefs.auto_fallback}"
        )
        if self.global_prefs.output_json_report_path:
            self._vprint(f"JSON Report output: {self.global_prefs.output_json_report_path}")
        self._vprint(
            f"Line shift tolerance: {self.global_prefs.line_shift_tolerance_str} (parsed as: {'percentage' if self.global_prefs.tolerance_is_percentage else 'absolute'}, value: {self.global_prefs.tolerance_value})"
        )
        self._vprint("-" * 50)

    def _vprint(self, *args, **kwargs):
        """Prints only if verbose mode is enabled."""
        if self.global_prefs.verbose:
            print(*args, **kwargs)

    def _normalize_repo_name(self, repo_name: str) -> str:
        """
        Normalizes a repository name for comparison against the current repository.

        If the given repo_name (case-insensitive) matches the main repository name
        (self.git_repo) or is one of its configured aliases (self.repo_aliases),
        this method returns the lowercased main repository name.
        Otherwise, it returns the lowercased version of the input repo_name.
        """
        if not repo_name:
            return repo_name
        lower_repo_name = repo_name.lower()
        if lower_repo_name == self.git_repo.lower() or lower_repo_name in self.global_prefs.repo_aliases:
            return self.git_repo.lower()
        return lower_repo_name

    def _discover_phase(self) -> ExaminationSet:
        """Find all GitHub commit permalinks in the repository."""
        examination_set = ExaminationSet()

        ignored_paths_set: Optional[Set[Path]] = None
        try:
            ignored_paths_set = load_ignored_paths(self.repo_root) if self.global_prefs.respect_gitignore else set()
        except RuntimeError as e:
            self._vprint(
                f"⚠️ Warning: Could not get git-ignored paths: {e}. Gitignore rules will not be applied effectively."
            )

        self._vprint(f"Searching for GitHub permalinks in {self.effective_scan_path}")

        global_found_count = 0

        files_to_scan: List[Path] = []
        if self.effective_scan_path.is_file():
            files_to_scan.append(self.effective_scan_path)
        elif self.effective_scan_path.is_dir():
            files_to_scan.extend(self.effective_scan_path.rglob("*"))
        else:
            # This case should ideally be caught by the exists() check in __init__
            # but as a safeguard:
            print(f"Warning: Scan path {self.effective_scan_path} is neither a file nor a directory. No files to scan.")

        for file_path in files_to_scan:
            # Determine if the file should be processed or skipped
            process_this_file = True
            log_as_skipped_due_to_gitignore = False
            # 1. Check if skipped by fundamental rules (directory, .git, non-text extension)
            #    Pass `None` for ignored_paths_from_git to check only fundamental rules.
            skipped_by_fundamental_rules = should_skip_file_search(file_path, self.repo_root, None)

            if skipped_by_fundamental_rules:
                process_this_file = False
            else:
                # 2. Not skipped by fundamental rules. Now check .gitignore if respect_gitignore is
                # active.
                if self.global_prefs.respect_gitignore and ignored_paths_set:
                    # Check if the file is covered by .gitignore rules by seeing if
                    # should_skip_file_search returns True when the gitignore set IS provided.
                    if should_skip_file_search(file_path, self.repo_root, ignored_paths_set):
                        # Since skipped_by_fundamental_rules is False, this means it's skipped
                        # *solely* due to .gitignore
                        process_this_file = False
                        log_as_skipped_due_to_gitignore = True

            if not process_this_file:
                if log_as_skipped_due_to_gitignore and self.global_prefs.verbose:
                    # Peek into the git-ignored file to see if it contains permalinks for logging
                    # purposes
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as ignored_file:
                            lines = ignored_file.readlines()
                        # Use a temporary count, don't affect main global_found_count or detailed logging
                        permalinks_in_ignored_file, _ = extract_permalinks_from_file(
                            file_path,
                            lines,
                            self.repo_root,
                            self.git_owner,
                            self.git_repo,
                            0,
                            self._normalize_repo_name,
                        )
                        if permalinks_in_ignored_file:
                            self._vprint(
                                f"  🙈 git-ignored file with {len(permalinks_in_ignored_file)} permalink(s): {file_path.relative_to(self.repo_root)}"
                            )
                    except (UnicodeDecodeError, IOError, OSError, PermissionError) as e_log:
                        self._vprint(
                            f"  ⚠️ Could not read git-ignored file {file_path.relative_to(self.repo_root)} for special logging: {e_log}"
                        )
                continue

            # If process_this_file is True, proceed with normal processing
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                (permalinks_in_file, global_found_count) = extract_permalinks_from_file(
                    file_path,
                    lines,
                    self.repo_root,
                    self.git_owner,
                    self.git_repo,
                    global_found_count,
                    self._normalize_repo_name,
                )
                for pl in permalinks_in_file:
                    examination_set.add_permalink(pl)
            except (UnicodeDecodeError, IOError, OSError, PermissionError) as e:
                print(f"Warning: Could not read {file_path}: {e}")
                continue

        return examination_set

    def _display_content_mismatch(
        self,
        original_permalink_info: PermalinkInfo,
        original_content_snippet: List[str],
        target_description: str,  # e.g., "ancestor commit X:path/to/file" or "URL Y"
        sample_target_content: Optional[List[str]],
        line_shift_tolerance: int,
    ):
        """Helper to log detailed mismatch information if verbose."""
        if not self.global_prefs.verbose:
            return

        self._vprint(
            f"  ⚠️ Content mismatch for {original_permalink_info.url_path} L{original_permalink_info.line_start}{'-' + str(original_permalink_info.line_end) if original_permalink_info.line_end else ''} in {target_description} (tolerance: {line_shift_tolerance})."
        )
        self._vprint(f"    ⚰️ Original content ({len(original_content_snippet)} lines):")
        for line in original_content_snippet:
            self._vprint(f"      | {line}")

        if sample_target_content:
            self._vprint(f"    🎯 Target content at unshifted line numbers ({len(sample_target_content)} lines):")
            for line in sample_target_content:
                self._vprint(f"      | {line}")
        elif not sample_target_content:
            self._vprint(f"    ❌ Target content could not be fetched or was empty.")

    def _verify_content_match(
        self,
        original: PermalinkInfo,  # Defines original content source (commit, path, lines)
        target_commit_hash: Optional[str] = None,
        target_url_path: Optional[str] = None,
        target_url: Optional[str] = None,
        custom_tolerance_str: Optional[str] = None,  # Optional custom tolerance string (e.g., "5" or "10%")
    ) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Verifies if the content from the original permalink's specified lines exists in the target,
        allowing for line shifts. The target can be specified by a commit hash and file path,
        or by a URL. Strips leading/trailing whitespace from lines for comparison.

        Returns: (match_found, repl_ls, repl_le)
        The repl_ls/repl_le are the new line numbers in the target if a match is found.
        """
        # 1. Handle original permalink to get original content
        if not original.url_path or original.line_start is None:
            # No specific lines in original to verify.
            # If target is a URL, try to return its line numbers.
            if target_url:
                gh_info = parse_github_blob_permalink(target_url)
                parsed_ls, parsed_le = (gh_info[4], gh_info[5]) if gh_info else (None, None)
                return True, parsed_ls, parsed_le  # Vacuously true, return line numbers from target URL if present
            return True, None, None  # Vacuously true for git targets

        orig_lines = get_file_content_at_commit(original.commit_hash, original.url_path, repo_path=self.repo_root)
        if not orig_lines:
            return False, None, None  # Content not available

        try:
            orig_start_idx = original.line_start - 1
            orig_end_idx = (original.line_end or original.line_start) - 1
            if not (
                0 <= orig_start_idx < len(orig_lines)
                and 0 <= orig_end_idx < len(orig_lines)
                and orig_start_idx <= orig_end_idx
            ):
                return False, None, None  # Original line numbers out of bounds
            orig_content = [line.strip() for line in orig_lines[orig_start_idx : orig_end_idx + 1]]
            if not orig_content:
                return False, None, None
            num_orig_lines = len(orig_content)
        except IndexError:
            return False, None, None

        # 2. Get target lines (repl_lines)
        repl_lines: Optional[List[str]]
        repl_ls: Optional[int] = None
        if target_url:
            target_gh_info = parse_github_blob_permalink(target_url)
            if target_gh_info:  # It's a GitHub URL
                _, _, _, _, repl_ls, _ = target_gh_info
                if repl_ls is None:
                    return True, None, None  # No lines specified in URL fragment. User should know what they're doing
                repl_lines = fetch_raw_github_content_from_url(target_url)
            else:  # Not a GitHub URL or unparseable
                self._vprint(
                    f"⚠️ Verifying against non-GitHub or unparseable URL '{target_url}'. Assuming content matches."
                )
                return True, None, None  # Matches old behavior for non-GitHub URLs
        elif target_commit_hash and target_url_path:
            repl_lines = get_file_content_at_commit(target_commit_hash, target_url_path, repo_path=self.repo_root)
        else:
            raise ValueError("Either target_url or (target_commit_hash and target_url_path) must be provided.")

        if repl_lines is None:  # Fetch failed for GitHub URL or git target
            return False, None, None

        # 3. Determine effective tolerance
        eff_tolerance: int
        local_tolerance_is_percentage = self.global_prefs.tolerance_is_percentage
        local_tolerance_value = self.global_prefs.tolerance_value

        if custom_tolerance_str:
            try:
                local_tolerance_is_percentage, local_tolerance_value = parse_tolerance_input(custom_tolerance_str)
            except ValueError as e:
                self._vprint(f"  ⚠️ Invalid custom tolerance '{custom_tolerance_str}': {e}. Using global tolerance.")
                # Fallback to global if custom is invalid

        if local_tolerance_is_percentage:
            eff_tolerance = int(len(repl_lines) * (local_tolerance_value / 100.0))
        else:
            eff_tolerance = local_tolerance_value

        # 4. Perform matching logic with shifts
        try:
            sample_target_content: Optional[List[str]] = None  # To display content mismatches
            # Try all shifts from 0 outward, alternating `+shift` and `-shift`
            for offset in range(0, eff_tolerance + 1):
                for shift in (offset, -offset) if offset != 0 else (0,):
                    # Shift is relative to original's line numbers for git path, but relative to replacement lines for target_url
                    if target_url and repl_ls is not None:
                        shifted_repl_start_idx = repl_ls - 1 + shift
                    else:
                        shifted_repl_start_idx = orig_start_idx + shift
                    if 0 <= shifted_repl_start_idx < len(repl_lines) and (
                        shifted_repl_start_idx + num_orig_lines
                    ) <= len(repl_lines):
                        repl_content = [
                            line.strip()
                            for line in repl_lines[shifted_repl_start_idx : shifted_repl_start_idx + num_orig_lines]
                        ]
                        if shift == 0:
                            sample_target_content = repl_content
                        if orig_content == repl_content:
                            new_repl_ls = shifted_repl_start_idx + 1
                            new_repl_le = new_repl_ls + num_orig_lines - 1 if num_orig_lines > 1 else None
                            # Ensure line numbers are positive
                            if new_repl_ls <= 0 or (new_repl_le is not None and new_repl_le <= 0):
                                continue  # Invalid shift result
                            return True, new_repl_ls, new_repl_le
            self._display_content_mismatch(
                original,
                orig_content,
                target_url
                if target_url
                else f"{target_commit_hash[:8] if target_commit_hash else ''}:{target_url_path}",
                sample_target_content,
                eff_tolerance,
            )
            return False, None, None  # No match found after trying all shifts
        except IndexError:
            return False, None, None

    def _construct_repl_permalink(
        self,
        original: PermalinkInfo,
        repl_commit: str,
        repl_url_path: Optional[str],
        repl_ls: Optional[int] = None,
        repl_le: Optional[int] = None,
    ) -> str:
        """Creates a replacement permalink string."""
        match = re.search(r"github\.com/([^/]+)/([^/]+)/(blob|tree)/", original.url)
        # Use current repo's owner/repo if not extractable (should not happen for valid permalinks)
        git_owner = match.group(1) if match else self.git_owner
        git_repo = match.group(2) if match else self.git_repo
        url_type = match.group(3) if match else "blob"  # Default to blob if somehow not found

        base_url_parts = [f"https://github.com/{git_owner}/{git_repo}"]
        if url_type == "tree" or not repl_url_path:  # Tree link or blob link with no path (points to commit root)
            base_url_parts.extend(["tree", repl_commit])
            return "/".join(base_url_parts)

        base_url_parts.extend([url_type, repl_commit, repl_url_path.lstrip("/")])
        url_no_frag = "/".join(base_url_parts)
        # update_url_with_line_numbers handles adding #L fragments correctly
        return update_github_url_with_line_numbers(url_no_frag, repl_ls, repl_le)

    def _construct_url_from_current_state(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],
        state: ResolutionState,
    ) -> Optional[str]:
        """Constructs a URL string based on the current resolution state for the 'keep' option."""
        if state["current_is_external"] and state["current_external_url_base"]:
            return update_github_url_with_line_numbers(
                state["current_external_url_base"],
                state["current_ls"],
                state["current_le"],
            )
        if ancestor_commit:
            return self._construct_repl_permalink(
                original,
                ancestor_commit,
                state["current_url_path_for_ancestor"],
                state["current_ls"],
                state["current_le"],
            )
        return None

    def _evaluate_current_resolution_candidate(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],
        state: ResolutionState,
    ) -> Tuple[str, str, Optional[str]]:
        """
        Evaluates the current candidate for permalink replacement.
        Returns: (status_code, problem_description, proposed_final_url_or_none)
        Status codes: "resolved", "needs_external_url", "lines_mismatch_external",
                      "path_cleared", "path_missing_ancestor", "lines_mismatch_ancestor", "error"
        """
        current_external_url_base = state["current_external_url_base"]
        current_url_path_for_ancestor = state["current_url_path_for_ancestor"]

        if state["current_is_external"]:
            if not current_external_url_base:
                return (
                    "needs_external_url",
                    "No external URL specified. Provide one ('u') or choose another option.",
                    None,
                )
            if original.line_start is not None:
                verify_url = update_github_url_with_line_numbers(
                    current_external_url_base, state["current_ls"], state["current_le"]
                )
                self._vprint(f"Verifying external URL: {verify_url}")
                match, v_ls, v_le = self._verify_content_match(
                    original, target_url=verify_url, custom_tolerance_str=state["custom_tolerance_str"]
                )
                if match:
                    print(f"✅ Content matches for external URL.")
                    repl_url = update_github_url_with_line_numbers(current_external_url_base, v_ls, v_le)
                    return "resolved", "", repl_url
                current_tolerance_display = (
                    state["custom_tolerance_str"]
                    if state["custom_tolerance_str"] is not None
                    else self.global_prefs.line_shift_tolerance_str
                )
                return (
                    "lines_mismatch_external",
                    f"Line content differs or cannot be verified for external URL {current_external_url_base} (current tolerance: {current_tolerance_display}).",
                    None,
                )

            # External URL, original had no lines
            repl_url = update_github_url_with_line_numbers(
                current_external_url_base, state["current_ls"], state["current_le"]
            )
            print(f"✅ Using external URL (no line verification needed): {repl_url}")
            return "resolved", "", repl_url

        if ancestor_commit:
            if not current_url_path_for_ancestor and original.url_path:
                return (
                    "path_cleared",
                    "Path for ancestor was cleared. Specify a new path ('p') or clear lines ('c') if this is intended for commit root.",
                    None,
                )
            if not current_url_path_for_ancestor and not original.url_path:  # Tree link
                repl_url = self._construct_repl_permalink(original, ancestor_commit, None, None, None)
                print(f"✅ Using tree-style link for ancestor: {repl_url}")
                return "resolved", "", repl_url
            if current_url_path_for_ancestor and not file_exists_at_commit(
                ancestor_commit, current_url_path_for_ancestor, repo_path=self.repo_root
            ):
                return (
                    "path_missing_ancestor",
                    f"File '{current_url_path_for_ancestor}' does not exist in ancestor {ancestor_commit[:8]}.",
                    None,
                )
            if current_url_path_for_ancestor:  # Path exists
                if original.line_start is None:  # Original had no lines
                    repl_url = self._construct_repl_permalink(
                        original, ancestor_commit, current_url_path_for_ancestor, None, None
                    )
                    print(f"✅ Path exists in ancestor (no line verification needed): {repl_url}")
                    return "resolved", "", repl_url
                # Original had lines, verify them
                self._vprint(f"Verifying content in ancestor {ancestor_commit[:8]}:{current_url_path_for_ancestor}...")
                match, v_ls, v_le = self._verify_content_match(
                    original,
                    target_commit_hash=ancestor_commit,
                    target_url_path=current_url_path_for_ancestor,
                    custom_tolerance_str=state["custom_tolerance_str"],
                )
                if match:
                    repl_url = self._construct_repl_permalink(
                        original, ancestor_commit, current_url_path_for_ancestor, v_ls, v_le
                    )
                    orig_line_str = f"L{original.line_start}" + (
                        f"-L{original.line_end}"
                        if original.line_end and original.line_end != original.line_start
                        else ""
                    )
                    new_line_str = f"L{v_ls}" + (f"-L{v_le}" if v_le and v_le != v_ls else "")
                    if new_line_str == orig_line_str:
                        print(f"✅ Line content matches at {orig_line_str} in ancestor.")
                    else:
                        print(
                            f"✅ Line content matches, found at {new_line_str} in ancestor (original was {orig_line_str})."
                        )
                    self._vprint(f"  Match at URL: {repl_url}")
                    return "resolved", "", repl_url

                return (
                    "lines_mismatch_ancestor",
                    f"Line content differs in ancestor {ancestor_commit[:8]}:{current_url_path_for_ancestor} (current tolerance: {self.global_prefs.line_shift_tolerance_str}).",
                    None,
                )
        return "error", "Cannot determine replacement target. No ancestor and no external URL mode.", None

    def _resolution_menu_handle_set_url(
        self, ancestor_commit: Optional[str], state: ResolutionState
    ) -> Tuple[str, ResolutionState]:
        """Handles the 'u' menu choice for setting a new full URL."""
        new_url_input = input("    Enter new full URL: ").strip()
        if not new_url_input.lower().startswith("https://"):
            print("    Invalid URL. Must start with https://")
            return "invalid_choice_continue", state

        gh_info = parse_github_blob_permalink(new_url_input)
        new_url_ls, new_url_le = (gh_info[4], gh_info[5]) if gh_info else (None, None)

        if (
            ancestor_commit
            and gh_info
            and gh_info[0].lower() == self.git_owner.lower()
            and self._normalize_repo_name(gh_info[1]) == self.git_repo.lower()
            and gh_info[2] == ancestor_commit
        ):
            self._vprint(f"    Parsed as URL for current ancestor commit ({ancestor_commit[:8]}).")
            state["current_is_external"] = False
            state["current_external_url_base"] = None  # Clear to reduce confusion
            state["current_url_path_for_ancestor"] = gh_info[3]
            state["current_ls"], state["current_le"] = new_url_ls, new_url_le
            self._vprint(f"    Set path to '{state['current_url_path_for_ancestor']}' and lines from URL fragment.")
        else:
            confirm_ext = (
                input(
                    f"    The URL points outside current ancestor context or is not a GitHub file URL. Use it anyway? (y/n): "
                )
                .strip()
                .lower()
            )
            if confirm_ext == "y":
                state["current_is_external"] = True
                state["current_external_url_base"] = new_url_input.split("#")[0].split("?")[0]
                state["current_url_path_for_ancestor"] = None
                state["current_ls"], state["current_le"] = new_url_ls, new_url_le

                self._vprint(f"    Set to external URL: {state['current_external_url_base']}")
            else:
                self._vprint("    New URL not used.")
        return "state_updated_continue", state

    @staticmethod
    def _resolution_menu_handle_set_line_numbers(state: ResolutionState) -> Tuple[str, ResolutionState]:
        """Handles the 'l' menu choice for setting new line numbers."""
        new_lines_input = input("    Enter new line numbers (e.g., 10 or 10-15, or empty to clear): ").strip()
        if not new_lines_input:
            state["current_ls"], state["current_le"] = None, None
            print("    Line numbers cleared.")
        else:
            try:
                if "-" in new_lines_input:
                    ls_str, le_str = new_lines_input.split("-", 1)
                    nl_ls, nl_le = int(ls_str), int(le_str)
                    if nl_ls <= 0 or nl_le <= 0 or nl_le < nl_ls:
                        raise ValueError("Invalid range.")
                else:
                    nl_ls = int(new_lines_input)
                    if nl_ls <= 0:
                        raise ValueError("Line must be positive.")
                    nl_le = None
                state["current_ls"], state["current_le"] = nl_ls, nl_le
                print(
                    f"    Set line numbers to: L{state['current_ls']}"
                    + (f"-L{state['current_le']}" if state["current_le"] else "")
                )
            except ValueError as e:
                print(f"    Invalid line number format: {e}")
                return "invalid_choice_continue", state
        return "state_updated_continue", state

    def _process_resolution_menu_choice(
        self, menu_choice: str, original: PermalinkInfo, ancestor_commit: Optional[str], state: ResolutionState
    ) -> Tuple[str, ResolutionState]:
        """
        Interactively resolves a permalink replacement, handling missing paths and line mismatches.
        """

        if menu_choice == "o":
            urls_to_open_list = [("Original URL", original.url)]
            candidate_display_url = self._construct_url_from_current_state(original, ancestor_commit, state)
            if candidate_display_url:
                urls_to_open_list.append(("Candidate Replacement URL", candidate_display_url))
            open_urls_in_browser(urls_to_open_list)
            # No state change, just continue
        elif menu_choice == "p" and ancestor_commit:
            new_path_input = input("    Enter new file path (relative to repo root for ancestor): ").strip()
            if not new_path_input:
                print("    Path cannot be empty. Try again.")
            else:
                state["current_url_path_for_ancestor"] = new_path_input
                state["current_is_external"] = False
                state["current_ls"], state["current_le"] = original.line_start, original.line_end  # Reset lines
                print(
                    f"    Set path for ancestor to: '{state['current_url_path_for_ancestor']}'. Lines reset to original."
                )
        elif menu_choice == "l":
            return self._resolution_menu_handle_set_line_numbers(state)
        elif menu_choice == "u":
            return self._resolution_menu_handle_set_url(ancestor_commit, state)
        elif (
            menu_choice == "t"
            and ancestor_commit
            and state["current_url_path_for_ancestor"]
            and original.line_start is not None
        ):
            try:
                new_tolerance_input = input(
                    f"    Enter new line shift tolerance (e.g., 5 or 10%, 0 or 0% to disable): "
                ).strip()
                # Validate by parsing, but store the string
                _ = parse_tolerance_input(new_tolerance_input)  # Will raise ValueError if invalid
                state["custom_tolerance_str"] = new_tolerance_input
                print(f"    Tolerance for next check set to: {state['custom_tolerance_str']}")
            except ValueError as e:
                print(f"    Invalid tolerance format/value: {e}")
        elif menu_choice == "c":
            state["current_ls"], state["current_le"] = None, None
            print("    Line numbers cleared for current candidate.")
        elif menu_choice == "k":
            return "resolve_with_current", state
        elif menu_choice == "a":
            return "abort", state
        else:
            print("    Invalid choice. Try again.")
            return "invalid_choice_continue", state
        return "state_updated_continue", state

    def _resolve_replacement_interactively(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],
    ) -> Tuple[Optional[str], bool]:
        """
        Interactively resolves a permalink replacement, handling missing paths and line mismatches.
        Returns (repl_url, aborted)
        """

        def display_resolution_menu(
            current_problem: str,
            current_url_path_for_ancestor: Optional[str],
            original_has_lines: bool,
        ) -> None:
            """Displays the interactive resolution menu."""
            print(f"\n❓ PERMALINK RESOLUTION")
            if current_problem:
                print(f"  ⚠️ Current issue: {current_problem}")

            print("  OPTIONS:")
            print("  o) Open original and current candidate URLs in browser")
            print("  u) Set new full URL (override)")
            if current_url_path_for_ancestor:
                print("  p) Set new URL path (for ancestor commit) and check again")
                if original_has_lines:
                    print("  l) Set new line numbers (for current target) and check again")
                    print(
                        f"  t) Retry content check with different line shift tolerance (currently global: {self.global_prefs.line_shift_tolerance_str})"
                    )
                    print("  c) Clear line numbers from replacement and accept")
            print("  k) Keep candidate URL as is (proceed to Action Menu, URL may be broken)")
            print("  a) Abort replacement for this permalink (skip)")

        # Check cache first
        if original.url in self.resolved_repl_cache:
            cached_repl_url = self.resolved_repl_cache[original.url]
            self._vprint(f"  ✅ Found cached replacement for {original.url}: {cached_repl_url}")
            return cached_repl_url, False  # Not aborted

        state: ResolutionState = {
            "current_is_external": ancestor_commit is None,
            "current_external_url_base": None,
            "current_url_path_for_ancestor": original.url_path if ancestor_commit else None,
            "current_ls": original.line_start,
            "current_le": original.line_end,
            "custom_tolerance_str": None,
        }

        if state["current_is_external"]:
            self._vprint(
                f"  ℹ️ Original commit {original.commit_hash[:8]} has no suitable ancestor in {self.global_prefs.main_branch} or one was not provided."
            )
            self._vprint(f"     User will need to provide a full replacement URL or skip this permalink.")

        while True:  # Loop for interactive resolution
            resolution_status, problem_description, resolved_url = self._evaluate_current_resolution_candidate(
                original, ancestor_commit, state
            )
            state["custom_tolerance_str"] = None  # Reset after use

            if resolution_status == "resolved":
                # Success messages are printed by _evaluate_current_resolution_candidate
                return resolved_url, False

            display_resolution_menu(
                problem_description, state["current_url_path_for_ancestor"], original.line_start is not None
            )
            menu_choice = input("\nSelect resolution option: ").strip().lower()

            control_flow, new_state = self._process_resolution_menu_choice(
                menu_choice, original, ancestor_commit, state
            )
            state = new_state  # Update state

            if control_flow == "abort":
                print("    Aborting replacement for this permalink.")
                return None, True
            if control_flow == "resolve_with_current":
                repl_url_to_keep = self._construct_url_from_current_state(original, ancestor_commit, state)
                if repl_url_to_keep:
                    print(f"✅ Keeping replacement URL as is")
                    return repl_url_to_keep, False
                print("    ⚠️ Cannot keep settings, no valid target defined.")
                # Loop again, effectively forcing user to fix or abort
            # For "state_updated_continue", "open_urls_and_continue", "invalid_choice_continue", just loop.

    def _prompt_user_for_action(
        self,
        original: PermalinkInfo,
        repl_url: Optional[str],  # The fully formed candidate replacement URL
        is_commit_slated_for_tagging: bool,
        auto_action_directive_for_commit: Optional[str] = None,  # From 'rc' or 'sc'
    ) -> tuple[str, Optional[str]]:
        """
        Prompts the user for the action (replace, tag, skip) for a permalink and handles remembering
        choices.
        This is also where --auto-accept-replace and --auto-fallback flags take effect.
        Returns: (action_string, value_to_remember_if_any)
        """

        ### First, determine remembered action based on current context

        auto_chosen_action: Optional[str] = None

        # Priority 1: Commit-level auto directive (from 'rc' or 'sc' for this commit group)
        if repl_url and auto_action_directive_for_commit == "replace":
            auto_chosen_action = "replace"
            self._vprint(
                f"    🤖 Commit-level 'replace' directive: Auto-choosing 'replace' for '{original.url[-50:]}'."
            )
        elif not repl_url and auto_action_directive_for_commit == "skip":
            # `sc` (skip commit group) is a fallback choice.
            # It applies if no replacement URL is available for the current permalink.
            auto_chosen_action = "skip"
            self._vprint(
                f"    🤖 Commit-level 'skip' directive (fallback): Auto-choosing 'skip' for '{original.url[-50:]}'."
            )

        # Priority 2: Global auto flags (--auto-accept-replace, --auto-fallback)
        # Only if not already decided by commit-level directive
        if not auto_chosen_action:
            if repl_url:  # Replacement is possible
                if self.session_prefs.auto_accept_replace:
                    auto_chosen_action = "replace"
                    self._vprint(f"    🤖 --auto-accept-replace: Auto-choosing 'replace' for '{original.url[-50:]}'.")
            else:  # Fallback: No viable replacement URL
                if self.session_prefs.auto_fallback == "tag":
                    auto_chosen_action = "tag"
                    self._vprint(f"    🤖 --auto-fallback=tag: Auto-choosing 'tag' for '{original.url[-50:]}'.")
                elif self.session_prefs.auto_fallback == "skip":
                    auto_chosen_action = "skip"
                    self._vprint(f"    🤖 --auto-fallback=skip: Auto-choosing 'skip' for '{original.url[-50:]}'.")

        # Priority 3: Remembered choices ('ra', 'ta', 'sa'), scoped to two types of prompt menus
        # (with or without repl_url)
        # Only if not already decided by commit-level or global auto flags
        if not auto_chosen_action:
            if repl_url:  # Replacement is possible
                if self.session_prefs.remembered_action_with_repl == "replace":
                    auto_chosen_action = "replace"
                    self._vprint(
                        f"    🤖 Remembered 'replace' (global): Auto-choosing 'replace' for '{original.url[-50:]}'."
                    )
            else:  # Fallback
                if self.session_prefs.remembered_action_without_repl == "tag":
                    auto_chosen_action = "tag"
                    self._vprint(
                        f"    🤖 Remembered 'tag' (global fallback): Auto-choosing 'tag' for '{original.url[-50:]}'."
                    )
                elif self.session_prefs.remembered_action_without_repl == "skip":
                    auto_chosen_action = "skip"
                    self._vprint(
                        f"    🤖 Remembered 'skip' (global fallback): Auto-choosing 'skip' for '{original.url[-50:]}'."
                    )

        if auto_chosen_action:
            return auto_chosen_action, None  # Auto actions don't set "remember_this_choice" for future global use

        ### Then, If no auto-action was taken, proceed to display the interactive prompt

        print("\n❓ ACTIONS:")
        print(f"  o) Open {'original & replacement URLs' if repl_url else 'original URL'} in browser")

        # Replacement is offered if a repl_url has been successfully verified of manually provided
        if repl_url:
            print("  r) Replace with suggested URL (i.e., update reference)")
            print("    rc) Auto-accept 'Replace' for rest of Commit group")
            print("    ra) Auto-accept 'Replace' for All commits from now on")

        if is_commit_slated_for_tagging:
            print("  -t) UNTAG this commit")
        else:
            print("  t) Tag commit (i.e., preserve exact permalink)")
            print("    ta) Automatically fall back to tagging for All commits from now on")

        print("  s) Skip this permalink")
        print("    sc) Automatically fall back to skipping for rest of Commit group")
        print("    sa) Automatically fall back to skipping for All commits from now on")

        while True:
            action: Optional[str] = None
            remember_this_choice: Optional[str] = None

            prompt_options_list = ["o"]
            if repl_url:
                prompt_options_list.extend(["r", "rc", "ra"])
            prompt_options_list.append("-t" if is_commit_slated_for_tagging else "t")
            prompt_options_list.append("ta")  # Always offer tag all, context handled by remember key
            prompt_options_list.extend(["s", "sc", "sa"])
            menu_choice = input(f"\nSelect action ({','.join(prompt_options_list)}): ").strip().lower()

            if menu_choice == "o":
                urls_to_open_list = [("original URL", original.url)]
                if repl_url:
                    urls_to_open_list.append(("suggested replacement URL", repl_url))
                open_urls_in_browser(urls_to_open_list)
                continue
            if menu_choice == "r" and repl_url:
                action = "replace"
            elif menu_choice == "rc" and repl_url:
                action = "replace_commit_group"
            elif menu_choice == "ra" and repl_url:
                action, remember_this_choice = "replace", "replace"
            elif menu_choice == "t" and not is_commit_slated_for_tagging:
                action = "tag"
            elif menu_choice == "ta" and not is_commit_slated_for_tagging:
                action, remember_this_choice = "tag", "tag"
            elif menu_choice == "-t" and is_commit_slated_for_tagging:
                action = "untag"  # Special action to indicate untagging
                # No "remember this choice" for untagging individual commits
                # against a global remembered "tag"
            elif menu_choice == "s":
                action = "skip"
            elif menu_choice == "sc":
                action = "skip_commit_group"
            elif menu_choice == "sa":
                action, remember_this_choice = "skip", "skip"

            if action:
                return action, remember_this_choice
            print("    Invalid choice. Please try again.")

    def _process_permalink(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],  # For context, even if user provides external URL
        index: int,
        total: int,
        is_commit_slated_for_tagging: bool,
        auto_action_directive_for_commit: Optional[str] = None,  # "replace" or "skip"
    ) -> Tuple[str, Optional[str]]:  # Returns (action_str, final_repl_url_if_action_is_replace)
        """
        Process a permalink (for a given file, for a given commit), including verifying content match,
        prompting for replacement, and handling user actions.

        Returns a tuple: (action, repl_url, trigger_rc_bool).
        repl_url is only set if `action` is "replace".
        """
        index_msg = f"Permalink #{index + 1}/{total} for {original.commit_hash[:8]}"
        print(f"\n    [*] {index_msg} {'- ' * ((75 - len(index_msg)) // 2)}")
        print("      🚧 PERMALINK PROTECTION NEEDED")
        print()
        print(f"📄 Found in: {original.found_in_file.relative_to(self.repo_root)}:{original.found_at_line}")  # type: ignore
        print(f"🔗 Original URL: {original.url}")
        self._vprint(f"⛓️‍💥 Original commit: {original.commit_hash[:8]} (not in {self.global_prefs.main_branch})")
        if is_commit_slated_for_tagging:
            print(f"🏷️ Commit {original.commit_hash[:8]} is currently slated to be TAGGED.")
        print()

        repl_url: Optional[str] = None  # A fully formed URL if user provides one

        # --- Stage 1: Resolve File Path/URL for Replacement ---
        if ancestor_commit:  # Only offer path/URL resolution if an ancestor context exists
            if ancestor_info := get_commit_info(ancestor_commit, repo_path=self.repo_root):
                self._vprint(f"⏪ Suggested ancestor commit: {ancestor_commit[:8]} - {ancestor_info['subject']}")
                self._vprint(f"   👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")

            if original.url_path:  # Only if the original permalink pointed to a file
                repl_url, aborted_resolution = self._resolve_replacement_interactively(original, ancestor_commit)
                if aborted_resolution:
                    return "skip", None
                # repl_url is now the fully resolved URL or None
            else:  # E.g., tree link, direct replacement with ancestor
                repl_url = self._construct_repl_permalink(original, ancestor_commit, None, None, None)

        else:  # No ancestor, resolution relies on user providing a full URL
            self._vprint("No ancestor commit. User must provide a full URL or skip/tag.")
            repl_url, aborted_resolution = self._resolve_replacement_interactively(
                original,
                None,  # No ancestor context
            )
            if aborted_resolution:
                return "skip", None

        if repl_url:
            print(f"✨ Suggested replacement URL: {repl_url}")
        else:  # No ancestor, and user didn't provide a URL
            print("  ℹ️ No common ancestor found and no alternative URL provided by user.")

        # --- Stage 2: Action Prompt ---
        action, remember_this_choice = self._prompt_user_for_action(
            original,
            repl_url,
            is_commit_slated_for_tagging,
            auto_action_directive_for_commit=auto_action_directive_for_commit,
        )

        if remember_this_choice:
            current_remember_key = "with_repl" if repl_url else "without_repl"
            if current_remember_key == "with_repl":
                self.session_prefs.remembered_action_with_repl = remember_this_choice
            else:
                self.session_prefs.remembered_action_without_repl = remember_this_choice

        if action in ["replace", "replace_commit_group"]:
            if repl_url:
                # Cache the successful resolution
                self.resolved_repl_cache[original.url] = repl_url
                return action, repl_url
            self._vprint(
                f"  ⚠️ Warning: Action '{action}' chosen but no replacement URL available for {original.url}. Falling back to skip."
            )
            action = "skip"
        return action, None

    def _process_commit_with_details(
        self,
        commit_hash: str,
        commit_permalinks: List[PermalinkInfo],
        commit_info: Dict[str, str],
        ancestor_commit: Optional[str],
    ) -> Tuple[Optional[Tuple[str, Dict[str, str]]], List[Tuple[PermalinkInfo, str]]]:
        """
        Handles interactive prompting for each permalink within a commit group.
        Returns an optional tag to create and a list of replacements to make.
        """
        pending_repls: List[Tuple[PermalinkInfo, str]] = []
        pending_tag: Optional[Tuple[str, Dict[str, str]]] = None
        auto_action_directive_for_rest_in_commit: Optional[str] = None  # "replace" or "skip"

        ### First, determine if commit is slated for tagging based on remembered choices

        commit_is_currently_slated_for_tagging = False
        if (ancestor_commit and self.session_prefs.remembered_action_with_repl == "tag") or (
            not ancestor_commit and self.session_prefs.remembered_action_without_repl == "tag"
        ):
            commit_is_currently_slated_for_tagging = True
            pending_tag = (commit_hash, commit_info)
            self._vprint(f"  ℹ️ Commit {commit_hash[:8]} is initially slated for tagging due to remembered choice.")

        ### Then iterate through all the files referencing this commit

        self._vprint(
            f"\n  🚧 Interactively processing {len(commit_permalinks)} permalink(s) for commit {commit_hash[:8]}:"
        )
        permalinks_by_file: Dict[Path, List[PermalinkInfo]] = {}
        for p in commit_permalinks:
            permalinks_by_file.setdefault(p.found_in_file, []).append(p)
        sorted_file_paths = sorted(permalinks_by_file.keys())

        stop_processing_permalinks_for_this_commit_entirely = False

        # Loop through each file in sorted order
        commit_wide_repl_idx = 0
        for file_group_idx, file_path in enumerate(sorted_file_paths):
            permalinks_in_this_file = permalinks_by_file[file_path]
            permalinks_in_this_file.sort(key=lambda p_info: p_info.found_at_line)

            print(
                f"\n  [*] File #{file_group_idx + 1}/{len(sorted_file_paths)}: {file_path.relative_to(self.repo_root)} "  # type: ignore
                f"({len(permalinks_in_this_file)} permalink(s) for this commit)"
            )

            permalink_for_this_file_idx = 0
            while permalink_for_this_file_idx < len(permalinks_in_this_file):
                permalink = permalinks_in_this_file[permalink_for_this_file_idx]

                action, repl_url = self._process_permalink(
                    permalink,
                    ancestor_commit,
                    index=commit_wide_repl_idx,
                    total=len(commit_permalinks),
                    is_commit_slated_for_tagging=commit_is_currently_slated_for_tagging,
                    auto_action_directive_for_commit=auto_action_directive_for_rest_in_commit,
                )

                if action == "untag":
                    if commit_is_currently_slated_for_tagging:
                        commit_is_currently_slated_for_tagging = False
                        pending_tag = None
                        self._vprint(
                            f"  ℹ️ Commit {commit_hash[:8]} is no longer slated for tagging. Re-evaluating current permalink."
                        )
                    # Do not increment permalink_idx or commit_wide_repl_idx; re-process current permalink
                    continue  # Restart the while loop for the current permalink_idx

                # Check if the current action implies a real action plus a remembered choice
                if action == "replace_commit_group":
                    auto_action_directive_for_rest_in_commit = (action := "replace")
                    self._vprint(
                        f"    🤖 User chose 'replace commit'. Will auto-accept replace for rest of commit {commit_hash[:8]}."
                    )
                    if not repl_url:  # Should not happen
                        self._vprint(
                            f"  🐛 Action was 'replace_commit_group' but no replacement URL was provided for '{permalink.url[-50:]}'. Skipping…"
                        )
                        action = "skip"  # Fallback to skip if URL is missing

                elif action == "skip_commit_group":
                    auto_action_directive_for_rest_in_commit = (action := "skip")
                    self._vprint(
                        f"    🤖 User chose 'skip commit'. Will auto-fallback to skip for rest of commit {commit_hash[:8]}."
                    )

                # Now that we know what the real action is
                if action == "tag":
                    if not commit_is_currently_slated_for_tagging:  # User chose 't' or 'ta' when not slated
                        commit_is_currently_slated_for_tagging = True
                        pending_tag = (commit_hash, commit_info)  # Mark for tagging
                        self._vprint(
                            f"  ℹ️ Commit {commit_hash[:8]} is now slated to be tagged based on choice for '{permalink.url[-50:]}'…"
                        )

                        if pending_repls:  # If prior replacements exist for this commit
                            print(
                                "\n⚠️ Commit is now slated for tagging, but you previously chose to REPLACE some permalink(s) for this commit."
                            )
                            print("   1) Tag commit & DISCARD all previous REPLACEMENT choices for this commit.")
                            print(
                                "   2) Tag commit & KEEP previous REPLACEMENTS. Stop offering to replace other permalinks for this commit."
                            )
                            print(
                                "   3) Tag commit & KEEP previous REPLACEMENTS. Continue to be prompted for other permalinks for this commit."
                            )
                            while True:
                                sub_choice = input("      Select how to handle existing replacements (1,2,3): ").strip()
                                if sub_choice == "1":
                                    pending_repls.clear()
                                    print("  🗑️ Previous replacement choices for this commit have been discarded.")
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                if sub_choice == "2":
                                    print("  🛑 Previous replacements kept. No more prompts for this commit.")
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                if sub_choice == "3":
                                    print("  🟢 Previous replacements kept. Will continue prompting for this commit.")
                                    # commit_is_currently_slated_for_tagging remains True
                                    break
                                print("      Invalid choice. Please select 1, 2, or 3.")
                        else:  # No prior replacements, just tagging
                            print(
                                f"  ℹ️ Commit {commit_hash[:8]} will be tagged. Other permalinks for this commit will reflect this."
                            )
                            # If the user chose "ta" (tag all), _prompt_user_for_final_action would
                            # have set remembered_action.
                            # If they just chose "t", we don't automatically stop unless they pick
                            # "ta" or sub_choice 2.
                            # If 'ta' was chosen, self.remembered_action_* would be 'tag'.
                            # If 't' was chosen, and no sub-prompt, we continue.

                    # If commit was already slated and user chose 't' (which shouldn't be an option
                    # if the UI is correct, as it would be '-t'), this path is defensive.

                elif action == "replace":
                    if repl_url:
                        pending_repls.append((permalink, repl_url))
                    else:  # Should not happen if action is "replace"
                        self._vprint(
                            f"  🐛 Action was 'replace' but no replacement URL was provided for permalink '{permalink.url[-50:]}'. Skipping…"
                        )

                elif action == "skip":
                    print(f"  ⏩ Skipping permalink '{permalink.url[-50:]}'…")

                permalink_for_this_file_idx += 1
                commit_wide_repl_idx += 1

                if stop_processing_permalinks_for_this_commit_entirely:
                    break  # Break from inner while loop (permalinks in this file)
            if stop_processing_permalinks_for_this_commit_entirely:
                break  # Break from outer for loop (files for this commit)

        return pending_tag, pending_repls

    def _prompt_user_about_fetching_this_commit(self, commit_hash: str) -> bool:
        """
        Prompts the user whether to fetch a missing commit.
        Updates self.session_prefs.fetch_mode if user chooses 'ya' or 'na'.
        Returns True if the user wants to fetch this specific commit ('y' or 'ya').
        """
        while True:
            print(f"\n❓ Look for {commit_hash} at the remote?")
            print("  y) Yes, fetch this commit from 'origin'")
            print("    ya) Yes to all - fetch this and all subsequent missing commits (sets fetch-mode to 'always')")
            print("  n) No, do not fetch this commit")
            print(
                "    na) No to all - skip fetching for this and all subsequent missing commits (sets fetch-mode to 'never')"
            )
            choice = input("     Choose an action (y/n/ya/na): ").strip().lower()

            if choice == "y":
                return True
            if choice == "n":
                return False
            if choice == "ya":
                self.session_prefs.fetch_mode = FetchMode.ALWAYS_FETCH
                print("    ℹ️ Fetch mode set to 'always' for subsequent missing commits.")
                return True
            if choice == "na":
                self.session_prefs.fetch_mode = FetchMode.NEVER_FETCH
                print("    ℹ️ Fetch mode set to 'never' for subsequent missing commits.")
                return False
            print("   Invalid choice. Please try again.")

    def _check_commit_is_available_locally(self, commit_hash: str) -> bool:
        """
        Checks if a commit is available locally in the repository and fetches it if necessary
        and allowed by the fetch mode preference.

        Return whether commit is available locally after checks and potential fetch.
        """
        if not (commit_available := is_commit_available_locally(commit_hash, repo_path=self.repo_root)):
            print(f"  ❗ Commit {commit_hash} does not exist in this repository")
            should_attempt_fetch_this_commit = False

            if self.session_prefs.fetch_mode == FetchMode.ALWAYS_FETCH:
                self._vprint(f"  🤖 Auto-fetching commit {commit_hash} as per fetch-mode=always.")
                should_attempt_fetch_this_commit = True
            elif self.session_prefs.fetch_mode == FetchMode.PROMPT:
                should_attempt_fetch_this_commit = self._prompt_user_about_fetching_this_commit(commit_hash)
            # If FetchMode.NEVER_FETCH, should_attempt_fetch_this_commit remains False

            if should_attempt_fetch_this_commit:
                if fetch_commit_missing_locally(commit_hash, self._vprint, repo_path=self.repo_root):
                    if not (commit_available := is_commit_available_locally(commit_hash, repo_path=self.repo_root)):
                        print(f"  ❌ Fetch for {commit_hash} seemed to succeed, but commit still not found.")
                else:
                    # Fetch failed, commit still not available
                    print(f"  ❌ Fetch attempt for {commit_hash} failed or commit still not found.")
            else:  # Not attempting fetch
                self._vprint(f"  ⏩ Skipping fetch for commit {commit_hash} (fetch-mode is 'never' or user declined).")

        return commit_available

    def _process_commit(
        self, commit_hash: str, commit_permalinks: List[PermalinkInfo], index: int, total: int
    ) -> Tuple[Optional[Tuple[str, Dict[str, str]]], List[Tuple[PermalinkInfo, str]]]:
        """
        Processes a single commit hash and all its associated permalinks for the Examination phase.
        Determines if auto-actions apply or if interactive prompting is needed.

        Returns (commit_hash, commit_info) tuple for tagging (or None) and
        (permalink_info, repl_url) tuples for replacements for this commit.
        """

        print(f"\n{'-' * 80}")
        index_msg = f"Commit #{index + 1}/{total}: {commit_hash[:8]} ({len(commit_permalinks)} permalink(s))"
        print(f"\n[*] {index_msg} {'- ' * ((75 - len(index_msg)) // 2)}")

        if not self._check_commit_is_available_locally(commit_hash):
            print(f"  ❌ Commit {commit_hash} is not available. Skipping processing for this commit.")
            return None, []  # Skip if commit unavailable

        if not (commit_info := get_commit_info(commit_hash, repo_path=self.repo_root)):
            print(f"  ❌ Could not get info for commit {commit_hash}")
            return None, []

        self._vprint(f"  📝 {commit_info['subject']}")
        self._vprint(f"    👤 Author: {commit_info['author']} ({commit_info['date']})")
        self._vprint(f"  🔗 Referenced in {len(commit_permalinks)} permalink(s)")

        # Check if the commit is already in the main branch
        if is_commit_in_main(commit_hash, self.global_prefs.main_branch, repo_path=self.repo_root):
            print(f"  ✅ Already merged into {self.global_prefs.main_branch}. Permalinks to this commit are safe.")
            return None, []

        print(f"  ⛓️‍💥️ Not in {self.global_prefs.main_branch}")
        if ancestor_commit := find_closest_ancestor_in_main(
            commit_hash, self.global_prefs.main_branch, repo_path=self.repo_root
        ):
            ancestor_info = get_commit_info(ancestor_commit, repo_path=self.repo_root)
            print(
                f"  ⏪ Closest ancestor in main: {ancestor_commit[:8]} - {ancestor_info['subject'] if ancestor_info else 'Unknown'}"
            )
            if ancestor_info:
                self._vprint(f"    👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")
        else:
            print(f"  ❌ No common ancestor with {self.global_prefs.main_branch} found for {commit_hash[:8]}.")

        return self._process_commit_with_details(commit_hash, commit_permalinks, commit_info, ancestor_commit)

    def _execute_replacement(self, permalink: PermalinkInfo, repl_url: str) -> None:
        """Replaces the permalink in the file."""
        try:
            file_path = permalink.found_in_file
            if not file_path.exists():
                print(f"  ❌ File {file_path} no longer exists. Cannot replace permalink.")
                return

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.readlines()

            if permalink.found_at_line > len(content) or permalink.found_at_line < 1:
                print(f"  ❌ Line number {permalink.found_at_line} out of range in {file_path}. Cannot replace.")
                return

            original_line = content[permalink.found_at_line - 1]
            if permalink.url not in original_line:
                print(f"  ⚠️ Original URL not found in line {permalink.found_at_line} of {file_path}. Cannot replace.")
                return

            content[permalink.found_at_line - 1] = original_line.replace(permalink.url, repl_url, 1)

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(content)

            print(
                f"  ✅ Replaced permalink in {file_path.relative_to(self.repo_root)} at line {permalink.found_at_line}"
            )
        except (IOError, OSError, UnicodeDecodeError, PermissionError) as e:
            print(f"  ❌ Failed to replace permalink in {permalink.found_in_file.relative_to(self.repo_root)}: {e}")

    def _push_created_tags(self, operation_set: OperationSet) -> None:
        """
        Pushes the given list of created tags to the remote 'origin'.
        This method respects self.dry_run.
        """
        tags_successfully_created_locally = [
            entry["tag_name"]
            for entry in operation_set.report_data.get("tags_created", [])
            if entry.get("status") == "created"
        ]
        tags_that_would_be_created_in_dry_run = [
            entry["tag_name"]
            for entry in operation_set.report_data.get("tags_created", [])
            if entry.get("status") == "would_create"
        ]

        if not tags_successfully_created_locally and not (
            self.global_prefs.dry_run and tags_that_would_be_created_in_dry_run
        ):
            self._vprint("  ℹ️ No new tags were actually created locally or would be created in dry run.")
            return

        if self.global_prefs.dry_run:
            if tags_that_would_be_created_in_dry_run:
                self._vprint(
                    f"  🧪 DRY RUN: Would attempt to push {len(tags_that_would_be_created_in_dry_run)} tags if not in dry run: {', '.join(tags_that_would_be_created_in_dry_run)}"
                )
            else:
                self._vprint("  🧪 DRY RUN: No tags were simulated for creation (all existed or failed simulation).")
            return

        if tags_successfully_created_locally:
            print(f"\n🚀 Pushing {len(tags_successfully_created_locally)} created tags to origin…")
            try:
                push_command = ["git", "push", "origin"] + tags_successfully_created_locally
                subprocess.run(
                    push_command,
                    cwd=self.repo_root,  # Ensure push happens in the correct repo
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=60,
                )
                print("  ✅ Tags pushed successfully.")
            except subprocess.CalledProcessError as e:
                stderr_output = e.stderr.strip() if e.stderr else "N/A"
                print(
                    f"  ❌ Failed to push tags. Command '{subprocess.list2cmdline(e.cmd)}' (rc={e.returncode}). Stderr: '{stderr_output}'",
                    file=sys.stderr,
                )
                print(
                    "  🎗️ You may need to push them manually: git push origin --tags"
                )  # Suggest pushing all tags as a fallback
            except subprocess.TimeoutExpired as e:
                print(f"  ❌ Error: Timeout during tag push operation: {e}", file=sys.stderr)
                print("  🎗️ You may need to push them manually: git push origin --tags")
        else:
            self._vprint("  ℹ️ No new tags were actually created to push.")

    def _execute_tag_creation(self, commits_to_tag: List[TagCreationOperation], operation_set: OperationSet) -> None:
        """
        Processes commits that need tagging, creates tags locally, or simulates in dry_run.
        And ends by calling the function to push the tags to the remote 'origin'.
        """
        # commits_to_tag is now List[TagCreationOperation]
        print(f"\n📌 Processing {len(set(c.commit_hash for c in commits_to_tag))} unique commit(s) for tagging")

        # Deduplicate commits_to_tag by commit_hash, keeping the first encountered commit_info
        final_commits_to_tag_ops: List[TagCreationOperation] = []
        seen_hashes = set()
        for op in reversed(commits_to_tag):  # Keep first encountered if multiple for same hash
            if op.commit_hash not in seen_hashes:
                final_commits_to_tag_ops.append(op)
                seen_hashes.add(op.commit_hash)
        final_commits_to_tag_ops.reverse()  # Process in original order

        for op in final_commits_to_tag_ops:
            commit_hash = op.commit_hash
            commit_info = op.commit_info

            tag_name = gen_git_tag_name(commit_hash, commit_info.get("subject", ""), self.global_prefs.tag_prefix)
            tag_message = f"Preserve permalink reference to: {commit_info.get('subject', 'commit ' + commit_hash[:8])}"
            report_entry_for_this_tag = {
                "commit_hash": commit_hash,
                "commit_subject": commit_info.get("subject", "N/A"),
                "tag_name": tag_name,
                "tag_message": tag_message,
            }

            if git_tag_exists(tag_name, repo_path=self.repo_root):
                print(f"  ✅ Tag {tag_name} already exists for commit {commit_hash[:8]}")
                report_entry_for_this_tag["status"] = "already_exists"
                operation_set.report_data["tags_created"].append(report_entry_for_this_tag)
                continue

            if create_git_tag(tag_name, commit_hash, tag_message, self.global_prefs.dry_run, repo_path=self.repo_root):
                # Message already printed by execute_git_tag_creation
                report_entry_for_this_tag["status"] = "created"
                if self.global_prefs.dry_run:
                    report_entry_for_this_tag["status"] = "would_create"
            else:
                # Error message already printed by execute_git_tag_creation
                report_entry_for_this_tag["status"] = "failed_to_create"

            operation_set.report_data["tags_created"].append(report_entry_for_this_tag)

        # Now push any successfully created tags (or report for dry run)
        self._push_created_tags(operation_set)

    def _examine_phase(self, examination_set: ExaminationSet) -> OperationSet:
        operation_set = OperationSet()

        # This is the main loop for examination.
        # Process each commit and its permalinks, handling auto-replace, auto-tag, or interactive prompts.
        # Actual file modifications and tagging are done later.
        commit_items = examination_set.get_commit_examination_items()
        for index, (commit_hash, commit_permalinks) in enumerate(commit_items):
            tag_to_create, replacements = self._process_commit(commit_hash, commit_permalinks, index, len(commit_items))
            if tag_to_create:
                # tag_info_for_commit is (commit_hash, commit_info_dict)
                operation_set.tags_to_create.append(
                    TagCreationOperation(commit_hash=tag_to_create[0], commit_info=tag_to_create[1])
                )
            for permalink_info, repl_url in replacements:
                operation_set.replacements.append(
                    PermalinkReplacementOperation(permalink_info=permalink_info, repl_url=repl_url)
                )
        return operation_set

    def _execute_phase(self, operation_set: OperationSet):
        print(f"\n{'=' * 80}")

        # Find all permalink commits
        # Populate report data for replacements
        if self.global_prefs.output_json_report_path and operation_set.replacements:
            for op_repl in operation_set.replacements:
                operation_set.report_data["replacements"].append(
                    {
                        "original_url": op_repl.permalink_info.url,
                        "new_url": op_repl.repl_url,
                        "found_in_file": str(op_repl.permalink_info.found_in_file.relative_to(self.repo_root)),  # type: ignore
                        "found_at_line": op_repl.permalink_info.found_at_line,
                    }
                )

        # Perform actual file modifications for replacements
        if operation_set.replacements:
            # Use the helper method to count unique files involved in replacements
            repls_by_file: Dict[Path, List[PermalinkReplacementOperation]] = {}
            for op_repl in operation_set.replacements:
                repls_by_file.setdefault(op_repl.permalink_info.found_in_file, []).append(op_repl)

            sorted_file_paths_for_replacement = sorted(repls_by_file.keys())

            if self.global_prefs.dry_run:
                print(
                    f"\n🧪 DRY RUN SUMMARY: Would execute {len(operation_set.replacements)} replacement(s) in {len(sorted_file_paths_for_replacement)} unique file(s):\n"
                )
            else:
                print(
                    f"\n🏃 Executing {len(operation_set.replacements)} permalink replacement(s) in {len(sorted_file_paths_for_replacement)} file(s)…"
                )

            global_repl_idx = 0
            for group_idx, file_path_for_repl in enumerate(sorted_file_paths_for_replacement):
                repls_for_file = repls_by_file[file_path_for_repl]
                repls_for_file.sort(key=lambda item: item.permalink_info.found_at_line)

                print(
                    f"\n#{group_idx + 1}/{len(sorted_file_paths_for_replacement)} files: {file_path_for_repl.relative_to(self.repo_root)} ({len(repls_for_file)} replacement(s))"  # type: ignore
                )

                for op_repl in repls_for_file:
                    global_repl_idx += 1
                    print(f"  {global_repl_idx:3d}. Line {op_repl.permalink_info.found_at_line}:")
                    print(f"    🔗 OLD: {op_repl.permalink_info.url}")
                    print(f"    ✨ NEW: {op_repl.repl_url}")

                    if not self.global_prefs.dry_run:
                        self._execute_replacement(op_repl.permalink_info, op_repl.repl_url)

        else:  # No replacements to make
            if self.global_prefs.dry_run:
                print("\n🧪 DRY RUN: No permalink replacements to make.")
            else:
                print("\nℹ️ No permalink replacements were made.")

        # Process and create tags for all commits that need tagging
        if operation_set.tags_to_create:
            self._execute_tag_creation(operation_set.tags_to_create, operation_set)
        elif self.global_prefs.dry_run:  # No tags to create, but it's a dry run
            print("\n🧪 DRY RUN: No commits identified for tagging.")
        else:  # No tags to create, not a dry run
            print("\nℹ️ No commits were identified for tagging.")

        operation_set.write_json_report(self.global_prefs.output_json_report_path)
        print("\n🏁 Permalink checking complete.")

    def run(self) -> None:
        """Main execution function."""
        self._print_initial_summary()

        examination_set = self._discover_phase()
        if not examination_set.commits_to_examine:
            print("No GitHub permalinks at this path.")
            if self.global_prefs.output_json_report_path:
                OperationSet().write_json_report(self.global_prefs.output_json_report_path)
            return

        num_permalinks = sum(len(c.permalinks) for c in examination_set.commits_to_examine.values())
        num_unique_files = len(
            set(p.found_in_file for c in examination_set.commits_to_examine.values() for p in c.permalinks)
        )
        self._vprint(
            f"\nFound {num_permalinks} GitHub permalinks in {num_unique_files} unique file(s) referencing {len(examination_set.commits_to_examine)} unique commit(s)"
        )

        operation_set = self._examine_phase(examination_set)
        self._execute_phase(operation_set)
