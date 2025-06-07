#!/usr/bin/env python3
"""
GitHub Permalink Fixer
======================

Makes sure permalinks stay permanent.
The goal is to avoid git's garbage collection from nuking commits that it thinks
are no longer referenced.

Finds GitHub commit permalinks in a repository, checks if commits are merged
into `main` and, for unmerged commits, tries to find the closest ancestor in
`main` (and checks that any line references still make sense).
For unmerged commits, it prompts the user to replace its permalinks to new ones
pointing to the ancestor; it also provides a fallback of tagging the commit
to protect it.


Usage
-----

python3 git_permalink_fixer.py [OPTIONS]

Help: to see all flags, run with `-h`


Supported
---------

Supports the following cloud git repos:

- GitHub with links of the form:
    - `https://github.com/org/project/blob/commit_hash/url_path#Lline_start-Lline_end`
    - `https://github.com/org/project/tree/commit_hash`

Requires
--------
Python v3.9+

History
-------

- 2025-06-01 Authored by AI with huyz's strict guidance, supervision, and editing.
"""

import argparse
import re
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from .text_utils import parse_tolerance_input

from .file_ops import (
    extract_permalinks_from_file,
    should_skip_file_search,
    parse_github_blob_permalink,
)
from .git_utils import (
    get_repo_root,
    get_remote_url,
    is_commit_in_main,
    get_commit_info,
    find_closest_ancestor_in_main,
    file_exists_at_commit,
    get_file_content_at_commit,
    gen_git_tag_name,
    git_tag_exists,
    create_git_tag,
    fetch_commit_if_missing,
    get_github_info_from_url,
    update_url_with_line_numbers,
)
from .permalink_info import PermalinkInfo
from .web_utils import (
    open_urls_in_browser,
    fetch_raw_github_content_from_url,
)


class GitPermalinkChecker:
    repo_root: Path

    def __init__(
        self,
        verbose: bool = False,
        dry_run: bool = False,
        respect_gitignore: bool = True,
        repo_aliases: Optional[List[str]] = None,
        main_branch: str = "main",
        tag_prefix: str = "permalinks/ref",
        auto_fetch_commits: bool = False,
        auto_accept_replace: bool = False,
        auto_fallback: Optional[str] = None, # "tag" or "skip"
        line_shift_tolerance: str = "20",
        output_json_report: Optional[str] = None,
    ):
        self.verbose = verbose
        self.dry_run = dry_run
        self.main_branch = main_branch
        self.respect_gitignore = respect_gitignore
        self.repo_aliases = [alias.lower() for alias in repo_aliases] if repo_aliases else []
        self.tag_prefix = tag_prefix
        self.auto_fetch_commits = auto_fetch_commits # User's choice via flag
        self.auto_accept_replace = auto_accept_replace
        self.auto_fallback = auto_fallback # "tag", "skip", or None
        self.output_json_report_path = Path(output_json_report) if output_json_report else None
        self.report_data: Dict[str, List] = {"replacements": [], "tags_created": []}

        self.line_shift_tolerance_str = line_shift_tolerance  # Store original for display/prompts
        self.tolerance_is_percentage, self.tolerance_value = parse_tolerance_input(
            line_shift_tolerance
        )

        # Initialize repo and GitHub info first, as _load_ignored_paths might need them
        self.repo_root = get_repo_root()
        self.remote_url = get_remote_url()
        self.git_owner, self.git_repo = get_github_info_from_url(self.remote_url)

        # For remembering choices in interactive mode
        self.remembered_action_with_repl: Optional[str] = None
        self.remembered_action_without_repl: Optional[str] = None
        self._remember_skip_all_fetches: bool = False
        self.ignored_paths_set: Set[Path] = (
            self._load_ignored_paths() if self.respect_gitignore else set()
        )

    def _load_ignored_paths(self) -> Set[Path]:
        """
        Loads all git-ignored files and directories using 'git status --porcelain=v1 --ignored'.
        Returns a set of absolute Paths.
        """
        ignored_set = set()
        try:
            # -C self.repo_root ensures the command runs in the repo root.
            # Paths in output are relative to repo_root.
            result = subprocess.run(
                ["git", "-C", str(self.repo_root), "status", "--porcelain=v1", "--ignored"],
                capture_output=True,
                text=True,
                check=True,
                encoding="utf-8",
            )
            for line in result.stdout.splitlines():
                if line.startswith("!! "):
                    # Output is "!! path/to/item", so path is relative to repo root
                    ignored_item_relative_path = line[3:].strip()
                    ignored_set.add(self.repo_root / ignored_item_relative_path)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self._vprint(
                f"⚠️ Warning: Could not get git ignored paths: {e}. Gitignore rules will not be applied effectively."
            )
        return ignored_set

    def _vprint(self, *args, **kwargs):
        """Prints only if verbose mode is enabled."""
        if self.verbose:
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
        if lower_repo_name == self.git_repo.lower() or lower_repo_name in self.repo_aliases:
            return self.git_repo.lower()
        return lower_repo_name

    def find_github_permalinks(self) -> List[PermalinkInfo]:
        """Find all GitHub commit permalinks in the repository."""
        permalinks = []

        self._vprint(f"Searching for GitHub permalinks in {self.repo_root}")

        found_count = 0
        for file_path in self.repo_root.rglob("*"):
            # Determine if the file should be processed or skipped
            process_this_file = True
            log_as_skipped_due_to_gitignore = False

            # 1. Check if skipped by fundamental rules (directory, .git, non-text extension)
            #    Pass `None` for ignored_paths_from_git to check only fundamental rules.
            skipped_by_fundamental_rules = should_skip_file_search(file_path, self.repo_root, None)

            if skipped_by_fundamental_rules:
                process_this_file = False
            else:
                # 2. Not skipped by fundamental rules. Now check .gitignore if respect_gitignore is active.
                if self.respect_gitignore and self.ignored_paths_set:
                    # Check if the file is covered by .gitignore rules by seeing if
                    # should_skip_file_search returns True when the gitignore set IS provided.
                    if should_skip_file_search(file_path, self.repo_root, self.ignored_paths_set):
                        # Since skipped_by_fundamental_rules is False, this means it's skipped *solely* due to .gitignore
                        process_this_file = False
                        log_as_skipped_due_to_gitignore = True

            if not process_this_file:
                if log_as_skipped_due_to_gitignore and self.verbose:
                    # Peek into the gitignored file to see if it contains permalinks for logging purposes
                    try:
                        with open(
                            file_path, "r", encoding="utf-8", errors="ignore"
                        ) as ignored_file:
                            lines = ignored_file.readlines()
                        # Use a temporary count, don't affect main found_count or detailed logging
                        permalinks_in_ignored_file, _, _ = extract_permalinks_from_file(
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
                                f"  🙈 gitignored file with {len(permalinks_in_ignored_file)} permalink(s): {file_path.relative_to(self.repo_root)}"
                            )
                    except (UnicodeDecodeError, IOError, OSError, PermissionError) as e_log:
                        self._vprint(
                            f"  ⚠️ Could not read gitignored file {file_path.relative_to(self.repo_root)} for special logging: {e_log}"
                        )
                continue

            # If process_this_file is True, proceed with normal processing
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                (
                    permalinks_in_file,
                    found_count,
                    _,
                ) = extract_permalinks_from_file(
                    file_path,
                    lines,
                    self.repo_root,
                    self.git_owner,
                    self.git_repo,
                    found_count,
                    self._normalize_repo_name,
                )
                permalinks.extend(permalinks_in_file)
            except (UnicodeDecodeError, IOError, OSError, PermissionError) as e:
                print(f"Warning: Could not read {file_path}: {e}")
                continue

        return permalinks

    def _verify_line_content(
        self,
        original: PermalinkInfo,  # Defines original content source (commit, path, lines)
        repl_commit_hash: str,  # Commit to check in
        repl_url_path: str,  # File path to check in repl_commit_hash
        custom_tolerance: Optional[int] = None,  # Optional line shift tolerance
    ) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Verify line content, allowing for shifts. Strips leading/trailing whitespace.
        Returns: (match_found, repl_ls, repl_le)
        The repl_ls/repl_le are for the repl_commit if match_found is True.
        A custom_tolerance can be provided to override self.line_shift_tolerance.
        If the original permalink has no line numbers or no repl_url_path,
        returns (True, None, None) or (False, None, None).
        """
        if not original.url_path or original.line_start is None or not repl_url_path:
            return True, None, None  # Vacuously true, no specific lines to verify

        orig_lines = get_file_content_at_commit(original.commit_hash, original.url_path)
        repl_lines = get_file_content_at_commit(
            repl_commit_hash,
            repl_url_path,  # Use the specified path for replacement
        )

        if not orig_lines or not repl_lines:
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

            eff_tolerance: int
            if custom_tolerance is not None:  # custom_tolerance is always absolute
                eff_tolerance = custom_tolerance
            elif self.tolerance_is_percentage:
                # This part assumes repl_lines is available if we need to calculate percentage.
                # The function structure ensures repl_lines is fetched early if original.url_path is valid.
                # If repl_lines is None here, it means the file content wasn't available,
                # and the function would have returned (False, None, None) earlier.
                if not repl_lines:  # Should ideally not happen if logic flows correctly
                    self._vprint(
                        f"Warning: Could not determine replacement content lines for percentage tolerance calculation for {repl_url_path}"
                    )
                    return False, None, None
                num_lines_in_repl = len(repl_lines)
                eff_tolerance = int(num_lines_in_repl * (self.tolerance_value / 100.0))
            else:  # Absolute tolerance from self (self.tolerance_value)
                eff_tolerance = self.tolerance_value

            # Try all shifts from 0 outward, alternating +shift and -shift
            for offset in range(0, eff_tolerance + 1):
                for shift in (offset, -offset) if offset != 0 else (0,):
                    shifted_repl_start_idx = orig_start_idx + shift
                    if 0 <= shifted_repl_start_idx < len(repl_lines) and (
                        shifted_repl_start_idx + num_orig_lines
                    ) <= len(repl_lines):
                        repl_content = [
                            line.strip()
                            for line in repl_lines[
                                shifted_repl_start_idx : shifted_repl_start_idx + num_orig_lines
                            ]
                        ]
                        if orig_content == repl_content:
                            new_ls_repl = original.line_start + shift
                            new_le_repl = (
                                (original.line_end + shift)
                                if original.line_end is not None
                                else None
                            )
                            return True, new_ls_repl, new_le_repl

            return False, None, None  # No match found

        except IndexError:
            return False, None, None

    def _verify_line_content_from_url(
        self,
        original: PermalinkInfo,
        repl_candidate_url: str,
    ) -> bool:
        """
        Verify line content against a replacement candidate URL.
        Fetches content if it's a GitHub URL. Trusts non-GitHub URLs for content match.
        Returns: match_found
        """
        if not original.url_path or original.line_start is None:
            self._vprint(
                f"⚠️ Warning: Original permalink {original.url} has no line numbers or path, cannot verify content."
            )
            return True

        orig_lines = get_file_content_at_commit(original.commit_hash, original.url_path)
        if not orig_lines:
            self._vprint(
                f"⚠️ Warning: Could not get original content for {original.url} to verify against {repl_candidate_url}"
            )
            return False

        orig_start_idx = original.line_start - 1
        orig_end_idx = (original.line_end or original.line_start) - 1
        if not (
            0 <= orig_start_idx < len(orig_lines)
            and 0 <= orig_end_idx < len(orig_lines)
            and orig_start_idx <= orig_end_idx
        ):
            return False

        orig_content = [line.strip() for line in orig_lines[orig_start_idx : orig_end_idx + 1]]
        if not orig_content:
            return False
        num_target_lines = len(orig_content)

        repl_gh_info = parse_github_blob_permalink(repl_candidate_url)
        if repl_gh_info:
            _, _, _, _, repl_ls, _ = repl_gh_info
            if repl_ls is None:
                self._vprint(
                    f"⚠️ Warning: GitHub URL {repl_candidate_url} has no line numbers. Cannot perform specific line content verification."
                )
                return True
            self._vprint(
                f"Attempting to fetch content from GitHub URL: {repl_candidate_url} for verification."
            )
            repl_lines = fetch_raw_github_content_from_url(repl_candidate_url)
            if repl_lines is None:
                self._vprint(f"⚠️ Warning: Failed to fetch content from {repl_candidate_url}.")
                return False
        else:
            self._vprint(
                f"⚠️ Warning: Verifying against non-GitHub or unparseable URL '{repl_candidate_url}'. Assuming content matches based on user input."
            )
            return True

        # At this point, repl_lines is from a GitHub URL, and repl_ls is not None.
        try:
            repl_start_idx = repl_ls - 1  # Expected start in the replacement content

            if 0 <= repl_start_idx < len(repl_lines) and (repl_start_idx + num_target_lines) <= len(
                repl_lines
            ):
                repl_content = [
                    line.strip()
                    for line in repl_lines[repl_start_idx : repl_start_idx + num_target_lines]
                ]
                return orig_content == repl_content
            return False
        except IndexError:
            return False

    def _create_repl_permalink(
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
        url_type = match.group(3) if match else "blob" # Default to blob if somehow not found

        base_url_parts = [f"https://github.com/{git_owner}/{git_repo}"]
        if url_type == "tree" or not repl_url_path: # Tree link or blob link with no path (points to commit root)
            base_url_parts.extend(["tree", repl_commit])
            return "/".join(base_url_parts)
        else: # blob with a path
            base_url_parts.extend([url_type, repl_commit, repl_url_path.lstrip('/')])
            url_no_frag = "/".join(base_url_parts)
            # update_url_with_line_numbers handles adding #L fragments correctly
            return update_url_with_line_numbers(url_no_frag, repl_ls, repl_le)


    def _parse_and_confirm_manual_url_input(
        self,
        user_input: str,
        # context_commit_for_path_extraction is the commit against which a path might be extracted
        # from the user_input if it's a URL pointing to this specific commit.
        context_commit_for_path_extraction: Optional[str],
    ) -> Tuple[str, Optional[str], Optional[int], Optional[int]]:
        """
        Parses user input that might be a URL, confirms it, and extracts relevant info.

        Returns:
            A tuple (status, value1, ls, le):
            - status (str):
                - "path_extracted": URL was for context_commit, value1 is the extracted path.
                - "url_confirmed": A generic URL was confirmed, value1 is the URL string.
                - "url_rejected": User rejected the URL. value1 is None.
                - "not_a_url": Input was not a URL. value1 is the original user_input.
            - value1 (Optional[str]): Path string, URL string, or original input.
            - ls (Optional[int]): Parsed line start from URL fragment.
            - le (Optional[int]): Parsed line end from URL fragment.
        """
        if not user_input.lower().startswith("https://"):
            return "not_a_url", user_input, None, None

        repl_gh_info = parse_github_blob_permalink(user_input)
        if repl_gh_info:  # It's a GitHub blob URL
            gh_owner, gh_repo, gh_ref, gh_path, gh_ls, gh_le = repl_gh_info
            is_current_repo_link = (
                gh_owner.lower() == self.git_owner.lower()
                and self._normalize_repo_name(gh_repo) == self.git_repo.lower()
            )

            if (
                context_commit_for_path_extraction
                and is_current_repo_link
                and gh_ref == context_commit_for_path_extraction
                and gh_path
            ):
                print(
                    f"    Parsed as URL for current context commit ({context_commit_for_path_extraction[:8]}). Using file path: '{gh_path}'"
                )
                return "path_extracted", gh_path, gh_ls, gh_le
            else:
                confirm_external = input(
                    f"    ❗ The GitHub URL points to '{gh_owner}/{gh_repo}/blob/{gh_ref}'. Are you sure? (y/n): "
                ).strip().lower()
                return ("url_confirmed", user_input, gh_ls, gh_le) if confirm_external == "y" else ("url_rejected", None, None, None)
        else:  # Arbitrary URL (not parseable as GitHub blob, but starts with https://)
            confirm_arbitrary = input(
                f"    ❗ The input '{user_input}' is not a recognized GitHub file URL. Are you sure? (y/n): "
            ).strip().lower()
            if confirm_arbitrary == "y":
                arb_ls, arb_le = None, None
                match_lines_frag = re.search(r"#L(\d+)(?:-L(\d+))?$", user_input)
                if match_lines_frag:
                    arb_ls = int(match_lines_frag.group(1))
                    if match_lines_frag.group(2):
                        arb_le = int(match_lines_frag.group(2))
                return "url_confirmed", user_input, arb_ls, arb_le
            else:
                return "url_rejected", None, None, None

    def _prompt_user_to_resolve_url_path(
        self,
        original: PermalinkInfo,
        ancestor_commit: str,
        initial_path_to_check: str,
        initial_ls: Optional[int],
        initial_le: Optional[int],
    ) -> Tuple[str, Optional[int], Optional[int], bool, str]:
        """
        Interactively resolve the file path for replacement if it's missing in the ancestor.
        Returns: (resolved_target_spec, resolved_ls, resolved_le, should_abort, target_type)
        target_spec is a file path string or a full URL string.
        target_type is "path", "user_provided_url".
        """
        path_to_check = initial_path_to_check
        current_ls, current_le = initial_ls, initial_le

        while not file_exists_at_commit(ancestor_commit, path_to_check):
            self._vprint(
                f"\n❌ File '{path_to_check}' (from original or last input) does not exist in ancestor {ancestor_commit[:8]}"
            )
            print("\n❓ MISSING FILE RESOLUTION:")
            print("  o) Open original and replacement URLs in browser")
            print("  m) MANUALLY override with a new URL path or a new full URL")
            print("  k) KEEP current path for replacement URL (it will likely be broken)")
            print("  a) ABORT replacement for this permalink (skip)")
            menu_choice = input("\nSelect resolution for missing file (o,m,k,a): ").strip().lower()

            if menu_choice == "o":
                broken_repl_url = self._create_repl_permalink(
                    original, ancestor_commit, path_to_check, current_ls, current_le
                )
                urls_to_open = [
                    ("original URL", original.url),
                    ("(likely broken) replacement URL", broken_repl_url),
                ]
                open_urls_in_browser(urls_to_open)
                continue  # Re-prompt
            elif menu_choice == "m":
                # The user may enter:
                # - a relative path from the repo root,
                # - a full path that starts with the prefix of the repo root,
                # - a full GitHub URL that starts with the same prefix as the original URL.
                # - any arbitrary URL, if the user confirms
                new_input = input(
                    "    Enter the new URL path (relative to the repo root), or the full file path, or any URL: "
                ).strip()
                if not new_input:
                    print("    Input cannot be empty. Try again.")
                    continue  # Re-prompt for manual input

                status, extracted_value, val_ls, val_le = self._parse_and_confirm_manual_url_input(new_input, ancestor_commit)

                if status == "path_extracted":
                    # extracted_value is github url_path, val_ls/val_le are from the URL fragment or None
                    path_to_check = extracted_value
                    current_ls = val_ls if val_ls is not None else original.line_start
                    current_le = val_le if val_le is not None else original.line_end
                    # Loop continues to check file_exists_at_commit with this new path_to_check
                    continue
                elif status == "url_confirmed":
                    # extracted_value is the confirmed URL string, val_ls/val_le are from its fragment or None
                    return extracted_value, val_ls, val_le, False, "user_provided_url"
                elif status == "url_rejected":
                    continue # Re-prompt for manual input
                elif status == "not_a_url":
                    # Input is treated as a file path (relative or absolute)
                    input_path_obj = Path(new_input)
                    if input_path_obj.is_absolute():
                        try:
                            # Convert an absolute path to relative if it's within the repo root
                            relative_path = input_path_obj.relative_to(self.repo_root)
                            new_relative_path_str = str(relative_path)
                        except ValueError:
                            print(
                                f"    Absolute path '{new_input}' is not within the repository root '{self.repo_root}'."
                                " Please provide a relative path, an absolute path within the repository, or a full GitHub URL."
                            )
                            continue  # Re-prompt for manual input
                    else:  # Input is a relative path
                        new_relative_path_str = new_input

                    if new_relative_path_str is not None:
                        print(
                            f"    Using file path: '{new_relative_path_str}'. Line numbers will be re-evaluated based on original permalink if applicable."
                        )
                        path_to_check = new_relative_path_str
                        # current_ls, current_le retain values from original permalink or previous URL input if path_extracted
                continue  # Loop will re-evaluate existence
            elif menu_choice == "k":
                self._vprint(
                    f"    Keeping path '{path_to_check}' for replacement URL, though it's missing in ancestor."
                )
                return path_to_check, current_ls, current_le, False, "path"

            elif menu_choice == "a":
                print("    Aborting replacement for this permalink.")
                return initial_path_to_check, initial_ls, initial_le, True, "path"  # Abort
            else:
                print("    Invalid choice. Try again.")

        return path_to_check, current_ls, current_le, False, "path"  # File exists, don't abort

    def _prompt_user_to_resolve_line_mismatch(
        self,
        original: PermalinkInfo,
        # Context for verification - either local ancestor or an external URL
        ancestor_commit_or_external_url: str,  # If is_external_source, this is the URL
        repl_url_path_or_none: Optional[str],  # Path if local, None if external_url is primary
        initial_ls: Optional[int],
        initial_le: Optional[int],
        is_external_source: bool = False,
    ) -> Tuple[Optional[int], Optional[int], bool, Optional[str]]:
        """
        Interactively resolve line number mismatches.
        Returns: (resolved_ls, resolved_le, should_abort_permalink, overriding_url_if_provided)
        The overriding_url_if_provided is a full URL string if the user chose to replace with a new URL.
        """
        current_ls, current_le = initial_ls, initial_le
        # The primary target for verification/replacement:
        verification_target_url = ancestor_commit_or_external_url if is_external_source else None
        verification_target_commit = None if is_external_source else ancestor_commit_or_external_url
        verification_target_path = None if is_external_source else repl_url_path_or_none

        while True:
            print("\n❓ LINE MISMATCH RESOLUTION:")
            print("  o) OPEN original and replacement URLs in browser")
            print("  l) retry with different LINE shift tolerance for search")
            print(
                "  m) MANUALLY override the line numbers OR with a full GitHub URL"
            )
            print("  c) CLEAR line numbers from replacement URL")
            print("  k) KEEP original line numbers in replacement URL")
            print("  a) ABORT replacement (skip this permalink for now)")
            menu_choice = input("\nSelect resolution for lines (o,l,m,c,k,a): ").strip().lower()

            if menu_choice == "o":
                if is_external_source and verification_target_url:
                    broken_repl_url = update_url_with_line_numbers(
                        verification_target_url, current_ls, current_le
                    )
                elif verification_target_commit and verification_target_path:
                    broken_repl_url = self._create_repl_permalink(
                        original,
                        verification_target_commit,
                        verification_target_path,
                        current_ls,
                        current_le,
                    )
                else:  # Should not happen
                    broken_repl_url = "ERROR_COULD_NOT_FORM_URL"

                urls_to_open = [
                    ("original URL", original.url),
                    ("(likely broken) replacement URL", broken_repl_url),
                ]
                open_urls_in_browser(urls_to_open)
                continue  # Re-prompt
            elif menu_choice == "l":
                abs_custom_tolerance: int
                try:
                    new_tol_input = input(
                        f"    Enter new tolerance (current global: {self.line_shift_tolerance_str}, e.g., 20 or 10%, 0 to disable shift): "
                    ).strip()
                    if not new_tol_input:
                        print("    Input cannot be empty. Try again.")
                        continue

                    is_tol_percentage, tol_value = parse_tolerance_input(new_tol_input)

                    if is_external_source and verification_target_url:
                        # For external URL, we assume any line numbers provided by the user are valid
                        match, ls, le = self._verify_line_content_from_url(
                            original, verification_target_url
                        )

                    elif verification_target_commit and verification_target_path:  # Local ancestor
                        if is_tol_percentage:
                            repl_lines = get_file_content_at_commit(
                                verification_target_commit, verification_target_path
                            )
                            if not repl_lines:
                                print(
                                    f"    ⚠️ Could not fetch content of '{verification_target_path}' in ancestor to calculate percentage. Try absolute tolerance."
                                )
                                continue
                            num_lines = len(repl_lines)
                            abs_custom_tolerance = int(num_lines * (tol_value / 100.0))
                            self._vprint(
                                f"    ℹ️ Using {tol_value}% of {num_lines} lines = {abs_custom_tolerance} lines tolerance for this check."
                            )
                        else:
                            abs_custom_tolerance = tol_value
                        print(f"\n🔄 Re-checking with tolerance {abs_custom_tolerance} lines…")
                        match, ls, le = self._verify_line_content(
                            original,
                            verification_target_commit,
                            verification_target_path,
                            custom_tolerance=abs_custom_tolerance,
                        )
                    else:  # Should not happen
                        print("    ⚠️ Cannot determine verification context for tolerance retry.")
                        continue

                    if match:
                        print(
                            f"✅ Match found with new tolerance at L{ls}"
                            + (f"-L{le}" if le and le != ls else "")
                            + "!"
                        )
                        return ls, le, False, None  # Resolved, no overriding URL
                    else:
                        print("💥 No match found even with new tolerance.")
                except ValueError as e:
                    print(f"    Invalid tolerance: {e}")
                    continue  # Re-prompt for line mismatch

            elif menu_choice == "m":
                new_input = input(
                    "    Enter new line numbers (e.g., 10 or 10-15) OR or any URL: "
                ).strip()
                if not new_input:
                    print("    Input cannot be empty. Try again.")
                    continue

                # For line mismatch, context_commit_for_path_extraction is None.
                # Any URL input is treated as a full override URL.
                status, extracted_value, val_ls, val_le = self._parse_and_confirm_manual_url_input(new_input, None)

                if status == "url_confirmed":
                    # val1_url_or_lines is the confirmed URL string.
                    # val_ls, val_le are parsed from its fragment or None.
                    return val_ls, val_le, False, extracted_value
                elif status == "url_rejected":
                    continue # Re-prompt for line mismatch
                elif status == "not_a_url":
                    # Input is treated as line numbers.
                    try:
                        if "-" in new_input:
                            new_input_ls, new_input_le = new_input.split("-", 1)
                            ls = int(new_input_ls)
                            le = int(new_input_le)
                            if ls <= 0 or le <= 0 or le < ls:
                                raise ValueError("Invalid line range.")
                        else:
                            ls = int(new_input)
                            if ls <= 0:
                                raise ValueError("Line must be positive.")
                            le = None  # Single line

                        print("    Manually set line numbers for replacement.")
                        return ls, le, False, None  # Resolved, no overriding URL
                    except ValueError as e:
                        print(
                            f"    Invalid line number format: {e}. Expected e.g., '10' or '10-15'."
                        )
                        continue  # Re-prompt for line mismatch

            elif menu_choice == "c":
                return None, None, False, None  # Cleared, resolved
            elif menu_choice == "k":
                return original.line_start, original.line_end, False, None  # Kept, resolved
            elif menu_choice == "a":
                return current_ls, current_le, True, None  # Abort
            else:
                print("    Invalid choice. Try again.")

    def _prompt_user_for_final_action(
        self,
        original: PermalinkInfo,
        repl_url: Optional[str],  # The fully formed candidate replacement URL
        is_commit_slated_for_tagging: bool,
        auto_action_directive_for_commit: Optional[str] = None, # From 'rc' or 'sc'
    ) -> Optional[tuple[str, Optional[str]]]:
        """
        Prompts the user for the final action (replace, tag, skip) and handles remembering choices.
        This is also where --auto-accept-replace and --auto-fallback flags take effect.
        Returns: (action_string, value_to_remember_if_any)
        """
        # Determine remembered action based on current context
        auto_chosen_action: Optional[str] = None

        # Priority 1: Commit-level auto directive (from 'rc' or 'sc' for this commit group)
        if auto_action_directive_for_commit == "replace" and repl_url:
            auto_chosen_action = "replace"
            self._vprint(f"    🤖 Commit-level 'replace' directive: Auto-choosing 'replace' for '{original.url[-50:]}'.")
        elif auto_action_directive_for_commit == "skip":
            # 'sc' (skip commit group) is a fallback choice.
            # It applies if no replacement URL is available for the current permalink.
            if not repl_url: # Fallback context
                auto_chosen_action = "skip"
                self._vprint(f"    🤖 Commit-level 'skip' directive (fallback): Auto-choosing 'skip' for '{original.url[-50:]}'.")

        # Priority 2: Global auto flags (--auto-accept-replace, --auto-fallback)
        # Only if not already decided by commit-level directive
        if not auto_chosen_action:
            if repl_url: # Replacement is possible
                if self.auto_accept_replace:
                    auto_chosen_action = "replace"
                    self._vprint(f"    🤖 --auto-accept-replace: Auto-choosing 'replace' for '{original.url[-50:]}'.")
            else:  # Fallback: No viable replacement URL
                if self.auto_fallback == "tag":
                    auto_chosen_action = "tag"
                    self._vprint(f"    🤖 --auto-fallback=tag: Auto-choosing 'tag' for '{original.url[-50:]}'.")
                elif self.auto_fallback == "skip":
                    auto_chosen_action = "skip"
                    self._vprint(f"    🤖 --auto-fallback=skip: Auto-choosing 'skip' for '{original.url[-50:]}'.")

        # Priority 3: Global remembered choices ('ra', 'ta', 'sa')
        # Only if not already decided by commit-level or global auto flags
        if not auto_chosen_action:
            if repl_url: # Replacement is possible
                # 'replace_commit_group' from 'ra' means always replace if possible
                if self.remembered_action_with_repl in ["replace", "replace_commit_group"]:
                    auto_chosen_action = "replace"
                    self._vprint(f"    🤖 Remembered 'replace' (global): Auto-choosing 'replace' for '{original.url[-50:]}'.")
            else:  # Fallback
                if self.remembered_action_without_repl == "tag":
                    auto_chosen_action = "tag"
                    self._vprint(f"    🤖 Remembered 'tag' (global fallback): Auto-choosing 'tag' for '{original.url[-50:]}'.")
                elif self.remembered_action_without_repl == "skip":
                    auto_chosen_action = "skip"
                    self._vprint(f"    🤖 Remembered 'skip' (global fallback): Auto-choosing 'skip' for '{original.url[-50:]}'.")

        if auto_chosen_action:
            # Auto-actions should not select "untag". If commit is slated and auto says "tag", it's still "tag".
            if auto_chosen_action == "untag":
                 # This should not be reachable if logic is correct, force prompt if it is.
                pass # Fall through to interactive prompt
            else:
                return auto_chosen_action, None # Auto actions don't set "remember_this_choice" for future global use

        # If no auto-action was taken, proceed to display the interactive prompt:
        print("\n❓ ACTIONS:")
        print(
            f"  o) Open {'original & replacement URLs' if repl_url else 'original URL'} in browser"
        )

        # Replacement is offered if a repl_url has been successfully verified of manually provided
        if repl_url:
            print("  r) Replace with suggested URL (i.e., update reference)")
            print("    rc) Auto-accept 'Replace' for rest of Commit group")
            print("    ra) Auto-accept 'Replace' from now on")  # Make wording general

        if is_commit_slated_for_tagging:
            print("  -t) UNTAG this commit")
        else:
            print("  t) Tag commit (i.e., preserve exact permalink)")
            print("    ta) Automatically fall back to tagging")

        print("  s) Skip this permalink")
        print("    sc) Automatically fall back to skipping for the rest of this Commit group")
        print("    sa) Automatically fall back to skipping")

        while True:
            action: Optional[str] = None
            remember_this_choice: Optional[str] = None

            prompt_options_list = ["o"]
            if repl_url:
                prompt_options_list.extend(["r", "rc", "ra"])
            prompt_options_list.append("-t" if is_commit_slated_for_tagging else "t")
            prompt_options_list.append(
                "ta"
            )  # Always offer tag all, context handled by remember key
            prompt_options_list.extend(["s", "sc", "sa"])
            menu_choice = (
                input(f"\nSelect action ({','.join(prompt_options_list)}): ").strip().lower()
            )

            if menu_choice == "o":
                urls_to_open_list = [("original URL", original.url)]
                if repl_url:
                    urls_to_open_list.append(("suggested replacement URL", repl_url))
                open_urls_in_browser(urls_to_open_list)
                continue
            elif menu_choice == "r" and repl_url:
                auto_chosen_action = "replace"
                action = "replace"
            elif menu_choice == "rc" and repl_url:
                action = "replace_commit_group"
            elif (
                menu_choice == "ra" and repl_url
            ):  # Remember based on if ancestor/replacement was possible
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

    def _prompt_user_for_action_on_permalink(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],  # For context, even if user provides external URL
        file_path: Path,
        index: int,
        total: int,
        is_commit_slated_for_tagging: bool,
        auto_action_directive_for_commit: Optional[str] = None, # "replace" or "skip"
    ) -> Tuple[str, Optional[str]]:  # Returns (action_str, final_repl_url_if_action_is_replace)
        """
        Prompt user to confirm replacement permalink.
        Returns a tuple: (action_str, final_repl_url_string, trigger_rc_bool).
        The URL string is only present if action_str is "replace".
        """
        index_msg = f"Permalink #{index + 1}/{total} for {original.commit_hash[:8]}"
        print(f"\n    [*] {index_msg} {'- ' * ((75 - len(index_msg)) // 2)}")
        print("      🚧 PERMALINK PROTECTION NEEDED")
        print()
        print(
            f"📄 Found in: {original.found_in_file.relative_to(self.repo_root)}:{original.found_at_line}"
        )
        print(f"🔗 Original URL: {original.url}")
        self._vprint(f"⛓️‍💥 Original commit: {original.commit_hash[:8]} (not in {self.main_branch})")
        if is_commit_slated_for_tagging:
            print(f"🏷️ Commit {original.commit_hash[:8]} is currently slated to be TAGGED.")
        print()

        # These store the current best candidate for replacement
        spec_repl_url: Optional[str] = None  # A fully formed URL if user provides one
        # Or, if using ancestor:
        candidate_path_for_ancestor: Optional[str] = original.url_path
        candidate_repl_ls: Optional[int] = original.line_start
        candidate_repl_le: Optional[int] = original.line_end

        # --- Stage 1: Resolve File Path/URL for Replacement ---
        if ancestor_commit:  # Only offer path/URL resolution if an ancestor context exists
            ancestor_info = get_commit_info(ancestor_commit)
            if ancestor_info:
                self._vprint(
                    f"⏪ Suggested ancestor commit: {ancestor_commit[:8]} - {ancestor_info['subject']}"
                )
                self._vprint(f"   👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")

            if original.url_path:  # Only if original permalink pointed to a file
                (resolved_target_spec, resolved_ls, resolved_le, abort_path_res, target_type) = (
                    self._prompt_user_to_resolve_url_path(
                        original,
                        ancestor_commit,
                        candidate_path_for_ancestor or "",  # initial path
                        candidate_repl_ls,
                        candidate_repl_le,
                    )
                )
                if abort_path_res:
                    return "skip", None

                if target_type == "user_provided_url":
                    spec_repl_url = resolved_target_spec
                    candidate_repl_ls = resolved_ls  # Lines from the user's URL
                    candidate_repl_le = resolved_le
                else:  # "path"
                    candidate_path_for_ancestor = resolved_target_spec
                    candidate_repl_ls = resolved_ls  # Lines for that path
                    candidate_repl_le = resolved_le
            # If original.url_path was None (e.g. tree link), we don't do this path resolution.
            # spec_repl_url remains None, candidate_path_for_ancestor is None.

        # --- Stage 2: Content Verification and Line Mismatch Resolution ---
        repl_url: Optional[str] = None

        if spec_repl_url:  # User provided a full URL
            if (
                original.line_start is None
            ):  # Original has no lines, so no line verification needed for user URL
                print(f"✅ Using user-provided URL: {spec_repl_url}")
                repl_url = spec_repl_url  # Trust it as is
            else:  # Original has lines, so verify against user URL
                print(f"\n🔄 Verifying content against user-provided URL: {spec_repl_url}…")
                match, v_ls, v_le = self._verify_line_content_from_url(original, spec_repl_url)
                if match:
                    repl_url = update_url_with_line_numbers(spec_repl_url, v_ls, v_le)
                    print(f"✅ Content matches or accepted for user URL. Updated to: {repl_url}")
                else:
                    print("💥 Line content differs or could not be verified for the provided URL.")
                    # Pass spec_repl_url as the context for line mismatch
                    mls, mle, abort_mismatch, override_url = (
                        self._prompt_user_to_resolve_line_mismatch(
                            original,
                            spec_repl_url,
                            None,  # URL is primary context
                            candidate_repl_ls,
                            candidate_repl_le,
                            is_external_source=True,
                        )
                    )
                    if abort_mismatch:
                        return "skip", None
                    if override_url:  # User gave a new URL during line mismatch
                        spec_repl_url = override_url
                        # Re-verify this new URL (simplified: assume lines from it are now trusted, or re-verify)
                        # For now, trust lines from override_url or use mls, mle
                        repl_url = update_url_with_line_numbers(override_url, mls, mle)
                        print(f"✅ Using new URL from manual input: {repl_url}")
                    else:  # User gave new line numbers for the spec_repl_url
                        repl_url = update_url_with_line_numbers(spec_repl_url, mls, mle)
                        print(f"✅ Using manually adjusted lines for URL: {repl_url}")

        elif ancestor_commit and candidate_path_for_ancestor and original.line_start is not None:
            # Standard ancestor-based verification
            if file_exists_at_commit(ancestor_commit, candidate_path_for_ancestor):
                match, verified_ls, verified_le = self._verify_line_content(
                    original, ancestor_commit, candidate_path_for_ancestor
                )
                if match:
                    # Message about match success/shift
                    orig_line_str = f"L{original.line_start}" + (
                        f"-L{original.line_end}"
                        if original.line_end and original.line_end != original.line_start
                        else ""
                    )
                    new_line_str = f"L{verified_ls}" + (
                        f"-L{verified_le}" if verified_le and verified_le != verified_ls else ""
                    )
                    if new_line_str == orig_line_str:
                        print(f"✅ Line content matches at {orig_line_str}")
                    else:
                        print(
                            f"✅ Line content matches, found at {new_line_str} in ancestor (original was {orig_line_str})"
                        )
                else:
                    print("💥 Line content differs in ancestor, even with default tolerance.")
                    mls, mle, abort_mismatch, override_url = (
                        self._prompt_user_to_resolve_line_mismatch(
                            original,
                            ancestor_commit,
                            candidate_path_for_ancestor,
                            candidate_repl_ls,
                            candidate_repl_le,
                            is_external_source=False,
                        )
                    )
                    if abort_mismatch:
                        return "skip", None
                    if override_url:  # User provided a full URL during line mismatch for ancestor
                        # This switches context to user_provided_url
                        # We should re-verify this new URL. For simplicity now, we'll trust it with its lines.
                        repl_url = update_url_with_line_numbers(override_url, mls, mle)
                        print(f"✅ Switched to user-provided URL: {repl_url}")
                    else:  # User gave new lines for ancestor path
                        candidate_repl_ls, candidate_repl_le = mls, mle
            else:  # File for ancestor path doesn't exist (e.g. user kept a bad path)
                print(
                    f"❌ File '{candidate_path_for_ancestor}' does not exist in ancestor {ancestor_commit[:8]}."
                )
                # Simplified: if file doesn't exist, can't form a good replacement unless user clears lines.
                # This part of the logic for "missing file but keep path" needs to be robust.
                # For now, if path is bad, replacement URL will be too.

            # Construct URL for ancestor path if not overridden by a full URL
            if not repl_url:
                repl_url = self._create_repl_permalink(
                    original,
                    ancestor_commit,
                    candidate_path_for_ancestor,
                    candidate_repl_ls,
                    candidate_repl_le,
                )

        elif ancestor_commit and not original.url_path:  # E.g. original was a /tree/ link
            repl_url = self._create_repl_permalink(original, ancestor_commit, None, None, None)

        if repl_url:
            print(f"✨ Suggested replacement URL: {repl_url}")
        elif not ancestor_commit:  # No ancestor, no user URL
            print(
                "  ℹ️ No common ancestor found in the main branch, and no alternative URL provided."
            )

        # --- Stage 3: Final Action Prompt ---
        action, remember_this_choice = self._prompt_user_for_final_action(
            original,
            repl_url,
            is_commit_slated_for_tagging,
            auto_action_directive_for_commit=auto_action_directive_for_commit,
        )

        if remember_this_choice:
            # Remember based on whether a replacement was possible or not
            # This logic for remember_key might need refinement based on how "replace all" vs "tag all" should behave
            # when user provides an external URL vs. using an ancestor.
            # For now, if any replacement URL was formed, consider it "with_ancestor" context for remembering.
            current_remember_key = (
                "with_repl" if (ancestor_commit or spec_repl_url) else "without_repl"
            )
            setattr(self, f"remembered_action_{current_remember_key}", remember_this_choice)

        if action in ["replace", "replace_commit_group"]:
            return action, repl_url
        else:  # "tag", "untag", "skip", "skip_commit_group"
            return action, None

    def _perform_replacement(self, permalink: PermalinkInfo, repl_url: str) -> None:
        """Replaces the permalink in the file."""
        try:
            file_path = permalink.found_in_file
            if not file_path.exists():
                print(f"  ❌ File {file_path} no longer exists. Cannot replace permalink.")
                return

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.readlines()

            if permalink.found_at_line > len(content) or permalink.found_at_line < 1:
                print(
                    f"  ❌ Line number {permalink.found_at_line} out of range in {file_path}. Cannot replace."
                )
                return

            original_line = content[permalink.found_at_line - 1]
            if permalink.url not in original_line:
                print(
                    f"  ⚠️ Original URL not found in line {permalink.found_at_line} of {file_path}. Cannot replace."
                )
                # This might happen if the line was already modified or the URL parsing had an issue.
                # Or if multiple identical permalinks were on the same line and one was already replaced.
                return

            # Replace only the first instance of the URL in the line to avoid issues if multiple identical URLs are present
            content[permalink.found_at_line - 1] = original_line.replace(permalink.url, repl_url, 1)

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(content)

            print(
                f"  ✅ Replaced permalink in {file_path.relative_to(self.repo_root)} at line {permalink.found_at_line}"
            )
        except (IOError, OSError, UnicodeDecodeError, PermissionError) as e:
            print(
                f"  ❌ Failed to replace permalink in {permalink.found_in_file.relative_to(self.repo_root)}: {e}"
            )

    def _process_commit_further(
        self,
        commit_hash: str,
        commit_info: Dict[str, str],
        ancestor_commit: Optional[str],
        commit_permalinks: List[PermalinkInfo],
    ) -> Tuple[Optional[Tuple[str, Dict[str, str]]], List[Tuple[PermalinkInfo, str]]]:
        """
        Handles interactive prompting for each permalink within a commit group.
        Returns an optional tag to create and a list of replacements to make.
        """
        replacements_for_this_commit_group: List[Tuple[PermalinkInfo, str]] = []
        pending_tag_for_commit: Optional[Tuple[str, Dict[str, str]]] = None
        auto_action_directive_for_remaining_in_commit: Optional[str] = None # "replace" or "skip"

        commit_is_currently_slated_for_tagging = False
        # Initial slating based *only* on remembered choices.
        # auto_fallback's effect will be handled per-permalink if a permalink cannot be replaced.
        if (ancestor_commit and self.remembered_action_with_repl == "tag") or \
                (not ancestor_commit and self.remembered_action_without_repl == "tag"):
            commit_is_currently_slated_for_tagging = True
            # If remembered action is tag, then we intend to tag the commit.
            pending_tag_for_commit = (commit_hash, commit_info)
            self._vprint(
                f"  ℹ️ Commit {commit_hash[:8]} is initially slated for tagging due to remembered choice."
            )

        self._vprint(
            f"\n  🚧 Interactively processing {len(commit_permalinks)} permalink(s) for commit {commit_hash[:8]}:"
        )
        permalinks_by_file: Dict[Path, List[PermalinkInfo]] = {}
        for p in commit_permalinks:
            permalinks_by_file.setdefault(p.found_in_file, []).append(p)
        sorted_file_paths = sorted(permalinks_by_file.keys())

        commit_wide_repl_idx = 0
        stop_processing_permalinks_for_this_commit_entirely = False

        for file_group_idx, file_path in enumerate(sorted_file_paths):
            permalinks_in_this_file = permalinks_by_file[file_path]
            # Sort permalinks within this file by line number for consistent processing order
            permalinks_in_this_file.sort(key=lambda p_info: p_info.found_at_line)

            print(
                f"\n  [*] File #{file_group_idx + 1}/{len(sorted_file_paths)}: {file_path.relative_to(self.repo_root)} "
                f"({len(permalinks_in_this_file)} permalink(s) for this commit)"
            )

            permalink_idx = 0
            while permalink_idx < len(permalinks_in_this_file):
                permalink = permalinks_in_this_file[permalink_idx]
                current_action: str
                final_repl_url_if_action_is_replace: Optional[str] = None

                action_from_prompt, repl_url_from_prompt = (
                    self._prompt_user_for_action_on_permalink(
                        permalink,
                        ancestor_commit,
                        file_path=file_path,
                        index=commit_wide_repl_idx,
                        total=len(commit_permalinks),
                        is_commit_slated_for_tagging=commit_is_currently_slated_for_tagging,
                        auto_action_directive_for_commit=auto_action_directive_for_remaining_in_commit
                    )
                )
                current_action = action_from_prompt
                final_repl_url_if_action_is_replace = repl_url_from_prompt

                if current_action == "untag":
                    if commit_is_currently_slated_for_tagging:
                        commit_is_currently_slated_for_tagging = False
                        pending_tag_for_commit = None
                        print(
                            f"  ℹ️ Commit {commit_hash[:8]} is no longer slated for tagging. Re-evaluating current permalink."
                        )
                    # Do not increment permalink_idx or commit_wide_repl_idx; re-process current permalink
                    continue  # Restart the while loop for the current permalink_idx

                # If an auto-action for the rest of the commit wasn't already set,
                # check if the current action implies one.
                if not auto_action_directive_for_remaining_in_commit:
                    if current_action == "replace_commit_group":
                        auto_action_directive_for_remaining_in_commit = "replace"
                        current_action = "replace"  # The current permalink is processed as a "replace"
                        self._vprint(
                            f"    🤖 User chose 'replace commit'. Will auto-accept replace for rest of commit {commit_hash[:8]}."
                        )
                        # final_repl_url_if_action_is_replace is already set from prompt
                        if not final_repl_url_if_action_is_replace: # Should not happen
                            self._vprint(
                                f"  ⚠️ Action was 'replace_commit_group' but no replacement URL was provided for '{permalink.url[-50:]}'. Skipping this one."
                            )
                            current_action = "skip" # Fallback to skip if URL is missing

                    elif current_action == "skip_commit_group":
                        auto_action_directive_for_remaining_in_commit = "skip"
                        current_action = "skip" # The current permalink is processed as a "skip"
                        self._vprint(
                            f"    🤖 User chose 'skip commit'. Will auto-fallback to skip for rest of commit {commit_hash[:8]}."
                        )
                        final_repl_url_if_action_is_replace = None # Ensure no replacement

                # If action is not "untag", we proceed with this permalink's decision
                elif current_action == "tag":
                    if (
                        not commit_is_currently_slated_for_tagging
                    ):  # User chose 't' or 'ta' when not slated
                        commit_is_currently_slated_for_tagging = True
                        pending_tag_for_commit = (commit_hash, commit_info)  # Mark for tagging
                        self._vprint(
                            f"  ℹ️ Commit {commit_hash[:8]} is now slated to be tagged based on choice for '{permalink.url[-50:]}'…"
                        )

                        if (
                            replacements_for_this_commit_group
                        ):  # If prior replacements exist for this commit
                            print(
                                "\n⚠️ Commit is now slated for tagging, but you previously chose to REPLACE some permalink(s) for this commit."
                            )
                            print(
                                "   1) Tag commit & DISCARD all previous REPLACEMENT choices for this commit."
                            )
                            print(
                                "   2) Tag commit & KEEP previous REPLACEMENTS. Stop offering to replace other permalinks for this commit."
                            )
                            print(
                                "   3) Tag commit & KEEP previous REPLACEMENTS. Continue to be prompted for other permalinks for this commit."
                            )
                            while True:
                                sub_choice = input(
                                    "      Select how to handle existing replacements (1/2/3): "
                                ).strip()
                                if sub_choice == "1":
                                    replacements_for_this_commit_group.clear()
                                    print(
                                        "  🗑️ Previous replacement choices for this commit have been discarded."
                                    )
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                elif sub_choice == "2":
                                    print(
                                        "  ✅ Previous replacements kept. No more prompts for this commit."
                                    )
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                elif sub_choice == "3":
                                    print(
                                        "  ✅ Previous replacements kept. Will continue prompting for this commit."
                                    )
                                    # commit_is_currently_slated_for_tagging remains True
                                    break
                                else:
                                    print("      Invalid choice. Please select 1, 2, or 3.")
                        else:  # No prior replacements, just tagging
                            print(
                                f"  ℹ️ Commit {commit_hash[:8]} will be tagged. Other permalinks for this commit will reflect this."
                            )
                            # If user chose "ta" (tag all), _prompt_user_for_final_action would have set remembered_action.
                            # If they just chose "t", we don't automatically stop unless they pick "ta" or sub_choice 2.
                            # If 'ta' was chosen, self.remembered_action_* would be 'tag'.
                            # If 't' was chosen, and no sub-prompt, we continue.

                    # If commit was already slated and user chose 't' (which shouldn't be an option if UI is correct,
                    # as it would be '-t'), this path is defensive.

                elif current_action == "replace":
                    if final_repl_url_if_action_is_replace:
                        replacements_for_this_commit_group.append(
                            (permalink, final_repl_url_if_action_is_replace)
                        )
                    else:  # Should not happen if action is "replace"
                        self._vprint(
                            f"  ⚠️ Action was 'replace' but no replacement URL was provided for permalink '{permalink.url[-50:]}'. Skipping."
                        )

                elif current_action == "skip":
                    print(f"  ⏭️ Skipping permalink '{permalink.url[-50:]}'…")

                permalink_idx += 1
                commit_wide_repl_idx += 1

                if stop_processing_permalinks_for_this_commit_entirely:
                    break  # Break from inner while loop (permalinks in this file)
            if stop_processing_permalinks_for_this_commit_entirely:
                break  # Break from outer for loop (files for this commit)

        return pending_tag_for_commit, replacements_for_this_commit_group

    def _prompt_to_fetch_commit(self, commit_hash: str) -> bool:
        """
        Prompts the user whether to fetch a missing commit.
        This method can modify self.auto_fetch_commits or self._remember_skip_all_fetches.
        """
        while True:
            print(f"\n❓ Look for {commit_hash} at the remote?")
            print("  y) Yes, fetch this commit from 'origin'")
            print(
                "    ya) Yes to all - fetch this and all subsequent missing commits automatically"
            )
            print("  n) No, do not fetch this commit")
            print("    na) No to all - skip fetching for this and all subsequent missing commits")
            choice = input("     Choose an action (y/n/ya/na): ").strip().lower()

            if choice == "y":
                return True
            elif choice == "n":
                return False
            elif choice == "ya":
                self.auto_fetch_commits = True  # Enable for future calls
                return True
            elif choice == "na":
                self._remember_skip_all_fetches = True  # Prevent future prompts
                self.auto_fetch_commits = False  # Ensure auto-fetch is off
                return False
            else:
                print("   Invalid choice. Please try again.")

    def _process_commit(
        self, commit_hash: str, commit_permalinks: List[PermalinkInfo], index: int, total: int
    ) -> Tuple[Optional[Tuple[str, Dict[str, str]]], List[Tuple[PermalinkInfo, str]]]:
        """
        Processes a single commit hash and all its associated permalinks.
        Determines if auto-actions apply or if interactive prompting is needed.
        It can modify self.auto_fetch_commits and self._remember_skip_all_fetches
        based on user input if a prompt for fetching is shown.

        Returns lists of (commit_hash, commit_info) tuples for tagging (or None) and
        (permalink_info, repl_url) tuples for replacements
        """
        pending_repls: List[Tuple[PermalinkInfo, str]] = []
        pending_tag: Optional[Tuple[str, Dict[str, str]]] = None

        print(f"\n{'-' * 80}")
        index_msg = f"Commit #{index + 1}/{total}: {commit_hash[:8]} ({len(commit_permalinks)} permalink(s))"
        print(f"\n[*] {index_msg} {'- ' * ((75 - len(index_msg)) // 2)}")

        can_prompt_for_fetch = not self.auto_fetch_commits and not self._remember_skip_all_fetches

        if not fetch_commit_if_missing(
            commit_hash,
            self.auto_fetch_commits,
            self._vprint,
            self._prompt_to_fetch_commit if can_prompt_for_fetch else None,
        ):
            return None, pending_repls  # Skip if commit unavailable

        commit_info = get_commit_info(commit_hash)
        if not commit_info:
            print(f"  ❌ Could not get info for commit {commit_hash}")
            return None, pending_repls

        self._vprint(f"  📝 {commit_info['subject']}")
        self._vprint(f"    👤 Author: {commit_info['author']} ({commit_info['date']})")
        self._vprint(f"  🔗 Referenced in {len(commit_permalinks)} permalink(s)")

        # Check if the commit is already in the main branch
        if is_commit_in_main(commit_hash, self.main_branch):
            print(f"  ✅ Already merged into {self.main_branch}. Permalinks to this commit are safe.")
            return None, pending_repls

        print(f"  ⛓️‍💥️ Not in {self.main_branch}")
        ancestor_commit = find_closest_ancestor_in_main(commit_hash, self.main_branch)

        if ancestor_commit:
            ancestor_info = get_commit_info(ancestor_commit)
            print(f"  ⏪ Closest ancestor in main: {ancestor_commit[:8]} - {ancestor_info['subject'] if ancestor_info else 'Unknown'}")
            if ancestor_info:
                self._vprint(f"    👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")
        else:
            print(f"  ❌ No common ancestor with {self.main_branch} found for {commit_hash[:8]}.")

        pending_tag, repls = self._process_commit_further(
            commit_hash, commit_info, ancestor_commit, commit_permalinks
        )
        pending_repls.extend(repls)

        return pending_tag, pending_repls

    def _process_and_create_tags(self, commits_to_tag: List[Tuple[str, Dict[str, str]]]) -> None:
        """
        Processes commits that need tagging, creates tags locally, or simulates in dry_run.
        And ends by calling the function to push the tags to the remote 'origin'.
        """
        print(f"\n📌 Tagging {len(set(c[0] for c in commits_to_tag))} unique commit(s)")
        created_tag_names = []

        # Deduplicate commits_to_tag by commit_hash, keeping the first encountered commit_info
        unique_commits_to_tag_dict = {
            commit_hash: commit_info for commit_hash, commit_info in reversed(commits_to_tag)
        }
        final_commits_to_tag = [(ch, ci) for ch, ci in unique_commits_to_tag_dict.items()]

        for commit_hash, commit_info in final_commits_to_tag:
            report_entry_for_this_tag = None
            if self.output_json_report_path:
                report_entry_for_this_tag = {
                    "commit_hash": commit_hash,
                    "commit_subject": commit_info.get("subject", "N/A"),
                    # tag_name, tag_message, and status will be set below
                }

            tag_name = gen_git_tag_name(
                commit_hash, commit_info.get("subject", ""), self.tag_prefix
            )

            if git_tag_exists(tag_name):
                print(f"  ✅ Tag {tag_name} already exists for commit {commit_hash[:8]}")
                if report_entry_for_this_tag:  # Still report if it already exists
                    report_entry_for_this_tag["tag_name"] = tag_name
                    report_entry_for_this_tag["tag_message"] = (
                        f"Preserve permalink reference to: {commit_info.get('subject', 'commit ' + commit_hash[:8])}"  # Reconstruct expected message
                    )
                    report_entry_for_this_tag["status"] = "already_exists"
                    self.report_data["tags_created"].append(report_entry_for_this_tag)
                continue

            tag_message = f"Preserve permalink reference to: {commit_info.get('subject', 'commit ' + commit_hash[:8])}"

            if report_entry_for_this_tag:
                report_entry_for_this_tag["tag_name"] = tag_name
                report_entry_for_this_tag["tag_message"] = tag_message

            tag_created_successfully_or_simulated = create_git_tag(
                tag_name, commit_hash, tag_message, self.dry_run
            )

            if tag_created_successfully_or_simulated:
                if self.dry_run:  # Message already printed by execute_git_tag_creation
                    if report_entry_for_this_tag:
                        report_entry_for_this_tag["status"] = "would_create"
                else:
                    # Message already printed by execute_git_tag_creation
                    # print(f"  🏷️ For commit {commit_hash[:8]}, successfully created tag: {tag_name}")
                    if report_entry_for_this_tag:
                        report_entry_for_this_tag["status"] = "created"
                created_tag_names.append(tag_name)
            else:
                # Error message already printed by execute_git_tag_creation
                if report_entry_for_this_tag:
                    report_entry_for_this_tag["status"] = "failed_to_create"

            if report_entry_for_this_tag and "status" in report_entry_for_this_tag:
                self.report_data["tags_created"].append(report_entry_for_this_tag)

        self._push_created_tags(created_tag_names)

    def _push_created_tags(self, created_tag_names: List[str]) -> None:
        """
        Pushes the given list of created tags to the remote 'origin'.
        This method respects self.dry_run.
        """
        if not created_tag_names:  # No new tags were actually created (e.g. all existed or failed)
            if self.dry_run and any(
                entry.get("status") == "would_create"
                for entry in self.report_data.get("tags_created", [])
            ):
                self._vprint(
                    "  🧪 DRY RUN: Would attempt to push tags if not in dry run and tags were newly created."
                )
            else:
                self._vprint("  ℹ️ No new tags were marked for creation/pushing, or all failed.")
            return

        if self.dry_run:
            self._vprint(
                f"  🧪 DRY RUN: Would attempt to push {len(created_tag_names)} tags if not in dry run: {', '.join(created_tag_names)}"
            )
            return

        # In non-dry run, created_tag_names should only contain successfully created tags.
        if created_tag_names:
            print(f"\n🚀 Pushing {len(created_tag_names)} created tags to origin…")
            try:
                push_command = ["git", "push", "origin"] + created_tag_names
                subprocess.run(
                    push_command,
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

    def run(self) -> None:
        """Main execution function."""
        self._vprint(f"Repository: {self.repo_root}")
        self._vprint(f"GitHub: {self.git_owner}/{self.git_repo}")
        self._vprint(f"Main branch: {self.main_branch}, Tag prefix: {self.tag_prefix}")
        self._vprint(f"Repo aliases: {self.repo_aliases if self.repo_aliases else 'None'}")
        self._vprint(
            f"Respect gitignore: {self.respect_gitignore}, "
            f"Dry run: {self.dry_run}, Auto fetch: {self.auto_fetch_commits}, "
            f"Auto accept replace: {self.auto_accept_replace}, Auto fallback: {self.auto_fallback}"
        )
        if self.output_json_report_path:
            self._vprint(f"JSON Report output: {self.output_json_report_path}")
        self._vprint(
            f"Line shift tolerance: {self.line_shift_tolerance_str} (parsed as: {'percentage' if self.tolerance_is_percentage else 'absolute'}, value: {self.tolerance_value})"
        )
        self._vprint("-" * 50)

        # Find all permalink commits
        permalinks = self.find_github_permalinks()
        if not permalinks:
            print("No GitHub permalinks found in this repository.")
            self._write_json_report()  # Write empty report if path specified
            return

        num_unique_commits, num_unique_files = PermalinkInfo.count_unique_commits_and_files(
            permalinks
        )
        self._vprint(
            f"\nFound {len(permalinks)} GitHub permalinks in {num_unique_files} unique file(s) referencing {num_unique_commits} unique commit(s)"
        )

        # Group permalinks by commit hash
        commits_to_process_map: dict[str, list[PermalinkInfo]] = {}
        for permalink in permalinks:
            commits_to_process_map.setdefault(permalink.commit_hash, []).append(permalink)

        all_pending_tags: List[Tuple[str, Dict[str, str]]] = []
        all_pending_repls: List[Tuple[PermalinkInfo, str]] = []

        # This is the main loop.
        # Process each commit and its permalinks, handling auto-replace, auto-tag, or interactive prompts.
        # Actual file modifications and tagging are done later.
        for index, (commit_hash, commit_permalinks) in enumerate(
            commits_to_process_map.items()
        ):
            tag_for_commit, repls_from_commit = self._process_commit(
                commit_hash, commit_permalinks, index, len(commits_to_process_map)
            )
            if tag_for_commit:
                all_pending_tags.append(tag_for_commit)
            all_pending_repls.extend(repls_from_commit)

        print(f"\n{'=' * 80}")

        # Populate report data for replacements
        if self.output_json_report_path and all_pending_repls:
            for pl_info, repl_url in all_pending_repls:
                self.report_data["replacements"].append(
                    {
                        "original_url": pl_info.url,
                        "new_url": repl_url,
                        "found_in_file": str(pl_info.found_in_file.relative_to(self.repo_root)),
                        "found_at_line": pl_info.found_at_line,
                    }
                )

        # Perform actual file modifications for replacements
        if all_pending_repls:
            # Use the helper method to count unique files involved in replacements
            repls_by_file: Dict[Path, List[Tuple[PermalinkInfo, str]]] = {}
            for pl_info, repl_url in all_pending_repls:
                repls_by_file.setdefault(pl_info.found_in_file, []).append(
                    (pl_info, repl_url)
                )

            sorted_file_paths_for_replacement = sorted(repls_by_file.keys())

            if self.dry_run:
                print(
                    f"\n🧪 DRY RUN SUMMARY: Would perform {len(all_pending_repls)} replacement(s) in {len(sorted_file_paths_for_replacement)} unique file(s):\n"
                )
            else:
                print(
                    f"\n🏃 Performing {len(all_pending_repls)} permalink replacement(s) in {len(sorted_file_paths_for_replacement)} file(s)…"
                )

            global_repl_idx = 0
            for group_idx, file_path_for_repl in enumerate(
                sorted_file_paths_for_replacement
            ):
                repls_for_file = repls_by_file[file_path_for_repl]
                repls_for_file.sort(key=lambda item: item[0].found_at_line)

                print(
                    f"\n#{group_idx + 1}/{len(sorted_file_paths_for_replacement)} files: {file_path_for_repl.relative_to(self.repo_root)} ({len(repls_for_file)} replacement(s))"
                )

                for pl_info, repl_url in repls_for_file:
                    global_repl_idx += 1
                    print(f"  {global_repl_idx:3d}. Line {pl_info.found_at_line}:")
                    print(f"    🔗 OLD: {pl_info.url}")
                    print(f"    ✨ NEW: {repl_url}")

                    if not self.dry_run:
                        self._perform_replacement(pl_info, repl_url)

        else:  # No replacements to make
            if self.dry_run:
                print("\n🧪 DRY RUN: No permalink replacements to make.")
            else:
                print("\nℹ️ No permalink replacements were made.")

        # Process and create tags for all commits that need tagging
        if all_pending_tags:
            self._process_and_create_tags(all_pending_tags)
        elif self.dry_run:  # No tags to create, but it's a dry run
            print("\n🧪 DRY RUN: No commits identified for tagging.")
        else:  # No tags to create, not a dry run
            print("\nℹ️ No commits were identified for tagging.")

        self._write_json_report()
        print("\n🏁 Permalink checking complete.")

    def _write_json_report(self):
        """Writes the collected report data to a JSON file if a path is specified."""
        if not self.output_json_report_path:
            return

        try:
            # Ensure parent directory exists
            self.output_json_report_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_json_report_path, "w", encoding="utf-8") as f:
                json.dump(self.report_data, f, indent=2)
            print(f"\n📝 JSON report written to: {self.output_json_report_path}")
        except IOError as e:
            print(
                f"\n❌ Error writing JSON report to {self.output_json_report_path}: {e}",
                file=sys.stderr,
            )


def main():
    parser = argparse.ArgumentParser(
        description="Finds GitHub commit permalinks, checks their status relative to the main branch, and assists in preserving or updating them.",
        formatter_class=argparse.RawTextHelpFormatter,  # Allows for better formatting of help
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output for more detailed logging.",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="Show what would be done without making any changes (tags, file modifications, or remote pushes).\n"
        "Note: will still attempt to fetch commits if they are not found locally.",
    )
    parser.add_argument(
        "-I",
        "--no-ignore",
        action="store_false",
        dest="respect_gitignore",  # By default, respect_gitignore will be True
        help="Disable checking .gitignore. By default, files ignored by git are skipped.\n"
        "Set this flag to include them in the search (current behavior before this flag).",
    )
    parser.add_argument(
        "--repo-alias",
        dest="repo_aliases",
        default=[],
        action="append",
        help="Alternative repository names (e.g., 'old-repo-name' 'project-alias') that should be\n"
        "considered aliases for the current repository when parsing permalinks.\n"
        "This flag can be used multiple times to specify different aliases.",
    )
    parser.add_argument(
        "--main-branch",
        default="main",
        help="Specify the main branch name (default: %(default)s).",
    )
    parser.add_argument(
        "--tag-prefix",
        default="permalinks/ref",
        help="Specify the tag prefix for preserving commits (default: %(default)s).",
    )
    parser.add_argument(
        "--auto-fetch-commits",
        action="store_true",
        help="Automatically attempt to fetch commits not found locally from the 'origin' remote.",
    )
    parser.add_argument(
        "--auto-accept-replace",
        action="store_true",
        help="Automatically accept suggested replacements if verification is successful (e.g. ancestor found and lines match within tolerance,\n"
             "or user manually resolved to a verifiable state). Bypasses the final action prompt for these cases.",
    )
    parser.add_argument(
        "--auto-fallback",
        choices=["tag", "skip"],
        default=None,
        help="If a permalink cannot be successfully replaced (e.g., no ancestor, or line content verification fails and isn't resolved by user),\n"
             "automatically choose a fallback action: 'tag' the original commit or 'skip' the permalink.\n"
             "Bypasses the final action prompt for these fallback cases.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Enable non-interactive mode. This is a shorthand for setting:\n"
        "  --auto-accept-replace\n"
        "  --auto-fallback tag\n" # Default to tagging for preservation in non-interactive
        "  --auto-fetch-commits\n"
        "User will not be prompted for decisions.",
    )
    parser.add_argument(
        "--line-shift-tolerance",
        type=str,
        default="20",
        help="Max number of lines to shift up/down when searching for matching content in ancestor commits"
        " (default: %(default)s).\n"
        "Can be an absolute number (e.g., '20') or a percentage of the target file's lines (e.g., '10%%').\n"
        "Set to '0' or '0%%' to disable shifting.",
    )
    parser.add_argument(
        "--output-json-report",
        type=str,
        default=None,
        help="File path to output a JSON report of actions (replacements and tags).",
    )

    args = parser.parse_args()

    if args.non_interactive:
        args.auto_accept_replace = True
        args.auto_fallback = "tag" # Default fallback for non-interactive is to tag
        args.auto_fetch_commits = True
        if args.verbose:
            print(
                f"ℹ️ Non-interactive mode enabled: --auto-accept-replace, --auto-fallback={args.auto_fallback}, and --auto-fetch-commits are active."
            )

    try:
        checker = GitPermalinkChecker(
            verbose=args.verbose,
            dry_run=args.dry_run,
            respect_gitignore=args.respect_gitignore,
            repo_aliases=args.repo_aliases,
            main_branch=args.main_branch,
            tag_prefix=args.tag_prefix,
            auto_fetch_commits=args.auto_fetch_commits,
            auto_accept_replace=args.auto_accept_replace,
            auto_fallback=args.auto_fallback,
            line_shift_tolerance=args.line_shift_tolerance,
            output_json_report=args.output_json_report,
        )
        checker.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except RuntimeError as e:  # Catch specific custom errors
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # Catch other unexpected errors
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()
