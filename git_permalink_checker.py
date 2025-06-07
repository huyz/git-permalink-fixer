#!/usr/bin/env python3
"""
GitHub Permalink Persistence Checker
====================================

Finds GitHub commit permalinks in a repository, checks if commits are merged
into `main` and, for unmerged commits, tries to find the closest ancestor in `main`
(and checks that any line references still make sense).
For unmerged commits, it prompts the user to either tag the commit to preserve
the permalink or replace the permalink with a new one pointing to the ancestor
commit.

The goal is to avoid git's garbage collection from nuking commits that it thinks
are no longer referenced.

Usage
-----

python3 git_permalink_checker.py [OPTIONS]

For all flags, run `python3 git_permalink_checker.py -h`


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

- 2025-06-01 Authored by huyz and AI
"""

import argparse
import re
import subprocess
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

from git_permalink_checker_lib.file_ops import (
    extract_permalinks_from_file_lines,
    should_skip_file_search,
    parse_github_permalink,
)
from git_permalink_checker_lib.git_utils import (
    get_repo_root,
    get_remote_url,
    is_commit_in_main,
    get_commit_info,
    find_closest_ancestor_in_main,
    file_exists_at_commit,
    get_file_content_at_commit,
    generate_git_tag_name,
    git_tag_exists,
    execute_git_tag_creation,
    fetch_commit_if_missing,
    get_github_info_from_url,
)
from git_permalink_checker_lib.permalink import PermalinkInfo
from git_permalink_checker_lib.web_utils import open_urls_in_browser


class GitPermalinkChecker:
    repo_root: Path

    def __init__(
        self,
        verbose: bool = False,
        dry_run: bool = False,
        main_branch: str = "main",
        tag_prefix: str = "permalinks/ref",
        auto_fetch_commits: bool = False,
        auto_replace: bool = False,
        auto_tag: bool = False,
        line_shift_tolerance: str = "20",
        repo_aliases: Optional[List[str]] = None,
        respect_gitignore: bool = True,
        output_json_report: Optional[str] = None,
    ):
        self.verbose = verbose
        self.dry_run = dry_run
        self.main_branch = main_branch
        self.tag_prefix = tag_prefix
        self.auto_fetch_commits = auto_fetch_commits
        self.auto_replace = auto_replace
        self.auto_tag = auto_tag
        self.respect_gitignore = respect_gitignore
        self.output_json_report_path = Path(output_json_report) if output_json_report else None
        self.report_data: Dict[str, List] = {"replacements": [], "tags_created": []}
        self.repo_aliases = [alias.lower() for alias in repo_aliases] if repo_aliases else []

        self.line_shift_tolerance_str = line_shift_tolerance # Store original for display/prompts
        self.tolerance_is_percentage, self.tolerance_value = GitPermalinkChecker._parse_tolerance_input(line_shift_tolerance)

        # Initialize repo and GitHub info first, as _load_ignored_paths might need them
        self.repo_root = get_repo_root()
        self.remote_url = get_remote_url()
        self.github_owner, self.github_repo = get_github_info_from_url(self.remote_url)

        # For remembering choices in interactive mode
        self.remembered_choice_with_ancestor: Optional[str] = None
        self.remembered_choice_no_ancestor: Optional[str] = None
        self._remember_skip_all_fetches: bool = False
        self.ignored_paths_set: Set[Path] = self._load_ignored_paths() if self.respect_gitignore else set()

    @staticmethod
    def _parse_tolerance_input(tolerance_str: str) -> Tuple[bool, int]:
        """
        Parses the line shift tolerance string and validates it.
        Returns: (is_percentage, value)
        Raises ValueError if the format or value is invalid.
        """
        if tolerance_str.endswith("%"):
            try:
                val = int(tolerance_str[:-1])
                if not (0 <= val <= 100):
                    raise ValueError("Percentage tolerance must be between 0% and 100%.")
                return True, val
            except ValueError as e:
                raise ValueError(f"Invalid percentage tolerance format '{tolerance_str}': {e}")
        else:
            try:
                val = int(tolerance_str)
                if val < 0:
                    raise ValueError("Absolute line shift tolerance cannot be negative.")
                return False, val
            except ValueError as e:
                raise ValueError(f"Invalid absolute tolerance format '{tolerance_str}': {e}")


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
                capture_output=True, text=True, check=True, encoding="utf-8"
            )
            for line in result.stdout.splitlines():
                if line.startswith("!! "):
                    # Output is "!! path/to/item", path is relative to repo root
                    ignored_item_relative_path = line[3:].strip()
                    ignored_set.add(self.repo_root / ignored_item_relative_path)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            self._vprint(f"Warning: Could not get git ignored paths: {e}. Gitignore rules will not be applied effectively.")
        return ignored_set

    def _vprint(self, *args, **kwargs):
        """Prints only if verbose mode is enabled."""
        if self.verbose:
            print(*args, **kwargs)

    def _normalize_repo_name(self, repo_name: str) -> str:
        """
        Normalizes a repository name for comparison against the current repository.

        If the given repo_name (case-insensitive) matches the main repository name
        (self.github_repo) or is one of its configured aliases (self.repo_aliases),
        this method returns the lowercased main repository name.
        Otherwise, it returns the lowercased version of the input repo_name.
        """
        if not repo_name:
            return repo_name
        lower_repo_name = repo_name.lower()
        if lower_repo_name == self.github_repo.lower() or lower_repo_name in self.repo_aliases:
            return self.github_repo.lower()
        return lower_repo_name

    @staticmethod
    def _count_unique_commits_and_files(permalinks: List[PermalinkInfo]) -> Tuple[int, int]:
        """Helper to count unique commit hashes and unique files from a list of permalinks."""
        unique_commits = set()
        unique_files = set()
        for permalink in permalinks:
            unique_commits.add(permalink.commit_hash)
            unique_files.add(permalink.found_in_file)
        return len(unique_commits), len(unique_files)

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
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f_ignored:
                            lines_ignored = f_ignored.readlines()
                        # Use a temporary count, don't affect main found_count or detailed logging
                        permalinks_in_ignored_file, _, _ = extract_permalinks_from_file_lines(
                            file_path, lines_ignored, self.repo_root, self.github_owner,
                            self.github_repo, 0, self._normalize_repo_name,
                        )
                        if permalinks_in_ignored_file:
                            self._vprint(
                                f"  🙈 gitignored file with {len(permalinks_in_ignored_file)} permalink(s): {file_path.relative_to(self.repo_root)}"
                            )
                    except (UnicodeDecodeError, IOError, OSError, PermissionError) as e_log:
                        self._vprint(f"  ⚠️ Could not read gitignored file {file_path.relative_to(self.repo_root)} for special logging: {e_log}")
                continue

            # If process_this_file is True, proceed with normal processing
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                (
                    permalinks_in_file,
                    found_count,
                    _,
                ) = extract_permalinks_from_file_lines(
                    file_path,
                    lines,
                    self.repo_root,
                    self.github_owner,
                    self.github_repo,
                    found_count,
                    self._normalize_repo_name,
                )
                permalinks.extend(permalinks_in_file)
            except (UnicodeDecodeError, IOError, OSError, PermissionError) as e:
                print(f"Warning: Could not read {file_path}: {e}")
                continue

        return permalinks

    def _create_replacement_permalink(
        self,
        original: PermalinkInfo,
        new_commit_hash: str,
        replacement_url_path: Optional[str],  # The file path for the new permalink
        replacement_line_start: Optional[int] = None,
        replacement_line_end: Optional[int] = None,
    ) -> str:
        """Create a replacement permalink URL."""
        # Determine if the original URL used 'blob' or 'tree'
        match = re.search(r"github\.com/[^/]+/[^/]+/(blob|tree)/", original.url)
        url_type = match.group(1) if match else "blob"
        base_url = f"https://github.com/{self.github_owner}/{self.github_repo}/{url_type}/{new_commit_hash}"

        if replacement_url_path:  # Use the provided replacement_url_path
            url = f"{base_url}/{replacement_url_path}"

            # Line numbers only make sense for blobs
            if url_type == "blob" and replacement_line_start:
                if replacement_line_end and replacement_line_end != replacement_line_start:
                    url += f"#L{replacement_line_start}-L{replacement_line_end}"
                else:  # Single line
                    url += f"#L{replacement_line_start}"
            return url
        else:  # No file_path, likely a /tree/ link
            return (
                f"https://github.com/{self.github_owner}/{self.github_repo}/tree/{new_commit_hash}"
            )

    def _verify_line_content(
        self,
        original: PermalinkInfo,  # Defines original content source (commit, path, lines)
        replacement_commit_hash: str,  # Commit to check in
        replacement_url_path: str,  # File path to check in replacement_commit_hash
        custom_tolerance: Optional[int] = None,  # Optional line shift tolerance
    ) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Verify line content, allowing for shifts. Strips leading/trailing whitespace.
        Returns: (match_found, new_line_start_in_replacement, new_line_end_in_replacement)
        The new_line_start/end are for the replacement_commit if match_found is True.
        A custom_tolerance can be provided to override self.line_shift_tolerance.
        If the original permalink has no line numbers or no replacement_url_path,
        returns (True, None, None) or (False, None, None).
        """
        if not original.url_path or original.line_start is None or not replacement_url_path:
            return True, None, None  # Vacuously true, no specific lines to verify

        original_content_lines = get_file_content_at_commit(
            original.commit_hash, original.url_path
        )
        replacement_content_lines = get_file_content_at_commit(
            replacement_commit_hash,
            replacement_url_path,  # Use the specified path for replacement
        )

        if not original_content_lines or not replacement_content_lines:
            return False, None, None  # Content not available

        try:
            start_idx_orig = original.line_start - 1
            end_idx_orig = (original.line_end or original.line_start) - 1

            if not (
                0 <= start_idx_orig < len(original_content_lines)
                and 0 <= end_idx_orig < len(original_content_lines)
                and start_idx_orig <= end_idx_orig
            ):
                return False, None, None  # Original line numbers out of bounds

            target_original_stripped_lines = [
                line.strip() for line in original_content_lines[start_idx_orig : end_idx_orig + 1]
            ]
            if not target_original_stripped_lines:
                return False, None, None

            num_target_lines = len(target_original_stripped_lines)

            effective_tolerance_lines: int
            if custom_tolerance is not None: # custom_tolerance is always absolute
                effective_tolerance_lines = custom_tolerance
            elif self.tolerance_is_percentage:
                # This part assumes replacement_content_lines is available if we need to calculate percentage.
                # The function structure ensures replacement_content_lines is fetched early if original.url_path is valid.
                # If replacement_content_lines is None here, it means the file content wasn't available,
                # and the function would have returned (False, None, None) earlier.
                if not replacement_content_lines: # Should ideally not happen if logic flows correctly
                    self._vprint(f"Warning: Could not determine replacement content lines for percentage tolerance calculation for {replacement_url_path}")
                    return False, None, None
                num_lines_in_replacement = len(replacement_content_lines)
                effective_tolerance_lines = int(num_lines_in_replacement * (self.tolerance_value / 100.0))
            else: # Absolute tolerance from self (self.tolerance_value)
                effective_tolerance_lines = self.tolerance_value

            # Try all shifts from 0 outward, alternating +shift and -shift
            for offset in range(0, effective_tolerance_lines + 1):
                for shift in (offset, -offset) if offset != 0 else (0,):
                    shifted_start_idx_repl = start_idx_orig + shift
                    if 0 <= shifted_start_idx_repl < len(replacement_content_lines) and (
                        shifted_start_idx_repl + num_target_lines
                    ) <= len(replacement_content_lines):
                        candidate_stripped_lines = [
                            line.strip()
                            for line in replacement_content_lines[
                                shifted_start_idx_repl : shifted_start_idx_repl + num_target_lines
                            ]
                        ]
                        if target_original_stripped_lines == candidate_stripped_lines:
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

    def _prompt_user_to_resolve_url_path(
        self,
        original: PermalinkInfo,
        ancestor_commit: str,
        initial_path_to_check: str,
        initial_ls: Optional[int],
        initial_le: Optional[int],
    ) -> Tuple[Optional[str], Optional[int], Optional[int], bool]:
        """
        Interactively resolve the file path for replacement if it's missing in the ancestor.
        Returns: (resolved_file_path, resolved_ls, resolved_le, should_abort_permalink)
        """
        path_to_check = initial_path_to_check
        current_ls, current_le = initial_ls, initial_le

        while not file_exists_at_commit(ancestor_commit, path_to_check):
            self._vprint(
                f"\n❌ File '{path_to_check}' (from original or last input) does not exist in ancestor {ancestor_commit[:8]}"
            )
            print("\n❓ MISSING FILE RESOLUTION:")
            print("  o) Open original URL (and attempted replacement) in browser")
            print(
                "  m) MANUALLY enter new file path for replacement (relative to repo root, or full GitHub URL)"
            )
            print("  k) KEEP current path for replacement URL (it will likely be broken)")
            print("  a) ABORT replacement for this permalink (skip)")
            menu_choice = input("\nSelect resolution for missing file (o,m,k,a): ").strip().lower()

            if menu_choice == "o":
                broken_replacement_url = self._create_replacement_permalink(
                    original, ancestor_commit, path_to_check, current_ls, current_le
                )
                urls_to_open = [
                    ("original URL", original.url),
                    ("(likely broken) replacement URL", broken_replacement_url)
                ]
                open_urls_in_browser(urls_to_open)
                continue  # Re-prompt
            elif menu_choice == "m":
                # The user may enter:
                # - a relative path from the repo root,
                # - a full path that starts with the prefix of the repo root,
                # - or a full GitHub URL that starts with the same prefix as the original URL.
                new_input = input("    Enter new file path or full GitHub URL for replacement: ").strip()
                if not new_input:
                    print("    Input cannot be empty. Try again.")
                    continue # Re-prompt for manual input

                is_url_attempt = new_input.lower().startswith("https://")
                if is_url_attempt:
                    # Attempt to parse as a GitHub URL
                    parsed_info_from_url = parse_github_permalink(
                        new_input, self.github_owner, self.github_repo, self._normalize_repo_name
                    )
                    if parsed_info_from_url:
                        # Successfully parsed as a URL for *this* repo
                        if parsed_info_from_url.url_path: # It must point to a file
                            print(f"    Parsed as URL. Using file path: '{parsed_info_from_url.url_path}'")
                            path_to_check = parsed_info_from_url.url_path
                            # Update line numbers if present in the URL, otherwise clear them
                            current_ls = parsed_info_from_url.line_start
                            current_le = parsed_info_from_url.line_end
                        else:
                            # URL parsed for this repo, but no file_path (e.g. base tree/commit link)
                            print(f"    The GitHub URL '{new_input}' does not point to a specific file. Please provide a URL that includes a file path, or enter a file path directly.")
                            continue # Re-prompt for manual input
                    else:
                        # Input looked like a URL, but parsing failed (malformed or wrong repo)
                        print(f"    The input '{new_input}' is not a valid GitHub URL for the current repository ({self.github_owner}/{self.github_repo}), or it's malformed. Please provide a valid URL for this repository or a file path.")
                        continue # Re-prompt for manual input
                else: # Input is treated as a file path (relative or absolute)
                    input_path_obj = Path(new_input)
                    new_relative_path_str: Optional[str] = None
                    if input_path_obj.is_absolute():
                        try:
                            # Convert an absolute path to relative if it's within the repo root
                            relative_path = input_path_obj.relative_to(self.repo_root)
                            new_relative_path_str = str(relative_path)
                        except ValueError:
                            print(f"    Absolute path '{new_input}' is not within the repository root '{self.repo_root}'. Please provide a relative path, an absolute path within the repository, or a full GitHub URL.")
                            continue # Re-prompt for manual input
                    else: # Input is a relative path
                        new_relative_path_str = new_input

                    if new_relative_path_str is not None:
                        print(f"    Using file path: '{new_relative_path_str}'. Line numbers will be re-evaluated based on original permalink if applicable.")
                        path_to_check = new_relative_path_str
                        # Line numbers (current_ls, current_le) are not modified here by path input;
                        # they retain values from original permalink or previous URL input.
                continue # Loop will re-evaluate existence

            elif menu_choice == "k":
                print(f"    Keeping path '{path_to_check}' for replacement URL, though it's missing in ancestor.")
                return path_to_check, current_ls, current_le, False  # Keep the path, don't abort

            elif menu_choice == "a":
                print("    Aborting replacement for this permalink.")
                return path_to_check, current_ls, current_le, True # Abort
            else:
                print("    Invalid choice. Try again.")

        return path_to_check, current_ls, current_le, False # File exists, don't abort

    def _prompt_user_to_resolve_line_mismatch(
        self,
        original: PermalinkInfo,
        ancestor_commit: str,
        replacement_url_path: str, # Already confirmed to exist in ancestor
        initial_ls: Optional[int],
        initial_le: Optional[int],
    ) -> Tuple[Optional[int], Optional[int], bool]:
        """
        Interactively resolve line number mismatches.
        Returns: (resolved_ls, resolved_le, should_abort_permalink)
        """
        current_ls, current_le = initial_ls, initial_le
        while True:
            print("\n❓ LINE MISMATCH RESOLUTION:")
            print("  o) Open original URL (and attempted replacement) in browser")
            print("  l) Retry with different line shift TOLERANCE for search")
            print("  m) MANUALLY enter new line numbers (e.g., 10 or 10-15) OR a full GitHub URL for replacement")
            print("  c) CLEAR line numbers from replacement URL")
            print("  k) KEEP original line numbers in replacement URL")
            print("  a) ABORT replacement (skip this permalink for now)")
            menu_choice = input("\nSelect resolution for lines (o,l,m,c,k,a): ").strip().lower()

            if menu_choice == "o":
                broken_replacement_url = self._create_replacement_permalink(
                    original, ancestor_commit, replacement_url_path, current_ls, current_le
                )
                urls_to_open = [
                    ("original URL", original.url),
                    ("(likely broken) replacement URL", broken_replacement_url)
                ]
                open_urls_in_browser(urls_to_open)
                continue  # Re-prompt
            elif menu_choice == 'l':
                abs_custom_tolerance: int
                try:
                    new_tol_str = input(f"    Enter new tolerance (current global: {self.line_shift_tolerance_str}, e.g., 20 or 10%, 0 to disable shift): ").strip()
                    if not new_tol_str:
                        print("    Input cannot be empty. Try again.")
                        continue

                    is_percentage, val = GitPermalinkChecker._parse_tolerance_input(new_tol_str)

                    if is_percentage:
                        # Fetch replacement content lines to calculate absolute tolerance
                        replacement_content_lines_for_calc = get_file_content_at_commit(ancestor_commit, replacement_url_path)
                        if not replacement_content_lines_for_calc:
                            print(f"    ⚠️ Could not fetch content of '{replacement_url_path}' in ancestor to calculate percentage. Try absolute tolerance.")
                            continue
                        num_lines = len(replacement_content_lines_for_calc)
                        abs_custom_tolerance = int(num_lines * (val / 100.0))
                        self._vprint(f"    ℹ️ Using {val}% of {num_lines} lines = {abs_custom_tolerance} lines tolerance for this check.")
                    else:
                        abs_custom_tolerance = val

                    print(f"\n🔄 Re-checking with tolerance {abs_custom_tolerance} lines...")
                    match, ls, le = self._verify_line_content(original, ancestor_commit, replacement_url_path, custom_tolerance=abs_custom_tolerance)
                    if match:
                        print(f"✅ Match found with new tolerance at L{ls}" + (f"-L{le}" if le and le != ls else "") + "!")
                        return ls, le, False # Resolved
                    else:
                        print(f"💥 No match found even with tolerance {abs_custom_tolerance} lines.")
                except ValueError as e:
                    print(f"    Invalid tolerance: {e}")
                    continue # Re-prompt for line mismatch

            elif menu_choice == 'm':
                new_input = input("    Enter new line numbers (e.g., 10 or 10-15) OR a full GitHub URL for replacement: ").strip()
                if not new_input:
                    print("    Input cannot be empty. Try again.")
                    continue

                is_url_attempt = new_input.lower().startswith("https://")
                if is_url_attempt:
                    parsed_info_from_url = parse_github_permalink(new_input, self.github_owner, self.github_repo, self._normalize_repo_name)
                    if parsed_info_from_url:
                        if parsed_info_from_url.url_path:
                            if parsed_info_from_url.url_path == replacement_url_path:
                                self._vprintf(f"    Parsed as URL for file '{replacement_url_path}'. Using line numbers from URL.")
                                return parsed_info_from_url.line_start, parsed_info_from_url.line_end, False # Resolved
                            else:
                                print(f"    ⚠️ The GitHub URL points to a different file ('{parsed_info_from_url.url_path}').")
                        else:
                            # URL parsed for this repo, but no file_path (e.g. base tree/commit link)
                            print(f"    ⚠️ The GitHub URL '{new_input}' does not point to a specific file.");
                    else:
                        print(f"    ⚠️ The input '{new_input}' is not a valid GitHub URL for the current repository ({self.github_owner}/{self.github_repo}), or it's malformed.")
                    continue # Re-prompt for line mismatch
                else: # Input is treated as line numbers
                    try:
                        if '-' in new_input:
                            start_str, end_str = new_input.split('-', 1)
                            new_ls_manual = int(start_str)
                            new_le_manual = int(end_str)
                            if new_ls_manual <= 0 or new_le_manual <= 0 or new_le_manual < new_ls_manual:
                                raise ValueError("Invalid line range.")
                        else:
                            new_ls_manual = int(new_input)
                            if new_ls_manual <= 0:
                                raise ValueError("Line must be positive.")
                            new_le_manual = None # Single line

                        print("    Manually set line numbers for replacement.")
                        return new_ls_manual, new_le_manual, False # Resolved
                    except ValueError as e:
                        print(f"    Invalid line number format: {e}. Expected e.g., '10' or '10-15'.")
                        continue # Re-prompt for line mismatch


            elif menu_choice == 'c':
                return None, None, False # Cleared, resolved
            elif menu_choice == 'k':
                return original.line_start, original.line_end, False # Kept, resolved
            elif menu_choice == 'a':
                return current_ls, current_le, True # Abort
            else:
                print("    Invalid choice. Try again.")

    @staticmethod
    def _prompt_user_for_final_action(
        original: PermalinkInfo,
        has_ancestor: bool,
        replacement_url: Optional[str], # Only if has_ancestor is true
        is_commit_slated_for_tagging: bool,
    ) -> Optional[tuple[str, Optional[str]]]:
        """
        Prompts the user for the final action (replace, tag, skip) and handles remembering choices.
        Returns: (action_string, value_to_remember_if_any)
        """
        print("\n❓ ACTIONS:")
        print(f"  o) Open URL(s) in browser{' (original & replacement)' if has_ancestor else ' (original only)'}")

        if has_ancestor:
            print("  r) Replace with suggested URL (i.e., update reference)")
            print("    ra) Replace ALL from now on (for prompts with ancestors)")

        if is_commit_slated_for_tagging:
            print("  -t) UNTAG this commit")
        else:
            print("  t) Tag original commit (i.e., preserve exact permalink)")
            print(f"    ta) Tag ALL from now on (for prompts {'with' if has_ancestor else 'without'} ancestors)")

        print("  s) Skip this permalink")
        print(f"    sa) Skip ALL from now on (for prompts {'with' if has_ancestor else 'without'} ancestors)")

        while True:
            action: Optional[str] = None
            remember_this_choice: Optional[str] = None

            prompt_options = "o,"
            if has_ancestor:
                prompt_options += "r,ra,"
            prompt_options += "-t," if is_commit_slated_for_tagging else "t,ta,"
            prompt_options += "s,sa"
            menu_choice = input(f"\nSelect action ({prompt_options}): ").strip().lower()

            if menu_choice == "o":
                urls_to_open_list = [("original URL", original.url)]
                if has_ancestor and replacement_url:
                    urls_to_open_list.append(("suggested replacement URL", replacement_url))
                open_urls_in_browser(urls_to_open_list)
                continue
            elif menu_choice == "r" and has_ancestor:
                action = "replace"
            elif menu_choice == "ra" and has_ancestor and replacement_url:
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
            elif menu_choice == "sa":
                action, remember_this_choice = "skip", "skip"

            if action:
                return action, remember_this_choice
            print("    Invalid choice. Please try again.")

    def _prompt_user_for_replacement(
        self,
        original: PermalinkInfo,
        ancestor_commit: Optional[str],
        file_path: Path, # File where permalink is found, for context
        index: int,
        total: int,
        is_commit_slated_for_tagging: bool, # NEW: Is the parent commit already marked for tagging?
    ) -> Tuple[str, Optional[str], Optional[int], Optional[int]]:
        """
        Prompt user to confirm replacement permalink.
        Returns a tuple: (
            action_str,
            effective_replacement_url_path,
            new_line_start_for_replacement,
            new_line_end_for_replacement).
        The line numbers are only relevant if action_str is "replace".
        """
        has_ancestor = ancestor_commit is not None
        remembered_choice_key = "with_ancestor" if has_ancestor else "no_ancestor"
        remembered_choice = getattr(self, f"remembered_choice_{remembered_choice_key}")

        if remembered_choice:
            # If choice is remembered, we assume it implies how to handle lines too (e.g., auto-replace logic)
            self._vprint(f"    🤖 Using remembered choice: {remembered_choice}")
            return ( # Return the remembered action, and default path/lines
                remembered_choice,
                original.url_path,
                original.line_start,
                original.line_end,
            )  # Default path and lines if remembered

        index_message = f"Permalink #{index + 1}/{total} for {original.commit_hash[:8]}"
        print(f"\n    [*] {index_message} {'- ' * ((75 - len(index_message)) // 2)}")
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

        replacement_url: Optional[str] = None  # Will be set if ancestor exists
        # These will store the line numbers to be used in the *final* replacement URL
        current_replacement_ls: Optional[int] = original.line_start
        current_replacement_le: Optional[int] = original.line_end
        # This will be the file path used for the replacement link.
        effective_replacement_url_path: Optional[str] = original.url_path

        if has_ancestor and ancestor_commit:
            ancestor_info = get_commit_info(ancestor_commit)
            if ancestor_info:
                self._vprint(
                    f"⏪ Suggested ancestor commit: {ancestor_commit[:8]} - {ancestor_info['subject']}"
                )
                self._vprint(f"   👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")

            # --- Stage 1: Resolve File Path for Replacement, if original had one ---
            if original.url_path:
                ( # Ensure file_exists_at_commit is called with self if it's a method
                    effective_replacement_url_path,
                    current_replacement_ls,
                    current_replacement_le,
                    abort_url_path_resolution,
                ) = self._prompt_user_to_resolve_url_path(
                    original,
                    ancestor_commit,
                    original.url_path, # initial path to check (this needs to be self.file_exists_at_commit)
                    current_replacement_ls,
                    current_replacement_le,
                )
                if abort_url_path_resolution:
                    return "skip", effective_replacement_url_path, None, None

            # Content verification and sub-prompt logic
            if (
                effective_replacement_url_path and original.line_start is not None
            ):  # Only verify if lines are expected and we have a path
                if file_exists_at_commit(ancestor_commit, effective_replacement_url_path):
                    match_found, verified_ls, verified_le = self._verify_line_content(
                        original, ancestor_commit, effective_replacement_url_path
                    )
                    if match_found:
                        current_replacement_ls = verified_ls
                        current_replacement_le = verified_le
                        original_line_range_str = f"L{original.line_start}"
                        if original.line_end and original.line_end != original.line_start:
                            original_line_range_str += f"-L{original.line_end}"

                        if verified_ls == original.line_start and verified_le == original.line_end:
                            print(f"✅ Line content matches at {original_line_range_str}")
                        else:
                            verified_line_range_str = f"L{verified_ls}"
                            if (
                                verified_le and verified_le != verified_ls
                            ):  # verified_le can be None
                                verified_line_range_str += f"-L{verified_le}"
                            print(
                                f"✅ Line content matches, found at {verified_line_range_str} in ancestor (original was {original_line_range_str})"
                            )
                    else:
                        print("💥 Line content differs in ancestor, even with default tolerance.")
                        (
                            current_replacement_ls,
                            current_replacement_le,
                            aborted_line_mismatch,
                        ) = self._prompt_user_to_resolve_line_mismatch(
                            original,
                            ancestor_commit,
                            effective_replacement_url_path,
                            current_replacement_ls,
                            current_replacement_le,
                        )
                        if aborted_line_mismatch:
                            return "skip", effective_replacement_url_path, None, None
                else:
                    print(
                        f"❌ File '{effective_replacement_url_path}' does not exist in suggested ancestor commit {ancestor_commit[:8]}"
                    )
                    # This sub-prompt is for when lines were expected, but the file (chosen via 'k' or initial bad path) is missing.
                    while True:
                        # This is the existing "MISSING FILE RESOLUTION" but it's actually "LINES FOR MISSING FILE"
                        print("\nMISSING FILE RESOLUTION:")
                        print("  m. MANUALLY enter new line numbers (assumes file path is still desired)")
                        print(
                            "  c. CLEAR line numbers from replacement URL (keeps file path if present)"
                        )
                        print(
                            "  k. KEEP original line numbers in replacement URL (file path and lines may be invalid)"
                        )
                        print("  a. ABORT replacement (skip this permalink for now)")
                        menu_choice = (
                            input("\nSelect resolution for lines/file (m,c,k,a): ").strip().lower()
                        )
                        # Manual entry logic is similar to above, simplified as file context is missing
                        if menu_choice == "m":  # Simplified manual entry
                            try:
                                ls_str = input(
                                    "    Enter new START line number (if known, or 0 to clear): "
                                )
                                new_ls_manual = int(ls_str)
                                if new_ls_manual < 0:
                                    raise ValueError("Line number cannot be negative.")
                                current_replacement_ls = (
                                    new_ls_manual if new_ls_manual > 0 else None
                                )
                                current_replacement_le = None  # Assume single line or cleared
                                if (
                                    current_replacement_ls
                                    and original.line_end
                                    and original.line_start
                                    and original.line_end > original.line_start
                                ):  # if original was range
                                    le_str = input(
                                        "    Enter new END line number (or Enter for single line): "
                                    ).strip()
                                    if le_str:
                                        current_replacement_le = int(le_str)
                                print("    Manually set line numbers for replacement.")
                                break
                            except ValueError as e:
                                print(f"    Invalid input: {e}")
                        elif menu_choice == "c":
                            current_replacement_ls = None
                            current_replacement_le = None
                            print("    Line numbers cleared.")
                            break
                        elif menu_choice == "k":
                            current_replacement_ls = original.line_start
                            current_replacement_le = original.line_end
                            print("    Original lines kept.")
                            break  # This keeps original lines, path is effective_replacement_url_path
                        elif menu_choice == "a":
                            print("    Aborting.")
                            return "skip", effective_replacement_url_path, None, None
                        else:
                            print("    Invalid choice.")

            # Create/update the replacement_url with potentially modified line numbers
            replacement_url = self._create_replacement_permalink(
                original,  # For original URL type (blob/tree)
                ancestor_commit,
                effective_replacement_url_path,  # The resolved file path
                current_replacement_ls,  # The resolved line start
                current_replacement_le,  # The resolved line end
            )
            print(f"✨ Suggested replacement URL: {replacement_url}")

        elif not has_ancestor:
            print("  ℹ️ No common ancestor found in the main branch.")

        action, remember_this_choice = self._prompt_user_for_final_action(
            original, has_ancestor, replacement_url,
            is_commit_slated_for_tagging
        )

        if remember_this_choice:
            setattr(self, f"remembered_choice_{remembered_choice_key}", remember_this_choice)

        # "untag" is a specific action returned by _prompt_user_for_final_action
        # It will be handled by _prompt_user_for_commit to re-evaluate the current permalink.
        if action == "untag":
            return "untag", None, None, None # Path/lines not relevant for untag action itself
        elif action == "replace":
            return action, effective_replacement_url_path, current_replacement_ls, current_replacement_le
        elif action == "tag": # This means user chose 't' or 'ta' when commit was NOT slated for tagging
            return action, None, None, None # Path/lines not relevant for tag action itself
        else: # skip
            return action, effective_replacement_url_path, None, None

    def _perform_replacement(self, permalink: PermalinkInfo, replacement_url: str) -> None:
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
            content[permalink.found_at_line - 1] = original_line.replace(
                permalink.url, replacement_url, 1
            )

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(content)

            print(
                f"  ✅ Replaced permalink in {file_path.relative_to(self.repo_root)} at line {permalink.found_at_line}"
            )
        except (IOError, OSError, UnicodeDecodeError, PermissionError) as e:
            print(
                f"  ❌ Failed to replace permalink in {permalink.found_in_file.relative_to(self.repo_root)}: {e}"
            )

    def _perform_auto_replacements_for_commit(
        self,
        commit_hash: str, # The original commit hash of the permalinks
        ancestor_commit: str, # The ancestor commit to replace with
        commit_permalinks: List[PermalinkInfo],
    ) -> List[Tuple[PermalinkInfo, str]]:
        """
        Handles --auto-replace logic for a group of permalinks belonging to the same commit.
        Verifies line content and creates replacement URLs.
        Returns a list of (original_permalink_info, replacement_url_string) tuples.
        """
        replacements = []
        self._vprint(
            f"  🤖 --auto-replace: Processing {len(commit_permalinks)} permalinks for commit {commit_hash[:8]} against ancestor {ancestor_commit[:8]}"
        )
        for permalink in commit_permalinks:
            verified_ls_for_replacement = permalink.line_start
            verified_le_for_replacement = permalink.line_end

            if permalink.url_path and permalink.line_start:
                if file_exists_at_commit(ancestor_commit, permalink.url_path):
                    match_found, new_ls, new_le = self._verify_line_content(
                        permalink, ancestor_commit, permalink.url_path
                    )
                    if match_found:
                        verified_ls_for_replacement = new_ls
                        verified_le_for_replacement = new_le
                        if new_ls == permalink.line_start and new_le == permalink.line_end:
                            self._vprint(f"    - Content for {permalink.url[:60]}... matches at original lines in ancestor.")
                        else:
                            self._vprint(f"    - Content for {permalink.url[:60]}... found shifted in ancestor.")
                    else:
                        self._vprint(f"    - Content for {permalink.url[:60]}... differs or not found in ancestor. Using original lines.")
                else:
                    self._vprint(f"    - File {permalink.url_path} not in ancestor. Using original lines for {permalink.url[:60]}...")

            final_replacement_url = self._create_replacement_permalink(
                permalink, ancestor_commit, permalink.url_path,
                verified_ls_for_replacement, verified_le_for_replacement
            )
            replacements.append((permalink, final_replacement_url))
        return replacements

    def _prompt_user_for_commit(
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
        tag_to_create_for_commit: Optional[Tuple[str, Dict[str, str]]] = None

        # Determine if commit is initially slated for tagging based on auto-flags or remembered choices
        # This is a simplified check; auto_replace might override auto_tag.
        # The main _process_commit handles the precedence of auto_replace over auto_tag.
        # Here, we check remembered choices for interactive mode.
        commit_is_currently_slated_for_tagging = False
        if (ancestor_commit and self.remembered_choice_with_ancestor == "tag") or \
                (not ancestor_commit and self.remembered_choice_no_ancestor == "tag"):
            commit_is_currently_slated_for_tagging = True

        if commit_is_currently_slated_for_tagging and not self.auto_replace: # auto_replace would override remembered tag
            tag_to_create_for_commit = (commit_hash, commit_info)
            self._vprint(f"  ℹ️ Commit {commit_hash[:8]} is initially slated for tagging due to remembered choice.")

        self._vprint(
            f"\n  🚧 Interactively processing {len(commit_permalinks)} permalink(s) for commit {commit_hash[:8]}:"
        )
        permalinks_by_file: Dict[Path, List[PermalinkInfo]] = {}
        for p in commit_permalinks:
            permalinks_by_file.setdefault(p.found_in_file, []).append(p)

        sorted_file_paths = sorted(permalinks_by_file.keys())

        commit_wide_replacement_idx = 0
        stop_processing_permalinks_for_this_commit_entirely = False # Used to break all loops for this commit

        for file_group_idx, file_path in enumerate(sorted_file_paths):
            if stop_processing_permalinks_for_this_commit_entirely:
                break  # Stop processing files if commit is tagged

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

                if stop_processing_permalinks_for_this_commit_entirely:
                    break

                (
                    current_action,
                    effective_replacement_url_path,
                    new_ls_for_replace,
                    new_le_for_replace,
                ) = self._prompt_user_for_replacement(
                    permalink,
                    ancestor_commit,
                    file_path=file_path,
                    index=commit_wide_replacement_idx,
                    total=len(commit_permalinks),
                    is_commit_slated_for_tagging=commit_is_currently_slated_for_tagging,
                )

                if current_action == "untag":
                    if commit_is_currently_slated_for_tagging:
                        commit_is_currently_slated_for_tagging = False
                        tag_to_create_for_commit = None
                        print(f"  ℹ️ Commit {commit_hash[:8]} is no longer slated for tagging. Re-evaluating current permalink.")
                    # Do not increment permalink_idx or commit_wide_replacement_idx; re-process current permalink
                    continue # Restart the while loop for the current permalink_idx

                # If action is not "untag", we proceed with this permalink's decision
                elif current_action == "tag":
                    if not commit_is_currently_slated_for_tagging: # User chose 't' or 'ta' when not slated
                        commit_is_currently_slated_for_tagging = True
                        tag_to_create_for_commit = (commit_hash, commit_info) # Mark for tagging
                        self._vprint(f"  ℹ️ Commit {commit_hash[:8]} is now slated to be tagged based on choice for {permalink.url[:50]}...")

                        if replacements_for_this_commit_group: # If prior replacements exist for this commit
                            print("\n⚠️ Commit is now slated for tagging, but you previously chose to REPLACE some permalink(s) for this commit.")
                            print("   1) Tag commit & DISCARD all previous REPLACEMENT choices for this commit.")
                            print("   2) Tag commit & KEEP previous REPLACEMENTS. Stop offering to replace other permalinks for this commit.")
                            print("   3) Tag commit & KEEP previous REPLACEMENTS. Continue to be prompted for other permalinks for this commit.")
                            while True:
                                sub_choice = input("      Select how to handle existing replacements (1/2/3): ").strip()
                                if sub_choice == '1':
                                    replacements_for_this_commit_group.clear()
                                    print("  🗑️ Previous replacement choices for this commit have been discarded.")
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                elif sub_choice == '2':
                                    print("  ✅ Previous replacements kept. No more prompts for this commit.")
                                    stop_processing_permalinks_for_this_commit_entirely = True
                                    break
                                elif sub_choice == '3':
                                    print("  ✅ Previous replacements kept. Will continue prompting for this commit.")
                                    # commit_is_currently_slated_for_tagging remains True
                                    break
                                else:
                                    print("      Invalid choice. Please select 1, 2, or 3.")
                        else: # No prior replacements, just tagging
                            print(f"  ℹ️ Commit {commit_hash[:8]} will be tagged. Other permalinks for this commit will reflect this.")
                            # If user chose "ta" (tag all), _prompt_user_for_final_action would have set remembered_choice.
                            # If they just chose "t", we don't automatically stop unless they pick "ta" or sub_choice 2.
                            # If 'ta' was chosen, self.remembered_choice_* would be 'tag'.
                            # If 't' was chosen, and no sub-prompt, we continue.

                    # If commit was already slated and user chose 't' (which shouldn't be an option if UI is correct,
                    # as it would be '-t'), this path is defensive.

                elif current_action == "replace":
                    if ancestor_commit: # Should be true if action is "replace"
                        final_replacement_url = self._create_replacement_permalink(
                            permalink, ancestor_commit, effective_replacement_url_path,
                            new_ls_for_replace, new_le_for_replace
                        )
                        replacements_for_this_commit_group.append((permalink, final_replacement_url))
                elif current_action == "skip":
                    print(f"  ⏭️ Skipping permalink: {permalink.url[:50]}...")

                # Increment counters as we are done with this permalink (or decided to stop all for commit)
                permalink_idx += 1
                commit_wide_replacement_idx += 1

                if stop_processing_permalinks_for_this_commit_entirely:
                    break # Break from inner while loop (permalinks in this file)
            if stop_processing_permalinks_for_this_commit_entirely:
                break # Break from outer for loop (files for this commit)

        return tag_to_create_for_commit, replacements_for_this_commit_group

    def _prompt_to_fetch_commit(self, commit_hash: str) -> bool:
        """
        Prompts the user whether to fetch a missing commit.
        This method can modify self.auto_fetch_commits or self._remember_skip_all_fetches.
        """
        while True:
            print(f"\n❓ Look for {commit_hash} at the remote?")
            print("  y) Yes, fetch this commit from 'origin'")
            print("    ya) Yes to all - fetch this and all subsequent missing commits automatically")
            print("  n) No, do not fetch this commit")
            print("    na) No to all - skip fetching for this and all subsequent missing commits")
            choice = input("     Choose an action (y/n/ya/na): ").strip().lower()

            if choice == 'y':
                return True
            elif choice == 'n':
                return False
            elif choice == 'ya':
                self.auto_fetch_commits = True # Enable for future calls
                return True
            elif choice == 'na':
                self._remember_skip_all_fetches = True # Prevent future prompts
                self.auto_fetch_commits = False # Ensure auto-fetch is off
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

        Returns lists of (commit_hash, commit_info) tuples for tagging and
        (permalink_info, replacement_url) tuples for replacements, or None for the tag.
        """
        local_replacements_to_make: List[Tuple[PermalinkInfo, str]] = []
        single_tag_to_create: Optional[Tuple[str, Dict[str, str]]] = None

        print(f"\n{'-' * 80}")
        index_message = f"Commit #{index + 1}/{total}: {commit_hash[:8]} ({len(commit_permalinks)} permalink(s))"
        print(f"\n[*] {index_message} {'- ' * ((75 - len(index_message)) // 2)}")

        # Determine if we should offer a prompt for fetching missing commits.
        # The prompt itself can change self.auto_fetch_commits or self._remember_skip_all_fetches.
        can_prompt_for_fetch = not self.auto_fetch_commits and not self._remember_skip_all_fetches

        # Check if the commit exists locally, and fetch if not
        if not fetch_commit_if_missing(
            commit_hash,
            self.auto_fetch_commits, # Current state of auto-fetch
            self._vprint,
            self._prompt_to_fetch_commit if can_prompt_for_fetch else None
        ):
            return None, local_replacements_to_make # Skip if commit unavailable

        commit_info = get_commit_info(commit_hash)
        if not commit_info:
            print(f"  ❌ Could not get info for commit {commit_hash}")
            return None, local_replacements_to_make

        self._vprint(f"  📝 {commit_info['subject']}")
        self._vprint(f"    👤 Author: {commit_info['author']} ({commit_info['date']})")
        self._vprint(f"  🔗 Referenced in {len(commit_permalinks)} permalink(s)")

        # Check if the commit is already in the main branch
        if is_commit_in_main(commit_hash, self.main_branch):
            print(f"  ✅ Already merged into {self.main_branch}")
            return None, local_replacements_to_make

        print(f"  ⛓️‍💥️ Not in {self.main_branch}")
        ancestor_commit = find_closest_ancestor_in_main(commit_hash, self.main_branch)
        action_for_commit_group: Optional[str] = None

        # Determine action based on ancestor presence and auto flags
        if ancestor_commit:
            # Found a common ancestor in main branch
            ancestor_info = get_commit_info(ancestor_commit)
            print(f"  ⏪ Closest ancestor in main: {ancestor_commit[:8]} - {ancestor_info['subject'] if ancestor_info else 'Unknown'}")
            self._vprint(f"    👤 Author: {ancestor_info['author']} ({ancestor_info['date']})")
            if self.auto_replace: # auto_replace takes precedence
                action_for_commit_group = "replace_all_permalinks"
                self._vprint(f"  🤖 --auto-replace: Will process replacements for {commit_hash[:8]}.")
            elif self.auto_tag:
                action_for_commit_group = "tag_commit"
                self._vprint(f"  🤖 --auto-tag: Will tag {commit_hash[:8]} (ancestor found but auto-replace not set).")
        else: # No ancestor
            print(f"  ❌ No common ancestor with {self.main_branch} found for {commit_hash[:8]}.")
            if self.auto_tag:
                action_for_commit_group = "tag_commit"
                self._vprint(f"  🤖 --auto-tag: Will tag {commit_hash[:8]} (no ancestor).")

        if action_for_commit_group == "replace_all_permalinks" and ancestor_commit:
            replacements = self._perform_auto_replacements_for_commit(commit_hash, ancestor_commit, commit_permalinks)
            local_replacements_to_make.extend(replacements)
        elif action_for_commit_group == "tag_commit":
            single_tag_to_create = (commit_hash, commit_info)
        else: # Interactive mode for this commit group
            single_tag_to_create, replacements = self._prompt_user_for_commit(
                commit_hash, commit_info, ancestor_commit, commit_permalinks
            )
            local_replacements_to_make.extend(replacements)

        return single_tag_to_create, local_replacements_to_make

    def _process_and_create_tags(
        self, commits_to_tag: List[Tuple[str, Dict[str, str]]]
    ) -> None:
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

            tag_name = generate_git_tag_name(commit_hash, commit_info.get("subject", ""), self.tag_prefix)

            if git_tag_exists(tag_name):
                print(f"  ✅ Tag {tag_name} already exists for commit {commit_hash[:8]}")
                continue

            tag_message = f"Preserve permalink reference to: {commit_info.get('subject', 'commit ' + commit_hash[:8])}"

            if report_entry_for_this_tag:
                report_entry_for_this_tag["tag_name"] = tag_name
                report_entry_for_this_tag["tag_message"] = tag_message

            if git_tag_exists(tag_name): # Check again, as it might have been created by another process or concurrently
                print(f"  ✅ Tag {tag_name} already exists for commit {commit_hash[:8]}")
                if report_entry_for_this_tag:
                    report_entry_for_this_tag["status"] = "already_exists"
                    self.report_data["tags_created"].append(report_entry_for_this_tag)
                continue

            tag_created_successfully_or_simulated = execute_git_tag_creation(
                tag_name, commit_hash, tag_message, self.dry_run
            )

            if tag_created_successfully_or_simulated:
                if self.dry_run: # Message already printed by execute_git_tag_creation
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
        if not created_tag_names or self.dry_run:
            if self.dry_run and created_tag_names:
                self._vprint(
                    f"  🧪 DRY RUN: Would attempt to push {len(created_tag_names)} tags if not in dry run."
                )
            elif not created_tag_names:
                self._vprint("  ℹ️ No new tags were marked for creation/pushing.")
            return

        # Filter out tags that might have been in the list but weren't actually created
        # (e.g., if a creation step failed but somehow the name was still added, or for robustness)
        # In the current _process_and_create_tags, created_tag_names should only contain successfully created tags
        # or tags that would be created in dry_run.
        actually_created_tags_for_push = [t for t in created_tag_names if git_tag_exists(t) or self.dry_run]

        if actually_created_tags_for_push:
            print(
                f"\n🚀 Pushing {len(actually_created_tags_for_push)} created/verified tags to origin..."
            )
            try:
                push_command = ["git", "push", "origin"] + actually_created_tags_for_push
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
                print(f"  ❌ Failed to push tags. Command '{subprocess.list2cmdline(e.cmd)}' (rc={e.returncode}). Stderr: '{stderr_output}'", file=sys.stderr)
                print("  🎗️ You may need to push them manually: git push origin --tags")
            except subprocess.TimeoutExpired as e:
                print(f"  ❌ Error: Timeout during tag push operation: {e}", file=sys.stderr)
                print("  🎗️ You may need to push them manually: git push origin --tags")

        elif (
            created_tag_names
        ):  # Tags were identified for creation, but none were new/successfully made or exist now
            print(
                "\nℹ️ No new tags were created or available to push (either existed previously, failed creation)."
            )

    def run(self) -> None:
        """Main execution function."""
        self._vprint(f"Repository: {self.repo_root}")
        self._vprint(f"GitHub: {self.github_owner}/{self.github_repo}")
        self._vprint(f"Main branch: {self.main_branch}, Tag prefix: {self.tag_prefix}")
        self._vprint(
            f"Repo aliases: {self.repo_aliases if self.repo_aliases else 'None'}"
        )
        self._vprint( # Added respect_gitignore
            f"Respect gitignore: {self.respect_gitignore}, "
            f"Dry run: {self.dry_run}, Auto fetch: {self.auto_fetch_commits}, Auto replace: {self.auto_replace}, Auto tag: {self.auto_tag}"
        ) # self.line_shift_tolerance_str
        if self.output_json_report_path: # self.line_shift_tolerance_str
            self._vprint(f"JSON Report output: {self.output_json_report_path}") # self.line_shift_tolerance_str
        self._vprint(f"Line shift tolerance: {self.line_shift_tolerance_str} (parsed as: {'percentage' if self.tolerance_is_percentage else 'absolute'}, value: {self.tolerance_value})")
        self._vprint("-" * 50)

        # Find all permalink commits
        permalinks = self.find_github_permalinks()
        if not permalinks:
            print("No GitHub permalinks found in this repository.")
            return

        num_unique_commits, num_unique_files = self._count_unique_commits_and_files(permalinks)
        self._vprint(f"\nFound {len(permalinks)} GitHub permalinks in {num_unique_files} unique file(s) referencing {num_unique_commits} unique commit(s)")

        # Group permalinks by commit hash
        commits_to_process_map: dict[str, list[PermalinkInfo]] = {}
        for permalink in permalinks:
            if permalink.commit_hash not in commits_to_process_map:
                commits_to_process_map[permalink.commit_hash] = []
            commits_to_process_map[permalink.commit_hash].append(permalink)

        all_commits_to_tag: List[Tuple[str, Dict[str, str]]] = []
        all_replacements_to_make: List[Tuple[PermalinkInfo, str]] = []

        # Process each commit and its permalinks, handling auto-replace, auto-tag, or interactive prompts.
        # Actual file modifications and tagging are done later.
        for index, (commit_hash, commit_permalinks_list) in enumerate(commits_to_process_map.items()):
            tag_for_commit, replacements_from_commit = self._process_commit(
                commit_hash, commit_permalinks_list, index, len(commits_to_process_map)
            )
            if tag_for_commit:
                all_commits_to_tag.append(tag_for_commit)
            all_replacements_to_make.extend(replacements_from_commit)

        print(f"\n{'=' * 80}")

        # Populate report data for replacements
        if self.output_json_report_path and all_replacements_to_make:
            for permalink_info, replacement_url in all_replacements_to_make:
                self.report_data["replacements"].append({
                    "original_url": permalink_info.url,
                    "new_url": replacement_url,
                    "found_in_file": str(permalink_info.found_in_file.relative_to(self.repo_root)),
                    "found_at_line": permalink_info.found_at_line,
                })


        # Perform actual file modifications for replacements
        if all_replacements_to_make:
            # Use the helper method to count unique files involved in replacements
            replacements_by_file: Dict[Path, List[Tuple[PermalinkInfo, str]]] = {}
            for permalink_info, replacement_url in all_replacements_to_make:
                file_path = permalink_info.found_in_file
                if file_path not in replacements_by_file:
                    replacements_by_file[file_path] = []
                replacements_by_file[file_path].append((permalink_info, replacement_url))

            sorted_file_paths = sorted(replacements_by_file.keys())

            if self.dry_run:
                print(
                    f"\n🧪 DRY RUN SUMMARY: Would perform {len(all_replacements_to_make)} replacement(s) in {len(sorted_file_paths)} unique file(s):\n"
                )
            else:
                print(
                    f"\n🏃 Performing {len(all_replacements_to_make)} permalink replacement(s) in {len(sorted_file_paths)} file(s)..."
                )

            global_replacement_idx = 0
            for group_idx, file_path in enumerate(sorted_file_paths):
                replacements_in_file = replacements_by_file[file_path]
                # Sort replacements within a file by line number for consistent order
                replacements_in_file.sort(key=lambda item: item[0].found_at_line)

                print(
                    f"\n#{group_idx + 1}/{len(sorted_file_paths)} files: {file_path.relative_to(self.repo_root)} ({len(replacements_in_file)} replacement(s))"
                )

                for permalink_info, replacement_url in replacements_in_file:
                    global_replacement_idx += 1
                    print(
                        f"  {global_replacement_idx:3d}. Line {permalink_info.found_at_line}:"
                    )
                    print(f"    🔗 OLD: {permalink_info.url}")
                    print(f"    ✨ NEW: {replacement_url}")

                    if not self.dry_run:
                        self._perform_replacement(permalink_info, replacement_url)

        else: # No replacements to make
            if self.dry_run:
                print("\n🧪 DRY RUN: No permalink replacements to make.")
            else:
                print("\nℹ️ No permalink replacements were made.")

        # Process and create tags for all commits that need tagging
        if all_commits_to_tag:
            self._process_and_create_tags(all_commits_to_tag)

        self._write_json_report()
        print("\n🏁 Permalink checking complete.")

    def _write_json_report(self):
        """Writes the collected report data to a JSON file if a path is specified."""
        if not self.output_json_report_path:
            return

        try:
            with open(self.output_json_report_path, "w", encoding="utf-8") as f:
                json.dump(self.report_data, f, indent=2)
            print(f"\n📝 JSON report written to: {self.output_json_report_path}")
        except IOError as e:
            print(f"\n❌ Error writing JSON report to {self.output_json_report_path}: {e}", file=sys.stderr)



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
        "--auto-tag",
        action="store_true",
        help="Automatically tag all unmerged commits without prompting.\n"
        "If --auto-replace is also set, this only applies if replacement is not possible (e.g., no ancestor).",
    )
    parser.add_argument(
        "--auto-replace",
        action="store_true",
        help="Automatically replace permalinks with versions pointing to the closest ancestor in the main branch,\n"
        "if found. Takes precedence over --auto-tag when an ancestor is available.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Enable non-interactive mode. This is a shorthand for setting:\n"
        "  --auto-tag\n"
        "  --auto-replace\n"
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
        "--repo-alias",
        dest="repo_aliases",
        default=[],
        action="append",
        help="Alternative repository names (e.g., 'old-repo-name' 'project-alias') that should be\n"
        "considered aliases for the current repository when parsing permalinks.\n"
        "This flag can be used multiple times to specify different aliases.",
    )
    parser.add_argument(
        "--output-json-report",
        type=str,
        default=None,
        help="File path to output a JSON report of actions (replacements and tags).",
    )

    args = parser.parse_args()

    if args.non_interactive:
        args.auto_tag = True
        args.auto_replace = True
        args.auto_fetch_commits = True
        if args.verbose:
            print(
                "ℹ️ Non-interactive mode enabled: --auto-tag, --auto-replace, and --auto-fetch-commits are active."
            )

    try:
        tagger = GitPermalinkChecker(
            verbose=args.verbose,
            dry_run=args.dry_run,
            main_branch=args.main_branch,
            tag_prefix=args.tag_prefix,
            auto_fetch_commits=args.auto_fetch_commits,
            auto_replace=args.auto_replace,
            auto_tag=args.auto_tag,
            line_shift_tolerance=args.line_shift_tolerance,
            repo_aliases=args.repo_aliases,
            respect_gitignore=args.respect_gitignore,
            output_json_report=args.output_json_report,
        )
        tagger.run()
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


if __name__ == "__main__":
    main()
