#!/usr/bin/env python3
"""
GitHub Permalink Persistence Checker
====================================

Finds GitHub commit permalinks in a repository, checks if commits are merged
into main, and for unmerged commits, tries to find the closest ancestor in main
(and checks that any line references still make sense).
For unmerged commits, it prompts the user to either tag the commit to preserve
the permalink or replace the permalink with a new one pointing to the ancestor
commit.

The goal is to avoid git's garbage collection from nuking commits that it thinks
are no longer referenced.

Usage
-----

python git_permalink_checker.py [OPTIONS]

Options:
- `--dry-run`: Show what would be done without making changes.
- `--main-branch BRANCH`: Specify the main branch name (default: `main`).
- `--tag-prefix PREFIX`: Specify the tag prefix, preferably namespaced with slash
    (default: `permalinks/ref`).
- `--auto-replace`: Automatically replace permalinks with ancestor versions if found
    (takes precedence over --auto-tag if an ancestor exists).
- `--auto-tag`: Automatically tag all unmerged commits without prompting
    (--auto-replace takes precedence if an ancestor exists).
- `--auto-fetch-commits`: Automatically fetch commits from the remote if missing
    from the local repository.
- `--non-interactive`: Enable all --auto-* flags (--auto-tag, --auto-replace,
    --auto-fetch-commits).


Supported
---------

Supports the following cloud git repos:

- github.com with links of the form:
    - `https://github.com/org/project/blob/commit_hash/file_path#Lline_start-Lline_end`
    - `https://github.com/org/project/tree/commit_hash`

History
-------

- 2025-06-01 Authored by huyz and AI
"""

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class PermalinkInfo:
    url: str
    commit_hash: str
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    found_in_file: Path
    found_at_line: int


class GitPermalinkChecker:
    def __init__(
        self,
        verbose: bool = False,
        dry_run: bool = False,
        main_branch: str = "main",
        tag_prefix: str = "permalinks/ref",
        auto_fetch_commits: bool = False,
        auto_replace: bool = False,
        auto_tag: bool = False,
        line_shift_tolerance: int = 10,
    ):
        self.verbose = verbose
        self.dry_run = dry_run
        self.main_branch = main_branch
        self.tag_prefix = tag_prefix
        self.auto_fetch_commits = auto_fetch_commits
        self.auto_replace = auto_replace
        self.auto_tag = auto_tag
        self.line_shift_tolerance = line_shift_tolerance

        self.GITHUB_REMOTE_RE = re.compile(r"^(?:git@|https?://)github\.com[:/]")
        self.GITHUB_PERMALINK_RE = re.compile(
            r"https://github\.com/([^/]+)/([^/]+)/(?:blob|tree)/([a-f0-9]{7,40})(?:/([^#\s\?]+))?(?:#L(\d+)(?:-L(\d+))?)?",
            re.IGNORECASE,
        )

        self.repo_root = self._get_repo_root()
        self.remote_url = self._get_remote_url()
        self.github_owner, self.github_repo = self._get_github_info()

        # For remembering choices in interactive mode
        self.remembered_choice_with_ancestor: Optional[str] = None
        self.remembered_choice_no_ancestor: Optional[str] = None

    def _vprint(self, *args, **kwargs):
        """Prints only if verbose mode is enabled."""
        if self.verbose:
            print(*args, **kwargs)

    def _get_repo_root(self) -> Path:
        """Get the root directory of the git repository."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True,
            )
            return Path(result.stdout.strip())
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Not in a git repository: {e}")

    def _get_remote_url(self) -> str:
        """Get the origin remote URL."""
        try:
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
            )

            remote_url = result.stdout.strip()
            if not remote_url:
                raise RuntimeError("Empty remote URL returned")

            # We sometimes use the `insteadOf` directive to map to domains
            # that .ssh/config can recognize.  In those cases, we want to use
            # the simpler way to extract the URL
            if not self.GITHUB_REMOTE_RE.match(remote_url):
                result = subprocess.run(
                    ["git", "config", "--get", "remote.origin.url"],
                    capture_output=True,
                    text=True,
                    check=True,
                )

                remote_url = result.stdout.strip()
                if not remote_url:
                    raise RuntimeError("Empty remote URL returned from git config")

            if not self.GITHUB_REMOTE_RE.match(remote_url):
                raise RuntimeError(f"Remote URL does not match GitHub format: {remote_url}")

            return remote_url
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"No origin remote found: {e}")

    def _get_github_info(self) -> Tuple[str, str]:
        """Extract owner/repo from GitHub URL."""
        patterns = [
            r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$",
            r"github\.com[:/]([^/]+)/([^/]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, self.remote_url)
            if match:
                owner = match.group(1)
                repo = match.group(2).rstrip(".git")
                if owner and repo:  # Ensure non-empty matches
                    return (owner, repo)

        raise RuntimeError(f"Could not parse GitHub info from remote URL: {self.remote_url}")

    def _normalize_repo_name(self, repo_name: str) -> str:
        """Normalize repository name by removing common prefixes."""
        if not repo_name:
            return repo_name
        # Special repo alias handling: platform-, risk-, rails-
        # prefixes
        return re.sub(r"^(?:platform-|risk-|rails-)", "", repo_name.lower())

    def _parse_github_permalink(self, url: str) -> Optional[PermalinkInfo]:
        """Parse a GitHub permalink URL to extract commit hash, file path, and line numbers."""

        match = self.GITHUB_PERMALINK_RE.match(url)
        if not match:
            return None

        owner, repo, commit_hash, file_path, line_start, line_end = match.groups()

        # Validate commit hash length
        if len(commit_hash) < 7 or len(commit_hash) > 40:
            return None

        # Only process URLs from the current repository
        if owner.lower() != self.github_owner.lower() or self._normalize_repo_name(
            repo
        ) != self._normalize_repo_name(self.github_repo):
            return None

        return PermalinkInfo(
            url=url,
            commit_hash=commit_hash,
            file_path=file_path,
            line_start=int(line_start) if line_start else None,
            line_end=int(line_end) if line_end else None,
            found_in_file=Path(),  # Will be set by caller
            found_at_line=0,  # Will be set by caller
        )

    def find_github_permalinks(self) -> List[PermalinkInfo]:
        """Find all GitHub commit permalinks in the repository."""
        permalinks = []

        # File extensions (of text files) to search
        # TIP: `git ls-files | grep -o "\.\w\+" | sort -u`
        text_extensions = {
            ".bash",
            ".bat",
            ".c",
            ".conf",
            ".config",
            ".cpp",
            ".d2",
            ".go",
            ".h",
            ".htm",
            ".html",
            ".java",
            ".js",
            ".jsx",
            ".json",
            ".md",
            ".mdx",
            ".php",
            ".properties",
            ".property",
            ".ps1",
            ".py",
            ".rb",
            ".rs",
            ".rst",
            ".sh",
            ".sql",
            ".svg",
            ".swift",
            ".ts",
            ".tsx",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
            ".zsh",
        }
        self._vprint(f"Searching for GitHub permalinks in {self.repo_root}")

        found_count = 0
        for file_path in self.repo_root.rglob("*"):
            # Skip directories, hidden files, and files in .git
            if (
                file_path.is_dir()
                or ".git" in file_path.parts
                or ".idea" in file_path.parts
                or ".vscode" in file_path.parts
            ):
                continue

            # Only search in text files by running `file` command
            # 2025-06-04 This is too slow, which is why we rely on text_extensions as heuristics.
            # try:
            #    result = subprocess.run(
            #        ["file", "--mime-type", "-b", str(file_path)],
            #        capture_output=True,
            #        text=True,
            #        check=True,
            #    )
            #    if "text" not in result.stdout.lower():
            #        continue
            # except subprocess.CalledProcessError:
            #    print(f"Warning: Could not determine file type for {file_path}")
            #    continue

            # Only search in text files or in common git repo filenames with no extension'
            if file_path.suffix == "":
                if file_path.name not in {
                    "README",
                    "LICENSE",
                    "CHANGELOG",
                    "CONTRIBUTING",
                    "AUTHORS",
                    "INSTALL",
                    "Makefile",
                    "Dockerfile",
                    ".gitignore",
                    ".env",
                    ".envrc",
                }:
                    continue
            else:
                if file_path.suffix.lower() not in text_extensions:
                    continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                file_header_printed_for_current_file = False

                for line_num, line in enumerate(lines, 1):
                    # Find all GitHub URLs in the line
                    urls_in_line = re.findall(r"https://github\.com/[^][()<>\"'{}|\\^`\s]+", line)

                    permalinks_found_on_this_line = []

                    for url in urls_in_line:
                        permalink_info = self._parse_github_permalink(url)
                        if permalink_info:
                            permalink_info.found_in_file = file_path
                            permalink_info.found_at_line = line_num
                            permalinks.append(permalink_info)  # Add to the main list
                            permalinks_found_on_this_line.append(permalink_info)

                    if permalinks_found_on_this_line:
                        if not file_header_printed_for_current_file:
                            self._vprint(f"\n- In `{file_path.relative_to(self.repo_root)}`:")
                            file_header_printed_for_current_file = True

                        self._vprint(f"  - Line {line_num}: {line.strip()}")

                        for p_info in permalinks_found_on_this_line:
                            found_count += 1
                            self._vprint(
                                f"    {found_count:2d}. 📍 Found permalink: {p_info.commit_hash[:8]}"
                            )

            except (UnicodeDecodeError, IOError, OSError, PermissionError) as e:
                print(f"Warning: Could not read {file_path}: {e}")
                continue

        return permalinks

    def is_commit_in_main(self, commit_hash: str) -> bool:
        """Check if a commit is reachable from the main branch."""
        try:
            result = subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit_hash, self.main_branch],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def commit_exists(self, commit_hash: str) -> bool:
        """Check if a commit exists in the repository."""
        try:
            result = subprocess.run(
                ["git", "cat-file", "-e", commit_hash],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def get_commit_info(self, commit_hash: str) -> Optional[Dict[str, str]]:
        """Get commit information."""
        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "-1",
                    "--format=%H|%s|%an|%ad",
                    "--date=short",
                    commit_hash,
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            output = result.stdout.strip()
            if not output:
                return None

            parts = output.split("|", 3)
            if len(parts) != 4:
                return None

            return {
                "hash": parts[0],
                "subject": parts[1],
                "author": parts[2],
                "date": parts[3],
            }
        except subprocess.CalledProcessError:
            return None

    def find_closest_ancestor_in_main(self, commit_hash: str) -> Optional[str]:
        """Find the closest ancestor commit that is in the main branch."""
        try:
            result = subprocess.run(
                ["git", "merge-base", commit_hash, self.main_branch],
                capture_output=True,
                text=True,
                check=True,
            )
            ancestor = result.stdout.strip()
            return ancestor if ancestor else None
        except subprocess.CalledProcessError:
            return None

    def file_exists_at_commit(self, commit_hash: str, file_path: str) -> bool:
        """Check if a file exists at a specific commit."""
        try:
            result = subprocess.run(
                ["git", "cat-file", "-e", f"{commit_hash}:{file_path}"],
                capture_output=True,
                check=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

    def get_file_content_at_commit(self, commit_hash: str, file_path: str) -> Optional[List[str]]:
        """Get file content at a specific commit."""
        try:
            result = subprocess.run(
                ["git", "show", f"{commit_hash}:{file_path}"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError:
            return None

    def create_replacement_permalink(
        self,
        original: PermalinkInfo,
        new_commit_hash: str,
        replacement_file_path: Optional[str],  # The file path for the new permalink
        replacement_line_start: Optional[int] = None,
        replacement_line_end: Optional[int] = None,
    ) -> str:
        """Create a replacement permalink URL."""
        # Determine if original URL used 'blob' or 'tree'
        match = re.search(r"github\.com/[^/]+/[^/]+/(blob|tree)/", original.url)
        url_type = match.group(1) if match else "blob"
        base_url = f"https://github.com/{self.github_owner}/{self.github_repo}/{url_type}/{new_commit_hash}"

        if replacement_file_path:  # Use the provided replacement_file_path
            url = f"{base_url}/{replacement_file_path}"

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

    def verify_line_content(
        self,
        original: PermalinkInfo,  # Defines original content source (commit, path, lines)
        replacement_commit_hash: str,  # Commit to check in
        replacement_file_path: str,  # File path to check in replacement_commit_hash
        custom_tolerance: Optional[int] = None,  # Optional line shift tolerance
    ) -> Tuple[bool, Optional[int], Optional[int]]:
        """
        Verify line content, allowing for shifts. Strips leading/trailing whitespace.
        Returns: (match_found, new_line_start_in_replacement, new_line_end_in_replacement)
        The new_line_start/end are for the replacement_commit if match_found is True.
        A custom_tolerance can be provided to override self.line_shift_tolerance.
        If original permalink has no line numbers or no replacement_file_path,
        returns (True, None, None) or (False, None, None).
        """
        if not original.file_path or original.line_start is None or not replacement_file_path:
            return True, None, None  # Vacuously true, no specific lines to verify

        original_content_lines = self.get_file_content_at_commit(
            original.commit_hash, original.file_path
        )
        replacement_content_lines = self.get_file_content_at_commit(
            replacement_commit_hash,
            replacement_file_path,  # Use the specified path for replacement
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

            tolerance_to_use = (
                custom_tolerance if custom_tolerance is not None else self.line_shift_tolerance
            )
            # Try all shifts from 0 outward, alternating +shift and -shift
            tried_shifts = set()
            for offset in range(0, tolerance_to_use + 1):
                for shift in (offset, -offset) if offset != 0 else (0,):
                    if shift in tried_shifts:
                        continue
                    tried_shifts.add(shift)
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

    def prompt_user_for_replacement(
        self, original: PermalinkInfo, ancestor_commit: Optional[str], index: int, total: int
    ) -> Tuple[str, Optional[str], Optional[int], Optional[int]]:
        """
        Prompt user to confirm replacement permalink.
        Returns a tuple: (
            action_str,
            effective_replacement_file_path,
            new_line_start_for_replacement,
            new_line_end_for_replacement).
        The line numbers are only relevant if action_str is "replace".
        """
        has_ancestor = ancestor_commit is not None
        remembered_choice_key = "with_ancestor" if has_ancestor else "no_ancestor"
        remembered_choice = getattr(self, f"remembered_choice_{remembered_choice_key}")

        if remembered_choice:
            # If choice is remembered, we assume it implies how to handle lines too (e.g. auto-replace logic)
            self._vprint(f"  🤖 Using remembered choice: {remembered_choice}")
            return (
                remembered_choice,
                original.file_path,
                original.line_start,
                original.line_end,
            )  # Default path & lines if remembered

        index_message = f"#{index + 1}/{total} for commit {original.commit_hash[:8]}"
        print(f"\n- - {index_message} {'- ' * ((76 - len(index_message)) // 2)}")
        print("🚧 PERMALINK REPLACEMENT NEEDED")
        print()
        print(
            f"📄 Found in: {original.found_in_file.relative_to(self.repo_root)}:{original.found_at_line}"
        )
        print(f"🔗 Original URL: {original.url}")
        print(f"⛓️‍💥 Original commit: {original.commit_hash[:8]} (not in {self.main_branch})")
        print()

        replacement_url: Optional[str] = None  # Will be set if ancestor exists
        # These will store the line numbers to be used in the *final* replacement URL
        current_replacement_ls: Optional[int] = original.line_start
        current_replacement_le: Optional[int] = original.line_end
        # This will be the file path used for the replacement link.
        effective_replacement_file_path: Optional[str] = original.file_path

        if has_ancestor and ancestor_commit:
            ancestor_info = self.get_commit_info(ancestor_commit)
            if ancestor_info:
                print(
                    f"⏪ Suggested ancestor commit: {ancestor_commit[:8]} - {ancestor_info['subject']}"
                )
                print(f"   Author: {ancestor_info['author']} ({ancestor_info['date']})")

            # --- Stage 1: Resolve File Path for Replacement, if original had one ---
            if original.file_path:
                path_to_check_in_ancestor = original.file_path  # Start with original path

                # Loop if the current path_to_check_in_ancestor is not found in the ancestor commit
                while not self.file_exists_at_commit(ancestor_commit, path_to_check_in_ancestor):
                    print(
                        f"\n❌ File '{path_to_check_in_ancestor}' (from original or last input) does not exist in ancestor {ancestor_commit[:8]}"
                    )
                    print("\nMISSING FILE RESOLUTION:")
                    print("  o. Open original URL (and attempted replacement) in browser")
                    print(
                        "  m. MANUALLY enter new file path for replacement (relative to repo root, or full GitHub URL)"
                    )
                    print("  k. KEEP current path for replacement URL (it will likely be broken)")
                    print("  a. ABORT replacement for this permalink (skip)")
                    sub_choice_file = (
                        input("\nSelect resolution for missing file (o,m,k,a): ").strip().lower()
                    )

                    if sub_choice_file == "o":
                        try:
                            import webbrowser

                            print(f"🌐 Attempting to open original URL: {original.url}")
                            webbrowser.open(original.url)
                            # Construct a temporary "broken" replacement URL to show the user
                            broken_replacement_url = self.create_replacement_permalink(
                                original,
                                ancestor_commit,
                                path_to_check_in_ancestor,  # The path that's missing
                                current_replacement_ls,
                                current_replacement_le,
                            )
                            print(
                                f"🌐 Attempting to open (likely broken) replacement URL: {broken_replacement_url}"
                            )
                            webbrowser.open(broken_replacement_url)
                        except ImportError:
                            print(f"🌐 Please manually open: {original.url}")
                            if (
                                ancestor_commit and path_to_check_in_ancestor
                            ):  # Check path_to_check_in_ancestor to avoid error if None
                                broken_replacement_url = self.create_replacement_permalink(
                                    original,
                                    ancestor_commit,
                                    path_to_check_in_ancestor,
                                    current_replacement_ls,
                                    current_replacement_le,
                                )
                                print(
                                    f"🌐 And suggested (likely broken) replacement: {broken_replacement_url}"
                                )
                        continue  # Re-prompt for missing file resolution

                    elif sub_choice_file == "m":
                        new_path_input = input(
                            "    Enter new file path or full GitHub URL for replacement: "
                        ).strip()
                        if not new_path_input:
                            print("    Input cannot be empty. Try again.")
                            continue

                        parsed_url_info = self._parse_github_permalink(new_path_input)
                        if parsed_url_info:
                            print(
                                f"    Parsed as URL. Using file path: '{parsed_url_info.file_path}'"
                            )
                            path_to_check_in_ancestor = parsed_url_info.file_path
                            # If URL provides lines, they become the new baseline for current_replacement_ls/le
                            if parsed_url_info.line_start is not None:
                                current_replacement_ls = parsed_url_info.line_start
                                current_replacement_le = parsed_url_info.line_end  # Can be None
                        else:  # Treat as a relative file path
                            path_to_check_in_ancestor = new_path_input
                        # Loop will re-evaluate existence of path_to_check_in_ancestor
                        continue

                    elif sub_choice_file == "k":
                        print(
                            f"    Keeping path '{path_to_check_in_ancestor}' for replacement URL, though it's missing in ancestor."
                        )
                        effective_replacement_file_path = path_to_check_in_ancestor
                        break  # Exit missing file loop
                    elif sub_choice_file == "a":
                        print("    Aborting replacement for this permalink.")
                        return "skip", effective_replacement_file_path, None, None
                    else:
                        print("    Invalid choice. Try again.")
                else:  # Else for 'while not self.file_exists_at_commit': file exists
                    effective_replacement_file_path = path_to_check_in_ancestor
            # effective_replacement_file_path is now set (or None if original.file_path was None)

            # Content verification and sub-prompt logic
            if (
                effective_replacement_file_path and original.line_start is not None
            ):  # Only verify if lines are expected and we have a path
                if self.file_exists_at_commit(ancestor_commit, effective_replacement_file_path):
                    # Use original for its line_start/end to define the text block to search for.
                    # Use effective_replacement_file_path for where to search in the ancestor.
                    match_found, verified_ls, verified_le = self.verify_line_content(
                        original, ancestor_commit, effective_replacement_file_path
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
                        print(
                            f"💥 Line content differs at L{original.line_start}"
                            + (
                                f"-L{original.line_end}"
                                if original.line_end and original.line_end != original.line_start
                                else ""
                            )
                            + " in ancestor, even with default tolerance."
                        )
                        # Sub-prompt for handling differing lines
                        while True:
                            print("\nLINE MISMATCH RESOLUTION:")
                            print("  l. Retry with different line shift TOLERANCE for search")
                            print("  m. MANUALLY enter new line numbers for replacement")
                            print("  c. CLEAR line numbers from replacement URL")
                            print("  k. KEEP original line numbers in replacement URL")
                            print("    a. ABORT replacement (skip this permalink for now)")
                            sub_choice = (
                                input("\nSelect resolution for lines (l,m,c,k,a): ").strip().lower()
                            )

                            if sub_choice == "l":
                                try:
                                    new_tol_str = input(
                                        f"    Enter new tolerance (current global: {self.line_shift_tolerance}, 0 to disable shift): "
                                    )
                                    new_tolerance = int(new_tol_str)
                                    if new_tolerance < 0:
                                        raise ValueError("Tolerance cannot be negative.")
                                    print(f"\n🔄 Re-checking with tolerance {new_tolerance}...")
                                    temp_match, temp_ls, temp_le = (
                                        self.verify_line_content(  # Pass effective_replacement_file_path
                                            original,
                                            ancestor_commit,
                                            effective_replacement_file_path,
                                            custom_tolerance=new_tolerance,
                                        )
                                    )
                                    if temp_match:
                                        current_replacement_ls = temp_ls
                                        current_replacement_le = temp_le
                                        temp_range_str = f"L{temp_ls}"
                                        if temp_le and temp_le != temp_ls:
                                            temp_range_str += f"-L{temp_le}"
                                        print(
                                            f"✅ Match found with new tolerance at {temp_range_str}!"
                                        )
                                        break
                                    else:
                                        print(
                                            f"❌ No match found even with tolerance {new_tolerance}."
                                        )
                                except ValueError as e:
                                    print(f"    Invalid tolerance: {e}")
                                continue
                            elif sub_choice == "m":
                                try:
                                    ls_str = input(
                                        "    Enter new START line number for replacement: "
                                    )
                                    new_ls_manual = int(ls_str)
                                    if new_ls_manual <= 0:
                                        raise ValueError("Line number must be positive.")
                                    current_replacement_ls = new_ls_manual
                                    current_replacement_le = None

                                    is_original_range = (
                                        original.line_start is not None
                                        and original.line_end is not None
                                        and original.line_end > original.line_start
                                    )
                                    if is_original_range:
                                        original_num_lines = (
                                            original.line_end - original.line_start + 1
                                        )
                                        default_le_manual = new_ls_manual + (original_num_lines - 1)
                                        le_str = input(
                                            f"    Enter new END line number (original was {original_num_lines} lines, e.g., L{original.line_start}-L{original.line_end}).\n"
                                            f"      (Press Enter for {default_le_manual}, or type a number. Use 0 or same as start for single line): "
                                        ).strip()
                                        if not le_str:
                                            current_replacement_le = default_le_manual
                                        else:
                                            new_le_manual = int(le_str)
                                            if new_le_manual == 0 or new_le_manual == new_ls_manual:
                                                current_replacement_le = None
                                            elif new_le_manual < new_ls_manual:
                                                raise ValueError(
                                                    "End line cannot be before start line."
                                                )
                                            else:
                                                current_replacement_le = new_le_manual
                                    print("    Manually set line numbers for replacement.")
                                    break
                                except ValueError as e:
                                    print(f"    Invalid line number: {e}")
                                continue
                            elif sub_choice == "c":
                                current_replacement_ls = None
                                current_replacement_le = None
                                print("    Line numbers will be cleared from replacement URL.")
                                break
                            elif sub_choice == "k":
                                current_replacement_ls = original.line_start
                                current_replacement_le = original.line_end
                                print("    Original line numbers will be kept for replacement URL.")
                                break
                            elif sub_choice == "a":
                                print("    Aborting replacement for this permalink.")
                                return "skip", effective_replacement_file_path, None, None
                            else:
                                print("    Invalid choice for line handling. Try again.")
                else:
                    print(
                        f"❌ File '{effective_replacement_file_path}' does not exist in suggested ancestor commit {ancestor_commit[:8]}"
                    )
                    # This sub-prompt is for when lines were expected, but the file (chosen via 'k' or initial bad path) is missing.
                    while True:
                        # This is the existing "MISSING FILE RESOLUTION" but it's actually "LINES FOR MISSING FILE"
                        print("\nMISSING FILE RESOLUTION:")
                        print(
                            "  m. MANUALLY enter new line numbers (assumes file path is still desired)"
                        )
                        print(
                            "  c. CLEAR line numbers from replacement URL (keeps file path if present)"
                        )
                        print(
                            "  k. KEEP original line numbers in replacement URL (file path and lines may be invalid)"
                        )
                        print("  a. ABORT replacement (skip this permalink for now)")
                        sub_choice = (
                            input("\nSelect resolution for lines/file (m,c,k,a): ").strip().lower()
                        )
                        # Manual entry logic is similar to above, simplified as file context is missing
                        if sub_choice == "m":  # Simplified manual entry
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
                        elif sub_choice == "c":
                            current_replacement_ls = None
                            current_replacement_le = None
                            print("    Line numbers cleared.")
                            break
                        elif sub_choice == "k":
                            current_replacement_ls = original.line_start
                            current_replacement_le = original.line_end
                            print("    Original lines kept.")
                            break  # This keeps original lines, path is effective_replacement_file_path
                        elif sub_choice == "a":
                            print("    Aborting.")
                            return "skip", effective_replacement_file_path, None, None
                        else:
                            print("    Invalid choice.")

            # Create/update the replacement_url with potentially modified line numbers
            replacement_url = self.create_replacement_permalink(
                original,  # For original URL type (blob/tree)
                ancestor_commit,
                effective_replacement_file_path,  # The resolved file path
                current_replacement_ls,  # The resolved line start
                current_replacement_le,  # The resolved line end
            )
            print(f"✨ Suggested replacement URL: {replacement_url}")

        elif not has_ancestor:
            print("  ℹ️ No common ancestor found in the main branch.")

        print("\nACTIONS:")
        print(
            f"  o. Open URL(s) in browser{' (original & replacement)' if has_ancestor else ' (original only)'}"
        )
        if has_ancestor:
            print("  r. Replace with suggested URL (i.e., update reference)")
            print("     R. Replace ALL from now on (for prompts with ancestors)")
        print("  t. Tag original commit (i.e., preserve exact permalink)")
        print(
            f"     T. Tag ALL from now on (for prompts {'with' if has_ancestor else 'without'} ancestors)"
        )
        print("  s. Skip this permalink")
        print(
            f"     S. Skip ALL from now on (for prompts {'with' if has_ancestor else 'without'} ancestors)"
        )

        while True:
            try:
                choice_input = input(
                    f"\nSelect action ({'o,r,R,t,T,s,S' if has_ancestor else 'o,t,T,s,S'}): "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nInterrupted by user")
                sys.exit(1)

            action: Optional[str] = None
            remember_this_choice: Optional[str] = None

            if choice_input == "o":
                try:
                    import webbrowser

                    print(f"🌐 Attempting to open original URL: {original.url}")
                    webbrowser.open(original.url)
                    if has_ancestor and replacement_url:
                        print(f"🌐 Attempting to open replacement URL: {replacement_url}")
                        webbrowser.open(replacement_url)
                except ImportError:
                    print(f"🌐 Please manually open: {original.url}")
                    if has_ancestor and replacement_url:
                        print(f"🌐 And suggested: {replacement_url}")
                continue  # Re-prompt
            elif choice_input == "r" and has_ancestor:
                action = "replace"
            elif (
                choice_input == "R" and has_ancestor and replacement_url
            ):  # Ensure replacement_url is available
                action = "replace"
                remember_this_choice = "replace"
            elif choice_input == "t":
                action = "tag"
            elif choice_input == "T":
                action = "tag"
                remember_this_choice = "tag"
            elif choice_input == "s":
                action = "skip"
            elif choice_input == "S":
                action = "skip"
                remember_this_choice = "skip"
            else:
                print("Invalid choice. Please try again.")
                continue

            if action:
                if remember_this_choice:
                    setattr(
                        self,
                        f"remembered_choice_{remembered_choice_key}",
                        remember_this_choice,
                    )
                if action == "replace":
                    return (
                        action,
                        effective_replacement_file_path,
                        current_replacement_ls,
                        current_replacement_le,
                    )
                else:
                    return (
                        action,
                        effective_replacement_file_path,
                        None,
                        None,
                    )  # Path might be informative, lines not relevant for tag/skip
            # Should not reach here if logic is correct
            print("Error in choice processing. Please try again.")

    def create_tag(self, commit_hash: str, commit_info: Dict[str, str]) -> str:
        """Create a descriptive tag for the commit."""
        subject = commit_info.get("subject", "")
        safe_subject = re.sub(r"[^a-zA-Z0-9\-_]", "-", subject[:30])
        safe_subject = re.sub(r"-+", "-", safe_subject).strip("-")

        if safe_subject:
            tag_name = f"{self.tag_prefix}-{commit_hash[:8]}-{safe_subject}"
        else:
            tag_name = f"{self.tag_prefix}-{commit_hash[:8]}"

        if len(tag_name) > 100:
            tag_name = f"{self.tag_prefix}-{commit_hash[:8]}"

        return tag_name

    def tag_exists(self, tag_name: str) -> bool:
        """Check if a tag already exists."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", f"refs/tags/{tag_name}"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except subprocess.CalledProcessError:
            return False

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
                    f"  ⚠️  Original URL not found in line {permalink.found_at_line} of {file_path}. Cannot replace."
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

    def _fetch_commit_if_missing(self, commit_hash: str) -> bool:
        """
        Checks if a commit exists locally. If not, prompts/auto-fetches it.
        Returns True if the commit is available after the process, False otherwise.
        """
        if self.commit_exists(commit_hash):
            return True

        self._vprint(f"  ❌ Commit {commit_hash} does not exist in this repository")
        should_try_fetch = False
        if self.auto_fetch_commits:
            self._vprint("  🤖 --auto-fetch-commits enabled.")
            should_try_fetch = True
        else:
            try:
                prompt_msg = f"Fetch commit {commit_hash} and its ancestors from origin?"
                fetch_choice = input(f"  {prompt_msg} (y/n): ").strip().lower()
                if fetch_choice == "y" or fetch_choice == "yes":
                    should_try_fetch = True
            except (EOFError, KeyboardInterrupt):
                print("\n  Skipping fetch due to user interruption.")
                sys.exit(1)  # Exit if user interrupts during this critical prompt

        if should_try_fetch:
            print(f"  🔽 Attempting to fetch commit {commit_hash}...")
            try:
                result = subprocess.run(
                    ["git", "fetch", "origin", "--depth=100000", commit_hash],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if result.returncode == 0:
                    self._vprint(f"  🔽 Successfully fetched commit {commit_hash}")
                    if not self.commit_exists(commit_hash):
                        print(
                            f"  ❌ Commit {commit_hash} still not found after successful-looking fetch command."
                        )
                        return False
                    self._vprint(f"  🆗 Commit {commit_hash} is now available.")
                    return True
                else:
                    print(
                        f"  ❌ Failed to fetch commit {commit_hash}. STDERR: {result.stderr.strip()}"
                    )
                    self._vprint(
                        "  ℹ️  You might need to ensure your remote 'origin' is up-to-date or."
                    )
                    return False
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                print(f"  ❌ Failed to fetch commit {commit_hash}: {e}")
                return False
        else:
            self._vprint(
                f"  Skipping commit {commit_hash} as it's not found locally and fetch was not attempted/declined."
            )
            return False

    def run(self) -> None:
        """Main execution function."""
        self._vprint(f"Repository: {self.repo_root}")
        self._vprint(f"GitHub: {self.github_owner}/{self.github_repo}")
        self._vprint(f"Main branch: {self.main_branch}, Tag prefix: {self.tag_prefix}")
        self._vprint(
            f"Dry run: {self.dry_run}, Auto fetch: {self.auto_fetch_commits}, Auto replace: {self.auto_replace}, Auto tag: {self.auto_tag}"
        )
        self._vprint(f"Line shift tolerance: {self.line_shift_tolerance}")
        self._vprint("-" * 50)

        # Find all permalink commits
        permalinks = self.find_github_permalinks()

        if not permalinks:
            print("No GitHub permalinks found in this repository.")
            return

        print(f"\nFound {len(permalinks)} GitHub permalinks")

        # Group permalinks by commit hash
        commits_to_process: dict[str, list[PermalinkInfo]] = {}
        for permalink in permalinks:
            if permalink.commit_hash not in commits_to_process:
                commits_to_process[permalink.commit_hash] = []
            commits_to_process[permalink.commit_hash].append(permalink)

        # Process each unique commit
        commits_to_tag = []
        replacements_needed = []

        for commit_hash, commit_permalinks in commits_to_process.items():
            print(f"\n{'-' * 80}")
            print(f"\n🔍 Processing commit: {commit_hash}")

            # Check if commit exists; if not, try to fetch it from remote
            if not self._fetch_commit_if_missing(commit_hash):
                # If commit is still not available after attempting fetch, skip this commit.
                continue

            # Get commit info
            commit_info = self.get_commit_info(commit_hash)
            if not commit_info:
                print(f"  ❌ Could not get info for commit {commit_hash}")
                continue

            self._vprint(f"  📝 {commit_info['subject']}")
            self._vprint(f"  👤 {commit_info['author']} ({commit_info['date']})")
            self._vprint(
                f"  🔗 Referenced in {len(commit_permalinks)} permalink(s) within this repository"
            )

            # Check if already in main
            if self.is_commit_in_main(commit_hash):
                print(f"  ✅ Already merged into {self.main_branch}")
                continue

            print(f"  ⛓️‍💥️  Not in {self.main_branch}")

            action_for_commit_group: Optional[str] = None  # "tag_commit", "replace_all_permalinks"

            ancestor_commit = self.find_closest_ancestor_in_main(commit_hash)
            if ancestor_commit:  # Ancestor found
                ancestor_info = self.get_commit_info(ancestor_commit)  # Should exist
                print(
                    f"  ⏪ Closest ancestor in main: {ancestor_commit[:8]} - {ancestor_info['subject'] if ancestor_info else 'Unknown'}"
                )
                if self.auto_replace:
                    action_for_commit_group = "replace_all_permalinks"
                    msg = f"  🤖 --auto-replace enabled. Will process replacements for commit {commit_hash[:8]}."
                    if self.dry_run:
                        msg = f"  🧪 DRY RUN: {msg}"
                    self._vprint(msg)
                elif self.auto_tag:
                    action_for_commit_group = "tag_commit"
                    msg = f"  🤖 --auto-tag enabled (and --auto-replace not applicable/set). Will tag commit {commit_hash[:8]}."
                    if self.dry_run:
                        msg = f"  🧪 DRY RUN: {msg}"
                    self._vprint(msg)
            else:  # No ancestor found
                print(
                    f"  ❌ No common ancestor with {self.main_branch} found for commit {commit_hash[:8]}."
                )
                if self.auto_tag:  # Note --auto-replace is not applicable here
                    action_for_commit_group = "tag_commit"
                    msg = f"  🤖 --auto-tag enabled (no ancestor found). Will tag commit {commit_hash[:8]}."
                    if self.dry_run:
                        msg = f"  🧪 DRY RUN: {msg}"
                    self._vprint(msg)

            if action_for_commit_group == "replace_all_permalinks" and ancestor_commit:
                # Display the number of permalinks in this commit group
                print(
                    f"\n  🚧 Processing {len(commit_permalinks)} permalink(s) for commit {commit_hash[:8]}..."
                )

                for permalink in commit_permalinks:
                    # Determine the best replacement URL, considering line content verification
                    final_replacement_url: str
                    verified_ls_for_replacement = permalink.line_start
                    verified_le_for_replacement = permalink.line_end  # Can be None

                    if (
                        permalink.file_path and permalink.line_start
                    ):  # Only verify if lines are present
                        if self.file_exists_at_commit(ancestor_commit, permalink.file_path):
                            match_found, new_ls, new_le = self.verify_line_content(
                                permalink,
                                ancestor_commit,
                                permalink.file_path,  # Use original file path for auto-replace
                            )
                            if match_found:
                                verified_ls_for_replacement = new_ls
                                verified_le_for_replacement = new_le  # This can be None
                                # Messages for vprint
                                if new_ls == permalink.line_start and new_le == permalink.line_end:
                                    self._vprint(
                                        f"  🤖 Auto-replace: Content for {permalink.url} matches at original line numbers in ancestor."
                                    )
                                else:
                                    new_range_str = f"L{new_ls}"
                                    if new_le and new_le != new_ls:
                                        new_range_str += f"-L{new_le}"
                                    self._vprint(
                                        f"  🤖 Auto-replace: Content for {permalink.url} found shifted to {new_range_str} in ancestor."
                                    )
                            else:
                                self._vprint(
                                    f"  🤖 Auto-replace: Content for {permalink.url} at L{permalink.line_start} (and range) differs or not found in ancestor. Using original line numbers for replacement URL."
                                )
                        else:
                            self._vprint(
                                f"  🤖 Auto-replace: File {permalink.file_path} not in ancestor {ancestor_commit[:8]}. Using original line numbers for replacement URL."
                            )

                    final_replacement_url = self.create_replacement_permalink(
                        permalink,
                        ancestor_commit,
                        permalink.file_path,  # Use original file path for auto-replace
                        verified_ls_for_replacement,
                        verified_le_for_replacement,
                    )

                    replacements_needed.append((permalink, final_replacement_url))
                    if not self.dry_run:
                        self._perform_replacement(permalink, final_replacement_url)
                    # Dry run messages for replacements are handled at the end

            elif action_for_commit_group == "tag_commit":
                if (commit_hash, commit_info) not in commits_to_tag:
                    commits_to_tag.append((commit_hash, commit_info))
                # Dry run message for tagging is handled later

            else:  # Interactive mode for this commit group
                # Display the number of permalinks in this commit group
                print(
                    f"\n  🚧 Processing {len(commit_permalinks)} permalink(s) for commit {commit_hash[:8]}..."
                )

                # Process each permalink individually for this commit
                for index, permalink in enumerate(commit_permalinks):
                    action, returned_file_path, new_ls_for_replace, new_le_for_replace = (
                        self.prompt_user_for_replacement(
                            permalink, ancestor_commit, index=index, total=len(commit_permalinks)
                        )
                    )

                    if action == "tag":
                        if (commit_hash, commit_info) not in commits_to_tag:
                            commits_to_tag.append((commit_hash, commit_info))
                            self._vprint(
                                f"  ℹ️ Commit {commit_hash[:8]} will be tagged based on choice for {permalink.url[:50]}..."
                            )
                        # If commit is tagged, all its permalinks are effectively preserved by that tag.
                        # We can break here to avoid redundant prompts for other permalinks of the same commit if user chose 'tag'.
                        print(
                            f"  ℹ️ Commit {commit_hash[:8]} will be tagged. Other permalinks for this commit are covered."
                        )
                        break

                    elif action == "replace":
                        if ancestor_commit:  # Should be true if action is "replace"
                            final_replacement_url_interactive = self.create_replacement_permalink(
                                permalink,  # For original URL type (blob/tree)
                                ancestor_commit,
                                returned_file_path,  # This was determined by prompt_user_for_replacement
                                new_ls_for_replace,
                                new_le_for_replace,
                            )
                            replacements_needed.append(
                                (permalink, final_replacement_url_interactive)
                            )

                            if self.dry_run:
                                print(
                                    f"  🧪 DRY RUN: Would change file {permalink.found_in_file.relative_to(self.repo_root)}:{permalink.found_at_line} :\n"
                                    f"     🔗 OLD: {permalink.url}\n"
                                    f"     ✨ NEW: {final_replacement_url_interactive}\n"
                                )
                            else:
                                self._perform_replacement(
                                    permalink, final_replacement_url_interactive
                                )
                    elif action == "skip":
                        print(f"  ⏭️ Skipping permalink: {permalink.url[:50]}...")
            # else: # This case was when no ancestor was found, and not auto-tagging.

        if commits_to_tag:
            self._process_and_create_tags(commits_to_tag)

        # Summarize replacements if in dry_run mode (actual replacements are done inline if not dry_run)
        if self.dry_run and replacements_needed:
            print(f"\n{'=' * 80}")
            print("\n🧪 DRY RUN SUMMARY: Suggested replacements:\n")
            for permalink, replacement_url in replacements_needed:
                print(
                    f"  - In file: {permalink.found_in_file.relative_to(self.repo_root)}:{permalink.found_at_line}"
                )
                print(f"    Replace: {permalink.url}")
                print(f"    With:    {replacement_url}")
                print()
        elif not self.dry_run and replacements_needed:
            print(f"\n✅ Processed {len(replacements_needed)} permalink replacement(s).")

        print("\n🏁 Permalink checking complete.")

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
            tag_name = self.create_tag(commit_hash, commit_info)

            if self.tag_exists(tag_name):
                print(f"  ✅ Tag {tag_name} already exists for commit {commit_hash[:8]}")
                continue

            if self.dry_run:
                print(f"  🧪 DRY RUN: For commit {commit_hash[:8]}, would create tag: {tag_name}")
                created_tag_names.append(tag_name)
            else:
                try:
                    tag_message = f"Preserve permalink reference to: {commit_info['subject']}"
                    subprocess.run(
                        ["git", "tag", "-a", tag_name, commit_hash, "-m", tag_message],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    print(f"  🏷️ For commit {commit_hash[:8]}, successfully created tag: {tag_name}")
                    created_tag_names.append(tag_name)
                except subprocess.CalledProcessError as e:
                    error_msg = e.stderr
                    if isinstance(error_msg, bytes):
                        error_msg = error_msg.decode(errors="replace")
                    print(
                        f"  ❌ For commit {commit_hash[:8]}, failed to create tag {tag_name}: {error_msg.strip()}"
                    )
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
        actually_created_tags_for_push = [t for t in created_tag_names if self.tag_exists(t)]

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
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                error_message = e.stderr.strip() if hasattr(e, "stderr") and e.stderr else str(e)
                if isinstance(error_message, bytes):
                    error_message = error_message.decode(errors="replace")
                print(f"  ❌ Failed to push tags: {error_message}")
                print("  🎗️ You may need to push them manually: git push origin --tags")
        elif (
            created_tag_names
        ):  # Tags were identified for creation, but none were new/successfully made or exist now
            print(
                "\nℹ️ No new tags were created or available to push (either existed previously, failed creation)."
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
        "--dry-run",
        action="store_true",
        help="Show what would be done without making any changes (tags, file modifications, or remote pushes)."
        "Note: will still attempt to fetch commits if they are not found locally.",
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
        help="Automatically replace permalinks with versions pointing to the closest ancestor in the main branch, if found.\n"
        "Takes precedence over --auto-tag when an ancestor is available.",
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
        type=int,
        default=20,
        help="Max number of lines to shift up/down when searching for matching content in ancestor commits (default: %(default)s). Set to 0 to disable shifting.",
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
