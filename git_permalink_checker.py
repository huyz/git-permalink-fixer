#!/usr/bin/env python3
"""
GitHub Permalink Persistence Checker

Finds GitHub commit permalinks in a repository, checks if commits are merged
into main, and for unmerged commits, tries to find the closest ancestor in main.
For unmerged commits, it prompts the user to either tag the commit to preserve
the permalink or replace the permalink with a new one pointing to the ancestor
commit.

This is to avoid git garbage collection from breaking permalinks.

Usage: python get_permalink_checker.py [--dry-run] [--main-branch BRANCH] [--tag-prefix PREFIX] [--auto-tag]

Supports the following cloud git repos:

- github.com

History:

- 2025-06-01 Authored by huyz and Claude Sonnet 4
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


class SmartPermalinkTagger:
    def __init__(
        self,
        main_branch: str = "main",
        tag_prefix: str = "permalink-ref",
        dry_run: bool = False,
        auto_tag: bool = False,
    ):
        self.main_branch = main_branch
        self.tag_prefix = tag_prefix
        self.dry_run = dry_run
        self.auto_tag = auto_tag
        self.repo_root = self._get_repo_root()
        self.remote_url = self._get_remote_url()
        self.github_owner, self.github_repo = self._get_github_info()

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
        except subprocess.CalledProcessError:
            raise RuntimeError("Not in a git repository")

    def _get_remote_url(self) -> str:
        """Get the origin remote URL."""
        try:
            GIT_RE = re.compile(r"^(?:git@|https?://)github\.com[:/]")

            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()

            # We sometimes use the `insteadOf` directive to map to domains
            # that .ssh/config can recognize.  In those cases, we want to use
            # the simpler way to extract the URL
            if not GIT_RE.match(result):
                result = subprocess.run(
                    ["git", "config", "--get", "remote.origin.url"],
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout.strip()

            if not GIT_RE.match(result):
                raise RuntimeError(
                    f"Remote URL does not match GitHub format: {result}"
                )

            return result
        except subprocess.CalledProcessError:
            raise RuntimeError("No origin remote found")

    def _get_github_info(self) -> Tuple[str, str]:
        """Extract owner/repo from GitHub URL."""
        patterns = [
            r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$",
            r"github\.com[:/]([^/]+)/([^/]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, self.remote_url)
            if match:
                return (match.group(1), match.group(2).rstrip(".git"))

        raise RuntimeError(
            f"Could not parse GitHub info from remote URL: {self.remote_url}"
        )

    def _parse_github_permalink(self, url: str) -> Optional[PermalinkInfo]:
        """Parse a GitHub permalink URL to extract commit hash, file path, and line numbers."""
        # Match GitHub permalinks with optional line numbers
        pattern = re.compile(
            r"https://github\.com/([^/]+)/([^/]+)/(?:blob|tree)/([a-f0-9]{7,40})(?:/([^#\s\?]+))?(?:#L(\d+)(?:-L(\d+))?)?",
            re.IGNORECASE,
        )

        match = pattern.match(url)
        if not match:
            return None

        owner, repo, commit_hash, file_path, line_start, line_end = match.groups()

        # Only process URLs from the current repository
        # Repo aliases
        if (
            owner.lower() != self.github_owner.lower()
            or repo.lower().replace(r'^(?:platform-|risk-|rails-)?', '') != self.github_repo.lower().replace(r'^(?:platform-|risk-|rails-)?', '')
        ):
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
        extensions = {
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
            ".php",
            ".properties",
            ".property",
            ".ps1",
            ".py",
            ".rb",
            ".rs",
            ".rst",
            ".rust",
            ".sh",
            ".sql",
            ".svg",
            ".ts",
            ".tsx",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
            ".zsh",
        }

        print(f"Searching for GitHub permalinks in {self.repo_root}")

        found_count = 0
        for file_path in self.repo_root.rglob("*"):
            # Skip directories, hidden files, and files in .git
            if (
                file_path.is_dir()
                or file_path.name.startswith(".")
                or ".git" in file_path.parts
                or ".idea" in file_path.parts
            ):
                continue

            # Only search in text files by running `file` command
            # 2025-06-04 This is too slow, which is why we rely on extensions as heuristics.
            #try:
            #    result = subprocess.run(
            #        ["file", "--mime-type", "-b", str(file_path)],
            #        capture_output=True,
            #        text=True,
            #        check=True,
            #    )
            #    if "text" not in result.stdout.lower():
            #        continue
            #except subprocess.CalledProcessError:
            #    print(f"Warning: Could not determine file type for {file_path}")
            #    continue

            # Only search in text files or in common git repo filenames with no extension‘
            if file_path.suffix.lower() not in extensions or \
                    (file_path.suffix == "" and file_path.name in \
                        {"Makefile", "README", "LICENSE", "CHANGELOG", "CONTRIBUTING", "AUTHORS", "INSTALL"}):
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                # Variable to track if the file header has been printed
                file_header_printed_for_current_file = False

                for line_num, line in enumerate(lines, 1):
                    # Find all GitHub URLs in the line
                    urls_in_line = re.findall(r"https://github\.com/[^][()<>\"{}|\\^`\s]+", line)

                    permalinks_found_on_this_line = []

                    for url in urls_in_line:
                        permalink_info = self._parse_github_permalink(url)
                        if permalink_info:
                            permalink_info.found_in_file = file_path
                            permalink_info.found_at_line = line_num
                            permalinks.append(permalink_info) # Add to the main list
                            permalinks_found_on_this_line.append(permalink_info)

                    if permalinks_found_on_this_line:
                        if not file_header_printed_for_current_file:
                            print(f"\n- In `{file_path.relative_to(self.repo_root)}`:")
                            file_header_printed_for_current_file = True

                        print(f"  - Line {line_num}: {line.strip()}")

                        for p_info in permalinks_found_on_this_line:
                            found_count += 1
                            print(
                                f"    {found_count:2d}. 📍 Found permalink: {p_info.commit_hash[:8]}"
                            )

            except (UnicodeDecodeError, IOError) as e:
                print(f"Warning: Could not read {file_path}: {e}")
                continue

        return permalinks

    def is_commit_in_main(self, commit_hash: str) -> bool:
        """Check if a commit is reachable from the main branch."""
        try:
            subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit_hash, self.main_branch],
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def commit_exists(self, commit_hash: str) -> bool:
        """Check if a commit exists in the repository."""
        try:
            subprocess.run(
                ["git", "cat-file", "-e", commit_hash], capture_output=True, check=True
            )
            return True
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
            parts = result.stdout.strip().split("|", 3)
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
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def file_exists_at_commit(self, commit_hash: str, file_path: str) -> bool:
        """Check if a file exists at a specific commit."""
        try:
            subprocess.run(
                ["git", "cat-file", "-e", f"{commit_hash}:{file_path}"],
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def get_file_content_at_commit(
        self, commit_hash: str, file_path: str
    ) -> Optional[List[str]]:
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
        self, original: PermalinkInfo, new_commit_hash: str
    ) -> str:
        """Create a replacement permalink URL."""
        base_url = f"https://github.com/{self.github_owner}/{self.github_repo}/blob/{new_commit_hash}"

        if original.file_path:
            url = f"{base_url}/{original.file_path}"
            if original.line_start:
                if original.line_end and original.line_end != original.line_start:
                    url += f"#L{original.line_start}-L{original.line_end}"
                else:
                    url += f"#L{original.line_start}"
            return url
        else:
            return f"https://github.com/{self.github_owner}/{self.github_repo}/commit/{new_commit_hash}"

    def verify_line_content(
        self, original: PermalinkInfo, replacement_commit: str
    ) -> bool:
        """Verify that the referenced lines still exist and make sense in the replacement commit."""
        if not original.file_path or not original.line_start:
            return True  # Can't verify without specific lines

        original_content = self.get_file_content_at_commit(
            original.commit_hash, original.file_path
        )
        replacement_content = self.get_file_content_at_commit(
            replacement_commit, original.file_path
        )

        if not original_content or not replacement_content:
            return False

        # Get the referenced lines from both versions
        try:
            start_idx = original.line_start - 1
            end_idx = (original.line_end or original.line_start) - 1

            original_lines = original_content[start_idx : end_idx + 1]

            # Check if the same lines exist in the replacement
            if end_idx < len(replacement_content):
                replacement_lines = replacement_content[start_idx : end_idx + 1]
                return original_lines == replacement_lines
            else:
                return False

        except IndexError:
            return False

    def prompt_user_for_replacement(
        self, original: PermalinkInfo, replacement_commit: str
    ) -> str:
        """Prompt user to confirm replacement permalink."""
        commit_info = self.get_commit_info(replacement_commit)
        replacement_url = self.create_replacement_permalink(
            original, replacement_commit
        )

        print(f"\n{'='*80}")
        print("🔗 PERMALINK REPLACEMENT NEEDED")
        print(f"{'='*80}")
        print(
            f"📍 Found in: {original.found_in_file.relative_to(self.repo_root)}:{original.found_at_line}"
        )
        print(f"🔗 Original URL: {original.url}")
        print(
            f"❌ Original commit: {original.commit_hash[:8]} (not in {self.main_branch})"
        )

        if commit_info:
            print(
                f"✅ Suggested commit: {replacement_commit[:8]} - {commit_info['subject']}"
            )
            print(f"   Author: {commit_info['author']} ({commit_info['date']})")

        print(f"🔗 Replacement URL: {replacement_url}")

        # Show content verification if applicable
        if original.file_path and original.line_start:
            if self.file_exists_at_commit(replacement_commit, original.file_path):
                if self.verify_line_content(original, replacement_commit):
                    print(
                        f"✅ Line content matches at L{original.line_start}"
                        + (f"-L{original.line_end}" if original.line_end else "")
                    )
                else:
                    print(
                        f"⚠️  Line content differs at L{original.line_start}"
                        + (f"-L{original.line_end}" if original.line_end else "")
                    )
                    print("   Please verify the replacement URL manually")
            else:
                print(
                    f"❌ File '{original.file_path}' does not exist in replacement commit"
                )

        print("\nOptions:")
        print("  1. Tag original commit (preserve exact permalink)")
        print("  2. Replace with suggested URL (update documentation)")
        print("  3. Skip this permalink")
        print("  4. Open replacement URL in browser to verify")

        while True:
            choice = input("\nEnter your choice (1-4): ").strip()

            if choice == "1":
                return "tag"
            elif choice == "2":
                return "replace"
            elif choice == "3":
                return "skip"
            elif choice == "4":
                # Try to open URL in browser
                try:
                    import webbrowser

                    webbrowser.open(replacement_url)
                    print(f"Opened {replacement_url} in browser")
                except ImportError:
                    print(f"Please manually open: {replacement_url}")
                continue
            else:
                print("Invalid choice. Please enter 1, 2, 3, or 4.")

    def create_tag(self, commit_hash: str, commit_info: Dict[str, str]) -> str:
        """Create a descriptive tag for the commit."""
        safe_subject = re.sub(r"[^a-zA-Z0-9\-_]", "-", commit_info["subject"][:30])
        safe_subject = re.sub(r"-+", "-", safe_subject).strip("-")

        tag_name = f"{self.tag_prefix}-{commit_hash[:8]}-{safe_subject}"

        if len(tag_name) > 100:
            tag_name = f"{self.tag_prefix}-{commit_hash[:8]}"

        return tag_name

    def tag_exists(self, tag_name: str) -> bool:
        """Check if a tag already exists."""
        try:
            subprocess.run(
                ["git", "rev-parse", f"refs/tags/{tag_name}"],
                capture_output=True,
                check=True,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def run(self) -> None:
        """Main execution function."""
        print(f"Repository: {self.repo_root}")
        print(f"GitHub: {self.github_owner}/{self.github_repo}")
        print(f"Main branch: {self.main_branch}")
        print(f"Tag prefix: {self.tag_prefix}")
        print(f"Dry run: {self.dry_run}")
        print(f"Auto tag: {self.auto_tag}")
        print("-" * 50)

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
            print(f"\n🔍 Processing commit: {commit_hash}")

            # Check if commit exists
            if not self.commit_exists(commit_hash):
                print(f"  ❌ Commit {commit_hash} does not exist in this repository")

                # Ask user if they want to try fetching the commit
                fetch_choice = input(f"  Fetch commit {commit_hash} and its ancestors from origin? (y/n): ").strip().lower()

                if fetch_choice == 'y' or fetch_choice == 'yes':
                    print(f"  🔄 Attempting to fetch commit {commit_hash}...")
                    try:
                        if self.dry_run:
                            print(f"  🧪️ Would fetch commit {commit_hash}, but as we're in dry run mode, Commit {commit_hash} does not exist in this repository.")
                        else:
                            # Try to fetch the specific commit
                            subprocess.run(
                                ["git", "fetch", "origin", "--depth=10000", commit_hash],
                                capture_output=True,
                                check=True,
                            )
                            print(f"  🔽 Successfully fetched commit {commit_hash}")

                            # Check again if the commit exists after fetching
                            if not self.commit_exists(commit_hash):
                                print(f"  ❌ Commit {commit_hash} still not found after fetching")
                                continue
                            else:
                                print(f"  🆗 Commit {commit_hash} is now available in the repository")
                    except subprocess.CalledProcessError as e:
                        print(f"  ❌ Failed to fetch commit {commit_hash}: {e}")
                        continue
                else:
                    # User chose not to fetch
                    continue

            # Get commit info
            commit_info = self.get_commit_info(commit_hash)
            if not commit_info:
                print(f"  ❌ Could not get info for commit {commit_hash}")
                continue

            print(f"  📝 {commit_info['subject']}")
            print(f"  👤 {commit_info['author']} ({commit_info['date']})")
            print(f"  📍 Referenced in {len(commit_permalinks)} permalink(s)")

            # Check if already in main
            if self.is_commit_in_main(commit_hash):
                print(f"  ✅ Already merged into {self.main_branch}")
                continue

            print(f"  ⚠️  Not in {self.main_branch}")

            # Find closest ancestor in main
            ancestor_commit = self.find_closest_ancestor_in_main(commit_hash)
            if ancestor_commit:
                ancestor_info = self.get_commit_info(ancestor_commit)
                print(
                    f"  🔄 Closest ancestor in main: {ancestor_commit[:8]} - {ancestor_info['subject'] if ancestor_info else 'Unknown'}"
                )

                if self.auto_tag:
                    commits_to_tag.append((commit_hash, commit_info))
                else:
                    # For each permalink, prompt user for action
                    for permalink in commit_permalinks:
                        action = self.prompt_user_for_replacement(
                            permalink, ancestor_commit
                        )

                        if action == "tag":
                            if (commit_hash, commit_info) not in commits_to_tag:
                                commits_to_tag.append((commit_hash, commit_info))
                        elif action == "replace":
                            replacement_url = self.create_replacement_permalink(
                                permalink, ancestor_commit
                            )
                            replacements_needed.append((permalink, replacement_url))

                            if self.dry_run:
                                print(
                                    f"  🧪️ For permalink {permalink.url}, would replace with: {replacement_url}"
                                )
                            else:
                                # Perform the replacement in the file
                                try:
                                    with open(permalink.found_in_file, "r+", encoding="utf-8") as f:
                                        content = f.readlines()
                                        # Replace all instances of the URL in the line with the new permalink, using exact
                                        # substring search (not regex)
                                        content[permalink.found_at_line - 1] = content[permalink.found_at_line - 1].replace(
                                            permalink.url, replacement_url
                                        )
                                        f.seek(0)
                                        f.writelines(content)
                                        f.truncate()
                                    print(f"  ✅ Replaced permalink in {permalink.found_in_file.relative_to(self.repo_root)} at line {permalink.found_at_line}")
                                except Exception as e:
                                    print(
                                        f"  ❌ Failed to replace permalink in {permalink.found_in_file.relative_to(self.repo_root)}: {e}"
                                    )
                        # Skip action requires no further processing
            else:
                if self.auto_tag:
                    print(f"  ⏳ No common ancestor with {self.main_branch} found. Will tag commit this automatically.")
                    commits_to_tag.append((commit_hash, commit_info))
                else:
                    print(f"  ❌ No common ancestor with {self.main_branch} found")

        # Handle tagging
        if commits_to_tag:
            print(f"\n📌 Tagging {len(commits_to_tag)} commits")
            created_tags = []

            for commit_hash, commit_info in commits_to_tag:
                tag_name = self.create_tag(commit_hash, commit_info)

                if self.tag_exists(tag_name):
                    print(f"  ✅ Tag {tag_name} already exists")
                    continue

                if self.dry_run:
                    print(f"  🧪 For commit {commit_hash[:8]}, would create tag: {tag_name}")
                    created_tags.append(tag_name)
                else:
                    try:
                        tag_message = (
                            f"Preserve permalink reference to: {commit_info['subject']}"
                        )
                        subprocess.run(
                            [
                                "git",
                                "tag",
                                "-a",
                                tag_name,
                                commit_hash,
                                "-m",
                                tag_message,
                            ],
                            check=True,
                        )
                        print(f"  🏷️ For commit {commit_hash[:8]}, successfully created tag: {tag_name}")
                        created_tags.append(tag_name)
                    except subprocess.CalledProcessError as e:
                        print(f"  ❌ For commit {commit_hash[:8]}, failed to create tag {tag_name}: {e}")

            # Push tags
            if created_tags and not self.dry_run:
                print(f"\n🚀 Pushing {len(created_tags)} tags to origin...")
                try:
                    subprocess.run(["git", "push", "origin"] + created_tags, check=True)
                    print("  ✅ All tags pushed successfully!")
                except subprocess.CalledProcessError as e:
                    print(f"  ❌ Failed to push tags: {e}")

        # Handle replacements
        if self.dry_run and replacements_needed:
            print("\n🧪 Dry run: Suggested replacements:")
            for permalink, replacement_url in replacements_needed:
                print(
                    f"  📍 {permalink.found_in_file.relative_to(self.repo_root)}:{permalink.found_at_line}"
                )
                print(f"    Replace: {permalink.url}")
                print(f"    With:    {replacement_url}")
                print()


def main():
    parser = argparse.ArgumentParser(
        description="Smart GitHub permalink processor with ancestor chain analysis"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--main-branch", default="main", help="Main branch name (default: main)"
    )
    parser.add_argument(
        "--tag-prefix",
        default="permalinks/ref",
        help="Tag prefix, preferably namespaced with slash (default: permalinks/ref)",
    )
    parser.add_argument(
        "--auto-tag",
        action="store_true",
        help="Automatically tag all unmerged commits without prompting",
    )

    args = parser.parse_args()

    try:
        tagger = SmartPermalinkTagger(
            main_branch=args.main_branch,
            tag_prefix=args.tag_prefix,
            dry_run=args.dry_run,
            auto_tag=args.auto_tag,
        )
        tagger.run()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
