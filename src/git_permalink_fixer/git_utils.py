import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Set, Tuple, Callable
import re
import sys

from .constants import GITHUB_REMOTE_RE


def get_repo_root(start_dir: Optional[Path] = None) -> Path:
    """Returns the repo's root in the filesystem.
    If start_dir is provided, 'git rev-parse --show-toplevel' is run
    as if executed from that directory. Otherwise, it uses the current working directory.
    """
    try:
        # If start_dir is provided, git command should be run as if in that directory.
        # Using cwd for subprocess.run effectively does this for rev-parse.
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start_dir if start_dir else None,  # Pass start_dir as cwd if provided
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        context_msg = f"from directory '{start_dir}'" if start_dir else "from current directory"
        raise RuntimeError(
            f"Could not determine repository root {context_msg}. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'"
        ) from e


def get_remote_url(repo_path: Path) -> str:
    """Get the origin remote URL from the specified repository path."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
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
        if not GITHUB_REMOTE_RE.match(remote_url):
            result = subprocess.run(
                ["git", "-C", str(repo_path), "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                check=True,
            )

            remote_url = result.stdout.strip()
            if not remote_url:
                raise RuntimeError("Empty remote URL returned from git config")

        if not GITHUB_REMOTE_RE.match(remote_url):
            raise RuntimeError(f"Remote URL does not match GitHub format: {remote_url}")

        return remote_url
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Failed to get remote URL from repo '{repo_path}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        raise RuntimeError("Failed to get remote URL for 'origin'.") from e


def load_ignored_paths(repo_root: Path) -> Set[Path]:
    """
    Loads all git-ignored files and directories using 'git status --porcelain=v1 --ignored'.
    Returns a set of absolute Paths.
    """
    try:
        # -C self.repo_root ensures the command runs in the repo root.
        # Paths in output are relative to repo_root.
        result = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--ignored"],
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
        ignored_set = set()
        for line in result.stdout.splitlines():
            if line.startswith("!! "):
                # Output is "!! path/to/item", so path is relative to repo root
                ignored_item_relative_path = line[3:].strip()
                ignored_set.add(repo_root / ignored_item_relative_path)
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Failed to get git-ignored files. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        raise RuntimeError("Failed to get git-ignored files.") from e
    except FileNotFoundError as e:
        raise RuntimeError("Failed to get git-ignored files.") from e
    return ignored_set


def get_github_info_from_url(remote_url: str) -> Tuple[str, str]:
    """Extract owner/repo from a GitHub remote URL."""
    patterns = [
        # Handles common SSH and HTTPS URLs, including those ending with .git or a slash
        r"github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$",
        # A more general pattern as a fallback, might be too broad if other patterns fail
        r"github\.com[:/]([^/]+)/([^/]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, remote_url)
        if match:
            owner = match.group(1)
            repo = match.group(2).rstrip(".git")  # Remove .git suffix if present
            if owner and repo:  # Ensure non-empty matches
                return owner, repo
    raise RuntimeError(f"Could not parse GitHub owner/repo from remote URL: {remote_url}")


def is_commit_in_main(commit_hash: str, main_branch: str, repo_path: Path) -> bool:
    """Check if a commit is reachable from the main branch in the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", commit_hash, main_branch],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error during 'is_commit_in_main' in repo '{repo_path}': Command '{subprocess.list2cmdline(e.cmd)}' failed for commit '{commit_hash}' and branch '{main_branch}' (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False


def get_file_content_at_commit(commit_hash: str, url_path: str, repo_path: Path) -> Optional[List[str]]:
    """Get file content at a specific commit from the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "show", f"{commit_hash}:{url_path}"],
            capture_output=True,
            text=True,
            check=True,  # Errors if file/commit doesn't exist
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Failed to get content of '{url_path}' at commit '{commit_hash}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return None


def gen_git_tag_name(commit_hash: str, commit_subject: str, tag_prefix: str) -> str:
    """Create a descriptive tag name for the commit."""
    safe_subject = re.sub(r"[^a-zA-Z0-9\-_]", "-", commit_subject[:30])
    safe_subject = re.sub(r"-+", "-", safe_subject).strip("-")

    if safe_subject:
        tag_name = f"{tag_prefix}-{commit_hash[:8]}-{safe_subject}"
    else:
        tag_name = f"{tag_prefix}-{commit_hash[:8]}"

    if len(tag_name) > 100:  # Git has tag name length limits, be conservative
        tag_name = f"{tag_prefix}-{commit_hash[:8]}"
    return tag_name


def git_tag_exists(tag_name: str, repo_path: Path) -> bool:
    """Check if a git tag already exists in the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "rev-parse", f"refs/tags/{tag_name}"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Checking existence of tag '{tag_name}' in repo '{repo_path}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False


def create_git_tag(tag_name: str, commit_hash: str, tag_message: str, dry_run: bool, repo_path: Path) -> bool:
    """Executes the git tag command in the specified repository."""
    if dry_run:
        print(f"🧪 DRY RUN: Would create tag: {tag_name} for commit {commit_hash[:8]} with message '{tag_message}'")
        return True  # Simulate success for dry run
    try:
        subprocess.run(
            ["git", "-C", str(repo_path), "tag", "-a", tag_name, commit_hash, "-m", tag_message],
            capture_output=True,
            text=True,
            check=True,
        )
        print(f"Successfully created tag: {tag_name} for commit {commit_hash[:8]}")
        return True
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Failed to create tag {tag_name} for commit {commit_hash[:8]}. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False


def is_commit_available_locally(commit_hash: str, repo_path: Path) -> bool:
    """Check if a commit exists in the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", commit_hash],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Checking existence of commit '{commit_hash}' in repo '{repo_path}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False


def fetch_commit_missing_locally(commit_hash: str, vprint_func: Callable, repo_path: Path) -> bool:
    """
    Attempts to fetch a specific commit from the 'origin' remote.
    Returns True if the fetch command executes successfully (return code 0), False otherwise.
    Note: A successful command doesn't guarantee the commit is now available,
    so the caller should re-check with is_commit_available_locally.
    """
    vprint_func(f"  Attempting to fetch commit {commit_hash} from 'origin' for repo '{repo_path}'...")
    try:
        # Using --no-tags to avoid fetching all tags, and --no-write-commit-graph for speed if not needed.
        # Depth is large to ensure we get the commit if it's far back.
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
                "fetch",
                "origin",
                "--depth=100000",
                commit_hash,
                "--no-tags",
                "--no-write-commit-graph",
            ],
            capture_output=True,
            text=True,
            timeout=120,  # Increased timeout for potentially large fetches
            check=False,  # Check return code manually
        )
        if result.returncode == 0:
            print(f"  🔽 Fetch command for commit {commit_hash} completed successfully.")
            return True
        print(
            f"Error: Failed to fetch commit {commit_hash}. Git command exited with {result.returncode}. STDERR: {result.stderr.strip()}",
            file=sys.stderr,
        )
        return False
    except subprocess.CalledProcessError as e:  # Should not happen with check=False
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: A git command during fetch operation for {commit_hash} failed. Command '{subprocess.list2cmdline(e.cmd)}' (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False
    except subprocess.TimeoutExpired as e:
        print(f"Error: Timeout during fetch operation for {commit_hash}: {e}", file=sys.stderr)
        return False


def get_commit_info(commit_hash: str, repo_path: Path) -> Optional[Dict[str, str]]:
    """Get commit information from the specified repository."""
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_path),
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
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Failed to get info for commit '{commit_hash}' in repo '{repo_path}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return None


def find_closest_ancestor_in_main(commit_hash: str, main_branch: str, repo_path: Path) -> Optional[str]:
    """Find the closest ancestor commit that is in the main branch in the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "merge-base", commit_hash, main_branch],
            capture_output=True,
            text=True,
            check=True,  # Errors if no common ancestor
        )
        ancestor = result.stdout.strip()
        return ancestor if ancestor else None
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Finding closest ancestor for '{commit_hash}' in '{main_branch}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return None


def file_exists_at_commit(commit_hash: str, url_path: str, repo_path: Path) -> bool:
    """Check if a file exists at a specific commit in the specified repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_path), "cat-file", "-e", f"{commit_hash}:{url_path}"],
            capture_output=True,  # Don't need output, just return code
            check=True,  # Errors if file doesn't exist at commit
        )
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        stderr_output = e.stderr.strip() if e.stderr else "N/A"
        print(
            f"Error: Checking if file '{url_path}' exists at commit '{commit_hash}' in repo '{repo_path}'. Command '{subprocess.list2cmdline(e.cmd)}' failed (rc={e.returncode}). Stderr: '{stderr_output}'",
            file=sys.stderr,
        )
        return False
