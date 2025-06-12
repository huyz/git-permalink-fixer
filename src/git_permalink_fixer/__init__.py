import argparse
import sys
import importlib.metadata
from pathlib import Path

from .global_prefs import GlobalPreferences
from .session_prefs import SessionPreferences, FetchMode
from .app import PermalinkFixerApp


def main():
    """Main entry point for the GitHub Permalink Fixer application."""
    parser = argparse.ArgumentParser(
        description="Finds GitHub commit permalinks, checks their status relative to the main branch, and assists"
        " in preserving or updating them.",
        formatter_class=argparse.RawTextHelpFormatter,  # Allows for better formatting of help
    )

    try:
        package_version = importlib.metadata.version("git-permalink-fixer")
    except importlib.metadata.PackageNotFoundError:
        package_version = "unknown"
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {package_version}",
        help="Show program's version number and exit.",
    )
    parser.add_argument(
        "scan_path",
        nargs="?",
        type=Path,
        default=None,
        help="Optional path to a directory or file to scan. If not provided, scans from the repository root.\n"
        "The path must be within the git repository.",
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
        "--line-shift-tolerance",
        type=str,
        default="20",
        help="Max number of lines to shift up/down when searching for matching content in ancestor commits"
        " (default: %(default)s).\n"
        "Can be an absolute number (e.g., '20') or a percentage of the target file's lines (e.g., '10%%').\n"
        "Set to '0' or '0%%' to disable shifting.",
    )
    parser.add_argument(
        "--fetch-mode",
        type=str,
        choices=[mode.value for mode in FetchMode],
        default=FetchMode.PROMPT.value,
        help="Behavior for fetching commits not found locally from 'origin' remote (default: %(default)s).\n"
        "  'prompt': Ask for each commit or group.\n"
        "  'always': Automatically fetch all missing commits.\n"
        "  'never': Never fetch missing commits.",
    )
    parser.add_argument(
        "--auto-accept-replace",
        action="store_true",
        help="Automatically accept suggested replacements if verification is successful (e.g. ancestor found and"
        " lines match within tolerance, or user manually resolved to a verifiable state).\n"
        "Bypasses the final action prompt for these cases.",
    )
    parser.add_argument(
        "--auto-fallback",
        choices=["tag", "skip"],
        default=None,
        help="If a permalink cannot be successfully replaced (e.g., no ancestor, or line content verification fails"
        " and isn't resolved by user), automatically choose a fallback action: 'tag' the original commit or 'skip'"
        " the permalink.\n"
        "Bypasses the final action prompt for these fallback cases.",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Enable non-interactive mode. This is a shorthand for setting:\n"
        "  --auto-accept-replace\n"
        "  --auto-fallback tag\n"  # Default to tagging for preservation in non-interactive
        "  --fetch-mode always\n"
        "User will not be prompted for decisions.",
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
        args.auto_fallback = "tag"  # Default fallback for non-interactive is to tag
        args.fetch_mode = FetchMode.ALWAYS_FETCH.value
        if args.verbose:
            print(
                f"ℹ️ Non-interactive mode enabled: --auto-accept-replace, --auto-fallback={args.auto_fallback},"
                f" and --fetch-mode={args.fetch_mode} are active."
            )

    try:
        global_prefs = GlobalPreferences.from_args(args)
        session_prefs = SessionPreferences.from_args(args)

        app = PermalinkFixerApp(global_prefs, session_prefs)
        app.run()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except RuntimeError as e:  # Catch specific custom errors
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:  # Catch other unexpected errors  # pylint: disable=broad-except
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        import traceback  # pylint: disable=import-outside-toplevel

        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

    return 0


if __name__ == "__main__":
    main()
