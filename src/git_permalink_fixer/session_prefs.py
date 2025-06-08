import argparse
from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionPreferences:
    """Preferences that could change during teh session."""
    auto_fetch_commits: bool = False
    auto_accept_replace: bool = False
    auto_fallback: Optional[str] = None  # "tag" or "skip"
    remembered_action_with_repl: Optional[str] = None
    remembered_action_without_repl: Optional[str] = None
    remember_skip_all_fetches: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> 'SessionPreferences':
        return cls(
            auto_fetch_commits=args.auto_fetch_commits,
            auto_accept_replace=args.auto_accept_replace,
            auto_fallback=args.auto_fallback,
        )
