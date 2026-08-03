import argparse
from dataclasses import dataclass
from enum import Enum


class FetchMode(Enum):
    PROMPT = "prompt"
    ALWAYS_FETCH = "always"
    NEVER_FETCH = "never"


@dataclass
class SessionPreferences:
    """Preferences that could change during teh session."""

    fetch_mode: FetchMode = FetchMode.PROMPT
    auto_accept_replace: bool = False
    auto_fallback: str | None = None  # "tag" or "skip"
    remembered_action_with_repl: str | None = None
    remembered_action_without_repl: str | None = None

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "SessionPreferences":
        try:
            fetch_mode_enum = FetchMode(args.fetch_mode)
        except ValueError:
            # Should not happen if argparse choices are set correctly
            fetch_mode_enum = FetchMode.PROMPT
        return cls(
            fetch_mode=fetch_mode_enum,
            auto_accept_replace=args.auto_accept_replace,
            auto_fallback=args.auto_fallback,
        )
