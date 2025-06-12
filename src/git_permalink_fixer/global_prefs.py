import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .text_utils import parse_tolerance_input


@dataclass
class GlobalPreferences:
    """Preferences not expected to change."""

    verbose: bool = False
    dry_run: bool = False
    respect_gitignore: bool = True
    repo_aliases: List[str] = field(default_factory=list)
    main_branch: str = "main"
    tag_prefix: str = "permalinks/ref"
    line_shift_tolerance_str: str = "20"
    output_json_report_path: Optional[Path] = None
    scan_path: Optional[Path] = None  # New: Path to start scanning from

    # Derived attributes
    tolerance_is_percentage: bool = field(init=False)
    tolerance_value: int = field(init=False)

    def __post_init__(self):
        self.tolerance_is_percentage, self.tolerance_value = parse_tolerance_input(self.line_shift_tolerance_str)
        self.repo_aliases = [alias.lower() for alias in self.repo_aliases]

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "GlobalPreferences":
        return cls(
            verbose=args.verbose,
            dry_run=args.dry_run,
            respect_gitignore=args.respect_gitignore,
            repo_aliases=args.repo_aliases or [],
            main_branch=args.main_branch,
            tag_prefix=args.tag_prefix,
            line_shift_tolerance_str=args.line_shift_tolerance,
            output_json_report_path=Path(args.output_json_report) if args.output_json_report else None,
            scan_path=args.scan_path,
        )
