import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional

from .permalink_info import PermalinkInfo


@dataclass
class PermalinkReplacementOperation:
    permalink_info: PermalinkInfo
    repl_url: str


@dataclass
class TagCreationOperation:
    commit_hash: str
    commit_info: Dict[str, str]
    # tag_name and tag_message will be generated later if not provided
    tag_name: Optional[str] = None
    tag_message: Optional[str] = None


@dataclass
class OperationSet:
    replacements: List[PermalinkReplacementOperation] = field(default_factory=list)
    tags_to_create: List[TagCreationOperation] = field(default_factory=list)
    report_data: Dict[str, List] = field(default_factory=lambda: {"replacements": [], "tags_created": []})

    def write_json_report(self, output_path: Optional[Path]) -> None:
        """Writes the collected report data to a JSON file if a path is specified."""
        if not output_path:
            return

        try:
            # Ensure parent directory exists
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.report_data, f, indent=2)
            print(f"\n📝 JSON report written to: {output_path}")
        except IOError as e:
            print(
                f"\n❌ Error writing JSON report to {output_path}: {e}",
                file=sys.stderr,
            )
