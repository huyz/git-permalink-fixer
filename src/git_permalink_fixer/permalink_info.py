from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple


@dataclass
class PermalinkInfo:
    url: str
    commit_hash: str
    url_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    found_in_file: Path
    found_at_line: int

    @staticmethod
    def count_unique_commits_and_files(permalinks: List["PermalinkInfo"]) -> Tuple[int, int]:
        """Helper to count unique commit hashes and unique files from a list of permalinks."""
        unique_commits = set()
        unique_files = set()
        for permalink in permalinks:
            unique_commits.add(permalink.commit_hash)
            unique_files.add(permalink.found_in_file)
        return len(unique_commits), len(unique_files)
