from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class PermalinkInfo:
    url: str
    commit_hash: str
    url_path: str
    line_start: Optional[int]
    line_end: Optional[int]
    found_in_file: Path
    found_at_line: int
