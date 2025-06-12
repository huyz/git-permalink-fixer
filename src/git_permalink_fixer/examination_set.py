from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional

from .permalink_info import PermalinkInfo


@dataclass
class CommitToExamine:
    commit_hash: str
    permalinks: List[PermalinkInfo]
    commit_info: Optional[Dict[str, str]] = None  # Fetched during examination
    ancestor_commit: Optional[str] = None  # Determined during examination


@dataclass
class ExaminationSet:
    commits_to_examine: Dict[str, CommitToExamine] = field(default_factory=dict)

    def add_permalink(self, permalink: PermalinkInfo):
        if permalink.commit_hash not in self.commits_to_examine:
            self.commits_to_examine[permalink.commit_hash] = CommitToExamine(
                commit_hash=permalink.commit_hash, permalinks=[]
            )
        self.commits_to_examine[permalink.commit_hash].permalinks.append(permalink)

    def get_commit_examination_items(self) -> List[Tuple[str, List[PermalinkInfo]]]:
        # Helper to adapt to existing loop structure in _examine_phase
        return [(commit_hash, data.permalinks) for commit_hash, data in self.commits_to_examine.items()]
