from dataclasses import dataclass, field

from .permalink_info import PermalinkInfo


@dataclass
class CommitToExamine:
    commit_hash: str
    permalinks: list[PermalinkInfo]
    commit_info: dict[str, str] | None = None  # Fetched during examination
    ancestor_commit: str | None = None  # Determined during examination


@dataclass
class ExaminationSet:
    commits_to_examine: dict[str, CommitToExamine] = field(default_factory=dict)

    def add_permalink(self, permalink: PermalinkInfo):
        if permalink.commit_hash not in self.commits_to_examine:
            self.commits_to_examine[permalink.commit_hash] = CommitToExamine(
                commit_hash=permalink.commit_hash, permalinks=[]
            )
        self.commits_to_examine[permalink.commit_hash].permalinks.append(permalink)

    def get_commit_examination_items(self) -> list[tuple[str, list[PermalinkInfo]]]:
        # Helper to adapt to existing loop structure in _examine_phase
        return [(commit_hash, data.permalinks) for commit_hash, data in self.commits_to_examine.items()]
