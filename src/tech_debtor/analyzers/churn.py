from __future__ import annotations

from pathlib import Path

from tree_sitter import Tree

from tech_debtor.config import Config
from tech_debtor.models import Finding

try:
    from git import Repo, InvalidGitRepositoryError
except ImportError:
    Repo = None
    InvalidGitRepositoryError = Exception


def get_file_churn(project_path: Path, max_commits: int = 500) -> dict[str, int]:
    if Repo is None:
        return {}
    try:
        repo = Repo(project_path, search_parent_directories=True)
    except InvalidGitRepositoryError:
        return {}

    churn: dict[str, int] = {}
    try:
        for commit in repo.iter_commits(max_count=max_commits):
            for path in commit.stats.files:
                if path.endswith(".py"):
                    churn[path] = churn.get(path, 0) + 1
    except Exception:
        pass
    return churn


class ChurnAnalyzer:
    def __init__(self, churn_data: dict[str, int] | None = None):
        self._churn_data = churn_data or {}

    def analyze(self, file_path: str, source: str, tree: Tree, config: Config) -> list[Finding]:
        return []
