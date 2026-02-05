import subprocess
from pathlib import Path

from tech_debtor.analyzers.churn import ChurnAnalyzer, get_file_churn
from tech_debtor.config import Config


def _init_git_repo(tmp_path: Path):
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_path, capture_output=True)
    f = tmp_path / "a.py"
    for i in range(5):
        f.write_text(f"x = {i}\n")
        subprocess.run(["git", "add", "a.py"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", f"commit {i}"], cwd=tmp_path, capture_output=True)


def test_get_file_churn(tmp_path):
    _init_git_repo(tmp_path)
    churn = get_file_churn(tmp_path)
    assert "a.py" in churn
    assert churn["a.py"] == 5


def test_churn_no_git(tmp_path):
    churn = get_file_churn(tmp_path)
    assert churn == {}
