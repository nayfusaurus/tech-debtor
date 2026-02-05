from pathlib import Path
from click.testing import CliRunner

from tech_debtor.cli import main


def _make_project(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "simple.py").write_text("def add(x, y):\n    return x + y\n")
    (src / "complex.py").write_text(
        "def f(data):\n"
        + "    if data:\n" * 20
        + "        pass\n"
    )


def test_analyze_command(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(tmp_path / "src")])
    assert result.exit_code == 0
    assert "Debt Score" in result.output


def test_analyze_json(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(tmp_path / "src"), "--json"])
    assert result.exit_code == 0
    assert '"debt_score"' in result.output


def test_score_command(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(tmp_path / "src")])
    assert result.exit_code == 0


def test_score_fail_above(tmp_path):
    _make_project(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(tmp_path / "src"), "--fail-above", "0"])
    # Should fail because any findings push score above 0
    assert result.exit_code == 1
