from pathlib import Path
from click.testing import CliRunner

from tech_debtor.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


def test_full_analysis_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(FIXTURES)])
    assert result.exit_code == 0
    # Should find all types of debt
    assert "COMPLEXITY" in result.output
    assert "SMELL" in result.output
    assert "DEAD CODE" in result.output
    assert "DUPLICATION" in result.output
    assert "Debt Score" in result.output


def test_json_output_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(FIXTURES), "--json"])
    assert result.exit_code == 0
    import json

    data = json.loads(result.output)
    assert data["total_findings"] > 0
    debt_types = {f["debt_type"] for f in data["findings"]}
    assert "complexity" in debt_types
    assert "smell" in debt_types


def test_score_fail_above_on_fixture():
    runner = CliRunner()
    result = runner.invoke(main, ["score", str(FIXTURES), "--fail-above", "0"])
    assert result.exit_code == 1
