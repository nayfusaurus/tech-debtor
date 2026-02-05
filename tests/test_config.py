from tech_debtor.config import Config, load_config


def test_default_config():
    cfg = Config()
    assert cfg.max_complexity == 15
    assert cfg.max_cognitive_complexity == 10
    assert cfg.max_function_length == 50
    assert cfg.max_parameters == 5
    assert cfg.max_nesting_depth == 4
    assert cfg.min_severity == "medium"
    assert cfg.exclude == []
    assert cfg.cost_per_line == 0.5


def test_load_config_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text("""
[tool.tech-debtor]
max-complexity = 20
max-function-length = 100
exclude = ["vendor/"]
""")
    cfg = load_config(tmp_path)
    assert cfg.max_complexity == 20
    assert cfg.max_function_length == 100
    assert cfg.exclude == ["vendor/"]
    # Defaults still apply for unset values
    assert cfg.max_parameters == 5


def test_load_config_missing_file(tmp_path):
    cfg = load_config(tmp_path)
    assert cfg.max_complexity == 15  # all defaults
